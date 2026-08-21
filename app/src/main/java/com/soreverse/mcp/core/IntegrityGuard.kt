/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

package com.soreverse.mcp.core

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.os.Process
import com.soreverse.mcp.nativecore.SignatureVerifier
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import kotlin.random.Random
import kotlin.system.exitProcess

object IntegrityGuard {
    data class Result(val trusted: Boolean, val reason: String, val expected: String, val actual: List<String>, val threats: List<String> = emptyList())

    @Volatile private var cached: Pair<Long, Result>? = null

    private val scheduleLock = Any()

    @Volatile private var recheckStarted = false

    /**
     * Runs all integrity checks (Java PackageManager + native APK file
     * verification) and terminates the process if any check fails.
     *
     * This is the main entry point for startup integrity enforcement.
     * It should be called once during Application.onCreate().
     *
     * The reason for two layers of verification:
     * - Cracking tools (kstools, ApkSignatureKiller, MT) hook the Java
     *   PackageManager.getPackageInfo() Binder call to replace the
     *   returned signature. The Java-level check alone can be bypassed.
     * - The native check reads the APK directly from the filesystem and
     *   extracts the certificate from the META-INF/ *.RSA PKCS7 signature.
     *   This path cannot be intercepted by a Binder-level hook.
     * - Together, they provide defense in depth: a cracker would need to
     *   hook BOTH the Java PackageManager AND the native JNI bridge,
     *   significantly raising the effort required.
     *
     * Signature-bypass frameworks (SigKill, TweakMe, SignatureKiller) rely on
     * the same Java PackageManager hook. To resist them we additionally
     * [verify][enforceEarly] at attachBaseContext(), where those tools install
     * their hook, and re-verify periodically at runtime so a one-shot or
     * timing-based bypass does not survive past startup.
     *
     * Reference:
     *   - https://github.com/xxxyanchenxxx/SigKill
     *   - https://github.com/liaoguobao/TweakMe
     *   - https://github.com/Familyye/SignatureKiller
     */
    fun enforce(context: Context) {
        // 1. Java-level check (can be hooked by kstools-style tools)
        val javaResult = verify(context)
        val javaPass = javaResult.trusted

        // 2. Native-level check (reads APK directly, bypasses PackageManager hook)
        val nativePass = SignatureVerifier.verify(context)

        // 3. Native package-name pin (rejects repackaged builds that changed
        //    applicationId, even if the Java layer reports a spoofed name).
        val packagePass = SignatureVerifier.verifyPackageName(context)

        // 4. Native APK integrity (ZIP structure + critical entries + dex CRC)
        val integrityCode = SignatureVerifier.verifyApkIntegrity(context)
        val integrityPass = integrityCode == SignatureVerifier.IntegrityCode.OK

        if (!javaPass || !nativePass || !packagePass || !integrityPass) {
            val reasons = mutableListOf<String>()
            if (!javaPass) reasons.add("Java: ${javaResult.reason}")
            if (!nativePass) {
                reasons.add(
                    "Native: APK signer mismatch detected by filesystem-level verification"
                )
            }
            if (!packagePass) {
                reasons.add("Native: package name does not match the pinned value")
            }
            if (!integrityPass) {
                reasons.add("Native: APK integrity check failed (code=0x${integrityCode.toString(16)})")
            }
            AppLog.e("INTEGRITY ENFORCEMENT FAILED: ${reasons.joinToString("; ")}")
            terminateWithContext(context)
            return
        }

        // 5. Keep re-verifying at runtime so tampering after startup is caught.
        schedulePeriodicRecheck(context.applicationContext ?: context)
    }

    /**
     * Lightweight early gate executed from Application.attachBaseContext().
     * Only the native filesystem-level checks run here (signer digest, package
     * name pin, APK integrity): reading the APK directly bypasses the Java
     * PackageManager hook that SigKill / TweakMe / SignatureKiller install at
     * exactly this lifecycle point.
     */
    fun enforceEarly(context: Context) {
        if (!SignatureVerifier.verify(context) ||
            !SignatureVerifier.verifyPackageName(context) ||
            SignatureVerifier.verifyApkIntegrity(context) != SignatureVerifier.IntegrityCode.OK
        ) {
            AppLog.e("INTEGRITY ENFORCEMENT (early) FAILED: native signer / package / integrity mismatch")
            terminateWithContext(context)
        }
    }

    /**
     * Schedules a randomized-interval background re-verification. Using random
     * delays makes a deterministic "bypass the startup check, then hook later"
     * plan much harder to time accurately.
     */
    private fun schedulePeriodicRecheck(context: Context) {
        synchronized(scheduleLock) {
            if (recheckStarted) return
            recheckStarted = true
        }
        Thread({
            var delay = 8_000L + Random.nextLong(12_000L)
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(delay)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                // Native check is the trustworthy one; the Java check cannot be
                // faked but can be hooked, so it is cross-checked too.
                val nativeOk = SignatureVerifier.verify(context)
                val javaOk = verify(context).trusted
                val packageOk = SignatureVerifier.verifyPackageName(context)
                val integrityOk =
                    SignatureVerifier.verifyApkIntegrity(context) ==
                        SignatureVerifier.IntegrityCode.OK
                if (!nativeOk || !javaOk || !packageOk || !integrityOk) {
                    AppLog.e("INTEGRITY PERIODIC CHECK FAILED: tampering detected at runtime")
                    terminateWithContext(context)
                    return@Thread
                }
                delay = 45_000L + Random.nextLong(90_000L)
            }
        }).apply {
            isDaemon = true
            name = "soreverse-integrity"
            start()
        }
    }

    fun verify(context: Context): Result {
        cached?.let { (time, result) ->
            if (System.currentTimeMillis() - time < 2_000L) return result
        }
        val result = runCatching {
            val expected = SignatureVerifier.getExpectedSignerDigest().normalizeDigest()
            val threats = runtimeThreats()
            if (expected.isBlank()) {
                Result(
                    threats.isEmpty(),
                    if (threats.isEmpty()) "no release signer pin configured" else "runtime instrumentation detected",
                    expected,
                    emptyList(),
                    threats
                )
            } else {
                val actual = signingCertificateDigests(context).map { it.normalizeDigest() }
                val signerTrusted = actual.any { it == expected }
                val allThreats = if (signerTrusted) {
                    threats
                } else {
                    listOf("application signature mismatch") +
                        threats
                }
                Result(
                    trusted = allThreats.isEmpty(),
                    reason = if (allThreats.isEmpty()) {
                        "trusted release signer"
                    } else {
                        allThreats.joinToString(
                            "; "
                        )
                    },
                    expected = expected,
                    actual = actual,
                    threats = allThreats
                )
            }
        }.getOrElse {
            Result(
                false,
                it.message ?: it.javaClass.simpleName,
                SignatureVerifier.getExpectedSignerDigest().normalizeDigest(),
                emptyList()
            )
        }
        cached = System.currentTimeMillis() to result
        return result
    }

    fun isTrusted(context: Context): Boolean = verify(context).trusted

    /**
     * Terminates the current process immediately. This is a hard kill that
     * bypasses any Java-level exception handlers.
     */
    fun terminateWithContext(context: Context) {
        try {
            if (context is Activity) {
                context.finishAffinity()
            }
        } catch (_: Exception) {
        }
        Process.killProcess(Process.myPid())
        exitProcess(173)
    }

    fun terminate(activity: Activity) {
        runCatching { activity.finishAffinity() }
        exitProcess(173)
    }

    private fun signingCertificateDigests(context: Context): List<String> {
        val info = packageInfo(context)
        val certs = if (Build.VERSION.SDK_INT >= 28) {
            val signingInfo = info.signingInfo ?: return emptyList()
            val signers = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
            signers.orEmpty().map { it.toByteArray() }
        } else {
            @Suppress("DEPRECATION")
            info.signatures.orEmpty().map { it.toByteArray() }
        }
        return certs.map { bytes ->
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                "%02X".format(it)
            }
        }
    }

    private fun runtimeThreats(): List<String> {
        val threats = linkedSetOf<String>()
        if (Debug.isDebuggerConnected() ||
            Debug.waitingForDebugger()
        ) {
            threats += "debugger attached"
        }
        val tracer = tracerPid()
        if (tracer > 0) threats += "native tracer attached"
        val maps = procMapsIndicators()
        if (maps.isNotEmpty()) threats += maps
        val ports = openLocalInstrumentationPorts()
        if (ports.isNotEmpty()) threats += ports.map { "instrumentation port open: $it" }
        return threats.toList()
    }

    private fun tracerPid(): Int = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')
                ?.trim()
                ?.toIntOrNull() ?: 0
        }
    }.getOrDefault(0)

    private fun procMapsIndicators(): List<String> = runCatching {
        val needles =
            listOf(
                "frida",
                "gum-js-loop",
                "gadget",
                "xposed",
                "lsposed",
                "edxp",
                "zygisk",
                "substrate",
                // Non-root signature-bypass / injection frameworks we defend against:
                "apptweak",
                "guobao",
                "tweakme",
                "signaturekill",
                "sigkill",
                "yc/pm",
                "signaturefaker"
            )
        val hits = linkedSetOf<String>()
        File("/proc/self/maps").useLines { lines ->
            lines.take(8_000).forEach { line ->
                val lower = line.lowercase()
                needles.firstOrNull { lower.contains(it) }?.let {
                    hits +=
                        "runtime hook artifact: $it"
                }
            }
        }
        hits.toList()
    }.getOrDefault(emptyList())

    private fun openLocalInstrumentationPorts(): List<Int> {
        val ports = listOf(27042, 27043)
        return ports.filter { port ->
            runCatching {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 80)
                    true
                }
            }.getOrDefault(false)
        }
    }

    private fun packageInfo(context: Context): PackageInfo {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        }
    }

    private fun String.normalizeDigest(): String = normalizeSignerDigest(this)
}

internal fun normalizeSignerDigest(value: String): String = value.filter {
    it.isLetterOrDigit()
}.uppercase()
