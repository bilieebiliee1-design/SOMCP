/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (C) 2026 bilieebiliee1-design
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 */

package com.soreverse.mcp.core

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.os.Process
import com.soreverse.mcp.nativecore.NativeProbe
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

    /** Failure recorded by [enforceEarly]; consumed (fail-closed) by [enforce]. */
    @Volatile private var earlyNativeFailure: String? = null

    /**
     * Runs all checks (Java PackageManager + native filesystem-level probe) and
     * terminates the process if any check fails.
     *
     * This is the main entry point for startup enforcement.
     * It should be called once during Application.onCreate().
     *
     * The reason for two layers of checking:
     * - Runtime patching tools replace the package metadata returned through
     *   the Java PackageManager Binder interface, so a Java-level check alone
     *   can be defeated.
     * - The native probe reads the package file directly from the filesystem
     *   and extracts the record embedded in the META-INF PKCS7 entry, a path
     *   that a Binder-level replacement cannot reach.
     * - Together they provide defense in depth: an attacker would have to
     *   intervene in BOTH the Java PackageManager AND the native JNI bridge.
     *
     * Those same tools install their hook inside attachBaseContext(), so the
     * native probe additionally runs from [enforceEarly] at that exact
     * lifecycle point, and is repeated periodically at runtime so a one-shot or
     * timing-based bypass does not survive past startup.
     */
    fun enforce(context: Context) {
        // 0. Consume any failure the attachBaseContext-time gate recorded. It
        //    was deliberately non-fatal there (no crash reporter yet), but it
        //    is authoritative by the time onCreate runs: fail closed.
        val earlyFailure = earlyNativeFailure
        earlyNativeFailure = null

        // 1. Java-level check (readable through the Binder interface)
        val javaResult = inspect(context)
        val javaPass = javaResult.trusted

        // 2. Native-level check (reads the package file directly)
        val nativePass = NativeProbe.matches(context)

        // 2b. Native v2/v3 (Signing Block) identity check. Independently reads
        //     the record stored in the v2/v3 block so a scheme-confusion repack
        //     (preserved v1 entries + re-signed v2/v3) cannot pass the
        //     filesystem-level v1 check.
        val v234Pass = NativeProbe.matchesV234(context)

        // 3. Native package-id pin (rejects repackaged builds that changed
        //    applicationId, even if the Java layer reports a spoofed name).
        val packagePass = NativeProbe.matchesId(context)

        // 4. Native archive probe (ZIP structure + critical entries + dex CRC)
        val probeCode = NativeProbe.probeArchive(context)
        val probePass = probeCode == NativeProbe.ProbeCode.OK

        // 5. Native cryptographic verification of the v2/v3 signature record.
        //    Steps 2/2b only prove that the signing block *names* the pinned
        //    signer: the block is a blob, so editing the file content and
        //    leaving the original signature record (and the digests recorded in
        //    it) in place passes both - it installs wherever the installer's own
        //    signature verification is bypassed. This step verifies the
        //    signature with the pinned signer's key and recomputes the signed
        //    content digest, which rejects exactly that repack.
        val blockCode = NativeProbe.verifyBlock(context)
        val blockPass = !NativeProbe.isTamper(blockCode)

        if (earlyFailure != null ||
            !javaPass ||
            !nativePass ||
            !v234Pass ||
            !packagePass ||
            !probePass ||
            !blockPass
        ) {
            val reasons = mutableListOf<String>()
            if (earlyFailure != null) {
                reasons.add("Early gate (attachBaseContext): $earlyFailure")
            }
            if (!javaPass) reasons.add("Java: ${javaResult.reason}")
            if (!nativePass) {
                reasons.add(
                    "Native: build identity differs from the pinned one"
                )
            }
            if (!v234Pass) {
                reasons.add(
                    "Native: v2/v3 identity record missing or mismatched"
                )
            }
            if (!packagePass) {
                reasons.add("Native: package id does not match the pinned value")
            }
            if (!probePass) {
                reasons.add("Native: archive probe failed (code=0x${probeCode.toString(16)})")
            }
            if (!blockPass) {
                reasons.add(
                    "Native: v2/v3 signature or content digest mismatch " +
                        "(code=0x${blockCode.toString(16)})"
                )
            }
            AppLog.e("INTEGRITY ENFORCEMENT FAILED: ${reasons.joinToString("; ")}")
            terminateWithContext(context)
            return
        }

        // 6. Keep re-checking at runtime so later tampering is caught.
        schedulePeriodicRecheck(context.applicationContext ?: context)
    }

    /**
     * Lightweight early gate executed from Application.attachBaseContext().
     * Only the native filesystem-level checks run here (identity digest,
     * package-id pin, archive probe): reading the package file directly
     * bypasses the Binder-level replacement that runtime patching tools install
     * at exactly this lifecycle point.
     *
     * NOTE: this gate is NON-FATAL on failure. At attachBaseContext() the app
     * has neither initialized AppLog nor installed CrashReporter, so a hard
     * kill (Process.killProcess) here produced no diagnosable evidence and
     * reboot-looped the app on any transient or false mismatch - the root cause
     * of the startup-crash issue. We therefore only record the mismatch here;
     * the authoritative kill happens in Application.onCreate() via [enforce],
     * which re-runs the same native checks after AppLog has been initialized
     * and logs the exact reason before terminating. The failure is recorded in
     * [earlyNativeFailure] so [enforce] cannot proceed past it even if the
     * state is somehow transient (fail-closed accumulation).
     */
    fun enforceEarly(context: Context) {
        val failures = mutableListOf<String>()
        if (!NativeProbe.matches(context)) failures += "native identity"
        if (!NativeProbe.matchesV234(context)) failures += "native v2/v3 identity"
        if (!NativeProbe.matchesId(context)) failures += "package id pin"
        val probeCode = NativeProbe.probeArchive(context)
        if (probeCode != NativeProbe.ProbeCode.OK) {
            failures += "archive probe (code=0x${probeCode.toString(16)})"
        }
        if (failures.isNotEmpty()) {
            earlyNativeFailure = failures.joinToString("; ")
            AppLog.w(
                "INTEGRITY (early) $earlyNativeFailure mismatch detected; " +
                    "deferring termination to onCreate (attachBaseContext has no crash reporter)"
            )
        }
    }

    /**
     * Schedules a randomized-interval background re-check. Using random delays
     * makes a deterministic "bypass the startup check, then hook later" plan
     * much harder to time accurately.
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
                // The native probe is the trustworthy one; the Java read cannot
                // be faked but can be intercepted, so it is cross-checked too.
                val nativeOk = NativeProbe.matches(context)
                val javaOk = inspect(context).trusted
                val v234Ok = NativeProbe.matchesV234(context)
                val packageOk = NativeProbe.matchesId(context)
                val probeOk =
                    NativeProbe.probeArchive(context) ==
                        NativeProbe.ProbeCode.OK
                // Signature + content-digest verification is the only check that
                // notices content edited under a preserved signature record, so
                // it runs on every re-check as well.
                val blockOk = !NativeProbe.isTamper(NativeProbe.verifyBlock(context))
                if (!nativeOk || !javaOk || !v234Ok || !packageOk || !probeOk || !blockOk) {
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

    fun inspect(context: Context): Result {
        cached?.let { (time, result) ->
            if (System.currentTimeMillis() - time < 2_000L) return result
        }
        val result = runCatching {
            val expected = NativeProbe.pinnedFingerprint().normalizeDigest()
            val threats = runtimeThreats(context)
            if (expected.isBlank()) {
                Result(
                    threats.isEmpty(),
                    if (threats.isEmpty()) "no pinned identity configured" else "runtime instrumentation detected",
                    expected,
                    emptyList(),
                    threats
                )
            } else {
                val actual = installFingerprints(context).map { it.normalizeDigest() }
                val identityTrusted = actual.any { it == expected }
                val allThreats = if (identityTrusted) {
                    threats
                } else {
                    listOf("application identity mismatch") +
                        threats
                }
                Result(
                    trusted = allThreats.isEmpty(),
                    reason = if (allThreats.isEmpty()) {
                        "pinned identity matched"
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
                NativeProbe.pinnedFingerprint().normalizeDigest(),
                emptyList()
            )
        }
        cached = System.currentTimeMillis() to result
        return result
    }

    /**
     * Gate used by the service and boot entry points.
     *
     * [inspect] alone reads the package metadata through PackageManager, which a
     * runtime patching framework can substitute; the native identity checks read
     * the package file itself, so they are required here too. The full
     * cryptographic verification (with its content-digest pass over the whole
     * file) is deliberately not part of this path - it runs at startup and on
     * every periodic re-check.
     */
    fun isTrusted(context: Context): Boolean = inspect(context).trusted &&
        runCatching {
            NativeProbe.matches(context) &&
                NativeProbe.matchesV234(context) &&
                NativeProbe.matchesId(context)
        }.getOrDefault(false)

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

    private fun installFingerprints(context: Context): List<String> {
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

    private fun runtimeThreats(context: Context): List<String> {
        val threats = linkedSetOf<String>()
        if (Debug.isDebuggerConnected() ||
            Debug.waitingForDebugger()
        ) {
            threats += "debugger attached"
        }
        val tracer = tracerPid()
        if (tracer > 0) threats += "native tracer attached"
        creatorIntegrityThreat()?.let { threats += it }
        factoryHijackThreat(context)?.let { threats += it }
        applicationClassThreat(context)?.let { threats += it }
        lspatchClassLoaderThreat(context)?.let { threats += it }
        lspatchMetaDataThreat(context)?.let { threats += it }
        val maps = procMapsIndicators()
        if (maps.isNotEmpty()) threats += maps
        val ports = openLocalInstrumentationPorts()
        if (ports.isNotEmpty()) threats += ports.map { "instrumentation port open: $it" }
        return threats.toList()
    }

    /**
     * Detects a Parcel/Creator substitution of the PackageManager result
     * (SoLab "normal"/"original_apk" signature-bypass templates, DPatch's
     * loader): these frameworks install their own Creator class as
     * [PackageInfo.CREATOR] so every getPackageInfo() response is rewritten
     * with the original signatures during unparceling. The genuine Creator is
     * a framework class loaded by the boot classloader (reported as null);
     * anything the repack ships is loaded by an app-visible classloader.
     */
    private fun creatorIntegrityThreat(): String? = runCatching {
        val creator = PackageInfo::class.java.getField("CREATOR").get(null)
        when {
            creator == null -> "PackageInfo.CREATOR is null"

            creator.javaClass.classLoader != null ->
                "PackageInfo.CREATOR replaced by a non-boot classloader"

            else -> null
        }
    }.getOrNull()

    /**
     * DPatch takes over process startup by rewriting the manifest's
     * appComponentFactory (to com.pandora.core.AppFactory) before the app's
     * own code ever runs. This app declares no component factory, so any
     * non-empty value means the installed manifest was hijacked.
     */
    private fun factoryHijackThreat(context: Context): String? = runCatching {
        val factory = context.applicationInfo?.appComponentFactory
        if (!factory.isNullOrEmpty()) {
            "foreign appComponentFactory declared (value withheld)"
        } else {
            null
        }
    }.getOrNull()

    /**
     * A proxy Application that subclasses ours (so the manifest entry still
     * reaches our code) is caught by exact-class identity: the object passed
     * to attachBaseContext/onCreate must be precisely [android.app.Application]
     * of the declared class, not a repack's subclass installing hooks first.
     * Only applies while [context] is the Application instance itself; an
     * Activity context carries no information about the Application class.
     */
    private fun applicationClassThreat(context: Context): String? {
        if (context !is android.app.Application) return null
        val expected = "com.soreverse.mcp.SoReverseApplication"
        return if (context.javaClass.name != expected) {
            "application instance class is not the declared one"
        } else {
            null
        }
    }

    /**
     * LSPatch (and metaloader derivatives) inject their payload by rewriting the
     * manifest appComponentFactory and loading their Java side from
     * assets/lspatch/loader.dex through an InMemoryDexClassLoader placed on the
     * app's classloader parent chain. The genuine build can never resolve that
     * class, so a successful load means the loader is present in this process.
     */
    private fun lspatchClassLoaderThreat(context: Context): String? = runCatching {
        val loader = context.classLoader
        // Class.forName(String, boolean, ClassLoader) - do NOT initialize the
        // class: only its resolvability is the evidence.
        Class.forName("org.lsposed.lspatch.loader.LSPApplication", false, loader)
        "lspatch loader class resolvable from the app classloader chain"
    }.getOrNull()

    /**
     * LSPatch's patcher writes its bypass config (sigBypassLevel, the original
     * signature, the hijacked factory name) into the manifest as
     * <meta-data android:name="lspatch">. The genuine build declares no such
     * key, and the manifest's own integrity is already covered by the native
     * content-digest check, so a visible key here is unambiguous evidence.
     */
    private fun lspatchMetaDataThreat(context: Context): String? = runCatching {
        val meta = context.applicationInfo?.metaData
        if (meta != null && meta.containsKey("lspatch")) {
            "lspatch meta-data present in the active manifest"
        } else {
            null
        }
    }.getOrNull()

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
                // Non-root runtime-patching / injection frameworks we defend against:
                "apptweak",
                "guobao",
                "tweakme",
                marked("7369676e61747572656b696c6c"),
                "yc/pm",
                marked("7369676e617475726566616b6572"),
                // DPatch payload + the inline/JNI hook engines it embeds, and
                // the SoLab signature-bypass native helper:
                "pandora",
                "dobby",
                "lsplant",
                marked("736f6c61625f7369676e6174757265"),
                // LSPatch: liblspatch.so / the cache/lspatch origin.apk redirect
                // target / its in-memory loader dex and the Xposed API surface
                // it ships:
                "lspatch",
                "lspd",
                marked("64652e726f6276"),
                "loader.dex",
                "origin.apk"
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

    /**
     * Decodes a hex-encoded marker at runtime. Keeping these markers out of the
     * literal pool avoids leaving their plain text in the compiled artifacts.
     */
    private fun marked(hex: String): String = hex.chunked(2).map { it.toInt(16).toChar() }.joinToString("")

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

    private fun String.normalizeDigest(): String = normalizeFingerprint(this)
}

internal fun normalizeFingerprint(value: String): String = value.filter {
    it.isLetterOrDigit()
}.uppercase()
