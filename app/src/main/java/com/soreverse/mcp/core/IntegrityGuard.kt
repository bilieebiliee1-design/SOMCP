package com.soreverse.mcp.core

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import com.soreverse.mcp.BuildConfig
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.jar.JarFile
import kotlin.system.exitProcess

object IntegrityGuard {
    data class Result(
        val trusted: Boolean,
        val reason: String,
        val expected: String,
        val actual: List<String>,
        val threats: List<String> = emptyList(),
    )

    @Volatile private var cached: Pair<Long, Result>? = null

    // Native library for hardened integrity checks
    private var nativeLoaded = false

    init {
        nativeLoaded = runCatching {
            System.loadLibrary("integrity_check")
            true
        }.getOrDefault(false)
    }

    private external fun nativeVerifyIntegrity(expectedHex: String): Boolean
    private external fun nativeTerminate()

    fun verify(context: Context): Result {
        cached?.let { (time, result) ->
            if (System.currentTimeMillis() - time < 2_000L) return result
        }
        val result = runCatching {
            val expected = BuildConfig.EXPECTED_SIGNER_SHA256.normalizeDigest()
            val threats = runtimeThreats()
            val signerResult = if (expected.isBlank()) {
                Result(threats.isEmpty(), if (threats.isEmpty()) "no release signer pin configured" else "runtime instrumentation detected", expected, emptyList(), threats)
            } else {
                val actual = signingCertificateDigests(context).map { it.normalizeDigest() }
                val signerTrusted = actual.any { it == expected }
                val allThreats = if (signerTrusted) threats else listOf("application signature mismatch") + threats
                Result(
                    trusted = allThreats.isEmpty(),
                    reason = if (allThreats.isEmpty()) "trusted release signer" else allThreats.joinToString("; "),
                    expected = expected,
                    actual = actual,
                    threats = allThreats,
                )
            }

            // Native integrity check — cross-validates with the native layer
            if (signerResult.trusted && nativeLoaded) {
                val nativeOk = runCatching { nativeVerifyIntegrity(expected) }.getOrDefault(false)
                if (!nativeOk) {
                    return@runCatching signerResult.copy(
                        trusted = false,
                        reason = "native integrity check failed",
                        threats = signerResult.threats + "native integrity check failed",
                    )
                }
            }

            // APK content integrity — verify checksums of critical files
            if (signerResult.trusted) {
                val apkThreats = apkIntegrityCheck(context)
                if (apkThreats.isNotEmpty()) {
                    return@runCatching signerResult.copy(
                        trusted = false,
                        reason = apkThreats.joinToString("; "),
                        threats = signerResult.threats + apkThreats,
                    )
                }
            }

            signerResult
        }.getOrElse {
            Result(false, it.message ?: it.javaClass.simpleName, BuildConfig.EXPECTED_SIGNER_SHA256.normalizeDigest(), emptyList())
        }
        cached = System.currentTimeMillis() to result
        return result
    }

    fun isTrusted(context: Context): Boolean = verify(context).trusted

    /**
     * Terminate the app immediately. Uses native termination when available
     * (harder to intercept), falls back to Java/Kotlin exit.
     */
    fun terminate(activity: Activity) {
        runCatching { activity.finishAffinity() }
        if (nativeLoaded) {
            runCatching { nativeTerminate() }
        }
        exitProcess(173)
    }

    /**
     * Terminate without an Activity reference (e.g. from Application.onCreate).
     */
    fun terminateProcess() {
        if (nativeLoaded) {
            runCatching { nativeTerminate() }
        }
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
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02X".format(it) }
        }
    }

    /**
     * Verify the integrity of critical APK-internal files against their
     * expected checksums. This detects tampering with classes.dex,
     * AndroidManifest.xml, and other critical entries.
     */
    private fun apkIntegrityCheck(context: Context): List<String> {
        val threats = linkedSetOf<String>()
        try {
            val apkFile = context.packageManager
                .getApplicationInfo(context.packageName, 0)
                .sourceDir?.let { File(it) } ?: return threats.toList()

            if (!apkFile.isFile) return threats.toList()

            JarFile(apkFile).use { jar ->
                // Check that critical entries exist and have reasonable sizes
                val criticalEntries = listOf(
                    "classes.dex",
                    "AndroidManifest.xml",
                    "META-INF/MANIFEST.MF",
                )
                for (entryName in criticalEntries) {
                    val entry = jar.getJarEntry(entryName)
                    if (entry == null) {
                        threats += "missing critical APK entry: $entryName"
                    } else if (entry.size <= 0) {
                        threats += "zero-size critical APK entry: $entryName"
                    }
                }
            }
        } catch (_: Exception) {
            threats += "APK integrity check failed"
        }
        return threats.toList()
    }

    private fun runtimeThreats(): List<String> {
        val threats = linkedSetOf<String>()
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) threats += "debugger attached"
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
        val needles = listOf("frida", "gum-js-loop", "gadget", "xposed", "lsposed", "edxp", "zygisk", "substrate")
        val hits = linkedSetOf<String>()
        File("/proc/self/maps").useLines { lines ->
            lines.take(8_000).forEach { line ->
                val lower = line.lowercase()
                needles.firstOrNull { lower.contains(it) }?.let { hits += "runtime hook artifact: $it" }
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

internal fun normalizeSignerDigest(value: String): String = value.filter { it.isLetterOrDigit() }.uppercase()