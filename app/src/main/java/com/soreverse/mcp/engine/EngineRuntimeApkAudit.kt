// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Runtime adapters for the APK audit tools (apk_sig_verify, apk_cert_info,
// apk_zip_anomaly, apk_abi_coverage). The input gate mirrors analyzeApk:
// path allow-list, size limit, memory guard, self-artifact rejection and the
// ZIP magic check happen before any parsing.
package com.soreverse.mcp.engine

import com.soreverse.mcp.core.MemoryGuard
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeProbe
import java.io.File
import org.json.JSONObject

/** Loads APK bytes for the audit tools; returns the error envelope on any gate failure. */
internal fun EngineRuntime.loadApkAuditInput(path: String): Pair<ByteArray, JSONObject?> {
    if (path.isBlank()) return ByteArray(0) to err("INVALID_ARGUMENT", "APK path is required", "path", path)
    // Reject absolute paths and traversal segments before any filesystem or SAF
    // access: the work-directory reader resolves by relative path only, and a
    // canonical form keeps the allow-list check meaningful.
    val normalized = path.replace('\\', '/')
    val segments = normalized.split('/').filter { it.isNotEmpty() && it != "." }
    val traversal = normalized.startsWith("/") ||
        normalized.contains(":") ||
        segments.any { it == ".." }
    if (traversal) {
        return ByteArray(0) to err("PATH_NOT_ALLOWED", "APK path must be relative and stay inside its root", "path", path)
    }
    val local = File(path)
    if (local.isFile && !isAllowedLocalInput(local)) {
        return ByteArray(0) to err(
            "PATH_NOT_ALLOWED",
            "Local APK path must be inside the app's private/external files directory or the selected work directory",
            "path",
            path
        )
    }
    if (local.isFile && local.length() > ApkAnalyzer.MAX_INPUT_BYTES) {
        return ByteArray(0) to err(
            "APK_LIMIT_EXCEEDED",
            "APK exceeds ${ApkAnalyzer.MAX_INPUT_BYTES / 1024 / 1024} MiB input limit",
            "path",
            path
        )
    }
    val bytes = try {
        if (local.isFile) {
            MemoryGuard.ensureAnalysisMemory(local.length(), "Analyzing APK ${local.name}")
            local.readBytes()
        } else {
            val dir = workDir
                ?: return ByteArray(0) to err(
                    "WORK_DIRECTORY_NOT_SELECTED",
                    "APK path is not a local file and no work directory is selected",
                    "path",
                    path
                )
            MemoryGuard.ensureAnalysisMemory(
                dir.fileSize(path) ?: ApkAnalyzer.MAX_INPUT_BYTES,
                "Analyzing APK $path"
            )
            dir.readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
        }
    } catch (error: ApkAnalysisLimitException) {
        return ByteArray(0) to err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
    if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4b.toByte()) {
        return ByteArray(0) to err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
    }
    if (isSelfApkBytes(bytes) || (local.isFile && NativeProbe.isOwnApk(local.absolutePath))) {
        return ByteArray(0) to selfForbidden("apk:$path")
    }
    return bytes to null
}

private fun EngineRuntime.apkAuditOk(path: String, bytes: ByteArray, payload: JSONObject): JSONObject = ok(
    JSONObject()
        .put("path", path)
        .put("size", bytes.size)
        .put("sha256", sha256(bytes))
        .put("audit", payload)
)

internal fun EngineRuntime.apkSigVerify(path: String): JSONObject = guarded {
    val (bytes, error) = loadApkAuditInput(path)
    if (error != null) return@guarded error
    apkAuditOk(path, bytes, ApkSigTools.verify(bytes))
}

internal fun EngineRuntime.apkCertInfo(path: String): JSONObject = guarded {
    val (bytes, error) = loadApkAuditInput(path)
    if (error != null) return@guarded error
    apkAuditOk(path, bytes, ApkSigTools.certInfo(bytes))
}

internal fun EngineRuntime.apkZipAnomaly(path: String): JSONObject = guarded {
    val (bytes, error) = loadApkAuditInput(path)
    if (error != null) return@guarded error
    apkAuditOk(path, bytes, ApkSigTools.zipAnomalies(bytes))
}

internal fun EngineRuntime.apkAbiCoverage(path: String): JSONObject = guarded {
    val (bytes, error) = loadApkAuditInput(path)
    if (error != null) return@guarded error
    apkAuditOk(path, bytes, ApkSigTools.abiCoverage(bytes))
}
