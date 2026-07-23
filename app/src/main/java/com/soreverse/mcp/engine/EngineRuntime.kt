package com.soreverse.mcp.engine

import android.content.Context
import android.net.Uri
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.err
import org.json.JSONObject
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.concurrent.ConcurrentHashMap

internal class EngineRuntime(internal val context: Context) {
    internal val lief = LiefEngine()
    internal val xanso = XAnSoEngine(context)
    internal val unidbg = UnidbgEmulator(context)
    internal val blutter = BlutterCoordinator(context)
    internal var workDir: WorkDirectory? = null
    internal var workDirUri: Uri? = null
    internal var sources: List<SoSource> = emptyList()
    internal var sourceFingerprint: List<FileFingerprint> = emptyList()
    internal val sourceSummaryCache = ConcurrentHashMap<String, SourceSummary>()
    internal val workspaceBySourceKey = ConcurrentHashMap<String, String>()
    internal val pageStore = PageStore()
    internal val emulatorSessions = ConcurrentHashMap<String, EmulatorSession>()
    internal val searchCache = ConcurrentHashMap<String, List<JSONObject>>()
    internal val workspaces = ConcurrentHashMap<String, Workspace>()

    internal fun guarded(block: () -> JSONObject): JSONObject = try {
        block()
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        AppLog.e("Tool failed", error)
        val message = error.message ?: "Tool failed"
        when {
            message.startsWith("Workspace not found") && message.substringAfterLast(": ", "").isBlank() -> err("WORKSPACE_REQUIRED", "No workspaceId was provided. Call so_open first and use its returned workspaceId.", "workspaceId", "")
            message.startsWith("Workspace not found") -> err("WORKSPACE_NOT_FOUND", "$message. Call so_open again and use its returned workspaceId.", "workspaceId", message.substringAfterLast(": ", ""))
            message.startsWith("No work directory selected") -> err("WORK_DIRECTORY_NOT_SELECTED", message)
            message.startsWith("NOT_ELF_INPUT") -> err("NOT_ELF_INPUT", message.substringAfter(": ").ifBlank { "The selected entry is not an ELF SO file." })
            message.startsWith("SO path not found") -> err("SO_NOT_FOUND", message, "path", message.substringAfter(": ", ""))
            message.contains("Invalid URI", ignoreCase = true) -> err("INVALID_WORK_DIRECTORY", message)
            else -> err("ELF_CORRUPTED", message)
        }
    }

    internal fun hex(v: Long) = "0x${v.toString(16)}"
    internal fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    internal fun checksums(bytes: ByteArray) = JSONObject().put("sha256", sha256(bytes)).put("size", bytes.size)
}
