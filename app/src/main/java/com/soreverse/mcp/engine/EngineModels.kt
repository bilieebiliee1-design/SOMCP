package com.soreverse.mcp.engine

import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

data class Workspace(
    val id: String,
    val source: SoSource,
    val data: ByteArray,
    val elf: ElfFile,
    val temporary: Boolean,
    val originalSha256: String,
    val analysisInputSource: String,
    val structureRecovery: JSONObject,
    val edits: MutableMap<String, EditSession> = ConcurrentHashMap(),
)

internal data class SourceSummary(
    val architecture: String,
    val bits: Int,
    val endian: String,
    val hasDebugInfo: Boolean,
    val stripped: Boolean,
)

internal data class PageState(
    val field: String,
    val items: List<JSONObject>,
    val offset: Int,
    val limit: Int,
)

internal data class DisasmCursorState(
    val workspaceId: String,
    val editSessionId: String,
    val locator: String,
    val byteOffset: Int,
    val limit: Int,
    val maxBytes: Int,
)

data class EditSession(
    val id: String,
    val data: ByteArray,
    var revision: Int = 0,
    val patches: MutableList<PatchRecord> = mutableListOf(),
    val snapshots: MutableList<Snapshot> = mutableListOf(),
    val undone: MutableList<PatchRecord> = mutableListOf(),
)

internal data class EmulatorSession(
    val id: String,
    val workspaceId: String,
    val editSessionId: String,
    val architecture: String,
    val data: ByteArray,
    val live: UnidbgEmulator.LiveSession? = null,
    val createdAt: Long = System.currentTimeMillis(),
)

data class Snapshot(
    val revision: Int,
    val sha256: String,
    val timeMillis: Long,
    val patchCount: Int,
    val dataCopy: ByteArray,
)

data class PatchRecord(
    val timeMillis: Long,
    val kind: String,
    val locator: String,
    val fileOffset: Int,
    val oldHex: String,
    val newHex: String,
    val asm: String = "",
)
