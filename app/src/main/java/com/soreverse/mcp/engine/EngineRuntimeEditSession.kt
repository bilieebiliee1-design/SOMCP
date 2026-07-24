package com.soreverse.mcp.engine

import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.toJsonArray
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

internal fun EngineRuntime.editOpen(workspaceId: String): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val id = "so-edit-${UUID.randomUUID()}"
    ws.edits[id] = EditSession(id, ws.data.copyOf())
    ok(JSONObject().put("editSessionId", id).put("workspaceId", workspaceId).put("initialTargetVersion", sha256(ws.data)))
}

internal fun EngineRuntime.editSnapshot(workspaceId: String, editSessionId: String, label: String = ""): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val settings = SettingsStore(context)
    if (session.snapshots.size >= settings.maxSnapshots) session.snapshots.removeAt(0)
    val snap = Snapshot(session.revision, sha256(session.data), System.currentTimeMillis(), session.patches.size, session.data.copyOf())
    session.snapshots += snap
    ok(JSONObject()
        .put("snapshotIndex", session.snapshots.size - 1)
        .put("revision", snap.revision)
        .put("sha256", snap.sha256)
        .put("patchCount", snap.patchCount)
        .put("label", label)
        .put("totalSnapshots", session.snapshots.size))
}

internal fun EngineRuntime.editRollback(workspaceId: String, editSessionId: String, snapshotIndex: Int = -1): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    if (session.snapshots.isEmpty()) return@guarded err("NO_SNAPSHOT", "No snapshot exists in this session. Call session_history (action=snapshot) first.")
    val idx = if (snapshotIndex < 0) session.snapshots.size - 1 else snapshotIndex
    if (idx !in session.snapshots.indices) return@guarded err("SNAPSHOT_NOT_FOUND", "Snapshot index $idx out of range [0, ${session.snapshots.size - 1}]", "snapshotIndex", snapshotIndex)
    val snap = session.snapshots[idx]
    val before = sha256(session.data)
    val keptPatches = session.patches.take(snap.patchCount)
    System.arraycopy(snap.dataCopy, 0, session.data, 0, session.data.size)
    session.revision = snap.revision
    session.patches.clear()
    session.patches += keptPatches
    session.undone.clear()
    pageStore.clear()
    searchCache.clear()
    ok(JSONObject()
        .put("rolledBackTo", idx)
        .put("beforeSha256", before)
        .put("afterSha256", snap.sha256)
        .put("revision", session.revision)
        .put("patchCount", session.patches.size)
        .put("newTargetVersion", sha256(session.data)))
}

internal fun EngineRuntime.editUndo(workspaceId: String, editSessionId: String, count: Int = 1): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    if (session.patches.isEmpty()) return@guarded err("NOTHING_TO_UNDO", "No patches to undo in this session")
    val n = count.coerceIn(1, session.patches.size)
    val undone = JSONArray()
    repeat(n) {
        val p = session.patches.removeAt(session.patches.lastIndex)
        val oldBytes = p.oldHex.split(' ').filter { it.isNotBlank() }.map { it.toInt(16).toByte() }.toByteArray()
        if (p.fileOffset in 0..(session.data.size - oldBytes.size)) System.arraycopy(oldBytes, 0, session.data, p.fileOffset, oldBytes.size)
        session.undone += p
        undone.put(PatchByteUtils.patchJson(p))
    }
    session.revision = (session.revision - n).coerceAtLeast(0)
    pageStore.clear()
    searchCache.clear()
    ok(JSONObject()
        .put("undoneCount", n)
        .put("undone", undone)
        .put("remainingPatches", session.patches.size)
        .put("newTargetVersion", sha256(session.data)))
}

internal fun EngineRuntime.editRedo(workspaceId: String, editSessionId: String, count: Int = 1): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    if (session.undone.isEmpty()) return@guarded err("NOTHING_TO_REDO", "No undone patches to redo in this session")
    val n = count.coerceIn(1, session.undone.size)
    val redone = JSONArray()
    repeat(n) {
        val p = session.undone.removeAt(session.undone.lastIndex)
        val newBytes = p.newHex.split(' ').filter { it.isNotBlank() }.map { it.toInt(16).toByte() }.toByteArray()
        if (newBytes.isNotEmpty() && p.fileOffset in 0..(session.data.size - newBytes.size)) System.arraycopy(newBytes, 0, session.data, p.fileOffset, newBytes.size)
        session.patches += p
        redone.put(PatchByteUtils.patchJson(p))
    }
    session.revision += n
    pageStore.clear()
    searchCache.clear()
    ok(JSONObject()
        .put("redoneCount", n)
        .put("redone", redone)
        .put("remainingUndone", session.undone.size)
        .put("activePatches", session.patches.size)
        .put("newTargetVersion", sha256(session.data)))
}

internal fun EngineRuntime.editReset(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val beforePatches = session.patches.size
    val beforeUndone = session.undone.size
    val beforeSnapshots = session.snapshots.size
    System.arraycopy(ws.data, 0, session.data, 0, session.data.size)
    session.patches.clear()
    session.undone.clear()
    session.snapshots.clear()
    session.revision = 0
    pageStore.clear()
    searchCache.clear()
    ok(JSONObject()
        .put("reset", true)
        .put("clearedPatches", beforePatches)
        .put("clearedUndone", beforeUndone)
        .put("clearedSnapshots", beforeSnapshots)
        .put("newTargetVersion", sha256(session.data)))
}

internal fun EngineRuntime.maybeAutoSnapshot(session: EditSession, trigger: String, settings: SettingsStore) {
    if (!settings.autoSnapshotBeforeEdit) return
    if (session.snapshots.size >= settings.maxSnapshots) session.snapshots.removeAt(0)
    session.snapshots += Snapshot(session.revision, sha256(session.data), System.currentTimeMillis(), session.patches.size, session.data.copyOf())
    AppLog.i("Auto-snapshot (trigger=$trigger) rev=${session.revision} patches=${session.patches.size}")
}

internal fun EngineRuntime.maybeAutoPersist(workspaceId: String, session: EditSession, settings: SettingsStore): JSONObject? {
    if (!settings.editAutoPersist) return null
    return runCatching {
        val dir = auditDir()
        val existing = dir.listFiles { f -> f.isFile && f.name.startsWith("${session.id}-") }?.toList() ?: emptyList()
        if (existing.size >= settings.maxAudits) existing.sortedBy { it.lastModified() }.take(existing.size - settings.maxAudits + 1).forEach { it.delete() }
        val ts = System.currentTimeMillis()
        val file = File(dir, "${session.id}-auto-$ts.json")
        val payload = JSONObject()
            .put("workspaceId", workspaceId)
            .put("editSessionId", session.id)
            .put("persistedAt", ts)
            .put("auto", true)
            .put("revision", session.revision)
            .put("activePatchCount", session.patches.size)
            .put("currentTargetVersion", sha256(session.data))
            .put("patches", session.patches.mapIndexed { i, p -> PatchByteUtils.patchJson(p).put("index", i) }.toJsonArray())
        file.writeText(payload.toString(2))
        JSONObject().put("autoPersistPath", file.absolutePath)
    }.getOrElse { e -> AppLog.w("auto-persist failed: ${e.message}"); null }
}

internal fun EngineRuntime.editCheck(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val bytes = session.data
    val failures = JSONArray()
    val warnings = JSONArray()
    runCatching { lief.parse(bytes) }.getOrElse {
        return@guarded ok(JSONObject().put("status", "failed").put("failures", JSONArray().put(JSONObject().put("code", "ELF_CORRUPTED").put("message", it.message ?: "ELF parse failed"))).put("warnings", JSONArray()).put("claimedPatches", session.patches.size).put("effectivePatches", 0))
    }
    val settings = SettingsStore(context)
    val claimed = session.patches.size
    var emptyPatches = 0
    var stalePatches = 0
    if (settings.editCheckDeep) {
        session.patches.forEachIndexed { idx, p ->
            if (p.newHex.isBlank()) {
                emptyPatches++
                failures.put(JSONObject().put("code", "EMPTY_PATCH").put("message", "Patch #$idx (${p.kind}) at ${p.fileOffset} has empty newHex — claimed but never written").put("index", idx).put("kind", p.kind).put("fileOffset", p.fileOffset))
            } else {
                val current = runCatching {
                    val off = p.fileOffset
                    val len = p.newHex.split(' ').filter { it.isNotBlank() }.size
                    if (off in 0..(bytes.size - len)) PatchByteUtils.hexBytes(bytes.copyOfRange(off, off + len)) else ""
                }.getOrDefault("")
                if (current.isNotBlank() && current != p.newHex) {
                    stalePatches++
                    warnings.put(JSONObject().put("code", "STALE_PATCH").put("message", "Patch #$idx at ${hex(p.fileOffset.toLong())} was overwritten by a later edit").put("index", idx).put("expected", p.newHex).put("actual", current))
                }
            }
        }
    }
    val diffRanges = JSONArray()
    var i = 0
    while (i < ws.data.size && i < session.data.size && diffRanges.length() < 500) {
        if (ws.data[i] == session.data[i]) { i++; continue }
        val start = i
        while (i < ws.data.size && i < session.data.size && ws.data[i] != session.data[i]) i++
        diffRanges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start))
    }
    val effective = diffRanges.length()
    if (settings.editCheckDeep && claimed > 0 && effective == 0) warnings.put(JSONObject().put("code", "NO_EFFECTIVE_CHANGES").put("message", "Session claims $claimed patch(es) but zero effective byte ranges differ from the original SO"))
    if (settings.editCheckDeep && emptyPatches > 0) warnings.put(JSONObject().put("code", "EMPTY_PATCHES_SUMMARY").put("message", "$emptyPatches of $claimed patch(es) have empty newHex (no-op writes)").put("emptyPatchCount", emptyPatches))
    val status = if (failures.length() > 0) "failed" else if (warnings.length() > 0) "warning" else "ok"
    ok(JSONObject()
        .put("status", status)
        .put("failures", failures)
        .put("warnings", warnings)
        .put("claimedPatches", claimed)
        .put("effectivePatches", effective)
        .put("emptyPatches", emptyPatches)
        .put("stalePatches", stalePatches)
        .put("diffRangeCount", effective)
        .put("targetVersion", sha256(session.data)))
}
