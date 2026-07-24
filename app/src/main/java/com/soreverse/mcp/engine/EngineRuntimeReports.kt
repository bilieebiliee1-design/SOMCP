package com.soreverse.mcp.engine

import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.toJsonArray
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.math.min

internal fun EngineRuntime.analysisReport(workspaceId: String, editSessionId: String = "", writeToFile: Boolean = true): JSONObject = guarded {
    val resolvedId = resolveWorkspaceId(workspaceId, "")
    val ws = workspaces[resolvedId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found", "workspaceId", workspaceId)
    val elf = elfFor(resolvedId, editSessionId)
    val data = dataFor(resolvedId, editSessionId)
    val stats = readStats(resolvedId, editSessionId)
    val sections = list(resolvedId, editSessionId, "sections", "", 5000).optJSONArray("items") ?: JSONArray()
    val dynsyms = list(resolvedId, editSessionId, "dynsyms", "", 5000).optJSONArray("items") ?: JSONArray()
    val strings = strings(resolvedId, editSessionId, "", "", 500, "", "").optJSONArray("items") ?: JSONArray()
    val functions = rzFunctions(resolvedId, editSessionId).optJSONArray("functions") ?: JSONArray()
    val crypto = rzScanCrypto(resolvedId, editSessionId)
    val recommendations = JSONArray()
    if (elf.sections.isEmpty()) recommendations.put("No section headers detected: run edit_fix_sections before section-based patching")
    if (functions.length() == 0) recommendations.put("No Rizin functions detected: use read_disasm(addr=<.text.virtualAddr>) and analyze_elf dynsyms/sections")
    if ((crypto.optJSONArray("items")?.length() ?: 0) > 0) recommendations.put("Crypto-like constants or high-entropy regions detected: inspect analyze_crypto findings")
    if ((elf.dynSymbols.count { it.name == "JNI_OnLoad" || it.name.startsWith("Java_") }) > 0) recommendations.put("JNI exports detected: use emulate_call for JNI_OnLoad or Java_* validation")
    val payload = JSONObject()
        .put("workspaceId", resolvedId)
        .put("editSessionId", editSessionId)
        .put("generatedAt", System.currentTimeMillis())
        .put("source", JSONObject()
            .put("path", ws.source.path)
            .put("name", ws.source.name)
            .put("source", ws.source.source)
            .put("apkPath", ws.source.apkPath)
            .put("apkEntry", ws.source.apkEntry)
            .put("abi", ws.source.abi))
        .put("architecture", elf.architecture)
        .put("checksums", checksums(data))
        .put("stats", stats)
        .put("sections", sections)
        .put("programHeaders", JSONArray(elf.programHeaders.map { EngineJson.phJson(it) }))
        .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { EngineJson.dynJson(it) }))
        .put("dynsyms", dynsyms)
        .put("imports", list(resolvedId, editSessionId, "imports", "", 5000).optJSONArray("items") ?: JSONArray())
        .put("relocations", list(resolvedId, editSessionId, "relocations", "", 5000).optJSONArray("items") ?: JSONArray())
        .put("strings", strings)
        .put("functions", functions)
        .put("crypto", crypto)
        .put("security", analyze(resolvedId, editSessionId).optJSONObject("security") ?: JSONObject())
        .put("recommendations", recommendations)
    val file = if (writeToFile) {
        val dir = reportDir()
        val safeName = ws.source.name.replace(Regex("[^A-Za-z0-9._-]"), "_")
        File(dir, "${safeName}.${System.currentTimeMillis()}.analysis-report.json").also { it.writeText(payload.toString(2)) }
    } else null
    ok(JSONObject().put("report", payload).put("written", file != null).put("reportPath", file?.absolutePath ?: JSONObject.NULL))
}

internal fun EngineRuntime.editAudit(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val patchesArr = JSONArray()
    session.patches.forEachIndexed { idx, p -> patchesArr.put(PatchByteUtils.patchJson(p).put("index", idx).put("active", true)) }
    val undoneArr = JSONArray()
    session.undone.forEachIndexed { idx, p -> undoneArr.put(PatchByteUtils.patchJson(p).put("index", idx).put("active", false)) }
    val snapshotsArr = JSONArray()
    session.snapshots.forEachIndexed { idx, s ->
        snapshotsArr.put(JSONObject()
            .put("index", idx)
            .put("revision", s.revision)
            .put("sha256", s.sha256)
            .put("patchCount", s.patchCount)
            .put("timeMillis", s.timeMillis))
    }
    val byKind = JSONObject()
    session.patches.groupBy { it.kind }.forEach { (kind, list) -> byKind.put(kind, list.size) }
    ok(JSONObject()
        .put("workspaceId", workspaceId)
        .put("editSessionId", editSessionId)
        .put("revision", session.revision)
        .put("activePatchCount", session.patches.size)
        .put("undonePatchCount", session.undone.size)
        .put("snapshotCount", session.snapshots.size)
        .put("patchesByKind", byKind)
        .put("patches", patchesArr)
        .put("undonePatches", undoneArr)
        .put("snapshots", snapshotsArr)
        .put("currentTargetVersion", sha256(session.data)))
}

internal fun EngineRuntime.listBuildOutputs(prefix: String = "", limit: Int = 200): JSONObject = guarded {
    val settings = SettingsStore(context)
    val dir = context.getExternalFilesDir(null) ?: context.filesDir
    val boundedLimit = limit.coerceIn(1, settings.maxBuildOutputs)
    val items = JSONArray()
    if (dir.exists()) {
        dir.listFiles { f -> f.isFile && (f.name.endsWith(".so", true) || f.name.endsWith(".patch-report.json", true)) }
            ?.sortedByDescending { it.lastModified() }
            ?.asSequence()
            ?.filter { prefix.isBlank() || it.name.startsWith(prefix, ignoreCase = true) }
            ?.take(boundedLimit)
            ?.forEach { f ->
                val isReport = f.name.endsWith(".patch-report.json", true)
                items.put(JSONObject()
                    .put("name", f.name)
                    .put("path", f.absolutePath)
                    .put("openPath", f.absolutePath)
                    .put("size", f.length())
                    .put("modified", f.lastModified())
                    .put("kind", if (isReport) "patch-report" else "so")
                    .put("canOpen", !isReport))
            }
    }
    val count = items.length()
    ok(JSONObject()
        .put("items", items)
        .put("usage", "Pass the path/openPath of any item with kind=so to so_open. patch-report items are JSON sidecars from build_so.")
        .put("directory", dir.absolutePath)
        .put("pagination", pagination(false, null, count, boundedLimit, count)))
}

internal fun EngineRuntime.auditDir(): File {
    val dir = File(context.getExternalFilesDir(null) ?: context.filesDir, "audits")
    if (!dir.exists()) dir.mkdirs()
    return dir
}

internal fun EngineRuntime.reportDir(): File {
    val dir = File(context.getExternalFilesDir(null) ?: context.filesDir, "reports")
    if (!dir.exists()) dir.mkdirs()
    return dir
}

internal fun EngineRuntime.persistAudit(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val settings = SettingsStore(context)
    if (!settings.auditPersist) return@guarded ok(JSONObject().put("persisted", false).put("reason", "auditPersist disabled"))
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val dir = auditDir()
    val existing = dir.listFiles { f -> f.isFile && f.name.startsWith("$editSessionId-") }?.toList() ?: emptyList()
    if (existing.size >= settings.maxAudits) existing.sortedBy { it.lastModified() }.take(existing.size - settings.maxAudits + 1).forEach { it.delete() }
    val ts = System.currentTimeMillis()
    val file = File(dir, "$editSessionId-$ts.json")
    val payload = JSONObject()
        .put("workspaceId", workspaceId)
        .put("editSessionId", editSessionId)
        .put("sourcePath", ws.source.path)
        .put("sourceSha256", sha256(ws.data))
        .put("persistedAt", ts)
        .put("revision", session.revision)
        .put("activePatchCount", session.patches.size)
        .put("undonePatchCount", session.undone.size)
        .put("snapshotCount", session.snapshots.size)
        .put("currentTargetVersion", sha256(session.data))
        .put("patches", session.patches.mapIndexed { i, p -> PatchByteUtils.patchJson(p).put("index", i).put("active", true) }.toJsonArray())
        .put("undonePatches", session.undone.mapIndexed { i, p -> PatchByteUtils.patchJson(p).put("index", i).put("active", false) }.toJsonArray())
        .put("snapshots", session.snapshots.mapIndexed { i, s -> JSONObject().put("index", i).put("revision", s.revision).put("sha256", s.sha256).put("patchCount", s.patchCount).put("timeMillis", s.timeMillis) }.toJsonArray())
    file.writeText(payload.toString(2))
    ok(JSONObject().put("persisted", true).put("path", file.absolutePath).put("size", file.length()).put("persistedAt", ts))
}

internal fun EngineRuntime.listAudits(prefix: String = "", limit: Int = 100): JSONObject = guarded {
    val settings = SettingsStore(context)
    val dir = auditDir()
    val bounded = limit.coerceIn(1, settings.maxAudits)
    val items = JSONArray()
    if (dir.exists()) {
        dir.listFiles { f -> f.isFile && f.name.endsWith(".json") && (prefix.isBlank() || f.name.startsWith(prefix)) }
            ?.sortedByDescending { it.lastModified() }
            ?.take(bounded)
            ?.forEach { f ->
                val meta = runCatching {
                    val obj = JSONObject(f.readText())
                    JSONObject()
                        .put("editSessionId", obj.optString("editSessionId"))
                        .put("workspaceId", obj.optString("workspaceId"))
                        .put("sourcePath", obj.optString("sourcePath"))
                        .put("revision", obj.optInt("revision"))
                        .put("activePatchCount", obj.optInt("activePatchCount"))
                        .put("undonePatchCount", obj.optInt("undonePatchCount"))
                        .put("snapshotCount", obj.optInt("snapshotCount"))
                        .put("persistedAt", obj.optLong("persistedAt"))
                        .put("currentTargetVersion", obj.optString("currentTargetVersion"))
                }.getOrDefault(JSONObject().put("editSessionId", f.nameWithoutExtension))
                items.put(meta.put("file", f.name).put("path", f.absolutePath).put("size", f.length()))
            }
    }
    ok(JSONObject().put("items", items).put("directory", dir.absolutePath).put("pagination", pagination(false, null, items.length(), bounded, items.length())))
}

internal fun EngineRuntime.loadAudit(file: String): JSONObject = guarded {
    val f = File(file)
    if (!f.exists() || !f.isFile) return@guarded err("AUDIT_NOT_FOUND", "Audit file not found: $file", "file", file)
    val obj = runCatching { JSONObject(f.readText()) }.getOrElse { return@guarded err("AUDIT_CORRUPTED", "Audit file is not valid JSON: ${it.message}", "file", file) }
    ok(obj.put("path", f.absolutePath))
}

internal fun EngineRuntime.diff(workspaceId: String, editSessionId: String, limit: Int, compareSessionId: String = "", compareWorkspaceId: String = ""): JSONObject = guarded {
    val settings = SettingsStore(context)
    val cap = limit.coerceIn(1, settings.maxCompareRanges)
    val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
    val baselineWs = if (compareWorkspaceId.isNotBlank()) workspaces[compareWorkspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Compare workspace not found") else ws
    val compareData = if (compareSessionId.isBlank()) ws.data else baselineWs.edits[compareSessionId]?.data ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Compare edit session not found: $compareSessionId")
    val ranges = JSONArray()
    var i = 0
    val maxSize = maxOf(compareData.size, session.data.size)
    while (i < maxSize && ranges.length() < cap) {
        if (i < compareData.size && i < session.data.size && compareData[i] == session.data[i]) {
            i++
            continue
        }
        val start = i
        while (i < maxSize && !(i < compareData.size && i < session.data.size && compareData[i] == session.data[i])) i++
        val old = if (start < compareData.size) compareData.copyOfRange(start, min(i, compareData.size)) else ByteArray(0)
        val next = if (start < session.data.size) session.data.copyOfRange(start, min(i, session.data.size)) else ByteArray(0)
        ranges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start).put("oldHex", PatchByteUtils.hexBytes(old)).put("newHex", PatchByteUtils.hexBytes(next)))
    }
    val result = JSONObject()
        .put("workspaceId", workspaceId)
        .put("editSessionId", editSessionId)
        .put("patchCount", session.patches.size)
        .put("patches", session.patches.map(PatchByteUtils::patchJson).toJsonArray())
        .put("diffRanges", ranges)
        .put("diffRangeCount", ranges.length())
        .put("targetVersion", sha256(session.data))
    if (compareSessionId.isNotBlank()) {
        result.put("compareSessionId", compareSessionId)
        result.put("compareWorkspaceId", compareWorkspaceId.ifBlank { workspaceId })
        result.put("compareTargetVersion", sha256(compareData))
        result.put("mode", "session_vs_session")
    } else {
        result.put("mode", "session_vs_original")
    }
    ok(result)
}

internal fun EngineRuntime.writePatchReport(workspaceId: String, session: EditSession, output: File): File {
    val report = File(output.parentFile, "${output.nameWithoutExtension}.patch-report.json")
    val ws = workspaces[workspaceId]
    val emptyPatches = session.patches.count { it.newHex.isBlank() }
    val diffRanges = JSONArray()
    if (ws != null) {
        var i = 0
        while (i < ws.data.size && i < session.data.size && diffRanges.length() < 500) {
            if (ws.data[i] == session.data[i]) { i++; continue }
            val start = i
            while (i < ws.data.size && i < session.data.size && ws.data[i] != session.data[i]) i++
            diffRanges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start))
        }
    }
    val payload = JSONObject()
        .put("workspaceId", workspaceId)
        .put("editSessionId", session.id)
        .put("sourcePath", ws?.source?.path ?: JSONObject.NULL)
        .put("outputPath", output.absolutePath)
        .put("revision", session.revision)
        .put("patchCount", session.patches.size)
        .put("claimedPatches", session.patches.size)
        .put("effectivePatches", diffRanges.length())
        .put("emptyPatches", emptyPatches)
        .put("snapshotCount", session.snapshots.size)
        .put("undonePatchCount", session.undone.size)
        .put("patches", session.patches.map(PatchByteUtils::patchJson).toJsonArray())
        .put("diffRanges", diffRanges)
        .put("snapshots", session.snapshots.mapIndexed { idx, s ->
            JSONObject().put("index", idx).put("revision", s.revision).put("sha256", s.sha256).put("patchCount", s.patchCount).put("timeMillis", s.timeMillis)
        }.toJsonArray())
        .put("checksums", checksums(session.data))
    report.writeText(payload.toString(2))
    return report
}
