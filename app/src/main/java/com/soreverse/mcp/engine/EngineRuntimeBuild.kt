package com.soreverse.mcp.engine

import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

internal fun EngineRuntime.build(workspaceId: String, editSessionId: String, outputName: String, conflictStrategy: String = "", writeReport: Boolean? = null, writeToWorkDir: Boolean? = null): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val settings = SettingsStore(context)
    val strategy = (conflictStrategy.ifBlank { settings.outputConflictStrategy }).let { if (it == "overwrite") "overwrite" else "rename" }
    val out = resolveOutputFile(outputName.ifBlank { "patched.so" }, strategy)
    out.writeBytes(bytes)
    val session = workspaces[workspaceId]?.edits?.get(editSessionId)
    val report = if (session != null && (writeReport ?: settings.writePatchReport)) writePatchReport(workspaceId, session, out) else null
    AppLog.i("Built ${out.absolutePath}")
    val requestedWorkDirCopy = writeToWorkDir ?: settings.buildCopyToWorkDir
    val workDirCopy = workDirCopyResult(requestedWorkDirCopy) {
        writeCopyToWorkDirectory(out.nameWithoutExtension + ".so", bytes)
    }
    ok(JSONObject()
        .put("outputPath", out.absolutePath)
        .put("reportPath", report?.absolutePath ?: JSONObject.NULL)
        .put("workDirCopyPath", workDirCopy.opt("path") ?: JSONObject.NULL)
        .put("workDirCopy", workDirCopy)
        .put("writeToWorkDir", requestedWorkDirCopy)
        .put("warnings", if (requestedWorkDirCopy && !workDirCopy.optBoolean("ok")) JSONArray().put("workDirCopy failed: ${workDirCopy.optString("message")}") else JSONArray())
        .put("conflictStrategy", strategy)
        .put("size", out.length())
        .put("checksums", checksums(bytes))
        .put("openHint", "Pass outputPath to so_open, or call build_so (action=list) to enumerate built files."))
}

internal fun EngineRuntime.buildMany(workspaceId: String, editSessionId: String, outputs: JSONArray, conflictStrategy: String = "", writeReport: Boolean? = null, writeToWorkDir: Boolean? = null): JSONObject = guarded {
    if (outputs.length() == 0) return@guarded err("INVALID_ARGUMENT", "outputs array must not be empty", "outputs", outputs)
    val settings = SettingsStore(context)
    if (outputs.length() > settings.defaultBuildVariants) return@guarded err("TOO_MANY_VARIANTS", "outputs length ${outputs.length()} exceeds defaultBuildVariants ${settings.defaultBuildVariants}", "outputs", outputs.length())
    val bytes = dataFor(workspaceId, editSessionId)
    val strategy = (conflictStrategy.ifBlank { settings.outputConflictStrategy }).let { if (it == "overwrite") "overwrite" else "rename" }
    val session = workspaces[workspaceId]?.edits?.get(editSessionId)
    val results = JSONArray()
    for (i in 0 until outputs.length()) {
        val entry = outputs.optJSONObject(i)
        val name = entry?.optString("outputName")?.ifBlank { "patched_$i.so" } ?: "patched_$i.so"
        val useWorkDir = entry?.optBoolean("writeToWorkDir", writeToWorkDir ?: settings.buildCopyToWorkDir) ?: (writeToWorkDir ?: settings.buildCopyToWorkDir)
        val wantReport = entry?.let { if (it.has("writePatchReport")) it.optBoolean("writePatchReport") else (writeReport ?: settings.writePatchReport) } ?: (writeReport ?: settings.writePatchReport)
        val out = resolveOutputFile(name, strategy)
        out.writeBytes(bytes)
        val report = if (session != null && wantReport) writePatchReport(workspaceId, session, out) else null
        val workDirCopy = workDirCopyResult(useWorkDir) {
            writeCopyToWorkDirectory(out.nameWithoutExtension + ".so", bytes)
        }
        results.put(JSONObject()
            .put("index", i)
            .put("outputName", name)
            .put("outputPath", out.absolutePath)
            .put("reportPath", report?.absolutePath ?: JSONObject.NULL)
            .put("workDirCopyPath", workDirCopy.opt("path") ?: JSONObject.NULL)
            .put("workDirCopy", workDirCopy)
            .put("writeToWorkDir", useWorkDir)
            .put("warnings", if (useWorkDir && !workDirCopy.optBoolean("ok")) JSONArray().put("workDirCopy failed: ${workDirCopy.optString("message")}") else JSONArray())
            .put("size", out.length())
            .put("checksums", checksums(bytes)))
    }
    ok(JSONObject()
        .put("outputs", results)
        .put("outputCount", results.length())
        .put("conflictStrategy", strategy)
        .put("checksums", checksums(bytes))
        .put("openHint", "Pass any outputPath to so_open, or call build_so (action=list) to enumerate built files."))
}

private fun EngineRuntime.writeCopyToWorkDirectory(fileName: String, bytes: ByteArray): String? {
    val tree = workDirUri ?: error("work directory not configured")
    val dir = workDir ?: WorkDirectory(context, tree).also { workDir = it }
    if (!dir.isAccessible()) error("work directory is not accessible: $tree")
    val resolver = context.contentResolver
    val existing = runCatching { findSource(fileName) }.getOrNull()
    if (existing?.treeDocumentUri != null) {
        resolver.openOutputStream(existing.treeDocumentUri, "wt")?.use { it.write(bytes) }
            ?: error("cannot open existing workdir file for write: ${existing.treeDocumentUri}")
        return existing.path
    }
    val created = dir.writeRootFile(fileName, bytes)
    return created.path
}

internal fun EngineRuntime.snapshotBytes(workspaceId: String, editSessionId: String): Pair<ByteArray, String> {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    return bytes to elf.architecture
}

internal fun EngineRuntime.fixSections(workspaceId: String, editSessionId: String): JSONObject {
    if (!lief.available()) return err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
    val original = dataFor(workspaceId, editSessionId)
    val before = original.copyOf()
    val beforeHash = sha256(before)
    val elfBefore = lief.parse(before)
    val fixed = lief.fixSections(before)
    val afterHash = sha256(fixed)
    val diffRanges = PatchByteUtils.byteDiffRanges(before, fixed)
    if (fixed.contentEquals(before)) return ok(JSONObject().put("changed", false).put("message", "No section header reconstruction needed").put("sha256Before", beforeHash).put("sha256After", afterHash).put("diffRangeCount", 0))
    val elfAfter = lief.parse(fixed)
    val alreadyStructured = elfBefore.sections.isNotEmpty() && elfBefore.programHeaders.isNotEmpty() && elfBefore.dynamicEntries.isNotEmpty()
    val onlyCanonicalization = alreadyStructured && elfBefore.sections.size == elfAfter.sections.size && elfBefore.programHeaders.size == elfAfter.programHeaders.size && elfBefore.dynamicEntries.size == elfAfter.dynamicEntries.size && before.size == fixed.size
    if (onlyCanonicalization) return ok(JSONObject()
        .put("changed", false)
        .put("wouldChange", true)
        .put("message", "Section headers are already present and parseable; skipped LIEF canonicalization rewrite")
        .put("sha256Before", beforeHash)
        .put("sha256After", beforeHash)
        .put("candidateSha256After", afterHash)
        .put("diffRangeCount", diffRanges.length())
        .put("diffRanges", diffRanges)
        .put("beforeSections", elfBefore.sections.size)
        .put("afterSections", elfAfter.sections.size)
        .put("beforeProgramHeaders", elfBefore.programHeaders.size)
        .put("afterProgramHeaders", elfAfter.programHeaders.size)
        .put("beforeDynamicEntries", elfBefore.dynamicEntries.size)
        .put("afterDynamicEntries", elfAfter.dynamicEntries.size))
    val targetSession = editSessionId.takeIf { it.isNotBlank() }?.let { workspaces[workspaceId]?.edits?.get(it) }
    val sessionId = when {
        targetSession != null && targetSession.data.size == fixed.size -> {
            System.arraycopy(fixed, 0, targetSession.data, 0, fixed.size)
            targetSession.undone.clear()
            targetSession.revision++
            val firstDiff = diffRanges.optJSONObject(0)
            targetSession.patches += PatchRecord(System.currentTimeMillis(), "fix_sections", "xanso:fix_sections", LocatorParser.hex(firstDiff?.optString("fileOffset") ?: "0x0")?.toInt() ?: 0, firstDiff?.optString("oldHex") ?: "", firstDiff?.optString("newHex") ?: "", "rebuild section headers; diffRangeCount=${diffRanges.length()}")
            editSessionId
        }
        else -> {
            val newSessionId = "fix-${UUID.randomUUID()}"
            val session = EditSession(newSessionId, fixed)
            workspaces[workspaceId]?.edits?.put(newSessionId, session)
            newSessionId
        }
    }
    pageStore.clear()
    searchCache.clear()
    return ok(JSONObject()
        .put("changed", true)
        .put("editSessionId", sessionId)
        .put("requestedEditSessionId", editSessionId)
        .put("appliedToRequestedSession", sessionId == editSessionId && editSessionId.isNotBlank())
        .put("sha256Before", beforeHash)
        .put("sha256After", afterHash)
        .put("diffRangeCount", diffRanges.length())
        .put("diffRanges", diffRanges)
        .put("beforeSections", elfBefore.sections.size)
        .put("afterSections", elfAfter.sections.size)
        .put("beforeSymbols", elfBefore.symbols.size + elfBefore.dynSymbols.size)
        .put("afterSymbols", elfAfter.symbols.size + elfAfter.dynSymbols.size)
        .put("beforeProgramHeaders", elfBefore.programHeaders.size)
        .put("afterProgramHeaders", elfAfter.programHeaders.size)
        .put("beforeDynamicEntries", elfBefore.dynamicEntries.size)
        .put("afterDynamicEntries", elfAfter.dynamicEntries.size)
        .put("sizeBefore", original.size)
        .put("sizeAfter", fixed.size))
}

private fun EngineRuntime.resolveOutputFile(rawName: String, strategy: String): File {
    val dir = context.getExternalFilesDir(null) ?: context.filesDir
    val cleanName = rawName.replace('\\', '/').substringAfterLast('/').trim().ifBlank { "patched.so" }
    val base = File(dir, cleanName)
    if (strategy == "overwrite" || !base.exists()) return base
    val stem = base.nameWithoutExtension.ifBlank { "patched" }
    val ext = base.extension.takeIf { it.isNotBlank() }?.let { ".$it" }.orEmpty()
    var index = 1
    while (index < 10_000) {
        val candidate = File(dir, "$stem-$index$ext")
        if (!candidate.exists()) return candidate
        index++
    }
    return File(dir, "$stem-${System.currentTimeMillis()}$ext")
}

private fun EngineRuntime.workDirCopyResult(requested: Boolean, copy: () -> String?): JSONObject {
    if (!requested) return JSONObject().put("ok", false).put("path", JSONObject.NULL).put("message", "not requested")
    return runCatching { copy() }.fold(
        onSuccess = { path ->
            if (path.isNullOrBlank()) JSONObject().put("ok", false).put("path", JSONObject.NULL).put("message", "work directory not configured or copy returned empty path")
            else JSONObject().put("ok", true).put("path", path).put("message", "copied")
        },
        onFailure = { error ->
            AppLog.w("workDir copy failed: ${error.message}")
            JSONObject().put("ok", false).put("path", JSONObject.NULL).put("message", error.message ?: error.javaClass.simpleName)
        },
    )
}
