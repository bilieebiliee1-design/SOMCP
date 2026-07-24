package com.soreverse.mcp.engine

import android.net.Uri
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

internal fun EngineRuntime.setWorkDirectory(uri: Uri) {
    if (workDirUri == uri && workDir != null) return
    workDirUri = uri
    workDir = WorkDirectory(context, uri)
    sources = emptyList()
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    workspaceBySourceKey.clear()
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Work directory selected: ${WorkDirectory.displayPath(uri)}")
}

internal fun EngineRuntime.listAvailableSos(prefix: String = "", limit: Int = 50, cursor: String = ""): JSONObject = guarded {
    val dir = workDir ?: return@guarded err("SO_NOT_FOUND", "No work directory selected")
    val currentSources = ensureSources(dir)
    val boundedLimit = limit.coerceIn(1, 500)
    val start = cursor.removePrefix("source:").toIntOrNull()?.coerceAtLeast(0) ?: 0
    val filtered = currentSources.filter { prefix.isBlank() || it.path.startsWith(prefix) || it.name.startsWith(prefix) }
    val items = JSONArray()
    filtered.asSequence()
        .drop(start)
        .take(boundedLimit)
        .forEach { src ->
            val meta = sourceSummary(dir, src)
            items.put(JSONObject()
                .put("path", src.path)
                .put("filePath", src.path)
                .put("openPath", src.path)
                .put("source", src.source)
                .put("apkPath", src.apkPath)
                .put("apkEntry", src.apkEntry)
                .put("abi", src.abi)
                .put("size", src.size)
                .put("modified", src.modified)
                .put("architecture", meta.architecture)
                .put("bits", meta.bits)
                .put("endian", meta.endian)
                .put("soname", JSONObject.NULL)
                .put("hasDebugInfo", meta.hasDebugInfo)
                .put("stripped", meta.stripped))
        }
    val nextOffset = start + items.length()
    val nextCursor = if (nextOffset < filtered.size) "source:$nextOffset" else null
    ok(JSONObject()
        .put("items", items)
        .put("usage", "Call so_open with path or filePath from any item. Use the returned workspaceId for the other tools.")
        .put("pagination", pagination(nextCursor != null, nextCursor, items.length(), boundedLimit, filtered.size)))
}

internal fun EngineRuntime.open(path: String, temporary: Boolean): JSONObject = guarded {
    if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "Missing SO path. Pass path or filePath from so_open (action=list).", "path", path)
    val ws = openWorkspace(path, temporary)
    val elf = ws.elf
    val src = ws.source
    val symbolFunctions = (elf.symbols + elf.dynSymbols).filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
    val exportedFunctions = elf.dynSymbols.filter { it.type == "FUNC" && !it.imported && it.value > 0 }.distinctBy { it.name to it.value }
    val analyzedFunctions = if (NativeEngine.active().available()) runCatching { JSONArray(NativeEngine.active().functions(ws.data, elf.architecture)).length() }.getOrDefault(symbolFunctions.size) else symbolFunctions.size
    val pltStubs = elf.relocations.count { it.section.contains("plt", true) }
    ok(JSONObject()
        .put("workspaceId", ws.id)
        .put("temporary", temporary)
        .put("soFileName", src.name)
        .put("source", src.source)
        .put("inputPath", src.path)
        .put("apkPath", src.apkPath)
        .put("apkEntry", src.apkEntry)
        .put("abi", src.abi)
        .put("architecture", elf.architecture)
        .put("bits", elf.bits)
        .put("endian", elf.endian)
        .put("elfType", "ET_${elf.type}")
        .put("machine", elf.machineName)
        .put("entryPoint", hex(elf.entry))
        .put("analysisInput", JSONObject().put("source", ws.analysisInputSource).put("originalSha256", ws.originalSha256).put("analysisSha256", sha256(ws.data)).put("structureRecovery", ws.structureRecovery))
        .put("counts", JSONObject().put("sections", elf.sections.size).put("symbols", elf.symbols.size).put("dynsyms", elf.dynSymbols.size).put("relocations", elf.relocations.size).put("functions", symbolFunctions.size).put("functionsMeaning", "symbolFunctions").put("symbolFunctions", symbolFunctions.size).put("exportedFunctions", exportedFunctions.size).put("analyzedFunctions", analyzedFunctions).put("pltStubs", pltStubs).put("strings", elf.strings.size))
        .put("capabilities", JSONObject().put("canDisassemble", true).put("canEditAsm", true).put("canEditHex", true).put("canResolveRelocs", elf.relocations.isNotEmpty()).put("hasPltGot", elf.sections.any { it.name in setOf(".plt", ".got") }).put("canSearchStrings", elf.strings.isNotEmpty()).put("hasDebugInfo", elf.sections.any { it.name.startsWith(".debug") }).put("hasEhFrame", elf.sections.any { it.name in setOf(".eh_frame", ".ARM.exidx") }))
        .put("checksums", checksums(ws.data)))
}

internal fun EngineRuntime.analyzeApk(path: String, entryLimit: Int = 500): JSONObject = guarded {
    if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "APK path is required", "path", path)
    val local = File(path)
    if (local.isFile && local.length() > ApkAnalyzer.MAX_INPUT_BYTES) return@guarded err("APK_LIMIT_EXCEEDED", "APK exceeds ${ApkAnalyzer.MAX_INPUT_BYTES / 1024 / 1024} MiB input limit", "path", path)
    val bytes = try {
        if (local.isFile) local.readBytes() else (workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "APK path is not a local file and no work directory is selected", "path", path)).readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
    } catch (error: ApkAnalysisLimitException) {
        return@guarded err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
    if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4b.toByte()) return@guarded err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
    try {
        ok(ApkAnalyzer.analyze(bytes, path, entryLimit))
    } catch (error: ApkAnalysisLimitException) {
        err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
}

internal fun EngineRuntime.openUrl(url: String, outputName: String = "", temporary: Boolean = false): JSONObject = guarded {
    val dir = workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "A work directory must be selected before downloading a SO URL")
    val parsed = runCatching { URL(url.trim()) }.getOrNull() ?: return@guarded err("INVALID_ARGUMENT", "url must be a valid http(s) URL", "url", url)
    if (parsed.protocol !in setOf("http", "https")) return@guarded err("UNSUPPORTED_URL_SCHEME", "Only http and https URLs are supported", "url", url)
    val timeout = SettingsStore(context).requestTimeoutMs
    val conn = (parsed.openConnection() as HttpURLConnection).apply { connectTimeout = timeout.coerceAtMost(30_000); readTimeout = timeout; instanceFollowRedirects = true; requestMethod = "GET" }
    val status = conn.responseCode
    if (status !in 200..299) return@guarded err("DOWNLOAD_FAILED", "HTTP download failed with status $status", "url", url)
    val maxBytes = 256L * 1024L * 1024L
    if (conn.contentLengthLong > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "contentLength", conn.contentLengthLong)
    val bytes = conn.inputStream.use { input -> java.io.ByteArrayOutputStream().apply { val buf = ByteArray(64 * 1024); var total = 0L; while (true) { val n = input.read(buf); if (n < 0) break; total += n; if (total > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "url", url); write(buf, 0, n) } }.toByteArray() }
    if (bytes.size < 4 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) return@guarded err("NOT_ELF_SO", "Downloaded file is not an ELF/SO file", "url", url)
    val rawName = outputName.ifBlank { parsed.path.substringAfterLast('/').substringBefore('?').ifBlank { "downloaded.so" } }
    val safeName = rawName.substringAfterLast('/').substringAfterLast('\\').let { if (it.endsWith(".so", ignoreCase = true)) it else "$it.so" }
    val source = dir.writeRootFile(safeName, bytes)
    sources = (sources.filterNot { it.path == source.path } + source).sortedBy { it.path }
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    open(source.path, temporary).put("download", JSONObject().put("url", url).put("savedAs", source.path).put("size", bytes.size).put("sha256_16", sha256(bytes).take(16)))
}

internal fun EngineRuntime.listWorkspaces(): JSONObject = guarded {
    val items = JSONArray()
    workspaces.values.sortedBy { it.source.path }.forEach { ws -> items.put(JSONObject().put("workspaceId", ws.id).put("path", ws.source.path).put("filePath", ws.source.path).put("soFileName", ws.source.name).put("source", ws.source.source).put("apkPath", ws.source.apkPath).put("apkEntry", ws.source.apkEntry).put("abi", ws.source.abi).put("architecture", ws.elf.architecture).put("bits", ws.elf.bits).put("temporary", ws.temporary)) }
    ok(JSONObject().put("items", items).put("count", items.length()))
}

internal fun EngineRuntime.close(workspaceId: String): JSONObject = guarded {
    workspaces.remove(workspaceId)
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Closed $workspaceId")
    ok(JSONObject().put("success", true))
}

internal fun EngineRuntime.clearCaches() {
    sources = emptyList()
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    workspaceBySourceKey.clear()
    pageStore.clear()
    searchCache.clear()
    workDir?.clearPersistentCache()
    AppLog.i("Index caches cleared")
}

internal fun EngineRuntime.openWorkspace(path: String, temporary: Boolean): Workspace {
    val archiveEntry = path.substringAfterLast('!', "")
    if (archiveEntry.isNotBlank() && !archiveEntry.endsWith(".so", ignoreCase = true)) error("NOT_ELF_INPUT: $path is an APK/JAR entry, not an ELF SO file. Use apk_analyze or an APK MCP tool.")
    val keyFallback = "local:$path"
    val src = findSource(path) ?: resolveLocalSoSource(path) ?: error("SO path not found: $path")
    val key = sourceKey(src).ifBlank { keyFallback }
    workspaceBySourceKey[key]?.let { existingId -> workspaces[existingId]?.let { return it } }
    val original = when (src.source) { "build_output", "local_file" -> runCatching { File(src.path).readBytes() }.getOrElse { error("SO path not found: $path") }; else -> (workDir ?: error("No work directory selected")).readSource(src) }
    require(original.size >= 4 && original[0] == 0x7f.toByte() && original[1] == 'E'.code.toByte() && original[2] == 'L'.code.toByte() && original[3] == 'F'.code.toByte()) { "NOT_ELF_INPUT: ${src.path} is not an ELF SO file. Use apk_analyze or an APK MCP tool." }
    val prepared = prepareAnalysisInput(original)
    val ws = Workspace("so-ws-${UUID.randomUUID()}", src, prepared.first, lief.parse(prepared.first), temporary, sha256(original), prepared.second, prepared.third)
    workspaces[ws.id] = ws
    workspaceBySourceKey[key] = ws.id
    AppLog.i("Opened ${src.path} as ${ws.id}")
    return ws
}

internal fun EngineRuntime.prepareAnalysisInput(original: ByteArray): Triple<ByteArray, String, JSONObject> {
    val before = lief.parse(original)
    val facts = JSONObject().put("attempted", false).put("changed", false).put("sectionsBefore", before.sections.size).put("programHeadersBefore", before.programHeaders.size).put("symbolsBefore", before.symbols.size).put("dynSymbolsBefore", before.dynSymbols.size).put("functionSymbolsRecovered", false)
    if (before.sections.isNotEmpty()) return Triple(original, "original", facts.put("reason", "section_table_present"))
    if (original.size < 5 || !xanso.available()) return Triple(original, "original", facts.put("reason", if (original.size < 5) "invalid_elf_ident" else "xanso_unavailable"))
    facts.put("attempted", true)
    val recovered = when (original[4].toInt() and 0xff) { 1 -> xanso.buildSections(original); 2 -> xanso.recoverElf64Sections(original)?.let { lief.fixSections(it) }; else -> null }
    if (recovered == null || recovered.isEmpty()) return Triple(original, "original", facts.put("reason", "xanso_recovery_failed"))
    val after = lief.parse(recovered)
    if (after.sections.isEmpty()) return Triple(original, "original", facts.put("reason", "recovered_section_table_not_parseable"))
    facts.put("changed", !recovered.contentEquals(original)).put("reason", "missing_section_table").put("recoveryMode", if ((original[4].toInt() and 0xff) == 1) "xanso32_section_fix" else "xanso64_section_recovery_lief_finalize").put("sectionsAfter", after.sections.size).put("programHeadersAfter", after.programHeaders.size).put("symbolsAfter", after.symbols.size).put("dynSymbolsAfter", after.dynSymbols.size).put("functionSymbolsRecovered", after.symbols.count { it.type == "FUNC" } > before.symbols.count { it.type == "FUNC" })
    return Triple(recovered, "xanso_recovered_sections", facts)
}

internal fun EngineRuntime.resolveLocalSoSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val file = File(rawPath)
    if (!file.exists() || !file.isFile) return null
    val extDir = context.getExternalFilesDir(null)?.canonicalPath
    val intDir = context.filesDir.canonicalPath
    val canonical = runCatching { file.canonicalPath }.getOrDefault(rawPath)
    if (listOfNotNull(extDir, intDir).none { canonical.startsWith(it) } || !file.name.endsWith(".so", ignoreCase = true)) return null
    return SoSource(canonical, "build_output", file.name, file.length(), file.lastModified(), null)
}

internal fun EngineRuntime.findSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val path = rawPath.trim().removePrefix("/")
    workDir?.let { ensureSources(it) }
    val apkUri = rawPath.trim().removePrefix("content://apk/")
    if (apkUri != rawPath.trim() && apkUri.isNotBlank()) {
        val separator = apkUri.indexOf('/')
        if (separator > 0) sources.firstOrNull { it.source == "apk" && it.apkPath?.substringAfterLast('/') == apkUri.substring(0, separator) && it.apkEntry == apkUri.substring(separator + 1) }?.let { return it }
    }
    return sources.firstOrNull { it.path == rawPath || it.path == path } ?: sources.firstOrNull { it.name == rawPath || it.name == path } ?: sources.firstOrNull { it.apkEntry == rawPath || it.apkEntry == path } ?: sources.firstOrNull { it.path.endsWith("/$path") || it.path.contains(path) }
}

internal fun EngineRuntime.ensureSources(dir: WorkDirectory): List<SoSource> {
    val settings = SettingsStore(context)
    val options = scanOptions(settings)
    if (!settings.indexCacheEnabled) { sources = dir.listSos(options); sourceFingerprint = sources.map { FileFingerprint(it.path, it.size, it.modified) }; return sources }
    val nextFingerprint = dir.fingerprint(options)
    if (sources.isNotEmpty() && nextFingerprint == sourceFingerprint) return sources
    sources = dir.listSos(options)
    sourceFingerprint = nextFingerprint
    pageStore.clear()
    AppLog.i("Scanned ${sources.size} SO entries")
    return sources
}

internal fun EngineRuntime.scanOptions(settings: SettingsStore): ScanOptions = ScanOptions(settings.scanApks, settings.scanSubdirectories, settings.maxScanDepth, settings.skipFilesLargerThanMb.toLong() * 1024L * 1024L)

internal fun EngineRuntime.sourceSummary(dir: WorkDirectory, src: SoSource): SourceSummary {
    if (!SettingsStore(context).parseMetadataInList) return SourceSummary("unknown", 0, "little", false, false)
    return sourceSummaryCache.getOrPut(sourceKey(src)) {
        dir.cachedSummary(src)?.let { return@getOrPut SourceSummary(it.architecture, it.bits, it.endian, it.hasDebugInfo, it.stripped) }
        runCatching { lief.parse(dir.readSource(src)).let { elf -> SourceSummary(elf.architecture, elf.bits, elf.endian, elf.sections.any { it.name.startsWith(".debug") }, elf.symbols.isEmpty()).also { dir.putCachedSummary(src, CachedSourceSummary(it.architecture, it.bits, it.endian, it.hasDebugInfo, it.stripped)) } } }.getOrElse { SourceSummary("unknown", 0, "little", false, true) }
    }
}

internal fun EngineRuntime.sourceKey(src: SoSource): String = "${src.path}|${src.size}|${src.modified}"
