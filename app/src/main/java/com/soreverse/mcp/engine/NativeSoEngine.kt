package com.soreverse.mcp.engine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.toJsonArray
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.ZipInputStream
import kotlin.math.min

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

private data class SourceSummary(
    val architecture: String,
    val bits: Int,
    val endian: String,
    val hasDebugInfo: Boolean,
    val stripped: Boolean,
)

private data class PageState(
    val field: String,
    val items: List<JSONObject>,
    val offset: Int,
    val limit: Int,
)

private data class DisasmCursorState(
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

private data class EmulatorSession(
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

class NativeSoEngine(private val context: Context) {
    internal val lief = LiefEngine()
    private val xanso = XAnSoEngine(context)
    private val unidbg = UnidbgEmulator(context)
    private var workDir: WorkDirectory? = null
    private var workDirUri: Uri? = null
    private var sources: List<SoSource> = emptyList()
    private var sourceFingerprint: List<FileFingerprint> = emptyList()
    private val sourceSummaryCache = ConcurrentHashMap<String, SourceSummary>()
    private val workspaceBySourceKey = ConcurrentHashMap<String, String>()
    private val pageCache = ConcurrentHashMap<String, PageState>()
    private val emulatorSessions = ConcurrentHashMap<String, EmulatorSession>()
    private val searchCache = ConcurrentHashMap<String, List<JSONObject>>()
    private val workspaces = ConcurrentHashMap<String, Workspace>()

    fun setWorkDirectory(uri: Uri) {
        if (workDirUri == uri && workDir != null) return
        workDirUri = uri
        workDir = WorkDirectory(context, uri)
        sources = emptyList()
        sourceFingerprint = emptyList()
        sourceSummaryCache.clear()
        workspaceBySourceKey.clear()
        pageCache.clear()
        searchCache.clear()
        AppLog.i("Work directory selected: ${WorkDirectory.displayPath(uri)}")
    }

    fun listAvailableSos(prefix: String = "", limit: Int = 50, cursor: String = ""): JSONObject = guarded {
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

    fun open(path: String, temporary: Boolean): JSONObject = guarded {
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
            .put("analysisInput", JSONObject()
                .put("source", ws.analysisInputSource)
                .put("originalSha256", ws.originalSha256)
                .put("analysisSha256", sha256(ws.data))
                .put("structureRecovery", ws.structureRecovery))
            .put("counts", JSONObject()
                .put("sections", elf.sections.size)
                .put("symbols", elf.symbols.size)
                .put("dynsyms", elf.dynSymbols.size)
                .put("relocations", elf.relocations.size)
                .put("functions", symbolFunctions.size)
                .put("functionsMeaning", "symbolFunctions")
                .put("symbolFunctions", symbolFunctions.size)
                .put("exportedFunctions", exportedFunctions.size)
                .put("analyzedFunctions", analyzedFunctions)
                .put("pltStubs", pltStubs)
                .put("strings", elf.strings.size))
            .put("capabilities", JSONObject()
                .put("canDisassemble", true)
                .put("canEditAsm", true)
                .put("canEditHex", true)
                .put("canResolveRelocs", elf.relocations.isNotEmpty())
                .put("hasPltGot", elf.sections.any { it.name in setOf(".plt", ".got") })
                .put("canSearchStrings", elf.strings.isNotEmpty())
                .put("hasDebugInfo", elf.sections.any { it.name.startsWith(".debug") })
                .put("hasEhFrame", elf.sections.any { it.name in setOf(".eh_frame", ".ARM.exidx") }))
            .put("checksums", checksums(ws.data)))
    }

    fun analyzeApk(path: String, entryLimit: Int = 500): JSONObject = guarded {
        if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "APK path is required", "path", path)
        val bytes = runCatching { File(path).readBytes() }.getOrElse {
            (workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "APK path is not a local file and no work directory is selected", "path", path)).readFile(path)
        }
        if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4b.toByte()) {
            return@guarded err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
        }
        val entries = JSONArray()
        val nativeLibs = JSONArray()
        val dexFiles = JSONArray()
        val signatures = JSONArray()
        val abis = linkedSetOf<String>()
        var manifest: JSONObject = JSONObject().put("present", false)
        var resourcesArsc = false
        var totalEntries = 0
        ZipInputStream(bytes.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                totalEntries++
                val name = entry.name
                val size = entry.size.takeIf { it >= 0 } ?: -1L
                if (entries.length() < entryLimit.coerceIn(1, 5000)) {
                    entries.put(JSONObject().put("name", name).put("size", size).put("compressedSize", entry.compressedSize).put("directory", entry.isDirectory))
                }
                if (!entry.isDirectory && name.matches(Regex("^lib/[^/]+/[^/]+\\.so$"))) {
                    val abi = name.split('/')[1]
                    abis += abi
                    nativeLibs.put(JSONObject().put("entry", name).put("abi", abi).put("name", name.substringAfterLast('/')).put("size", size))
                }
                if (!entry.isDirectory && name.matches(Regex("^classes(?:[2-9][0-9]*)?\\.dex$"))) {
                    val dex = zip.readBytes()
                    dexFiles.put(parseDexHeader(name, dex))
                } else if (!entry.isDirectory && name == "AndroidManifest.xml") {
                    val data = zip.readBytes()
                    manifest = parseManifestSummary(data)
                } else if (!entry.isDirectory && name == "resources.arsc") {
                    resourcesArsc = true
                } else if (!entry.isDirectory && name.startsWith("META-INF/", true) &&
                    (name.endsWith(".RSA", true) || name.endsWith(".DSA", true) || name.endsWith(".EC", true) || name.endsWith(".SF", true) || name.endsWith("MANIFEST.MF", true))) {
                    signatures.put(name)
                }
                zip.closeEntry()
            }
        }
        ok(JSONObject()
            .put("path", path)
            .put("size", bytes.size)
            .put("sha256", sha256(bytes))
            .put("parser", "builtin_apk_zip_dex_axml")
            .put("externalApkMcpRequired", false)
            .put("entryCount", totalEntries)
            .put("entriesTruncated", totalEntries > entries.length())
            .put("entries", entries)
            .put("abis", JSONArray(abis.toList()))
            .put("nativeLibraries", nativeLibs)
            .put("dexFiles", dexFiles)
            .put("manifest", manifest)
            .put("resourcesArsc", resourcesArsc)
            .put("v1SignatureFiles", signatures)
            .put("hasV1Signature", signatures.length() > 0)
            .put("limitations", JSONArray(listOf("APK Signature Scheme v2/v3/v4 block verification is not included in this basic parser", "Binary AndroidManifest attributes require the full resource table resolver"))))
    }

    private fun parseDexHeader(name: String, dex: ByteArray): JSONObject {
        fun u32(offset: Int): Long {
            if (offset + 4 > dex.size) return 0
            return (dex[offset].toLong() and 0xff) or ((dex[offset + 1].toLong() and 0xff) shl 8) or
                ((dex[offset + 2].toLong() and 0xff) shl 16) or ((dex[offset + 3].toLong() and 0xff) shl 24)
        }
        val magic = if (dex.size >= 8) String(dex.copyOfRange(0, 8), Charsets.ISO_8859_1).replace("\u0000", "\\0") else ""
        return JSONObject().put("entry", name).put("size", dex.size).put("magic", magic)
            .put("valid", dex.size >= 0x70 && magic.startsWith("dex\\n"))
            .put("fileSize", u32(0x20)).put("headerSize", u32(0x24)).put("endianTag", "0x${u32(0x28).toString(16)}")
            .put("stringIds", u32(0x38)).put("typeIds", u32(0x40)).put("protoIds", u32(0x48))
            .put("fieldIds", u32(0x50)).put("methodIds", u32(0x58)).put("classDefs", u32(0x60))
    }

    private fun parseManifestSummary(data: ByteArray): JSONObject {
        val binary = data.size >= 8 && data[0] == 0x03.toByte() && data[1] == 0x00.toByte()
        val printable = if (!binary) String(data, Charsets.UTF_8).take(4096) else ""
        return JSONObject().put("present", true).put("size", data.size)
            .put("format", if (binary) "android_binary_xml" else "text_xml")
            .put("textPreview", if (printable.isBlank()) JSONObject.NULL else printable)
    }

    fun openUrl(url: String, outputName: String = "", temporary: Boolean = false): JSONObject = guarded {
        val dir = workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "A work directory must be selected before downloading a SO URL")
        val parsed = runCatching { URL(url.trim()) }.getOrNull()
            ?: return@guarded err("INVALID_ARGUMENT", "url must be a valid http(s) URL", "url", url)
        if (parsed.protocol !in setOf("http", "https")) return@guarded err("UNSUPPORTED_URL_SCHEME", "Only http and https URLs are supported", "url", url)
        val timeout = SettingsStore(context).requestTimeoutMs
        val conn = (parsed.openConnection() as HttpURLConnection).apply {
            connectTimeout = timeout.coerceAtMost(30_000)
            readTimeout = timeout
            instanceFollowRedirects = true
            requestMethod = "GET"
        }
        val status = conn.responseCode
        if (status !in 200..299) return@guarded err("DOWNLOAD_FAILED", "HTTP download failed with status $status", "url", url)
        val declaredSize = conn.contentLengthLong
        val maxBytes = 256L * 1024L * 1024L
        if (declaredSize > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "contentLength", declaredSize)
        val bytes = conn.inputStream.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "url", url)
                out.write(buf, 0, n)
            }
            out.toByteArray()
        }
        if (bytes.size < 4 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) {
            return@guarded err("NOT_ELF_SO", "Downloaded file is not an ELF/SO file", "url", url)
        }
        val rawName = outputName.ifBlank { parsed.path.substringAfterLast('/').substringBefore('?').ifBlank { "downloaded.so" } }
        val safeName = rawName.substringAfterLast('/').substringAfterLast('\\').let { if (it.endsWith(".so", ignoreCase = true)) it else "$it.so" }
        val source = dir.writeRootFile(safeName, bytes)
        sources = (sources.filterNot { it.path == source.path } + source).sortedBy { it.path }
        sourceFingerprint = emptyList()
        sourceSummaryCache.clear()
        val opened = open(source.path, temporary)
        opened.put("download", JSONObject()
            .put("url", url)
            .put("savedAs", source.path)
            .put("size", bytes.size)
            .put("sha256_16", sha256(bytes).take(16)))
    }

    fun listWorkspaces(): JSONObject = guarded {
        val items = JSONArray()
        workspaces.values.sortedBy { it.source.path }.forEach { ws ->
            items.put(JSONObject()
                .put("workspaceId", ws.id)
                .put("path", ws.source.path)
                .put("filePath", ws.source.path)
                .put("soFileName", ws.source.name)
                .put("source", ws.source.source)
                .put("apkPath", ws.source.apkPath)
                .put("apkEntry", ws.source.apkEntry)
                .put("abi", ws.source.abi)
                .put("architecture", ws.elf.architecture)
                .put("bits", ws.elf.bits)
                .put("temporary", ws.temporary))
        }
        ok(JSONObject().put("items", items).put("count", items.length()))
    }

    fun close(workspaceId: String): JSONObject = guarded {
        workspaces.remove(workspaceId)
        pageCache.clear()
        searchCache.clear()
        AppLog.i("Closed $workspaceId")
        ok(JSONObject().put("success", true))
    }

    fun clearCaches() {
        sources = emptyList()
        sourceFingerprint = emptyList()
        sourceSummaryCache.clear()
        workspaceBySourceKey.clear()
        pageCache.clear()
        searchCache.clear()
        workDir?.clearPersistentCache()
        AppLog.i("Index caches cleared")
    }

    fun list(workspaceId: String, editSessionId: String, view: String, prefix: String, limit: Int, pathHint: String = "", cursor: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val all = when (view) {
            "sections" -> elf.sections.asSequence().withIndex().filter { it.value.name.startsWith(prefix) }.map { (index, section) ->
                sectionJson(name, section, index).put("virtualAddr", hex(section.addr)).put("fileOffset", hex(section.offset)).put("alignment", section.addralign)
            }
            "symbols", "dynsyms" -> (if (view == "dynsyms") elf.dynSymbols else elf.symbols).asSequence().filter { it.name.startsWith(prefix) }.map {
                symbolJson(name, it)
            }
            "functions" -> (elf.symbols + elf.dynSymbols).asSequence().filter { it.type == "FUNC" && !it.imported && it.name.startsWith(prefix) }.map {
                JSONObject().put("locator", "so_function:$name!${it.name}").put("name", it.name).put("demangled", JSONObject.NULL).put("startAddr", hex(it.value and -2L)).put("endAddr", hex((it.value and -2L) + it.size)).put("size", it.size).put("section", sectionFor(elf, it.value)?.name ?: "").put("isExported", it.exported)
            }
            "relocations" -> elf.relocations.asSequence().filter { it.symbol.startsWith(prefix) }.map {
                relocationJson(name, elf, it)
            }
            "strings" -> elf.strings.asSequence().filter { prefix.isBlank() || it.value.contains(prefix, ignoreCase = true) }.map {
                stringJson(name, it)
            }
            "imports" -> elf.dynSymbols.asSequence().filter { it.imported && it.name.startsWith(prefix) }.map {
                JSONObject().put("locator", "so_import:$name!UNRESOLVED!${it.name}").put("soname", JSONObject.NULL).put("resolution", "unresolved_without_symbol_version_mapping").put("neededLibraries", JSONArray(neededLibraries(elf, dataFor(workspaceId, editSessionId)))).put("symbol", it.name).put("symbolLocator", "so_symbol:$name!${it.name}").put("isWeak", it.bind == "WEAK")
            }
            "plt_stubs" -> emptySequence()
            else -> return@guarded err("INVALID_LOCATOR", "Unsupported list view", "view", view)
        }.toList()
        page("items", all, limit, cursor)
    }

    fun readElf(workspaceId: String, editSessionId: String, pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        ok(JSONObject()
            .put("workspaceId", resolvedWorkspaceId)
            .put("ident", JSONObject().put("magic", "7F 45 4C 46").put("class", if (elf.bits == 64) "ELF64" else "ELF32").put("data", elf.endian))
            .put("type", elf.type)
            .put("machine", elf.machineName)
            .put("entryPoint", hex(elf.entry))
            .put("programHeaders", JSONArray(elf.programHeaders.map { phJson(it) }))
            .put("sectionHeaders", elf.sections.map { JSONObject().put("name", it.name).put("type", it.type).put("flags", flags(it.flags)).put("addr", hex(it.addr)).put("offset", hex(it.offset)).put("size", it.size) }.toJsonArray())
            .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { dynJson(it) })))
    }

    fun hexdump(workspaceId: String, editSessionId: String, locator: String, byteOffset: Int, maxBytes: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val bytes = dataFor(workspaceId, editSessionId)
        val sec = resolveSection(elf, locator) ?: return@guarded err("SECTION_NOT_FOUND", "Section '${locatorTarget(locator, "so_section")}' not found. Call analyze_elf (view=list, subView=sections) to see available sections. If names are duplicated, pass the full locator returned by analyze_elf.", "locator", locator, "availableSections" to elf.sections.mapIndexed { index, section -> sectionKey(section, index) })
        val start = (sec.offset + byteOffset).toInt().coerceIn(0, bytes.size)
        val count = min(maxBytes.coerceIn(1, 4096), bytes.size - start)
        val slice = bytes.copyOfRange(start, start + count)
        ok(JSONObject()
            .put("locator", locator)
            .put("targetName", sec.name)
            .put("targetLocator", sectionLocator(workspaces[workspaceId]?.source?.name ?: "lib.so", sec, elf.sections.indexOf(sec)))
            .put("entrySize", sec.size)
            .put("byteWindow", JSONObject().put("hex", slice.joinToString(" ") { "%02X".format(it) }).put("ascii", slice.map { val c = it.toInt() and 0xff; if (c in 32..126) c.toChar() else '.' }.joinToString("")).put("byteOffset", byteOffset).put("bytesReturned", count))
            .put("targetVersion", sha256(slice)))
    }

    fun strings(workspaceId: String, editSessionId: String, locator: String, prefix: String, limit: Int, pathHint: String = "", cursor: String = "", regex: Boolean = false, ignoreCase: Boolean = true, encoding: String = "", minConfidence: Double = 0.0): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val section = locatorTarget(locator, "so_section")
        val encodingFilter = encoding.trim().uppercase()
        val compiledRegex = if (regex && prefix.isNotBlank()) {
            runCatching { Regex(prefix, if (ignoreCase) setOf(RegexOption.IGNORE_CASE) else emptySet()) }
                .getOrElse { return@guarded err("INVALID_REGEX", it.message ?: "Invalid regex", "prefix", prefix) }
        } else null
        val all = elf.strings.asSequence()
            .filter { locator.isBlank() || it.section == section }
            .filter { encodingFilter.isBlank() || it.encoding.equals(encodingFilter, ignoreCase = true) || (encodingFilter == "UTF16" && it.encoding.startsWith("UTF-16", ignoreCase = true)) }
            .filter { it.confidence >= minConfidence }
            .filter { prefix.isBlank() || compiledRegex?.containsMatchIn(it.value) ?: it.value.contains(prefix, ignoreCase = ignoreCase) }
            .map { stringJson(name, it) }
            .toList()
        page("items", all, limit, cursor)
            .put("workspaceId", resolvedWorkspaceId)
            .put("matchMode", if (regex) "regex" else "contains")
            .put("ignoreCase", ignoreCase)
            .put("encoding", if (encodingFilter.isBlank()) "any" else encodingFilter)
            .put("minConfidence", minConfidence)
    }

    fun disasm(workspaceId: String, editSessionId: String, locator: String, limit: Int, cursor: String = "", instructionOffset: Int = 0, byteOffset: Int = 0, maxBytes: Int = 4096, addr: String = "", thumb: Boolean? = null, mode: String = "auto"): JSONObject = guarded {
        val cursorArgs = parseDisasmCursor(cursor)
        if (cursor.startsWith("disasm:") && cursorArgs == null) return@guarded err("INVALID_CURSOR", "Invalid disassembly cursor", "cursor", cursor)
        val effectiveWorkspaceId = cursorArgs?.workspaceId ?: workspaceId
        val effectiveEditSessionId = cursorArgs?.editSessionId ?: editSessionId
        val effectiveLocator = cursorArgs?.locator ?: locator
        val effectiveLimit = cursorArgs?.limit ?: limit
        val effectiveMaxBytes = cursorArgs?.maxBytes ?: maxBytes
        val elf = elfFor(effectiveWorkspaceId, effectiveEditSessionId)
        val bytes = dataFor(effectiveWorkspaceId, effectiveEditSessionId)
        val directRawVa = parseHexLong(addr.ifBlank { effectiveLocator.takeIf { it.startsWith("0x", ignoreCase = true) } ?: "" })
        val directVa = directRawVa?.let { if (elf.architecture == "arm32") it and -2L else it }
        if (directVa != null) {
            val directThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (directRawVa and 1L) == 1L)
            val addressIssue = validateCodeAddress(elf, directVa, directThumb)
            if (addressIssue != null) return@guarded addressIssue
            val off = vaToOffset(elf, directVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(directVa)} cannot be mapped to a file offset", "addr", hex(directVa))
            val requestedMaxBytes = effectiveMaxBytes.coerceIn(1, 65536)
            val windowBytes = requestedMaxBytes.coerceAtMost(bytes.size - off)
            val slice = bytes.copyOfRange(off, off + windowBytes)
            val rizinText = runCatching { NativeEngine.active().disassemble(slice, elf.architecture, directVa, directThumb, effectiveLimit.coerceIn(1, 5000)) }.getOrDefault("")
            val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
            val symbolHints = disasmSymbolHints(referenceHints, elf, directVa, windowBytes.toLong())
            val lines = annotateDisasmLines(referenceHints, cleanDisasmLines(rizinText, effectiveLimit.coerceIn(1, 5000)))
            val containingFunction = functionContaining(elf, directVa)
            val section = executableSectionFor(elf, directVa)
            return@guarded ok(JSONObject()
                .put("locator", if (effectiveLocator.isBlank()) hex(directVa) else effectiveLocator)
                .put("addr", hex(directVa))
                .put("architecture", elf.architecture)
                .put("disasmMode", if (directThumb) "thumb" else elf.architecture)
                .put("thumb", directThumb)
                .put("disasmBackend", "rizin-address")
                .put("resolvedSection", section?.let { sectionJson(workspaces[effectiveWorkspaceId]?.source?.name ?: "lib.so", it, elf.sections.indexOf(it)) } ?: JSONObject.NULL)
                .put("resolvedFunction", containingFunction?.let { functionIdentityJson(elf, it) } ?: JSONObject.NULL)
                .put("instructionCount", lines.size)
                .put("bytesReturned", windowBytes)
                .put("symbolHints", symbolHints)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, directVa))
                .put("textWindow", JSONObject().put("text", lines.joinToString("\n")).put("startByteOffset", 0).put("endByteOffset", windowBytes).put("startAddress", hex(directVa)).put("requestedMaxBytes", requestedMaxBytes).put("effectiveMaxBytes", windowBytes))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(slice))
                .put("workspaceHash", sha256(bytes))
                .put("pagination", disasmPagination(false, null, lines.size, effectiveLimit, windowBytes, windowBytes)))
        }
        val locatorVa = locatorAddress(effectiveLocator) ?: resolveRizinFunctionAddress(bytes, elf, locatorTarget(effectiveLocator, "so_function"))
        val name = locatorTarget(effectiveLocator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        if (sym == null && locatorVa != null) {
            val addressIssue = validateCodeAddress(elf, locatorVa, false)
            if (addressIssue != null) return@guarded addressIssue
            val off = vaToOffset(elf, locatorVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(locatorVa)} cannot be mapped to a file offset", "locator", effectiveLocator)
            val windowLimit = rizinFunctionSize(bytes, elf, locatorVa) ?: functionByteSizeFromAddress(elf, locatorVa, off, bytes.size)
            val requestedMaxBytes = effectiveMaxBytes.coerceIn(1, 65536)
            val windowBytes = requestedMaxBytes.coerceAtMost(windowLimit)
            val slice = bytes.copyOfRange(off, off + windowBytes)
            val rizinText = runCatching { NativeEngine.active().disassemble(slice, elf.architecture, locatorVa, false, effectiveLimit.coerceIn(1, 5000)) }.getOrDefault("")
            val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
            val symbolHints = disasmSymbolHints(referenceHints, elf, locatorVa, windowBytes.toLong())
            val lines = annotateDisasmLines(referenceHints, cleanDisasmLines(rizinText, effectiveLimit.coerceIn(1, 5000)))
            return@guarded ok(JSONObject()
                .put("locator", effectiveLocator)
                .put("functionName", name)
                .put("addr", hex(locatorVa))
                .put("architecture", elf.architecture)
                .put("disasmMode", elf.architecture)
                .put("thumb", false)
                .put("disasmBackend", "rizin-address")
                .put("instructionCount", lines.size)
                .put("bytesReturned", windowBytes)
                .put("symbolHints", symbolHints)
                .put("resolvedSection", executableSectionFor(elf, locatorVa)?.let { sectionJson(workspaces[effectiveWorkspaceId]?.source?.name ?: "lib.so", it, elf.sections.indexOf(it)) } ?: JSONObject.NULL)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, locatorVa))
                .put("functionBounds", JSONObject().put("startAddr", hex(locatorVa)).put("endAddr", hex(locatorVa + windowLimit)).put("size", windowLimit).put("source", "rizin-locator-address"))
                .put("textWindow", JSONObject().put("text", lines.joinToString("\n")).put("startByteOffset", 0).put("endByteOffset", windowBytes).put("startAddress", hex(locatorVa)).put("requestedMaxBytes", requestedMaxBytes).put("effectiveMaxBytes", windowBytes))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(slice))
                .put("workspaceHash", sha256(bytes))
                .put("pagination", disasmPagination(false, null, lines.size, effectiveLimit, windowBytes, windowBytes)))
        }
        if (sym == null) return@guarded err("FUNCTION_NOT_FOUND", "Function not found", "locator", locator)
        val startAddress = sym.value and -2L
        val symThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L)
        val addressIssue = validateCodeAddress(elf, startAddress, symThumb)
        if (addressIssue != null) return@guarded addressIssue
        val off = vaToOffset(elf, startAddress)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address cannot be mapped")
        val size = (rizinFunctionSize(bytes, elf, startAddress) ?: functionByteSize(elf, sym, off, bytes.size)).coerceIn(0, bytes.size - off)
        val derivedByteOffset = cursorArgs?.byteOffset ?: if (byteOffset > 0) byteOffset else instructionOffsetToByteOffset(elf, sym, instructionOffset)
        val windowOffset = derivedByteOffset.coerceIn(0, size)
        val windowBytes = effectiveMaxBytes.coerceIn(256, 65536).coerceAtMost(size - windowOffset)
        if (windowBytes <= 0) {
            return@guarded ok(JSONObject()
                .put("locator", effectiveLocator)
                .put("functionName", name)
                .put("architecture", elf.architecture)
                .put("disasmMode", elf.architecture)
                .put("instructionCount", 0)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, startAddress))
                .put("textWindow", JSONObject().put("text", "").put("startByteOffset", windowOffset).put("endByteOffset", windowOffset).put("startAddress", hex(startAddress + windowOffset)).put("maxBytes", 0))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(ByteArray(0)))
                .put("workspaceHash", sha256(bytes))
                .put("bytesReturned", 0)
                .put("pagination", disasmPagination(false, null, 0, effectiveLimit, 0, size)))
        }
        val functionBytes = bytes.copyOfRange(off + windowOffset, off + windowOffset + windowBytes)
        val windowAddress = startAddress + windowOffset
        val rizinText = runCatching {
            NativeEngine.active().disassemble(functionBytes, elf.architecture, windowAddress, symThumb, effectiveLimit.coerceIn(1, 5000))
        }.getOrDefault("")
        val usedPseudo = rizinText.isBlank()
        val text = rizinText.ifBlank {
            if (SettingsStore(context).disasmPseudoFallback) pseudoDisasm(elf, sym, functionBytes, effectiveLimit.coerceIn(1, 5000), windowAddress) else ""
        }
        val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
        val symbolHints = disasmSymbolHints(referenceHints, elf, windowAddress, windowBytes.toLong())
        val lines = if (usedPseudo) text.lineSequence().take(effectiveLimit.coerceIn(1, 5000)).toList() else annotateDisasmLines(referenceHints, cleanDisasmLines(text, effectiveLimit.coerceIn(1, 5000)))
        val nextByteOffset = windowOffset + windowBytes
        val nextCursor = if (nextByteOffset < size) disasmCursor(effectiveWorkspaceId, effectiveEditSessionId, effectiveLocator, nextByteOffset, effectiveLimit, effectiveMaxBytes) else null
        ok(JSONObject()
            .put("locator", effectiveLocator)
            .put("functionName", name)
            .put("architecture", elf.architecture)
            .put("disasmMode", if ((thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L))) "thumb" else elf.architecture)
            .put("thumb", thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L))
            .put("disasmBackend", if (usedPseudo) "pseudo-fallback" else "rizin")
            .put("functionKind", functionKind(elf, sym))
            .put("thunk", thunkInfoFromLines(lines, startAddress))
            .put("instructionCount", lines.size)
            .put("bytesReturned", windowBytes)
            .put("symbolHints", symbolHints)
            .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, startAddress, lines))
            .put("functionBounds", JSONObject().put("startAddr", hex(startAddress)).put("endAddr", hex(startAddress + size)).put("size", size).put("source", "symbol"))
            .put("textWindow", JSONObject()
                .put("text", lines.joinToString("\n"))
                .put("startByteOffset", windowOffset)
                .put("endByteOffset", nextByteOffset)
                .put("startAddress", hex(windowAddress))
                .put("requestedMaxBytes", effectiveMaxBytes.coerceIn(1, 65536))
                .put("effectiveMaxBytes", windowBytes))
            .put("basicBlocks", JSONArray())
            .put("windowHash", sha256(functionBytes))
            .put("workspaceHash", sha256(bytes))
            .put("pagination", disasmPagination(nextCursor != null, nextCursor, lines.size, effectiveLimit, windowBytes, size)))
    }

    fun outline(workspaceId: String, editSessionId: String, locator: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val name = locatorTarget(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name } ?: return@guarded err("FUNCTION_NOT_FOUND", "Function not found", "locator", locator)
        val start = sym.value and -2L
        ok(JSONObject()
            .put("locator", locator)
            .put("name", name)
            .put("demangled", JSONObject.NULL)
            .put("startAddr", hex(start))
            .put("endAddr", hex(start + sym.size))
            .put("size", sym.size)
            .put("instructionCount", if (elf.architecture in setOf("arm32", "arm64", "mips")) (sym.size / 4).toInt() else sym.size.toInt())
            .put("basicBlocks", JSONArray().put(JSONObject().put("index", 0).put("startAddr", hex(start)).put("endAddr", hex(start + sym.size)).put("instructionCount", 0).put("isEntry", true).put("isExit", true).put("successors", JSONArray()).put("predecessors", JSONArray())))
            .put("calledFunctions", JSONArray())
            .put("callers", JSONArray())
            .put("stringReferences", JSONArray())
            .put("dataReferences", JSONArray())
            .put("loops", JSONArray()))
    }

    fun xrefSymbol(workspaceId: String, editSessionId: String, locator: String, refDirection: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val symbol = locatorTarget(locator, "so_symbol")
        val incoming = JSONArray()
        elf.relocations.asSequence().filter { it.symbol == symbol }.take(limit).forEach {
            incoming.put(JSONObject().put("type", "relocation").put("from", "so_reloc:${workspaces[workspaceId]?.source?.name}!${it.section}!${it.offset.toString(16)}").put("to", locator).put("address", hex(it.offset)).put("confidence", "high"))
        }
        ok(JSONObject()
            .put("locator", locator)
            .put("refDirection", refDirection)
            .put("incoming", if (refDirection != "outgoing") incoming else JSONArray())
            .put("outgoing", JSONArray())
            .put("pagination", pagination(false, null, incoming.length(), limit, incoming.length())))
    }

    fun xrefString(workspaceId: String, editSessionId: String, locator: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val targetOffset = locator.substringAfterLast('!').toLongOrNull(16) ?: return@guarded err("INVALID_LOCATOR", "Invalid string locator")
        val targetVa = elf.sections.firstOrNull { targetOffset >= it.offset && targetOffset < it.offset + it.size }?.let { it.addr + (targetOffset - it.offset) }
        val refs = JSONArray()
        if (targetVa != null) {
            val bytes = dataFor(workspaceId, editSessionId)
            val pattern = byteArrayOf((targetVa and 0xff).toByte(), ((targetVa shr 8) and 0xff).toByte(), ((targetVa shr 16) and 0xff).toByte(), ((targetVa shr 24) and 0xff).toByte())
            var i = 0
            while (i <= bytes.size - pattern.size && refs.length() < limit) {
                if (pattern.indices.all { bytes[i + it] == pattern[it] }) refs.put(JSONObject().put("type", "literal_address").put("address", hex(i.toLong())).put("locator", locator).put("confidence", "medium"))
                i++
            }
        }
        ok(JSONObject().put("locator", locator).put("references", refs).put("pagination", pagination(false, null, refs.length(), limit, refs.length())))
    }

    fun search(workspaceId: String, editSessionId: String, target: String, query: String, limit: Int, pathHint: String = "", cursor: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint.ifBlank { query })
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val key = searchKey(resolvedWorkspaceId, editSessionId, target, query, limit)
        if (searchCache.size > 64) searchCache.clear()
        val hits = searchCache.getOrPut(key) {
            val next = mutableListOf<JSONObject>()
            val needle = query.lowercase()
            if (target in setOf("symbols", "overview")) {
                (elf.symbols + elf.dynSymbols).asSequence()
                    .filter { it.name.lowercase().contains(needle) }
                    .forEach { next += JSONObject().put("target", "symbols").put("locator", "so_symbol:$name!${it.name}").put("snippet", it.name) }
            }
            if (target in setOf("strings", "overview")) {
                elf.strings.asSequence()
                    .filter { it.value.lowercase().contains(needle) }
                    .forEach { next += JSONObject().put("target", "strings").put("locator", "so_string:$name!${it.offset.toString(16)}").put("snippet", it.value.take(160)) }
                rawUtf8Hits(dataFor(resolvedWorkspaceId, editSessionId), query, limit).forEach { (offset, snippet) ->
                    next += JSONObject().put("target", "raw_utf8").put("locator", "so_raw_string:$name!${offset.toString(16)}").put("snippet", snippet)
                }
            }
            next
        }
        page("hits", hits, limit, cursor).put("workspaceId", resolvedWorkspaceId)
    }

    fun editOpen(workspaceId: String): JSONObject = guarded {
        val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        val id = "so-edit-${UUID.randomUUID()}"
        ws.edits[id] = EditSession(id, ws.data.copyOf())
        ok(JSONObject().put("editSessionId", id).put("workspaceId", workspaceId).put("initialTargetVersion", sha256(ws.data)))
    }

    fun editSnapshot(workspaceId: String, editSessionId: String, label: String = ""): JSONObject = guarded {
        val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        if (session.snapshots.size >= settings.maxSnapshots) {
            session.snapshots.removeAt(0)
        }
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

    fun editRollback(workspaceId: String, editSessionId: String, snapshotIndex: Int = -1): JSONObject = guarded {
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
        pageCache.clear()
        searchCache.clear()
        ok(JSONObject()
            .put("rolledBackTo", idx)
            .put("beforeSha256", before)
            .put("afterSha256", snap.sha256)
            .put("revision", session.revision)
            .put("patchCount", session.patches.size)
            .put("newTargetVersion", sha256(session.data)))
    }

    fun editUndo(workspaceId: String, editSessionId: String, count: Int = 1): JSONObject = guarded {
        val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        if (session.patches.isEmpty()) return@guarded err("NOTHING_TO_UNDO", "No patches to undo in this session")
        val n = count.coerceIn(1, session.patches.size)
        val undone = JSONArray()
        repeat(n) {
            val p = session.patches.removeAt(session.patches.lastIndex)
            val oldBytes = p.oldHex.split(' ').filter { it.isNotBlank() }.map { it.toInt(16).toByte() }.toByteArray()
            if (p.fileOffset in 0..(session.data.size - oldBytes.size)) {
                System.arraycopy(oldBytes, 0, session.data, p.fileOffset, oldBytes.size)
            }
            session.undone += p
            undone.put(patchJson(p))
        }
        session.revision = (session.revision - n).coerceAtLeast(0)
        pageCache.clear()
        searchCache.clear()
        ok(JSONObject()
            .put("undoneCount", n)
            .put("undone", undone)
            .put("remainingPatches", session.patches.size)
            .put("newTargetVersion", sha256(session.data)))
    }

    fun editRedo(workspaceId: String, editSessionId: String, count: Int = 1): JSONObject = guarded {
        val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        if (session.undone.isEmpty()) return@guarded err("NOTHING_TO_REDO", "No undone patches to redo in this session")
        val n = count.coerceIn(1, session.undone.size)
        val redone = JSONArray()
        repeat(n) {
            val p = session.undone.removeAt(session.undone.lastIndex)
            val newBytes = p.newHex.split(' ').filter { it.isNotBlank() }.map { it.toInt(16).toByte() }.toByteArray()
            if (newBytes.isNotEmpty() && p.fileOffset in 0..(session.data.size - newBytes.size)) {
                System.arraycopy(newBytes, 0, session.data, p.fileOffset, newBytes.size)
            }
            session.patches += p
            redone.put(patchJson(p))
        }
        session.revision += n
        pageCache.clear()
        searchCache.clear()
        ok(JSONObject()
            .put("redoneCount", n)
            .put("redone", redone)
            .put("remainingUndone", session.undone.size)
            .put("activePatches", session.patches.size)
            .put("newTargetVersion", sha256(session.data)))
    }

    fun editReset(workspaceId: String, editSessionId: String): JSONObject = guarded {
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
        pageCache.clear()
        searchCache.clear()
        ok(JSONObject()
            .put("reset", true)
            .put("clearedPatches", beforePatches)
            .put("clearedUndone", beforeUndone)
            .put("clearedSnapshots", beforeSnapshots)
            .put("newTargetVersion", sha256(session.data)))
    }

    fun readStats(workspaceId: String, editSessionId: String = "", pathHint: String = ""): JSONObject = guarded {
        val resolvedId = resolveWorkspaceId(workspaceId, pathHint)
        val data = if (editSessionId.isNotBlank()) {
            workspaces[resolvedId]?.edits?.get(editSessionId)?.data ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        } else {
            workspaces[resolvedId]?.data ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        }
        val elf = runCatching { lief.parse(data) }.getOrElse { return@guarded err("ELF_PARSE_FAILED", it.message ?: "ELF parse failed") }
        val sections = elf.sections.size
        val symbols = elf.symbols.size
        val dynSymbols = elf.dynSymbols.size
        val symbolFunctions = (elf.symbols + elf.dynSymbols).count { it.type == "FUNC" && !it.imported }
        val exportedFunctions = elf.dynSymbols.count { it.type == "FUNC" && !it.imported && it.value > 0 }
        val analyzedFunctions = rizinFunctions(data, elf).size
        val pltStubs = elf.relocations.count { it.section.contains("plt", true) }
        val strings = elf.strings.size
        val relocations = elf.relocations.size
        val imports = elf.dynSymbols.count { it.imported }
        val jniExports = (elf.symbols + elf.dynSymbols).count { it.name == "JNI_OnLoad" || it.name.startsWith("Java_") }
        val res = JSONObject()
            .put("workspaceId", resolvedId)
            .put("size", data.size)
            .put("sha256", sha256(data))
            .put("arch", elf.architecture)
            .put("bits", elf.bits)
            .put("endian", elf.endian)
            .put("stripped", elf.symbols.isEmpty())
            .put("counts", JSONObject()
                .put("sections", sections)
                .put("symbols", symbols)
                .put("dynSymbols", dynSymbols)
                .put("functions", analyzedFunctions)
                .put("functionsMeaning", "analyzedFunctions")
                .put("functionsFieldMeaning", "functions==analyzedFunctions (Rizin recovered routines including anonymous/local); symbolFunctions are ELF FUNC symbols; exportedFunctions are dynamic exports; pltStubs are import stubs")
                .put("symbolFunctions", symbolFunctions)
                .put("exportedFunctions", exportedFunctions)
                .put("analyzedFunctions", analyzedFunctions)
                .put("pltStubs", pltStubs)
                .put("strings", strings)
                .put("relocations", relocations)
                .put("imports", imports)
                .put("jniExports", jniExports))
            .put("hint", "Use analyze_elf (view=list, subView=<count-name>) for details. analyze_crypto for security-tinged hints. functionsMeaning explains which function count is default.")
        if (editSessionId.isNotBlank()) res.put("editSessionId", editSessionId)
        ok(res)
    }

    fun assembleRaw(workspaceId: String, editSessionId: String = "", asm: String, addr: Long = 0L, thumb: Boolean? = null, mode: String = "auto"): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        if (asm.isBlank()) return@guarded err("INVALID_ARGUMENT", "asm must not be blank", "asm", asm)
        val rawAddr = addr
        val normalizedAddr = if (elf.architecture == "arm32") rawAddr and -2L else rawAddr
        val useThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (rawAddr and 1L) == 1L)
        val encoded = NativeEngine.active().assemble(asm, elf.architecture, normalizedAddr, useThumb)
        ok(JSONObject()
            .put("architecture", elf.architecture)
            .put("addr", hex(normalizedAddr))
            .put("thumb", useThumb)
            .put("mode", if (useThumb) "thumb" else elf.architecture)
            .put("asm", asm)
            .put("size", encoded.size)
            .put("hex", encoded.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }))
    }

    fun analysisReport(workspaceId: String, editSessionId: String = "", writeToFile: Boolean = true): JSONObject = guarded {
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
            .put("programHeaders", JSONArray(elf.programHeaders.map { phJson(it) }))
            .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { dynJson(it) }))
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

    fun editAudit(workspaceId: String, editSessionId: String): JSONObject = guarded {
        val ws = workspaces[workspaceId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        val session = ws.edits[editSessionId] ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val patchesArr = JSONArray()
        session.patches.forEachIndexed { idx, p -> patchesArr.put(patchJson(p).put("index", idx).put("active", true)) }
        val undoneArr = JSONArray()
        session.undone.forEachIndexed { idx, p -> undoneArr.put(patchJson(p).put("index", idx).put("active", false)) }
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

    private fun maybeAutoSnapshot(session: EditSession, trigger: String, settings: SettingsStore) {
        if (!settings.autoSnapshotBeforeEdit) return
        if (session.snapshots.size >= settings.maxSnapshots) session.snapshots.removeAt(0)
        session.snapshots += Snapshot(session.revision, sha256(session.data), System.currentTimeMillis(), session.patches.size, session.data.copyOf())
        AppLog.i("Auto-snapshot (trigger=$trigger) rev=${session.revision} patches=${session.patches.size}")
    }

    private fun maybeAutoPersist(workspaceId: String, session: EditSession, settings: SettingsStore): JSONObject? {
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
                .put("patches", session.patches.mapIndexed { i, p -> patchJson(p).put("index", i) }.toJsonArray())
            file.writeText(payload.toString(2))
            JSONObject().put("autoPersistPath", file.absolutePath)
        }.getOrElse { e -> AppLog.w("auto-persist failed: ${e.message}"); null }
    }

    fun editHex(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        if (!dryRun) maybeAutoSnapshot(session, "hex", settings)
        val strict = settings.editStrictValidation
        val maxPatch = settings.maxPatchBytes
        val elf = lief.parse(session.data)
        val sec = resolveSection(elf, locator) ?: return@guarded err("SECTION_NOT_FOUND", "Section '${locatorTarget(locator, "so_section")}' not found. Call analyze_elf (view=list, subView=sections) to see available sections. If names are duplicated, pass the full locator returned by analyze_elf.", "locator", locator, "availableSections" to elf.sections.mapIndexed { index, section -> sectionKey(section, index) })
        val sectionName = sec.name
        val previews = JSONArray()
        var applied = 0
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            val aliases = listOf("newHex", "hex", "bytes", "data", "rawHex")
                .mapNotNull { key -> edit.optString(key).trim().takeIf { it.isNotBlank() }?.let { key to it } }
                .toMutableList()
            val rawValue = edit.opt("rawValue")
            when (rawValue) {
                is String -> rawValue.trim().takeIf { it.isNotBlank() }?.let { aliases += "rawValue" to it }
                is JSONArray -> aliases += "rawValue" to (0 until rawValue.length()).joinToString("") { index -> "%02x".format(rawValue.optInt(index).coerceIn(0, 255)) }
            }
            val normalizedValues = aliases.map { it.second.replace(Regex("[\\s,]"), "").lowercase() }.distinct()
            if (normalizedValues.size > 1) return@guarded err("CONFLICTING_ARGUMENTS", "Hex aliases contain different values at edit index $i", "edits[$i]", JSONObject(aliases.toMap()))
            val rawHex = aliases.firstOrNull()?.second.orEmpty()
            if (rawHex.isBlank()) {
                return@guarded err("INVALID_ARGUMENT", "Missing newHex (aliases: hex/bytes/data/rawHex/rawValue) for hex edit at index $i", "edits[$i].newHex", null)
            }
            val cleaned = rawHex.replace(" ", "").replace("\t", "").replace("\n", "").replace(",", "")
            if (cleaned.isEmpty() || cleaned.length % 2 != 0 || !cleaned.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                return@guarded err("INVALID_HEX", "newHex must be even-length hex digits, got: $rawHex", "edits[$i].newHex", rawHex)
            }
            val patch = cleaned.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            if (patch.isEmpty()) {
                return@guarded err("INVALID_ARGUMENT", "Decoded patch is empty for hex edit at index $i", "edits[$i].newHex", rawHex)
            }
            if (patch.size > maxPatch) {
                return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes $maxPatch", "edits[$i].newHex", patch.size)
            }
            val relOff = edit.optInt("byteOffset", edit.optInt("offset", Int.MIN_VALUE))
            if (relOff == Int.MIN_VALUE) {
                return@guarded err("INVALID_ARGUMENT", "Missing byteOffset (alias: offset) for hex edit at index $i", "edits[$i].byteOffset", null)
            }
            if (strict && relOff < 0) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "byteOffset must be >= 0, got $relOff", "edits[$i].byteOffset", relOff)
            }
            val off = sec.offset.toInt() + relOff
            if (off < 0 || off + patch.size > session.data.size) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "Hex edit range [${hex(off.toLong())}, +${patch.size}) exceeds file bytes (${session.data.size})", "edits[$i].byteOffset", relOff)
            }
            if (off < sec.offset.toInt() || off + patch.size > sec.offset.toInt() + sec.size.toInt()) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "Hex edit range falls outside section '$sectionName'", "edits[$i].byteOffset", relOff)
            }
            val old = session.data.copyOfRange(off, off + patch.size)
            val preview = JSONObject()
                .put("index", i)
                .put("fileOffset", hex(off.toLong()))
                .put("sectionOffset", hex(relOff.toLong()))
                .put("oldHex", hexBytes(old))
                .put("newHex", hexBytes(patch))
                .put("length", patch.size)
            if (dryRun) {
                previews.put(preview)
                continue
            }
            session.patches += PatchRecord(System.currentTimeMillis(), "hex", locator, off, hexBytes(old), hexBytes(patch))
            System.arraycopy(patch, 0, session.data, off, patch.size)
            applied++
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        session.revision++
        pageCache.clear()
        searchCache.clear()
        val res = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", applied)
        maybeAutoPersist(workspaceId, session, settings)?.let { res.put("autoPersist", it) }
        ok(res)
    }

    fun editHexVa(workspaceId: String, editSessionId: String, va: Long, patch: ByteArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        if (patch.isEmpty()) return@guarded err("INVALID_ARGUMENT", "patchHex decoded to empty bytes", "patchHex", "")
        val settings = SettingsStore(context)
        if (patch.size > settings.maxPatchBytes) return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes ${settings.maxPatchBytes}", "patchHex", patch.size)
        val elf = lief.parse(session.data)
        val off = vaToOffset(elf, va)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(va)} cannot be mapped to a file offset", "va", hex(va))
        if (off < 0 || off + patch.size > session.data.size) return@guarded err("OFFSET_OUT_OF_RANGE", "Patch range [${hex(off.toLong())}, +${patch.size}) exceeds file bytes (${session.data.size})", "va", hex(va))
        val old = session.data.copyOfRange(off, off + patch.size)
        val section = sectionForOffset(elf, off.toLong())
        val preview = JSONObject()
            .put("fileOffset", hex(off.toLong()))
            .put("virtualAddress", hex(va))
            .put("section", section?.name ?: JSONObject.NULL)
            .put("sectionOffset", section?.let { hex(off.toLong() - it.offset) } ?: JSONObject.NULL)
            .put("oldHex", hexBytes(old))
            .put("newHex", hexBytes(patch))
            .put("length", patch.size)
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", JSONArray().put(preview))
                .put("previewCount", 1)
                .put("targetVersion", sha256(session.data)))
        }
        maybeAutoSnapshot(session, "hex-va", settings)
        session.patches += PatchRecord(System.currentTimeMillis(), "hex-va", "va:${hex(va)}", off, hexBytes(old), hexBytes(patch))
        System.arraycopy(patch, 0, session.data, off, patch.size)
        session.revision++
        pageCache.clear()
        searchCache.clear()
        val res = JSONObject()
            .put("workspaceId", workspaceId)
            .put("editSessionId", editSessionId)
            .put("newTargetVersion", sha256(session.data))
            .put("editCount", session.revision)
            .put("patchCount", session.patches.size)
            .put("applied", 1)
            .put("patch", preview)
        maybeAutoPersist(workspaceId, session, settings)?.let { res.put("autoPersist", it) }
        ok(res)
    }

    fun editAsm(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        if (!dryRun) maybeAutoSnapshot(session, "asm", settings)
        val maxPatch = settings.maxPatchBytes
        val elf = lief.parse(session.data)
        val name = locatorTarget(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        val startVa = resolveCodeAddress(session.data, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address '$name' could not be resolved", "locator", locator, "acceptedForms" to acceptedLocatorForms())
        val base = vaToOffset(elf, startVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Function address ${hex(startVa)} cannot be mapped", "locator", locator)
        val thumb = elf.architecture == "arm32" && ((sym?.value ?: startVa) and 1L) == 1L
        val functionSize = rizinFunctionSize(session.data, elf, startVa) ?: sym?.let { functionByteSize(elf, it, base, session.data.size) } ?: functionByteSizeFromAddress(elf, startVa, base, session.data.size)
        val assembledNop = runCatching { NativeEngine.active().assemble("nop", elf.architecture, startVa, thumb) }
            .getOrElse { architectureNop(elf.architecture, thumb) }
        val nop = if (assembledNop.isEmpty()) architectureNop(elf.architecture, thumb) else assembledNop
        val previews = JSONArray()
        var applied = 0
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            val mode = edit.optString("mode", "replace_instructions")
            if (mode in setOf("insert_before", "insert_after", "prepend_function", "append_function", "write_function") && !edit.has("byteLength") && !edit.has("instructionCount")) {
                return@guarded err("UNSUPPORTED_OPERATION", "Insertion-style asm edits require an explicit byteLength or instructionCount because Android native build does not relocate downstream function bytes")
            }
            var range = asmEditRange(edit, startVa, thumb, elf.architecture, nop.size, functionSize)
            val patch = if (mode == "nop_out" || mode == "delete_instructions") {
                repeatBytes(nop, range.second)
            } else {
                val asm = edit.optString("writeAsm", edit.optString("newAsm", edit.optString("asm", edit.optString("assembly", "")))).trim()
                if (asm.isBlank()) return@guarded err("ASM_SYNTAX_ERROR", "Missing writeAsm/newAsm/asm (alias: assembly) for asm edit at index $i")
                val encoded = runCatching { NativeEngine.active().assemble(asm, elf.architecture, startVa + range.first, thumb) }
                    .getOrElse { return@guarded err("ASM_SYNTAX_ERROR", it.message ?: "Assembler failed to encode: $asm") }
                if (encoded.isEmpty()) return@guarded err("ASM_SYNTAX_ERROR", "Assembler produced no bytes for: $asm")
                if (encoded.size > range.second && !edit.has("instructionCount") && !edit.has("byteLength")) {
                    val step = if (thumb) 2 else if (elf.architecture in setOf("arm32", "arm64")) 4 else nop.size.coerceAtLeast(1)
                    val needed = ((encoded.size + step - 1) / step) * step
                    if (range.first + needed <= functionSize) range = range.first to needed
                }
                if (encoded.size > range.second) return@guarded err("SIZE_MISMATCH", "Assembled code (${encoded.size}B) is larger than selected instruction range (${range.second}B). Set instructionCount/byteLength to cover multiple instructions, or split into single-instruction edits.", "edits[$i]", JSONObject().put("assembled", encoded.size).put("range", range.second))
                encoded + repeatBytes(nop, range.second - encoded.size)
            }
            if (patch.size > maxPatch) {
                return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes $maxPatch", "edits[$i]", patch.size)
            }
            val writeOffset = base + range.first
            val old = session.data.copyOfRange(writeOffset, writeOffset + patch.size)
            val asmText = edit.optString("writeAsm", edit.optString("newAsm", edit.optString("asm", edit.optString("assembly", mode))))
            val preview = JSONObject()
                .put("index", i)
                .put("fileOffset", hex(writeOffset.toLong()))
                .put("virtualAddress", hex(startVa + range.first))
                .put("oldHex", hexBytes(old))
                .put("newHex", hexBytes(patch))
                .put("asm", asmText)
                .put("mode", mode)
                .put("length", patch.size)
            if (dryRun) {
                previews.put(preview)
                continue
            }
            session.patches += PatchRecord(System.currentTimeMillis(), "asm", locator, writeOffset, hexBytes(old), hexBytes(patch), asmText)
            System.arraycopy(patch, 0, session.data, base + range.first, patch.size)
            applied++
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        session.revision++
        pageCache.clear()
        searchCache.clear()
        val resAsm = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", applied)
        maybeAutoPersist(workspaceId, session, settings)?.let { resAsm.put("autoPersist", it) }
        ok(resAsm)
    }

    fun editSymbol(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        if (!dryRun) maybeAutoSnapshot(session, "symbol", settings)
        val name = locatorTarget(locator, "so_symbol")
        val previews = JSONArray()
        var applied = 0
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            if (edit.optString("op", "rename") == "rename") {
                val newName = edit.optString("newName", name)
                if (newName.length > name.length) return@guarded err("SYMTAB_OVERFLOW", "Rename to longer symbol is not supported in native Android build")
                val oldBytes = name.toByteArray()
                val newBytes = newName.toByteArray()
                val pos = indexOf(session.data, oldBytes)
                if (pos < 0) return@guarded err("SYMBOL_NOT_FOUND", "Symbol string not found in SO bytes")
                val replacement = ByteArray(oldBytes.size) { if (it < newBytes.size) newBytes[it] else 0 }
                val preview = JSONObject()
                    .put("index", i)
                    .put("fileOffset", hex(pos.toLong()))
                    .put("oldHex", hexBytes(oldBytes))
                    .put("newHex", hexBytes(replacement))
                    .put("asm", "rename $name -> $newName")
                    .put("length", oldBytes.size)
                if (dryRun) {
                    previews.put(preview)
                    continue
                }
                session.patches += PatchRecord(System.currentTimeMillis(), "symbol", locator, pos, hexBytes(oldBytes), hexBytes(replacement), "rename $name -> $newName")
                for (j in oldBytes.indices) session.data[pos + j] = if (j < newBytes.size) newBytes[j] else 0
                applied++
            } else {
                return@guarded err("UNSUPPORTED_OPERATION", "Only same-or-shorter rename is supported")
            }
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        session.revision++
        pageCache.clear()
        searchCache.clear()
        val resSym = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", applied)
        maybeAutoPersist(workspaceId, session, settings)?.let { resSym.put("autoPersist", it) }
        ok(resSym)
    }

    fun editCheck(workspaceId: String, editSessionId: String): JSONObject = guarded {
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
                        if (off in 0..(bytes.size - len)) hexBytes(bytes.copyOfRange(off, off + len)) else ""
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
        if (settings.editCheckDeep && claimed > 0 && effective == 0) {
            warnings.put(JSONObject().put("code", "NO_EFFECTIVE_CHANGES").put("message", "Session claims $claimed patch(es) but zero effective byte ranges differ from the original SO"))
        }
        if (settings.editCheckDeep && emptyPatches > 0) {
            warnings.put(JSONObject().put("code", "EMPTY_PATCHES_SUMMARY").put("message", "$emptyPatches of $claimed patch(es) have empty newHex (no-op writes)").put("emptyPatchCount", emptyPatches))
        }
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

    fun build(workspaceId: String, editSessionId: String, outputName: String, conflictStrategy: String = "", writeReport: Boolean? = null, writeToWorkDir: Boolean? = null): JSONObject = guarded {
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

    fun buildMany(workspaceId: String, editSessionId: String, outputs: JSONArray, conflictStrategy: String = "", writeReport: Boolean? = null, writeToWorkDir: Boolean? = null): JSONObject = guarded {
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

    private fun writeCopyToWorkDirectory(fileName: String, bytes: ByteArray): String? {
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

    fun listBuildOutputs(prefix: String = "", limit: Int = 200): JSONObject = guarded {
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

    private fun auditDir(): File {
        val dir = File(context.getExternalFilesDir(null) ?: context.filesDir, "audits")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun reportDir(): File {
        val dir = File(context.getExternalFilesDir(null) ?: context.filesDir, "reports")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun persistAudit(workspaceId: String, editSessionId: String): JSONObject = guarded {
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
            .put("patches", session.patches.mapIndexed { i, p -> patchJson(p).put("index", i).put("active", true) }.toJsonArray())
            .put("undonePatches", session.undone.mapIndexed { i, p -> patchJson(p).put("index", i).put("active", false) }.toJsonArray())
            .put("snapshots", session.snapshots.mapIndexed { i, s -> JSONObject().put("index", i).put("revision", s.revision).put("sha256", s.sha256).put("patchCount", s.patchCount).put("timeMillis", s.timeMillis) }.toJsonArray())
        file.writeText(payload.toString(2))
        ok(JSONObject().put("persisted", true).put("path", file.absolutePath).put("size", file.length()).put("persistedAt", ts))
    }

    fun listAudits(prefix: String = "", limit: Int = 100): JSONObject = guarded {
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

    fun loadAudit(file: String): JSONObject = guarded {
        val f = File(file)
        if (!f.exists() || !f.isFile) return@guarded err("AUDIT_NOT_FOUND", "Audit file not found: $file", "file", file)
        val obj = runCatching { JSONObject(f.readText()) }.getOrElse { return@guarded err("AUDIT_CORRUPTED", "Audit file is not valid JSON: ${it.message}", "file", file) }
        ok(obj.put("path", f.absolutePath))
    }

    fun diff(workspaceId: String, editSessionId: String, limit: Int, compareSessionId: String = "", compareWorkspaceId: String = ""): JSONObject = guarded {
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
            ranges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start).put("oldHex", hexBytes(old)).put("newHex", hexBytes(next)))
        }
        val result = JSONObject()
            .put("workspaceId", workspaceId)
            .put("editSessionId", editSessionId)
            .put("patchCount", session.patches.size)
            .put("patches", session.patches.map(::patchJson).toJsonArray())
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

    fun analyze(workspaceId: String, editSessionId: String, pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val bytes = dataFor(resolvedWorkspaceId, editSessionId)
        val allSymbols = elf.symbols + elf.dynSymbols
        val names = allSymbols.map { it.name }
        val imports = elf.dynSymbols.filter { it.imported }.map { it.name }
        val strings = elf.strings.map { it.value }
        val jniExports = names.filter { it == "JNI_OnLoad" || it.startsWith("Java_") }.take(200)
        val registerNativesHints = (names + strings).filter { it.contains("RegisterNatives", ignoreCase = true) }.distinct().take(50)
        val urlStrings = strings.filter { it.contains("http://") || it.contains("https://") }.take(80)
        val pathStrings = strings.filter { it.startsWith("/") || it.contains("/data/") || it.contains("/sdcard/") }.take(80)
        val commandStrings = strings.filter { value ->
            listOf("su", "sh ", "chmod", "mount", "getprop", "setprop").any { value.contains(it, ignoreCase = true) }
        }.take(80)
        val cryptoImports = imports.filter { it.contains("ssl", true) || it.contains("crypto", true) || it.contains("AES", true) || it.contains("RSA", true) }.distinct()
        val dynamicImports = imports.filter { it in setOf("dlopen", "dlsym", "dlclose", "android_dlopen_ext") }.distinct()
        val symbolFunctions = allSymbols.filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
        val overview = ElfOverviewBuilder.build(
            elf = elf,
            bytes = bytes,
            fileName = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so",
            sha256 = sha256(bytes),
            size = bytes.size.toLong(),
            functionCountHint = symbolFunctions.size,
        )
        ok(JSONObject()
            .put("workspaceId", resolvedWorkspaceId)
            .put("architecture", elf.architecture)
            .put("bits", elf.bits)
            .put("entryPoint", hex(elf.entry))
            .put("stripped", elf.symbols.isEmpty())
            .put("hasDebugInfo", elf.sections.any { it.name.startsWith(".debug") })
            .put("hasJniOnLoad", names.any { it == "JNI_OnLoad" })
            .put("jniExports", jniExports.toJsonArray())
            .put("registerNativesHints", registerNativesHints.toJsonArray())
            .put("dynamicLoaderImports", dynamicImports.toJsonArray())
            .put("cryptoImports", cryptoImports.toJsonArray())
            .put("interestingStrings", JSONObject()
                .put("urls", urlStrings.toJsonArray())
                .put("paths", pathStrings.toJsonArray())
                .put("commands", commandStrings.toJsonArray()))
            .put("counts", JSONObject()
                .put("sections", elf.sections.size)
                .put("symbols", elf.symbols.size)
                .put("dynsyms", elf.dynSymbols.size)
                .put("imports", imports.size)
                .put("relocations", elf.relocations.size)
                .put("strings", elf.strings.size)
                .put("segments", elf.programHeaders.size)
                .put("needed", overview.optJSONArray("neededLibraries")?.length() ?: 0)
                .put("exports", overview.optInt("exportCount"))
                .put("functions", overview.optInt("functionCount")))
            .put("overview", overview))
    }

    fun overview(workspaceId: String, editSessionId: String = "", pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val bytes = dataFor(resolvedWorkspaceId, editSessionId)
        val symbolFunctions = (elf.symbols + elf.dynSymbols).filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
        ok(
            ElfOverviewBuilder.build(
                elf = elf,
                bytes = bytes,
                fileName = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so",
                sha256 = sha256(bytes),
                size = bytes.size.toLong(),
                functionCountHint = symbolFunctions.size,
            ).put("workspaceId", resolvedWorkspaceId),
        )
    }

    fun continuePage(cursor: String): JSONObject = guarded {
        if (cursor.startsWith("source:")) {
            return@guarded listAvailableSos(cursor = cursor)
        }
        if (cursor.startsWith("disasm:")) {
            return@guarded disasm("", "", "", 0, cursor)
        }
        val state = pageCache[cursor] ?: return@guarded err("INVALID_CURSOR", "Cursor expired or not found", "cursor", cursor)
        page(state.field, state.items, state.limit, cursor)
    }

    private fun guarded(block: () -> JSONObject): JSONObject = try {
        block()
    } catch (t: Throwable) {
        AppLog.e("Tool failed", t)
        val message = t.message ?: "Tool failed"
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
    private fun openWorkspace(path: String, temporary: Boolean): Workspace {
        val archiveEntry = path.substringAfterLast('!', "")
        if (archiveEntry.isNotBlank() && !archiveEntry.endsWith(".so", ignoreCase = true)) {
            error("NOT_ELF_INPUT: $path is an APK/JAR entry, not an ELF SO file. Use apk_analyze or an APK MCP tool.")
        }
        val keyFallback = "local:$path"
        val src = findSource(path) ?: resolveLocalSoSource(path) ?: error("SO path not found: $path")
        val key = sourceKey(src).ifBlank { keyFallback }
        workspaceBySourceKey[key]?.let { existingId ->
            workspaces[existingId]?.let { return it }
        }
        val original = when (src.source) {
            "build_output", "local_file" -> runCatching { java.io.File(src.path).readBytes() }.getOrElse { error("SO path not found: $path") }
            else -> (workDir ?: error("No work directory selected")).readSource(src)
        }
        require(original.size >= 4 && original[0] == 0x7f.toByte() && original[1] == 'E'.code.toByte() && original[2] == 'L'.code.toByte() && original[3] == 'F'.code.toByte()) {
            "NOT_ELF_INPUT: ${src.path} is not an ELF SO file. Use apk_analyze or an APK MCP tool for APK/JAR entries."
        }
        val prepared = prepareAnalysisInput(original)
        val bytes = prepared.first
        val elf = lief.parse(bytes)
        val id = "so-ws-${UUID.randomUUID()}"
        val ws = Workspace(
            id,
            src,
            bytes,
            elf,
            temporary,
            sha256(original),
            prepared.second,
            prepared.third,
        )
        workspaces[id] = ws
        workspaceBySourceKey[key] = id
        AppLog.i("Opened ${src.path} as $id")
        return ws
    }

    private fun prepareAnalysisInput(original: ByteArray): Triple<ByteArray, String, JSONObject> {
        val before = lief.parse(original)
        val facts = JSONObject()
            .put("attempted", false)
            .put("changed", false)
            .put("sectionsBefore", before.sections.size)
            .put("programHeadersBefore", before.programHeaders.size)
            .put("symbolsBefore", before.symbols.size)
            .put("dynSymbolsBefore", before.dynSymbols.size)
            .put("functionSymbolsRecovered", false)
        if (before.sections.isNotEmpty()) {
            facts.put("reason", "section_table_present")
            return Triple(original, "original", facts)
        }
        if (original.size < 5 || !xanso.available()) {
            facts.put("reason", if (original.size < 5) "invalid_elf_ident" else "xanso_unavailable")
            return Triple(original, "original", facts)
        }
        facts.put("attempted", true)
        val elfClass = original[4].toInt() and 0xff
        val recovered = when (elfClass) {
            1 -> xanso.buildSections(original)
            2 -> xanso.recoverElf64Sections(original)?.let { lief.fixSections(it) }
            else -> null
        }
        if (recovered == null || recovered.isEmpty()) {
            facts.put("reason", "xanso_recovery_failed")
            return Triple(original, "original", facts)
        }
        val after = lief.parse(recovered)
        if (after.sections.isEmpty()) {
            facts.put("reason", "recovered_section_table_not_parseable")
            return Triple(original, "original", facts)
        }
        facts
            .put("changed", !recovered.contentEquals(original))
            .put("reason", "missing_section_table")
            .put("recoveryMode", if (elfClass == 1) "xanso32_section_fix" else "xanso64_section_recovery_lief_finalize")
            .put("sectionsAfter", after.sections.size)
            .put("programHeadersAfter", after.programHeaders.size)
            .put("symbolsAfter", after.symbols.size)
            .put("dynSymbolsAfter", after.dynSymbols.size)
            .put("functionSymbolsRecovered", after.symbols.count { it.type == "FUNC" } > before.symbols.count { it.type == "FUNC" })
        return Triple(recovered, "xanso_recovered_sections", facts)
    }
    private fun resolveLocalSoSource(rawPath: String): SoSource? {
        if (rawPath.isBlank()) return null
        val file = java.io.File(rawPath)
        if (!file.exists() || !file.isFile) return null
        val extDir = context.getExternalFilesDir(null)?.canonicalPath
        val intDir = context.filesDir.canonicalPath
        val canonical = runCatching { file.canonicalPath }.getOrDefault(rawPath)
        val allowed = listOfNotNull(extDir, intDir)
        if (allowed.none { canonical.startsWith(it) }) return null
        if (!file.name.endsWith(".so", ignoreCase = true)) return null
        return SoSource(
            path = canonical,
            source = "build_output",
            name = file.name,
            size = file.length(),
            modified = file.lastModified(),
            treeDocumentUri = null,
        )
    }
    private fun findSource(rawPath: String): SoSource? {
        if (rawPath.isBlank()) return null
        val path = rawPath.trim().removePrefix("/")
        workDir?.let { ensureSources(it) }
        val apkUri = rawPath.trim().removePrefix("content://apk/")
        if (apkUri != rawPath.trim() && apkUri.isNotBlank()) {
            val separator = apkUri.indexOf('/')
            if (separator > 0) {
                val apkName = apkUri.substring(0, separator)
                val entry = apkUri.substring(separator + 1)
                sources.firstOrNull {
                    it.source == "apk" &&
                        it.apkPath?.substringAfterLast('/') == apkName &&
                        it.apkEntry == entry
                }?.let { return it }
            }
        }
        return sources.firstOrNull { it.path == rawPath || it.path == path }
            ?: sources.firstOrNull { it.name == rawPath || it.name == path }
            ?: sources.firstOrNull { it.apkEntry == rawPath || it.apkEntry == path }
            ?: sources.firstOrNull { it.path.endsWith("/$path") || it.path.contains(path) }
    }
    private fun resolveWorkspaceId(workspaceId: String, pathHint: String = ""): String {
        if (workspaceId.isNotBlank() && workspaces.containsKey(workspaceId)) return workspaceId
        if (pathHint.isNotBlank()) return openWorkspace(pathHint, temporary = true).id
        if (workspaceId.isNotBlank()) {
            findSource(workspaceId)?.let { return openWorkspace(it.path, temporary = true).id }
        }
        if (workspaceId.isBlank() && workspaces.size == 1) return workspaces.keys.first()
        error("Workspace not found: $workspaceId")
    }
    private fun workspace(id: String): Workspace = workspaces[id] ?: error("Workspace not found: $id")
    private fun dataFor(workspaceId: String, editSessionId: String): ByteArray = if (editSessionId.isBlank()) workspace(workspaceId).data else workspace(workspaceId).edits[editSessionId]?.data ?: error("Edit session not found")
    private fun elfFor(workspaceId: String, editSessionId: String): ElfFile = if (editSessionId.isBlank()) workspace(workspaceId).elf else lief.parse(dataFor(workspaceId, editSessionId))

    private fun locatorTarget(locator: String, prefix: String = ""): String {
        val trimmed = locator.trim()
        val withoutPrefix = if (prefix.isNotBlank() && trimmed.startsWith("$prefix:")) trimmed.substringAfter(':') else trimmed
        return withoutPrefix.substringAfterLast('!').substringBeforeLast('@').trim()
    }

    private fun locatorAddress(locator: String): Long? {
        val trimmed = locator.trim()
        // Prefer explicit @addr / !file@addr tail for fcn.NAME@0xVA and so_function forms.
        val at = trimmed.substringAfterLast('@', "")
        if (at.isNotBlank() && at != trimmed) return parseHexLong(at)
        val bangTail = trimmed.substringAfterLast('!', "")
        if (bangTail.isNotBlank() && bangTail != trimmed && bangTail.contains('@')) {
            return parseHexLong(bangTail.substringAfterLast('@'))
        }
        return null
    }

    private fun parseHexLong(value: String): Long? {
        val trimmed = value.trim()
        if (trimmed.isBlank()) return null
        val normalized = trimmed.removePrefix("0x").removePrefix("0X")
        return normalized.toLongOrNull(16)
    }

    private fun normalizeSymbolName(raw: String): String {
        val base = raw.substringBefore('@').trim()
        return base
            .removePrefix("so_function:")
            .removePrefix("so_symbol:")
            .substringAfterLast('!')
            .removePrefix("sym.imp.")
            .removePrefix("sym.")
            .removePrefix("fcn.")
            .ifBlank { raw.substringBefore('@').trim() }
    }

    private fun acceptedLocatorForms(): JSONArray = JSONArray(
        listOf(
            "0xVA",
            "VA",
            "symbolName",
            "fcn.NAME",
            "fcn.0xVA",
            "fcn.0000VA",
            "fcn.NAME@0xVA",
            "sym.NAME",
            "sym.imp.NAME",
            "so_function:name@0xVA",
            "so_symbol:name@0xVA",
        ),
    )

    private fun resolveCodeAddress(bytes: ByteArray, elf: ElfFile, locator: String, explicitAddress: String = ""): Long? {
        val target = locator.ifBlank { explicitAddress }.trim()
        if (target.isEmpty() && explicitAddress.isBlank()) return null
        // Explicit address fields and @addr tails win first (fcn.0000b208@0xb208).
        parseHexLong(explicitAddress)?.let { return it }
        locatorAddress(target)?.let { return it }
        parseHexLong(target)?.let { return it }

        val name = locatorTarget(target, if (target.startsWith("so_symbol:")) "so_symbol" else "so_function")
        val bare = normalizeSymbolName(name)

        // fcn.0000b208 / fcn.b208 — zero-padded hex function name without 0x
        if (bare.isNotEmpty() && bare.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } && bare.length >= 3) {
            bare.toLongOrNull(16)?.takeIf { it > 0 }?.let { return it }
        }

        (elf.symbols + elf.dynSymbols).firstOrNull {
            it.name == name || it.name == bare || it.name == "sym.$bare" || it.name == "sym.imp.$bare" || it.name == "fcn.$bare"
        }?.value?.and(-2L)?.takeIf { it > 0 }?.let { return it }

        resolveRizinFunctionAddress(bytes, elf, name)?.let { return it }
        if (bare != name) resolveRizinFunctionAddress(bytes, elf, bare)?.let { return it }
        resolveRizinFunctionAddress(bytes, elf, "fcn.$bare")?.let { return it }
        return null
    }

    private fun hexToBytes(value: String): ByteArray? {
        val clean = value.replace(" ", "").replace("\n", "").replace("\t", "")
        if (clean.isBlank() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) + lo).toByte()
        }
        return out
    }

    fun snapshotBytes(workspaceId: String, editSessionId: String): Pair<ByteArray, String> {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        return bytes to elf.architecture
    }

    fun fixSections(workspaceId: String, editSessionId: String): JSONObject {
        if (!lief.available()) return err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
        val original = dataFor(workspaceId, editSessionId)
        val before = original.copyOf()
        val beforeHash = sha256(before)
        val elfBefore = lief.parse(before)
        val fixed = lief.fixSections(before)
        val afterHash = sha256(fixed)
        val diffRanges = byteDiffRanges(before, fixed)
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
                targetSession.revision++
                val firstDiff = diffRanges.optJSONObject(0)
                targetSession.patches += PatchRecord(System.currentTimeMillis(), "fix_sections", "xanso:fix_sections", parseHexLong(firstDiff?.optString("fileOffset") ?: "0x0")?.toInt() ?: 0, firstDiff?.optString("oldHex") ?: "", firstDiff?.optString("newHex") ?: "", "rebuild section headers; diffRangeCount=${diffRanges.length()}")
                editSessionId
            }
            else -> {
                val newSessionId = "fix-${UUID.randomUUID()}"
                val session = EditSession(newSessionId, fixed)
                workspaces[workspaceId]?.edits?.put(newSessionId, session)
                newSessionId
            }
        }
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

    // ── Rizin-backed deep analysis (ESIL/CFG/crypto/diff/functions/xrefs/search) ──

    fun rzAnalyze(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val result = NativeEngine.active().analyze(bytes, elf.architecture)
        ok(JSONObject(result).put("workspaceId", workspaceId).put("architecture", elf.architecture))
    }

    fun rzFunctions(workspaceId: String, editSessionId: String = "", limit: Int = SettingsStore(context).defaultLimit, cursor: String = ""): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val result = NativeEngine.active().functions(bytes, elf.architecture)
        val arr = runCatching { JSONArray(result) }.getOrNull()
        if (arr != null && arr.length() > 0) {
            val wsName = workspaces[workspaceId]?.source?.name ?: "lib.so"
            val list = (0 until arr.length()).map {
                val item = arr.getJSONObject(it)
                val name = item.optString("name")
                val start = item.optLong("addr") and -2L
                item.put("locator", "so_function:$wsName!$name@${hex(start)}")
                    .put("startAddr", hex(start))
                    .put("endAddr", hex(start + item.optLong("size")))
                    .put("kind", rizinFunctionKind(elf, item))
            }
            return@guarded page("functions", list, limit, cursor).put("workspaceId", workspaceId).put("architecture", elf.architecture).put("source", "rizin")
        }
        val wsName = workspaces[workspaceId]?.source?.name ?: "lib.so"
        val fallback = (elf.symbols + elf.dynSymbols)
            .filter { it.type == "FUNC" && !it.imported }
            .map { JSONObject().put("locator", "so_function:$wsName!${it.name}@${hex(it.value and -2L)}").put("name", it.name).put("offset", it.value and -2L).put("addr", it.value and -2L).put("startAddr", hex(it.value and -2L)).put("endAddr", hex((it.value and -2L) + it.size)).put("size", it.size).put("calls", 0).put("kind", functionKind(elf, it)).put("source", "lief-dynsym-fallback") }
        val warning = if (arr == null) "Rizin function JSON could not be parsed; using LIEF exported FUNC symbols as fallback." else "Rizin returned no functions; using LIEF exported FUNC symbols as fallback."
        page("functions", fallback, limit, cursor).put("workspaceId", workspaceId).put("architecture", elf.architecture).put("source", "lief-dynsym-fallback").put("warning", warning)
    }

    fun rzCfg(workspaceId: String, editSessionId: String, locator: String): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val name = locatorTarget(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        val funcVa = resolveCodeAddress(bytes, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address could not be resolved", "locator", locator)
        validateCodeAddress(elf, funcVa, false)?.let { return@guarded it }
        val result = NativeEngine.active().cfg(bytes, elf.architecture, funcVa)
        val payload = JSONObject(result).put("workspaceId", workspaceId).put("functionName", name).put("functionVa", hex(funcVa))
        normalizeCfgPayload(payload, elf)
        if (payload.has("error")) return@guarded err("RIZIN_CFG_FAILED", payload.optString("error", "Rizin CFG failed"), "locator", locator, "payload" to payload)
        ok(payload)
    }

    fun rzXrefs(workspaceId: String, editSessionId: String, locator: String, direction: String = "to"): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val name = normalizeSymbolName(locatorTarget(locator, if (locator.startsWith("so_function:")) "so_function" else "so_symbol"))
        val bareName = name.removePrefix("sym.imp.").removePrefix("sym.")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull {
            it.name == name || it.name == bareName || it.name == "sym.imp.$bareName" || it.name == "sym.$bareName"
        }
        val importHints = rizinImportStubHints(workspaceId, editSessionId, elf)
        val pltStubVa = importHints.entries.firstOrNull {
            it.value == bareName || it.value == name || "sym.imp.${it.value}" == name
        }?.key
        val atVa = locatorAddress(locator)
            ?: parseHexLong(locator)
            ?: resolveCodeAddress(bytes, elf, locator)
            ?: sym?.value?.and(-2L)?.takeIf { it > 0 }
            ?: pltStubVa
            ?: return@guarded err("SYMBOL_NOT_FOUND", "Symbol not found and locator has no address or PLT fallback", "locator", locator)
        val result = NativeEngine.active().xrefs(bytes, elf.architecture, atVa, direction)
        val payload = JSONObject(result)
        val xrefs = payload.optJSONArray("xrefs") ?: JSONArray().also { payload.put("xrefs", it) }
        val seen = HashSet<String>()
        for (i in 0 until xrefs.length()) {
            val item = xrefs.getJSONObject(i)
            if (!item.has("sourceType")) item.put("sourceType", "direct")
            if (!item.has("type") || item.optString("type").isBlank()) item.put("type", "code")
            seen += "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType", item.optString("type"))}:${item.optString("direction")}"
        }
        val relocations = elf.relocations.filter {
            it.symbol == bareName || it.symbol == name || it.symbol == "sym.imp.$bareName" ||
                (parseHexLong(locator) != null && it.offset == atVa) || it.offset == atVa
        }
        val gotSlots = relocations.map { it.offset }.toMutableSet()
        if (direction == "to" || direction == "both") {
            relocations.forEach { relocation ->
                val key = "${relocation.offset}:$atVa:relocation:incoming"
                if (seen.add(key)) {
                    xrefs.put(
                        JSONObject()
                            .put("from", relocation.offset)
                            .put("to", atVa)
                            .put("type", "relocation")
                            .put("sourceType", "relocation")
                            .put("direction", "incoming")
                            .put("section", relocation.section)
                            .put("symbol", relocation.symbol)
                            .put("evidence", "${relocation.section} relocation maps ${hex(relocation.offset)} to $bareName"),
                    )
                }
            }
            if (elf.architecture == "arm64") {
                val targets = (gotSlots + atVa + listOfNotNull(pltStubVa)).toSet()
                aarch64ComputedXrefs(bytes, elf, targets).forEach { item ->
                    val key = "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType")}:incoming"
                    if (seen.add(key)) xrefs.put(item)
                    if (item.optString("sourceType") == "got") gotSlots += item.optLong("to")
                }
                // Direct BL/B to function body. BL to PLT stub is classified as plt_call.
                if (pltStubVa != null) {
                    aarch64BranchXrefs(bytes, elf, setOf(pltStubVa)).forEach { item ->
                        item.put("to", atVa)
                        item.put("pltStub", hex(pltStubVa))
                        item.put("sourceType", "plt_call")
                        item.put("type", "plt_call")
                        item.put("evidence", "AArch64 BL to PLT stub ${hex(pltStubVa)} for $bareName")
                        val key = "${item.optLong("from")}:$atVa:plt_call:incoming"
                        if (seen.add(key)) xrefs.put(item)
                    }
                }
                // Direct BL/B to the resolved target itself (non-PLT body / local function).
                aarch64BranchXrefs(bytes, elf, setOf(atVa)).forEach { item ->
                    if (pltStubVa != null && item.optLong("to") == pltStubVa) return@forEach
                    val key = "${item.optLong("from")}:${item.optLong("to")}:direct_call:incoming"
                    if (seen.add(key)) xrefs.put(item)
                }
                // LDR from GOT then BLR Xn (indirect call through GOT).
                aarch64GotBlrXrefs(bytes, elf, gotSlots, atVa, bareName).forEach { item ->
                    val key = "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType")}:incoming"
                    if (seen.add(key)) xrefs.put(item)
                }
            }
        }
        val bySource = JSONObject()
        for (i in 0 until xrefs.length()) {
            val st = xrefs.getJSONObject(i).optString("sourceType", "direct")
            bySource.put(st, bySource.optInt(st, 0) + 1)
        }
        ok(
            payload
                .put("workspaceId", workspaceId)
                .put("symbolName", bareName)
                .put("direction", direction)
                .put("atVa", hex(atVa))
                .put("pltStubVa", pltStubVa?.let(::hex) ?: JSONObject.NULL)
                .put("resolvedVia", when {
                    sym?.imported == true && sym.value == 0L -> "plt_stub"
                    pltStubVa != null && atVa == pltStubVa -> "plt_stub"
                    else -> "locator"
                })
                .put("relocationSlots", JSONArray(relocations.map { hex(it.offset) }))
                .put("sourceTypeCounts", bySource)
                .put("xrefCount", xrefs.length())
                .put("sourceTypeLegend", JSONObject()
                    .put("direct", "Rizin analysis graph edge")
                    .put("relocation", "ELF relocation slot")
                    .put("got", "ADRP+LDR GOT load")
                    .put("computed", "ADRP+ADD computed address")
                    .put("direct_call", "direct BL/B to target")
                    .put("plt_call", "BL to PLT stub of target")
                    .put("got_call", "BLR through GOT slot of target")),
        )
    }

    private fun setOfNotNull(vararg values: Long?): Set<Long> = values.filterNotNull().toSet()

    private fun aarch64ComputedXrefs(bytes: ByteArray, elf: ElfFile, targets: Set<Long>): List<JSONObject> {
        if (targets.isEmpty()) return emptyList()
        val found = ArrayList<JSONObject>()
        elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 8 }.forEach { section ->
            val start = section.offset.toInt().coerceAtLeast(0)
            val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt()
            var offset = start
            while (offset + 8 <= end) {
                val adrp = littleEndianInt(bytes, offset)
                if (adrp and 0x9f000000.toInt() == 0x90000000.toInt()) {
                    val register = adrp and 0x1f
                    val imm21 = (((adrp ushr 5) and 0x7ffff) shl 2) or ((adrp ushr 29) and 0x3)
                    val signed = if (imm21 and 0x100000 != 0) imm21 or -0x200000 else imm21
                    val instructionVa = section.addr + (offset - start)
                    val page = (instructionVa and -0x1000L) + (signed.toLong() shl 12)
                    for (lookAhead in 1..4) {
                        val nextOffset = offset + lookAhead * 4
                        if (nextOffset + 4 > end) break
                        val next = littleEndianInt(bytes, nextOffset)
                        val baseRegister = (next ushr 5) and 0x1f
                        if (baseRegister != register) continue
                        val addImmediate = next and 0x7f000000 == 0x11000000
                        val loadUnsigned = next and 0x3b000000 == 0x39000000 && next and 0x00400000 != 0
                        if (!addImmediate && !loadUnsigned) continue
                        val immediate = (next ushr 10) and 0xfff
                        val scale = if (addImmediate) if (next and 0x00400000 != 0) 4096L else 1L else 1L shl ((next ushr 30) and 0x3)
                        val target = page + immediate * scale
                        if (target !in targets) continue
                        val sourceType = if (loadUnsigned) "got" else "computed"
                        found += JSONObject()
                            .put("from", instructionVa)
                            .put("to", target)
                            .put("type", sourceType)
                            .put("sourceType", sourceType)
                            .put("direction", "incoming")
                            .put("pairAddress", hex(section.addr + (nextOffset - start)))
                            .put("evidence", "AArch64 ADRP + ${if (loadUnsigned) "LDR" else "ADD"} resolves to ${hex(target)}")
                    }
                }
                offset += 4
            }
        }
        return found
    }

    /** Direct AArch64 BL/B (imm26) call/jump edges to exact targets (function body or PLT stub). */
    private fun aarch64BranchXrefs(bytes: ByteArray, elf: ElfFile, targets: Set<Long>): List<JSONObject> {
        if (targets.isEmpty()) return emptyList()
        val found = ArrayList<JSONObject>()
        elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 4 }.forEach { section ->
            val start = section.offset.toInt().coerceAtLeast(0)
            val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt() and -4
            var offset = start and -4
            while (offset + 4 <= end) {
                val insn = littleEndianInt(bytes, offset)
                val isBl = insn and 0xFC000000.toInt() == 0x94000000.toInt()
                val isB = insn and 0xFC000000.toInt() == 0x14000000.toInt()
                if (isBl || isB) {
                    var imm = insn and 0x03FFFFFF
                    if (imm and 0x02000000 != 0) imm = imm or -0x04000000
                    val instructionVa = section.addr + (offset - start)
                    val target = instructionVa + (imm.toLong() shl 2)
                    if (target in targets) {
                        found += JSONObject()
                            .put("from", instructionVa)
                            .put("to", target)
                            .put("type", if (isBl) "call" else "branch")
                            .put("sourceType", "direct_call")
                            .put("direction", "incoming")
                            .put("evidence", "AArch64 ${if (isBl) "BL" else "B"} ${hex(instructionVa)} -> ${hex(target)}")
                    }
                }
                offset += 4
            }
        }
        return found
    }

    /**
     * Recover call sites that load a GOT slot then BLR:
     * ADRP+LDR Xt, [Xn, #off] ... BLR Xt  where the GOT slot belongs to [gotSlots].
     */
    private fun aarch64GotBlrXrefs(bytes: ByteArray, elf: ElfFile, gotSlots: Set<Long>, symbolVa: Long, symbolName: String): List<JSONObject> {
        if (gotSlots.isEmpty()) return emptyList()
        val found = ArrayList<JSONObject>()
        elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 8 }.forEach { section ->
            val start = section.offset.toInt().coerceAtLeast(0)
            val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt()
            // Map: register -> (gotSlot, loadVa) recently materialised in a local window.
            val live = HashMap<Int, Pair<Long, Long>>()
            var offset = start and -4
            while (offset + 4 <= end) {
                val insn = littleEndianInt(bytes, offset)
                val instructionVa = section.addr + (offset - start)
                // Expire stale register tags after ~24 instructions.
                live.entries.removeAll { instructionVa - it.value.second > 0x60 }
                if (insn and 0x9f000000.toInt() == 0x90000000.toInt()) {
                    val register = insn and 0x1f
                    val imm21 = (((insn ushr 5) and 0x7ffff) shl 2) or ((insn ushr 29) and 0x3)
                    val signed = if (imm21 and 0x100000 != 0) imm21 or -0x200000 else imm21
                    val page = (instructionVa and -0x1000L) + (signed.toLong() shl 12)
                    for (lookAhead in 1..4) {
                        val nextOffset = offset + lookAhead * 4
                        if (nextOffset + 4 > end) break
                        val next = littleEndianInt(bytes, nextOffset)
                        val baseRegister = (next ushr 5) and 0x1f
                        if (baseRegister != register) continue
                        val loadUnsigned = next and 0x3b000000 == 0x39000000 && next and 0x00400000 != 0
                        if (!loadUnsigned) continue
                        val dest = next and 0x1f
                        val immediate = (next ushr 10) and 0xfff
                        val scale = 1L shl ((next ushr 30) and 0x3)
                        val target = page + immediate * scale
                        if (target in gotSlots) {
                            live[dest] = target to (section.addr + (nextOffset - start))
                        }
                    }
                }
                // BLR Xn
                if (insn and 0xFFFFFC1F.toInt() == 0xD63F0000.toInt()) {
                    val rn = (insn ushr 5) and 0x1f
                    val hit = live[rn]
                    if (hit != null) {
                        found += JSONObject()
                            .put("from", instructionVa)
                            .put("to", symbolVa)
                            .put("type", "got_call")
                            .put("sourceType", "got_call")
                            .put("direction", "incoming")
                            .put("gotSlot", hex(hit.first))
                            .put("pairAddress", hex(hit.second))
                            .put("evidence", "AArch64 LDR GOT ${hex(hit.first)} + BLR X$rn for $symbolName")
                    }
                }
                // MOV Xd, Xm keeps tag if source tagged
                if (insn and 0xFFE0FFE0.toInt() == 0xAA0003E0.toInt()) {
                    val rm = (insn ushr 16) and 0x1f
                    val rd = insn and 0x1f
                    live[rm]?.let { live[rd] = it }
                }
                offset += 4
            }
        }
        return found
    }

    private fun littleEndianInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8) or ((bytes[offset + 2].toInt() and 0xff) shl 16) or ((bytes[offset + 3].toInt() and 0xff) shl 24)

    fun rzSearchBytes(workspaceId: String, editSessionId: String, pattern: String, fromVa: Long = 0, toVa: Long = 0): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val result = NativeEngine.active().searchBytes(bytes, elf.architecture, pattern, fromVa, toVa)
        val payload = JSONObject(result).put("workspaceId", workspaceId).put("pattern", pattern).put("architecture", elf.architecture)
        val nativeHits = payload.optJSONArray("hits") ?: JSONArray()
        enrichRizinSearchHits(elf, nativeHits)
        if (nativeHits.length() > 0) return@guarded ok(payload.put("backend", "rizin"))
        if (!payload.has("error")) return@guarded ok(payload.put("backend", "rizin"))
        val fallbackHits = fallbackByteSearch(bytes, elf, pattern, fromVa, toVa)
        if (payload.has("error") && fallbackHits.length() == 0) return@guarded err("RIZIN_SEARCH_FAILED", payload.optString("error", "Rizin byte search failed"), "pattern", pattern, "payload" to payload)
        ok(JSONObject()
            .put("hits", fallbackHits)
            .put("workspaceId", workspaceId)
            .put("pattern", pattern)
            .put("architecture", elf.architecture)
            .put("backend", "file-fallback")
            .put("nativeHitCount", 0)
            .put("nativeError", payload.optString("error", "")))
    }

    fun rzScanCrypto(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val result = NativeEngine.active().scanCrypto(bytes, elf.architecture)
        ok(JSONObject(result).put("workspaceId", workspaceId).put("architecture", elf.architecture))
    }

    fun rzEsilStep(workspaceId: String, editSessionId: String, locator: String, stepCount: Int = 1): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val name = locatorTarget(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        val startVa = resolveCodeAddress(bytes, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address could not be resolved", "locator", locator)
        val result = NativeEngine.active().esilStep(bytes, elf.architecture, startVa, stepCount.coerceIn(1, 1000))
        ok(JSONObject(result).put("workspaceId", workspaceId).put("functionName", name).put("startVa", hex(startVa)).put("stepCount", stepCount))
    }

    fun rzDiff(workspaceIdA: String, editSessionIdA: String, workspaceIdB: String, editSessionIdB: String): JSONObject = guarded {
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val bytesA = dataFor(workspaceIdA, editSessionIdA)
        val bytesB = dataFor(workspaceIdB, editSessionIdB)
        if (maxOf(bytesA.size, bytesB.size) <= 1024 * 1024) {
            val ranges = byteDiffRanges(bytesA, bytesB)
            return@guarded ok(JSONObject()
                .put("workspaceIdA", workspaceIdA)
                .put("workspaceIdB", workspaceIdB)
                .put("diffBackend", "fast-byte-diff")
                .put("diffRangeCount", ranges.length())
                .put("diffRanges", ranges)
                .put("sha256A", sha256(bytesA))
                .put("sha256B", sha256(bytesB)))
        }
        val result = NativeEngine.active().diff(bytesA, bytesB)
        ok(JSONObject(result).put("workspaceIdA", workspaceIdA).put("workspaceIdB", workspaceIdB).put("diffBackend", "rizin"))
    }

    fun rzCommand(workspaceId: String, editSessionId: String = "", command: String, unsafe: Boolean = false): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        if (command.isBlank()) return@guarded err("INVALID_ARGUMENT", "command must not be blank", "command", command)
        // Align low-level axt/axtj with high-level analyze_xrefs / rizin_api xrefs enrichment.
        parseAxtCommand(command)?.let { (va, asJson) ->
            val enriched = rzXrefs(workspaceId, editSessionId, hex(va), "to")
            if (enriched.optBoolean("ok", false) || enriched.has("xrefs") || enriched.optJSONObject("data") != null) {
                val data = enriched.optJSONObject("data") ?: enriched
                val xrefs = data.optJSONArray("xrefs") ?: JSONArray()
                val text = if (asJson) {
                    xrefs.toString()
                } else {
                    buildString {
                        for (i in 0 until xrefs.length()) {
                            val x = xrefs.getJSONObject(i)
                            append(hex(x.optLong("from")))
                            append(' ')
                            append(x.optString("sourceType", x.optString("type", "ref")))
                            append(" -> ")
                            append(hex(x.optLong("to")))
                            val ev = x.optString("evidence")
                            if (ev.isNotBlank()) {
                                append("  ; ")
                                append(ev)
                            }
                            append('\n')
                        }
                        if (isEmpty()) append("[]\n")
                    }
                }
                return@guarded ok(
                    JSONObject()
                        .put("command", command)
                        .put("text", text)
                        .put("xrefs", xrefs)
                        .put("xrefCount", xrefs.length())
                        .put("atVa", hex(va))
                        .put("sourceTypeCounts", data.optJSONObject("sourceTypeCounts") ?: JSONObject())
                        .put("alignedWith", "rizin_api.xrefs / analyze_xrefs")
                        .put("workspaceId", workspaceId)
                        .put("editSessionId", editSessionId)
                        .put("architecture", elf.architecture)
                        .put("unsafe", unsafe)
                        .put("mode", "axt_enriched"),
                )
            }
        }
        val result = NativeEngine.active().command(bytes, elf.architecture, command, unsafe)
        val payload = JSONObject(result).put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("architecture", elf.architecture).put("unsafe", unsafe).put("mode", if (unsafe) "rizin_raw_full" else "rizin_raw_readonly")
        if (payload.has("error")) return@guarded err("RIZIN_COMMAND_FAILED", payload.optString("error", "Rizin command failed"), "command", command, "payload" to payload)
        if (unsafe && payload.optBoolean("mutated", false)) {
            val patched = bytes.copyOf()
            val patches = payload.optJSONArray("patches") ?: JSONArray()
            for (i in 0 until patches.length()) {
                val patch = patches.getJSONObject(i)
                val offset = patch.getInt("offset")
                val patchBytes = hexToBytes(patch.getString("hex")) ?: return@guarded err("RIZIN_COMMAND_FAILED", "Native Rizin returned invalid patch bytes")
                if (offset < 0 || offset + patchBytes.size > patched.size) return@guarded err("RIZIN_COMMAND_FAILED", "Native Rizin patch range exceeds workspace bytes")
                System.arraycopy(patchBytes, 0, patched, offset, patchBytes.size)
            }
            val sessionId = "rizin-${UUID.randomUUID()}"
            workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
            payload.put("editSessionId", sessionId).put("sha256Before", sha256(bytes)).put("sha256After", sha256(patched)).put("patchCount", patches.length())
        }
        ok(payload)
    }

    /** Parse `axtj @ 0xVA`, `axt @VA`, `s 0xVA; axtj` style commands. */
    private fun parseAxtCommand(command: String): Pair<Long, Boolean>? {
        val cmd = command.trim()
        val asJson = cmd.contains("axtj", ignoreCase = true)
        if (!cmd.contains("axt", ignoreCase = true)) return null
        // axtj @ 0x1c6f0  /  axt @1c6f0
        Regex("""(?i)axtj?\s*@\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)""").find(cmd)?.groupValues?.getOrNull(1)?.let { parseHexLong(it) }?.let {
            return it to asJson
        }
        // s 0x1c6f0; axtj  or  s 0x1c6f0\naxt
        Regex("""(?i)s\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\s*[;\n\r]+\s*axtj?""").find(cmd)?.groupValues?.getOrNull(1)?.let { parseHexLong(it) }?.let {
            return it to asJson
        }
        return null
    }

    fun rzDecompile(workspaceId: String, editSessionId: String = "", locator: String = "", strict: Boolean = true): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
        val target = locator.ifBlank { hex(elf.entry) }
        val name = locatorTarget(target, "so_function")
        val va = resolveCodeAddress(bytes, elf, target) ?: return@guarded err("INVALID_ARGUMENT", "locator must resolve to a function or hex VA", "locator", locator)
        val payload = JSONObject(NativeEngine.active().decompile(bytes, elf.architecture, va))
            .put("workspaceId", workspaceId)
            .put("addr", hex(va))
            .put("requestedBackend", "rizin-ghidra")
            .put("usesBuiltinPseudo", false)
        val decompErr = payload.optString("error")
        if ((decompErr == "DECOMPILER_UNAVAILABLE" || decompErr == "DECOMPILER_FAILED") && strict) {
            return@guarded err(decompErr, payload.optString("message"), "backend", "rizin-ghidra", "payload" to payload)
        }
        if (payload.has("error")) return@guarded ok(payload)
        ok(enrichDecompilePayload(payload, bytes, elf, va, name, target))
    }

    fun capabilityRegistry(): JSONObject = JSONObject()
        .put("coverage", "capability-registry")
        .put("truth", "Entries are generated from code paths that are callable through MCP and verified against packaged runtime modules. Commercial-only upstream modules are never advertised as native open-source implementations.")
        .put("backends", JSONObject()
            .put("rizin", JSONObject()
                .put("status", NativeEngine.active().loadStatus())
                .put("coverageClass", "native_full_gateway")
                .put("supported", JSONArray(listOf("full_rz_core_command_gateway", "authenticated_unsafe_mutating_file_shell_debugger_commands", "persistent_patch_edit_sessions", "disassemble", "assemble", "arm32_thumb_disassemble", "arm32_thumb_assemble", "analyze", "functions", "cfg", "xrefs", "search_bytes", "crypto_scan", "esil_step", "diff", "decompile_probe")))
                .put("gating", JSONObject().put("unsafeCommands", "require unsafe=true and authenticated MCP access").put("mutations", "returned as persistent edit sessions")))
            .put("lief", JSONObject()
                .put("status", lief.loadStatus())
                .put("version", "0.16.1")
                .put("coverageClass", "native_serialized_object_tree")
                .put("compiledFormats", JSONArray(listOf("ELF", "PE", "Mach-O", "DEX", "ART", "OAT", "VDEX")))
                .put("supported", JSONArray(listOf("parse_any_official_json", "native_snapshot", "native_get", "native_list", "parse_elf", "parse_pe", "parse_macho", "parse_dex", "parse_art", "parse_oat", "parse_vdex", "object_path_dispatch", "sections", "symbols", "relocations", "program_headers", "dynamic_entries", "get_set_section_content", "patch_address", "add_exported_function", "remove_symbol", "fix_sections", "build")))
                .put("notCountedAsLief", JSONArray(listOf("Rizin assembly", "Rizin debug info", "Rizin Objective-C analysis", "Rizin dyld cache analysis"))))
            .put("unidbg", JSONObject()
                .put("status", emulationStatus())
                .put("coverageClass", "native_full_gateway")
                .put("upstreamNativeToolCount", 41)
                .put("supported", JSONArray(listOf("upstream_native_schemas", "upstream_native_tool_dispatch", "load_so", "session_open", "session_list", "session_close", "session_call", "session_call_address", "session_dump", "session_memory_maps", "session_registers", "session_modules", "session_exports", "session_memory_write", "session_memory_map", "session_memory_protect", "session_memory_unmap", "session_trace_code", "session_breakpoint_add", "reflect_roots", "reflect_methods", "reflect_invoke", "object_handle_chaining", "JNI_OnLoad", "call_export", "call_Java_native", "dump_memory", "modules", "exports", "imports", "unidbg_batch_cli_pipeline")))
                .put("dynamicCoverage", "All public methods reachable from packaged live emulator/vm/module/backend/memory objects are discoverable and invokable through object handles"))
            .put("xanso", JSONObject()
                .put("status", JSONObject().put("available", xanso.available()).put("backend", "freakishfox/xAnSo upstream + xAnSo64 extension"))
                .put("coverageClass", "native_full_upstream_scope")
                .put("supported", JSONArray(listOf("help", "build-section", "ELF32_ARM_upstream_section_fix", "ELF64_LIEF_assisted_reconstruction", "persistent_edit_session", "sha256_and_diff_evidence")))
                .put("upstreamScope", "Complete public xAnSo CLI/core functionality: h/help, build-section, quit/session close semantics")))

    fun liefDispatch(workspaceId: String, editSessionId: String = "", op: String, objectPath: String = "", method: String = "", args: JSONArray = JSONArray(), dryRun: Boolean = false): JSONObject = guarded {
        val elf by lazy { elfFor(workspaceId, editSessionId) }
        when (op) {
            "roots" -> return@guarded ok(JSONObject().put("roots", JSONArray(listOf("binary", "sections", "symbols", "dynSymbols", "relocations", "programHeaders", "dynamicEntries", "strings", "nativeJson"))).put("formats", JSONArray(listOf("ELF", "PE", "Mach-O", "DEX", "ART", "OAT", "VDEX"))))
            "methods" -> return@guarded ok(JSONObject().put("methods", JSONArray(listOf("parseAny", "nativeSnapshot", "nativeGet", "nativeList", "toJson", "snapshot", "getSectionContent", "setSectionContent", "patchAddress", "addExportedFunction", "removeSymbol", "fixSections", "build"))).put("settableObjectPaths", JSONArray(listOf("sections[i].content", "symbols[i].name", "dynSymbols[i].name"))).put("argumentTemplates", JSONObject().put("parseAny", JSONArray(listOf("format:auto|elf|pe|macho|dex|art|oat|vdex"))).put("nativeGet", JSONArray(listOf("format", "objectPath"))).put("setSectionContent", JSONArray(listOf("sectionName", "hexContent"))).put("patchAddress", JSONArray(listOf("vaHex", "patchHex"))).put("addExportedFunction", JSONArray(listOf("vaHex", "name"))).put("removeSymbol", JSONArray(listOf("name"))).put("build", JSONArray(listOf("outputName", "conflictStrategy")))))
            "parse_any" -> return@guarded ok(JSONObject().put("format", args.optString(0, "auto")).put("binary", lief.parseAny(dataFor(workspaceId, editSessionId), args.optString(0, "auto"))))
            "native_snapshot" -> {
                val format = args.optString(0, "auto")
                return@guarded ok(JSONObject().put("format", format).put("source", "LIEF::to_json").put("binary", lief.parseAny(dataFor(workspaceId, editSessionId), format)))
            }
            "native_get", "native_list" -> {
                val format = args.optString(0, "auto")
                val nativeRoot = lief.parseAny(dataFor(workspaceId, editSessionId), format)
                val value = resolveJsonObjectPath(nativeRoot, objectPath)
                return@guarded ok(JSONObject().put("format", format).put("source", "LIEF::to_json").put("objectPath", objectPath).put(if (op == "native_list") "items" else "value", value))
            }
            "validate" -> return@guarded validateLiefDispatch(elf, objectPath, method, args)
            "get" -> return@guarded ok(JSONObject().put("objectPath", objectPath).put("value", resolveLiefObjectPath(elf, objectPath)))
            "list" -> return@guarded ok(JSONObject().put("objectPath", objectPath).put("items", resolveLiefObjectPath(elf, objectPath)))
            "call" -> return@guarded when (method) {
                "toJson", "snapshot" -> ok(JSONObject().put("binary", elfSummaryJson(workspaceId, editSessionId, elf)))
                "getSectionContent" -> {
                    val name = args.optString(0, objectPath.substringAfterLast('.'))
                    val content = lief.getSectionContent(dataFor(workspaceId, editSessionId), name)
                    ok(JSONObject().put("section", name).put("size", content.size).put("hexPreview", hexBytes(content.copyOfRange(0, minOf(content.size, 256)))))
                }
                "setSectionContent" -> {
                    val sectionName = args.optString(0)
                    val content = hexToBytes(args.optString(1)) ?: return@guarded err("INVALID_HEX", "args[1] must be hex section content", "args", args)
                    if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("section", sectionName).put("size", content.size))
                    val patched = lief.setSectionContent(dataFor(workspaceId, editSessionId), sectionName, content)
                    val sessionId = "lief-${UUID.randomUUID()}"
                    workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                    ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("method", method).put("section", sectionName).put("size", content.size), workspaceId, sessionId))
                }
                "patchAddress" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("va", args.optString(0)).put("patchHex", args.optString(1))) else liefPatchAddress(workspaceId, editSessionId, parseHexLong(args.optString(0)) ?: return@guarded err("INVALID_ARGUMENT", "args[0] must be hex VA", "args", args), hexToBytes(args.optString(1)) ?: return@guarded err("INVALID_HEX", "args[1] must be hex patch", "args", args))
                "addExportedFunction" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("va", args.optString(0)).put("name", args.optString(1))) else liefAddExportedFunction(workspaceId, editSessionId, parseHexLong(args.optString(0)) ?: return@guarded err("INVALID_ARGUMENT", "args[0] must be hex VA", "args", args), args.optString(1))
                "removeSymbol" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("name", args.optString(0))) else liefRemoveSymbol(workspaceId, editSessionId, args.optString(0))
                "fixSections" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method)) else fixSections(workspaceId, editSessionId)
                "build" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldBuild", true).put("outputName", args.optString(0, "patched.so")).put("conflictStrategy", args.optString(1, "rename"))) else build(workspaceId, editSessionId, args.optString(0, "patched.so"), args.optString(1, "rename"), null, null)
                else -> err("CAPABILITY_NOT_IMPLEMENTED", "LIEF method is not implemented by the current dispatcher", "method", method)
            }
            "set" -> return@guarded when {
                objectPath.startsWith("sections[") && objectPath.endsWith("].content") -> {
                    val idx = Regex("sections\\[(\\d+)]").find(objectPath)?.groupValues?.getOrNull(1)?.toIntOrNull()
                    val sec = idx?.let { elf.sections.getOrNull(it) } ?: return@guarded err("INVALID_ARGUMENT", "section index not found", "objectPath", objectPath)
                    val content = hexToBytes(args.optString(0)) ?: return@guarded err("INVALID_HEX", "args[0] must be hex section content", "args", args)
                    if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("objectPath", objectPath).put("section", sec.name).put("size", content.size))
                    val patched = lief.setSectionContent(dataFor(workspaceId, editSessionId), sec.name, content)
                    val sessionId = "lief-${UUID.randomUUID()}"
                    workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                    ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("objectPath", objectPath).put("section", sec.name).put("size", content.size), workspaceId, sessionId))
                }
                objectPath.matches(Regex("(symbols|dynSymbols)\\[\\d+].name")) -> {
                    val group = objectPath.substringBefore('[')
                    val idx = Regex("\\[(\\d+)]").find(objectPath)?.groupValues?.getOrNull(1)?.toIntOrNull()
                    val sym = idx?.let { if (group == "symbols") elf.symbols.getOrNull(it) else elf.dynSymbols.getOrNull(it) }
                        ?: return@guarded err("INVALID_ARGUMENT", "symbol index not found", "objectPath", objectPath)
                    val newName = args.optString(0)
                    if (newName.isBlank()) return@guarded err("INVALID_ARGUMENT", "args[0] must be the new symbol name", "args", args)
                    if (newName.length > sym.name.length) return@guarded err("SYMTAB_OVERFLOW", "Renaming to a longer symbol name is not supported by byte-level string-table replacement", "args", args)
                    val original = dataFor(workspaceId, editSessionId)
                    val oldBytes = sym.name.toByteArray()
                    val newBytes = newName.toByteArray()
                    val matches = allIndexesOf(original, oldBytes)
                    if (matches.isEmpty()) return@guarded err("SYMBOL_NOT_FOUND", "Symbol string bytes were not found", "objectPath", objectPath)
                    if (matches.size != 1) return@guarded err("AMBIGUOUS_SYMBOL_STRING", "Symbol string bytes matched multiple file offsets; use removeSymbol/addExportedFunction or a section-specific edit instead", "objectPath", objectPath)
                    val pos = matches.first()
                    if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("objectPath", objectPath).put("oldName", sym.name).put("newName", newName).put("fileOffset", hex(pos.toLong())))
                    val patched = original.copyOf()
                    val replacement = ByteArray(oldBytes.size) { if (it < newBytes.size) newBytes[it] else 0 }
                    System.arraycopy(replacement, 0, patched, pos, replacement.size)
                    val sessionId = "lief-${UUID.randomUUID()}"
                    workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                    ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("objectPath", objectPath).put("oldName", sym.name).put("newName", newName).put("fileOffset", hex(pos.toLong())), workspaceId, sessionId))
                }
                else -> err("CAPABILITY_NOT_IMPLEMENTED", "Generic LIEF property mutation is not implemented for this objectPath", "objectPath", objectPath)
            }
            else -> return@guarded err("UNKNOWN_ACTION", "Unknown LIEF dispatcher op", "op", op)
        }
    }

    private fun resolveLiefObjectPath(elf: ElfFile, objectPath: String): Any {
        val root = JSONObject()
            .put("binary", elfSummaryJson("", "", elf))
            .put("sections", JSONArray(elf.sections.map { sectionJson("", it) }))
            .put("symbols", JSONArray(elf.symbols.map { symbolJson("", it) }))
            .put("dynSymbols", JSONArray(elf.dynSymbols.map { symbolJson("", it) }))
            .put("relocations", JSONArray(elf.relocations.map { relocJson(it) }))
            .put("programHeaders", JSONArray(elf.programHeaders.map { phJson(it) }))
            .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { dynJson(it) }))
            .put("strings", JSONArray(elf.strings.map { stringJson("", it) }))
        if (objectPath.isBlank()) return root
        var cur: Any = root
        for (part in objectPath.split('.').filter { it.isNotBlank() }) {
            val name = part.substringBefore('[')
            if (name.isNotBlank()) cur = (cur as? JSONObject)?.opt(name) ?: JSONObject.NULL
            val idx = Regex("\\[(\\d+)]").find(part)?.groupValues?.getOrNull(1)?.toIntOrNull()
            if (idx != null) cur = (cur as? JSONArray)?.opt(idx) ?: JSONObject.NULL
        }
        return cur
    }

    private fun resolveJsonObjectPath(root: Any, objectPath: String): Any {
        if (objectPath.isBlank()) return root
        var current: Any? = root
        for (part in objectPath.split('.').filter { it.isNotBlank() }) {
            val name = part.substringBefore('[')
            if (name.isNotBlank()) current = (current as? JSONObject)?.opt(name) ?: JSONObject.NULL
            val indexes = Regex("\\[(\\d+)]").findAll(part).mapNotNull { it.groupValues[1].toIntOrNull() }
            for (index in indexes) current = (current as? JSONArray)?.opt(index) ?: JSONObject.NULL
        }
        return current ?: JSONObject.NULL
    }

    private fun validateLiefDispatch(elf: ElfFile, objectPath: String, method: String, args: JSONArray): JSONObject {
        val issues = JSONArray()
        if (objectPath.isNotBlank()) {
            val value = resolveLiefObjectPath(elf, objectPath)
            if (value == JSONObject.NULL) issues.put("objectPath does not resolve: $objectPath")
        }
        when (method) {
            "setSectionContent" -> {
                if (args.optString(0).isBlank()) issues.put("args[0] section name is required")
                if (hexToBytes(args.optString(1)) == null) issues.put("args[1] must be valid hex content")
            }
            "patchAddress" -> {
                val va = parseHexLong(args.optString(0))
                if (va == null) issues.put("args[0] must be a hex VA") else if (vaToOffset(elf, va) == null) issues.put("args[0] VA does not map to a file offset")
                if (hexToBytes(args.optString(1)) == null) issues.put("args[1] must be valid hex patch bytes")
            }
            "addExportedFunction" -> {
                if (parseHexLong(args.optString(0)) == null) issues.put("args[0] must be a hex VA")
                if (args.optString(1).isBlank()) issues.put("args[1] export name is required")
            }
            "removeSymbol" -> if (args.optString(0).isBlank()) issues.put("args[0] symbol name is required")
        }
        return ok(JSONObject().put("valid", issues.length() == 0).put("issues", issues).put("method", method).put("objectPath", objectPath))
    }

    private fun withMutationHints(payload: JSONObject, workspaceId: String, editSessionId: String): JSONObject = payload
        .put("mutation", true)
        .put("workspaceId", workspaceId)
        .put("nextActions", JSONArray(listOf(
            "session_history(action=check, workspaceId=$workspaceId, editSessionId=$editSessionId)",
            "session_audit(action=audit, workspaceId=$workspaceId, editSessionId=$editSessionId)",
            "build_so(action=build, workspaceId=$workspaceId, editSessionId=$editSessionId)"
        )))
        .put("rollbackHint", "Use session_history(action=rollback, workspaceId=$workspaceId, editSessionId=$editSessionId) if validation fails")

    fun unidbgDispatch(workspaceId: String, editSessionId: String = "", op: String, method: String = "", args: JSONArray = JSONArray()): JSONObject = guarded {
        return@guarded when (op) {
            "status", "roots" -> ok(emulationStatus().put("roots", JSONArray(listOf("emulator", "memory", "vm", "module", "symbols", "jni", "framework", "hooks", "environment", "debugger"))))
            "methods" -> ok(JSONObject().put("methods", JSONArray(listOf("session_open", "session_list", "session_close", "session_call", "session_call_address", "session_dump", "session_memory_maps", "session_registers", "session_modules", "session_exports", "session_trace_code", "session_breakpoint_add", "session_memory_write", "session_memory_map", "session_memory_protect", "session_memory_unmap", "native_schemas", "native_tool", "call", "dump", "modules", "exports", "imports", "reflect", "framework_matrix", "stub_template", "hook_template", "env_template"))).put("roots", JSONArray(listOf("emulator", "memory", "vm", "module", "symbols", "jni", "framework", "hooks", "environment", "debugger"))))
            "modules" -> ok(JSONObject().put("modules", JSONArray(listOf(JSONObject().put("name", workspaces[workspaceId]?.source?.name ?: "target.so").put("architecture", elfFor(workspaceId, editSessionId).architecture).put("source", "static-workspace")))).put("runtime", "Call session_open + session_call to load through Unidbg; persistent runtime module listing requires live emulator sessions."))
            "exports" -> list(workspaceId, editSessionId, "dynsyms", "", 500).put("unidbgView", "exports")
            "imports" -> list(workspaceId, editSessionId, "imports", "", 500).put("unidbgView", "imports")
            "debugger_plan", "memory_map_plan", "registers_plan", "breakpoints_plan", "trace_plan" -> ok(unidbgDebuggerPlan(op))
            "framework_matrix" -> ok(unidbgFrameworkMatrix())
            "stub_template" -> ok(unidbgStubTemplate(args.optString(0), args.optString(1)))
            "hook_template" -> ok(unidbgHookTemplate(args.optString(0), args.optString(1)))
            "env_template" -> ok(unidbgEnvironmentTemplate())
            "session_open" -> {
                val elf = elfFor(workspaceId, editSessionId)
                val id = "emu-${UUID.randomUUID()}"
                val open = unidbg.openSession(dataFor(workspaceId, editSessionId), elf.architecture, args.optBoolean(1, true))
                if (!open.optBoolean("ok", false)) return@guarded wrapUnidbgResult(open.put("workspaceId", workspaceId).put("architecture", elf.architecture))
                val live = open.remove("live") as? UnidbgEmulator.LiveSession
                    ?: return@guarded err("SESSION_OPEN_ERROR", "Unidbg live session handle was not created")
                emulatorSessions[id] = EmulatorSession(id, workspaceId, editSessionId, elf.architecture, dataFor(workspaceId, editSessionId), live)
                ok(open.put("emulatorSessionId", id).put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("architecture", elf.architecture).put("persistent", true))
            }
            "session_list" -> ok(JSONObject().put("sessions", JSONArray(emulatorSessions.values.map { JSONObject().put("id", it.id).put("workspaceId", it.workspaceId).put("editSessionId", it.editSessionId).put("architecture", it.architecture).put("createdAt", it.createdAt) })))
            "session_close" -> {
                val session = emulatorSessions.remove(args.optString(0))
                if (session?.live != null) unidbg.closeSession(session.live)
                ok(JSONObject().put("closed", session != null).put("emulatorSessionId", args.optString(0)))
            }
            "session_call" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val symbol = method.ifBlank { args.optString(1) }
                val callArgs = args.optJSONArray(2) ?: JSONArray()
                val trace = args.optBoolean(3, false)
                val result = session.live?.let { unidbg.sessionCall(it, symbol, callArgs, trace) }
                    ?: unidbg.emulate(session.data, session.architecture, symbol, callArgs, trace)
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("symbolName", symbol).put("architecture", session.architecture))
            }
            "session_call_address" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val callArgs = args.optJSONArray(2) ?: JSONArray()
                val result = session.live?.let { unidbg.sessionCallAddress(it, addr, callArgs) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "address calls require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_dump" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val size = args.optInt(2, 256)
                val result = session.live?.let { unidbg.sessionDump(it, addr, size.coerceIn(1, 65536)) }
                    ?: unidbg.dumpMemory(session.data, session.architecture, addr, size.coerceIn(1, 65536))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_memory_maps" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionMemoryMaps(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory maps require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_registers" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionRegisters(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "registers require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_modules" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionModules(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "modules require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_exports" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionExports(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "exports require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_trace_code" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val begin = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex begin address", "args", args)
                val end = parseHexLong(args.optString(2)) ?: return@guarded err("INVALID_ARGUMENT", "args[2] must be a hex end address", "args", args)
                val result = session.live?.let { unidbg.sessionTraceCode(it, begin, end) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "trace requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_trace_start" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val begin = parseHexLong(args.optString(2)) ?: 1L
                val end = parseHexLong(args.optString(3)) ?: 0L
                wrapUnidbgResult((session.live?.let { unidbg.sessionTraceStart(it, args.optString(1, "code"), begin, end) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_trace_events" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionTraceEvents(it, args.optInt(1, 0), args.optInt(2, 100)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_trace_stop" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionTraceStop(it, args.optString(1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_trace_clear" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionTraceClear(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_hook_start" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionHookStart(it, args.optString(1, "syscall"), parseHexLong(args.optString(2)) ?: 1L, parseHexLong(args.optString(3)) ?: 0L) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_hook_list" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionHookList(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_hook_stop" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionHookStop(it, args.optString(1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_breakpoint_add" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val result = session.live?.let { unidbg.sessionBreakpointAdd(it, addr) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "breakpoints require a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_debugger_status" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionDebuggerStatus(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_breakpoint_remove" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                wrapUnidbgResult((session.live?.let { unidbg.sessionBreakpointRemove(it, addr) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_single_step" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionSingleStep(it, args.optInt(1, 1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_emu_stop" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                wrapUnidbgResult((session.live?.let { unidbg.sessionEmuStop(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
            }
            "session_memory_write" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val result = session.live?.let { unidbg.sessionMemoryWrite(it, addr, args.optString(2)) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory write requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_memory_map" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
                val result = session.live?.let { unidbg.sessionMemoryMap(it, addr, size, args.optInt(3, 3)) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory map requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_memory_protect" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
                val result = session.live?.let { unidbg.sessionMemoryProtect(it, addr, size, args.optInt(3, 3)) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory protect requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "session_memory_unmap" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
                val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
                val result = session.live?.let { unidbg.sessionMemoryUnmap(it, addr, size) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory unmap requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "reflect_roots" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionReflectRoots(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "reflect_methods" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionReflectMethods(it, args.optString(1)) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "reflect_invoke" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionReflectInvoke(it, args.optString(1), method, args.optJSONArray(2) ?: JSONArray()) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
            }
            "native_schemas" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val result = session.live?.let { unidbg.sessionNativeToolSchemas(it) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId))
            }
            "native_tool" -> {
                val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
                val toolName = method.ifBlank { args.optString(1) }
                if (toolName.isBlank()) return@guarded err("INVALID_ARGUMENT", "native_tool requires a tool name", "method", method)
                val toolArgs = args.optJSONObject(2) ?: JSONObject()
                val result = session.live?.let { unidbg.sessionNativeToolCall(it, toolName, toolArgs) }
                    ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))
                wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId))
            }
            "call" -> emulate(workspaceId, editSessionId, method.ifBlank { args.optString(0) }, args.optJSONArray(1) ?: JSONArray(), args.optBoolean(2, false))
            "dump" -> dumpMemory(workspaceId, editSessionId, parseHexLong(args.optString(0)) ?: 0L, args.optInt(1, 256))
            "reflect" -> err("INVALID_ARGUMENT", "Use reflect_roots, reflect_methods, or reflect_invoke with a live emulatorSessionId", "op", op)
            else -> err("UNKNOWN_ACTION", "Unknown Unidbg dispatcher op", "op", op)
        }
    }

    private fun unidbgFrameworkMatrix(): JSONObject = JSONObject()
        .put("matrix", JSONArray(listOf(
            JSONObject().put("area", "DalvikVM/JNI").put("status", "implemented").put("items", JSONArray(listOf("createDalvikVM", "JNIEnv", "JNI_OnLoad", "Java_* JNI exported call"))),
            JSONObject().put("area", "Native exports").put("status", "implemented").put("items", JSONArray(listOf("exported symbol call", "argument passing", "return value", "memory dump"))),
            JSONObject().put("area", "Android framework classes").put("status", "targeted-stub-required").put("items", JSONArray(listOf("Context", "Application", "ActivityThread", "PackageManager", "Resources", "ClassLoader"))),
            JSONObject().put("area", "Device/environment APIs").put("status", "targeted-hook-required").put("items", JSONArray(listOf("Build", "Settings.Secure", "TelephonyManager", "system properties", "filesystem", "network"))),
            JSONObject().put("area", "Anti-analysis behavior").put("status", "targeted-hook-required").put("items", JSONArray(listOf("ptrace", "procfs", "thread checks", "timing checks", "emulator checks")))
        )))
        .put("workflow", JSONArray(listOf("Run emulate_call with trace=false", "If it fails, retry trace=true on a small symbol", "Extract missing class/method/syscall from error.stage or trace", "Generate stub_template or hook_template", "Implement targeted hook in UnidbgEmulator", "Retry emulate_call")))

    private fun unidbgDebuggerPlan(op: String): JSONObject = JSONObject()
        .put("op", op)
        .put("available", false)
        .put("reason", "Persistent live emulator sessions are enabled for session_call/session_dump. This specific debugger operation still needs a typed MCP wrapper and guardrails before being exposed.")
        .put("implementationPlan", JSONArray(listOf(
            "Promote EmulatorSession from bytes-only state to live emulator/vm/module/backend holder",
            "Add serialized single-thread access per emulator session",
            "Expose modules/exports/memory maps/registers as typed read-only operations first",
            "Add explicit breakpoint/trace operations with size/time guards",
            "Keep arbitrary Java reflection blocked unless a sandboxed object-path dispatcher is implemented"
        )))
        .put("safeAlternativesNow", JSONArray(listOf("session_call", "session_dump", "modules", "exports", "imports", "framework_matrix", "hook_template", "stub_template", "env_template")))

    private fun unidbgStubTemplate(className: String, methodName: String): JSONObject = JSONObject()
        .put("type", "java-class-stub")
        .put("className", className.ifBlank { "android/content/Context" })
        .put("methodName", methodName.ifBlank { "getPackageName" })
        .put("purpose", "Use this template when Unidbg fails on missing Android framework class/method resolution.")
        .put("kotlinSketch", JSONArray(listOf(
            "Detect className/methodName in Unidbg failure trace",
            "Register or intercept the Java class in DalvikVM",
            "Return deterministic app-specific values from Settings/env template",
            "Keep the stub narrow and library-specific to avoid unsafe global behavior"
        )))
        .put("exampleReturnValues", JSONObject()
            .put("getPackageName", "com.example.target")
            .put("getFilesDir", "/data/data/com.example.target/files")
            .put("getCacheDir", "/data/data/com.example.target/cache"))

    private fun unidbgHookTemplate(hookName: String, symbolOrApi: String): JSONObject = JSONObject()
        .put("type", "native-or-framework-hook")
        .put("hookName", hookName.ifBlank { "anti_emulator_bypass" })
        .put("target", symbolOrApi.ifBlank { "__system_property_get / open / access / ptrace" })
        .put("purpose", "Use this template when a SO performs environment, filesystem, syscall, or anti-analysis checks.")
        .put("strategy", JSONArray(listOf("Identify failing API from trace", "Return realistic device/app data", "Avoid broad hooks that hide real bugs", "Record hook hits in diagnostics")))
        .put("exampleValues", JSONObject()
            .put("ro.product.model", "Pixel 7")
            .put("ro.build.version.sdk", "33")
            .put("/proc/self/status", "TracerPid:\t0"))

    private fun unidbgEnvironmentTemplate(): JSONObject = JSONObject()
        .put("packageName", "com.example.target")
        .put("apiLevel", 33)
        .put("abi", JSONArray(listOf("arm64-v8a", "armeabi-v7a")))
        .put("files", JSONObject()
            .put("dataDir", "/data/data/com.example.target")
            .put("filesDir", "/data/data/com.example.target/files")
            .put("cacheDir", "/data/data/com.example.target/cache"))
        .put("systemProperties", JSONObject()
            .put("ro.product.manufacturer", "Google")
            .put("ro.product.model", "Pixel 7")
            .put("ro.build.version.sdk", "33"))
        .put("note", "Copy and specialize this environment per target app before adding hooks/stubs.")

    fun xansoDispatch(workspaceId: String, editSessionId: String = "", op: String): JSONObject = guarded {
        return@guarded when (op) {
            "status", "roots", "capabilities" -> ok(JSONObject()
                .put("available", xanso.available())
                .put("backend", "freakishfox/xAnSo upstream Core/fix")
                .put("upstreamCommit", "2f2b6bcff52aba995ad4280d41a588f7cd40a781")
                .put("roots", JSONArray(listOf("help", "build-section")))
                .put("formats", JSONArray(listOf("ELF32 little-endian ET_DYN ARM via upstream section_fix", "ELF64 via xAnSo64 LIEF-assisted reconstruction")))
                .put("scope", "Complete upstream CLI/core public functionality plus ELF64 reconstruction extension"))
            "methods", "help" -> ok(JSONObject()
                .put("methods", JSONArray(listOf("status", "capabilities", "help", "build-section")))
                .put("backend", "freakishfox/xAnSo upstream Core/fix")
                .put("commands", JSONArray(listOf("h", "build-section", "quit"))))
            "fix_sections", "build-section" -> xansoBuildSections(workspaceId, editSessionId, false)
            else -> err("UNKNOWN_ACTION", "Unknown xAnSo dispatcher op", "op", op)
        }
    }

    fun xansoBuildSections(workspaceId: String, editSessionId: String = "", force: Boolean = false): JSONObject = guarded {
        val original = dataFor(workspaceId, editSessionId)
        if (original.size < 5) return@guarded err("ELF_CORRUPTED", "Input is too small to contain an ELF identification header")
        val elfClass = original[4].toInt() and 0xff
        val beforeElf = lief.parse(original)
        val backend = when (elfClass) {
            1 -> "xAnSo32 upstream section_fix"
            2 -> "xAnSo64 LIEF-assisted reconstruction"
            else -> return@guarded err("XANSO_UNSUPPORTED_ELF_CLASS", "Unsupported ELF class", "elfClass", elfClass)
        }
        if (elfClass == 1 && !xanso.available()) return@guarded err("XANSO_UNAVAILABLE", "Real xAnSo native backend is not loaded for this ABI")
        if (elfClass == 2 && !lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF is required by the xAnSo64 reconstruction extension")
        val alreadyStructured = beforeElf.sections.isNotEmpty() && beforeElf.programHeaders.isNotEmpty() && beforeElf.dynamicEntries.isNotEmpty()
        if (alreadyStructured && !force) return@guarded ok(JSONObject()
            .put("backend", backend)
            .put("operation", "build-section")
            .put("elfClass", if (elfClass == 1) "ELF32" else "ELF64")
            .put("changed", false)
            .put("message", "Section table is already present and parseable; set force=true to rebuild it")
            .put("sections", beforeElf.sections.size)
            .put("programHeaders", beforeElf.programHeaders.size)
            .put("dynamicEntries", beforeElf.dynamicEntries.size)
            .put("sha256Before", sha256(original))
            .put("sha256After", sha256(original)))
        val recovered = if (elfClass == 2 && beforeElf.sections.isEmpty()) xanso.recoverElf64Sections(original) else null
        val fixed = when (elfClass) {
            1 -> xanso.buildSections(original)
            else -> runCatching { lief.fixSections(recovered ?: original) }.getOrNull()
        } ?: return@guarded err("XANSO_BUILD_FAILED", "$backend failed to reconstruct section headers")
        val afterElf = lief.parse(fixed)
        if (afterElf.sections.isEmpty()) return@guarded err("XANSO_BUILD_FAILED", "$backend produced an ELF without a usable section table")
        val sessionId = "xanso-${UUID.randomUUID()}"
        workspace(workspaceId).edits[sessionId] = EditSession(sessionId, fixed)
        ok(JSONObject()
            .put("backend", backend)
            .put("operation", "build-section")
            .put("elfClass", if (elfClass == 1) "ELF32" else "ELF64")
            .put("changed", !fixed.contentEquals(original))
            .put("recoveryMode", when { elfClass == 1 -> "upstream-section-fix"; recovered != null && recovered.size == original.size -> "orphan-section-table-scan+LIEF"; recovered != null -> "program-header-section-synthesis+LIEF"; else -> "dynamic-metadata+LIEF" })
            .put("editSessionId", sessionId)
            .put("sizeBefore", original.size)
            .put("sizeAfter", fixed.size)
            .put("sectionsBefore", beforeElf.sections.size)
            .put("sectionsAfter", afterElf.sections.size)
            .put("programHeadersBefore", beforeElf.programHeaders.size)
            .put("programHeadersAfter", afterElf.programHeaders.size)
            .put("dynamicEntriesBefore", beforeElf.dynamicEntries.size)
            .put("dynamicEntriesAfter", afterElf.dynamicEntries.size)
            .put("sha256Before", sha256(original))
            .put("sha256After", sha256(fixed))
            .put("diffRanges", byteDiffRanges(original, fixed)))
    }

    // ── LIEF-backed ELF modifications (patch_address / add_export / remove_symbol) ──

    fun liefPatchAddress(workspaceId: String, editSessionId: String, va: Long, patch: ByteArray): JSONObject = guarded {
        if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
        val original = dataFor(workspaceId, editSessionId)
        val patched = lief.patchAddress(original, va, patch)
        if (patched.contentEquals(original)) return@guarded err("PATCH_FAILED", "LIEF patch_address returned unchanged bytes (VA may not map to a loadable segment)")
        val newSessionId = "patch-${UUID.randomUUID()}"
        workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
        ok(JSONObject()
            .put("editSessionId", newSessionId)
            .put("va", hex(va))
            .put("patchSize", patch.size)
            .put("sizeBefore", original.size)
            .put("sizeAfter", patched.size))
    }

    fun liefAddExportedFunction(workspaceId: String, editSessionId: String, addr: Long, name: String): JSONObject = guarded {
        if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
        val original = dataFor(workspaceId, editSessionId)
        val patched = lief.addExportedFunction(original, addr, name)
        val newSessionId = "sym-${UUID.randomUUID()}"
        workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
        ok(JSONObject()
            .put("editSessionId", newSessionId)
            .put("addr", hex(addr))
            .put("name", name)
            .put("sizeBefore", original.size)
            .put("sizeAfter", patched.size))
    }

    fun liefRemoveSymbol(workspaceId: String, editSessionId: String, name: String): JSONObject = guarded {
        if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
        val original = dataFor(workspaceId, editSessionId)
        val patched = lief.removeSymbol(original, name)
        val newSessionId = "rm-${UUID.randomUUID()}"
        workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
        ok(JSONObject()
            .put("editSessionId", newSessionId)
            .put("removedSymbol", name)
            .put("sizeBefore", original.size)
            .put("sizeAfter", patched.size))
    }

    // ── Unidbg-backed emulation (DalvikVM + memory dump) ──

    fun emulationStatus(): JSONObject {
        val available = unidbg.available()
        return JSONObject()
        .put("available", available)
        .put("backend", "unidbg+unicorn2")
        .put("scope", "Full Unidbg Android native emulation path backed by Unicorn2 native backend: SO load, DalvikVM/JNIEnv, JNI_OnLoad, exported symbol calls, Java_* JNI calls, and post-load memory dump")
        .put("androidFramework", JSONObject()
            .put("status", "unidbg-runtime")
            .put("implemented", JSONArray(listOf("AndroidEmulatorBuilder", "Unicorn2Factory", "AndroidResolver", "DalvikVM creation", "JNIEnv for Java_* calls", "JNI_OnLoad pre-call", "exported symbol call", "post-load memory dump")))
            .put("requiresHooks", JSONArray(listOf("Context", "Application", "PackageManager", "Resources", "Build fields", "Settings/Secure", "TelephonyManager", "ActivityThread", "ClassLoader", "filesystem paths", "network/system properties", "anti-debug/anti-emulator checks")))
            .put("truth", "This uses the real Unidbg and Unicorn2 execution path. App-specific Android framework behavior is resolved by targeted hooks/stubs when a concrete SO demands it."))
        .put("coverageModel", JSONObject()
            .put("mcpTools", "emulate_call/emulate_dump plus unidbg_api dispatch")
            .put("backendFactory", "com.github.unidbg.arm.backend.Unicorn2Factory")
            .put("nativeLibraries", JSONArray(listOf("libcapstone.so", "libkeystone.so", "libunicorn.so", "libjnidispatch.so")))
            .put("nativeSelfTest", UnidbgEmulator.nativeSelfTest())
            .put("nativeLoadError", UnidbgEmulator.nativeDependencyError()?.toString() ?: JSONObject.NULL)
            .put("availabilityError", UnidbgEmulator.availabilityError()?.toString() ?: JSONObject.NULL))
        .put("limitations", JSONArray()
            .put("Android framework classes, syscalls, filesystem, and anti-analysis behavior are handled by concrete Unidbg hooks/stubs when a target SO requires them")
            .put("Use trace=true for diagnostics, inspect error.stage/error.nextActions, then add the exact missing hook/stub before retrying"))
        .put("nextActions", JSONArray(listOf("Start with symbolName=JNI_OnLoad or an exported Java_* symbol", "If Java/framework lookup fails, identify the exact missing class/method/syscall from error.stage or trace", "Implement the specific Unidbg hook/stub and retry the same symbol")))
    }

    fun emulate(workspaceId: String, editSessionId: String, symbolName: String, args: JSONArray, trace: Boolean): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        val result = unidbg.emulate(bytes, elf.architecture, symbolName, args, trace)
        result.put("persistent", false)
            .put("addressSpace", unidbgAddressSpaceHint())
        if (result.optString("returnValue") == "-1") result.put("semanticWarning", "Unidbg completed without backend exception, but returnValue=-1 may be target-specific or indicate an unmodeled signal/syscall/framework path. Validate with trace, mapped arguments, and target-specific hooks.")
        wrapUnidbgResult(result.put("workspaceId", workspaceId).put("symbolName", symbolName).put("architecture", elf.architecture))
    }

    fun dumpMemory(workspaceId: String, editSessionId: String, addr: Long, size: Int): JSONObject = guarded {
        val bytes = dataFor(workspaceId, editSessionId)
        val elf = elfFor(workspaceId, editSessionId)
        val result = unidbg.dumpMemory(bytes, elf.architecture, addr, size.coerceIn(1, 65536))
        result.put("persistent", false)
            .put("addressSpace", unidbgAddressSpaceHint())
        wrapUnidbgResult(result.put("workspaceId", workspaceId).put("architecture", elf.architecture))
    }

    private fun unidbgAddressSpaceHint(): JSONObject = JSONObject()
        .put("kind", "runtimeVirtualAddress")
        .put("note", "Unidbg memory APIs use runtime absolute virtual addresses. For ELF RVA/VA, add the module base returned by unidbg_session(action=modules) or session_modules.")

    private fun wrapUnidbgResult(result: JSONObject): JSONObject {
        if (result.optBoolean("ok", false)) return ok(result)
        if (result.has("content") && !result.optBoolean("isError", false) && !result.has("error")) {
            result.put("ok", true)
            return ok(result)
        }
        val error = result.optJSONObject("error") ?: JSONObject().put("code", "EMULATION_ERROR").put("message", "Unidbg returned an unsuccessful result")
        val code = error.optString("code", "EMULATION_ERROR")
        val message = error.optString("message", "Unidbg returned an unsuccessful result")
        val wrapped = err(code, message, "unidbg", result.optString("stage", "unknown"), "unidbg" to result)
        val next = error.optJSONArray("nextActions")
        if (next != null) wrapped.put("nextActions", next)
        return wrapped
    }

    private fun writePatchReport(workspaceId: String, session: EditSession, output: File): File {
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
            .put("patches", session.patches.map(::patchJson).toJsonArray())
            .put("diffRanges", diffRanges)
            .put("snapshots", session.snapshots.mapIndexed { idx, s ->
                JSONObject().put("index", idx).put("revision", s.revision).put("sha256", s.sha256).put("patchCount", s.patchCount).put("timeMillis", s.timeMillis)
            }.toJsonArray())
            .put("checksums", checksums(session.data))
        report.writeText(payload.toString(2))
        return report
    }

    private fun patchJson(patch: PatchRecord): JSONObject =
        JSONObject()
            .put("timeMillis", patch.timeMillis)
            .put("kind", patch.kind)
            .put("locator", patch.locator)
            .put("fileOffset", hex(patch.fileOffset.toLong()))
            .put("oldHex", patch.oldHex)
            .put("newHex", patch.newHex)
            .put("asm", patch.asm.ifBlank { JSONObject.NULL })

    private fun ensureSources(dir: WorkDirectory): List<SoSource> {
        val settings = SettingsStore(context)
        val options = scanOptions(settings)
        if (!settings.indexCacheEnabled) {
            sources = dir.listSos(options)
            sourceFingerprint = sources.map { FileFingerprint(it.path, it.size, it.modified) }
            return sources
        }
        val nextFingerprint = dir.fingerprint(options)
        if (sources.isNotEmpty() && nextFingerprint == sourceFingerprint) return sources
        sources = dir.listSos(options)
        sourceFingerprint = nextFingerprint
        pageCache.clear()
        AppLog.i("Scanned ${sources.size} SO entries")
        return sources
    }

    private fun scanOptions(settings: SettingsStore): ScanOptions =
        ScanOptions(
            scanApks = settings.scanApks,
            scanSubdirectories = settings.scanSubdirectories,
            maxDepth = settings.maxScanDepth,
            skipFilesLargerThanBytes = settings.skipFilesLargerThanMb.toLong() * 1024L * 1024L,
        )

    private fun sourceSummary(dir: WorkDirectory, src: SoSource): SourceSummary {
        if (!SettingsStore(context).parseMetadataInList) return SourceSummary("unknown", 0, "little", false, false)
        val key = sourceKey(src)
        return sourceSummaryCache.getOrPut(key) {
            dir.cachedSummary(src)?.let {
                return@getOrPut SourceSummary(it.architecture, it.bits, it.endian, it.hasDebugInfo, it.stripped)
            }
            runCatching {
                val elf = lief.parse(dir.readSource(src))
                val summary = SourceSummary(
                    architecture = elf.architecture,
                    bits = elf.bits,
                    endian = elf.endian,
                    hasDebugInfo = elf.sections.any { it.name.startsWith(".debug") },
                    stripped = elf.symbols.isEmpty(),
                )
                dir.putCachedSummary(src, CachedSourceSummary(summary.architecture, summary.bits, summary.endian, summary.hasDebugInfo, summary.stripped))
                summary
            }.getOrElse {
                SourceSummary("unknown", 0, "little", false, true)
            }
        }
    }

    private fun sourceKey(src: SoSource): String = "${src.path}|${src.size}|${src.modified}"

    private fun searchKey(workspaceId: String, editSessionId: String, target: String, query: String, limit: Int): String {
        val revision = if (editSessionId.isBlank()) 0 else workspaces[workspaceId]?.edits?.get(editSessionId)?.revision ?: 0
        return "$workspaceId|$editSessionId|$revision|$target|${query.lowercase()}|${limit.coerceIn(1, 5000)}"
    }

    private fun page(field: String, all: List<JSONObject>, limit: Int, cursor: String = ""): JSONObject {
        val boundedLimit = limit.coerceIn(1, 5000)
        val state = cursor.takeIf { it.isNotBlank() }?.let(pageCache::remove)
        val items = state?.items ?: all
        val fieldName = state?.field ?: field
        val start = state?.offset ?: 0
        val effectiveLimit = state?.limit ?: boundedLimit
        val chunk = items.drop(start).take(effectiveLimit)
        val nextOffset = start + chunk.size
        val nextCursor = if (nextOffset < items.size) {
            "page:${UUID.randomUUID()}"
                .also { pageCache[it] = PageState(fieldName, items, nextOffset, effectiveLimit) }
        } else {
            null
        }
        return ok(JSONObject()
            .put(fieldName, chunk.toJsonArray())
            .put("pagination", pagination(nextCursor != null, nextCursor, chunk.size, effectiveLimit, items.size)))
    }

    private fun parseDisasmCursor(cursor: String): DisasmCursorState? {
        if (!cursor.startsWith("disasm:")) return null
        val parts = cursor.removePrefix("disasm:").split(':')
        if (parts.size != 6) return null
        return runCatching {
            DisasmCursorState(
                workspaceId = decodeCursorPart(parts[0]),
                editSessionId = decodeCursorPart(parts[1]),
                locator = decodeCursorPart(parts[2]),
                byteOffset = parts[3].toInt().coerceAtLeast(0),
                limit = parts[4].toInt().coerceIn(1, 5000),
                maxBytes = parts[5].toInt().coerceIn(256, 65536),
            )
        }.getOrNull()
    }

    private fun disasmCursor(workspaceId: String, editSessionId: String, locator: String, byteOffset: Int, limit: Int, maxBytes: Int): String =
        listOf(
            encodeCursorPart(workspaceId),
            encodeCursorPart(editSessionId),
            encodeCursorPart(locator),
            byteOffset.toString(),
            limit.coerceIn(1, 5000).toString(),
            maxBytes.coerceIn(256, 65536).toString(),
        ).joinToString(":", prefix = "disasm:")

    private fun encodeCursorPart(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))
    private fun decodeCursorPart(value: String): String = String(Base64.getUrlDecoder().decode(value), Charsets.UTF_8)

    private fun functionByteSize(elf: ElfFile, sym: SymbolInfo, fileOffset: Int, fileSize: Int): Int {
        val declared = sym.size.toInt().takeIf { it > 0 }
        if (declared != null) return declared
        val start = sym.value and -2L
        val nextFunction = (elf.symbols + elf.dynSymbols)
            .asSequence()
            .filter { it.type == "FUNC" && !it.imported }
            .map { it.value and -2L }
            .filter { it > start }
            .minOrNull()
        val byNext = nextFunction?.let { (it - start).toInt().takeIf { size -> size > 0 } }
        if (byNext != null) return byNext.coerceAtMost(fileSize - fileOffset)
        val bySection = sectionFor(elf, start)?.let { (it.offset + it.size - fileOffset).toInt().takeIf { size -> size > 0 } }
        return (bySection ?: (fileSize - fileOffset)).coerceAtMost(64 * 1024)
    }

    private fun functionByteSizeFromAddress(elf: ElfFile, start: Long, fileOffset: Int, fileSize: Int): Int {
        val nextFunction = (elf.symbols + elf.dynSymbols)
            .asSequence()
            .filter { it.type == "FUNC" && !it.imported }
            .map { it.value and -2L }
            .filter { it > start }
            .minOrNull()
        val byNext = nextFunction?.let { (it - start).toInt().takeIf { size -> size > 0 } }
        if (byNext != null) return byNext.coerceAtMost(fileSize - fileOffset)
        val bySection = sectionFor(elf, start)?.let { (it.offset + it.size - fileOffset).toInt().takeIf { size -> size > 0 } }
        return (bySection ?: (fileSize - fileOffset)).coerceAtMost(64 * 1024)
    }

    private fun resolveRizinFunctionAddress(bytes: ByteArray, elf: ElfFile, name: String): Long? = rizinFunctions(bytes, elf)
        .firstOrNull { it.optString("name") == name }
        ?.optLong("addr", -1L)
        ?.takeIf { it >= 0 }
        ?.and(-2L)

    private fun rizinFunctionSize(bytes: ByteArray, elf: ElfFile, start: Long): Int? = rizinFunctions(bytes, elf)
        .firstOrNull { (it.optLong("addr", -1L) and -2L) == start }
        ?.optLong("size", 0L)
        ?.toInt()
        ?.takeIf { it > 0 }

    private fun rizinFunctions(bytes: ByteArray, elf: ElfFile): List<JSONObject> {
        if (!NativeEngine.active().available()) return emptyList()
        val arr = runCatching { JSONArray(NativeEngine.active().functions(bytes, elf.architecture)) }.getOrNull() ?: return emptyList()
        return (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
    }

    private fun neededLibraries(elf: ElfFile, bytes: ByteArray): List<String> {
        val dynstr = elf.sections.firstOrNull { it.name == ".dynstr" } ?: return emptyList()
        return elf.dynamicEntries.asSequence()
            .filter { it.tag == 1L }
            .mapNotNull { entry ->
                val start = (dynstr.offset + entry.value).toInt()
                if (start !in bytes.indices) return@mapNotNull null
                var end = start
                while (end < bytes.size && bytes[end].toInt() != 0) end++
                bytes.copyOfRange(start, end).toString(Charsets.UTF_8).takeIf { it.isNotBlank() }
            }
            .distinct()
            .toList()
    }

    private fun validateCodeAddress(elf: ElfFile, va: Long, thumb: Boolean): JSONObject? {
        val alignment = if (elf.architecture == "arm32" && thumb) 2L else if (elf.architecture in setOf("arm32", "arm64", "mips")) 4L else 1L
        if (alignment > 1 && va % alignment != 0L) return err("INVALID_ADDRESS_ALIGNMENT", "Address ${hex(va)} is not aligned for ${elf.architecture}${if (thumb) " thumb" else ""}", "addr", hex(va), "alignment" to alignment)
        val section = sectionFor(elf, va) ?: return err("OFFSET_OUT_OF_RANGE", "Address ${hex(va)} does not belong to any section", "addr", hex(va))
        if (!sectionExecutable(section)) return err("NON_EXECUTABLE_ADDRESS", "Address ${hex(va)} is in non-executable section '${section.name}'", "addr", hex(va), "section" to section.name, "sectionFlags" to flags(section.flags))
        return null
    }

    private fun sectionExecutable(section: SectionInfo): Boolean = section.flags and 4L != 0L

    private fun executableSectionFor(elf: ElfFile, va: Long): SectionInfo? = sectionFor(elf, va)?.takeIf(::sectionExecutable)

    private fun functionContaining(elf: ElfFile, va: Long): SymbolInfo? = (elf.symbols + elf.dynSymbols)
        .asSequence()
        .filter { it.type == "FUNC" && !it.imported && it.size > 0 }
        .firstOrNull { va >= (it.value and -2L) && va < (it.value and -2L) + it.size }

    private fun functionIdentityJson(elf: ElfFile, sym: SymbolInfo): JSONObject {
        val start = sym.value and -2L
        return JSONObject()
            .put("name", sym.name)
            .put("startAddr", hex(start))
            .put("endAddr", hex(start + sym.size))
            .put("size", sym.size)
            .put("kind", functionKind(elf, sym))
    }

    private fun functionKind(elf: ElfFile, sym: SymbolInfo): String {
        val start = sym.value and -2L
        val section = sectionFor(elf, start)
        return when {
            sym.imported -> "import_symbol"
            section?.name == ".plt" || sym.name.startsWith("sym.imp.") -> "plt_stub"
            sym.size in 1..4 && elf.architecture == "arm64" -> "export_thunk"
            else -> "real_function"
        }
    }

    private fun rizinFunctionKind(elf: ElfFile, item: JSONObject): String {
        val name = item.optString("name")
        val addr = item.optLong("addr", -1L)
        val section = if (addr >= 0) sectionFor(elf, addr) else null
        return when {
            section?.name == ".plt" || name.startsWith("sym.imp.") -> "plt_stub"
            item.optLong("size", 0L) in 1..4 && elf.architecture == "arm64" -> "export_thunk"
            else -> "real_function"
        }
    }

    private fun thunkInfoFromLines(lines: List<String>, entry: Long): JSONObject {
        val first = lines.firstOrNull().orEmpty()
        val branch = Regex("""^0x[0-9a-fA-F]+:\s+b\s+(0x[0-9a-fA-F]+)""").find(first)
        return if (branch != null) JSONObject()
            .put("isThunk", true)
            .put("entry", hex(entry))
            .put("target", branch.groupValues[1])
        else JSONObject().put("isThunk", false)
    }

    private fun decompileWithContext(workspaceId: String, editSessionId: String, elf: ElfFile, va: Long, lines: List<String> = emptyList()): JSONObject {
        val thunk = thunkInfoFromLines(lines, va)
        val payload = rzDecompile(workspaceId, editSessionId, hex(va), false)
        val decompileVa = payload.optString("addr", hex(va))
        return payload
            .put("entryVa", hex(va))
            .put("decompiledVa", decompileVa)
            .put("sameAsEntry", decompileVa == hex(va))
            .put("thunk", thunk)
            .put("sourceSection", sectionFor(elf, va)?.name ?: JSONObject.NULL)
    }

    private fun instructionOffsetToByteOffset(elf: ElfFile, sym: SymbolInfo, instructionOffset: Int): Int {
        if (instructionOffset <= 0) return 0
        val step = if (elf.architecture == "arm32" && (sym.value and 1L) == 1L) {
            2
        } else if (elf.architecture in setOf("arm32", "arm64", "mips")) {
            4
        } else {
            0
        }
        return if (step > 0) instructionOffset * step else 0
    }

    private fun resolveOutputFile(rawName: String, strategy: String): File {
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

    private fun symbolJson(file: String, s: SymbolInfo) = JSONObject().put("locator", "so_symbol:$file!${s.name}").put("name", s.name).put("bind", s.bind).put("type", s.type).put("visibility", s.visibility).put("value", hex(s.value)).put("size", s.size).put("isExported", s.exported).put("isImported", s.imported).put("demangled", JSONObject.NULL)
    private fun stringJson(file: String, s: StringInfo) = JSONObject().put("locator", "so_string:$file!${s.offset.toString(16)}").put("offset", hex(s.offset)).put("value", s.value).put("length", s.length).put("section", s.section).put("encoding", s.encoding).put("confidence", s.confidence).put("isTerminated", true)
    private fun sectionJson(file: String, s: SectionInfo, index: Int = -1) = JSONObject().put("locator", sectionLocator(file, s, index)).put("name", s.name).put("index", index).put("type", s.type).put("flags", s.flags).put("addr", hex(s.addr)).put("offset", hex(s.offset)).put("size", s.size).put("link", s.link).put("info", s.info).put("addralign", s.addralign).put("entsize", s.entsize)
    private fun relocJson(r: RelocInfo) = JSONObject().put("section", r.section).put("offset", hex(r.offset)).put("type", r.type).put("typeName", relocationTypeName(r.type)).put("symbol", r.symbol).put("symbolLocator", if (r.symbol.isNotBlank()) "so_symbol:lib.so!${r.symbol}" else JSONObject.NULL).put("addend", r.addend)
    private fun relocationJson(file: String, elf: ElfFile, r: RelocInfo): JSONObject {
        val symbol = r.symbol.takeIf { it.isNotBlank() }
        val symbolInfo = symbol?.let { name -> (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name } }
        return JSONObject()
            .put("locator", "so_reloc:$file!${r.section}!${r.offset.toString(16)}")
            .put("section", r.section)
            .put("offset", hex(r.offset))
            .put("type", r.type)
            .put("typeName", relocationTypeName(r.type))
            .put("symbol", symbol ?: JSONObject.NULL)
            .put("symbolLocator", symbol?.let { "so_symbol:$file!$it" } ?: JSONObject.NULL)
            .put("symbolValue", symbolInfo?.let { hex(it.value) } ?: JSONObject.NULL)
            .put("symbolImported", symbolInfo?.imported ?: JSONObject.NULL)
            .put("addend", r.addend)
    }
    private fun relocationTypeName(type: Long): String = when (type) {
        257L -> "R_AARCH64_ABS64"
        258L -> "R_AARCH64_ABS32"
        259L -> "R_AARCH64_ABS16"
        1024L -> "R_AARCH64_COPY"
        1025L -> "R_AARCH64_GLOB_DAT"
        1026L -> "R_AARCH64_JUMP_SLOT"
        1027L -> "R_AARCH64_RELATIVE"
        1031L -> "R_AARCH64_TLS_TPREL64"
        1032L -> "R_AARCH64_TLS_DTPREL32"
        1033L -> "R_AARCH64_IRELATIVE"
        268435456L + 1025L -> "R_AARCH64_GLOB_DAT|ANDROID_PACKED"
        268435456L + 1026L -> "R_AARCH64_JUMP_SLOT|ANDROID_PACKED"
        268435456L + 1027L -> "R_AARCH64_RELATIVE|ANDROID_PACKED"
        else -> "UNKNOWN_$type"
    }
    private fun phJson(p: ProgramHeaderInfo) = JSONObject().put("type", p.type).put("flags", p.flags).put("offset", hex(p.offset)).put("vaddr", hex(p.vaddr)).put("paddr", hex(p.paddr)).put("filesz", p.filesz).put("memsz", p.memsz).put("align", p.align)
    private fun dynJson(d: DynamicEntryInfo) = JSONObject().put("tag", d.tag).put("value", hex(d.value))
    private fun elfSummaryJson(workspaceId: String, editSessionId: String, elf: ElfFile) = JSONObject().put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("bits", elf.bits).put("endian", elf.endian).put("machine", elf.machineName).put("architecture", elf.architecture).put("entry", hex(elf.entry)).put("counts", JSONObject().put("sections", elf.sections.size).put("symbols", elf.symbols.size).put("dynSymbols", elf.dynSymbols.size).put("relocations", elf.relocations.size).put("programHeaders", elf.programHeaders.size).put("dynamicEntries", elf.dynamicEntries.size).put("strings", elf.strings.size))
    private fun sectionFor(elf: ElfFile, va: Long): SectionInfo? = elf.sections.firstOrNull { it.size > 0 && it.addr != 0L && va >= it.addr && va < it.addr + it.size }
    private fun sectionLocator(file: String, s: SectionInfo, index: Int): String = "so_section:$file!${sectionKey(s, index)}"
    private fun sectionKey(s: SectionInfo, index: Int): String = "${s.name}@${hex(s.offset)}#${index.coerceAtLeast(0)}"
    private fun resolveSection(elf: ElfFile, locator: String): SectionInfo? {
        val target = locatorTarget(locator, "so_section")
        val index = target.substringAfterLast('#', "").toIntOrNull()
        if (index != null && index in elf.sections.indices) return elf.sections[index]
        val offset = parseHexLong(target.substringAfterLast('@', ""))
        if (offset != null) elf.sections.firstOrNull { it.offset == offset }?.let { return it }
        val name = target.substringBefore('@').substringBefore('#')
        return elf.sections.firstOrNull { it.name == name }
    }
    private fun fallbackByteSearch(bytes: ByteArray, elf: ElfFile, pattern: String, fromVa: Long, toVa: Long): JSONArray {
        val parsed = parseHexPattern(pattern) ?: return JSONArray()
        val start = if (fromVa > 0) vaToOffset(elf, fromVa)?.toInt() ?: fromVa.toInt().coerceIn(0, bytes.size) else 0
        val end = if (toVa > 0) vaToOffset(elf, toVa)?.toInt() ?: toVa.toInt().coerceIn(0, bytes.size) else bytes.size
        val boundedStart = start.coerceIn(0, bytes.size)
        val boundedEnd = end.coerceIn(boundedStart, bytes.size)
        val hits = JSONArray()
        var pos = boundedStart
        val maxHits = 5000
        while (pos <= boundedEnd - parsed.size && hits.length() < maxHits) {
            if (parsed.indices.all { parsed[it] == null || bytes[pos + it] == parsed[it] }) {
                val va = offsetToVa(elf, pos.toLong())
                hits.put(JSONObject().put("fileOffset", hex(pos.toLong())).put("va", va?.let(::hex) ?: JSONObject.NULL).put("section", sectionForOffset(elf, pos.toLong())?.name ?: "").put("length", parsed.size))
                pos += parsed.size.coerceAtLeast(1)
            } else {
                pos++
            }
        }
        return hits
    }
    private fun parseHexPattern(pattern: String): List<Byte?>? {
        val tokens = pattern.trim().split(Regex("[\\s,]+"), 0).filter { it.isNotBlank() }
        if (tokens.isEmpty()) return null
        if (tokens.size == 1 && !tokens[0].contains('?')) {
            val compact = tokens[0]
            if (compact.length % 2 != 0 || !compact.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) return null
            return compact.chunked(2).map { it.toInt(16).toByte() }
        }
        return tokens.map { token ->
            if (token == "??" || token == "?") null else token.toIntOrNull(16)?.takeIf { it in 0..255 }?.toByte() ?: return null
        }
    }
    private fun sectionForOffset(elf: ElfFile, offset: Long): SectionInfo? = elf.sections.firstOrNull { offset >= it.offset && offset < it.offset + it.size }
    private fun enrichRizinSearchHits(elf: ElfFile, hits: JSONArray) {
        for (i in 0 until hits.length()) {
            val hit = hits.optJSONObject(i) ?: continue
            val addr = hit.optLong("addr", -1L)
            if (addr < 0) continue
            hit.put("hexAddr", hex(addr))
            val fileOffset = vaToOffset(elf, addr)
            if (fileOffset != null) {
                hit.put("fileOffset", hex(fileOffset))
                sectionForOffset(elf, fileOffset)?.let { section ->
                    hit.put("section", section.name)
                    hit.put("sectionOffset", hex(fileOffset - section.offset))
                }
            }
        }
    }
    private fun offsetToVa(elf: ElfFile, offset: Long): Long? {
        sectionForOffset(elf, offset)?.let { return it.addr + (offset - it.offset) }
        val ph = elf.programHeaders.firstOrNull { it.type == 1L && offset >= it.offset && offset < it.offset + it.filesz }
        return ph?.let { it.vaddr + (offset - it.offset) }
    }
    private fun vaToOffset(elf: ElfFile, va: Long): Long? {
        val ph = elf.programHeaders.firstOrNull { it.type == 1L && va >= it.vaddr && va < it.vaddr + it.filesz }
        if (ph != null) return ph.offset + (va - ph.vaddr)
        sectionFor(elf, va)?.let { return it.offset + (va - it.addr) }
        return null
    }
    private fun pseudoDisasm(elf: ElfFile, sym: SymbolInfo, bytes: ByteArray, limit: Int, startAddress: Long = sym.value and -2L): String {
        val step = if (elf.architecture == "arm32" && (sym.value and 1L) == 1L) 2 else if (elf.architecture in setOf("arm32", "arm64", "mips")) 4 else 1
        val lines = mutableListOf<String>()
        var p = 0
        while (p < bytes.size && lines.size < limit) {
            val chunk = bytes.copyOfRange(p, min(p + step, bytes.size))
            lines += "0x${(startAddress + p).toString(16)}: ${chunk.joinToString(" ") { "%02X".format(it) }}    .byte ${chunk.joinToString(", ") { "0x%02x".format(it) }}"
            p += step
        }
        return lines.joinToString("\n")
    }
    private fun cleanDisasmLines(text: String, limit: Int): List<String> = text.lineSequence()
        .map { it.trimEnd() }
        .filter { it.isNotBlank() }
        .map { line ->
            val mixed = Regex("""^(0x[0-9a-fA-F]+:)\s+(?:[0-9a-fA-F]{2}\s+){4,}(.+)$""").find(line.trim())
            if (mixed != null) "${mixed.groupValues[1]} ${mixed.groupValues[2].trim()}" else line.trim()
        }
        .filterNot { it.matches(Regex("""^[0-9a-fA-F]{4,}\s+[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){3,}.*""")) }
        .take(limit)
        .toList()

    private fun annotateDisasmLines(hints: Map<Long, String>, lines: List<String>): List<String> {
        if (lines.isEmpty()) return lines
        if (hints.isEmpty()) return lines
        val addressPattern = Regex("""\b0x[0-9a-fA-F]+\b""")
        return lines.map { line ->
            if (line.contains("sym.imp.") || line.contains("; import:")) return@map line
            val importNames = addressPattern.findAll(line)
                .mapNotNull { match -> parseHexLong(match.value)?.let(hints::get) }
                .distinct()
                .toList()
            if (importNames.isEmpty()) line else "$line ; import: ${importNames.joinToString(", ") { "sym.imp.$it" }}"
        }
    }

    private fun disasmReferenceHints(workspaceId: String, editSessionId: String, elf: ElfFile): Map<Long, String> {
        val hints = importAddressHints(elf).toMutableMap()
        hints.putAll(rizinImportStubHints(workspaceId, editSessionId, elf))
        return hints
    }

    private fun disasmSymbolHints(hints: Map<Long, String>, elf: ElfFile, startVa: Long, size: Long): JSONArray {
        val endVa = startVa + size.coerceAtLeast(0)
        val result = JSONArray()
        hints.entries
            .filter { it.key in startVa until endVa }
            .sortedBy { it.key }
            .forEach { (address, name) ->
                result.put(JSONObject()
                    .put("addr", hex(address))
                    .put("symbol", name)
                    .put("kind", "import")
                    .put("display", "sym.imp.$name"))
            }
        signalImports(elf).forEach { signalName ->
            result.put(JSONObject()
                .put("symbol", signalName)
                .put("kind", "signal-import")
                .put("display", "sym.imp.$signalName"))
        }
        return result
    }

    private fun importAddressHints(symbolHints: JSONArray): Map<Long, String> {
        val hints = linkedMapOf<Long, String>()
        for (i in 0 until symbolHints.length()) {
            val hint = symbolHints.optJSONObject(i) ?: continue
            val address = parseHexLong(hint.optString("addr")) ?: continue
            val symbol = hint.optString("symbol").takeIf { it.isNotBlank() } ?: continue
            if (hint.optString("kind") == "import") hints[address] = symbol
        }
        return hints
    }

    private fun importAddressHints(elf: ElfFile): Map<Long, String> {
        val importedSymbols = elf.dynSymbols.filter { it.imported && it.name.isNotBlank() }.associateBy { it.name }
        val hints = linkedMapOf<Long, String>()
        elf.relocations
            .filter { it.symbol.isNotBlank() && importedSymbols.containsKey(it.symbol) }
            .forEach { relocation -> hints[relocation.offset] = relocation.symbol }
        importedSymbols.values
            .filter { it.value > 0 }
            .forEach { symbol -> hints.putIfAbsent(symbol.value and -2L, symbol.name) }
        return hints
    }

    private fun rizinImportStubHints(workspaceId: String, editSessionId: String, elf: ElfFile): Map<Long, String> {
        if (!NativeEngine.active().available()) return emptyMap()
        val bytes = runCatching { dataFor(workspaceId, editSessionId) }.getOrNull() ?: return emptyMap()
        val functions = runCatching { JSONArray(NativeEngine.active().functions(bytes, elf.architecture)) }.getOrNull() ?: return emptyMap()
        val hints = linkedMapOf<Long, String>()
        for (i in 0 until functions.length()) {
            val function = functions.optJSONObject(i) ?: continue
            val name = function.optString("name")
            if (!name.startsWith("sym.imp.")) continue
            val address = function.optLong("addr", -1L)
            if (address >= 0) hints[address] = name.removePrefix("sym.imp.")
        }
        return hints
    }

    private fun signalImports(elf: ElfFile): List<String> {
        val signalNames = setOf("signal", "sigaction", "sigprocmask", "sigfillset", "sigemptyset", "sigaddset", "pthread_sigmask", "kill", "raise")
        return elf.dynSymbols.asSequence()
            .filter { it.imported && it.name in signalNames }
            .map { it.name }
            .distinct()
            .sorted()
            .toList()
    }

    private fun normalizeCfgPayload(payload: JSONObject, elf: ElfFile) {
        val blocks = payload.optJSONArray("basicBlocks") ?: payload.optJSONArray("blocks") ?: return
        for (i in 0 until blocks.length()) {
            val block = blocks.optJSONObject(i) ?: continue
            normalizeCfgAddressField(block, "jump", elf)
            normalizeCfgAddressField(block, "fail", elf)
            normalizeCfgAddressField(block, "addr", elf)
            normalizeCfgAddressField(block, "startAddr", elf)
            normalizeCfgAddressField(block, "endAddr", elf)
        }
        val edges = payload.optJSONArray("edges") ?: return
        for (i in 0 until edges.length()) {
            val edge = edges.optJSONObject(i) ?: continue
            normalizeCfgAddressField(edge, "from", elf)
            normalizeCfgAddressField(edge, "to", elf)
        }
        val signalNames = signalImports(elf)
        if (signalNames.isNotEmpty()) {
            payload.put("signalHandling", JSONObject()
                .put("importedSignals", JSONArray(signalNames))
                .put("staticCfgLimitation", "Signal handlers and asynchronous signal delivery are semantic/runtime edges; Rizin basic-block CFG does not automatically add those edges without concrete handler recovery."))
        }
    }

    private fun normalizeCfgAddressField(obj: JSONObject, field: String, elf: ElfFile) {
        if (!obj.has(field) || obj.isNull(field)) return
        val value = obj.opt(field)
        val longValue = when (value) {
            null -> null
            is Number -> value.toLong()
            is String -> parseHexLong(value) ?: value.toLongOrNull()
            else -> null
        }
        if (longValue == null || longValue < 0 || vaToOffset(elf, longValue) == null) {
            obj.put(field, JSONObject.NULL)
            obj.put("${field}Valid", false)
        } else {
            obj.put(field, hex(longValue))
            obj.put("${field}Valid", true)
        }
    }
    private fun architectureNop(architecture: String, thumb: Boolean): ByteArray = when (architecture) {
        "arm64" -> byteArrayOf(0x1f, 0x20, 0x03, 0xd5.toByte())
        "arm32" -> if (thumb) byteArrayOf(0x00, 0xbf.toByte()) else byteArrayOf(0x00, 0xf0.toByte(), 0x20, 0xe3.toByte())
        "mips" -> byteArrayOf(0x00, 0x00, 0x00, 0x00)
        else -> byteArrayOf(0x90.toByte())
    }
    private fun asmEditRange(edit: JSONObject, startVa: Long, thumb: Boolean, architecture: String, fallbackInsnSize: Int, maxBytes: Int): Pair<Int, Int> {
        val step = if (architecture == "arm32" && thumb) 2 else fallbackInsnSize.coerceAtLeast(1)
        if (edit.has("address") && edit.optString("address").isNotBlank()) {
            val addrStr = edit.optString("address").trim().removePrefix("0x").removePrefix("0X")
            val addr = addrStr.toLongOrNull(16)
                ?: throw IllegalArgumentException("address must be a hex VA like 0x978, got ${edit.optString("address")}")
            val off = (addr - startVa).toInt()
            val length = when {
                edit.optInt("byteLength", 0) > 0 -> edit.optInt("byteLength", 0)
                edit.optInt("length", 0) > 0 -> edit.optInt("length", 0)
                edit.has("instructionCount") -> edit.optInt("instructionCount", 1).coerceAtLeast(1) * step
                edit.has("count") -> edit.optInt("count", 1).coerceAtLeast(1) * step
                else -> step
            }
            require(off >= 0 && length > 0 && off + length <= maxBytes) { "Assembly edit address range [${hex(off.toLong())}, +$length) exceeds function bytes ($maxBytes)" }
            return off to length
        }
        if (edit.has("instructionIndex")) {
            val idx = edit.optInt("instructionIndex", 0)
            val count = edit.optInt("instructionCount", edit.optInt("count", 1)).coerceAtLeast(1)
            val off = idx * step
            val length = when {
                edit.optInt("byteLength", 0) > 0 -> edit.optInt("byteLength", 0)
                edit.optInt("length", 0) > 0 -> edit.optInt("length", 0)
                else -> count * step
            }
            require(idx >= 0 && length > 0 && off + length <= maxBytes) { "Assembly edit instruction range exceeds function bytes" }
            return off to length
        }
        val explicitByteOffset = when {
            edit.has("byteOffset") && edit.optInt("byteOffset", 0) != 0 -> edit.optInt("byteOffset", 0)
            edit.has("offset") && edit.optInt("offset", 0) != 0 -> edit.optInt("offset", 0)
            edit.has("byteOffset") && !edit.has("instructionIndex") -> edit.optInt("byteOffset", 0)
            edit.has("offset") && !edit.has("instructionIndex") -> edit.optInt("offset", 0)
            else -> 0
        }
        val length = edit.optInt("byteLength", edit.optInt("length", 0)).takeIf { it > 0 } ?: edit.optInt("instructionCount", edit.optInt("count", 1)).coerceAtLeast(1) * step
        require(explicitByteOffset >= 0 && length > 0 && explicitByteOffset + length <= maxBytes) { "Assembly edit byte range exceeds function bytes" }
        return explicitByteOffset to length
    }
    private fun repeatBytes(pattern: ByteArray, length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        val out = ByteArray(length)
        var pos = 0
        while (pos < length) {
            val n = min(pattern.size, length - pos)
            System.arraycopy(pattern, 0, out, pos, n)
            pos += n
        }
        return out
    }
    private fun byteDiffRanges(a: ByteArray, b: ByteArray): JSONArray {
        val ranges = JSONArray()
        val maxLen = maxOf(a.size, b.size)
        var i = 0
        while (i < maxLen) {
            val same = i < a.size && i < b.size && a[i] == b[i]
            if (same) {
                i++
                continue
            }
            val start = i
            while (i < maxLen && !(i < a.size && i < b.size && a[i] == b[i])) i++
            val oldBytes = if (start < a.size) a.copyOfRange(start, min(i, a.size)) else ByteArray(0)
            val newBytes = if (start < b.size) b.copyOfRange(start, min(i, b.size)) else ByteArray(0)
            ranges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start).put("oldHex", hexBytes(oldBytes)).put("newHex", hexBytes(newBytes)))
        }
        return ranges
    }
    private fun flags(flags: Long) = buildString { if (flags and 1L != 0L) append('W'); if (flags and 2L != 0L) append('A'); if (flags and 4L != 0L) append('X') }
    private fun indexOf(data: ByteArray, pattern: ByteArray): Int {
        if (pattern.isEmpty() || data.size < pattern.size) return -1
        for (i in 0..data.size - pattern.size) if (pattern.indices.all { data[i + it] == pattern[it] }) return i
        return -1
    }
    private fun allIndexesOf(data: ByteArray, pattern: ByteArray): List<Int> {
        if (pattern.isEmpty() || data.size < pattern.size) return emptyList()
        val out = mutableListOf<Int>()
        var start = 0
        while (start <= data.size - pattern.size) {
            val pos = indexOf(data, pattern, start)
            if (pos < 0) break
            out += pos
            start = pos + pattern.size
        }
        return out
    }
    private fun rawUtf8Hits(data: ByteArray, query: String, remaining: Int): List<Pair<Int, String>> {
        if (query.isBlank() || remaining <= 0) return emptyList()
        val pattern = query.toByteArray(Charsets.UTF_8)
        val hits = mutableListOf<Pair<Int, String>>()
        var start = 0
        while (start <= data.size - pattern.size && hits.size < remaining) {
            val pos = indexOf(data, pattern, start)
            if (pos < 0) break
            val from = (pos - 80).coerceAtLeast(0)
            val to = (pos + pattern.size + 80).coerceAtMost(data.size)
            val snippet = data.copyOfRange(from, to).toString(Charsets.UTF_8)
                .filter { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }
                .take(160)
            hits += pos to snippet
            start = pos + pattern.size
        }
        return hits
    }
    private fun indexOf(data: ByteArray, pattern: ByteArray, startAt: Int): Int {
        if (pattern.isEmpty() || data.size < pattern.size) return -1
        for (i in startAt.coerceAtLeast(0)..data.size - pattern.size) if (pattern.indices.all { data[i + it] == pattern[it] }) return i
        return -1
    }
    private fun hex(v: Long) = "0x${v.toString(16)}"
    private fun hexBytes(bytes: ByteArray): String = bytes.joinToString(" ") { "%02X".format(it) }
    private fun pagination(hasMore: Boolean, cursor: String?, returned: Int, limit: Int, total: Int) = JSONObject().put("hasMore", hasMore).put("nextCursor", cursor ?: JSONObject.NULL).put("returnedCount", returned).put("limitMax", limit).put("totalAvailableCount", total)
    private fun disasmPagination(hasMore: Boolean, cursor: String?, instructionCount: Int, limit: Int, bytesReturned: Int, totalBytes: Int) = JSONObject()
        .put("hasMore", hasMore)
        .put("nextCursor", cursor ?: JSONObject.NULL)
        .put("instructionCount", instructionCount)
        .put("bytesReturned", bytesReturned)
        .put("hasMoreInstructions", hasMore)
        .put("returnedCount", instructionCount)
        .put("limitMax", limit)
        .put("totalAvailableCount", totalBytes)
        .put("totalAvailableBytes", totalBytes)
        .put("units", JSONObject().put("returnedCount", "instructions").put("totalAvailableCount", "bytes"))
    private fun workDirCopyResult(requested: Boolean, copy: () -> String?): JSONObject {
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
    private fun enrichDecompilePayload(payload: JSONObject, bytes: ByteArray, elf: ElfFile, va: Long, name: String, locator: String): JSONObject {
        // Keep pseudocode exactly as emitted by the decompiler. Boundary repair happens in native analysis before pdg.
        // Post-pass only DETECTS real content crossing; never hard-clips text.
        val rawPseudo = payload.optString("pseudocode")
        val analyzedSize = payload.optLong("functionSize", 0L).takeIf { it > 0 }
            ?: rizinFunctionSize(bytes, elf, va)?.toLong()
            ?: (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name || (it.value and -2L) == va }?.size?.takeIf { it > 0 }
            ?: 0L
        val end = payload.optLong("functionEnd", 0L).takeIf { it > va }
            ?: if (analyzedSize > 0) va + analyzedSize else 0L
        val nextBoundary = payload.optLong("nextBoundary", 0L).takeIf { it > va }
            ?: (elf.symbols + elf.dynSymbols)
                .asSequence()
                .filter { it.type == "FUNC" && !it.imported }
                .map { (it.value and -2L) to it.name }
                .filter { it.first > va }
                .minByOrNull { it.first }
                ?.first
            ?: 0L
        val nextName = (elf.symbols + elf.dynSymbols)
            .firstOrNull { it.type == "FUNC" && !it.imported && (it.value and -2L) == nextBoundary }
            ?.name
        val resized = payload.optBoolean("resizedToBoundary", false)
        val returnInference = inferReturnType(bytes, elf, va, if (analyzedSize > 0) analyzedSize.toInt() else 0)
        val contentAudit = auditPseudocodeBoundary(rawPseudo, elf, va, end, nextBoundary, name, nextName)
        val contentCrossing = contentAudit.optBoolean("contentCrossing", false)
        val boundaryCrossing = contentCrossing
        val warnings = ArrayList<String>()
        if (resized && nextBoundary > 0) {
            warnings += if (!nextName.isNullOrBlank()) {
                "Analysis function object was resized to next boundary $nextName @ ${hex(nextBoundary)} before decompilation; pseudocode is uncut decompiler output"
            } else {
                "Analysis function object was resized to next boundary @ ${hex(nextBoundary)} before decompilation; pseudocode is uncut decompiler output"
            }
        }
        contentAudit.optJSONArray("warnings")?.let { arr ->
            for (i in 0 until arr.length()) arr.optString(i).takeIf { it.isNotBlank() }?.let(warnings::add)
        }
        return payload
            .put("locator", locator)
            .put("requestedFunction", name)
            .put("pseudocode", rawPseudo)
            .put("functionBounds", JSONObject()
                .put("startAddr", hex(va))
                .put("endAddr", if (end > 0) hex(end) else JSONObject.NULL)
                .put("size", payload.optLong("functionSize", analyzedSize))
                .put("rawSize", payload.optLong("rawFunctionSize", analyzedSize))
                .put("nextBoundary", if (nextBoundary > 0) hex(nextBoundary) else JSONObject.NULL)
                .put("resizedToBoundary", resized)
                .put("anchorCount", payload.optLong("anchorCount", 0L))
                .put("seededNeighbors", payload.optLong("seededNeighbors", 0L))
                .put("source", payload.optString("boundaryStrategy", if (payload.optLong("functionSize", 0L) > 0) "rizin" else "symbol-or-heuristic")))
            .put("boundaryCrossing", boundaryCrossing)
            .put("boundaryCrossingReasons", contentAudit.optJSONArray("reasons") ?: JSONArray())
            .put("pseudocodeCoverage", contentAudit.optJSONObject("coverage") ?: JSONObject()
                .put("declaredStart", hex(va))
                .put("declaredEnd", if (end > 0) hex(end) else JSONObject.NULL)
                .put("contentMinAddr", JSONObject.NULL)
                .put("contentMaxAddr", JSONObject.NULL)
                .put("outOfBoundsAddrs", JSONArray()))
            .put("boundaryWarning", when {
                warnings.isEmpty() -> JSONObject.NULL
                warnings.size == 1 -> warnings[0]
                else -> warnings.joinToString(" | ")
            })
            .put("typeInference", returnInference)
            .put("typeConfidenceNote", "Type fields are inferred heuristics, not proven ABI facts")
            .put("pseudocodePolicy", "never-hard-clip; root-cause analysis-boundary repair + post content-crossing detection only")
    }

    /**
     * Detect whether decompiler text references code after the declared function end.
     * Never rewrites/clips [pseudocode]. Function-pointer assignments to neighbor names
     * (e.g. `pcStack_x = n0g1a2`) are noted separately from true address overreach.
     */
    private fun auditPseudocodeBoundary(
        pseudocode: String,
        elf: ElfFile,
        startVa: Long,
        endVa: Long,
        nextBoundary: Long,
        functionName: String,
        nextName: String?,
    ): JSONObject {
        if (pseudocode.isBlank()) {
            return JSONObject()
                .put("contentCrossing", false)
                .put("reasons", JSONArray())
                .put("warnings", JSONArray())
                .put("coverage", JSONObject()
                    .put("declaredStart", hex(startVa))
                    .put("declaredEnd", if (endVa > 0) hex(endVa) else JSONObject.NULL)
                    .put("contentMinAddr", JSONObject.NULL)
                    .put("contentMaxAddr", JSONObject.NULL)
                    .put("outOfBoundsAddrs", JSONArray()))
        }
        val hardEnd = when {
            nextBoundary > startVa -> nextBoundary
            endVa > startVa -> endVa
            else -> 0L
        }
        val codeSites = LinkedHashSet<Long>()
        Regex("""(?i)\bcode_r0x([0-9a-f]{3,})\b""").findAll(pseudocode).forEach { m ->
            m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
        }
        Regex("""(?i)\bgoto\s+(?:code_r)?0x([0-9a-f]{3,})\b""").findAll(pseudocode).forEach { m ->
            m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
        }
        Regex("""(?i)WARNING:.*?at\s+0x([0-9a-f]+)""").findAll(pseudocode).forEach { m ->
            m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
        }
        val allExplicitAddrs = LinkedHashSet<Long>()
        Regex("""(?i)0x([0-9a-f]{3,})""").findAll(pseudocode).forEach { m ->
            m.groupValues[1].toLongOrNull(16)?.let(allExplicitAddrs::add)
        }
        val inRange = ArrayList<Long>()
        val outOfBounds = ArrayList<Long>()
        for (addr in codeSites) {
            // Ignore tiny immediates / stack slots misparsed as bare hex.
            if (addr < 0x1000) continue
            // Keep only addresses that land in executable image space.
            val inImage = sectionFor(elf, addr) != null || elf.programHeaders.any { it.type == 1L && addr >= it.vaddr && addr < it.vaddr + maxOf(it.memsz, it.filesz) }
            if (!inImage) continue
            if (hardEnd > startVa && addr >= hardEnd) {
                outOfBounds += addr
            } else if (endVa > startVa && addr >= endVa && (nextBoundary == 0L || addr < nextBoundary)) {
                outOfBounds += addr
            } else if (addr >= startVa && (hardEnd == 0L || addr < hardEnd)) {
                inRange += addr
            } else if (addr < startVa && sectionFor(elf, addr)?.let { it.flags and 0x4L != 0L } == true) {
                // references to earlier code (helpers/PLT) are normal; track coverage only for later/overrun.
            }
        }
        val reasons = JSONArray()
        val warnings = JSONArray()
        var contentCrossing = false
        if (outOfBounds.isNotEmpty()) {
            contentCrossing = true
            reasons.put("pseudocode_refs_after_boundary")
            warnings.put(
                "Pseudocode references ${outOfBounds.size} address(es) at/after declared boundary " +
                    "(first=${hex(outOfBounds.first())}" +
                    (if (hardEnd > 0) ", boundary=${hex(hardEnd)}" else "") +
                    "); output was NOT clipped",
            )
        }
        val picOutside = codeSites.filter { hardEnd > startVa && it >= hardEnd }
        if (picOutside.isNotEmpty()) {
            contentCrossing = true
            reasons.put("pic_or_warning_after_boundary")
            warnings.put("Decompiler PIC/WARNING sites after boundary: ${picOutside.take(4).joinToString { hex(it) }}")
        }
        val externalCodeRefs = allExplicitAddrs.filter { addr ->
            addr !in codeSites && addr >= 0x1000 &&
                (sectionFor(elf, addr)?.let { it.flags and 0x4L != 0L } == true) &&
                (addr < startVa || (hardEnd > startVa && addr >= hardEnd))
        }.distinct().sorted()
        val allCoverage = (inRange + outOfBounds)
        val coverage = JSONObject()
            .put("declaredStart", hex(startVa))
            .put("declaredEnd", if (endVa > 0) hex(endVa) else JSONObject.NULL)
            .put("hardBoundary", if (hardEnd > 0) hex(hardEnd) else JSONObject.NULL)
            .put("contentMinAddr", allCoverage.minOrNull()?.let(::hex) ?: JSONObject.NULL)
            .put("contentMaxAddr", allCoverage.maxOrNull()?.let(::hex) ?: JSONObject.NULL)
            .put("inBoundsAddrCount", inRange.size)
            .put("outOfBoundsAddrs", JSONArray(outOfBounds.distinct().sorted().take(32).map(::hex)))
            .put("externalCodeRefs", JSONArray(externalCodeRefs.take(64).map(::hex)))
        return JSONObject()
            .put("contentCrossing", contentCrossing)
            .put("reasons", reasons)
            .put("warnings", warnings)
            .put("coverage", coverage)
    }
    private fun inferReturnType(bytes: ByteArray, elf: ElfFile, startVa: Long, size: Int): JSONObject {
        if (elf.architecture != "arm64" || size < 8) return JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        val off = vaToOffset(elf, startVa)?.toInt() ?: return JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        val end = (off + size).coerceAtMost(bytes.size)
        var sawZero = false
        var sawOne = false
        var sawBoolBranch = false
        var i = off
        while (i + 4 <= end) {
            val insn = littleEndianInt(bytes, i)
            // MOV W0, #0 / MOVZ W0, #0
            if (insn == 0x52800000 || insn == 0x2a1f03e0) sawZero = true
            // MOV W0, #1 / MOVZ W0, #1
            if (insn == 0x52800020) sawOne = true
            // TBZ/TBNZ W0, #0, ...
            if ((insn and 0xff00001f.toInt()) == 0x36000000 || (insn and 0xff00001f.toInt()) == 0x37000000) {
                if (((insn ushr 19) and 0x1f) == 0) sawBoolBranch = true
            }
            i += 4
        }
        return when {
            sawZero && sawOne -> JSONObject().put("returnType", "bool|int").put("confidence", if (sawBoolBranch) 0.86 else 0.72).put("evidence", JSONArray(listOfNotNull("mov w0,#0", "mov w0,#1", if (sawBoolBranch) "tbz/tbnz w0,#0" else null)))
            sawBoolBranch -> JSONObject().put("returnType", "bool|int").put("confidence", 0.6).put("evidence", JSONArray(listOf("tbz/tbnz w0,#0")))
            else -> JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        }
    }
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun checksums(bytes: ByteArray) = JSONObject().put("sha256", sha256(bytes)).put("size", bytes.size)
}
