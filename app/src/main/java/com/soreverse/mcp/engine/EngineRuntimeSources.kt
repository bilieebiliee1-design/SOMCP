// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
package com.soreverse.mcp.engine

import android.net.Uri
import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SelfArtifactGuard
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import com.soreverse.mcp.nativecore.SignatureVerifier
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

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
    val filtered = currentSources.filter {
        prefix.isBlank() ||
            it.path.startsWith(prefix) ||
            it.name.startsWith(prefix)
    }
    val items = JSONArray()
    filtered.asSequence()
        .drop(start)
        .take(boundedLimit)
        .forEach { src ->
            val meta = sourceSummary(dir, src)
            items.put(
                JSONObject()
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
                    .put("stripped", meta.stripped)
            )
        }
    val nextOffset = start + items.length()
    val nextCursor = if (nextOffset < filtered.size) "source:$nextOffset" else null
    ok(
        JSONObject()
            .put("items", items)
            .put(
                "usage",
                "Call so_open with path or filePath from any item. Use the returned workspaceId for the other tools."
            )
            .put(
                "pagination",
                pagination(
                    nextCursor != null,
                    nextCursor,
                    items.length(),
                    boundedLimit,
                    filtered.size
                )
            )
    )
}

internal fun EngineRuntime.open(path: String, temporary: Boolean): JSONObject = guarded {
    if (path.isBlank()) {
        return@guarded err(
            "INVALID_ARGUMENT",
            "Missing SO path. Pass path or filePath from so_open (action=list).",
            "path",
            path
        )
    }
    val ws = openWorkspace(path, temporary)
    val elf = ws.elf
    val src = ws.source
    val symbolFunctions = (elf.symbols + elf.dynSymbols).filter {
        it.type == "FUNC" && !it.imported
    }.distinctBy {
        it.name to
            it.value
    }
    val exportedFunctions = elf.dynSymbols.filter {
        it.type == "FUNC" &&
            !it.imported &&
            it.value > 0
    }.distinctBy { it.name to it.value }
    val analyzedFunctions = if (NativeEngine.active().available()) {
        runCatching {
            JSONArray(NativeEngine.active().functions(ws.data, elf.architecture)).length()
        }.getOrDefault(symbolFunctions.size)
    } else {
        symbolFunctions.size
    }
    val pltStubs = elf.relocations.count { it.section.contains("plt", true) }
    ok(
        JSONObject()
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
            .put(
                "analysisInput",
                JSONObject().put(
                    "source",
                    ws.analysisInputSource
                ).put(
                    "originalSha256",
                    ws.originalSha256
                ).put(
                    "analysisSha256",
                    sha256(ws.data)
                ).put("structureRecovery", ws.structureRecovery)
            )
            .put(
                "counts",
                JSONObject().put(
                    "sections",
                    elf.sections.size
                ).put(
                    "symbols",
                    elf.symbols.size
                ).put(
                    "dynsyms",
                    elf.dynSymbols.size
                ).put(
                    "relocations",
                    elf.relocations.size
                ).put(
                    "functions",
                    symbolFunctions.size
                ).put(
                    "functionsMeaning",
                    "symbolFunctions"
                ).put(
                    "symbolFunctions",
                    symbolFunctions.size
                ).put(
                    "exportedFunctions",
                    exportedFunctions.size
                ).put(
                    "analyzedFunctions",
                    analyzedFunctions
                ).put("pltStubs", pltStubs).put("strings", elf.strings.size)
            )
            .put(
                "capabilities",
                JSONObject().put(
                    "canDisassemble",
                    true
                ).put(
                    "canEditAsm",
                    true
                ).put("canEditHex", true).put("canResolveRelocs", elf.relocations.isNotEmpty()).put(
                    "hasPltGot",
                    elf.sections.any {
                        it.name in
                            setOf(".plt", ".got")
                    }
                ).put("canSearchStrings", elf.strings.isNotEmpty()).put(
                    "hasDebugInfo",
                    elf.sections.any {
                        it.name.startsWith(".debug")
                    }
                ).put(
                    "hasEhFrame",
                    elf.sections.any {
                        it.name in
                            setOf(".eh_frame", ".ARM.exidx")
                    }
                )
            )
            .put("checksums", checksums(ws.data))
    )
}

internal fun EngineRuntime.analyzeApk(path: String, entryLimit: Int = 500): JSONObject = guarded {
    if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "APK path is required", "path", path)
    val local = File(path)
    if (local.isFile && !isAllowedLocalInput(local)) {
        return@guarded err(
            "PATH_NOT_ALLOWED",
            "Local APK path must be inside the app's private/external files directory or the selected work directory",
            "path",
            path
        )
    }
    if (local.isFile &&
        local.length() > ApkAnalyzer.MAX_INPUT_BYTES
    ) {
        return@guarded err(
            "APK_LIMIT_EXCEEDED",
            "APK exceeds ${ApkAnalyzer.MAX_INPUT_BYTES / 1024 / 1024} MiB input limit",
            "path",
            path
        )
    }
    val bytes = try {
        if (local.isFile) {
            local.readBytes()
        } else {
            (
                workDir
                    ?: return@guarded err(
                        "WORK_DIRECTORY_NOT_SELECTED",
                        "APK path is not a local file and no work directory is selected",
                        "path",
                        path
                    )
                ).readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
        }
    } catch (error: ApkAnalysisLimitException) {
        return@guarded err(
            "APK_LIMIT_EXCEEDED",
            error.message ?: "APK exceeds analysis limits",
            "path",
            path
        )
    }
    if (bytes.size < 4 ||
        bytes[0] != 0x50.toByte() ||
        bytes[1] != 0x4b.toByte()
    ) {
        return@guarded err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
    }
    if (isSelfApkBytes(bytes) ||
        (local.isFile && SignatureVerifier.isSelfSignedApk(local.absolutePath))
    ) {
        return@guarded selfForbidden("apk:$path")
    }
    try {
        ok(ApkAnalyzer.analyze(bytes, path, entryLimit))
    } catch (error: ApkAnalysisLimitException) {
        err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
}

internal fun EngineRuntime.openUrl(url: String, outputName: String = "", temporary: Boolean = false): JSONObject = guarded {
    val dir =
        workDir
            ?: return@guarded err(
                "WORK_DIRECTORY_NOT_SELECTED",
                "A work directory must be selected before downloading a SO URL"
            )
    val parsed =
        runCatching { URL(url.trim()) }.getOrNull()
            ?: return@guarded err("INVALID_ARGUMENT", "url must be a valid http(s) URL", "url", url)
    if (parsed.protocol !in
        setOf("http", "https")
    ) {
        return@guarded err(
            "UNSUPPORTED_URL_SCHEME",
            "Only http and https URLs are supported",
            "url",
            url
        )
    }
    runCatching { java.net.InetAddress.getAllByName(parsed.host) }.getOrNull()?.let { addresses ->
        if (addresses.any {
                it.isLoopbackAddress ||
                    it.isAnyLocalAddress ||
                    it.isLinkLocalAddress ||
                    it.isSiteLocalAddress ||
                    it.isMulticastAddress
            }
        ) {
            return@guarded err(
                "URL_HOST_NOT_ALLOWED",
                "Refusing to download from a private, loopback, or link-local address",
                "url",
                url
            )
        }
    }
    val timeout = SettingsStore(context).requestTimeoutMs
    val conn = (parsed.openConnection() as HttpURLConnection).apply {
        connectTimeout =
            timeout.coerceAtMost(30_000)
        readTimeout = timeout
        instanceFollowRedirects = true
        requestMethod =
            "GET"
    }
    val status = conn.responseCode
    if (status !in
        200..299
    ) {
        return@guarded err(
            "DOWNLOAD_FAILED",
            "HTTP download failed with status $status",
            "url",
            url
        )
    }
    val maxBytes = soDownloadMaxBytes()
    val maxMiB = maxBytes / (1024L * 1024L)
    if (conn.contentLengthLong >
        maxBytes
    ) {
        return@guarded err(
            "DOWNLOAD_TOO_LARGE",
            "SO download exceeds $maxMiB MiB limit",
            "contentLength",
            conn.contentLengthLong
        )
    }
    val bytes = conn.inputStream.use { input ->
        java.io.ByteArrayOutputStream().apply {
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n <
                    0
                ) {
                    break
                }
                total += n
                if (total >
                    maxBytes
                ) {
                    return@guarded err(
                        "DOWNLOAD_TOO_LARGE",
                        "SO download exceeds $maxMiB MiB limit",
                        "url",
                        url
                    )
                }
                write(buf, 0, n)
            }
        }.toByteArray()
    }
    if (isSelfApkBytes(bytes)) {
        return@guarded selfForbidden("url:$url")
    }
    if (bytes.size < 4 ||
        bytes[0] != 0x7f.toByte() ||
        bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() ||
        bytes[3] != 'F'.code.toByte()
    ) {
        return@guarded err("NOT_ELF_SO", "Downloaded file is not an ELF/SO file", "url", url)
    }
    val rawName = outputName.ifBlank {
        parsed.path.substringAfterLast('/').substringBefore('?').ifBlank { "downloaded.so" }
    }
    val safeName = rawName.substringAfterLast('/').substringAfterLast('\\').let {
        if (it.endsWith(".so", ignoreCase = true)) it else "$it.so"
    }
    val source = dir.writeRootFile(safeName, bytes)
    sources = (sources.filterNot { it.path == source.path } + source).sortedBy { it.path }
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    open(
        source.path,
        temporary
    ).put(
        "download",
        JSONObject().put(
            "url",
            url
        ).put(
            "savedAs",
            source.path
        ).put("size", bytes.size).put("sha256_16", sha256(bytes).take(16))
    )
}

/**
 * Dynamic limit for a single SO download, derived from the process max heap and
 * the work-directory free space. A downloaded ELF is later read fully into
 * memory (plus LIEF/xanso parsing copies), so on capable devices the cap scales
 * up with available heap, while low-memory devices degrade gracefully with a
 * smaller cap instead of crashing with an OutOfMemoryError.
 */
internal fun EngineRuntime.soDownloadMaxBytes(): Long {
    val heapMaxMiB = Runtime.getRuntime().maxMemory() / (1024L * 1024L)
    // Parsing roughly halves the free heap headroom; use ~50% of max heap as a
    // safety ceiling so a big library won't blow the process heap out.
    val heapCapMiB = (heapMaxMiB * 5) / 10
    val storageFreeMiB = workDir?.let { wd ->
        runCatching {
            val free = android.os.StatFs(wd.rootAbsolutePath()).availableBytes /
                (1024L * 1024L)
            (free - 16L).coerceAtLeast(0L) // keep headroom on disk for the file
        }.getOrDefault(heapCapMiB)
    } ?: heapCapMiB
    val capMiB = minOf(heapCapMiB, storageFreeMiB).coerceIn(64L, 2048L)
    return capMiB * 1024L * 1024L
}

/** True when [bytes] carries SOMCP's own package identifier (`BuildConfig.APPLICATION_ID`). */
internal fun containsPackageIdentifier(bytes: ByteArray): Boolean {
    val marker = BuildConfig.APPLICATION_ID
    if (marker.isBlank()) return false
    val ascii = marker.toByteArray(Charsets.US_ASCII)
    val utf16le = marker.toByteArray(Charsets.UTF_16LE)
    return containsSubsequence(bytes, ascii) || containsSubsequence(bytes, utf16le)
}

private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
    if (needle.isEmpty() || haystack.size < needle.size) return false
    for (i in 0..(haystack.size - needle.size)) {
        var j = 0
        while (j < needle.size && haystack[i + j] == needle[j]) j++
        if (j == needle.size) return true
    }
    return false
}

/** Returns a forbidden error when the target is recognised as SOMCP's own artifact. */
internal fun EngineRuntime.selfForbidden(desc: String): JSONObject = err(
    "SELF_ANALYSIS_FORBIDDEN",
    "SOMCP cannot analyze its own artifact (official signature or package ${BuildConfig.APPLICATION_ID})",
    "reason",
    desc
)

/** Byte-level check: true when [bytes] is SOMCP's own artifact via the package marker. */
internal fun EngineRuntime.isSelfApkBytes(bytes: ByteArray): Boolean = containsPackageIdentifier(bytes)

internal fun EngineRuntime.listWorkspaces(): JSONObject = guarded {
    val items = JSONArray()
    workspaces.values.sortedBy {
        it.source.path
    }.forEach { ws ->
        items.put(
            JSONObject().put(
                "workspaceId",
                ws.id
            ).put(
                "path",
                ws.source.path
            ).put(
                "filePath",
                ws.source.path
            ).put(
                "soFileName",
                ws.source.name
            ).put(
                "source",
                ws.source.source
            ).put(
                "apkPath",
                ws.source.apkPath
            ).put(
                "apkEntry",
                ws.source.apkEntry
            ).put(
                "abi",
                ws.source.abi
            ).put(
                "architecture",
                ws.elf.architecture
            ).put("bits", ws.elf.bits).put("temporary", ws.temporary)
        )
    }
    ok(JSONObject().put("items", items).put("count", items.length()))
}

internal fun EngineRuntime.close(workspaceId: String): JSONObject = guarded {
    // Release emulator sessions bound to this workspace so their native
    // unidbg VMs (and the in-memory copy of the SO they hold) are freed
    // immediately instead of lingering after so_close.
    emulatorSessions.entries.removeAll { (_, session) ->
        if (session.workspaceId == workspaceId) {
            session.live?.let(unidbg::closeSession)
            true
        } else {
            false
        }
    }
    workspaces.remove(workspaceId)
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Closed $workspaceId")
    ok(JSONObject().put("success", true))
}

internal fun EngineRuntime.clearCaches() {
    emulatorSessions.values.forEach { session -> session.live?.let(unidbg::closeSession) }
    emulatorSessions.clear()
    frida.closeAll()
    workspaces.clear()
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
    if (archiveEntry.isNotBlank() &&
        !archiveEntry.endsWith(".so", ignoreCase = true)
    ) {
        error(
            "NOT_ELF_INPUT: $path is an APK/JAR entry, not an ELF SO file. Use apk_analyze or an APK MCP tool."
        )
    }
    val keyFallback = "local:$path"
    // An APK-embedded reference is never a plain filesystem file, so skip the
    // resolveLocalSoSource() File().exists() probe for it (avoids treating
    // "apk:...!..." / "content://apk/..." as a real path).
    val isApkEmbedded = path.trim().let {
        it.contains('!') ||
            it.startsWith("content://apk/") ||
            it.startsWith("apk:")
    }
    val src = findSource(path) ?: (if (isApkEmbedded) null else resolveLocalSoSource(path)) ?: run {
        val trimmed = path.trim()
        // The work-directory boundary checks below do not apply to APK-embedded
        // references — fall straight through to SO_NOT_FOUND with a hint.
        val absolute = trimmed.startsWith("/")
        val root = workDir?.rootAbsolutePath()
        if (isApkEmbedded) {
            error(
                "SO path not found: $path. This looks like an APK-embedded SO; call so_open (action=list) first and open it with the returned path (apk:<relpath>!lib/<abi>/x.so)."
            )
        }
        if (workDir == null && absolute) {
            error(
                "WORK_DIRECTORY_NOT_SELECTED: No work directory selected. Select the containing directory with the work-directory picker, then pass the path returned by so_open action=list or the same absolute path: $trimmed"
            )
        }
        if (absolute && root != null && !trimmed.isSameOrChildOf(root)) {
            error(
                "PATH_OUTSIDE_WORK_DIRECTORY: '$trimmed' is outside the selected work directory root '$root'. Pick the containing directory or an ancestor with the work-directory picker."
            )
        }
        error("SO path not found: $path")
    }
    // Own-artifact protection: never open/view/modify SOMCP's own APK or the
    // native libraries it bundles, whether reached directly (local_file /
    // build_output) or through an APK-embedded reference.
    val selfCandidate = if (src.source == "apk") src.apkPath else src.path
    if (!selfCandidate.isNullOrBlank() && SelfArtifactGuard.isSelfArtifact(context, selfCandidate)) {
        throw IllegalArgumentException(
            "SELF_ANALYSIS_FORBIDDEN: SOMCP cannot open, view, or modify its own artifact $selfCandidate"
        )
    }
    val key = sourceKey(src).ifBlank { keyFallback }
    workspaceBySourceKey[key]?.let { existingId -> workspaces[existingId]?.let { return it } }
    val original = when (src.source) {
        "build_output", "local_file" -> runCatching {
            File(src.path).readBytes()
        }.getOrElse { error("SO path not found: $path") }

        else -> (
            workDir
                ?: error("No work directory selected")
            ).readSource(src)
    }
    require(
        original.size >= 4 &&
            original[0] == 0x7f.toByte() &&
            original[1] == 'E'.code.toByte() &&
            original[2] == 'L'.code.toByte() &&
            original[3] == 'F'.code.toByte()
    ) {
        "NOT_ELF_INPUT: ${src.path} is not an ELF SO file. Use apk_analyze or an APK MCP tool."
    }
    val prepared = prepareAnalysisInput(original)
    val ws =
        Workspace(
            "so-ws-${UUID.randomUUID()}",
            src,
            prepared.data,
            prepared.elf,
            temporary,
            sha256(original),
            prepared.source,
            prepared.facts
        )
    workspaces[ws.id] = ws
    workspaceBySourceKey[key] = ws.id
    AppLog.i("Opened ${src.path} as ${ws.id}")
    return ws
}

internal data class AnalysisInput(val data: ByteArray, val source: String, val facts: JSONObject, val elf: ElfFile)

internal fun EngineRuntime.prepareAnalysisInput(original: ByteArray): AnalysisInput {
    val before = lief.parse(original)
    val facts = JSONObject().put(
        "attempted",
        false
    ).put(
        "changed",
        false
    ).put(
        "sectionsBefore",
        before.sections.size
    ).put(
        "programHeadersBefore",
        before.programHeaders.size
    ).put(
        "symbolsBefore",
        before.symbols.size
    ).put("dynSymbolsBefore", before.dynSymbols.size).put("functionSymbolsRecovered", false)
    if (before.sections.isNotEmpty()) {
        return AnalysisInput(
            original,
            "original",
            facts.put("reason", "section_table_present"),
            before
        )
    }
    if (original.size < 5 ||
        !xanso.available()
    ) {
        return AnalysisInput(
            original,
            "original",
            facts.put(
                "reason",
                if (original.size <
                    5
                ) {
                    "invalid_elf_ident"
                } else {
                    "xanso_unavailable"
                }
            ),
            before
        )
    }
    facts.put("attempted", true)
    val recovered = when (original[4].toInt() and 0xff) {
        1 -> xanso.buildSections(original)
        2 -> xanso.recoverElf64Sections(original)?.let { lief.fixSections(it) }
        else -> null
    }
    if (recovered == null ||
        recovered.isEmpty()
    ) {
        return AnalysisInput(
            original,
            "original",
            facts.put("reason", "xanso_recovery_failed"),
            before
        )
    }
    val after = lief.parse(recovered)
    if (after.sections.isEmpty()) {
        return AnalysisInput(
            original,
            "original",
            facts.put("reason", "recovered_section_table_not_parseable"),
            before
        )
    }
    facts.put(
        "changed",
        !recovered.contentEquals(original)
    ).put("reason", "missing_section_table").put(
        "recoveryMode",
        if ((
                original[4].toInt() and
                    0xff
                ) ==
            1
        ) {
            "xanso32_section_fix"
        } else {
            "xanso64_section_recovery_lief_finalize"
        }
    ).put(
        "sectionsAfter",
        after.sections.size
    ).put(
        "programHeadersAfter",
        after.programHeaders.size
    ).put("symbolsAfter", after.symbols.size).put("dynSymbolsAfter", after.dynSymbols.size).put(
        "functionSymbolsRecovered",
        after.symbols.count { it.type == "FUNC" } > before.symbols.count { it.type == "FUNC" }
    )
    return AnalysisInput(recovered, "xanso_recovered_sections", facts, after)
}

internal fun EngineRuntime.isAllowedLocalInput(file: File): Boolean {
    val extDir = context.getExternalFilesDir(null)?.canonicalPath
    val intDir = runCatching { context.filesDir.canonicalPath }.getOrNull()
    val cacheDir = runCatching { context.cacheDir.canonicalPath }.getOrNull()
    val canonical = runCatching { file.canonicalPath }.getOrNull() ?: return false
    return listOfNotNull(extDir, intDir, cacheDir).any { canonical.startsWith(it) }
}

internal fun EngineRuntime.resolveLocalSoSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val file = File(rawPath)
    if (!file.exists() || !file.isFile) return null
    val extDir = context.getExternalFilesDir(null)?.canonicalPath
    val intDir = context.filesDir.canonicalPath
    val canonical = runCatching { file.canonicalPath }.getOrDefault(rawPath)
    if (listOfNotNull(extDir, intDir).none { canonical.startsWith(it) } ||
        !file.name.endsWith(".so", ignoreCase = true)
    ) {
        return null
    }
    return SoSource(canonical, "build_output", file.name, file.length(), file.lastModified(), null)
}

internal fun EngineRuntime.findSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val trimmed = rawPath.trim()
    val path = trimmed.removePrefix("/")
    workDir?.let { ensureSources(it) }
    // APK-embedded SO resolution. A single SO inside an APK can be referenced
    // in several equivalent forms and we must map every one of them back to the
    // scanned source whose canonical path is `apk:<relpath>!<entry>`:
    //   1. apk:<relpath>!lib/<abi>/x.so         (the form so_open list returns)
    //   2. /abs/path/App.apk!lib/<abi>/x.so     (absolute APK path + entry)
    //   3. content://apk/<apkName>/lib/<abi>/x.so
    //   4. a bare entry like lib/<abi>/x.so when only one APK provides it
    // Instead of matching the whole string we parse out (apkHint, entry) and
    // match against the source's real apkPath/apkEntry fields.
    resolveApkEmbeddedSource(trimmed)?.let { return it }
    val candidates = mutableListOf(trimmed, path)
    workDir?.rootAbsolutePath()?.let { root ->
        if (trimmed.isSameOrChildOf(root)) candidates += trimmed.drop(root.length).removePrefix("/")
    }
    candidates.distinct().forEach { candidate ->
        sources.firstOrNull {
            it.path == candidate ||
                it.name == candidate ||
                it.apkEntry == candidate
        }?.let { return it }
    }
    return sources.firstOrNull { it.path.endsWith("/$path") }
}

private fun String.isSameOrChildOf(root: String): Boolean = this == root || this.startsWith(root.trimEnd('/') + "/")

/**
 * Parse an APK-embedded SO reference into (apkHint, entry) and match it against
 * the scanned `source=="apk"` entries by their real apkPath/apkEntry, so any
 * equivalent spelling of the same embedded SO resolves to the same source.
 *
 * Returns null when [raw] is not an APK-embedded reference or nothing matches.
 */
internal fun EngineRuntime.resolveApkEmbeddedSource(raw: String): SoSource? {
    val apkSources = sources.filter { it.source == "apk" }
    if (apkSources.isEmpty()) return null

    val parsed = parseApkEmbeddedReference(raw) ?: return null
    val normalizedEntry = parsed.entry
    val apkBasename = parsed.apkBasename

    // Prefer an exact apkPath basename + entry match; fall back to entry-only
    // when the caller supplied no usable APK hint and the entry is unambiguous.
    apkSources.firstOrNull { src ->
        src.apkEntry == normalizedEntry &&
            (
                apkBasename == null ||
                    src.apkPath?.substringAfterLast('/')?.equals(apkBasename, ignoreCase = true) ==
                    true
                )
    }?.let { return it }

    if (apkBasename == null) {
        val entryMatches = apkSources.filter { it.apkEntry == normalizedEntry }
        if (entryMatches.size == 1) return entryMatches.first()
    }
    return null
}

/** Normalized (apkBasename, entry) parsed from an APK-embedded SO reference. */
internal data class ApkEmbeddedReference(val apkBasename: String?, val entry: String)

/**
 * Pure parser (no engine state) that turns the many equivalent spellings of an
 * APK-embedded SO reference into a normalized (apkBasename, entry) pair. Kept
 * separate from [resolveApkEmbeddedSource] so it is unit-testable on the JVM.
 * Returns null when [raw] is not an APK-embedded reference or has no entry.
 */
internal fun parseApkEmbeddedReference(raw: String): ApkEmbeddedReference? {
    val trimmed = raw.trim()
    val (apkHint, entry) = when {
        trimmed.startsWith("apk:") -> {
            val body = trimmed.removePrefix("apk:")
            val bang = body.indexOf('!')
            if (bang <= 0) "" to body else body.substring(0, bang) to body.substring(bang + 1)
        }

        trimmed.startsWith("content://apk/") -> {
            // The segment ending in .apk is the APK hint; everything after the
            // first ".apk/" is the entry. Tolerates APK paths with separators.
            val body = trimmed.removePrefix("content://apk/")
            val marker = body.indexOf(".apk/", ignoreCase = true)
            if (marker >=
                0
            ) {
                body.substring(0, marker + 4) to body.substring(marker + 5)
            } else {
                "" to body
            }
        }

        trimmed.contains('!') -> {
            val bang = trimmed.lastIndexOf('!')
            trimmed.substring(0, bang) to trimmed.substring(bang + 1)
        }

        trimmed.contains(".apk/", ignoreCase = true) -> {
            val marker = trimmed.lastIndexOf(".apk/", ignoreCase = true)
            trimmed.substring(0, marker + 4) to trimmed.substring(marker + 5)
        }

        // A bare entry only qualifies when it clearly looks like an in-APK SO.
        trimmed.trimStart('/').startsWith("lib/") && trimmed.endsWith(".so", ignoreCase = true) ->
            "" to
                trimmed.trimStart('/')

        else -> return null
    }

    val normalizedEntry = entry.trim().trimStart('/').removePrefix("./")
    if (normalizedEntry.isBlank()) return null
    val apkBasename = apkHint.trim().trimEnd('/').substringAfterLast('/').ifBlank { null }
    return ApkEmbeddedReference(apkBasename, normalizedEntry)
}

internal fun EngineRuntime.ensureSources(dir: WorkDirectory): List<SoSource> {
    val settings = SettingsStore(context)
    val options = scanOptions(settings)
    if (!settings.indexCacheEnabled) {
        sources = dir.listSos(options)
        sourceFingerprint = sources.map { FileFingerprint(it.path, it.size, it.modified) }
        return sources
    }
    // Single-pass scan: get sources AND fingerprint in one directory walk
    val (scanned, fingerprint) = dir.listSosWithFingerprint(options)
    if (sources.isNotEmpty() && fingerprint == sourceFingerprint) return sources
    sources = scanned
    sourceFingerprint = fingerprint
    pageStore.clear()
    AppLog.i("Scanned ${sources.size} SO entries")
    return sources
}

internal fun EngineRuntime.scanOptions(settings: SettingsStore): ScanOptions = ScanOptions(
    settings.scanApks,
    settings.scanSubdirectories,
    settings.maxScanDepth,
    settings.skipFilesLargerThanMb.toLong() * 1024L * 1024L
)

internal fun EngineRuntime.sourceSummary(dir: WorkDirectory, src: SoSource): SourceSummary {
    if (!SettingsStore(
            context
        ).parseMetadataInList
    ) {
        return SourceSummary("unknown", 0, "little", false, false)
    }
    return sourceSummaryCache.getOrPut(sourceKey(src)) {
        dir.cachedSummary(src)?.let {
            return@getOrPut SourceSummary(
                it.architecture,
                it.bits,
                it.endian,
                it.hasDebugInfo,
                it.stripped
            )
        }

        // Fast path: for filesystem SOs, parse ELF header via seeking (reads only ~few KB
        // instead of the full SO file, which can be tens of MB for libapp.so)
        if (src.source == "filesystem" && src.treeDocumentUri != null) {
            dir.readElfSummary(src.treeDocumentUri)?.let { summary ->
                if (summary.architecture != "unknown") {
                    dir.putCachedSummary(
                        src,
                        CachedSourceSummary(
                            summary.architecture,
                            summary.bits,
                            summary.endian,
                            summary.hasDebugInfo,
                            summary.stripped
                        )
                    )
                    return@getOrPut summary
                }
            }
        }

        // Fallback: read full file and parse with LIEF
        runCatching {
            lief.parse(dir.readSource(src)).let { elf ->
                SourceSummary(
                    elf.architecture,
                    elf.bits,
                    elf.endian,
                    elf.sections.any {
                        it.name.startsWith(".debug")
                    },
                    elf.symbols.isEmpty()
                ).also {
                    dir.putCachedSummary(
                        src,
                        CachedSourceSummary(
                            it.architecture,
                            it.bits,
                            it.endian,
                            it.hasDebugInfo,
                            it.stripped
                        )
                    )
                }
            }
        }.getOrElse { SourceSummary("unknown", 0, "little", false, true) }
    }
}

internal fun EngineRuntime.sourceKey(src: SoSource): String = "${src.path}|${src.size}|${src.modified}"
