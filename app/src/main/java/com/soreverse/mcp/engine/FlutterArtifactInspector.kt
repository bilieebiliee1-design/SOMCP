package com.soreverse.mcp.engine

import com.soreverse.mcp.core.MemoryGuard
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import org.json.JSONArray
import org.json.JSONObject

/**
 * Flutter artifact census and fingerprinting.
 *
 * Memory shape matters here more than anything else in the pipeline. A Flutter
 * APK is routinely 100–500 MiB and `libapp.so` alone can be 100 MiB+, while the
 * Dart snapshot inside it can only be deserialised as one contiguous buffer. The
 * host process therefore must never materialise either of them:
 *
 *  - APK listing goes through [ZipFile], which only reads the central directory.
 *  - Extraction streams one entry at a time to a file and hashes it on the way
 *    through, so peak heap is one 64 KiB buffer per entry.
 *  - ELF parsing runs over a [ByteView], which for a file is a read-only
 *    `mmap`. Those pages are file-backed, so the kernel can reclaim them under
 *    pressure instead of killing the process over anonymous dirty pages.
 *
 * The old implementation called `File.readBytes()` on the whole APK, then
 * `slice()`d every ELF section into fresh arrays, then decoded `.rodata` into a
 * `String` to run two regexes over it. On a 200 MiB APK that is roughly 600 MiB
 * of transient heap for a result that is a few kilobytes of JSON.
 */
internal object FlutterArtifactInspector {
    private const val MAX_APK_BYTES = 512L * 1024L * 1024L
    private const val MAX_SO_BYTES = 256L * 1024L * 1024L
    private const val MAX_ZIP_ENTRIES = 100_000
    private const val COPY_BUFFER_BYTES = 64 * 1024
    private const val SNAPSHOT_HASH_OFFSET = 20L
    private const val SNAPSHOT_HASH_BYTES = 32
    private const val SNAPSHOT_FLAG_BYTES = 288
    private val LIBRARY_ENTRY = Regex("^lib/[^/]+/(libapp|libflutter)\\.so$")

    // ---------------------------------------------------------------- inventory

    /** Inventories an APK on disk without reading it into the heap. */
    fun inspectApk(file: File, requestedAbi: String = "auto"): JSONObject {
        require(file.length() <= MAX_APK_BYTES) { "INPUT_LIMIT_EXCEEDED: APK exceeds 512 MiB" }
        ZipFile(file).use { zip ->
            return inspect(ZipFileSource(zip), file.path, requestedAbi)
        }
    }

    fun inspectApk(bytes: ByteArray, path: String, requestedAbi: String = "auto"): JSONObject {
        require(bytes.size.toLong() <= MAX_APK_BYTES) { "INPUT_LIMIT_EXCEEDED: APK exceeds 512 MiB" }
        return inspect(ByteArraySource(bytes), path, requestedAbi)
    }

    // ---------------------------------------------------------------- extraction

    /** Extracts the selected ABI pair into [target], streaming and hashing. */
    fun extractLibrariesTo(apk: File, target: File, requestedAbi: String = "auto"): FlutterLibraryFiles {
        ZipFile(apk).use { zip ->
            val source = ZipFileSource(zip)
            val selected = selectLibraries(inspect(source, apk.path, requestedAbi), apk.path)
            target.mkdirs()
            val app = File(target, "libapp.so")
            val flutter = File(target, "libflutter.so")
            val appDigest = writeEntry(source, selected.libappEntry, app)
            val flutterDigest = writeEntry(source, selected.libflutterEntry, flutter)
            return FlutterLibraryFiles(
                displayName = apk.name,
                abi = selected.abi,
                libapp = app,
                libflutter = flutter,
                libappEntry = selected.libappEntry,
                libflutterEntry = selected.libflutterEntry,
                libappSize = appDigest.size,
                libflutterSize = flutterDigest.size,
                libappSha256 = appDigest.sha256,
                libflutterSha256 = flutterDigest.sha256
            )
        }
    }

    /** Kept for in-memory callers (work-directory reads, `apk_analyze`). */
    fun extractLibraries(bytes: ByteArray, path: String, requestedAbi: String = "auto"): FlutterLibraries {
        val source = ByteArraySource(bytes)
        val selected = selectLibraries(inspect(source, path, requestedAbi), path)
        val app = readEntryBytes(source, selected.libappEntry)
        val flutter = readEntryBytes(source, selected.libflutterEntry)
        return FlutterLibraries(
            path.substringAfterLast('/').substringAfterLast('\\'),
            selected.abi,
            app,
            flutter,
            selected.libappEntry,
            selected.libflutterEntry
        )
    }

    /** Wraps an already-extracted pair; digests are streamed, never buffered. */
    fun libraryFiles(app: File, flutter: File, displayName: String, abi: String): FlutterLibraryFiles = FlutterLibraryFiles(
        displayName = displayName,
        abi = abi,
        libapp = app,
        libflutter = flutter,
        libappEntry = app.name,
        libflutterEntry = flutter.name,
        libappSize = app.length(),
        libflutterSize = flutter.length(),
        libappSha256 = digestOf(app),
        libflutterSha256 = digestOf(flutter)
    )

    // ---------------------------------------------------------------- fingerprint

    fun inspectLibraries(files: FlutterLibraryFiles): JSONObject = inspectLibraries(
        LibraryInput(openView(files.libapp, "libapp.so"), files.libappEntry, files.libappSize, files.libappSha256),
        LibraryInput(openView(files.libflutter, "libflutter.so"), files.libflutterEntry, files.libflutterSize, files.libflutterSha256),
        files.displayName,
        files.abi
    )

    fun inspectLibraries(libraries: FlutterLibraries): JSONObject {
        require(libraries.libapp.size.toLong() <= MAX_SO_BYTES) {
            "INPUT_LIMIT_EXCEEDED: libapp.so exceeds 256 MiB"
        }
        require(libraries.libflutter.size.toLong() <= MAX_SO_BYTES) {
            "INPUT_LIMIT_EXCEEDED: libflutter.so exceeds 256 MiB"
        }
        return inspectLibraries(
            LibraryInput(ByteViews.of(libraries.libapp), libraries.libappEntry, libraries.libapp.size.toLong(), sha256(libraries.libapp)),
            LibraryInput(ByteViews.of(libraries.libflutter), libraries.libflutterEntry, libraries.libflutter.size.toLong(), sha256(libraries.libflutter)),
            libraries.displayName,
            libraries.abi
        )
    }

    private fun inspectLibraries(app: LibraryInput, flutter: LibraryInput, displayName: String, abi: String): JSONObject {
        val appElf = parseElf(app.view, "libapp.so")
        val flutterElf = parseElf(flutter.view, "libflutter.so")
        val snapshot = snapshotEvidence(app.view, appElf.dynamicSymbols)
        val engine = engineEvidence(flutter.view, flutterElf)
        val fingerprint = FlutterFingerprint(
            dartVersion = engine.dartVersion,
            snapshotHash = snapshot.hash,
            flags = snapshot.flags,
            engineIds = engine.engineIds,
            architecture = if (appElf.machine == 183) {
                "arm64"
            } else if (appElf.machine == 62) {
                "x64"
            } else {
                null
            },
            os = if (appElf.machine == 183 || appElf.machine == 62) "android" else null,
            compressedPointers = snapshot.flags.any { it == "compressed-pointers" },
            confidence = listOf(
                snapshot.hash != null,
                engine.engineIds.isNotEmpty(),
                appElf.machine == 183
            ).count { it } / 3.0,
            evidence = snapshot.evidence + engine.evidence
        )
        return JSONObject()
            .put("displayName", displayName)
            .put("abi", abi)
            .put("libapp", fileJson(app.entry, app.size, app.sha256))
            .put("libflutter", fileJson(flutter.entry, flutter.size, flutter.sha256))
            .put("flutter", fingerprint.toJson())
            .put("libappElf", appElf.toJson())
            .put("libflutterElf", flutterElf.toJson())
    }

    // ---------------------------------------------------------------- apk sources

    private interface ApkSource {
        /** Central-directory listing. Cheap: no entry payload is decompressed. */
        fun list(): List<EntryInfo>

        /** Streams one entry's decompressed bytes into [sink]; returns the size. */
        fun copyEntry(name: String, sink: (ByteArray, Int) -> Unit): Long
    }

    private data class EntryInfo(val name: String, val directory: Boolean, val size: Long)

    private class ZipFileSource(private val zip: ZipFile) : ApkSource {
        override fun list(): List<EntryInfo> {
            val entries = mutableListOf<EntryInfo>()
            val iterator = zip.entries()
            while (iterator.hasMoreElements()) {
                require(entries.size < MAX_ZIP_ENTRIES) { "INPUT_LIMIT_EXCEEDED: APK contains too many entries" }
                val entry = iterator.nextElement()
                entries += EntryInfo(entry.name, entry.isDirectory, entry.size)
            }
            return entries
        }

        override fun copyEntry(name: String, sink: (ByteArray, Int) -> Unit): Long {
            val entry = zip.getEntry(name) ?: throw IllegalArgumentException("FLUTTER_LIBS_NOT_FOUND: APK entry $name is missing")
            return zip.getInputStream(entry).use { streamEntry(it, name, sink) }
        }
    }

    private class ByteArraySource(private val bytes: ByteArray) : ApkSource {
        override fun list(): List<EntryInfo> {
            val entries = mutableListOf<EntryInfo>()
            ZipInputStream(bytes.inputStream()).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    require(entries.size < MAX_ZIP_ENTRIES) { "INPUT_LIMIT_EXCEEDED: APK contains too many entries" }
                    entries += EntryInfo(entry.name, entry.isDirectory, entry.size)
                    zip.closeEntry()
                }
            }
            return entries
        }

        override fun copyEntry(name: String, sink: (ByteArray, Int) -> Unit): Long {
            ZipInputStream(bytes.inputStream()).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (!entry.isDirectory && entry.name == name) return streamEntry(zip, name, sink)
                    zip.closeEntry()
                }
            }
            throw IllegalArgumentException("FLUTTER_LIBS_NOT_FOUND: APK entry $name is missing")
        }
    }

    private fun inspect(source: ApkSource, path: String, requestedAbi: String): JSONObject {
        val candidates = linkedMapOf<String, MutableMap<String, Any>>()
        val assets = JSONArray()
        val entries = source.list()
        for (entry in entries) {
            val name = entry.name
            if (name.startsWith("assets/flutter_assets/")) assets.put(name)
            if (entry.directory || !LIBRARY_ENTRY.matches(name)) continue
            val abi = name.split('/')[1]
            val item = candidates.getOrPut(abi) { linkedMapOf() }
            val isApp = name.endsWith("libapp.so")
            item[if (isApp) "libappEntry" else "libflutterEntry"] = name
            item[if (isApp) "libappSize" else "libflutterSize"] = entry.size
        }
        val selected = selectAbi(candidates, requestedAbi)
        val result = JSONObject()
            .put("path", path)
            .put(
                "flutter",
                JSONObject()
                    .put("detected", selected != null)
                    .put("mode", if (selected != null) "aot" else "unknown")
                    .put("requestedAbi", requestedAbi)
                    .put("supportedAbis", JSONArray(candidates.keys))
                    .put("assets", assets)
                    .put("candidates", candidatesJson(candidates))
            )
            .put("entryCount", entries.size)
            .put(
                "limitations",
                JSONArray(
                    listOf(
                        "Flutter AOT semantic recovery requires a matching Blutter Dart VM runner",
                        "This inspector does not execute or decompile target code"
                    )
                )
            )
        if (selected == null) return result
        return result.put("selected", JSONObject(selected.value).put("abi", selected.key))
    }

    private data class AbiCandidate(val key: String, val value: Map<String, Any>)

    private data class SelectedLibraries(val abi: String, val libappEntry: String, val libflutterEntry: String)

    private fun selectLibraries(inventory: JSONObject, path: String): SelectedLibraries {
        val selected = inventory.optJSONObject("selected")
            ?: throw IllegalArgumentException(
                "FLUTTER_LIBS_NOT_FOUND: APK does not contain a complete libapp.so/libflutter.so pair ($path)"
            )
        return SelectedLibraries(
            selected.getString("abi"),
            selected.getString("libappEntry"),
            selected.getString("libflutterEntry")
        )
    }

    private fun selectAbi(candidates: Map<String, MutableMap<String, Any>>, requested: String): AbiCandidate? {
        val order = if (requested == "auto") {
            listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
        } else {
            listOf(requested)
        }
        return order.asSequence().mapNotNull { abi ->
            candidates[abi]?.takeIf {
                it.containsKey("libappEntry") && it.containsKey("libflutterEntry")
            }?.let { AbiCandidate(abi, it) }
        }.firstOrNull()
    }

    private fun candidatesJson(candidates: Map<String, MutableMap<String, Any>>): JSONArray = JSONArray().also { out ->
        candidates.forEach { (abi, value) ->
            out.put(
                JSONObject(value).put("abi", abi).put(
                    "complete",
                    value.containsKey("libappEntry") && value.containsKey("libflutterEntry")
                )
            )
        }
    }

    // ---------------------------------------------------------------- entry io

    private fun streamEntry(input: InputStream, name: String, sink: (ByteArray, Int) -> Unit): Long {
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            require(total <= MAX_SO_BYTES) { "INPUT_LIMIT_EXCEEDED: $name exceeds 256 MiB" }
            sink(buffer, count)
        }
        return total
    }

    private data class EntryDigest(val size: Long, val sha256: String)

    private fun writeEntry(source: ApkSource, entry: String, target: File): EntryDigest {
        val digest = MessageDigest.getInstance("SHA-256")
        return try {
            val size = BufferedOutputStream(FileOutputStream(target), COPY_BUFFER_BYTES).use { output ->
                source.copyEntry(entry) { chunk, count ->
                    digest.update(chunk, 0, count)
                    output.write(chunk, 0, count)
                }
            }
            EntryDigest(size, digest.digest().toHex())
        } catch (error: Exception) {
            target.delete()
            throw error
        }
    }

    private fun readEntryBytes(source: ApkSource, entry: String): ByteArray {
        val output = ByteArrayOutputStream()
        source.copyEntry(entry) { chunk, count -> output.write(chunk, 0, count) }
        return output.toByteArray()
    }

    // ---------------------------------------------------------------- elf

    private class LibraryInput(val view: ByteView, val entry: String, val size: Long, val sha256: String)

    private data class ElfInfo(val machine: Int, val dynamicSymbols: List<Symbol>, val rodataOffset: Long, val rodataSize: Long) {
        fun toJson(): JSONObject = JSONObject()
            .put("machine", machine)
            .put(
                "architecture",
                when (machine) {
                    183 -> "AArch64"
                    62 -> "x86_64"
                    else -> "unknown"
                }
            )
            .put("dynamicSymbolCount", dynamicSymbols.size)
            .put("hasRodata", rodataSize > 0)
    }

    private data class Symbol(val name: String, val value: Long, val size: Long, val fileOffset: Long = value)
    private data class SnapshotEvidence(val hash: String?, val flags: List<String>, val evidence: List<String>)
    private data class EngineEvidence(val engineIds: List<String>, val dartVersion: String?, val evidence: List<String>)

    private fun openView(file: File, label: String): ByteView {
        require(file.length() <= MAX_SO_BYTES) { "INPUT_LIMIT_EXCEEDED: $label exceeds 256 MiB" }
        return runCatching { ByteViews.map(file) }.getOrElse { error ->
            if (error is IllegalArgumentException) throw error
            // Filesystems without usable mmap (some FUSE / SAF mounts) fall back
            // to a heap read, but only when the heap can actually hold it.
            MemoryGuard.ensureAnalysisMemory(file.length(), "Reading $label")
            ByteViews.of(file.readBytes())
        }
    }

    private fun parseElf(view: ByteView, label: String): ElfInfo {
        require(
            view.size >= 0x40 &&
                view.u8(0) == 0x7f &&
                view.u8(1) == 'E'.code &&
                view.u8(2) == 'L'.code &&
                view.u8(3) == 'F'.code
        ) {
            "APK_INVALID: $label is not an ELF file"
        }
        val klass = view.u8(4)
        require(view.u8(5) == 1) { "UNSUPPORTED_ELF: $label is not little endian" }
        val machine = view.u16(18)
        val sectionOffset = if (klass == 2) view.u64(0x28) else view.u32(0x20)
        val sectionCount = if (klass == 2) view.u16(0x3c) else view.u16(0x30)
        val sectionSize = if (klass == 2) view.u16(0x3a) else view.u16(0x2e)
        val stringIndex = if (klass == 2) view.u16(0x3e) else view.u16(0x32)
        val sections = readSections(view, sectionOffset, sectionSize, sectionCount, klass)
        val names = sectionNames(view, sections, stringIndex)
        val loads = readLoadSegments(view, klass)
        val symbols = mutableListOf<Symbol>()
        var rodataOffset = 0L
        var rodataSize = 0L
        sections.forEachIndexed { index, section ->
            if (names.getOrNull(index).orEmpty() == ".rodata") {
                rodataOffset = section.offset
                rodataSize = section.size
            }
            if (section.type == 11L) symbols += parseSymbols(view, section, sections, klass, loads)
        }
        return ElfInfo(machine, symbols, rodataOffset, rodataSize)
    }

    private data class Section(val nameOffset: Long, val type: Long, val offset: Long, val size: Long, val link: Long, val entsize: Long)
    private data class LoadSegment(val virtualAddress: Long, val fileOffset: Long, val fileSize: Long)

    private fun readSections(view: ByteView, offset: Long, entrySize: Int, count: Int, klass: Int): List<Section> {
        if (entrySize <= 0) return emptyList()
        return (0 until count).mapNotNull { index ->
            val base = offset + index.toLong() * entrySize
            if (base < 0 || base + entrySize > view.size) return@mapNotNull null
            if (klass == 2) {
                Section(
                    view.u32(base),
                    view.u32(base + 4),
                    view.u64(base + 24),
                    view.u64(base + 32),
                    view.u32(base + 40),
                    view.u64(base + 56)
                )
            } else {
                Section(
                    view.u32(base),
                    view.u32(base + 4),
                    view.u32(base + 16),
                    view.u32(base + 20),
                    view.u32(base + 24),
                    view.u32(base + 36)
                )
            }
        }
    }

    private fun sectionNames(view: ByteView, sections: List<Section>, stringIndex: Int): List<String> {
        val strings = sections.getOrNull(stringIndex) ?: return sections.map { "" }
        return sections.map { FlutterByteScan.cString(view, strings.offset + it.nameOffset) }
    }

    private fun readLoadSegments(view: ByteView, klass: Int): List<LoadSegment> {
        val offset = if (klass == 2) view.u64(0x20) else view.u32(0x1c)
        val entrySize = if (klass == 2) view.u16(0x36) else view.u16(0x2a)
        val count = if (klass == 2) view.u16(0x38) else view.u16(0x2c)
        if (entrySize <= 0) return emptyList()
        return (0 until count).mapNotNull { index ->
            val base = offset + index.toLong() * entrySize
            if (base < 0 || base + entrySize > view.size) return@mapNotNull null
            if (view.u32(base) != 1L) return@mapNotNull null
            if (klass == 2) {
                LoadSegment(view.u64(base + 16), view.u64(base + 8), view.u64(base + 32))
            } else {
                LoadSegment(view.u32(base + 8), view.u32(base + 4), view.u32(base + 16))
            }
        }
    }

    private fun parseSymbols(view: ByteView, section: Section, sections: List<Section>, klass: Int, loads: List<LoadSegment>): List<Symbol> {
        if (section.entsize <= 0) return emptyList()
        val strings = sections.getOrNull(section.link.toInt()) ?: return emptyList()
        val count = (section.size / section.entsize).toInt().coerceAtMost(200_000)
        return (0 until count).mapNotNull { index ->
            val base = section.offset + index.toLong() * section.entsize
            if (klass == 2 && base + 24 <= view.size) {
                val value = view.u64(base + 8)
                Symbol(
                    FlutterByteScan.cString(view, strings.offset + view.u32(base)),
                    value,
                    view.u64(base + 16),
                    virtualToFileOffset(value, loads)
                )
            } else if (klass == 1 && base + 16 <= view.size) {
                val value = view.u32(base + 4)
                Symbol(
                    FlutterByteScan.cString(view, strings.offset + view.u32(base)),
                    value,
                    view.u32(base + 8),
                    virtualToFileOffset(value, loads)
                )
            } else {
                null
            }
        }
    }

    private fun virtualToFileOffset(value: Long, loads: List<LoadSegment>): Long = loads.firstOrNull {
        value >= it.virtualAddress && value - it.virtualAddress < it.fileSize
    }?.let {
        it.fileOffset + value - it.virtualAddress
    } ?: value

    private fun snapshotEvidence(view: ByteView, symbols: List<Symbol>): SnapshotEvidence {
        val symbol = symbols.firstOrNull { it.name == "_kDartVmSnapshotData" }
            ?: return SnapshotEvidence(
                null,
                emptyList(),
                listOf("libapp.so does not expose _kDartVmSnapshotData in its dynamic symbol table")
            )
        // Magic offsets of the snapshot header as Blutter's extract_dart_info reads
        // them: 20 bytes of prologue, then the 32-byte version hash, then flags.
        val start = symbol.fileOffset + SNAPSHOT_HASH_OFFSET
        if (start < 0 || start + SNAPSHOT_HASH_BYTES > view.size) {
            return SnapshotEvidence(
                null,
                emptyList(),
                listOf("_kDartVmSnapshotData is outside the file-backed range")
            )
        }
        val hash = view.ascii(start, SNAPSHOT_HASH_BYTES).takeIf { it.matches(Regex("[ -~]{32}")) }
        val flagsStart = start + SNAPSHOT_HASH_BYTES
        val flagsLength = (minOf(view.size, start + SNAPSHOT_FLAG_BYTES) - flagsStart).toInt()
        val flags = view.ascii(flagsStart, flagsLength).substringBefore('\u0000').trim().split(Regex("\\s+")).filter {
            it.isNotBlank()
        }
        return SnapshotEvidence(
            hash,
            flags,
            listOf(
                "_kDartVmSnapshotData",
                "snapshot hash and flags read using Blutter extract_dart_info compatibility rules"
            )
        )
    }

    private fun engineEvidence(view: ByteView, elf: ElfInfo): EngineEvidence {
        val ids = if (elf.rodataSize > 0) {
            FlutterByteScan.engineIds(view, elf.rodataOffset, elf.rodataSize)
        } else {
            emptyList()
        }
        val version = if (elf.rodataSize > 0) {
            FlutterByteScan.dartVersion(view, elf.rodataOffset, elf.rodataSize)
        } else {
            null
        }
        return EngineEvidence(
            ids,
            version,
            listOf(
                "libflutter.so .rodata",
                "engine IDs and Dart channel/version searched using Blutter compatibility rules"
            )
        )
    }

    // ---------------------------------------------------------------- helpers

    private fun fileJson(name: String, size: Long, sha256: String): JSONObject = JSONObject().put("name", name).put("size", size).put("sha256", sha256)

    private fun digestOf(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().toHex()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
}
