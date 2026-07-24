package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

internal object FlutterArtifactInspector {
    private const val MAX_APK_BYTES = 512L * 1024L * 1024L
    private const val MAX_SO_BYTES = 256L * 1024L * 1024L
    private const val MAX_ZIP_ENTRIES = 100_000

    fun inspectApk(bytes: ByteArray, path: String, requestedAbi: String = "auto"): JSONObject {
        require(bytes.size.toLong() <= MAX_APK_BYTES) { "INPUT_LIMIT_EXCEEDED: APK exceeds 512 MiB" }
        val candidates = linkedMapOf<String, MutableMap<String, Any>>()
        val assets = JSONArray()
        var entries = 0
        ZipInputStream(bytes.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries++
                require(entries <= MAX_ZIP_ENTRIES) { "INPUT_LIMIT_EXCEEDED: APK contains too many entries" }
                val name = entry.name
                if (name.startsWith("assets/flutter_assets/")) assets.put(name)
                if (!entry.isDirectory && name.matches(Regex("^lib/[^/]+/(libapp|libflutter)\\.so$"))) {
                    val parts = name.split('/')
                    val abi = parts[1]
                    val item = candidates.getOrPut(abi) { linkedMapOf() }
                    item[if (name.endsWith("libapp.so")) "libappEntry" else "libflutterEntry"] = name
                    item[if (name.endsWith("libapp.so")) "libappSize" else "libflutterSize"] = entry.size
                }
                zip.closeEntry()
            }
        }
        val selected = selectAbi(candidates, requestedAbi)
        val result = JSONObject()
            .put("path", path)
            .put("flutter", JSONObject().put("detected", selected != null).put("mode", if (selected != null) "aot" else "unknown").put("requestedAbi", requestedAbi).put("supportedAbis", JSONArray(candidates.keys)).put("assets", assets).put("candidates", candidatesJson(candidates)))
            .put("entryCount", entries)
            .put("limitations", JSONArray(listOf("Flutter AOT semantic recovery requires a matching Blutter Dart VM runner", "This inspector does not execute or decompile target code")))
        if (selected == null) return result
        return result.put("selected", JSONObject(selected.value).put("abi", selected.key))
    }

    fun extractLibraries(bytes: ByteArray, path: String, requestedAbi: String = "auto"): FlutterLibraries {
        val inventory = inspectApk(bytes, path, requestedAbi)
        val selected = inventory.optJSONObject("selected") ?: throw IllegalArgumentException("FLUTTER_LIBS_NOT_FOUND: APK does not contain a complete libapp.so/libflutter.so pair")
        val abi = selected.getString("abi")
        val appEntry = selected.getString("libappEntry")
        val flutterEntry = selected.getString("libflutterEntry")
        var app: ByteArray? = null
        var flutter: ByteArray? = null
        ZipInputStream(bytes.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                when (entry.name) {
                    appEntry -> app = readLimited(zip, appEntry)
                    flutterEntry -> flutter = readLimited(zip, flutterEntry)
                }
                zip.closeEntry()
            }
        }
        return FlutterLibraries(path.substringAfterLast('/').substringAfterLast('\\'), abi, requireNotNull(app), requireNotNull(flutter), appEntry, flutterEntry)
    }

    fun inspectLibraries(libraries: FlutterLibraries): JSONObject {
        require(libraries.libapp.size.toLong() <= MAX_SO_BYTES) { "INPUT_LIMIT_EXCEEDED: libapp.so exceeds 256 MiB" }
        require(libraries.libflutter.size.toLong() <= MAX_SO_BYTES) { "INPUT_LIMIT_EXCEEDED: libflutter.so exceeds 256 MiB" }
        val app = parseElf(libraries.libapp, "libapp.so")
        val flutter = parseElf(libraries.libflutter, "libflutter.so")
        val snapshot = snapshotEvidence(libraries.libapp, app.dynamicSymbols)
        val engine = engineEvidence(libraries.libflutter, flutter.rodata)
        val fingerprint = FlutterFingerprint(
            dartVersion = engine.dartVersion,
            snapshotHash = snapshot.hash,
            flags = snapshot.flags,
            engineIds = engine.engineIds,
            architecture = if (app.machine == 183) "arm64" else if (app.machine == 62) "x64" else null,
            os = if (app.machine == 183 || app.machine == 62) "android" else null,
            compressedPointers = snapshot.flags.any { it == "compressed-pointers" },
            confidence = listOf(snapshot.hash != null, engine.engineIds.isNotEmpty(), app.machine == 183).count { it } / 3.0,
            evidence = snapshot.evidence + engine.evidence,
        )
        return JSONObject()
            .put("displayName", libraries.displayName)
            .put("abi", libraries.abi)
            .put("libapp", fileJson(libraries.libappEntry, libraries.libapp))
            .put("libflutter", fileJson(libraries.libflutterEntry, libraries.libflutter))
            .put("flutter", fingerprint.toJson())
            .put("libappElf", app.toJson())
            .put("libflutterElf", flutter.toJson())
    }

    private data class AbiCandidate(val key: String, val value: Map<String, Any>)

    private fun selectAbi(candidates: Map<String, MutableMap<String, Any>>, requested: String): AbiCandidate? {
        val order = if (requested == "auto") listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86") else listOf(requested)
        return order.asSequence().mapNotNull { abi -> candidates[abi]?.takeIf { it.containsKey("libappEntry") && it.containsKey("libflutterEntry") }?.let { AbiCandidate(abi, it) } }.firstOrNull()
    }

    private fun candidatesJson(candidates: Map<String, MutableMap<String, Any>>): JSONArray = JSONArray().also { out -> candidates.forEach { (abi, value) -> out.put(JSONObject(value).put("abi", abi).put("complete", value.containsKey("libappEntry") && value.containsKey("libflutterEntry"))) } }

    private data class ElfInfo(val machine: Int, val dynamicSymbols: List<Symbol>, val rodata: ByteArray) {
        fun toJson(): JSONObject = JSONObject().put("machine", machine).put("architecture", if (machine == 183) "AArch64" else if (machine == 62) "x86_64" else "unknown").put("dynamicSymbolCount", dynamicSymbols.size).put("hasRodata", rodata.isNotEmpty())
    }

    private data class Symbol(val name: String, val value: Long, val size: Long, val fileOffset: Long = value)
    private data class SnapshotEvidence(val hash: String?, val flags: List<String>, val evidence: List<String>)
    private data class EngineEvidence(val engineIds: List<String>, val dartVersion: String?, val evidence: List<String>)

    private fun parseElf(bytes: ByteArray, label: String): ElfInfo {
        require(bytes.size >= 0x40 && bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) { "APK_INVALID: $label is not an ELF file" }
        val klass = bytes[4].toInt() and 0xff
        val endian = bytes[5].toInt() and 0xff
        require(endian == 1) { "UNSUPPORTED_ELF: $label is not little endian" }
        val order = ByteOrder.LITTLE_ENDIAN
        val machine = u16(bytes, 18, order)
        val sectionOffset = if (klass == 2) u64(bytes, 0x28, order) else u32(bytes, 0x20, order).toLong()
        val sectionCount = if (klass == 2) u16(bytes, 0x3c, order) else u16(bytes, 0x30, order)
        val sectionSize = if (klass == 2) u16(bytes, 0x3a, order) else u16(bytes, 0x2e, order)
        val stringIndex = if (klass == 2) u16(bytes, 0x3e, order) else u16(bytes, 0x32, order)
        val sections = readSections(bytes, sectionOffset, sectionSize, sectionCount, klass, order)
        val names = sectionNames(bytes, sections, stringIndex)
        val loads = readLoadSegments(bytes, klass, order)
        val symbols = mutableListOf<Symbol>()
        var rodata = ByteArray(0)
        sections.forEachIndexed { index, section ->
            val name = names.getOrNull(index).orEmpty()
            val data = slice(bytes, section.offset, section.size)
            if (name == ".rodata") rodata = data
            if (section.type == 11L) symbols += parseSymbols(bytes, section, sections, klass, order, loads)
        }
        return ElfInfo(machine, symbols, rodata)
    }

    private data class Section(val nameOffset: Long, val type: Long, val offset: Long, val size: Long, val link: Long, val entsize: Long)
    private data class LoadSegment(val virtualAddress: Long, val fileOffset: Long, val fileSize: Long)

    private fun readSections(bytes: ByteArray, offset: Long, entrySize: Int, count: Int, klass: Int, order: ByteOrder): List<Section> = (0 until count).mapNotNull { index ->
        val base = offset + index.toLong() * entrySize
        if (base < 0 || base + entrySize > bytes.size) return@mapNotNull null
        if (klass == 2) Section(u32(bytes, base, order), u32(bytes, base + 4, order), u64(bytes, base + 24, order), u64(bytes, base + 32, order), u32(bytes, base + 40, order), u64(bytes, base + 56, order))
        else Section(u32(bytes, base, order), u32(bytes, base + 4, order), u32(bytes, base + 16, order).toLong(), u32(bytes, base + 20, order).toLong(), u32(bytes, base + 24, order), u32(bytes, base + 36, order).toLong())
    }

    private fun sectionNames(bytes: ByteArray, sections: List<Section>, stringIndex: Int): List<String> {
        val strings = sections.getOrNull(stringIndex) ?: return sections.map { "" }
        val table = slice(bytes, strings.offset, strings.size)
        return sections.map { readCString(table, it.nameOffset.toInt()) }
    }

    private fun readLoadSegments(bytes: ByteArray, klass: Int, order: ByteOrder): List<LoadSegment> {
        val offset = if (klass == 2) u64(bytes, 0x20L, order) else u32(bytes, 0x1cL, order)
        val entrySize = if (klass == 2) u16(bytes, 0x36L, order) else u16(bytes, 0x2aL, order)
        val count = if (klass == 2) u16(bytes, 0x38L, order) else u16(bytes, 0x2cL, order)
        return (0 until count).mapNotNull { index ->
            val base = offset + index.toLong() * entrySize
            if (base < 0 || base + entrySize > bytes.size) return@mapNotNull null
            val type = u32(bytes, base, order)
            if (type != 1L) return@mapNotNull null
            if (klass == 2) LoadSegment(u64(bytes, base + 16, order), u64(bytes, base + 8, order), u64(bytes, base + 32, order))
            else LoadSegment(u32(bytes, base + 8, order), u32(bytes, base + 4, order), u32(bytes, base + 16, order))
        }
    }

    private fun parseSymbols(bytes: ByteArray, section: Section, sections: List<Section>, klass: Int, order: ByteOrder, loads: List<LoadSegment>): List<Symbol> {
        val strings = sections.getOrNull(section.link.toInt()) ?: return emptyList()
        val table = slice(bytes, strings.offset, strings.size)
        val count = if (section.entsize > 0) (section.size / section.entsize).toInt().coerceAtMost(200_000) else 0
        return (0 until count).mapNotNull { index ->
            val base = section.offset + index.toLong() * section.entsize
            if (klass == 2 && base + 24 <= bytes.size) {
                val value = u64(bytes, base + 8, order)
                Symbol(readCString(table, u32(bytes, base, order).toInt()), value, u64(bytes, base + 16, order), virtualToFileOffset(value, loads))
            } else if (klass == 1 && base + 16 <= bytes.size) {
                val value = u32(bytes, base + 4, order)
                Symbol(readCString(table, u32(bytes, base, order).toInt()), value, u32(bytes, base + 8, order), virtualToFileOffset(value, loads))
            }
            else null
        }
    }

    private fun virtualToFileOffset(value: Long, loads: List<LoadSegment>): Long = loads.firstOrNull { value >= it.virtualAddress && value - it.virtualAddress < it.fileSize }?.let { it.fileOffset + value - it.virtualAddress } ?: value

    private fun snapshotEvidence(bytes: ByteArray, symbols: List<Symbol>): SnapshotEvidence {
        val symbol = symbols.firstOrNull { it.name == "_kDartVmSnapshotData" } ?: return SnapshotEvidence(null, emptyList(), listOf("libapp.so does not expose _kDartVmSnapshotData in its dynamic symbol table"))
        val start = symbol.fileOffset.toInt() + 20
        if (start < 0 || start + 32 > bytes.size) return SnapshotEvidence(null, emptyList(), listOf("_kDartVmSnapshotData is outside the file-backed range"))
        val hash = bytes.copyOfRange(start, start + 32).toString(Charsets.US_ASCII).takeIf { it.matches(Regex("[ -~]{32}")) }
        val flagsBytes = bytes.copyOfRange(start + 32, minOf(bytes.size, start + 288))
        val flags = flagsBytes.toString(Charsets.US_ASCII).substringBefore('\u0000').trim().split(Regex("\\s+")).filter { it.isNotBlank() }
        return SnapshotEvidence(hash, flags, listOf("_kDartVmSnapshotData", "snapshot hash and flags read using Blutter extract_dart_info compatibility rules"))
    }

    private fun engineEvidence(bytes: ByteArray, rodata: ByteArray): EngineEvidence {
        val text = rodata.toString(Charsets.US_ASCII)
        val ids = Regex("(?<![a-f0-9])([a-f0-9]{40})(?![a-f0-9])").findAll(text).map { it.groupValues[1] }.distinct().toList()
        val version = Regex("([\\d\\w.-]+) \\((stable|beta|dev)\\)").find(text)?.groupValues?.get(1)
        return EngineEvidence(ids, version, listOf("libflutter.so .rodata", "engine IDs and Dart channel/version searched using Blutter compatibility rules"))
    }

    private fun fileJson(name: String, bytes: ByteArray): JSONObject = JSONObject().put("name", name).put("size", bytes.size).put("sha256", sha256(bytes))
    private fun readLimited(zip: ZipInputStream, name: String): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val count = zip.read(buffer)
            if (count < 0) break
            total += count
            require(total <= MAX_SO_BYTES) { "INPUT_LIMIT_EXCEEDED: $name exceeds 256 MiB" }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }
    private fun slice(bytes: ByteArray, offset: Long, size: Long): ByteArray = if (offset >= 0 && size >= 0 && offset <= bytes.size && size <= bytes.size - offset) bytes.copyOfRange(offset.toInt(), (offset + size).toInt()) else ByteArray(0)
    private fun readCString(bytes: ByteArray, offset: Int): String { if (offset !in bytes.indices) return ""; var end = offset; while (end < bytes.size && bytes[end].toInt() != 0) end++; return bytes.copyOfRange(offset, end).toString(Charsets.UTF_8) }
    private fun u16(bytes: ByteArray, offset: Long, order: ByteOrder): Int = ByteBuffer.wrap(bytes, offset.toInt(), 2).order(order).short.toInt() and 0xffff
    private fun u32(bytes: ByteArray, offset: Long, order: ByteOrder): Long = ByteBuffer.wrap(bytes, offset.toInt(), 4).order(order).int.toLong() and 0xffffffffL
    private fun u16(bytes: ByteArray, offset: Int, order: ByteOrder): Int = u16(bytes, offset.toLong(), order)
    private fun u32(bytes: ByteArray, offset: Int, order: ByteOrder): Long = u32(bytes, offset.toLong(), order)
    private fun u64(bytes: ByteArray, offset: Long, order: ByteOrder): Long = ByteBuffer.wrap(bytes, offset.toInt(), 8).order(order).long
    private fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
