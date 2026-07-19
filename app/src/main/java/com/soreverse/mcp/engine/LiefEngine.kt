package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlin.math.min

/**
 * LIEF-backed ELF parser and section header reconstructor.
 *
 * Replaces the hand-written [ElfParser] with LIEF's production-grade C++ ELF
 * parser, exposed via JNI in librz_native.so (lief_elf.cpp). When LIEF is not
 * available for the current ABI (stub fallback), it transparently delegates
 * to [ElfParser] so the engine still works.
 *
 * Key capabilities:
 *  - Full ELF parsing: sections, symbols, relocations, program headers,
 *    dynamic entries (richer than the old ElfParser).
 *  - [fixSections]: xAnSo-style section header reconstruction for hardened /
 *    stripped SO files. LIEF's parser reconstructs section info from the
 *    .dynamic segment, and the Builder writes a clean ELF with proper
 *    section headers.
 */
class LiefEngine {

    @Volatile
    private var libLoaded: Boolean = false

    @Volatile
    private var loadError: String = ""

    init {
        val result = runCatching { System.loadLibrary("rz_native") }
        libLoaded = result.isSuccess
        if (!libLoaded) {
            loadError = result.exceptionOrNull()?.message ?: "Unknown load error"
        }
    }

    fun available(): Boolean = libLoaded

    fun loadStatus(): String = if (libLoaded) "loaded" else "failed: $loadError"

    fun parse(data: ByteArray): ElfFile {
        if (!available()) return ElfParser(data).parse()
        return runCatching {
            val json = nativeParse(data)
            parseJson(json, data)
        }.getOrElse {
            ElfParser(data).parse()
        }
    }

    fun parseAny(data: ByteArray, format: String = "auto"): JSONObject = JSONObject(nativeParseAny(data, format))

    fun fixSections(data: ByteArray): ByteArray {
        if (!available()) return data
        return runCatching {
            val fixed = nativeFixSections(data)
            if (fixed.isNotEmpty()) fixed else data
        }.getOrElse { data }
    }

    fun patchAddress(data: ByteArray, va: Long, patch: ByteArray): ByteArray {
        if (!available()) return data
        return runCatching {
            val patched = nativePatchAddress(data, va, patch)
            if (patched.isNotEmpty()) patched else data
        }.getOrElse { data }
    }

    fun getSectionContent(data: ByteArray, sectionName: String): ByteArray {
        if (!available()) return ByteArray(0)
        return runCatching { nativeGetSectionContent(data, sectionName) }.getOrDefault(ByteArray(0))
    }

    fun setSectionContent(data: ByteArray, sectionName: String, content: ByteArray): ByteArray {
        if (!available()) return data
        return runCatching {
            val patched = nativeSetSectionContent(data, sectionName, content)
            if (patched.isNotEmpty()) patched else data
        }.getOrElse { data }
    }

    fun addExportedFunction(data: ByteArray, addr: Long, name: String): ByteArray {
        if (!available()) return data
        return runCatching {
            val patched = nativeAddExportedFunction(data, addr, name)
            if (patched.isNotEmpty()) patched else data
        }.getOrElse { data }
    }

    fun removeSymbol(data: ByteArray, name: String): ByteArray {
        if (!available()) return data
        return runCatching {
            val patched = nativeRemoveSymbol(data, name)
            if (patched.isNotEmpty()) patched else data
        }.getOrElse { data }
    }

    private fun parseJson(json: String, data: ByteArray): ElfFile {
        val obj = JSONObject(json)
        if (obj.has("error")) throw RuntimeException(obj.getString("error"))

        val bits = obj.getInt("bits")
        val littleEndian = obj.getBoolean("littleEndian")
        val type = obj.getInt("type")
        val machine = obj.getInt("machine")
        val entry = obj.getLong("entry")

        val sections = parseSections(obj.optJSONArray("sections") ?: JSONArray())
        val symbols = parseSymbols(obj.optJSONArray("symbols") ?: JSONArray())
        val dynSymbols = parseSymbols(obj.optJSONArray("dynSymbols") ?: JSONArray())
        val relocations = parseRelocations(obj.optJSONArray("relocations") ?: JSONArray())
        val programHeaders = parseProgramHeaders(obj.optJSONArray("programHeaders") ?: JSONArray())
        val dynamicEntries = parseDynamicEntries(obj.optJSONArray("dynamicEntries") ?: JSONArray())
        val strings = extractStrings(data, sections)

        return ElfFile(
            data, bits, littleEndian, type, machine, entry,
            sections, symbols, dynSymbols, relocations, strings,
            programHeaders, dynamicEntries,
        )
    }

    private fun parseSections(arr: JSONArray): List<SectionInfo> {
        val out = ArrayList<SectionInfo>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += SectionInfo(
                name = o.optString("name"),
                type = o.optLong("type"),
                flags = o.optLong("flags"),
                addr = o.optLong("addr"),
                offset = o.optLong("offset"),
                size = o.optLong("size"),
                link = o.optInt("link"),
                info = o.optInt("info"),
                addralign = o.optLong("addralign"),
                entsize = o.optLong("entsize"),
            )
        }
        return out
    }

    private fun parseSymbols(arr: JSONArray): List<SymbolInfo> {
        val out = ArrayList<SymbolInfo>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val name = o.optString("name")
            if (name.isEmpty()) continue
            out += SymbolInfo(
                name = name,
                bind = bindStr(o.optInt("bind")),
                type = typeStr(o.optInt("type")),
                visibility = visStr(o.optInt("visibility")),
                sectionIndex = o.optInt("sectionIndex"),
                value = o.optLong("value"),
                size = o.optLong("size"),
                imported = o.optBoolean("imported"),
                exported = o.optBoolean("exported"),
            )
        }
        return out
    }

    private fun parseRelocations(arr: JSONArray): List<RelocInfo> {
        val out = ArrayList<RelocInfo>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += RelocInfo(
                section = o.optString("section"),
                offset = o.optLong("offset"),
                type = o.optLong("type"),
                symbol = o.optString("symbol"),
                addend = o.optLong("addend"),
            )
        }
        return out
    }

    private fun parseProgramHeaders(arr: JSONArray): List<ProgramHeaderInfo> {
        val out = ArrayList<ProgramHeaderInfo>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += ProgramHeaderInfo(
                type = o.optLong("type"),
                flags = o.optLong("flags"),
                offset = o.optLong("offset"),
                vaddr = o.optLong("vaddr"),
                paddr = o.optLong("paddr"),
                filesz = o.optLong("filesz"),
                memsz = o.optLong("memsz"),
                align = o.optLong("align"),
            )
        }
        return out
    }

    private fun parseDynamicEntries(arr: JSONArray): List<DynamicEntryInfo> {
        val out = ArrayList<DynamicEntryInfo>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out += DynamicEntryInfo(
                tag = o.optLong("tag"),
                value = o.optLong("value"),
            )
        }
        return out
    }

    private fun extractStrings(data: ByteArray, sections: List<SectionInfo>): List<StringInfo> {
        val out = mutableListOf<StringInfo>()
        val seen = HashSet<String>()
        for (sec in sections) {
            if (!shouldScanStrings(sec)) continue
            val bytes = sectionBytes(data, sec)
            extractUtf8Strings(bytes, sec.offset, sec.name, out, seen)
            if (shouldScanUtf16Strings(sec)) extractUtf16LeStrings(bytes, sec.offset, sec.name, out, seen)
        }
        extractUtf8Strings(data, 0, "<file>", out, seen)
        return out
    }

    private fun shouldScanStrings(section: SectionInfo): Boolean {
        if (section.size <= 0) return false
        if (section.name in setOf(".rodata", ".strtab", ".dynstr", ".data", ".data.rel.ro", ".init_array", ".fini_array")) return true
        return section.name.contains("str", ignoreCase = true) || section.name.contains("rodata", ignoreCase = true)
    }

    private fun shouldScanUtf16Strings(section: SectionInfo): Boolean {
        if (section.flags and 4L != 0L) return false
        return section.name in setOf(".rodata", ".data", ".data.rel.ro") || section.name.contains("utf16", ignoreCase = true)
    }

    private fun sectionBytes(data: ByteArray, section: SectionInfo): ByteArray {
        if (section.offset < 0 || section.size <= 0) return ByteArray(0)
        val start = section.offset.toInt().coerceIn(0, data.size)
        val end = min(data.size, start + section.size.toInt())
        return data.copyOfRange(start, end)
    }

    private fun extractUtf8Strings(bytes: ByteArray, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<String>) {
        var start = 0
        var i = 0
        while (i <= bytes.size) {
            if (i == bytes.size || bytes[i] == 0.toByte()) {
                emitUtf8StringCandidate(bytes, start, i, base, section, out, seen)
                start = i + 1
            }
            i++
        }
    }

    private fun emitUtf8StringCandidate(bytes: ByteArray, start: Int, end: Int, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<String>) {
        if (end - start < 4) return
        val raw = bytes.copyOfRange(start, end)
        val text = runCatching {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw))
                .toString()
        }.getOrNull() ?: return
        val clean = text.takeWhile { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }.trimEnd()
        if (clean.length < 2) return
        val useful = clean.any { it.isLetterOrDigit() || Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val mostlyText = clean.count { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() } >= clean.length
        val letters = clean.count { it.isLetter() || Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val digits = clean.count { it.isDigit() }
        val hasHan = clean.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val confidence = when {
            hasHan && mostlyText -> 0.95
            letters + digits >= clean.length * 2 / 3 -> 0.9
            useful && mostlyText -> 0.8
            else -> 0.5
        }
        if (useful && mostlyText && confidence >= 0.5 && seen.add("UTF-8:${base + start}:$clean")) {
            out += StringInfo(base + start, clean.take(1024), raw.size, section, "UTF-8", confidence)
        }
    }

    private fun extractUtf16LeStrings(bytes: ByteArray, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<String>) {
        var start = -1
        var i = 0
        while (i + 1 < bytes.size) {
            val zeroTerminated = bytes[i] == 0.toByte() && bytes[i + 1] == 0.toByte()
            if (zeroTerminated) {
                if (start >= 0) emitUtf16LeStringCandidate(bytes, start, i, base, section, out, seen)
                start = -1
                i += 2
                continue
            }
            if (start < 0 && looksLikeUtf16LeCodeUnit(bytes, i)) start = i
            i += 2
        }
    }

    private fun looksLikeUtf16LeCodeUnit(bytes: ByteArray, i: Int): Boolean {
        if (i + 1 >= bytes.size) return false
        val code = (bytes[i].toInt() and 0xff) or ((bytes[i + 1].toInt() and 0xff) shl 8)
        if (code == 0) return false
        val c = code.toChar()
        return c == '\t' || c == '\n' || c == '\r' || !c.isISOControl()
    }

    private fun emitUtf16LeStringCandidate(bytes: ByteArray, start: Int, end: Int, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<String>) {
        if (section in setOf(".dynstr", ".strtab", ".shstrtab")) return
        val len = end - start
        if (len < 8 || len % 2 != 0) return
        if (len > 512) return
        val raw = bytes.copyOfRange(start, end)
        val units = raw.size / 2
        if (units < 3 || units > 128) return
        val asciiHighZero = (0 until units).count { raw[it * 2 + 1] == 0.toByte() }
        val asciiLowPrintable = (0 until units).count {
            val low = raw[it * 2].toInt() and 0xff
            low == 0x09 || low == 0x0a || low == 0x0d || low in 0x20..0x7e
        }
        val likelyAsciiUtf16 = asciiHighZero >= units * 7 / 8 && asciiLowPrintable >= units * 7 / 8
        val likelyMisalignedAscii = asciiHighZero == 0 && asciiLowPrintable >= units * 3 / 4
        if (likelyMisalignedAscii) return
        val text = runCatching { raw.toString(Charsets.UTF_16LE) }.getOrNull() ?: return
        val clean = text.takeWhile { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }.trimEnd()
        if (clean.length < 3) return
        val printable = clean.count { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }
        val letters = clean.count { it.isLetter() || Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val digits = clean.count { it.isDigit() }
        val spaces = clean.count { it.isWhitespace() }
        val useful = clean.any { it.isLetterOrDigit() || Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val mostlyText = printable >= clean.length * 95 / 100
        val hasHan = clean.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }
        val hasStrongTextSignal = likelyAsciiUtf16 || hasHan || clean.any { it.code > 0x7f && Character.isLetterOrDigit(it) }
        val entropyPenalty = clean.toSet().size >= clean.length * 3 / 4 && letters < clean.length / 3
        val confidence = when {
            hasHan && mostlyText -> 0.9
            likelyAsciiUtf16 && letters + digits >= clean.length / 2 -> 0.82
            hasStrongTextSignal && mostlyText && spaces > 0 -> 0.7
            else -> 0.35
        }
        if (useful && mostlyText && hasStrongTextSignal && !entropyPenalty && confidence >= 0.7 && seen.add("UTF-16LE:${base + start}:$clean")) {
            out += StringInfo(base + start, clean.take(256), raw.size, section, "UTF-16LE", confidence)
        }
    }

    private fun bindStr(v: Int): String = when (v) {
        0 -> "LOCAL"; 1 -> "GLOBAL"; 2 -> "WEAK"; else -> "OTHER"
    }

    private fun typeStr(v: Int): String = when (v) {
        0 -> "NOTYPE"; 1 -> "OBJECT"; 2 -> "FUNC"; 6 -> "TLS"; else -> "OTHER"
    }

    private fun visStr(v: Int): String = when (v) {
        0 -> "DEFAULT"; 1 -> "INTERNAL"; 2 -> "HIDDEN"; 3 -> "PROTECTED"; else -> "DEFAULT"
    }

    private external fun nativeParse(data: ByteArray): String
    private external fun nativeParseAny(data: ByteArray, format: String): String
    private external fun nativeFixSections(data: ByteArray): ByteArray
    private external fun nativePatchAddress(data: ByteArray, va: Long, patch: ByteArray): ByteArray
    private external fun nativeGetSectionContent(data: ByteArray, sectionName: String): ByteArray
    private external fun nativeSetSectionContent(data: ByteArray, sectionName: String, content: ByteArray): ByteArray
    private external fun nativeAddExportedFunction(data: ByteArray, addr: Long, name: String): ByteArray
    private external fun nativeRemoveSymbol(data: ByteArray, name: String): ByteArray
    private external fun nativeAvailable(): Boolean

    companion object {
        init {
            runCatching { System.loadLibrary("rz_native") }
        }
    }
}
