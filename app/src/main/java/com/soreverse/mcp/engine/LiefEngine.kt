package com.soreverse.mcp.engine

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.AbstractList
import kotlin.math.min
import org.json.JSONArray
import org.json.JSONObject

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
        if (result.isFailure) {
            libLoaded = false
            loadError = result.exceptionOrNull()?.message ?: "Unknown load error"
        } else {
            // JNI 符号验证：空 stub（rizin_stub.cpp，Rizin/LIEF 静态库缺失时
            // 的 fallback 构建）没有 nativeAvailable 符号，调用会抛
            // UnsatisfiedLinkError。仅凭 dlopen 成功就报告 loaded 会让 stub
            // 被误判为可用，导致 nativeParse 静默 fallback 到 Kotlin ElfParser
            // （dynamicEntries 等 LIEF 独有字段全部丢失，imports 全部显示
            // UNRESOLVED）。与 XAnSoEngine.available() 的验证模式保持一致。
            val jniOk = runCatching { nativeAvailable() }.getOrDefault(false)
            libLoaded = jniOk
            if (!libLoaded) {
                loadError =
                    "librz_native.so 加载成功但 LIEF JNI 自检失败——该 .so 可能是空 stub（LIEF 静态库缺失时的 fallback 构建）"
            }
        }
    }

    fun available(): Boolean = libLoaded

    fun loadStatus(): String = if (libLoaded) "loaded" else "failed: $loadError"

    // Like Rizin, the LIEF native layer builds/mutates C++ objects and uses
    // process-global state (logging, parser singletons). Serialize every native
    // LIEF entry point behind one lock so concurrent MCP coroutines can't corrupt
    // shared native state and crash. Kept consistent with RizinNativeEngine.
    private val nativeLock = java.util.concurrent.locks.ReentrantLock()

    private inline fun <T> serial(block: () -> T): T {
        nativeLock.lock()
        try {
            return block()
        } finally {
            nativeLock.unlock()
        }
    }

    fun parse(data: ByteArray): ElfFile {
        if (!available()) return ElfParser(data).parse()
        return serial {
            runCatching {
                val json = nativeParse(data)
                parseJson(json, data)
            }.getOrElse {
                ElfParser(data).parse()
            }
        }
    }

    fun parseAny(data: ByteArray, format: String = "auto"): JSONObject = serial {
        JSONObject(nativeParseAny(data, format))
    }

    fun fixSections(data: ByteArray): ByteArray {
        if (!available()) return data
        return serial {
            runCatching {
                val fixed = nativeFixSections(data)
                if (fixed.isNotEmpty()) fixed else data
            }.getOrElse { data }
        }
    }

    fun patchAddress(data: ByteArray, va: Long, patch: ByteArray): ByteArray {
        if (!available()) return data
        return serial {
            runCatching {
                val patched = nativePatchAddress(data, va, patch)
                if (patched.isNotEmpty()) patched else data
            }.getOrElse { data }
        }
    }

    fun getSectionContent(data: ByteArray, sectionName: String): ByteArray {
        if (!available()) return ByteArray(0)
        return serial {
            runCatching { nativeGetSectionContent(data, sectionName) }.getOrDefault(ByteArray(0))
        }
    }

    fun setSectionContent(data: ByteArray, sectionName: String, content: ByteArray): ByteArray {
        if (!available()) return data
        return serial {
            runCatching {
                val patched = nativeSetSectionContent(data, sectionName, content)
                if (patched.isNotEmpty()) patched else data
            }.getOrElse { data }
        }
    }

    fun addExportedFunction(data: ByteArray, addr: Long, name: String): ByteArray {
        if (!available()) return data
        return serial {
            runCatching {
                val patched = nativeAddExportedFunction(data, addr, name)
                if (patched.isNotEmpty()) patched else data
            }.getOrElse { data }
        }
    }

    fun removeSymbol(data: ByteArray, name: String): ByteArray {
        if (!available()) return data
        return serial {
            runCatching {
                val patched = nativeRemoveSymbol(data, name)
                if (patched.isNotEmpty()) patched else data
            }.getOrElse { data }
        }
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
        val strings = lazyStrings { extractStrings(data, sections) }

        return ElfFile(
            data, bits, littleEndian, type, machine, entry,
            sections, symbols, dynSymbols, relocations, strings,
            programHeaders, dynamicEntries
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
                entsize = o.optLong("entsize")
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
                exported = o.optBoolean("exported")
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
                addend = o.optLong("addend")
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
                align = o.optLong("align")
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
                value = o.optLong("value")
            )
        }
        return out
    }

    private fun extractStrings(data: ByteArray, sections: List<SectionInfo>): List<StringInfo> {
        val out = mutableListOf<StringInfo>()
        // Dedup keyed on (offset, byte length, encoding) packed into a single
        // long. The old "UTF-8:<offset>:<text>" key string kept a second full
        // copy of every extracted string alive for the whole scan.
        val seen = HashSet<Long>()
        for (sec in sections) {
            if (!shouldScanStrings(sec)) continue
            if (sec.offset < 0 || sec.size <= 0) continue
            // Scan the input in place: copying each section out first duplicated
            // up to a whole .rodata (tens of MiB) for every parse.
            val from = sec.offset.toInt().coerceIn(0, data.size)
            val to = min(data.size, from + sec.size.toInt()).coerceAtLeast(from)
            if (from >= to) continue
            extractUtf8Strings(data, from, to, sec.offset, sec.name, out, seen)
            if (shouldScanUtf16Strings(sec)) {
                extractUtf16LeStrings(data, from, to, sec.offset, sec.name, out, seen)
            }
        }
        extractUtf8Strings(data, 0, data.size, 0L, "<file>", out, seen)
        return out
    }

    private fun shouldScanStrings(section: SectionInfo): Boolean {
        if (section.size <= 0) return false
        if (section.name in
            setOf(
                ".rodata",
                ".strtab",
                ".dynstr",
                ".data",
                ".data.rel.ro",
                ".init_array",
                ".fini_array"
            )
        ) {
            return true
        }
        return section.name.contains("str", ignoreCase = true) ||
            section.name.contains("rodata", ignoreCase = true)
    }

    private fun shouldScanUtf16Strings(section: SectionInfo): Boolean {
        if (section.flags and 4L != 0L) return false
        return section.name in setOf(".rodata", ".data", ".data.rel.ro") ||
            section.name.contains("utf16", ignoreCase = true)
    }

    /**
     * Packs (file offset, byte length, encoding) of one string candidate into a
     * single long, so the dedup set holds 8 bytes per hit instead of a string
     * that re-states the extracted text. Offsets and lengths are `ByteArray`
     * indices, so both fit in 31 bits each, plus one bit for the encoding.
     */
    private fun dedupKey(offset: Long, length: Int, utf16: Boolean): Long = (offset shl 32) or ((length.toLong() shl 1) or if (utf16) 1L else 0L)

    /**
     * Hands out [provider]'s result on first element access instead of eagerly.
     *
     * String extraction walks every string-bearing section *and* the whole file,
     * so it dominates both the CPU time and the transient heap of one [parse] —
     * yet several callers never read [ElfFile.strings] at all: the probe parse
     * that only checks whether a section table survived hardening, the
     * scan-time metadata fallback (architecture / bits only), and the pre/post
     * parses that just diff or verify symbols. Deferring removes that cost from
     * every such parse while keeping [ElfFile.strings] identical for the callers
     * that do read it.
     *
     * The provider reads the parsed bytes, so a caller that intentionally
     * mutates an already-parsed array in place must read `strings` before doing
     * so (the open/analyze summary does, which forces the list at open time).
     */
    private fun lazyStrings(provider: () -> List<StringInfo>): List<StringInfo> = object : AbstractList<StringInfo>() {
        private val values: List<StringInfo> by lazy(LazyThreadSafetyMode.SYNCHRONIZED, provider)
        override val size: Int get() = values.size
        override fun get(index: Int): StringInfo = values[index]
    }

    private fun extractUtf8Strings(data: ByteArray, from: Int, to: Int, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<Long>) {
        val length = to - from
        var start = 0
        var i = 0
        while (i <= length) {
            if (i == length || data[from + i] == 0.toByte()) {
                emitUtf8StringCandidate(data, from + start, from + i, base + start, section, out, seen)
                start = i + 1
            }
            i++
        }
    }

    private fun emitUtf8StringCandidate(
        data: ByteArray,
        segStart: Int,
        segEnd: Int,
        offset: Long,
        section: String,
        out: MutableList<StringInfo>,
        seen: MutableSet<Long>
    ) {
        val length = segEnd - segStart
        if (length < 4) return
        val text = runCatching {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data, segStart, length))
                .toString()
        }.getOrNull() ?: return
        val clean = text.takeWhile {
            it == '\t' || it == '\n' || it == '\r' || !it.isISOControl()
        }.trimEnd()
        if (clean.length < 2) return
        val useful = clean.any {
            it.isLetterOrDigit() ||
                Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val mostlyText =
            clean.count { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() } >=
                clean.length
        val letters = clean.count {
            it.isLetter() ||
                Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val digits = clean.count { it.isDigit() }
        val hasHan = clean.any {
            Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val confidence = when {
            hasHan && mostlyText -> 0.95
            letters + digits >= clean.length * 2 / 3 -> 0.9
            useful && mostlyText -> 0.8
            else -> 0.5
        }
        if (useful && mostlyText && confidence >= 0.5 && seen.add(dedupKey(offset, length, utf16 = false))) {
            out +=
                StringInfo(offset, clean.take(1024), length, section, "UTF-8", confidence)
        }
    }

    private fun extractUtf16LeStrings(data: ByteArray, from: Int, to: Int, base: Long, section: String, out: MutableList<StringInfo>, seen: MutableSet<Long>) {
        val length = to - from
        var start = -1
        var i = 0
        while (i + 1 < length) {
            val zeroTerminated = data[from + i] == 0.toByte() && data[from + i + 1] == 0.toByte()
            if (zeroTerminated) {
                if (start >=
                    0
                ) {
                    emitUtf16LeStringCandidate(data, from + start, from + i, base + start, section, out, seen)
                }
                start = -1
                i += 2
                continue
            }
            if (start < 0 && looksLikeUtf16LeCodeUnit(data, from + i)) start = i
            i += 2
        }
    }

    private fun looksLikeUtf16LeCodeUnit(data: ByteArray, i: Int): Boolean {
        if (i + 1 >= data.size) return false
        val code = (data[i].toInt() and 0xff) or ((data[i + 1].toInt() and 0xff) shl 8)
        if (code == 0) return false
        val c = code.toChar()
        return c == '\t' || c == '\n' || c == '\r' || !c.isISOControl()
    }

    private fun emitUtf16LeStringCandidate(
        data: ByteArray,
        segStart: Int,
        segEnd: Int,
        offset: Long,
        section: String,
        out: MutableList<StringInfo>,
        seen: MutableSet<Long>
    ) {
        if (section in setOf(".dynstr", ".strtab", ".shstrtab")) return
        val length = segEnd - segStart
        if (length < 8 || length % 2 != 0) return
        if (length > 512) return
        val units = length / 2
        if (units < 3 || units > 128) return
        val asciiHighZero = (0 until units).count { data[segStart + it * 2 + 1] == 0.toByte() }
        val asciiLowPrintable = (0 until units).count {
            val low = data[segStart + it * 2].toInt() and 0xff
            low == 0x09 || low == 0x0a || low == 0x0d || low in 0x20..0x7e
        }
        val likelyAsciiUtf16 = asciiHighZero >= units * 7 / 8 && asciiLowPrintable >= units * 7 / 8
        val likelyMisalignedAscii = asciiHighZero == 0 && asciiLowPrintable >= units * 3 / 4
        if (likelyMisalignedAscii) return
        val text = runCatching { String(data, segStart, length, Charsets.UTF_16LE) }.getOrNull() ?: return
        val clean = text.takeWhile {
            it == '\t' || it == '\n' || it == '\r' || !it.isISOControl()
        }.trimEnd()
        if (clean.length < 3) return
        val printable = clean.count { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }
        val letters = clean.count {
            it.isLetter() ||
                Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val digits = clean.count { it.isDigit() }
        val spaces = clean.count { it.isWhitespace() }
        val useful = clean.any {
            it.isLetterOrDigit() ||
                Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val mostlyText = printable >= clean.length * 95 / 100
        val hasHan = clean.any {
            Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN
        }
        val hasStrongTextSignal =
            likelyAsciiUtf16 ||
                hasHan ||
                clean.any { it.code > 0x7f && Character.isLetterOrDigit(it) }
        val entropyPenalty =
            clean.toSet().size >= clean.length * 3 / 4 && letters < clean.length / 3
        val confidence = when {
            hasHan && mostlyText -> 0.9
            likelyAsciiUtf16 && letters + digits >= clean.length / 2 -> 0.82
            hasStrongTextSignal && mostlyText && spaces > 0 -> 0.7
            else -> 0.35
        }
        if (useful &&
            mostlyText &&
            hasStrongTextSignal &&
            !entropyPenalty &&
            confidence >= 0.7 &&
            seen.add(dedupKey(offset, length, utf16 = true))
        ) {
            out +=
                StringInfo(offset, clean.take(256), length, section, "UTF-16LE", confidence)
        }
    }

    private fun bindStr(v: Int): String = when (v) {
        0 -> "LOCAL"
        1 -> "GLOBAL"
        2 -> "WEAK"
        else -> "OTHER"
    }

    private fun typeStr(v: Int): String = when (v) {
        0 -> "NOTYPE"
        1 -> "OBJECT"
        2 -> "FUNC"
        6 -> "TLS"
        else -> "OTHER"
    }

    private fun visStr(v: Int): String = when (v) {
        0 -> "DEFAULT"
        1 -> "INTERNAL"
        2 -> "HIDDEN"
        3 -> "PROTECTED"
        else -> "DEFAULT"
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
