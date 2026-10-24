// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Native build profile logic behind android_ident_note, ndk_toolchain_fingerprint
// and libcxx_variant. Evidence comes from the note section, the string table and
// the dynamic symbol surface; every claim carries its evidence inline.
package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal object NativeProfile {
    private fun u32(data: ByteArray, off: Int, little: Boolean): Long {
        if (off < 0 || off + 4 > data.size) return 0L
        return java.nio.ByteBuffer.wrap(data, off, 4).order(
            if (little) java.nio.ByteOrder.LITTLE_ENDIAN else java.nio.ByteOrder.BIG_ENDIAN
        ).int.toLong() and 0xffffffffL
    }

    private fun sectionBytes(data: ByteArray, section: SectionInfo): ByteArray? {
        if (section.type == 8L || section.size <= 0) return null
        val start = section.offset.toInt().coerceIn(0, data.size)
        val end = minOf(data.size, start + section.size.toInt())
        if (start >= end) return null
        return data.copyOfRange(start, end)
    }

    private fun cstr(data: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= data.size) return ""
        var end = offset
        while (end < data.size && data[end] != 0.toByte()) end++
        return String(data, offset, end - offset, Charsets.UTF_8)
    }

    // ── android_ident_note ──

    /** Parses ELF notes (PT_NOTE segments / SHT_NOTE sections) as (name, type, desc) triples. */
    fun notes(data: ByteArray, elf: ElfFile): List<Triple<String, Int, ByteArray>> {
        val out = mutableListOf<Triple<String, Int, ByteArray>>()
        val regions = mutableListOf<Pair<Long, Long>>()
        elf.programHeaders.filter { it.type == 4L }.forEach { regions += it.offset to it.filesz }
        elf.sections.filter { it.type == 7L && it.size > 0 }.forEach { regions += it.offset to it.size }
        regions.forEach { (off, size) ->
            var pos = off.toInt().coerceIn(0, data.size)
            val end = minOf(data.size, pos + size.toInt())
            while (pos + 12 <= end && out.size < 64) {
                val namesz = u32(data, pos, elf.littleEndian).toInt()
                val descsz = u32(data, pos + 4, elf.littleEndian).toInt()
                val type = u32(data, pos + 8, elf.littleEndian).toInt()
                if (namesz < 0 || descsz < 0 || namesz > 256 || descsz > 65536) break
                val nameStart = pos + 12
                if (nameStart + namesz > end) break
                val name = String(data, nameStart, namesz, Charsets.UTF_8).trimEnd('\u0000')
                val descStart = nameStart + ((namesz + 3) / 4) * 4
                if (descStart + descsz > end) break
                out += Triple(name, type, data.copyOfRange(descStart, descStart + descsz))
                pos = descStart + ((descsz + 3) / 4) * 4
            }
        }
        return out
    }

    fun androidIdent(data: ByteArray, elf: ElfFile): JSONObject {
        val result = JSONObject().put("found", false)
        val notes = notes(data, elf)
        val android = notes.firstOrNull { it.first == "Android" }
        if (android == null) {
            return result
                .put("noteCount", notes.size)
                .put("method", "Scans PT_NOTE segments and SHT_NOTE sections for name=Android.")
        }
        val desc = android.third
        result.put("found", true).put("descSize", desc.size)
        if (desc.size >= 8) {
            val sdk = u32(desc, 0, elf.littleEndian)
            val ndkPacked = u32(desc, 4, elf.littleEndian)
            result
                .put("sdkVersion", sdk)
                .put("ndkVersion", ndkPacked)
                .put("ndkVersionHuman", ndkHuman(ndkPacked))
        }
        if (desc.size > 8) {
            result.put("buildNumber", String(desc, 8, desc.size - 8, Charsets.US_ASCII).trimEnd('\u0000'))
        }
        return result
    }

    private fun ndkHuman(packed: Long): String {
        val major = (packed shr 25) and 0x7fL
        val minor = (packed shr 14) and 0x7ffL
        val build = packed and 0x3fffL
        return "$major.$minor.$build"
    }

    // ── ndk_toolchain_fingerprint ──

    private val CLANG_RE = Regex("Android \\(\\d+\\) clang version (\\d+\\.\\d+\\.\\d+)")
    private val CLANG_PLAIN_RE = Regex("clang version (\\d+\\.\\d+\\.\\d+)")
    private val GCC_RE = Regex("(?:Android/)?[\\w-]+-gcc .*?(\\d+\\.\\d+\\.\\d+)")

    fun toolchainFingerprint(data: ByteArray, elf: ElfFile): JSONObject {
        val evidence = JSONArray()
        var compiler = "unknown"
        var version: String? = null
        for (s in elf.strings) {
            val v = s.value
            val clang = CLANG_RE.find(v) ?: CLANG_PLAIN_RE.find(v)
            if (clang != null) {
                compiler = "clang"
                if (version == null) version = clang.groupValues[1]
                if (evidence.length() < 20) {
                    evidence.put(
                        JSONObject().put("kind", "clang_version").put("value", v.take(120))
                            .put("section", s.section).put("offset", "0x${s.offset.toString(16)}")
                    )
                }
                continue
            }
            if (compiler == "unknown" && v.contains("GCC: (")) {
                compiler = "gcc"
                val g = GCC_RE.find(v)
                if (g != null) version = g.groupValues[1]
                if (evidence.length() < 20) {
                    evidence.put(
                        JSONObject().put("kind", "gcc_version").put("value", v.take(120))
                            .put("section", s.section).put("offset", "0x${s.offset.toString(16)}")
                    )
                }
            }
        }
        val symbols = elf.dynSymbols.map { it.name }
        val sanitizers = listOf("__asan_", "__msan_", "__tsan_", "__ubsan_").filter { prefix -> symbols.any { it.startsWith(prefix) } }
        if (sanitizers.isNotEmpty()) {
            evidence.put(JSONObject().put("kind", "sanitizer_symbols").put("value", sanitizers.joinToString(",")))
        }
        val ltoSections = elf.sections.filter { it.name in setOf(".llvmbc", ".llvm_addrsig") }.map { it.name }
        if (ltoSections.isNotEmpty()) evidence.put(JSONObject().put("kind", "lto_sections").put("value", ltoSections.joinToString(",")))
        val rustMarker = symbols.any { it.startsWith("_ZN") && it.contains("17rust") } ||
            elf.strings.any { it.value.contains("rustc") }
        if (rustMarker) evidence.put(JSONObject().put("kind", "rust_runtime").put("value", "rustc strings/symbols"))
        return JSONObject()
            .put("compiler", compiler)
            .put("version", version)
            .put("sanitizers", JSONArray(sanitizers))
            .put("lto", ltoSections.isNotEmpty())
            .put("rust", rustMarker)
            .put("evidence", evidence)
            .put(
                "method",
                "Version strings from the string table plus sanitizer/LTO/rust markers from symbols and sections. " +
                    "A stripped, string-less binary may legitimately report unknown."
            )
    }

    // ── libcxx_variant ──

    fun libcxxVariant(data: ByteArray, elf: ElfFile): JSONObject {
        val needed = ElfAudit.neededList(data, elf)
        val evidence = JSONArray()
        var variant = "none"
        when {
            needed.any { it.startsWith("libc++_shared") } -> {
                variant = "libc++_dynamic"
                evidence.put(JSONObject().put("kind", "dt_needed").put("value", needed.first { it.startsWith("libc++_shared") }))
            }
            needed.any { it.startsWith("libstdc++") } -> {
                variant = "libstdc++_dynamic"
                evidence.put(JSONObject().put("kind", "dt_needed").put("value", needed.first { it.startsWith("libstdc++") }))
            }
            needed.any { it.startsWith("libgnustl") || it.startsWith("libstlport") } -> {
                variant = "legacy_stl_dynamic"
                evidence.put(JSONObject().put("kind", "dt_needed").put("value", "legacy STL library in DT_NEEDED"))
            }
            elf.dynSymbols.any { it.name.startsWith("_ZNSt") || it.name.startsWith("_ZSt") } -> {
                variant = "stl_static"
                evidence.put(JSONObject().put("kind", "dynsym").put("value", "C++ standard library mangled symbols present without STL DT_NEEDED"))
            }
        }
        val cxaThrow = elf.dynSymbols.any { it.name == "__cxa_throw" }
        val rtti = elf.dynSymbols.any { it.name.startsWith("_ZTI") }
        val vtable = elf.dynSymbols.any { it.name.startsWith("_ZTV") }
        if (cxaThrow) evidence.put(JSONObject().put("kind", "exception_runtime").put("value", "__cxa_throw in dynsym"))
        return JSONObject()
            .put("variant", variant)
            .put("neededLibraries", JSONArray(needed))
            .put("exceptions", cxaThrow)
            .put("rttiHints", rtti)
            .put("vtablesInDynsym", vtable)
            .put("evidence", evidence)
    }
}
