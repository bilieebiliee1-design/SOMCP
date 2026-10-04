// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
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
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
package com.soreverse.mcp.engine

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject

/**
 * Import attribution: which library does each imported symbol come from.
 *
 * `DT_NEEDED` alone only lists the libraries a file depends on; it says nothing
 * about which symbol came from where. The precise source is the GNU symbol
 * version table: `.gnu.version` assigns every dynsym an index, and
 * `.gnu.version_r` (DT_VERNEED / DT_VERNEEDNUM) maps those indices back to a
 * version name and file. Android's Bionic linker populates this, so on a
 * normal system SO the attribution is exact rather than inferred.
 *
 * When the version table is missing — which happens for hand-written or
 * prelinked objects, and whenever the section headers are gone — attribution
 * degrades to a documented guess based on which `DT_NEEDED` entries actually
 * define the symbol. Every record says which mode produced it so the caller is
 * never misled about the provenance of a library name.
 */
internal object ImportAttribution {

    private const val DT_VERNEED = 0x6FFFFFFFL

    /** SHT_GNU_versym — the section type carrying `.gnu.version`. */
    private const val SHT_GNU_VERSYM = 0x6FFFFFFFL

    /** Android Bionic libraries and what a reviewer wants to know about them. */
    private val LIBRARY_ROLES = mapOf(
        "libc.so" to "C standard library (malloc, string, file, process)",
        "libm.so" to "math library",
        "libdl.so" to "dynamic loader helpers (dlopen/dlsym/dlerror)",
        "liblog.so" to "Android logging (__android_log_print)",
        "liblogd.so" to "log daemon client",
        "libandroid.so" to "Android native APIs (ANativeWindow, AAssetManager)",
        "libz.so" to "zlib compression",
        "libjnigraphics.so" to "Android graphics",
        "libEGL.so" to "EGL graphics",
        "libGLESv2.so" to "OpenGL ES 2",
        "libOpenSLES.so" to "OpenSL ES audio",
        "libaaudio.so" to "AAudio",
        "libmediandk.so" to "Media NDK",
        "libcamera2ndk.so" to "Camera2 NDK",
        "libbinder_ndk.so" to "Binder NDK",
        "libneuralnetworks.so" to "Neural Networks API",
        "libnativewindow.so" to "Native window",
        "libvulkan.so" to "Vulkan",
        "libstdc++.so" to "LLVM C++ runtime",
        "libc++_shared.so" to "LLVM C++ runtime (shared)",
        "libc++_static.so" to "LLVM C++ runtime (static)",
        "libc++_ndk_shared.so" to "LLVM C++ runtime (NDK shared)"
    )

    private fun dynFirst(elf: ElfFile, tag: Long): Long? = elf.dynamicEntries.firstOrNull { it.tag == tag }?.value

    private fun readCString(data: ByteArray, offset: Long): String? {
        if (offset < 0 || offset >= data.size) return null
        var end = offset.toInt()
        while (end < data.size && data[end].toInt() != 0) end++
        return data.copyOfRange(offset.toInt(), end).toString(Charsets.UTF_8).takeIf { it.isNotBlank() }
    }

    /**
     * Parses `.gnu.version_r` into versionIndex -> list of library names.
     *
     * Field layouts (all little-endian, as Android is):
     * ```
     * Elf64_Verneed { u16 vn_version; u16 vn_cnt; u32 vn_file; u32 vn_aux; u32 vn_next; }  // 16 bytes
     * Elf64_Vernaux { u32 vna_hash; u16 vna_flags; u16 vna_other; u32 vna_name; u32 vna_next; } // 16 bytes
     * Elf32_Verneed { u16 vn_version; u16 vn_cnt; u32 vn_file; u32 vn_aux; u32 vn_next; }  // 16 bytes
     * Elf32_Vernaux { u32 vna_hash; u16 vna_flags; u16 vna_other; u32 vna_name; u32 vna_next; } // 16 bytes
     * ```
     * Both are 16 bytes with the same offsets, so one read path serves both.
     * Only the *pointers* differ in width, and in these two structures the
     * file/aux/next members are all 32-bit regardless of ELF class.
     */
    private fun parseVerneed(elf: ElfFile, data: ByteArray): Map<Int, List<String>> {
        val out = LinkedHashMap<Int, MutableList<String>>()
        val base = dynFirst(elf, DT_VERNEED) ?: return out
        val strTab = elf.sections.firstOrNull { it.name == ".dynstr" } ?: return out
        val start = sectionOffsetOf(elf, base) ?: return out
        var off = start.toInt()
        var guard = 0
        while (off >= 0 && off + 16 <= data.size && guard++ < 256) {
            val fileNameOff = readU32(data, off + 4)
            val auxOff = readU32(data, off + 8)
            val nextOff = readU32(data, off + 12)
            val library = readCString(data, strTab.offset + fileNameOff)
            // Walk the auxiliary chain: each Vernaux carries its own version index.
            var aux = if (auxOff != 0L) off + auxOff.toInt() else -1
            var auxGuard = 0
            while (aux >= 0 && aux + 16 <= data.size && auxGuard++ < 256) {
                val other = readU16(data, aux + 6)
                val auxNext = readU32(data, aux + 12)
                if (library != null) {
                    out.getOrPut(other) { mutableListOf() }.let { list ->
                        if (library !in list) list.add(library)
                    }
                }
                if (auxNext == 0L) break
                aux += auxNext.toInt()
            }
            if (nextOff == 0L || nextOff < 16L) break
            off += nextOff.toInt()
        }
        return out
    }

    private fun sectionOffsetOf(elf: ElfFile, va: Long): Long? {
        val sec = elf.sections.firstOrNull { it.addr != 0L && va >= it.addr && va < it.addr + it.size }
        if (sec != null) return sec.offset + (va - sec.addr)
        val ph = elf.programHeaders.firstOrNull { it.type == 2L && va >= it.vaddr && va < it.vaddr + it.filesz }
        return ph?.let { it.offset + (va - it.vaddr) }
    }

    private fun readU16(data: ByteArray, off: Int): Int {
        if (off + 2 > data.size) return 0
        return (data[off].toInt() and 0xff) or ((data[off + 1].toInt() and 0xff) shl 8)
    }

    private fun readU32(data: ByteArray, off: Int): Long {
        if (off + 4 > data.size) return 0L
        var v = 0L
        for (i in 0 until 4) v = v or ((data[off + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    /** dynsym index -> version index, from `.gnu.version` (SHT_GNU_versym). */
    private fun parseVersym(elf: ElfFile, data: ByteArray): IntArray? {
        val sec = elf.sections.firstOrNull { it.type == SHT_GNU_VERSYM } ?: return null
        if (sec.size < 2) return null
        val start = sec.offset.toInt()
        val count = (sec.size / 2).toInt()
        if (start < 0 || start + count * 2 > data.size) return null
        return IntArray(count) { i ->
            val v = (data[start + i * 2].toInt() and 0xff) or ((data[start + i * 2 + 1].toInt() and 0xff) shl 8)
            v and 0x7FFF
        }
    }

    /**
     * [needed] is the DT_NEEDED library list; the caller resolves it because
     * reading it needs the EngineRuntime receiver that owns the ELF bytes.
     */
    fun analyze(elf: ElfFile, data: ByteArray, needed: List<String>): JSONObject {
        val imported = elf.dynSymbols.filter { it.imported }
        val versioned = runCatching { parseVerneed(elf, data) }.getOrNull()
        val versym = runCatching { parseVersym(elf, data) }.getOrNull()
        val mode = when {
            versioned != null && versioned.isNotEmpty() -> "gnu_version_r"
            else -> "needed_heuristic"
        }

        val libraries = LinkedHashMap<String, JSONArray>()
        val unresolved = JSONArray()
        val items = JSONArray()

        imported.forEachIndexed { index, sym ->
            val versionIndex = versym?.getOrNull(index)
            val candidates = versionIndex?.let { versioned?.get(it) }
            // Narrow once, up front: isNullOrEmpty() carries no contract, so it
            // would NOT smart-cast `candidates` in the versioned branch and the
            // resulting Pair would degrade to Pair<List<String>?, String>.
            val resolved = candidates?.takeIf { it.isNotEmpty() }
            val (libs, evidence) = if (resolved != null) {
                resolved to "gnu_version_r"
            } else {
                needed to "needed_heuristic"
            }
            val target = libs.firstOrNull()
            val record = JSONObject()
                .put("symbol", sym.name)
                .put("library", target ?: JSONObject.NULL)
                .put("evidence", evidence)
                .put("versionIndex", versionIndex ?: JSONObject.NULL)
                .put("versionLibraries", JSONArray(libs))
            items.put(record)
            if (target == null) {
                unresolved.put(sym.name)
            } else {
                libraries.getOrPut(target) { JSONArray() }.put(sym.name)
            }
        }

        val librarySummary = JSONArray()
        libraries.forEach { (lib, syms) ->
            librarySummary.put(
                JSONObject()
                    .put("library", lib)
                    .put("role", LIBRARY_ROLES[lib] ?: "unrecognised library")
                    .put("importCount", syms.length())
                    .put("symbols", syms)
            )
        }

        // A NEEDED entry that owns no import is worth surfacing: it is either
        // loaded for its constructors alone or it is a leftover.
        val unusedNeeded = needed.filter { it !in libraries.keys }

        return JSONObject()
            .put("mode", mode)
            .put("importCount", imported.size)
            .put("libraryCount", libraries.size)
            .put(
                "evidence",
                if (mode == "gnu_version_r") {
                    "Library names come from .gnu.version_r (DT_VERNEED) — exact attribution written by the linker."
                } else {
                    "No .gnu.version_r table; imports are attributed to the DT_NEEDED set as a whole. Library names here are NOT proof of origin."
                }
            )
            .put("neededLibraries", JSONArray(needed))
            .put("libraries", librarySummary)
            .put("unresolved", unresolved)
            .put("neededWithoutImports", JSONArray(unusedNeeded))
            .put("imports", items)
            .put(
                "limits",
                "Attribution is static. In heuristic mode every import is listed against every DT_NEEDED entry, so treat 'library' as a candidate set. A linker --as-needed link or a missing section table can leave NEEDED entries with no imports."
            )
    }

    fun capabilities(): JSONObject = JSONObject()
        .put("coverageClass", "elf_version_tables")
        .put(
            "supported",
            JSONArray(
                listOf(
                    "DT_NEEDED library enumeration",
                    ".gnu.version_r / DT_VERNEED parsing for exact symbol->library attribution",
                    ".gnu.version (SHT_GNU_versym) index decoding",
                    "DT_NEEDED fallback attribution when version tables are absent",
                    "Android Bionic library role annotations"
                )
            )
        )
        .put(
            "notCovered",
            JSONArray(
                listOf(
                    "runtime GOT overwrite detection is NOT implemented (needs a live process)",
                    "static RELRO presence is reported by analyze_elf, not by this tool"
                )
            )
        )
}

internal fun EngineRuntime.importTrace(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    if (elf.sections.isEmpty()) {
        return@guarded err(
            "NO_SECTIONS",
            "Section table is empty; .gnu.version_r cannot be located. Run edit_fix_sections (or xanso_api fix_sections) first."
        )
    }
    val data = dataFor(workspaceId, editSessionId)
    ok(ImportAttribution.analyze(elf, data, neededLibraries(elf, data)))
}

internal fun EngineRuntime.importCapabilities(): JSONObject = ImportAttribution.capabilities()
