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

/** Shared hex formatting so the scanner and the JSON emitters cannot drift. */
private fun hexOf(v: Long): String = "0x${v.toString(16)}"

/**
 * One recovered `JNINativeMethod` row.
 *
 * The JNI registration table is an array of three consecutive pointers per
 * entry: `const char* name`, `const char* signature`, `void* fnPtr`. Both
 * string pointers must land inside a readable section of this SO, and the
 * function pointer must land inside an executable segment — that triple
 * constraint is what keeps the scan from matching arbitrary pointer triples
 * that happen to sit next to each other in `.rodata`.
 */
internal data class JniNativeMethod(
    val name: String,
    val signature: String,
    val fnPtr: Long,
    val tableVa: Long,
    val fileOffset: Long,
    val resolvedSymbol: String?,
    val symbolBound: Boolean
)

/**
 * Static recovery of JNI dynamic registrations.
 *
 * Most Android `.so` files do not export their JNI entry points as
 * `Java_com_example_Foo_bar` symbols; they register them at runtime from
 * `JNI_OnLoad` through `RegisterNatives`. That hides the real
 * Java-method-to-native-address mapping from a plain symbol dump, which is
 * the single biggest reason a native SO looks unreadable at first glance.
 *
 * This scanner recovers the mapping without executing anything: it walks the
 * read-only data sections looking for pointer triples that decode as a
 * `JNINativeMethod` row, then resolves each `fnPtr` back to a symbol when the
 * address happens to be covered by `.symtab` / `.dynsym`. Everything here is
 * pure byte inspection, so it works on an untrusted file without running it.
 */
internal object JniRegisterEngine {

    /** Upper bound on rows per table so a wild pointer cannot spin forever. */
    private const val MAX_ROWS = 4096

    /** Plausibility ceiling for a JNI descriptor string, e.g. `(Ljava/lang/String;)V`. */
    private const val MAX_SIGNATURE_LEN = 256

    /** Plausibility ceiling for a Java method name. */
    private const val MAX_NAME_LEN = 512

    /** Sections that never hold a registration table. */
    private fun skipSection(sec: SectionInfo): Boolean {
        // SHT_NOBITS (.bss) has no file content to read.
        if (sec.type == 8L) return true
        val name = sec.name
        return name == ".bss" || name == ".tbss" || name == ".shstrtab"
    }

    /**
     * A JNI descriptor is `(<params>)<return>`. Requiring the parenthesis pair
     * plus a one-or-two-character return type rejects nearly every incidental
     * C string that happens to sit near a code pointer.
     */
    private fun looksLikeSignature(value: String): Boolean {
        if (value.length < 3 || value.length > MAX_SIGNATURE_LEN) return false
        if (value[0] != '(') return false
        val close = value.indexOf(')')
        if (close < 0) return false
        // Return type must follow ')' immediately.
        val ret = value.substring(close + 1)
        if (ret.isEmpty() || ret.length > 2) return false
        val params = value.substring(1, close)
        var i = 0
        while (i < params.length) {
            when (params[i]) {
                'L' -> {
                    // Object type: L<name-with-slashes>;
                    val end = params.indexOf(';', i)
                    if (end < 0) return false
                    val name = params.substring(i + 1, end)
                    if (name.isEmpty() || '/' !in name) return false
                    i = end + 1
                }

                '[', 'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'V' -> i++

                else -> return false
            }
        }
        return ret[0] in "VZBCSIJFD" && (ret.length == 1 || (ret[0] == 'L' && ret[1] == ';'))
    }

    /** A Java method name as seen from JNI: identifier chars plus `<init>` / `<clinit>`. */
    private fun looksLikeMethodName(value: String): Boolean {
        if (value.isEmpty() || value.length > MAX_NAME_LEN) return false
        if (value == "<init>" || value == "<clinit>") return true
        return value.all { it.isLetterOrDigit() || it == '_' || it == '$' }
    }

    private fun readCStringAt(data: ByteArray, offset: Int, limit: Int): String? {
        if (offset < 0 || offset >= data.size) return null
        val end = minOf(data.size, offset + limit)
        val sb = StringBuilder()
        var i = offset
        while (i < end) {
            val b = data[i].toInt() and 0xff
            if (b == 0) return if (sb.isEmpty()) null else sb.toString()
            // Non-ASCII in a JNI name/descriptor means this is not a table string.
            if (b > 0x7f) return null
            sb.append(b.toChar())
            i++
        }
        return null
    }

    private fun readPointer(data: ByteArray, offset: Int, bits: Int, littleEndian: Boolean): Long? {
        return when (bits) {
            32 -> {
                if (offset < 0 || offset + 4 > data.size) return null
                var v = 0L
                for (i in 0 until 4) {
                    val b = data[offset + i].toLong() and 0xff
                    v = if (littleEndian) {
                        v or (b shl (8 * i))
                    } else {
                        v or (b shl (8 * (3 - i)))
                    }
                }
                v
            }

            64 -> {
                if (offset < 0 || offset + 8 > data.size) return null
                var v = 0L
                for (i in 0 until 8) {
                    val b = data[offset + i].toLong() and 0xff
                    v = if (littleEndian) {
                        v or (b shl (8 * i))
                    } else {
                        v or (b shl (8 * (7 - i)))
                    }
                }
                v
            }

            else -> null
        }
    }

    /** True when [va] is inside a section with the executable flag (SHF_EXECINSTR). */
    private fun isExecutableVa(elf: ElfFile, va: Long): Boolean {
        val shfExec = 0x4L
        val inSection = elf.sections.any { it.addr != 0L && va >= it.addr && va < it.addr + it.size }
        if (inSection) {
            return elf.sections.any { it.addr != 0L && va >= it.addr && va < it.addr + it.size && (it.flags and shfExec) != 0L }
        }
        // Strip the ARM Thumb bit before testing segment permissions.
        val probe = if (elf.architecture == "arm32") va and -2L else va
        val pfX = 0x1L
        return elf.programHeaders.any { it.type == 1L && probe >= it.vaddr && probe < it.vaddr + it.filesz && (it.flags and pfX) != 0L }
    }

    /** True when [va] points into a section that holds file-backed bytes we can read. */
    private fun readableSectionFor(elf: ElfFile, va: Long): SectionInfo? = elf.sections.firstOrNull {
        it.type != 8L && it.size > 0 && va >= it.addr && va < it.addr + it.size
    }

    private fun symbolNameFor(elf: ElfFile, va: Long): Pair<String?, Boolean> {
        val probe = if (elf.architecture == "arm32") va and -2L else va
        val all = elf.symbols + elf.dynSymbols
        // Prefer the closest symbol at or below the address (local labels win ties).
        val hit = all.filter { it.value != 0L && it.value <= probe }
            .maxByOrNull { it.value }
        if (hit == null) return null to false
        val delta = probe - hit.value
        val bound = delta == 0L
        return hit.name to bound
    }

    /**
     * Scans every data section for `JNINativeMethod` rows.
     *
     * A real `RegisterNatives` call always passes one contiguous array, so the
     * scan simply walks forward in `3 * ptrSize` steps after a hit and in
     * `ptrSize` steps when a candidate is rejected. Duplicate rows (the same
     * method reachable through two tables) collapse by name+signature+fnPtr.
     */
    fun scan(elf: ElfFile): List<JniNativeMethod> {
        val data = elf.data
        val ptrSize = if (elf.bits == 64) 8 else 4
        val results = LinkedHashMap<String, JniNativeMethod>()

        for (sec in elf.sections) {
            if (skipSection(sec) || sec.size <= 0) continue
            val start = sec.offset.toInt()
            val end = minOf(data.size, start + sec.size.toInt())
            if (start < 0 || start >= end) continue

            var cursor = start
            while (cursor + 3 * ptrSize <= end) {
                if (results.size >= MAX_ROWS) return results.values.toList()
                val namePtr = readPointer(data, cursor, elf.bits, elf.littleEndian) ?: break
                val sigPtr = readPointer(data, cursor + ptrSize, elf.bits, elf.littleEndian)
                val fnPtr = readPointer(data, cursor + 2 * ptrSize, elf.bits, elf.littleEndian)
                if (sigPtr == null || fnPtr == null) break

                val nameSec = readableSectionFor(elf, namePtr)
                val sigSec = readableSectionFor(elf, sigPtr)
                if (nameSec == null || sigSec == null || fnPtr == 0L) {
                    cursor += ptrSize
                    continue
                }
                if (!isExecutableVa(elf, fnPtr)) {
                    cursor += ptrSize
                    continue
                }
                val nameOff = offsetOf(data, elf, namePtr) ?: run {
                    cursor += ptrSize
                    continue
                }
                val sigOff = offsetOf(data, elf, sigPtr) ?: run {
                    cursor += ptrSize
                    continue
                }
                val name = readCStringAt(data, nameOff, MAX_NAME_LEN)
                val sig = readCStringAt(data, sigOff, MAX_SIGNATURE_LEN)
                if (name == null || sig == null || !looksLikeMethodName(name) || !looksLikeSignature(sig)) {
                    cursor += ptrSize
                    continue
                }

                val (sym, bound) = symbolNameFor(elf, fnPtr)
                val key = "$name$sig${hexOf(fnPtr)}"
                results.getOrPut(key) {
                    JniNativeMethod(
                        name = name,
                        signature = sig,
                        fnPtr = fnPtr,
                        tableVa = sec.addr + (cursor - start),
                        fileOffset = cursor.toLong(),
                        resolvedSymbol = sym,
                        symbolBound = bound
                    )
                }
                // Keep walking in ptrSize steps: a table row is 3 pointers, and
                // the next row starts right after this one.
                cursor += 3 * ptrSize
            }
        }
        return results.values.toList()
    }

    private fun offsetOf(data: ByteArray, elf: ElfFile, va: Long): Int? {
        val sec = readableSectionFor(elf, va) ?: return null
        val off = sec.offset + (va - sec.addr)
        if (off < 0 || off >= data.size) return null
        return off.toInt()
    }

    /**
     * Infers the owning Java class from the conventional
     * `Java_<mangled-class>_<method>` symbol, when a registration resolves to
     * one. JNI mangles package separators `/` into `_`, and escapes `_`/`;`/`[`
     * as `_1`/`_2`/`_3`; other non-identifier chars become `_0xxxx`. The class
     * portion's `_` are therefore restored to package dots.
     *
     * JNI symbols are inherently ambiguous when the method name itself contains
     * an underscore (`do_thing`): the class/method boundary is taken at the LAST
     * underscore, the same convention common JNI tooling uses. Treat the result
     * as a hint, not a proven class name.
     */
    fun javaClassFromSymbol(symbol: String): String? {
        if (!symbol.startsWith("Java_")) return null
        var body = symbol.removePrefix("Java_")
        if (body.startsWith("m")) return null
        val out = StringBuilder()
        var i = 0
        while (i < body.length) {
            val c = body[i]
            if (c == '_') {
                when (val next = body.getOrNull(i + 1)) {
                    '_' -> {
                        out.append('_')
                        i += 2
                    }

                    '1' -> {
                        out.append('_')
                        i += 2
                    }

                    '2' -> {
                        out.append(';')
                        i += 2
                    }

                    '3' -> {
                        out.append('[')
                        i += 2
                    }

                    '0' -> {
                        // _0XXXX is a 4-hex-digit unicode escape.
                        val hexPart = body.substring(i + 2, minOf(body.length, i + 6))
                        val code = hexPart.toIntOrNull(16)
                        if (hexPart.length < 4 || code == null) return null
                        out.append(code.toChar())
                        i += 6
                    }

                    else -> {
                        out.append(c)
                        i++
                    }
                }
            } else {
                out.append(c)
                i++
            }
        }
        // Split the decoded name into <class>_<method> at the LAST underscore.
        // JNI mangles the class's `/` package separators into `_`, so the class
        // portion's remaining `_` are really package dots.
        val decoded = out.toString()
        val classPart = decoded.substringBeforeLast('_')
        val className = classPart.replace('/', '.').replace('_', '.')
        return className.ifBlank { null }
    }
}

internal fun EngineRuntime.jniScan(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    if (elf.sections.isEmpty()) {
        return@guarded err(
            "NO_SECTIONS",
            "Section table is empty; run edit_fix_sections (or xanso_api fix_sections) before JNI scanning."
        )
    }
    val rows = JniRegisterEngine.scan(elf)
    val jniOnLoad = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == "JNI_OnLoad" }

    val items = JSONArray()
    rows.forEach { row ->
        items.put(
            JSONObject()
                .put("name", row.name)
                .put("signature", row.signature)
                .put("fnPtr", hexOf(row.fnPtr))
                .put("thumb", elf.architecture == "arm32" && (row.fnPtr and 1L) == 1L)
                .put("tableVa", hexOf(row.tableVa))
                .put("fileOffset", hexOf(row.fileOffset))
                .put("resolvedSymbol", row.resolvedSymbol ?: JSONObject.NULL)
                .put("symbolExact", row.symbolBound)
        )
    }

    val byClass: Map<String, List<JniNativeMethod>> = rows
        .mapNotNull { row ->
            val className = JniRegisterEngine.javaClassFromSymbol(row.resolvedSymbol ?: return@mapNotNull null)
            className to row
        }
        .groupBy({ it.first }, { it.second })
    val classNames: List<String> = byClass.keys.sorted()

    ok(
        JSONObject()
            .put("count", rows.size)
            .put("jniOnLoadPresent", jniOnLoad != null)
            .put("jniOnLoadVa", jniOnLoad?.let { hexOf(it.value) } ?: JSONObject.NULL)
            .put("classes", JSONArray(classNames))
            .put("methods", items)
            .put(
                "note",
                "Recovered statically from read-only data sections; no code was executed. Rows whose resolvedSymbol is null have no covering .symtab/.dynsym entry and can only be addressed by fnPtr."
            )
    )
}

internal fun EngineRuntime.jniResolve(workspaceId: String, editSessionId: String = "", query: String): JSONObject = guarded {
    if (query.isBlank()) {
        return@guarded err("INVALID_ARGUMENT", "query is required (method name, signature, class name, or fnPtr hex).", "query", query)
    }
    val elf = elfFor(workspaceId, editSessionId)
    val rows = JniRegisterEngine.scan(elf)
    val needle = query.trim()
    val hit = rows.filter { row ->
        row.name.equals(needle, ignoreCase = true) ||
            row.signature.contains(needle) ||
            hexOf(row.fnPtr).equals(needle, ignoreCase = true) ||
            (row.resolvedSymbol?.contains(needle, ignoreCase = true) == true) ||
            (JniRegisterEngine.javaClassFromSymbol(row.resolvedSymbol ?: "")?.contains(needle, ignoreCase = true) == true)
    }
    if (hit.isEmpty()) {
        return@guarded ok(
            JSONObject().put("query", needle).put("count", 0).put("matches", JSONArray())
        )
    }
    val items = JSONArray()
    hit.forEach { row ->
        items.put(
            JSONObject()
                .put("name", row.name)
                .put("signature", row.signature)
                .put("fnPtr", hexOf(row.fnPtr))
                .put("javaClass", JniRegisterEngine.javaClassFromSymbol(row.resolvedSymbol ?: "") ?: JSONObject.NULL)
                .put("resolvedSymbol", row.resolvedSymbol ?: JSONObject.NULL)
        )
    }
    ok(JSONObject().put("query", needle).put("count", hit.size).put("matches", items))
}

internal fun EngineRuntime.jniCapabilities(): JSONObject = JSONObject()
    .put("coverageClass", "static_byte_inspection")
    .put(
        "supported",
        JSONArray(
            listOf(
                "JNINativeMethod table scan (name/signature/fnPtr triples)",
                "Java method name + JNI descriptor validation",
                "fnPtr -> .symtab/.dynsym symbol resolution",
                "ARM Thumb bit detection on fnPtr",
                "Java_<mangled> symbol -> Java class unmangling"
            )
        )
    )
    .put(
        "limits",
        JSONArray(
            listOf(
                "Does not execute the SO; tables decrypted at runtime are not visible",
                "Obfuscated tables with encrypted name/signature strings are not recovered",
                "fnPtr values resolved through a relocated GOT only resolve after applying relocations",
                "Java_* class unmangling splits at the last underscore, so a method name containing '_' is ambiguous"
            )
        )
    )
    .put(
        "staticRegistration",
        "Symbols already named Java_* in .symtab/.dynsym are reported with symbolExact=true; those do not require RegisterNatives."
    )
