// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure, JVM-testable ELF structural audit logic behind the elf_* tool family.
// Every function takes an already-parsed ElfFile (plus raw bytes where the ELF
// header itself must be re-read) and returns JSON fragments. The runtime layer
// only wraps these with workspace lookup and the error envelope.
package com.soreverse.mcp.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONArray
import org.json.JSONObject

internal object ElfAudit {
    private const val SHF_WRITE = 0x1L
    private const val SHF_ALLOC = 0x2L
    private const val SHF_EXECINSTR = 0x4L
    private const val SHT_NULL = 0L
    private const val SHT_NOBITS = 8L

    // ── shared byte readers (ElfParser.Reader is private) ──

    private fun u16(data: ByteArray, off: Int, little: Boolean): Int {
        if (off < 0 || off + 2 > data.size) return 0
        return ByteBuffer.wrap(data, off, 2).order(order(little)).short.toInt() and 0xffff
    }

    private fun u32(data: ByteArray, off: Int, little: Boolean): Long {
        if (off < 0 || off + 4 > data.size) return 0L
        return ByteBuffer.wrap(data, off, 4).order(order(little)).int.toLong() and 0xffffffffL
    }

    private fun u64(data: ByteArray, off: Int, little: Boolean): Long {
        if (off < 0 || off + 8 > data.size) return 0L
        return ByteBuffer.wrap(data, off, 8).order(order(little)).long
    }

    private fun order(little: Boolean) = if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

    private fun sectionBytes(data: ByteArray, section: SectionInfo): ByteArray {
        if (section.offset < 0 || section.size <= 0 || section.type == SHT_NOBITS) return ByteArray(0)
        val start = section.offset.toInt().coerceIn(0, data.size)
        val end = minOf(data.size, start + section.size.toInt())
        if (start >= end) return ByteArray(0)
        return data.copyOfRange(start, end)
    }

    /** vaddr → file offset via PT_LOAD mapping; null when unmapped. */
    fun vaddrToOffset(elf: ElfFile, vaddr: Long): Long? {
        for (ph in elf.programHeaders) {
            if (ph.type != 1L) continue
            if (vaddr >= ph.vaddr && vaddr < ph.vaddr + ph.filesz) return ph.offset + (vaddr - ph.vaddr)
        }
        return null
    }

    private fun bytesForVaddr(data: ByteArray, elf: ElfFile, vaddr: Long, size: Int): ByteArray? {
        val off = vaddrToOffset(elf, vaddr)?.toInt() ?: return null
        if (off < 0 || off + size > data.size) return null
        return data.copyOfRange(off, off + size)
    }

    private fun cstr(data: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= data.size) return ""
        var end = offset
        while (end < data.size && data[end] != 0.toByte()) end++
        return String(data, offset, end - offset, Charsets.UTF_8)
    }

    private fun sectionName(elf: ElfFile, name: String): String = name.ifBlank { "<noname>" }

    private fun secJson(section: SectionInfo, index: Int) = JSONObject()
        .put("name", section.name)
        .put("index", index)
        .put("type", section.type)
        .put("flags", section.flags)
        .put("addr", "0x${section.addr.toString(16)}")
        .put("offset", "0x${section.offset.toString(16)}")
        .put("size", section.size)

    // ── elf_abi_profile ──

    fun abiProfile(data: ByteArray, elf: ElfFile): JSONObject {
        fun u8(o: Int) = if (o in data.indices) data[o].toInt() and 0xff else 0
        val flagsOff = if (elf.bits == 64) 48 else 36
        val flags = u32(data, flagsOff, elf.littleEndian)
        val osAbi = when (u8(7)) {
            0 -> "SYSV"
            3 -> "LINUX"
            6 -> "SOLARIS"
            9 -> "FREEBSD"
            else -> "OTHER_${u8(7)}"
        }
        val flagBits = JSONArray()
        when (elf.machine) {
            40 -> {
                addIf(flagBits, flags and 0x05000000L == 0x05000000L, "EF_ARM_EABI_VER5", 0x05000000L)
                addIf(flagBits, flags and 0x200L != 0L, "EF_ARM_ABI_FLOAT_SOFT", 0x200L)
                addIf(flagBits, flags and 0x400L != 0L, "EF_ARM_ABI_FLOAT_HARD", 0x400L)
            }
        }
        return JSONObject()
            .put("eiClass", if (elf.bits == 64) "ELFCLASS64" else "ELFCLASS32")
            .put("eiData", if (elf.littleEndian) "ELFDATA2LSB" else "ELFDATA2MSB")
            .put("eiVersion", u8(6))
            .put("eiOsAbi", osAbi)
            .put("eiAbiVersion", u8(8))
            .put("eType", "ET_${elf.type}")
            .put("eMachine", elf.machineName)
            .put("architecture", elf.architecture)
            .put("eEntry", "0x${elf.entry.toString(16)}")
            .put("eFlags", "0x${flags.toString(16)}")
            .put("eFlagsOffset", flagsOff)
            .put("eFlagsBits", flagBits)
            .put("endian", elf.endian)
    }

    private fun addIf(arr: JSONArray, cond: Boolean, name: String, raw: Long) {
        if (cond) arr.put(JSONObject().put("name", name).put("raw", "0x${raw.toString(16)}"))
    }

    // ── elf_byte_ledger ──

    fun byteLedger(data: ByteArray, elf: ElfFile): JSONObject {
        val gaps = JSONArray()
        val overlaps = JSONArray()
        val outOfBounds = JSONArray()
        data class Span(val start: Long, val end: Long, val label: String, val kind: String)
        val spans = mutableListOf<Span>()
        spans += Span(0, minOf(elf.bits.let { if (it == 64) 64L else 52L }, data.size.toLong()), "ehdr", "header")
        elf.programHeaders.forEachIndexed { i, ph ->
            if (ph.offset >= 0 && ph.filesz > 0) {
                spans += Span(ph.offset, ph.offset + ph.filesz, "phdr[$i] type=${ph.type}", "programHeader")
            }
        }
        elf.sections.forEachIndexed { i, s ->
            if (s.type == SHT_NULL || s.type == SHT_NOBITS || s.size <= 0) return@forEachIndexed
            val end = s.offset + s.size
            if (end > data.size) {
                outOfBounds.put(JSONObject().put("section", s.name).put("index", i).put("offset", s.offset).put("size", s.size))
            }
            spans += Span(s.offset, minOf(end, data.size.toLong()), "section:${s.name}", "section")
        }
        spans.sortWith(compareBy({ it.start }, { it.end }))
        // Overlap detection only among sections/headers: a PT_LOAD covering the
        // sections it maps is the normal layout, not an overlap finding.
        val structural = spans.filter { it.kind != "programHeader" }.sortedBy { it.start }
        var cursor = 0L
        var i = 0
        while (i < spans.size) {
            var j = i
            var runEnd = spans[i].end
            while (j + 1 < spans.size && spans[j + 1].start < runEnd) {
                j++
                runEnd = maxOf(runEnd, spans[j].end)
            }
            if (spans[i].start > cursor) {
                gaps.put(JSONObject().put("offset", "0x${cursor.toString(16)}").put("size", spans[i].start - cursor))
            }
            cursor = maxOf(cursor, runEnd)
            i = j + 1
        }
        if (cursor < data.size) {
            gaps.put(JSONObject().put("offset", "0x${cursor.toString(16)}").put("size", data.size - cursor))
        }
        structural.forEachIndexed { ai, a ->
            structural.drop(ai + 1).forEach { b ->
                if (a.start < b.end && b.start < a.end) {
                    overlaps.put(
                        JSONObject()
                            .put(
                                "ranges",
                                JSONArray().apply {
                                    put(a.label)
                                    put(b.label)
                                }
                            )
                            .put("at", "0x${maxOf(a.start, b.start).toString(16)}")
                    )
                }
            }
        }
        var gapTotal = 0L
        for (i in 0 until gaps.length()) gapTotal += gaps.getJSONObject(i).getLong("size")
        val covered = data.size - gapTotal
        val coverage = if (data.isEmpty()) 100.0 else covered * 100.0 / data.size
        return JSONObject()
            .put("fileSize", data.size)
            .put("coveredBytes", covered)
            .put("coveragePercent", Math.round(coverage * 100.0) / 100.0)
            .put("sectionCount", elf.sections.size)
            .put("outOfBounds", outOfBounds)
            .put("overlaps", overlaps)
            .put("gaps", gaps)
            .put(
                "method",
                "Intervals: ELF header, each program header's file span, and every sized section (SHT_NOBITS excluded). " +
                    "Gaps are bytes no span consumes; overlaps are spans sharing bytes."
            )
    }

    // ── elf_section_anomaly ──

    fun sectionAnomalies(elf: ElfFile): JSONArray {
        val anomalies = JSONArray()
        val nameCounts = HashMap<String, Int>()
        elf.sections.forEach { nameCounts.merge(it.name, 1, Int::plus) }
        val reportedDup = HashSet<String>()
        elf.sections.forEachIndexed { i, s ->
            val sec = secJson(s, i)
            fun anomaly(kind: String, detail: String) {
                anomalies.put(
                    JSONObject().put("section", sectionName(elf, s.name)).put("index", i).put("kind", kind).put("detail", detail).put("sectionInfo", sec)
                )
            }
            if (s.type != SHT_NULL && s.name.isBlank()) anomaly("empty_name", "Section $i has an empty name")
            if (s.type != SHT_NULL && s.type != SHT_NOBITS && s.size == 0L && s.name != ".shstrtab") {
                anomaly("zero_size", "Non-NOBITS section has zero size")
            }
            if (s.flags and SHF_WRITE != 0L && s.flags and SHF_EXECINSTR != 0L) {
                anomaly("write_and_exec", "W+X section (SHF_WRITE|SHF_EXECINSTR) — self-modifying-code surface")
            }
            if (nameCounts.getOrDefault(s.name, 0) > 1 && reportedDup.add(s.name)) {
                anomaly("duplicate_name", "Name occurs ${nameCounts[s.name]} times")
            }
            if (s.type != SHT_NOBITS && s.size > 0 && s.offset + s.size > elf.data.size) {
                anomaly("out_of_bounds", "offset+size (${s.offset}+${s.size}) exceeds file size ${elf.data.size}")
            }
            if (s.addralign > 1 && (s.addralign and (s.addralign - 1)) != 0L) {
                anomaly("bad_align", "addralign ${s.addralign} is not a power of two")
            }
            if (s.flags and SHF_ALLOC != 0L && s.addr == 0L && s.type != SHT_NOBITS) {
                anomaly("alloc_without_addr", "SHF_ALLOC section has address 0")
            }
        }
        return anomalies
    }

    // ── elf_phdr_invariants ──

    fun phdrInvariants(elf: ElfFile): JSONObject {
        val findings = JSONArray()
        val loads = elf.programHeaders.filter { it.type == 1L }
        loads.forEachIndexed { i, ph ->
            fun issue(kind: String, detail: String) {
                findings.put(JSONObject().put("phdrIndex", i).put("type", "PT_LOAD").put("kind", kind).put("detail", detail))
            }
            if (ph.filesz > ph.memsz) issue("filesz_gt_memsz", "filesz 0x${ph.filesz.toString(16)} > memsz 0x${ph.memsz.toString(16)}")
            if (ph.align > 1 && (ph.align and (ph.align - 1)) != 0L) issue("align_not_pow2", "align 0x${ph.align.toString(16)} is not a power of two")
            if (ph.align > 1 && ph.offset % ph.align != ph.vaddr % ph.align) {
                issue(
                    "offset_vaddr_incongruent",
                    "offset % align (0x${(ph.offset % ph.align).toString(16)}) != vaddr % align (0x${(ph.vaddr % ph.align).toString(16)})"
                )
            }
        }
        for (a in loads.indices) {
            for (b in a + 1 until loads.size) {
                val x = loads[a]
                val y = loads[b]
                val fileOverlap = x.filesz > 0 &&
                    y.filesz > 0 &&
                    x.offset < y.offset + y.filesz &&
                    y.offset < x.offset + x.filesz
                if (fileOverlap) {
                    findings.put(
                        JSONObject()
                            .put("phdrIndex", a)
                            .put("otherIndex", b)
                            .put("type", "PT_LOAD")
                            .put("kind", "file_overlap")
                            .put(
                                "detail",
                                "file ranges 0x${x.offset.toString(
                                    16
                                )}+0x${x.filesz.toString(16)} and 0x${y.offset.toString(16)}+0x${y.filesz.toString(16)} overlap"
                            )
                    )
                }
            }
        }
        for (i in 1 until loads.size) {
            if (loads[i].vaddr < loads[i - 1].vaddr) {
                findings.put(
                    JSONObject().put("phdrIndex", i).put("type", "PT_LOAD").put("kind", "unsorted_vaddr")
                        .put("detail", "vaddr 0x${loads[i].vaddr.toString(16)} < previous 0x${loads[i - 1].vaddr.toString(16)}")
                )
            }
        }
        elf.programHeaders.filter { it.type == 7L }.forEachIndexed { i, ph ->
            if (ph.align > 1 && (ph.align and (ph.align - 1)) != 0L) {
                findings.put(
                    JSONObject().put("phdrIndex", i).put("type", "PT_TLS").put("kind", "align_not_pow2").put("detail", "align 0x${ph.align.toString(16)}")
                )
            }
        }
        return JSONObject()
            .put("programHeaderCount", elf.programHeaders.size)
            .put("ptLoadCount", loads.size)
            .put("findings", findings)
            .put("verdict", if (findings.length() == 0) "pass" else "fail")
    }

    // ── dynamic tag naming ──

    fun dynamicTagName(tag: Long): String = when (tag) {
        0L -> "DT_NULL"
        1L -> "DT_NEEDED"
        2L -> "DT_PLTRELSZ"
        3L -> "DT_PLTGOT"
        4L -> "DT_HASH"
        5L -> "DT_STRTAB"
        6L -> "DT_SYMTAB"
        7L -> "DT_RELA"
        8L -> "DT_RELASZ"
        9L -> "DT_RELAENT"
        10L -> "DT_STRSZ"
        11L -> "DT_SYMENT"
        12L -> "DT_INIT"
        13L -> "DT_FINI"
        14L -> "DT_SONAME"
        15L -> "DT_RPATH"
        16L -> "DT_SYMBOLIC"
        17L -> "DT_REL"
        18L -> "DT_RELSZ"
        19L -> "DT_RELENT"
        20L -> "DT_PLTREL"
        21L -> "DT_DEBUG"
        22L -> "DT_TEXTREL"
        23L -> "DT_JMPREL"
        24L -> "DT_BIND_NOW"
        25L -> "DT_INIT_ARRAY"
        26L -> "DT_FINI_ARRAY"
        27L -> "DT_INIT_ARRAYSZ"
        28L -> "DT_FINI_ARRAYSZ"
        29L -> "DT_RUNPATH"
        30L -> "DT_FLAGS"
        32L -> "DT_PREINIT_ARRAY"
        33L -> "DT_PREINIT_ARRAYSZ"
        34L -> "DT_RELRSZ"
        35L -> "DT_RELR"
        36L -> "DT_RELRENT"
        0x6000000fL -> "DT_ANDROID_REL(A)"
        0x60000010L -> "DT_ANDROID_RELA"
        0x60000011L -> "DT_ANDROID_RELSZ"
        0x60000012L -> "DT_ANDROID_RELASZ"
        0x6ffffdf5L -> "DT_GNU_PRELINKED"
        0x6ffffdf6L -> "DT_GNU_CONFLICTSZ"
        0x6ffffdf7L -> "DT_GNU_LIBLISTSZ"
        0x6ffffef5L -> "DT_GNU_HASH"
        0x6ffffff0L -> "DT_VERSYM"
        0x6ffffff9L -> "DT_RELACOUNT"
        0x6ffffffaL -> "DT_RELCOUNT"
        0x6ffffffbL -> "DT_FLAGS_1"
        0x6ffffffcL -> "DT_VERDEF"
        0x6ffffffdL -> "DT_VERDEFNUM"
        0x6ffffffeL -> "DT_VERNEED"
        0x6fffffffL -> "DT_VERNEEDNUM"
        0x6fffe000L -> "DT_ANDROID_RELR"
        0x6fffe001L -> "DT_ANDROID_RELRSZ"
        0x6fffe003L -> "DT_ANDROID_RELRENT"
        0x6fffe005L -> "DT_ANDROID_RELRCOUNT"
        else -> "DT_UNKNOWN_0x${tag.toString(16)}"
    }

    private val STRING_TAGS = mapOf(1L to "needed", 14L to "soname", 15L to "rpath", 29L to "runpath")

    /** DT_STRTAB bytes (length DT_STRSZ); string tag values are offsets into this table. */
    private fun dynstrBytes(data: ByteArray, elf: ElfFile): ByteArray? {
        val strtabVaddr = elf.dynamicEntries.firstOrNull { it.tag == 5L }?.value ?: return null
        val strsz = elf.dynamicEntries.firstOrNull { it.tag == 10L }?.value?.toInt() ?: 4096
        return bytesForVaddr(data, elf, strtabVaddr, strsz.coerceIn(1, 1 shl 20))
    }

    // ── elf_dynamic_tags ──

    fun dynamicTags(data: ByteArray, elf: ElfFile): JSONObject {
        val items = JSONArray()
        val dynstr = dynstrBytes(data, elf)
        elf.dynamicEntries.forEach { e ->
            val item = JSONObject()
                .put("tag", e.tag)
                .put("name", dynamicTagName(e.tag))
                .put("value", "0x${e.value.toString(16)}")
            val kind = STRING_TAGS[e.tag]
            // String tag values are offsets into DT_STRTAB, not vaddrs.
            if (kind != null && dynstr != null && e.value >= 0 && e.value < dynstr.size) {
                item.put(kind, cstr(dynstr, e.value.toInt()))
            }
            items.put(item)
        }
        return JSONObject()
            .put("count", elf.dynamicEntries.size)
            .put("items", items)
            .put(
                "method",
                "Decoded from PT_DYNAMIC (SHT_DYNAMIC fallback). String-valued tags resolved against DT_STRTAB/DT_STRSZ."
            )
    }

    // ── elf_dt_flags ──

    private val DF_FLAGS = linkedMapOf(
        0x1L to "DF_ORIGIN",
        0x2L to "DF_SYMBOLIC",
        0x4L to "DF_TEXTREL",
        0x8L to "DF_BIND_NOW",
        0x10L to "DF_STATIC_TLS"
    )

    private val DF_1_FLAGS = linkedMapOf(
        0x1L to "DF_1_NOW", 0x2L to "DF_1_GLOBAL", 0x4L to "DF_1_GROUP", 0x8L to "DF_1_NODELETE",
        0x10L to "DF_1_LOADFLTR", 0x20L to "DF_1_INITFIRST", 0x40L to "DF_1_NOOPEN", 0x80L to "DF_1_ORIGIN",
        0x100L to "DF_1_DIRECT", 0x400L to "DF_1_INTERPOSE", 0x800L to "DF_1_NODEFLIB", 0x1000L to "DF_1_NODUMP",
        0x2000L to "DF_1_CONFALT", 0x4000L to "DF_1_ENDFILTEE", 0x20000L to "DF_1_NODIRECT",
        0x08000000L to "DF_1_PIE"
    )

    private fun decodeFlagSet(raw: Long, table: Map<Long, String>): JSONArray {
        val out = JSONArray()
        table.forEach { (bit, name) ->
            if (raw and bit != 0L) out.put(JSONObject().put("name", name).put("bit", "0x${bit.toString(16)}"))
        }
        return out
    }

    fun dtFlags(elf: ElfFile): JSONObject {
        val flags = elf.dynamicEntries.firstOrNull { it.tag == 30L }
        val flags1 = elf.dynamicEntries.firstOrNull { it.tag == 0x6ffffffbL }
        val result = JSONObject()
            .put("dtFlagsPresent", flags != null)
            .put("dtFlags1Present", flags1 != null)
        if (flags != null) {
            result.put("dtFlags", "0x${flags.value.toString(16)}").put("dtFlagsDecoded", decodeFlagSet(flags.value, DF_FLAGS))
        }
        if (flags1 != null) {
            result.put("dtFlags1", "0x${flags1.value.toString(16)}").put("dtFlags1Decoded", decodeFlagSet(flags1.value, DF_1_FLAGS))
        }
        val bindNow = (flags?.value ?: 0L) and 0x8L != 0L || (flags1?.value ?: 0L) and 0x1L != 0L
        result.put("eagerBinding", bindNow)
        return result
    }

    // ── elf_hash_tables ──

    fun hashTables(data: ByteArray, elf: ElfFile): JSONObject {
        val result = JSONObject()
        val hashTag = elf.dynamicEntries.firstOrNull { it.tag == 4L }
        val gnuTag = elf.dynamicEntries.firstOrNull { it.tag == 0x6ffffef5L }
        var sysv: JSONObject? = null
        var gnu: JSONObject? = null
        if (hashTag != null) {
            val bytes = bytesForVaddr(data, elf, hashTag.value, 64 * 1024)
            if (bytes != null && bytes.size >= 8) {
                val nbuckets = u32(bytes, 0, elf.littleEndian).toInt()
                val nchain = u32(bytes, 4, elf.littleEndian).toInt()
                val table = JSONObject()
                    .put("kind", "sysv")
                    .put("vaddr", "0x${hashTag.value.toString(16)}")
                    .put("nbuckets", nbuckets)
                    .put("nchain", nchain)
                if (nbuckets in 1..65536) {
                    var maxLen = 0
                    var totalLen = 0L
                    for (b in 0 until nbuckets) {
                        var chain = u32(bytes, 8 + b * 4, elf.littleEndian).toInt()
                        var len = 0
                        while (chain != 0 && len < 4096) {
                            chain = u32(bytes, 8 + (nbuckets + chain) * 4, elf.littleEndian).toInt()
                            len++
                        }
                        maxLen = maxOf(maxLen, len)
                        totalLen += len
                    }
                    table.put("maxBucketChain", maxLen)
                    table.put("avgBucketChain", Math.round(totalLen * 100.0 / nbuckets) / 100.0)
                }
                sysv = table
            }
        }
        if (gnuTag != null) {
            val bytes = bytesForVaddr(data, elf, gnuTag.value, 512 * 1024)
            if (bytes != null && bytes.size >= 16) {
                val nbuckets = u32(bytes, 0, elf.littleEndian).toInt()
                val symoffset = u32(bytes, 4, elf.littleEndian).toInt()
                val bloomSize = u32(bytes, 8, elf.littleEndian).toInt()
                val bloomShift = u32(bytes, 12, elf.littleEndian).toInt()
                val table = JSONObject()
                    .put("kind", "gnu")
                    .put("vaddr", "0x${gnuTag.value.toString(16)}")
                    .put("nbuckets", nbuckets)
                    .put("symoffset", symoffset)
                    .put("bloomSize", bloomSize)
                    .put("bloomShift", bloomShift)
                val bucketsOff = 16 + bloomSize * if (elf.bits == 64) 8 else 4
                if (nbuckets in 1..65536 && bucketsOff >= 0) {
                    var maxLen = 0
                    var totalLen = 0L
                    var emptyBuckets = 0
                    for (b in 0 until nbuckets) {
                        val bucket = u32(bytes, bucketsOff + b * 4, elf.littleEndian).toInt()
                        if (bucket == 0) {
                            emptyBuckets++
                            continue
                        }
                        var chain = bucket
                        var len = 0
                        while (len < 4096) {
                            val chainOff = bucketsOff + nbuckets * 4 + (chain - symoffset) * 4
                            if (chainOff < 0 || chainOff + 4 > bytes.size) break
                            val value = u32(bytes, chainOff, elf.littleEndian)
                            len++
                            if (value and 1L != 0L) break
                            chain++
                        }
                        maxLen = maxOf(maxLen, len)
                        totalLen += len
                    }
                    table.put("maxBucketChain", maxLen)
                    table.put("avgBucketChain", Math.round(totalLen * 100.0 / nbuckets) / 100.0)
                    table.put("emptyBuckets", emptyBuckets)
                }
                gnu = table
            }
        }
        if (sysv != null) result.put("sysv", sysv)
        if (gnu != null) result.put("gnu", gnu)
        return result
            .put("hasSysv", sysv != null)
            .put("hasGnu", gnu != null)
            .put("method", "Bucket-chain statistics read in place from DT_HASH/DT_GNU_HASH. Truncated reads stop the walk and omit derived fields.")
    }

    // ── elf_reloc_census ──

    fun relocCensus(elf: ElfFile): JSONObject {
        val byType = LinkedHashMap<Long, Int>()
        val bySection = LinkedHashMap<String, Int>()
        var noSymbolNonRelative = 0
        elf.relocations.forEach { r ->
            byType.merge(r.type, 1, Int::plus)
            bySection.merge(r.section, 1, Int::plus)
            if (r.symbol.isBlank() && r.type != 1027L && r.type != 8L && r.type != 3L && r.type != 0L) noSymbolNonRelative++
        }
        val types = JSONArray()
        byType.entries.sortedByDescending { it.value }.forEach { (type, count) ->
            types.put(JSONObject().put("type", type).put("typeName", EngineJson.relocationTypeName(type)).put("count", count))
        }
        val sections = JSONArray()
        bySection.entries.sortedByDescending { it.value }.forEach { (name, count) ->
            sections.put(JSONObject().put("section", name).put("count", count))
        }
        return JSONObject()
            .put("total", elf.relocations.size)
            .put("byType", types)
            .put("bySection", sections)
            .put("unknownTypeCount", byType.keys.count { EngineJson.relocationTypeName(it).startsWith("UNKNOWN_") })
            .put("noSymbolNonRelative", noSymbolNonRelative)
            .put("machine", elf.machineName)
    }

    // ── dt_needed_resolve ──

    fun neededList(data: ByteArray, elf: ElfFile): List<String> {
        val dynstr = dynstrBytes(data, elf) ?: return emptyList()
        // DT_NEEDED/DT_SONAME/DT_RPATH/DT_RUNPATH values are byte offsets INTO the
        // string table, not vaddrs: no strtab-base subtraction here.
        return elf.dynamicEntries.filter { it.tag == 1L }.mapNotNull { e ->
            if (e.value < 0 || e.value > Int.MAX_VALUE) return@mapNotNull null
            cstr(dynstr, e.value.toInt()).takeIf { it.isNotBlank() }
        }
    }

    fun soname(data: ByteArray, elf: ElfFile): String? {
        val dynstr = dynstrBytes(data, elf) ?: return null
        val tag = elf.dynamicEntries.firstOrNull { it.tag == 14L } ?: return null
        if (tag.value < 0 || tag.value > Int.MAX_VALUE) return null
        return cstr(dynstr, tag.value.toInt()).takeIf { it.isNotBlank() }
    }

    // ── symbol_visibility_audit ──

    fun visibilityAudit(elf: ElfFile): JSONObject {
        val counts = LinkedHashMap<String, Int>()
        val hiddenExports = JSONArray()
        val protectedExports = JSONArray()
        val weakUndefined = JSONArray()
        elf.dynSymbols.forEach { s ->
            counts.merge("${s.visibility}/${s.bind}", 1, Int::plus)
            if (s.exported && s.visibility == "HIDDEN") hiddenExports.put(s.name)
            if (s.exported && s.visibility == "PROTECTED") protectedExports.put(s.name)
            if (s.imported && s.bind == "WEAK" && weakUndefined.length() < 50) weakUndefined.put(s.name)
        }
        val byPair = JSONArray()
        counts.entries.sortedByDescending { it.value }.forEach { (k, v) ->
            byPair.put(JSONObject().put("visibilityBind", k).put("count", v))
        }
        return JSONObject()
            .put("dynSymbolCount", elf.dynSymbols.size)
            .put("exported", elf.dynSymbols.count { it.exported })
            .put("imported", elf.dynSymbols.count { it.imported })
            .put("byVisibilityBind", byPair)
            .put("hiddenExports", hiddenExports)
            .put("protectedExports", protectedExports)
            .put("weakUndefined", weakUndefined)
            .put("method", "Dynsym surface grouped by visibility/binding. Hidden exported symbols are dead weight unless referenced internally.")
    }

    // ── caves (shared core of code_padding_caves / patch_cave_finder) ──

    data class Cave(val section: String, val index: Int, val fileOffset: Long, val va: Long, val size: Int, val fill: String)

    fun paddingCaves(data: ByteArray, elf: ElfFile, minSize: Int, execOnly: Boolean): List<Cave> {
        val caves = mutableListOf<Cave>()
        elf.sections.forEachIndexed { i, s ->
            if (s.type == SHT_NULL || s.type == SHT_NOBITS || s.size <= 0) return@forEachIndexed
            if (execOnly && s.flags and SHF_EXECINSTR == 0L) return@forEachIndexed
            if (s.flags and SHF_ALLOC == 0L) return@forEachIndexed
            val bytes = sectionBytes(data, s)
            var run = 0
            var fillByte = -1
            for (idx in 0..bytes.size) {
                val b = if (idx < bytes.size) bytes[idx].toInt() and 0xff else -1
                val isFill = b == 0x00 || b == 0x90 || b == 0xCC || b == 0x1F || b == -0x70
                if (isFill) {
                    if (run == 0) fillByte = b
                    if (b == fillByte) {
                        run++
                        continue
                    }
                }
                if (run >= minSize) {
                    val off = s.offset + (idx - run)
                    val va = s.addr + (idx - run)
                    caves += Cave(
                        s.name,
                        i,
                        off,
                        va,
                        run,
                        when (fillByte) {
                            0x00 -> "zero"
                            0x90 -> "x86_nop"
                            0xCC -> "int3"
                            0x1F -> "aarch64_nop_prefix"
                            else -> "mixed"
                        }
                    )
                }
                run = if (isFill) 1 else 0
                fillByte = if (isFill) b else -1
            }
        }
        return caves
    }
}
