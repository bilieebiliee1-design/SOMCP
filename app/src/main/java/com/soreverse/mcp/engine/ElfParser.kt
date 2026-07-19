package com.soreverse.mcp.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import kotlin.math.min

class ElfParser(private val data: ByteArray) {
    fun parse(): ElfFile {
        require(data.size >= 16 && data[0] == 0x7f.toByte() && data[1] == 'E'.code.toByte() && data[2] == 'L'.code.toByte() && data[3] == 'F'.code.toByte()) {
            "Not an ELF file"
        }
        val bits = if (data[4].toInt() == 2) 64 else 32
        val little = data[5].toInt() != 2
        val r = Reader(data, little)
        val type = r.u16(16)
        val machine = r.u16(18)
        val entry = if (bits == 64) r.u64(24) else r.u32(24)
        val shoff = if (bits == 64) r.u64(40) else r.u32(32)
        val shentsize = if (bits == 64) r.u16(58) else r.u16(46)
        val shnum = if (bits == 64) r.u16(60) else r.u16(48)
        val shstrndx = if (bits == 64) r.u16(62) else r.u16(50)

        val rawSections = (0 until shnum).map { idx ->
            val off = (shoff + idx.toLong() * shentsize).toInt()
            RawSection(
                nameOffset = r.u32(off).toInt(),
                type = r.u32(off + 4),
                flags = if (bits == 64) r.u64(off + 8) else r.u32(off + 8),
                addr = if (bits == 64) r.u64(off + 16) else r.u32(off + 12),
                offset = if (bits == 64) r.u64(off + 24) else r.u32(off + 16),
                size = if (bits == 64) r.u64(off + 32) else r.u32(off + 20),
                link = if (bits == 64) r.u32(off + 40).toInt() else r.u32(off + 24).toInt(),
                info = if (bits == 64) r.u32(off + 44).toInt() else r.u32(off + 28).toInt(),
                addralign = if (bits == 64) r.u64(off + 48) else r.u32(off + 32),
                entsize = if (bits == 64) r.u64(off + 56) else r.u32(off + 36),
            )
        }
        val shstr = rawSections.getOrNull(shstrndx)?.bytes(data) ?: ByteArray(0)
        val sections = rawSections.map {
            SectionInfo(
                name = cstr(shstr, it.nameOffset),
                type = it.type,
                flags = it.flags,
                addr = it.addr,
                offset = it.offset,
                size = it.size,
                link = it.link,
                info = it.info,
                addralign = it.addralign,
                entsize = it.entsize,
            )
        }
        val symbols = mutableListOf<SymbolInfo>()
        val dynSymbols = mutableListOf<SymbolInfo>()
        for ((index, sec) in sections.withIndex()) {
            if (sec.type != 2L && sec.type != 11L) continue
            val strtab = sections.getOrNull(sec.link)?.let { sectionBytes(it) } ?: ByteArray(0)
            val count = if (sec.entsize > 0) (sec.size / sec.entsize).toInt() else 0
            val dest = if (sec.type == 11L) dynSymbols else symbols
            for (i in 0 until count) {
                val off = (sec.offset + i * sec.entsize).toInt()
                if (off < 0 || off >= data.size) continue
                val nameOffset: Int
                val info: Int
                val other: Int
                val shndx: Int
                val value: Long
                val size: Long
                if (bits == 64) {
                    nameOffset = r.u32(off).toInt()
                    info = r.u8(off + 4)
                    other = r.u8(off + 5)
                    shndx = r.u16(off + 6)
                    value = r.u64(off + 8)
                    size = r.u64(off + 16)
                } else {
                    nameOffset = r.u32(off).toInt()
                    value = r.u32(off + 4)
                    size = r.u32(off + 8)
                    info = r.u8(off + 12)
                    other = r.u8(off + 13)
                    shndx = r.u16(off + 14)
                }
                val name = cstr(strtab, nameOffset)
                if (name.isEmpty()) continue
                val bind = when (info ushr 4) { 0 -> "LOCAL"; 1 -> "GLOBAL"; 2 -> "WEAK"; else -> "OTHER" }
                val typ = when (info and 0xf) { 0 -> "NOTYPE"; 1 -> "OBJECT"; 2 -> "FUNC"; 6 -> "TLS"; else -> "OTHER" }
                val vis = when (other and 0x3) { 0 -> "DEFAULT"; 1 -> "INTERNAL"; 2 -> "HIDDEN"; 3 -> "PROTECTED"; else -> "DEFAULT" }
                dest += SymbolInfo(name, bind, typ, vis, shndx, value, size, shndx == 0, bind != "LOCAL" && shndx != 0)
            }
        }
        val allSymbols = symbols + dynSymbols
        val relocs = mutableListOf<RelocInfo>()
        for (sec in sections) {
            if (sec.type != 9L && sec.type != 4L) continue
            val symtab = if (sec.link in sections.indices) {
                val linked = sections[sec.link]
                if (linked.type == 11L) dynSymbols else symbols
            } else allSymbols
            val count = if (sec.entsize > 0) (sec.size / sec.entsize).toInt() else 0
            for (i in 0 until count) {
                val off = (sec.offset + i * sec.entsize).toInt()
                val relocOffset: Long
                val info: Long
                val addend: Long
                if (bits == 64) {
                    relocOffset = r.u64(off)
                    info = r.u64(off + 8)
                    addend = if (sec.type == 4L) r.s64(off + 16) else 0L
                } else {
                    relocOffset = r.u32(off)
                    info = r.u32(off + 4)
                    addend = if (sec.type == 4L) r.s32(off + 8).toLong() else 0L
                }
                val symIndex = if (bits == 64) (info ushr 32).toInt() else (info ushr 8).toInt()
                val relocType = if (bits == 64) info and 0xffffffffL else info and 0xff
                relocs += RelocInfo(sec.name, relocOffset, relocType, symtab.getOrNull(symIndex)?.name.orEmpty(), addend)
            }
        }
        val strings = mutableListOf<StringInfo>()
        for (sec in sections) {
            if (sec.name !in setOf(".rodata", ".strtab", ".dynstr")) continue
            extractStrings(sectionBytes(sec), sec.offset, sec.name, strings)
        }
        return ElfFile(data, bits, little, type, machine, entry, sections, symbols, dynSymbols, relocs, strings)
    }

    private fun sectionBytes(section: SectionInfo): ByteArray {
        if (section.offset < 0 || section.size <= 0) return ByteArray(0)
        val start = section.offset.toInt().coerceIn(0, data.size)
        val end = min(data.size, start + section.size.toInt())
        return data.copyOfRange(start, end)
    }

    private fun extractStrings(bytes: ByteArray, base: Long, section: String, out: MutableList<StringInfo>) {
        var start = 0
        var i = 0
        while (i <= bytes.size) {
            if (i == bytes.size || bytes[i] == 0.toByte()) {
                emitStringCandidate(bytes, start, i, base, section, out)
                start = i + 1
            }
            i++
        }
    }

    private fun emitStringCandidate(bytes: ByteArray, start: Int, end: Int, base: Long, section: String, out: MutableList<StringInfo>) {
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
        if (useful && mostlyText) {
            out += StringInfo(base + start, clean.take(1024), raw.size, section)
        }
    }

    private fun cstr(bytes: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= bytes.size) return ""
        var end = offset
        while (end < bytes.size && bytes[end] != 0.toByte()) end++
        return bytes.copyOfRange(offset, end).toString(Charsets.UTF_8)
    }

    private data class RawSection(
        val nameOffset: Int,
        val type: Long,
        val flags: Long,
        val addr: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val info: Int,
        val addralign: Long,
        val entsize: Long,
    ) {
        fun bytes(data: ByteArray): ByteArray {
            val start = offset.toInt().coerceIn(0, data.size)
            val end = min(data.size, start + size.toInt().coerceAtLeast(0))
            return data.copyOfRange(start, end)
        }
    }

    private class Reader(private val bytes: ByteArray, little: Boolean) {
        private val order = if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        fun u8(o: Int): Int = bytes[o].toInt() and 0xff
        fun u16(o: Int): Int = ByteBuffer.wrap(bytes, o, 2).order(order).short.toInt() and 0xffff
        fun u32(o: Int): Long = ByteBuffer.wrap(bytes, o, 4).order(order).int.toLong() and 0xffffffffL
        fun s32(o: Int): Int = ByteBuffer.wrap(bytes, o, 4).order(order).int
        fun u64(o: Int): Long = ByteBuffer.wrap(bytes, o, 8).order(order).long
        fun s64(o: Int): Long = ByteBuffer.wrap(bytes, o, 8).order(order).long
    }
}
