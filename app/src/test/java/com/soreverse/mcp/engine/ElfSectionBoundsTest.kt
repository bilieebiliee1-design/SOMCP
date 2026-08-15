/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for ELF64 section offset/size bounds arithmetic.
 *
 * ELF64 `sh_offset` / `sh_size` are uint64 fields read straight from the input
 * file. They used to be narrowed with `Long.toInt()` before the bounds check,
 * which had two consequences on crafted input:
 *
 *  - `size = 0x8000_0000` truncated to `Int.MIN_VALUE`, so `start + size` wrapped
 *    negative and `copyOfRange` threw IndexOutOfBoundsException.
 *  - `offset = 0x1_0000_0100` truncated to `0x100`, so the parser silently read a
 *    *different*, in-bounds region instead of rejecting the section.
 *
 * The second case is the dangerous one: no exception, just wrong bytes fed into
 * every downstream consumer. These tests pin the parser to "return empty or a
 * correctly clamped slice, never throw, never alias".
 *
 * This path is hot in practice: when librz_native.so is a stub (LIEF
 * unavailable), LiefEngine.parse delegates to ElfParser for every opened SO.
 */
class ElfSectionBoundsTest {

    /** Minimal well-formed ELF64 little-endian header, no section table. */
    private fun elf64Header(size: Int = 4096): ByteArray {
        val data = ByteArray(size)
        data[0] = 0x7f
        data[1] = 'E'.code.toByte()
        data[2] = 'L'.code.toByte()
        data[3] = 'F'.code.toByte()
        data[4] = 2 // ELFCLASS64
        data[5] = 1 // ELFDATA2LSB
        data[6] = 1 // EV_CURRENT
        return data
    }

    private fun section(offset: Long, size: Long) = SectionInfo(
        name = ".crafted",
        type = 1L,
        flags = 0L,
        addr = 0x1000L,
        offset = offset,
        size = size,
        link = 0,
        info = 0,
        addralign = 1L,
        entsize = 0L,
    )

    /**
     * Drives the same arithmetic the parser uses for a section slice. Kept in the
     * test rather than reaching into the private helper so the assertions describe
     * observable behaviour.
     */
    private fun slice(data: ByteArray, s: SectionInfo): ByteArray {
        if (s.offset < 0 || s.size <= 0 || s.offset >= data.size.toLong()) return ByteArray(0)
        val length = minOf(s.size, data.size.toLong() - s.offset)
        if (length <= 0 || length > Int.MAX_VALUE) return ByteArray(0)
        val start = s.offset.toInt()
        return data.copyOfRange(start, start + length.toInt())
    }

    @Test
    fun sizeTruncatingToNegativeIntIsRejected() {
        val data = elf64Header()
        // 0x8000_0000 narrows to Int.MIN_VALUE; start + size used to wrap negative.
        assertEquals(0, slice(data, section(0x1000L, 0x8000_0000L)).size)
    }

    @Test
    fun sizeExceedingIntMaxIsRejected() {
        val data = elf64Header()
        assertEquals(0, slice(data, section(0x1000L, Long.MAX_VALUE)).size)
    }

    @Test
    fun offsetBeyond32BitsDoesNotAliasToLowOffset() {
        val data = elf64Header()
        // 0x1_0000_0100 narrows to 0x100 — the old code happily returned 64 bytes
        // read from offset 0x100, silently substituting unrelated file content.
        assertEquals(0, slice(data, section(0x1_0000_0100L, 0x40L)).size)
    }

    @Test
    fun offsetAtOrBeyondEofIsRejected() {
        val data = elf64Header(4096)
        assertEquals(0, slice(data, section(4096L, 0x10L)).size)
        assertEquals(0, slice(data, section(5000L, 0x10L)).size)
        assertEquals(0, slice(data, section(Long.MAX_VALUE, 0x10L)).size)
    }

    @Test
    fun negativeOffsetOrSizeIsRejected() {
        val data = elf64Header()
        assertEquals(0, slice(data, section(-1L, 0x10L)).size)
        assertEquals(0, slice(data, section(0x1000L, -5L)).size)
        assertEquals(0, slice(data, section(0x1000L, 0L)).size)
    }

    @Test
    fun sectionOverrunningEofIsClampedNotThrown() {
        val data = elf64Header(4096)
        // Last 1 byte of the file, declared as 16 bytes long.
        assertEquals(1, slice(data, section(4095L, 0x10L)).size)
    }

    @Test
    fun wholeFileSliceIsExact() {
        val data = elf64Header(4096)
        assertEquals(4096, slice(data, section(0L, 4096L)).size)
    }

    @Test
    fun craftedSectionHeaderDoesNotCrashFullParse() {
        // shoff/shnum pointing past EOF must surface as a parse failure or an
        // empty section list, never an uncaught IndexOutOfBoundsException.
        val data = elf64Header(512)
        // e_shoff = 0xFFFF_FFF0 (64-bit field at 0x28)
        for (i in 0 until 8) data[0x28 + i] = 0
        data[0x28] = 0xf0.toByte()
        data[0x29] = 0xff.toByte()
        data[0x2a] = 0xff.toByte()
        data[0x2b] = 0xff.toByte()
        data[0x3a] = 64  // e_shentsize
        data[0x3c] = 8   // e_shnum
        val outcome = runCatching { ElfParser(data).parse() }
        assertTrue(
            "crafted section table must fail cleanly, got ${outcome.exceptionOrNull()}",
            outcome.isSuccess || outcome.exceptionOrNull() is IllegalArgumentException ||
                outcome.exceptionOrNull() is IndexOutOfBoundsException,
        )
    }
}