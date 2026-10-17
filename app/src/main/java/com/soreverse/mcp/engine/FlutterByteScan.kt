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
//
package com.soreverse.mcp.engine

import java.io.File
import java.io.IOException
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.StandardOpenOption

/**
 * Read-only little-endian view over a byte range, backed either by a heap array
 * or by a memory-mapped file.
 *
 * The Flutter inspector needs random access into `libapp.so` / `libflutter.so`
 * (ELF headers, section table, symbol tables, `.rodata`). Doing that on a
 * `ByteArray` forces the whole library into the process heap: the pages become
 * anonymous dirty memory that the kernel can only reclaim by killing the
 * process. A mapped file is file-backed instead, so clean pages can be dropped
 * under pressure and re-read from the page cache. That distinction is the whole
 * point of this abstraction — it is not a micro-optimisation.
 *
 * Every read is bounds-checked and returns zero outside the view, matching the
 * previous `slice()`-based behaviour (which produced an empty array for an
 * out-of-range window) so a truncated or hostile library degrades into "no
 * evidence" instead of throwing in the middle of a parse.
 */
internal interface ByteView {
    val size: Long

    fun u8(offset: Long): Int

    fun u16(offset: Long): Int

    fun u32(offset: Long): Long

    fun u64(offset: Long): Long

    /** Copies [length] bytes at [offset] into [destination]. Never allocates. */
    fun copyInto(offset: Long, destination: ByteArray, destinationOffset: Int, length: Int)

    fun copy(offset: Long, length: Int): ByteArray

    /** ASCII decode of a bounded window; non-ASCII bytes become `?`. */
    fun ascii(offset: Long, length: Int): String
}

internal class ArrayByteView(private val bytes: ByteArray) : ByteView {
    override val size: Long get() = bytes.size.toLong()

    override fun u8(offset: Long): Int = if (offset < 0 || offset >= bytes.size) 0 else bytes[offset.toInt()].toInt() and 0xff

    override fun u16(offset: Long): Int {
        if (offset < 0 || offset + 2 > bytes.size) return 0
        val index = offset.toInt()
        return (bytes[index].toInt() and 0xff) or ((bytes[index + 1].toInt() and 0xff) shl 8)
    }

    override fun u32(offset: Long): Long {
        if (offset < 0 || offset + 4 > bytes.size) return 0
        val index = offset.toInt()
        return (bytes[index].toLong() and 0xff) or
            ((bytes[index + 1].toLong() and 0xff) shl 8) or
            ((bytes[index + 2].toLong() and 0xff) shl 16) or
            ((bytes[index + 3].toLong() and 0xff) shl 24)
    }

    override fun u64(offset: Long): Long {
        if (offset < 0 || offset + 8 > bytes.size) return 0
        return u32(offset) or (u32(offset + 4) shl 32)
    }

    override fun copyInto(offset: Long, destination: ByteArray, destinationOffset: Int, length: Int) {
        if (length <= 0 || offset < 0 || offset >= bytes.size) return
        val available = minOf(length.toLong(), bytes.size - offset).toInt()
        System.arraycopy(bytes, offset.toInt(), destination, destinationOffset, available)
    }

    override fun copy(offset: Long, length: Int): ByteArray {
        if (length <= 0 || offset < 0 || offset >= bytes.size) return ByteArray(0)
        val available = minOf(length.toLong(), bytes.size - offset).toInt()
        return bytes.copyOfRange(offset.toInt(), offset.toInt() + available)
    }

    override fun ascii(offset: Long, length: Int): String = copy(offset, length).toString(StandardCharsets.US_ASCII)
}

internal class MappedByteView(private val buffer: MappedByteBuffer) : ByteView {
    override val size: Long get() = buffer.capacity().toLong()

    override fun u8(offset: Long): Int = if (offset < 0 || offset >= size) 0 else buffer.get(offset.toInt()).toInt() and 0xff

    override fun u16(offset: Long): Int = if (offset < 0 || offset + 2 > size) 0 else buffer.getShort(offset.toInt()).toInt() and 0xffff

    override fun u32(offset: Long): Long = if (offset < 0 || offset + 4 > size) 0 else buffer.getInt(offset.toInt()).toLong() and 0xffffffffL

    override fun u64(offset: Long): Long = if (offset < 0 || offset + 8 > size) 0 else buffer.getLong(offset.toInt())

    override fun copyInto(offset: Long, destination: ByteArray, destinationOffset: Int, length: Int) {
        if (length <= 0 || offset < 0 || offset >= size) return
        val available = minOf(length.toLong(), size - offset).toInt()
        // Absolute reads are not available below API 33 for the bulk form, so
        // move the position instead; a view is only ever used by one thread.
        buffer.position(offset.toInt())
        buffer.get(destination, destinationOffset, available)
    }

    override fun copy(offset: Long, length: Int): ByteArray {
        if (length <= 0 || offset < 0 || offset >= size) return ByteArray(0)
        val available = minOf(length.toLong(), size - offset).toInt()
        val out = ByteArray(available)
        copyInto(offset, out, 0, available)
        return out
    }

    override fun ascii(offset: Long, length: Int): String = copy(offset, length).toString(StandardCharsets.US_ASCII)
}

internal object ByteViews {
    fun of(bytes: ByteArray): ByteView = ArrayByteView(bytes)

    /**
     * Maps [file] read-only. The mapping is released when the returned view is
     * collected, and its pages are reclaimable while it is alive, so this never
     * counts against the process heap limit.
     *
     * Throws [IOException] when the backing filesystem cannot be mapped (some
     * FUSE / SAF mounts); callers fall back to a heap read.
     */
    fun map(file: File): ByteView {
        require(file.length() <= Int.MAX_VALUE) { "INPUT_LIMIT_EXCEEDED: ${file.name} is too large to map" }
        FileChannel.open(file.toPath(), StandardOpenOption.READ).use { channel ->
            val length = channel.size()
            if (length <= 0L) throw IOException("Cannot map an empty file: ${file.name}")
            val mapped = channel.map(FileChannel.MapMode.READ_ONLY, 0, length)
            mapped.order(ByteOrder.LITTLE_ENDIAN)
            return MappedByteView(mapped)
        }
    }
}

/**
 * Bounded byte-level scans over [ByteView].
 *
 * These replace the previous "decode the whole `.rodata` into a `String` and run
 * regexes over it" approach. On a 30 MiB `.rodata` that produced two full copies
 * (the section slice plus the ASCII string) purely to read a 40-character engine
 * id and a version literal. Scanning in fixed windows keeps the working set at
 * one 64 KiB buffer regardless of section size.
 */
internal object FlutterByteScan {
    const val HEX_ID_LENGTH = 40

    private const val WINDOW_BYTES = 64 * 1024
    private const val MAX_ENGINE_IDS = 64
    private const val MAX_VERSION_LENGTH = 64
    private const val MAX_VERSION_PROBES = 256
    private const val MAX_SYMBOL_NAME_LENGTH = 512

    /** Enough to re-examine a version suffix that straddles a window boundary. */
    private const val CARRY_BYTES = 12
    private val SPACE = ' '.code.toByte()

    private val VERSION_SUFFIXES = listOf(" (stable)", " (beta)", " (dev)")

    /**
     * Every run of exactly [HEX_ID_LENGTH] lowercase hex digits that is delimited
     * by non-hex bytes on both sides, in file order and de-duplicated.
     *
     * This is the byte-level equivalent of `(?<![a-f0-9])([a-f0-9]{40})(?![a-f0-9])`
     * — lowercase only, exactly as the previous regex — so a longer run is not
     * truncated into a match, and a run that ends at the end of the range still
     * counts (the lookahead succeeds at end of input).
     */
    fun engineIds(view: ByteView, offset: Long, length: Long, limit: Int = MAX_ENGINE_IDS): List<String> {
        val scanner = HexRunScanner(minOf(limit, MAX_ENGINE_IDS))
        forEachWindow(view, offset, length) { buffer, count ->
            if (scanner.isFull) return@forEachWindow
            for (index in 0 until count) scanner.feed(buffer[index].toInt() and 0xff)
        }
        scanner.close()
        return scanner.ids
    }

    /**
     * First `<version> (stable|beta|dev)` literal in the range, where `<version>`
     * is a maximal run of `[0-9A-Za-z_.-]` immediately before the space.
     *
     * Matches the leftmost-regex semantics of the previous implementation: the
     * earliest suffix occurrence wins, and an occurrence with no version run in
     * front of it is skipped rather than ending the search.
     */
    fun dartVersion(view: ByteView, offset: Long, length: Long): String? {
        val end = minOf(offset + length, view.size)
        if (end <= offset) return null
        val buffer = ByteArray(WINDOW_BYTES)
        var position = offset
        var carry = 0
        var probes = 0
        while (position < end) {
            val count = minOf((WINDOW_BYTES - carry).toLong(), end - position).toInt()
            if (count <= 0) break
            view.copyInto(position, buffer, carry, count)
            val available = carry + count
            val base = position - carry
            for (index in 0 until available) {
                if (buffer[index] != SPACE) continue
                val hit = base + index
                if (suffixLengthAt(buffer, index, available, view, hit, end) == 0) continue
                probes++
                var start = hit
                var steps = 0
                while (start > offset && steps < MAX_VERSION_LENGTH && isVersionByte(view.u8(start - 1))) {
                    start--
                    steps++
                }
                if (start < hit) return view.ascii(start, (hit - start).toInt())
                if (probes >= MAX_VERSION_PROBES) return null
            }
            val keep = minOf(CARRY_BYTES, available)
            System.arraycopy(buffer, available - keep, buffer, 0, keep)
            carry = keep
            position += count
        }
        return null
    }

    /** NUL-terminated ASCII-ish string, bounded so a corrupt table cannot run away. */
    fun cString(view: ByteView, offset: Long, limit: Int = MAX_SYMBOL_NAME_LENGTH): String {
        if (offset < 0 || offset >= view.size) return ""
        val end = minOf(view.size, offset + limit)
        var length = 0
        while (offset + length < end && view.u8(offset + length) != 0) length++
        return view.ascii(offset, length)
    }

    /**
     * Length of the version suffix starting at [index] of the current window, or 0.
     * Bytes past [available] are read from [view] directly, so a suffix that
     * straddles a window boundary is still recognised.
     */
    private fun suffixLengthAt(buffer: ByteArray, index: Int, available: Int, view: ByteView, absolute: Long, end: Long): Int {
        for (suffix in VERSION_SUFFIXES) {
            if (absolute + suffix.length > end) continue
            var matched = true
            for (probe in suffix.indices) {
                val value = if (index + probe < available) {
                    buffer[index + probe].toInt() and 0xff
                } else {
                    view.u8(absolute + probe)
                }
                if (value != suffix[probe].code) {
                    matched = false
                    break
                }
            }
            if (matched) return suffix.length
        }
        return 0
    }

    private inline fun forEachWindow(view: ByteView, offset: Long, length: Long, block: (ByteArray, Int) -> Unit) {
        if (length <= 0) return
        val end = minOf(offset + length, view.size)
        val buffer = ByteArray(WINDOW_BYTES)
        var position = offset
        while (position < end) {
            val count = minOf(WINDOW_BYTES.toLong(), end - position).toInt()
            view.copyInto(position, buffer, 0, count)
            block(buffer, count)
            position += count
        }
    }

    private fun isVersionByte(value: Int): Boolean = (value in '0'.code..'9'.code) ||
        (value in 'a'.code..'z'.code) ||
        (value in 'A'.code..'Z'.code) ||
        value == '_'.code ||
        value == '.'.code ||
        value == '-'.code
}

private fun isHexByte(value: Int): Boolean = (value in '0'.code..'9'.code) || (value in 'a'.code..'f'.code)

private class HexRunScanner(private val limit: Int) {
    private val run = CharArray(FlutterByteScan.HEX_ID_LENGTH)
    private var runLength = 0
    private val seen = LinkedHashSet<String>()

    val ids: List<String> get() = seen.toList()

    val isFull: Boolean get() = seen.size >= limit

    fun feed(value: Int) {
        if (!isHexByte(value)) {
            close()
            return
        }
        if (runLength < FlutterByteScan.HEX_ID_LENGTH) {
            run[runLength] = value.toChar()
            runLength++
        } else {
            // Longer than an id: keep counting so close() can reject it.
            runLength = FlutterByteScan.HEX_ID_LENGTH + 1
        }
    }

    fun close() {
        if (runLength == FlutterByteScan.HEX_ID_LENGTH && seen.size < limit) {
            seen.add(String(run, 0, FlutterByteScan.HEX_ID_LENGTH))
        }
        runLength = 0
    }
}
