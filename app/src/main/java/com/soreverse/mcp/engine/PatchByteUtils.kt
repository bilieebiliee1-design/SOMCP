package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal object PatchByteUtils {
    fun patchJson(patch: PatchRecord): JSONObject =
        JSONObject()
            .put("timeMillis", patch.timeMillis)
            .put("kind", patch.kind)
            .put("locator", patch.locator)
            .put("fileOffset", hex(patch.fileOffset.toLong()))
            .put("oldHex", patch.oldHex)
            .put("newHex", patch.newHex)
            .put("asm", patch.asm.ifBlank { JSONObject.NULL })

    fun hexBytes(bytes: ByteArray): String = bytes.joinToString(" ") { "%02X".format(it) }

    fun architectureNop(architecture: String, thumb: Boolean): ByteArray = when (architecture) {
        "arm64" -> byteArrayOf(0x1f, 0x20, 0x03, 0xd5.toByte())
        "arm32" -> if (thumb) byteArrayOf(0x00, 0xbf.toByte()) else byteArrayOf(0x00, 0xf0.toByte(), 0x20, 0xe3.toByte())
        "mips" -> byteArrayOf(0x00, 0x00, 0x00, 0x00)
        else -> byteArrayOf(0x90.toByte())
    }

    fun repeatBytes(pattern: ByteArray, length: Int): ByteArray {
        if (length <= 0 || pattern.isEmpty()) return ByteArray(0)
        val out = ByteArray(length)
        var pos = 0
        while (pos < length) {
            val n = minOf(pattern.size, length - pos)
            System.arraycopy(pattern, 0, out, pos, n)
            pos += n
        }
        return out
    }

    fun byteDiffRanges(a: ByteArray, b: ByteArray): JSONArray {
        val ranges = JSONArray()
        val maxLen = maxOf(a.size, b.size)
        var i = 0
        while (i < maxLen) {
            val same = i < a.size && i < b.size && a[i] == b[i]
            if (same) {
                i++
                continue
            }
            val start = i
            while (i < maxLen && !(i < a.size && i < b.size && a[i] == b[i])) i++
            val oldBytes = if (start < a.size) a.copyOfRange(start, minOf(i, a.size)) else ByteArray(0)
            val newBytes = if (start < b.size) b.copyOfRange(start, minOf(i, b.size)) else ByteArray(0)
            ranges.put(JSONObject().put("fileOffset", hex(start.toLong())).put("length", i - start).put("oldHex", hexBytes(oldBytes)).put("newHex", hexBytes(newBytes)))
        }
        return ranges
    }

    private fun hex(value: Long) = "0x${value.toString(16)}"
}
