package com.soreverse.mcp.engine

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PatchByteUtilsTest {
    @Test
    fun patchJsonKeepsFields() {
        val json = PatchByteUtils.patchJson(PatchRecord(12L, "asm", "symbol:foo", 16, "00 FF", "90", "nop"))

        assertEquals(12L, json.getLong("timeMillis"))
        assertEquals("asm", json.getString("kind"))
        assertEquals("symbol:foo", json.getString("locator"))
        assertEquals("0x10", json.getString("fileOffset"))
        assertEquals("00 FF", json.getString("oldHex"))
        assertEquals("90", json.getString("newHex"))
        assertEquals("nop", json.getString("asm"))
        assertTrue(PatchByteUtils.patchJson(PatchRecord(0, "hex", "", 0, "", "")).isNull("asm"))
    }

    @Test
    fun formatsHexAsUppercaseWithSpaces() {
        assertEquals("00 0F A0 FF", PatchByteUtils.hexBytes(byteArrayOf(0, 15, 160.toByte(), 255.toByte())))
    }

    @Test
    fun returnsArchitectureNops() {
        assertEquals("1F 20 03 D5", PatchByteUtils.hexBytes(PatchByteUtils.architectureNop("arm64", false)))
        assertEquals("00 BF", PatchByteUtils.hexBytes(PatchByteUtils.architectureNop("arm32", true)))
        assertEquals("00 F0 20 E3", PatchByteUtils.hexBytes(PatchByteUtils.architectureNop("arm32", false)))
        assertEquals("00 00 00 00", PatchByteUtils.hexBytes(PatchByteUtils.architectureNop("mips", false)))
        assertEquals("90", PatchByteUtils.hexBytes(PatchByteUtils.architectureNop("x86_64", false)))
    }

    @Test
    fun repeatsAndTruncatesPattern() {
        assertEquals("01 02 01 02 01", PatchByteUtils.hexBytes(PatchByteUtils.repeatBytes(byteArrayOf(1, 2), 5)))
        assertEquals("01", PatchByteUtils.hexBytes(PatchByteUtils.repeatBytes(byteArrayOf(1, 2), 1)))
        assertEquals(0, PatchByteUtils.repeatBytes(byteArrayOf(), 5).size)
        assertEquals(0, PatchByteUtils.repeatBytes(byteArrayOf(1), 0).size)
        assertEquals(0, PatchByteUtils.repeatBytes(byteArrayOf(1), -1).size)
    }

    @Test
    fun reportsSameSingleAndMultipleDiffRanges() {
        assertEquals(0, PatchByteUtils.byteDiffRanges(byteArrayOf(1, 2), byteArrayOf(1, 2)).length())

        val single = PatchByteUtils.byteDiffRanges(byteArrayOf(1, 2, 3), byteArrayOf(1, 9, 3)).getJSONObject(0)
        assertRange(single, "0x1", 1, "02", "09")

        val multiple = PatchByteUtils.byteDiffRanges(byteArrayOf(1, 2, 3, 4, 5), byteArrayOf(9, 2, 8, 4, 7))
        assertEquals(3, multiple.length())
        assertRange(multiple.getJSONObject(0), "0x0", 1, "01", "09")
        assertRange(multiple.getJSONObject(1), "0x2", 1, "03", "08")
        assertRange(multiple.getJSONObject(2), "0x4", 1, "05", "07")
    }

    @Test
    fun reportsDifferentArrayLengths() {
        val ranges = PatchByteUtils.byteDiffRanges(byteArrayOf(1, 2), byteArrayOf(1, 2, 3, 4))

        assertEquals(1, ranges.length())
        assertRange(ranges.getJSONObject(0), "0x2", 2, "", "03 04")
    }

    private fun assertRange(json: JSONObject, offset: String, length: Int, oldHex: String, newHex: String) {
        assertEquals(offset, json.getString("fileOffset"))
        assertEquals(length, json.getInt("length"))
        assertEquals(oldHex, json.getString("oldHex"))
        assertEquals(newHex, json.getString("newHex"))
    }
}
