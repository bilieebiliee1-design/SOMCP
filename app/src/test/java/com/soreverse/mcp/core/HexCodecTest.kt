package com.soreverse.mcp.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HexCodecTest {
    @Test
    fun parsesAddressesWithPrefix() {
        assertEquals(0x1234L, HexCodec.long(" 0x1234 "))
    }

    @Test
    fun parsesSpacedCommaSeparatedBytes() {
        assertArrayEquals(byteArrayOf(0x01, 0xAF.toByte(), 0x20), HexCodec.bytes("01 af,20"))
    }

    @Test
    fun rejectsMalformedHex() {
        assertNull(HexCodec.bytes("123"))
        assertNull(HexCodec.bytes("zz"))
        assertNull(HexCodec.long("0xnope"))
    }
}
