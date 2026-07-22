package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DisasmCursorCodecTest {
    @Test
    fun roundTripsCursor() {
        val cursor = DisasmCursorCodec.encode("workspace", "session", "so_function:foo/bar?x=1", 32, 50, 4096)

        assertEquals(
            DisasmCursorState("workspace", "session", "so_function:foo/bar?x=1", 32, 50, 4096),
            DisasmCursorCodec.decode(cursor),
        )
        assertEquals(false, cursor.contains('='))
    }

    @Test
    fun roundTripsEmptyEditSession() {
        val cursor = DisasmCursorCodec.encode("workspace", "", "so_function:main", 0, 1, 256)

        assertEquals(DisasmCursorState("workspace", "", "so_function:main", 0, 1, 256), DisasmCursorCodec.decode(cursor))
    }

    @Test
    fun clampsBoundaryValues() {
        val lowerCursor = DisasmCursorCodec.encode("w", "e", "l", -10, 0, 1)
        val upperCursor = DisasmCursorCodec.encode("w", "e", "l", Int.MAX_VALUE, 5001, 65537)

        assertEquals(DisasmCursorState("w", "e", "l", 0, 1, 256), DisasmCursorCodec.decode(lowerCursor))
        assertEquals(DisasmCursorState("w", "e", "l", Int.MAX_VALUE, 5000, 65536), DisasmCursorCodec.decode(upperCursor))
        assertEquals(DisasmCursorState("f", "e", "l", 0, 1, 256), DisasmCursorCodec.decode("disasm:Zg:ZQ:bA:-10:0:1"))
        assertEquals(DisasmCursorState("f", "e", "l", Int.MAX_VALUE, 5000, 65536), DisasmCursorCodec.decode("disasm:Zg:ZQ:bA:2147483647:5001:65537"))
    }

    @Test
    fun rejectsInvalidPrefix() {
        assertNull(DisasmCursorCodec.decode("cursor:Zg:ZQ:b:1:1:256"))
    }

    @Test
    fun rejectsWrongSegmentCount() {
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:b:1:256"))
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:b:1:1:256:extra"))
    }

    @Test
    fun rejectsInvalidBase64() {
        assertNull(DisasmCursorCodec.decode("disasm:!:ZQ:b:1:1:256"))
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:bad*:1:1:256"))
    }

    @Test
    fun rejectsInvalidNumbers() {
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:b:not-a-number:1:256"))
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:b:1:not-a-number:256"))
        assertNull(DisasmCursorCodec.decode("disasm:Zg:ZQ:b:1:1:not-a-number"))
    }
}
