package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LocatorParserTest {
    @Test
    fun parsesCompleteLocators() {
        assertEquals("Java_com_example_run", LocatorParser.target("so_function:libdemo.so!Java_com_example_run@0x1234", "so_function"))
        assertEquals("malloc", LocatorParser.target("so_symbol:libdemo.so!malloc@0x2345", "so_symbol"))
        assertEquals(".text", LocatorParser.target("so_section:libdemo.so!.text@0x1000#4", "so_section"))
    }

    @Test
    fun parsesTargetsWithoutPrefixAndOnlyRemovesExactPrefix() {
        assertEquals("main", LocatorParser.target(" libdemo.so!main@0x1234 "))
        assertEquals("main", LocatorParser.target(" so_function:main ", "so_function"))
        assertEquals("so_symbol:main", LocatorParser.target(" so_symbol:main ", "so_function"))
    }

    @Test
    fun parsesLastAddressTail() {
        assertEquals(0x1234L, LocatorParser.address("fcn.main@0x1234"))
        assertEquals(0x2345L, LocatorParser.address("so_function:libdemo.so!main@2345"))
        assertEquals(0x3456L, LocatorParser.address("name@0x1234@0x3456"))
    }

    @Test
    fun rejectsMissingEmptyAndInvalidAddressTails() {
        assertNull(LocatorParser.address("so_function:libdemo.so!main"))
        assertNull(LocatorParser.address("so_function:libdemo.so!main@"))
        assertNull(LocatorParser.address("so_function:libdemo.so!main@not-hex"))
        assertNull(LocatorParser.address("@"))
        assertNull(LocatorParser.address(""))
    }

    @Test
    fun parsesHexWithAndWithoutPrefix() {
        assertEquals(0x1234L, LocatorParser.hex(" 0x1234 "))
        assertEquals(0xABCDL, LocatorParser.hex("ABCD"))
        assertNull(LocatorParser.hex("0xnope"))
        assertNull(LocatorParser.hex(""))
    }

    @Test
    fun normalizesRizinSymbolPrefixes() {
        assertEquals("malloc", LocatorParser.normalizeSymbol("sym.imp.malloc"))
        assertEquals("main", LocatorParser.normalizeSymbol("sym.main"))
        assertEquals("entry0", LocatorParser.normalizeSymbol("fcn.entry0"))
        assertEquals("malloc", LocatorParser.normalizeSymbol("so_symbol:libdemo.so!sym.imp.malloc@0x1234"))
    }
}
