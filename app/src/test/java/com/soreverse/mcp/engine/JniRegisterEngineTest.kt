// SPDX-License-Identifier: AGPL-3.0-only
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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Builds a minimal in-memory ELF64 image whose `.text` is executable and whose
 * `.rodata` holds a real `JNINativeMethod` table, so the scanner is exercised
 * against the same byte layout it sees in the field rather than a mock.
 */
private class FakeElf64(val rodata: ByteArray, val textAddr: Long, val textSize: Long, val rodataAddr: Long, val symbols: List<SymbolInfo> = emptyList()) {
    val data: ByteArray = ByteArray(0x400)

    init {
        // .rodata at file offset 0x100, .text at 0x300.
        rodata.copyInto(data, 0x100)
    }

    fun elf(): ElfFile {
        val sections = listOf(
            SectionInfo(".text", 1L, 0x6L, textAddr, 0x300L, textSize, 0, 0, 4, 0),
            SectionInfo(".rodata", 1L, 0x2L, rodataAddr, 0x100L, rodata.size.toLong(), 0, 0, 8, 0)
        )
        val ph = listOf(
            ProgramHeaderInfo(1L, 0x5L, 0x100L, rodataAddr, 0x100L, rodata.size.toLong(), rodata.size.toLong(), 0x1000L)
        )
        return ElfFile(
            data = data,
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = textAddr,
            sections = sections,
            symbols = symbols,
            dynSymbols = emptyList(),
            relocations = emptyList(),
            strings = emptyList(),
            programHeaders = ph,
            dynamicEntries = emptyList()
        )
    }
}

class JniRegisterEngineTest {

    private fun putCString(buf: ByteArray, offset: Int, s: String): Int {
        val bytes = s.toByteArray(Charsets.US_ASCII)
        bytes.copyInto(buf, offset)
        buf[offset + bytes.size] = 0
        return offset + bytes.size + 1
    }

    private fun putPtr(buf: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            buf[offset + i] = ((value ushr (8 * i)) and 0xff).toByte()
        }
    }

    /** Builds a one-row JNINativeMethod table and returns the fake ELF. */
    private fun elfWithTable(methodName: String, signature: String, fnPtr: Long, symbolName: String? = null): FakeElf64 {
        val buf = ByteArray(0x200)
        var cursor = 0
        val nameOff = cursor.also { putCString(buf, it, methodName) }
        cursor += methodName.length + 1
        val sigOff = cursor.also { putCString(buf, it, signature) }
        cursor += signature.length + 1
        // Align the pointer array to 8 bytes, as the compiler would.
        while (cursor % 8 != 0) cursor++
        putPtr(buf, cursor, rodataAddrOf(nameOff))
        putPtr(buf, cursor + 8, rodataAddrOf(sigOff))
        putPtr(buf, cursor + 16, fnPtr)

        val symbols = symbolName?.let {
            listOf(SymbolInfo(it, "GLOBAL", "FUNC", "DEFAULT", 1, fnPtr and -2L, 0x40, false, true))
        } ?: emptyList()
        // FakeElf64's init block already copies `rodata` to file offset 0x100.
        return FakeElf64(rodata = buf, textAddr = 0x8000L, textSize = 0x400L, rodataAddr = 0x1000L, symbols = symbols)
    }

    private fun rodataAddrOf(off: Int) = 0x1000L + off

    @Test
    fun recoversSingleRegisteredMethod() {
        val fake = elfWithTable("nativeInit", "()V", 0x8000L, symbolName = "Java_com_example_Demo_nativeInit")
        val rows = JniRegisterEngine.scan(fake.elf())
        assertEquals(1, rows.size)
        val row = rows.first()
        assertEquals("nativeInit", row.name)
        assertEquals("()V", row.signature)
        assertEquals(0x8000L, row.fnPtr)
        assertTrue("symbol should resolve", row.symbolBound)
        assertEquals("Java_com_example_Demo_nativeInit", row.resolvedSymbol)
    }

    @Test
    fun rejectsPointerTripleWithNonDescriptorString() {
        // Second field is a plain C string, not a JNI descriptor.
        val fake = elfWithTable("nativeInit", "not a descriptor", 0x8000L)
        assertTrue(JniRegisterEngine.scan(fake.elf()).isEmpty())
    }

    @Test
    fun rejectsPointerTripleWithNonPointerFunction() {
        // fnPtr lands in .rodata (non-executable) -> must be refused.
        val fake = elfWithTable("nativeInit", "()V", 0x1000L + 0x40L)
        assertTrue(JniRegisterEngine.scan(fake.elf()).isEmpty())
    }

    @Test
    fun recognizesObjectAndArrayDescriptors() {
        val fake = elfWithTable("doThing", "(Ljava/lang/String;[I)Z", 0x8000L)
        val rows = JniRegisterEngine.scan(fake.elf())
        assertEquals(1, rows.size)
        assertEquals("(Ljava/lang/String;[I)Z", rows.first().signature)
    }

    @Test
    fun unmanglesJavaSymbolToClass() {
        assertEquals(
            "com.example.Demo",
            JniRegisterEngine.javaClassFromSymbol("Java_com_example_Demo_nativeInit")
        )
    }

    @Test
    fun unmanglesNestedClassWithDollarEscape() {
        assertEquals(
            "com.example.Outer\$Inner",
            JniRegisterEngine.javaClassFromSymbol("Java_com_example_Outer\$Inner_run")
        )
    }

    @Test
    fun unmanglingDecodesEscapedUnderscoreInMethodName() {
        // A literal '_' inside a Java method name is mangled as '_1'. Decoding
        // Java_com_example_Demo_do_1thing yields method "do_thing", so the
        // class/method split (at the last decoded '_') lands on
        // "com.example.Demo.do" -- the documented, inherently ambiguous case.
        assertEquals(
            "com.example.Demo.do",
            JniRegisterEngine.javaClassFromSymbol("Java_com_example_Demo_do_1thing")
        )
    }

    @Test
    fun unmanglingRejectsNonJavaSymbols() {
        assertNull(JniRegisterEngine.javaClassFromSymbol("main"))
        assertNull(JniRegisterEngine.javaClassFromSymbol("Javaish_symbol"))
    }
}
