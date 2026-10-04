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
import org.junit.Assert.assertTrue
import org.junit.Test

class AntiDebugScannerTest {

    private fun elf(
        data: ByteArray = ByteArray(0x2000),
        importedNames: List<String> = emptyList(),
        strings: List<String> = emptyList(),
        sections: List<SectionInfo> = listOf(
            SectionInfo(".text", 1L, 0x6L, 0x1000L, 0x0L, 0x800L, 0, 0, 4, 0),
            SectionInfo(".rodata", 1L, 0x2L, 0x2000L, 0x800L, 0x400L, 0, 0, 8, 0)
        )
    ): ElfFile = ElfFile(
        data = data,
        bits = 64,
        littleEndian = true,
        type = 3,
        machine = 183,
        entry = 0x1000L,
        sections = sections,
        symbols = emptyList(),
        dynSymbols = importedNames.map {
            SymbolInfo(it, "UND", "NOTYPE", "DEFAULT", 0, 0L, 0L, true, false)
        },
        relocations = emptyList(),
        strings = strings.map { StringInfo(0L, it, it.length, ".rodata") },
        programHeaders = emptyList(),
        dynamicEntries = emptyList()
    )

    @Test
    fun importOfPtraceIsHighConfidenceEvidence() {
        val r = AntiDebugScanner.analyze(elf(importedNames = listOf("ptrace")))
        val findings = r.getJSONArray("findings")
        val classes = (0 until findings.length())
            .map { findings.getJSONObject(it).getString("evidenceClass") }
        assertTrue("ptrace import should be reported", classes.contains("import"))
        assertTrue(r.getInt("importHits") >= 1)
        assertTrue(r.getString("risk") in setOf("medium", "high"))
    }

    @Test
    fun manyImportsRaiseRiskToHigh() {
        val r = AntiDebugScanner.analyze(
            elf(importedNames = listOf("ptrace", "inotify_add_watch", "fork", "clock_gettime", "dl_iterate_phdr"))
        )
        assertEquals("high", r.getString("risk"))
    }

    @Test
    fun bareStringsAreWeakerThanImports() {
        val withStrings = AntiDebugScanner.analyze(elf(strings = listOf("/proc/self/status", "/proc/self/maps")))
        assertEquals("low", withStrings.getString("risk"))
        assertTrue(withStrings.getInt("stringHits") >= 1)
        assertEquals(0, withStrings.getInt("importHits"))
    }

    @Test
    fun injectorTokenClusterNeedsAtLeastTwoTokens() {
        // "frida" is a substring of "frida-agent", so a single mention yields
        // two token hits; the assertion below documents that deliberately.
        val one = AntiDebugScanner.analyze(elf(strings = listOf("plain log line about nothing")))
        val two = AntiDebugScanner.analyze(elf(strings = listOf("/proc/self/maps", "libxposed.so")))
        assertEquals(0, one.getJSONArray("injectorTokens").length())
        assertEquals(2, two.getJSONArray("injectorTokens").length())
    }

    @Test
    fun cleanBinaryReportsNoRisk() {
        val r = AntiDebugScanner.analyze(elf())
        assertEquals("none", r.getString("risk"))
        assertEquals(0, r.getJSONArray("findings").length())
    }

    @Test
    fun x86DetourTrampolineIsDetected() {
        val data = ByteArray(0x2000)
        // mov rax, imm64 ; jmp rax  ==  48 B8 <8 bytes> FF E0
        val stub = intArrayOf(0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xE0)
        stub.forEachIndexed { i, b -> data[0x40 + i] = b.toByte() }
        val r = AntiDebugScanner.analyze(elf(data = data))
        val findings = r.getJSONArray("findings")
        val classes = (0 until findings.length())
            .map { findings.getJSONObject(it).getString("evidenceClass") }
        assertTrue("detour pattern should be found, got $classes", classes.contains("code_pattern"))
    }
}
