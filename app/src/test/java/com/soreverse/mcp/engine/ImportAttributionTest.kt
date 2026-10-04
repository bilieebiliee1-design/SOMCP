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

class ImportAttributionTest {

    private fun imported(name: String) = SymbolInfo(name, "UND", "NOTYPE", "DEFAULT", 0, 0L, 0L, true, false)

    @Test
    fun fallsBackToNeededHeuristicWithoutVersionTable() {
        val elf = ElfFile(
            data = ByteArray(0x100),
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = 0x1000L,
            sections = listOf(
                SectionInfo(".text", 1L, 0x6L, 0x1000L, 0x0L, 0x100L, 0, 0, 4, 0),
                SectionInfo(".dynstr", 3L, 0x2L, 0x2000L, 0x0L, 0x40L, 0, 0, 1, 0)
            ),
            symbols = emptyList(),
            dynSymbols = listOf(imported("malloc"), imported("memcpy")),
            relocations = emptyList(),
            strings = emptyList(),
            programHeaders = emptyList(),
            // No DT_VERNEED, so attribution must degrade and say so.
            dynamicEntries = listOf(DynamicEntryInfo(1L, 1L))
        )
        val r = ImportAttribution.analyze(elf, elf.data, listOf("libc.so"))
        assertEquals("needed_heuristic", r.getString("mode"))
        assertTrue(r.getString("evidence").contains("NOT proof of origin"))
        assertEquals(2, r.getInt("importCount"))
    }

    @Test
    fun emptySectionTableYieldsNoAttribution() {
        val elf = ElfFile(
            data = ByteArray(0x40),
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = 0L,
            sections = emptyList(),
            symbols = emptyList(),
            dynSymbols = listOf(imported("malloc")),
            relocations = emptyList(),
            strings = emptyList()
        )
        val r = ImportAttribution.analyze(elf, elf.data, emptyList())
        assertEquals("needed_heuristic", r.getString("mode"))
        assertEquals(1, r.getJSONArray("unresolved").length())
    }

    @Test
    fun capabilitiesDisclaimRuntimeGotOverwrite() {
        val caps = ImportAttribution.capabilities()
        val notCovered = caps.getJSONArray("notCovered").toString()
        assertTrue("must not claim GOT overwrite detection", notCovered.contains("GOT overwrite"))
    }
}
