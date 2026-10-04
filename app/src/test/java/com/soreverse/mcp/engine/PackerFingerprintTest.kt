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

import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PackerFingerprintTest {

    private fun elf(data: ByteArray, entry: Long, sections: List<SectionInfo>): ElfFile = ElfFile(
        data = data,
        bits = 64,
        littleEndian = true,
        type = 3,
        machine = 183,
        entry = entry,
        sections = sections,
        symbols = emptyList(),
        dynSymbols = emptyList(),
        relocations = emptyList(),
        strings = emptyList(),
        programHeaders = emptyList(),
        dynamicEntries = emptyList()
    )

    @Test
    fun entropyOfUniformBytesIsEightBits() {
        val all = ByteArray(256) { it.toByte() }
        assertEquals(8.0, PackerFingerprint.shannonEntropy(all), 0.001)
    }

    @Test
    fun entropyOfSingleRepeatedByteIsZero() {
        assertEquals(0.0, PackerFingerprint.shannonEntropy(ByteArray(512) { 0x41 }), 0.001)
    }

    @Test
    fun entropyOfEmptyInputIsZero() {
        assertEquals(0.0, PackerFingerprint.shannonEntropy(ByteArray(0)), 0.001)
    }

    @Test
    fun randomDataIsHighEntropy() {
        val rnd = Random(42)
        val noise = ByteArray(8192).also { rnd.nextBytes(it) }
        assertTrue(PackerFingerprint.shannonEntropy(noise) > 7.9)
    }

    @Test
    fun cleanLibraryReportsClean() {
        val data = ByteArray(0x2000)
        val sections = listOf(
            SectionInfo(".text", 1L, 0x6L, 0x1000L, 0x0L, 0x800L, 0, 0, 4, 0),
            SectionInfo(".rodata", 1L, 0x2L, 0x2000L, 0x800L, 0x400L, 0, 0, 8, 0)
        )
        val result = PackerFingerprint.analyze(elf(data, entry = 0x1000L, sections = sections))
        assertEquals("clean", result.getString("overall"))
    }

    @Test
    fun detectsVendorMarkerString() {
        val data = ByteArray(0x2000)
        "libjiagu".toByteArray(Charsets.US_ASCII).copyInto(data, 0x900)
        val sections = listOf(
            SectionInfo(".text", 1L, 0x6L, 0x1000L, 0x0L, 0x800L, 0, 0, 4, 0),
            SectionInfo(".rodata", 1L, 0x2L, 0x2000L, 0x800L, 0x800L, 0, 0, 8, 0)
        )
        val result = PackerFingerprint.analyze(elf(data, entry = 0x1000L, sections = sections))
        val packers = result.getJSONArray("packers")
        val ids = (0 until packers.length()).map { packers.getJSONObject(it).getString("id") }
        assertTrue("expected a 360 marker hit, got $ids", ids.contains("360"))
    }

    @Test
    fun detectsEntryOutsideText() {
        val data = ByteArray(0x2000)
        val sections = listOf(
            SectionInfo(".text", 1L, 0x6L, 0x1000L, 0x0L, 0x100L, 0, 0, 4, 0)
        )
        // Entry sits far outside the .text range -> packer stub signature.
        val result = PackerFingerprint.analyze(elf(data, entry = 0x8000L, sections = sections))
        val packers = result.getJSONArray("packers")
        val ids = (0 until packers.length()).map { packers.getJSONObject(it).getString("id") }
        assertTrue("expected entry_outside_text, got $ids", ids.contains("entry_outside_text"))
    }

    @Test
    fun capabilitiesAdvertiseStaticOnly() {
        val caps = PackerFingerprint.capabilities()
        assertTrue(caps.getString("coverageClass") == "static_fingerprint")
        assertTrue(caps.getJSONArray("limits").length() > 0)
    }
}
