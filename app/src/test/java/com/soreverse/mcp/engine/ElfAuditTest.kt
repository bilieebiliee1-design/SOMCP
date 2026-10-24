// SPDX-License-Identifier: AGPL-3.0-only
//
// Audit-logic tests on the synthetic ELF fixture. These pin: the new
// ElfParser program-header/dynamic parsing, the byte ledger semantics
// (PT_LOAD covering sections is not an overlap), invariant verdicts, dynamic
// tag string resolution, cave enumeration and the negative (mutated-fixture)
// paths the tools exist to catch.
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ElfAuditTest {
    private val elf = ElfParser(SynthElf.build()).parse()
    private val data = SynthElf.build()

    @Test
    fun parserFillsProgramHeadersAndDynamicEntries() {
        assertEquals(3, elf.programHeaders.size)
        assertEquals(listOf(1L, 2L, 4L), elf.programHeaders.map { it.type })
        val tags = elf.dynamicEntries.map { it.tag }
        assertTrue(1L in tags) // DT_NEEDED
        assertTrue(14L in tags) // DT_SONAME
        assertEquals("libc.so", ElfAudit.neededList(data, elf).single())
        assertEquals("libtest.so", ElfAudit.soname(data, elf))
    }

    @Test
    fun abiProfileDecodesIdentAndMachine() {
        val profile = ElfAudit.abiProfile(data, elf)
        assertEquals("ELFCLASS64", profile.getString("eiClass"))
        assertEquals("ELFDATA2LSB", profile.getString("eiData"))
        assertEquals("SYSV", profile.getString("eiOsAbi"))
        assertEquals("EM_AARCH64", profile.getString("eMachine"))
        assertEquals("arm64", profile.getString("architecture"))
    }

    @Test
    fun byteLedgerCoversWholeFileWithoutPhantomOverlaps() {
        val ledger = ElfAudit.byteLedger(data, elf)
        assertEquals(data.size.toLong(), ledger.getLong("fileSize"))
        assertEquals(100.0, ledger.getDouble("coveragePercent"), 0.5)
        assertEquals(0, ledger.getJSONArray("overlaps").length())
        assertEquals(0, ledger.getJSONArray("gaps").length())
        assertEquals(0, ledger.getJSONArray("outOfBounds").length())
    }

    @Test
    fun byteLedgerFlagsGapsWhenFileGrowsWithoutSpans() {
        // Append 64 bytes without extending any span: the tail becomes orphan bytes.
        val mutated = data + ByteArray(64)
        val ledger = ElfAudit.byteLedger(mutated, ElfParser(mutated).parse())
        assertTrue(ledger.getJSONArray("gaps").length() >= 1)
        assertEquals(mutated.size.toLong(), ledger.getLong("fileSize"))
    }

    @Test
    fun phdrInvariantsPassOnWellFormedFixture() {
        val result = ElfAudit.phdrInvariants(elf)
        assertEquals("pass", result.getString("verdict"))
        assertEquals(0, result.getJSONArray("findings").length())
    }

    @Test
    fun phdrInvariantsFailWhenFileszExceedsMemsz() {
        val mutated = data.copyOf()
        // PT_LOAD p_filesz at ehdr(64) + 32
        val inflated = 0x7fffffff
        for (i in 0 until 4) mutated[64 + 32 + i] = ((inflated shr (i * 8)) and 0xff).toByte()
        val result = ElfAudit.phdrInvariants(ElfParser(mutated).parse())
        assertEquals("fail", result.getString("verdict"))
        val kinds = (0 until result.getJSONArray("findings").length())
            .map { result.getJSONArray("findings").getJSONObject(it).getString("kind") }
        assertTrue("filesz_gt_memsz" in kinds)
    }

    @Test
    fun sectionAnomaliesDetectWriteAndExec() {
        val wxElf = ElfParser(SynthElf.build(withWxSection = true)).parse()
        val anomalies = ElfAudit.sectionAnomalies(wxElf)
        val kinds = (0 until anomalies.length()).map { anomalies.getJSONObject(it).getString("kind") }
        assertTrue("write_and_exec" in kinds)
        // clean fixture: no anomalies
        assertEquals(0, ElfAudit.sectionAnomalies(elf).length())
    }

    @Test
    fun dynamicTagsResolveStringValuedTags() {
        val dynamic = ElfAudit.dynamicTags(data, elf)
        val items = dynamic.getJSONArray("items")
        var needed: String? = null
        var soname: String? = null
        for (i in 0 until items.length()) {
            val item = items.getJSONObject(i)
            if (item.getLong("tag") == 1L) needed = item.optString("needed")
            if (item.getLong("tag") == 14L) soname = item.optString("soname")
        }
        assertEquals("libc.so", needed)
        assertEquals("libtest.so", soname)
    }

    @Test
    fun dtFlagsReportEagerBinding() {
        val flags = ElfAudit.dtFlags(elf)
        assertTrue(flags.getBoolean("eagerBinding"))
        assertTrue(flags.getBoolean("dtFlagsPresent"))
        assertTrue(flags.getBoolean("dtFlags1Present"))
    }

    @Test
    fun relocCensusNamesKnownAArch64Type() {
        val census = ElfAudit.relocCensus(elf)
        assertEquals(1, census.getInt("total"))
        val types = census.getJSONArray("byType")
        assertEquals("R_AARCH64_RELATIVE", types.getJSONObject(0).getString("typeName"))
        assertEquals(0, census.getInt("unknownTypeCount"))
    }

    @Test
    fun visibilityAuditCountsExportedDynsym() {
        val visibility = ElfAudit.visibilityAudit(elf)
        assertTrue(visibility.getInt("exported") >= 1)
        assertTrue(visibility.getInt("imported") == 0)
    }

    @Test
    fun paddingCavesFindTheZeroRunInsideText() {
        val caves = ElfAudit.paddingCaves(data, elf, minSize = 16, execOnly = true)
        val textCave = caves.firstOrNull { it.section == ".text" }
        assertNotNull("32-byte zero cave inside .text must be found", textCave)
        assertEquals(32, textCave!!.size)
        assertEquals("zero", textCave.fill)
        // non-exec sections are excluded in execOnly mode
        assertTrue(caves.all { it.section != ".rodata" })
    }

    @Test
    fun vaddrMappingIsIdentityOnTheFixture() {
        val dynstrOffset = elf.dynamicEntries.first { it.tag == 5L }.value
        assertEquals(dynstrOffset, ElfAudit.vaddrToOffset(elf, dynstrOffset))
        assertNull(ElfAudit.vaddrToOffset(elf, 0x7ffff000L))
    }

    @Test
    fun androidIdentDecodesSdkNdkAndBuild() {
        val ident = NativeProfile.androidIdent(data, elf)
        assertTrue(ident.getBoolean("found"))
        assertEquals(29L, ident.getLong("sdkVersion"))
        assertEquals("27.1.855", ident.getString("ndkVersionHuman"))
        assertEquals("b1", ident.getString("buildNumber"))
    }

    @Test
    fun hashTablesWithoutTablesReportAbsence() {
        val tables = ElfAudit.hashTables(data, elf)
        assertFalse(tables.getBoolean("hasSysv"))
        assertFalse(tables.getBoolean("hasGnu"))
    }

    @Test
    fun toolchainAndStlVariantsStayHonestOnMinimalFixture() {
        // No version strings and no STL markers: the tools must report unknown/none, not guess.
        assertEquals("unknown", NativeProfile.toolchainFingerprint(data, elf).getString("compiler"))
        assertEquals("none", NativeProfile.libcxxVariant(data, elf).getString("variant"))
        assertFalse(NativeProfile.libcxxVariant(data, elf).getBoolean("exceptions"))
    }
}
