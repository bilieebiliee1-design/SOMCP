// SPDX-License-Identifier: AGPL-3.0-only
//
// Patch read-only verification tests: length guard arithmetic with nop fill,
// and the apply-verify verdict ladder (pass on pure byte diffs, warn on
// skeleton drift, fail on structural breakage).
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class PatchAuditTest {
    private val elf = ElfParser(SynthElf.build()).parse()
    private val data = SynthElf.build()

    @Test
    fun lengthGuardDistinguishesFitFillAndOverflow() {
        val patch4 = ByteArray(4) { 0x14 }
        assertEquals("fits_with_fill", PatchAudit.lengthGuard(patch4, 8, "arm64", false).getString("verdict"))
        assertEquals("fits", PatchAudit.lengthGuard(patch4, 4, "arm64", false).getString("verdict"))
        assertEquals("too_long", PatchAudit.lengthGuard(ByteArray(12), 4, "arm64", false).getString("verdict"))
    }

    @Test
    fun lengthGuardSuggestsArchitectureNopFill() {
        val result = PatchAudit.lengthGuard(ByteArray(4), 12, "arm64", false)
        assertEquals("fits_with_fill", result.getString("verdict"))
        assertEquals(8, result.getString("suggestedFill").split(" ").size)
    }

    @Test
    fun applyVerifyPassesPureByteDiffs() {
        val edited = data.copyOf().also { it[520] = it[520].toInt().inv().toByte() }
        val editedElf = ElfParser(edited).parse()
        val result = PatchAudit.applyVerify(data, edited, elf, editedElf)
        assertEquals("pass", result.getString("verdict"))
        assertEquals(1L, result.getJSONArray("checks").getJSONObject(0).getLong("changedBytes"))
    }

    @Test
    fun applyVerifyWarnsOnEntryPointChange() {
        val edited = data.copyOf().also { it[24] = 0x77 }
        val result = PatchAudit.applyVerify(data, edited, elf, ElfParser(edited).parse())
        assertEquals("warn", result.getString("verdict"))
        val checks = result.getJSONArray("checks")
        val entry = (0 until checks.length()).map { checks.getJSONObject(it) }.first { it.getString("check") == "entry_point" }
        assertEquals("changed", entry.getString("status"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun editedImageWithoutElfMagicIsRejectedAtParseTime() {
        // The runtime wrapper maps this to ELF_PARSE_FAILED before applyVerify runs;
        // at the pure layer the parser itself is the first line of defense.
        val edited = data.copyOf().also { it[0] = 0x00 }
        ElfParser(edited).parse()
    }
}
