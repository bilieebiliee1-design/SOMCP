package com.soreverse.mcp.core

import org.junit.Assert.assertEquals
import org.junit.Test

class IntegrityGuardDigestTest {
    @Test
    fun normalizesCaseAndStripsSeparators() {
        val colonSeparated = "ab:cd:ef:01:23:45:67:89"
        val spaced = "AB CD EF 01 23 45 67 89"
        val expected = "ABCDEF0123456789"
        assertEquals(expected, normalizeFingerprint(colonSeparated))
        assertEquals(expected, normalizeFingerprint(spaced))
    }

    @Test
    fun equalDigestsMatchAfterNormalizationRegardlessOfFormatting() {
        val pinned = normalizeFingerprint("ab:cd:ef")
        val runtime = normalizeFingerprint("ABCDEF")
        assertEquals(pinned, runtime)
    }

    @Test
    fun blankAndPunctuationOnlyBecomeEmpty() {
        assertEquals("", normalizeFingerprint(""))
        assertEquals("", normalizeFingerprint("   "))
        assertEquals("", normalizeFingerprint("::-- ::"))
    }

    @Test
    fun differentDigestsDoNotCollide() {
        val a = normalizeFingerprint("00:11:22")
        val b = normalizeFingerprint("00:11:23")
        assertEquals(false, a == b)
    }
}
