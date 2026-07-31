package com.soreverse.mcp.core

import org.junit.Assert.assertEquals
import org.junit.Test

class IntegrityGuardDigestTest {
    @Test
    fun normalizesCaseAndStripsSeparators() {
        val colonSeparated = "ab:cd:ef:01:23:45:67:89"
        val spaced = "AB CD EF 01 23 45 67 89"
        val expected = "ABCDEF0123456789"
        assertEquals(expected, normalizeSignerDigest(colonSeparated))
        assertEquals(expected, normalizeSignerDigest(spaced))
    }

    @Test
    fun equalDigestsMatchAfterNormalizationRegardlessOfFormatting() {
        val pinned = normalizeSignerDigest("ab:cd:ef")
        val runtime = normalizeSignerDigest("ABCDEF")
        assertEquals(pinned, runtime)
    }

    @Test
    fun blankAndPunctuationOnlyBecomeEmpty() {
        assertEquals("", normalizeSignerDigest(""))
        assertEquals("", normalizeSignerDigest("   "))
        assertEquals("", normalizeSignerDigest("::-- ::"))
    }

    @Test
    fun differentDigestsDoNotCollide() {
        val a = normalizeSignerDigest("00:11:22")
        val b = normalizeSignerDigest("00:11:23")
        assertEquals(false, a == b)
    }
}
