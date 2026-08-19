package com.soreverse.mcp.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelfAnalysisDetectionTest {
    @Test
    fun detectsOwnPackageMarkerAscii() {
        val bytes = "random lib \u0000 com.soreverse.mcp \u0000 stuff".toByteArray()
        assertTrue(containsPackageIdentifier(bytes))
    }

    @Test
    fun detectsOwnPackageMarkerUtf16le() {
        val bytes = "com.soreverse.mcp".toByteArray(Charsets.UTF_16LE)
        assertTrue(containsPackageIdentifier(bytes))
    }

    @Test
    fun doesNotFlagUnrelatedBytes() {
        val bytes = "com.example.other mcp soreverse.lib".toByteArray()
        assertFalse(containsPackageIdentifier(bytes))
    }

    @Test
    fun emptyBytesAreNotSelf() {
        assertFalse(containsPackageIdentifier(ByteArray(0)))
    }
}
