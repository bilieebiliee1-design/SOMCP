package com.soreverse.mcp.core

import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HttpHeaderSafetyTest {
    @Test
    fun removesLineBreaksFromCredentials() {
        assertEquals("token-value", sanitizeCredential("\n token-value\r\n"))
    }

    @Test
    fun rejectsInvalidHeaderName() {
        assertThrows(IllegalArgumentException::class.java) {
            Request.Builder().safeHeader("Bad Name", "value")
        }
    }

    @Test
    fun normalizesLineBreaksInHeaderValue() {
        val request = Request.Builder().url("https://example.com")
            .safeHeader("X-Test", "one\ntwo")
            .build()
        assertEquals("one two", request.header("X-Test"))
    }
}
