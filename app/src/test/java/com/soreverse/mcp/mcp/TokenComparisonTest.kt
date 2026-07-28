package com.soreverse.mcp.mcp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TokenComparisonTest {
    @Test
    fun matchesIdenticalTokens() {
        val token = "0123456789abcdef0123456789abcdef"
        assertTrue(tokenConstantTimeEquals(token, token))
    }

    @Test
    fun rejectsDifferentTokens() {
        assertFalse(tokenConstantTimeEquals("0123456789abcdef", "fedcba9876543210"))
    }

    @Test
    fun rejectsWhenCandidateIsEmpty() {
        assertFalse(tokenConstantTimeEquals("", "0123456789abcdef"))
    }

    @Test
    fun rejectsWhenSecretIsEmpty() {
        assertFalse(tokenConstantTimeEquals("0123456789abcdef", ""))
    }

    @Test
    fun rejectsPrefixOfLongerToken() {
        assertFalse(tokenConstantTimeEquals("0123", "0123456789abcdef"))
    }

    @Test
    fun rejectsDifferingLastCharacter() {
        assertFalse(tokenConstantTimeEquals("0123456789abcde0", "0123456789abcde1"))
    }
}
