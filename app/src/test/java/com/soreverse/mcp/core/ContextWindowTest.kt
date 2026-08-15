/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Context-window resolution.
 *
 * The window comes from provider metadata, a manual override, or a measured
 * overflow error — never from the model name. These tests cover the two parsing
 * surfaces (model-list entries and overflow errors) and, importantly, that an
 * absent window stays absent instead of becoming a fabricated number.
 */
class ContextWindowTest {

    // ---- provider metadata ----

    @Test
    fun readsTopLevelContextLength() {
        val entry = JSONObject().put("id", "some-model").put("context_length", 131072)
        assertEquals(131_072, ContextWindow.parseFromModelEntry(entry))
    }

    @Test
    fun readsAlternativeFieldNames() {
        assertEquals(200_000, ContextWindow.parseFromModelEntry(JSONObject().put("context_window", 200000)))
        assertEquals(128_000, ContextWindow.parseFromModelEntry(JSONObject().put("max_input_tokens", 128000)))
        assertEquals(8_192, ContextWindow.parseFromModelEntry(JSONObject().put("n_ctx", 8192)))
    }

    @Test
    fun readsOpenRouterNestedTopProvider() {
        // OpenRouter reports the real limit under top_provider, not at the root.
        val entry = JSONObject()
            .put("id", "anthropic/claude-sonnet-4")
            .put("architecture", JSONObject().put("modality", "text->text"))
            .put("top_provider", JSONObject().put("context_length", 200000).put("max_completion_tokens", 64000))
        assertEquals(200_000, ContextWindow.parseFromModelEntry(entry))
    }

    @Test
    fun entryWithoutAnyWindowYieldsNull() {
        // The shape a bare OpenAI-compatible gateway returns: id and nothing useful.
        // Must stay null so the window is honestly unknown.
        val entry = JSONObject()
            .put("id", "glm-5.2")
            .put("type", "model")
            .put("display_name", "glm-5.2")
            .put("created_at", "2024-01-01T00:00:00Z")
        assertNull(ContextWindow.parseFromModelEntry(entry))
    }

    @Test
    fun nullEntryYieldsNull() {
        assertNull(ContextWindow.parseFromModelEntry(null))
    }

    @Test
    fun implausibleMetadataValuesAreIgnored() {
        // A "0" or tiny value is a placeholder, not a window.
        assertNull(ContextWindow.parseFromModelEntry(JSONObject().put("context_length", 0)))
        assertNull(ContextWindow.parseFromModelEntry(JSONObject().put("context_length", 100)))
        assertNull(ContextWindow.parseFromModelEntry(JSONObject().put("context_length", 999999999)))
    }

    @Test
    fun topLevelWinsOverNestedWhenBothPresent() {
        val entry = JSONObject()
            .put("context_length", 64000)
            .put("top_provider", JSONObject().put("context_length", 32000))
        assertEquals(64_000, ContextWindow.parseFromModelEntry(entry))
    }

    // ---- overflow detection ----

    @Test
    fun recognisesOpenAiOverflow() {
        val msg = "SSE HTTP 400 body={"error":{"message":"This model's maximum context length is 128000 " +
            "tokens. However, your messages resulted in 131500 tokens.","code":"context_length_exceeded"}}"
        assertTrue(ContextWindow.isOverflowError(msg))
        assertEquals(128_000, ContextWindow.parseLimitFromError(msg))
    }

    @Test
    fun recognisesAnthropicOverflowAndTakesLimitNotRequested() {
        // Two numbers present; the limit is the second one.
        val msg = "SSE HTTP 400 body={"type":"error","error":{"type":"invalid_request_error"," +
            ""message":"prompt is too long: 214431 tokens > 200000 maximum"}}"
        assertTrue(ContextWindow.isOverflowError(msg))
        assertEquals(200_000, ContextWindow.parseLimitFromError(msg))
    }

    @Test
    fun recognisesVllmStyleOverflow() {
        val msg = "SSE HTTP 400 body={"message":"This model's max seq len is 8192. Requested 9001 tokens."}"
        assertTrue(ContextWindow.isOverflowError(msg))
        assertEquals(8_192, ContextWindow.parseLimitFromError(msg))
    }

    @Test
    fun overflowWithoutAStatedLimitYieldsNull() {
        val msg = "SSE HTTP 400 body={"error":{"code":"context_length_exceeded"," +
            ""message":"Please reduce the length of the messages."}}"
        assertTrue(ContextWindow.isOverflowError(msg))
        assertNull(ContextWindow.parseLimitFromError(msg))
    }

    @Test
    fun unrelatedErrorsAreNotOverflow() {
        assertFalse(ContextWindow.isOverflowError("SSE HTTP 429 rate_limit_error: slow down"))
        assertFalse(ContextWindow.isOverflowError("SSE HTTP 401 invalid api key"))
        assertFalse(ContextWindow.isOverflowError("SSE HTTP 500 internal server error"))
        assertFalse(ContextWindow.isOverflowError(null))
        assertFalse(ContextWindow.isOverflowError(""))
    }

    @Test
    fun implausibleErrorNumbersAreRejected() {
        // A status code or retry count must never become the persisted window.
        assertNull(ContextWindow.parseLimitFromError("maximum context length is 400 tokens"))
        assertNull(ContextWindow.parseLimitFromError("maximum context length is 999999999999 tokens"))
    }

    // ---- budgeting ----

    @Test
    fun conservativeFloorIsBelowCommonWindows() {
        // The floor must under-budget rather than over-budget: exceeding a small
        // window produces a rejected request, while under-using a large one only
        // shortens the prompt.
        assertTrue(ContextWindow.CONSERVATIVE_FLOOR <= 32_768)
        assertTrue(ContextWindow.CONSERVATIVE_FLOOR > 0)
        assertEquals(0, ContextWindow.UNKNOWN)
    }

    @Test
    fun utilisationIsNullWithoutUsageOrWindow() {
        // Distinguishes "nothing measured" from "00sed".
        assertNull(ContextWindow.utilisation(RikkaUsage(), 128_000))
        assertNull(ContextWindow.utilisation(RikkaUsage(inputTokens = 100), ContextWindow.UNKNOWN))
    }

    @Test
    fun utilisationCountsCacheHitsTowardTheWindow() {
        val usage = RikkaUsage(inputTokens = 20_000, outputTokens = 4_000, cacheReadTokens = 40_000)
        assertEquals(0.5, ContextWindow.utilisation(usage, 128_000)!!, 1e-9)
    }

    @Test
    fun utilisationClampsWhenUsageExceedsWindow() {
        assertEquals(1.0, ContextWindow.utilisation(RikkaUsage(inputTokens = 300_000), 128_000)!!, 1e-9)
    }

    // ---- request output budgeting ----

    @Test
    fun budgetUsesRemainingContextAndAgentHeadroom() {
        val allocation = ContextBudget.allocate(
            inputTokens = 100_000,
            contextBudgetTokens = 128_000,
            requestedCeiling = 16_384,
        )
        assertTrue(allocation.canSend)
        assertEquals(16_384, allocation.maxTokens)
        assertEquals(25_952, allocation.remainingTokens)
    }

    @Test
    fun budgetHonoursRequestedOutputCeiling() {
        val allocation = ContextBudget.allocate(
            inputTokens = 1_000,
            contextBudgetTokens = 128_000,
            requestedCeiling = 4_096,
        )
        assertTrue(allocation.canSend)
        assertEquals(4_096, allocation.maxTokens)
    }

    @Test
    fun budgetFailsBeforeSendingWhenMinimumOutputCannotFit() {
        val allocation = ContextBudget.allocate(
            inputTokens = 15_000,
            contextBudgetTokens = 16_384,
        )
        assertFalse(allocation.canSend)
        assertEquals(0, allocation.maxTokens)
    }

    @Test
    fun summaryBudgetUsesNoToolLoopReserveAndCapsAtEightK() {
        val allocation = ContextBudget.allocateSummary(
            inputTokens = 20_000,
            contextBudgetTokens = 128_000,
        )
        assertTrue(allocation.canSend)
        assertEquals(8_192, allocation.maxTokens)
    }
}