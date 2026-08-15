/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Token accounting arithmetic.
 *
 * The engine used to discard the `usage` object entirely, leaving the agent loop
 * with no measurement of context pressure — the "max iterations" and "history
 * limit" settings were unanchored guesses. These tests pin the normalization of
 * the two wire formats and the accumulation across turns.
 */
class RikkaUsageTest {

    @Test
    fun contextTokensCountsEverythingOccupyingTheWindow() {
        val u = RikkaUsage(inputTokens = 1000, outputTokens = 250, cacheReadTokens = 4000, cacheWriteTokens = 100)
        // Cache hits still occupy context even though they bill differently.
        assertEquals(5350, u.contextTokens)
    }

    @Test
    fun emptyUsageIsDetected() {
        assertTrue(RikkaUsage().isEmpty())
        assertFalse(RikkaUsage(inputTokens = 1).isEmpty())
        assertFalse(RikkaUsage(cacheReadTokens = 1).isEmpty())
    }

    @Test
    fun plusAccumulatesEveryField() {
        val a = RikkaUsage(inputTokens = 10, outputTokens = 20, cacheReadTokens = 30, cacheWriteTokens = 40, reasoningTokens = 50)
        val b = RikkaUsage(inputTokens = 1, outputTokens = 2, cacheReadTokens = 3, cacheWriteTokens = 4, reasoningTokens = 5)
        val sum = a + b
        assertEquals(11, sum.inputTokens)
        assertEquals(22, sum.outputTokens)
        assertEquals(33, sum.cacheReadTokens)
        assertEquals(44, sum.cacheWriteTokens)
        assertEquals(55, sum.reasoningTokens)
    }

    @Test
    fun plusIsAssociativeAcrossManyTurns() {
        val turn = RikkaUsage(inputTokens = 100, outputTokens = 40)
        var total = RikkaUsage()
        repeat(12) { total += turn }
        assertEquals(1200, total.inputTokens)
        assertEquals(480, total.outputTokens)
        assertEquals(1680, total.contextTokens)
    }

    @Test
    fun jsonExposesContextTotal() {
        val json = RikkaUsage(inputTokens = 7, outputTokens = 3, cacheReadTokens = 5).toJson()
        assertEquals(7, json.getInt("inputTokens"))
        assertEquals(3, json.getInt("outputTokens"))
        assertEquals(5, json.getInt("cacheReadTokens"))
        assertEquals(15, json.getInt("contextTokens"))
    }

    @Test
    fun runUsageStartsEmpty() {
        val run = RikkaRunUsage()
        assertEquals(0, run.turns)
        assertTrue(run.lastTurn.isEmpty())
        assertTrue(run.cumulative.isEmpty())
    }

    @Test
    fun runUsageTracksLastTurnSeparatelyFromTotal() {
        var run = RikkaRunUsage()
        val first = RikkaUsage(inputTokens = 500, outputTokens = 100)
        val second = RikkaUsage(inputTokens = 900, outputTokens = 200)
        run = RikkaRunUsage(lastTurn = first, cumulative = run.cumulative + first, turns = 1)
        run = RikkaRunUsage(lastTurn = second, cumulative = run.cumulative + second, turns = 2)
        // lastTurn is the current context size; cumulative is spend across the run.
        assertEquals(1100, run.lastTurn.contextTokens)
        assertEquals(1700, run.cumulative.contextTokens)
        assertEquals(2, run.turns)
    }
}