/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

/**
 * Decides, from a token estimate and the model's context window, whether the
 * agent loop should offload large tool results, fold older turns into a summary,
 * or report the context as exhausted.
 *
 * Pure logic: no summarisation or offload algorithm lives here, only the answer
 * to "what state are we in?". Execution is in [ContextOffload] and the loop.
 *
 * Thresholds are expressed as **fixed headroom below the ceiling** (10k/20k/40k),
 * not as a percentage. The invariant being protected is "one more agent turn
 * still fits", and a turn costs roughly the same number of tokens regardless of
 * how large the window is — so a percentage would leave far too little room on a
 * 32k window and waste tens of thousands of tokens on a 1M one.
 *
 * Ported from OpenMinis (`data/ContextPolicy.kt`), whose four-tier table this
 * mirrors, including the deliberate choice to disable both mechanisms below 32k
 * rather than compact aggressively in a window too small to hold a summary plus
 * a useful tail.
 */
data class ContextPolicy(
    /** Above this token count the next tool result is written to disk. 0 disables. */
    val offloadThreshold: Int,
    /** After offloading, shrink toward this target (below [offloadThreshold]). */
    val offloadTarget: Int,
    /** Above this, fold older turns into a summary. 0 disables. */
    val compactThreshold: Int,
    /** True when the window is too small to auto-compact; only report exhaustion. */
    val exhaustedOnly: Boolean,
    /** Whether an explicit "compact now" action makes sense for this window. */
    val manualCompactAllowed: Boolean,
) {
    enum class CheckResult { OK, NEEDS_COMPACT, EXHAUSTED }

    /**
     * Classify current pressure.
     *
     *  1. Compact enabled and past [compactThreshold] → [CheckResult.NEEDS_COMPACT]
     *  2. Small-window tier past the offload line (or 900f the window when
     *     offload is disabled entirely) → [CheckResult.EXHAUSTED]
     *  3. Otherwise [CheckResult.OK]
     */
    fun check(estimatedTokens: Int, contextWindow: Int): CheckResult {
        if (compactThreshold > 0 && estimatedTokens >= compactThreshold) {
            return CheckResult.NEEDS_COMPACT
        }
        if (exhaustedOnly) {
            val exhaustLine = if (offloadThreshold > 0) offloadThreshold else (contextWindow * 9 / 10)
            if (estimatedTokens >= exhaustLine) return CheckResult.EXHAUSTED
        }
        return CheckResult.OK
    }

    /** Whether the next tool result should be offloaded to disk. */
    fun shouldOffload(estimatedTokens: Int): Boolean =
        offloadThreshold > 0 && estimatedTokens >= offloadThreshold

    companion object {
        /**
         * Policy for a given window size:
         *
         *  - `< 32K` — both mechanisms off. A summary plus a usable tail does not
         *    fit; the honest answer is to tell the user to start a new session.
         *  - `32K–64K` — offload only, exhaust line at `ctx − 10k`.
         *  - `64K–128K` — offload + compact, 10k headroom for the compact call.
         *  - `≥ 128K` — generous offload + compact, 20k headroom.
         */
        fun forContextWindow(contextWindow: Int): ContextPolicy = when {
            contextWindow < 32_000 -> ContextPolicy(
                offloadThreshold = 0,
                offloadTarget = 0,
                compactThreshold = 0,
                exhaustedOnly = true,
                manualCompactAllowed = false,
            )
            contextWindow < 64_000 -> ContextPolicy(
                offloadThreshold = contextWindow - 10_000,
                offloadTarget = contextWindow - 15_000,
                compactThreshold = 0,
                exhaustedOnly = true,
                manualCompactAllowed = true,
            )
            contextWindow < 128_000 -> ContextPolicy(
                offloadThreshold = contextWindow - 20_000,
                offloadTarget = contextWindow - 30_000,
                compactThreshold = contextWindow - 10_000,
                exhaustedOnly = false,
                manualCompactAllowed = true,
            )
            else -> ContextPolicy(
                offloadThreshold = contextWindow - 40_000,
                offloadTarget = contextWindow - 60_000,
                compactThreshold = contextWindow - 20_000,
                exhaustedOnly = false,
                manualCompactAllowed = true,
            )
        }
    }
}