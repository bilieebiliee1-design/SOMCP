/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

/**
 * Context-window resolution for the deep-analysis agent loop.
 *
 * The window is **never guessed from the model name**. A name-derived table is
 * wrong in both directions: it under-budgets a large window for any model newer
 * than the table, and over-budgets when a gateway serves a truncated variant
 * under a familiar name. Either way the number looks authoritative while being
 * unverified.
 *
 * Sources, weakest to strongest:
 *
 *  1. **Provider metadata** — `context_length` / `context_window` /
 *     `max_input_tokens` from the model list. Authoritative when present, but many
 *     OpenAI-compatible gateways omit it entirely.
 *  2. **Manual override** — user-entered, for gateways that report nothing.
 *  3. **Measured** — parsed from a real overflow error. Strongest, because the
 *     provider stated the limit while refusing an actual request.
 *
 * When nothing is known the window is [UNKNOWN] and the caller budgets against
 * [CONSERVATIVE_FLOOR] while reporting the window as unknown, rather than
 * presenting a fabricated number.
 */
object ContextWindow {

    /** Sentinel for "no source has reported a window". */
    const val UNKNOWN = 0

    /**
     * Budget floor used while the window is [UNKNOWN]. Deliberately low: the cost
     * of under-using a large window is a shorter prompt, whereas over-estimating a
     * small one produces a request the provider rejects outright.
     */
    const val CONSERVATIVE_FLOOR = 16_384

    /** Field names carrying an input-window size across provider schemas. */
    private val WINDOW_KEYS = listOf(
        "context_length",      // OpenRouter, many gateways
        "context_window",      // some proxies
        "max_input_tokens",    // LiteLLM
        "max_context_length",
        "max_context_tokens",
        "context_size",
        "n_ctx",               // llama.cpp
    )

    /** Nested objects that may hold the window when it is not at the top level. */
    private val NESTED_CONTAINERS = listOf("top_provider", "architecture", "model_info", "limits", "capabilities")

    private const val MIN_PLAUSIBLE_LIMIT = 2_048
    private const val MAX_PLAUSIBLE_LIMIT = 20_000_000

    private fun plausible(value: Int?): Int? = value?.takeIf { it in MIN_PLAUSIBLE_LIMIT..MAX_PLAUSIBLE_LIMIT }

    /**
     * Extract a context window from one model-list entry, or null when the entry
     * reports none. Checks the top level first, then known nested containers
     * (OpenRouter puts the real limit under `top_provider.context_length`).
     */
    fun parseFromModelEntry(entry: org.json.JSONObject?): Int? {
        if (entry == null) return null
        WINDOW_KEYS.forEach { key ->
            plausible(entry.optInt(key, 0).takeIf { it > 0 })?.let { return it }
        }
        NESTED_CONTAINERS.forEach { container ->
            val nested = entry.optJSONObject(container) ?: return@forEach
            WINDOW_KEYS.forEach { key ->
                plausible(nested.optInt(key, 0).takeIf { it > 0 })?.let { return it }
            }
        }
        return null
    }

    /**
     * Patterns for the limit stated in an overflow error, in priority order.
     * Each captures the *limit*, never the requested size — the Anthropic wording
     * contains both numbers and the limit is the second one.
     *
     *  - OpenAI: "This model's maximum context length is 128000 tokens. However,
     *    your messages resulted in 130000 tokens"
     *  - Anthropic: "prompt is too long: 210000 tokens > 200000 maximum"
     *  - vLLM / llama.cpp: "This model's max seq len is 8192"
     */
    private val LIMIT_PATTERNS: List<Regex> = listOf(
        Regex("""maximum\s+context\s+length\s+is\s+(\d+)""", RegexOption.IGNORE_CASE),
        Regex("""context\s+length\s+of\s+(\d+)""", RegexOption.IGNORE_CASE),
        Regex(""">\s*(\d+)\s*maximum""", RegexOption.IGNORE_CASE),
        Regex("""max(?:imum)?\s+(?:seq(?:uence)?|sequence)\s+len(?:gth)?\s+is\s+(\d+)""", RegexOption.IGNORE_CASE),
        Regex("""maximum\s+(?:of\s+)?(\d+)\s+tokens""", RegexOption.IGNORE_CASE),
        Regex("""context\s+window\s+(?:of|is)\s+(\d+)""", RegexOption.IGNORE_CASE),
        Regex("""limit\s+of\s+(\d+)\s+tokens""", RegexOption.IGNORE_CASE),
    )

    /** Markers identifying an overflow rather than any other failure. */
    private val OVERFLOW_MARKERS = listOf(
        "context_length_exceeded",
        "maximum context length",
        "context length of",
        "prompt is too long",
        "too many tokens",
        "reduce the length",
        "max seq len",
        "context window",
        "string_above_max_length",
    )

    /** True when [message] describes a context-overflow failure. */
    fun isOverflowError(message: String?): Boolean {
        if (message.isNullOrBlank()) return false
        val lower = message.lowercase()
        return OVERFLOW_MARKERS.any { lower.contains(it) }
    }

    /**
     * Parse the real limit out of a provider error, or null when the message states
     * no usable number. Only meaningful for messages [isOverflowError] accepts, so
     * an unrelated number cannot be mistaken for a limit.
     */
    fun parseLimitFromError(message: String?): Int? {
        if (message.isNullOrBlank()) return null
        for (pattern in LIMIT_PATTERNS) {
            val value = pattern.find(message)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: continue
            plausible(value)?.let { return it }
        }
        return null
    }

    /**
     * Fraction of [window] consumed by [usage], clamped to 0..1.
     *
     * Null when there is no usage yet or the window is unknown — the caller must
     * distinguish "nothing measured" from "00sed" instead of drawing an empty
     * gauge that implies plenty of headroom.
     */
    fun utilisation(usage: RikkaUsage, window: Int): Double? {
        if (usage.isEmpty() || window <= 0) return null
        return (usage.contextTokens.toDouble() / window).coerceIn(0.0, 1.0)
    }
}

/**
 * Pure per-request output budgeting, based on OpenMinis' `dynamicMaxTokens()`.
 *
 * The context window constrains the sum of input and output. Agent tool loops
 * additionally need room for the next tool result, so SOMCP reserves
 * [AGENT_HEADROOM] before allocating output rather than spending every remaining
 * token on a single prose response.
 */
object ContextBudget {
    const val MIN_OUTPUT_TOKENS = 1_024
    const val DEFAULT_OUTPUT_CEILING = 16_384
    const val GLOBAL_OUTPUT_CEILING = 128_000
    const val AGENT_HEADROOM = 2_048

    data class Allocation(
        val maxTokens: Int,
        val inputTokens: Int,
        val budgetTokens: Int,
        val remainingTokens: Int,
        val canSend: Boolean,
        val reason: String? = null,
    )

    /**
     * Returns a provider-safe `max_tokens` for the next request. The minimum is
     * only granted when it fits after tool-loop headroom; otherwise the caller
     * must compact or fail locally instead of issuing a predictably invalid call.
     */
    fun allocate(
        inputTokens: Int,
        contextBudgetTokens: Int,
        requestedCeiling: Int = DEFAULT_OUTPUT_CEILING,
        reserveTokens: Int = AGENT_HEADROOM,
    ): Allocation {
        val budget = contextBudgetTokens.takeIf { it > 0 } ?: ContextWindow.CONSERVATIVE_FLOOR
        val input = inputTokens.coerceAtLeast(0)
        val remaining = (budget - input - reserveTokens).coerceAtLeast(0)
        val ceiling = requestedCeiling.coerceIn(MIN_OUTPUT_TOKENS, GLOBAL_OUTPUT_CEILING)
        if (remaining < MIN_OUTPUT_TOKENS) {
            return Allocation(
                maxTokens = 0,
                inputTokens = input,
                budgetTokens = budget,
                remainingTokens = remaining,
                canSend = false,
                reason = "only $remaining tokens remain after $reserveTokens-token agent headroom",
            )
        }
        return Allocation(
            maxTokens = minOf(ceiling, remaining),
            inputTokens = input,
            budgetTokens = budget,
            remainingTokens = remaining,
            canSend = true,
        )
    }

    /** Summary calls need no tool-loop reserve and cap output at 8K like OpenMinis. */
    fun allocateSummary(inputTokens: Int, contextBudgetTokens: Int): Allocation =
        allocate(
            inputTokens = inputTokens,
            contextBudgetTokens = contextBudgetTokens,
            requestedCeiling = 8_192,
            reserveTokens = 0,
        )
}