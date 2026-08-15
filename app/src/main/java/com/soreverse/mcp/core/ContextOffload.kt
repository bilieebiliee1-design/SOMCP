/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

import java.io.File
import java.security.MessageDigest

/**
 * Writes oversized tool results to disk and replaces them in the conversation
 * with a short stub, so the agent loop can keep going without re-sending tens of
 * thousands of characters on every subsequent turn.
 *
 * This is the cheaper half of context management and runs before any
 * summarisation: dropping one `read_disasm` result costs nothing in fidelity
 * (the file is still readable on request) whereas a summary is lossy and needs
 * an extra model call.
 *
 * Ported from OpenMinis' `offloadContextIfNeeded`, including its protection rule
 * that the most recent turns are never offloaded — the model needs those verbatim
 * to plan the current step coherently.
 */
internal object ContextOffload {

    /** Marks a result whose body was moved to disk. */
    const val OFFLOADED_PREFIX = "[offloaded]"

    /** Results at or above this many characters are offload candidates. */
    const val MIN_OFFLOAD_CHARS = 500

    /**
     * Recent tool results never offloaded. The model is mid-plan and needs the
     * last few results verbatim; stubbing them out causes it to re-run the same
     * calls, which costs more than it saves.
     */
    const val PROTECTED_RECENT_RESULTS = 4

    /**
     * Characters per token used for pre-flight estimates.
     *
     * Real usage is only known after a response arrives, but the offload decision
     * has to be made *before* sending. 3.5 is a deliberate compromise: English
     * prose is nearer 4, while the JSON and hex dumps this tool produces are
     * denser. Under-estimating would defeat the purpose, so the divisor is set
     * low enough to err toward offloading.
     */
    const val CHARS_PER_TOKEN = 3.5

    /** Token estimate for [text]. */
    fun estimateTokens(text: String): Int = (text.length / CHARS_PER_TOKEN).toInt()

    /** Token estimate for a whole conversation. */
    fun estimateConversationTokens(messages: List<RikkaMessage>): Int {
        var chars = 0L
        messages.forEach { message ->
            message.parts.forEach { part ->
                chars += when (part) {
                    is RikkaPart.Text -> part.text.length
                    is RikkaPart.Reasoning -> part.text.length
                    is RikkaPart.Tool -> part.arguments.length + (part.result?.length ?: 0)
                }
            }
        }
        return (chars / CHARS_PER_TOKEN).toInt()
    }

    /**
     * A tool result eligible for offloading, with the token count used to rank it.
     *
     * @param messageIndex index into the conversation
     * @param toolId the tool call whose result would be replaced
     */
    data class Candidate(
        val messageIndex: Int,
        val toolId: String,
        val toolName: String,
        val tokens: Int,
        val chars: Int,
    )

    /**
     * Rank offload candidates, largest first.
     *
     * Skips already-offloaded results (a second pass would only rewrite the stub)
     * and the last [PROTECTED_RECENT_RESULTS] results in the conversation.
     */
    fun findCandidates(messages: List<RikkaMessage>): List<Candidate> {
        val all = mutableListOf<Candidate>()
        messages.forEachIndexed { index, message ->
            message.parts.filterIsInstance<RikkaPart.Tool>().forEach { tool ->
                val result = tool.result ?: return@forEach
                if (isOffloadedStub(result)) return@forEach
                if (result.length < MIN_OFFLOAD_CHARS) return@forEach
                all += Candidate(
                    messageIndex = index,
                    toolId = tool.id,
                    toolName = tool.name,
                    tokens = estimateTokens(result),
                    chars = result.length,
                )
            }
        }
        // Protect the newest results in actual conversation order, even when some
        // of them are too short to be offload candidates. Taking the tail of `all`
        // would accidentally protect old large results whenever newer results were
        // short, already offloaded, or otherwise ineligible.
        val protectedIds = messages.asReversed().asSequence()
            .flatMap { message -> message.parts.filterIsInstance<RikkaPart.Tool>().asReversed().asSequence() }
            .filter { it.result != null }
            .take(PROTECTED_RECENT_RESULTS)
            .map { it.id }
            .toSet()
        return all.filterNot { it.toolId in protectedIds }.sortedByDescending { it.tokens }
    }

    private fun stableFilePart(value: String, fallback: String): String =
        value.filter { it.isLetterOrDigit() || it == '_' || it == '-' }
            .take(32).ifBlank { fallback }

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "00".format(it) }
        .take(20)

    private fun isOffloadedStub(result: String): Boolean =
        result.startsWith("$OFFLOADED_PREFIX v1 ")

    /**
     * Persist [content] and return a collision-resistant, versioned stub.
     * The complete tool id participates in the filename hash, so truncating the
     * readable prefix cannot overwrite a different call's evidence.
     */
    fun offloadToFile(dir: File, toolName: String, toolId: String, content: String): String? {
        val safeTool = stableFilePart(toolName, "tool")
        val file = File(dir, "${safeTool}_${digest(toolId)}.json")
        return runCatching {
            if (!dir.exists() && !dir.mkdirs()) error("cannot create offload dir ${dir.absolutePath}")
            val temp = File(dir, ".${file.name}.tmp-${Thread.currentThread().id}")
            temp.writeText(content)
            if (!temp.renameTo(file)) error("cannot atomically publish ${file.name}")
            buildStub(file, toolName, content)
        }.getOrNull()
    }

    /**
     * The replacement text the model sees. It states the size, the path, and how
     * to get the content back, so the model can decide whether it needs it rather
     * than assuming the call failed.
     */
    fun buildStub(file: File, toolName: String, original: String): String {
        val preview = original.take(280).replace("
", " ")
        return "$OFFLOADED_PREFIX v1 $toolName result was ${original.length} chars " +
            "(~${estimateTokens(original)} tokens) and was written to ${file.absolutePath} " +
            "to keep the context within the model's window. " +
            "Read that file if you need the full content. Preview: $preview"
    }

    /**
     * Apply offloading to [messages] until the estimate drops below
     * [ContextPolicy.offloadTarget], or candidates run out.
     *
     * @param force offload every candidate regardless of remaining headroom
     * @return the rewritten conversation plus a report of what was moved
     */
    fun apply(
        messages: List<RikkaMessage>,
        policy: ContextPolicy,
        currentTokens: Int,
        dir: File,
        force: Boolean = false,
    ): Result {
        if (!force && !policy.shouldOffload(currentTokens)) {
            return Result(messages, emptyList(), currentTokens, currentTokens)
        }
        val candidates = findCandidates(messages)
        if (candidates.isEmpty()) return Result(messages, emptyList(), currentTokens, currentTokens)

        val target = if (force) 0 else policy.offloadTarget
        val replacements = mutableMapOf<String, String>()
        val moved = mutableListOf<Candidate>()
        var running = currentTokens

        for (candidate in candidates) {
            if (!force && running <= target) break
            val message = messages.getOrNull(candidate.messageIndex) ?: continue
            val tool = message.parts.filterIsInstance<RikkaPart.Tool>()
                .firstOrNull { it.id == candidate.toolId } ?: continue
            val original = tool.result ?: continue
            val stub = offloadToFile(dir, candidate.toolName, candidate.toolId, original) ?: continue
            replacements[candidate.toolId] = stub
            moved += candidate
            // Charge the stub back so the loop stops once the target is met.
            running -= (candidate.tokens - estimateTokens(stub))
        }
        if (replacements.isEmpty()) return Result(messages, emptyList(), currentTokens, currentTokens)

        val rewritten = messages.map { message ->
            if (message.parts.none { it is RikkaPart.Tool && replacements.containsKey(it.id) }) {
                message
            } else {
                message.copy(
                    parts = message.parts.map { part ->
                        if (part is RikkaPart.Tool && replacements.containsKey(part.id)) {
                            part.copy(result = replacements[part.id])
                        } else {
                            part
                        }
                    },
                )
            }
        }
        return Result(rewritten, moved, currentTokens, estimateConversationTokens(rewritten))
    }

    data class Result(
        val messages: List<RikkaMessage>,
        val offloaded: List<Candidate>,
        val tokensBefore: Int,
        val tokensAfter: Int,
    ) {
        val freedTokens: Int get() = (tokensBefore - tokensAfter).coerceAtLeast(0)
        val didOffload: Boolean get() = offloaded.isNotEmpty()
    }
}