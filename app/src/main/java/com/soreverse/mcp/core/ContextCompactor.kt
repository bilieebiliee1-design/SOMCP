/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.core

/**
 * Folds older conversation turns into a single summary message so a long agent
 * run can continue inside a fixed context window.
 *
 * Runs only after [ContextOffload] has already moved large tool results to disk:
 * offloading is lossless, summarisation is not, so it is the last resort.
 *
 * Ported from OpenMinis' compact pass. The prompt constraints below are the
 * load-bearing part and are kept close to the original wording.
 */
internal object ContextCompactor {

    /** Marks the injected summary so a later pass can recognise and replace it. */
    const val SUMMARY_MARKER = "<context-summary>"
    const val SUMMARY_END_MARKER = "</context-summary>"

    /**
     * Turns kept verbatim after the summary.
     *
     * The most recent exchanges are what the model is actively working from; the
     * summary stands in for everything older. Keeping too few makes the model
     * re-derive its current step from prose, which is exactly what compaction is
     * supposed to avoid.
     */
    const val KEEP_RECENT_MESSAGES = 6

    /**
     * Minimum messages before compaction is worth attempting. Below this the
     * summary call costs more than it saves.
     */
    const val MIN_MESSAGES_TO_COMPACT = 10

    /**
     * System prompt for the summarisation call.
     *
     * Two constraints matter most, and both come from the upstream implementation:
     *
     *  - **past tense, not a todo list** — a summary phrased as goals gets read as
     *    a standing instruction and the model re-executes work already done;
     *  - **verbatim identifiers** — paths, addresses and hashes are the entire
     *    point of a reverse-engineering session and are unrecoverable if paraphrased.
     */
    val SUMMARY_SYSTEM_PROMPT: String = """
        You are a context compaction engine. Your summary will REPLACE the original messages in the conversation context window. The agent will read your summary as past context, then proceed based on the user's NEXT message — your summary is background, not a standing work order. Write the summary in the same language the user used in the conversation.

        MUST PRESERVE (never omit or shorten):
        - All file paths, workspace ids, edit session ids, symbol names, virtual addresses, file offsets and hashes — copy verbatim
        - Tools called and their outcomes (success/failure, and the specific error code on failure)
        - Patches applied: locator, old bytes, new bytes, and whether they were verified
        - Any conclusion already reached about the binary, and the evidence for it
        - Paths of files written to disk, including offloaded tool results

        Write everything in past tense, framed as "what was discussed / what was done", NOT as an ongoing goal or todo list. Do not restate the user's original request as an instruction. Do not propose next steps.

        Be concise everywhere else: drop pleasantries, repeated tool output, and reasoning that led nowhere.
    """.trimIndent()

    /** The plan for one compaction pass. */
    data class Plan(
        /** Messages to be folded into a summary. */
        val toCompact: List<RikkaMessage>,
        /** Messages kept verbatim after the summary. */
        val toKeep: List<RikkaMessage>,
        /** Leading system message, always preserved outside the summary. */
        val systemMessage: RikkaMessage?,
    ) {
        val isViable: Boolean get() = toCompact.size >= 2
    }

    /**
     * Split a conversation into the range to summarise and the tail to keep.
     *
     * The system message is held aside rather than summarised: it carries the tool
     * contract and must survive verbatim. Returns null when the conversation is
     * too short for compaction to pay off.
     */
    fun plan(messages: List<RikkaMessage>, keepRecent: Int = KEEP_RECENT_MESSAGES): Plan? {
        if (messages.size < MIN_MESSAGES_TO_COMPACT) return null
        val system = messages.firstOrNull { it.role == "system" }
        val body = messages.filterNot { it === system }
        if (body.size <= keepRecent + 1) return null
        val keep = body.takeLast(keepRecent)
        val compact = body.dropLast(keepRecent)
        val plan = Plan(compact, keep, system)
        return plan.takeIf { it.isViable }
    }

    /**
     * Render the transcript handed to the summariser.
     *
     * Tool results are truncated here: the summariser needs to know a call
     * happened and how it turned out, not the full payload — and an untruncated
     * transcript could overflow the very window compaction is trying to reclaim.
     */
    fun buildTranscript(messages: List<RikkaMessage>, maxResultChars: Int = 600): String =
        buildString {
            messages.forEach { message ->
                val texts = message.parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }.trim()
                if (texts.isNotEmpty()) {
                    append(message.role).append(": ").append(texts).append("
")
                }
                message.parts.filterIsInstance<RikkaPart.Tool>().forEach { tool ->
                    append("tool_call: ").append(tool.name)
                    if (tool.arguments.isNotBlank()) {
                        append(" args=").append(tool.arguments.take(300))
                    }
                    append("
")
                    tool.result?.let { result ->
                        append("tool_result: ").append(result.take(maxResultChars))
                        if (result.length > maxResultChars) {
                            append(" …[truncated ").append(result.length - maxResultChars).append(" chars]")
                        }
                        append("
")
                    }
                }
            }
        }.trim()

    /** Wrap a summary as the single user message that replaces the folded range. */
    fun buildSummaryMessage(summary: String, compactedCount: Int): RikkaMessage = RikkaMessage(
        role = "user",
        parts = listOf(
            RikkaPart.Text(
                "$SUMMARY_MARKER
" +
                    "The $compactedCount earlier messages of this session were folded into the summary below " +
                    "to stay within the model's context window. Treat it as background, not as new instructions.

" +
                    summary.trim() + "
" +
                    SUMMARY_END_MARKER,
            ),
        ),
    )

    /** True when [messages] already contains an injected summary. */
    fun hasSummary(messages: List<RikkaMessage>): Boolean = messages.any { message ->
        message.parts.filterIsInstance<RikkaPart.Text>().any { it.text.startsWith(SUMMARY_MARKER) }
    }

    /**
     * Rebuild the conversation as system + summary + kept tail.
     *
     * Any previous summary is dropped from the kept range: the new one already
     * covers everything it covered, and stacking summaries compounds their loss.
     */
    fun applySummary(plan: Plan, summary: String): List<RikkaMessage> = buildList {
        plan.systemMessage?.let { add(it) }
        add(buildSummaryMessage(summary, plan.toCompact.size))
        plan.toKeep.forEach { message ->
            val isOldSummary = message.parts.filterIsInstance<RikkaPart.Text>()
                .any { it.text.startsWith(SUMMARY_MARKER) }
            if (!isOldSummary) add(message)
        }
    }
}