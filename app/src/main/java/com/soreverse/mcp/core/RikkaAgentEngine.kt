package com.soreverse.mcp.core

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.collect
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import org.json.JSONObject

sealed interface RikkaPart {
    data class Text(val text: String) : RikkaPart
    data class Reasoning(val text: String) : RikkaPart
    data class Tool(
        val id: String,
        val name: String,
        val arguments: String,
        val result: String? = null,
        val index: Int = 0,
    ) : RikkaPart
}

internal data class RikkaMessage(
    val role: String,
    val parts: List<RikkaPart>,
)

internal data class RikkaTool(
    val name: String,
    val description: String,
    val schema: JSONObject,
    val execute: suspend (JSONObject) -> String,
)

/**
 * Token accounting for one request, as reported by the provider.
 *
 * Both wire formats are normalized here: OpenAI uses
 * `prompt_tokens`/`completion_tokens`, Anthropic uses
 * `input_tokens`/`output_tokens` plus separate cache counters. Prompt-cache hits
 * are tracked separately because they still occupy context but are billed
 * differently, so a raw sum would misreport both cost and context pressure.
 */
data class RikkaUsage(
    val inputTokens: Int = 0,
    val outputTokens: Int = 0,
    val cacheReadTokens: Int = 0,
    val cacheWriteTokens: Int = 0,
    val reasoningTokens: Int = 0,
) {
    /** Tokens occupying the context window on the next turn. */
    val contextTokens: Int get() = inputTokens + cacheReadTokens + cacheWriteTokens + outputTokens

    operator fun plus(other: RikkaUsage) = RikkaUsage(
        inputTokens = inputTokens + other.inputTokens,
        outputTokens = outputTokens + other.outputTokens,
        cacheReadTokens = cacheReadTokens + other.cacheReadTokens,
        cacheWriteTokens = cacheWriteTokens + other.cacheWriteTokens,
        reasoningTokens = reasoningTokens + other.reasoningTokens,
    )

    fun isEmpty(): Boolean = contextTokens == 0

    fun toJson(): org.json.JSONObject = org.json.JSONObject()
        .put("inputTokens", inputTokens)
        .put("outputTokens", outputTokens)
        .put("cacheReadTokens", cacheReadTokens)
        .put("cacheWriteTokens", cacheWriteTokens)
        .put("reasoningTokens", reasoningTokens)
        .put("contextTokens", contextTokens)
}

/** Bytes of an error response body retained for diagnostics and limit parsing. */
private const val ERROR_BODY_LIMIT = 2_000

/**
 * Ceiling on agent turns in a single run.
 *
 * This is a runaway guard, not a capacity setting: a loop that keeps calling tools
 * without converging (varying arguments just enough to dodge duplicate detection)
 * is stopped here. How much work actually fits is governed by the context window
 * via [ContextPolicy], so exposing this as a user-tunable number invited the
 * mistake of setting it low and having runs cut off while the window was still
 * mostly empty.
 */
const val MAX_AGENT_TURNS = 200

/**
 * The loop hit [MAX_AGENT_TURNS] without producing a final answer.
 *
 * [partialText] holds whatever prose was emitted so the caller can show it instead
 * of discarding the run.
 */
class AgentTurnLimitException(
    val limit: Int,
    val partialText: String,
) : Exception("Stopped after $limit agent turns to prevent a runaway loop. The run can be resumed.")

/**
 * Applies [ContextPolicy] to a conversation before each request: offloads oversized
 * tool results, then folds older turns into a summary when offloading is not enough.
 *
 * Implemented outside the engine because compaction needs a model call, which the
 * engine is in the middle of; the caller supplies [summarise].
 */
internal class ContextManager(
    private val contextWindow: Int,
    private val offloadDir: java.io.File,
    private val summarise: suspend (List<RikkaMessage>) -> String,
    private val onEvent: (String) -> Unit = {},
) {
    val budgetTokens: Int get() = contextWindow

    data class Managed(
        val messages: List<RikkaMessage>,
        val exhausted: Boolean = false,
        val exhaustedMessage: String? = null,
    )

    /**
     * Bring the conversation under budget.
     *
     * When [contextWindow] is not known the conversation is passed through
     * untouched: with no ceiling there is no threshold to compare against, and
     * acting on a guessed window would either truncate needlessly or not at all.
     * The provider's own overflow error remains the backstop.
     */
    suspend fun prepare(messages: List<RikkaMessage>, @Suppress("UNUSED_PARAMETER") lastUsage: RikkaUsage): Managed {
        // Usage belongs to the request that just completed. Tool execution mutates
        // `messages` after that response, so using it as the next request's size can
        // miss a newly-added, very large tool result. Re-estimate the actual
        // conversation every time; provider usage remains useful for UI/diagnostics.
        val estimate = ContextOffload.estimateConversationTokens(messages)
        if (contextWindow <= 0) return Managed(messages)
        val policy = ContextPolicy.forContextWindow(contextWindow)

        var current = messages
        var tokens = estimate

        if (policy.shouldOffload(tokens)) {
            val result = ContextOffload.apply(current, policy, tokens, offloadDir)
            if (result.didOffload) {
                onEvent(
                    "Offloaded ${result.offloaded.size} large tool result(s) to disk, " +
                        "freeing ~${result.freedTokens} tokens (${result.tokensBefore} → ${result.tokensAfter}).",
                )
                current = result.messages
                tokens = result.tokensAfter
            }
        }

        return when (policy.check(tokens, contextWindow)) {
            ContextPolicy.CheckResult.OK -> Managed(current)
            ContextPolicy.CheckResult.NEEDS_COMPACT -> compact(current, tokens, policy)
            ContextPolicy.CheckResult.EXHAUSTED -> Managed(
                messages = current,
                exhausted = true,
                exhaustedMessage = "Context is exhausted ($tokens / $contextWindow tokens) and this window is too " +
                    "small to compact automatically. Start a new analysis, or configure a model with a larger " +
                    "context window.",
            )
        }
    }

    private suspend fun compact(
        messages: List<RikkaMessage>,
        tokens: Int,
        policy: ContextPolicy,
    ): Managed {
        val plan = ContextCompactor.plan(messages)
            ?: return Managed(
                messages = messages,
                exhausted = true,
                exhaustedMessage = "Context is full ($tokens / $contextWindow tokens), but there are not enough older messages to compact. Start a new analysis to continue.",
            )
        val summary = runCatching { summarise(plan.toCompact) }.getOrNull()?.takeIf { it.isNotBlank() }
        if (summary == null) {
            // Summarisation failed. Force-offload everything eligible as a last
            // resort rather than sending a request that will certainly be rejected.
            val forced = ContextOffload.apply(messages, policy, tokens, offloadDir, force = true)
            if (forced.didOffload && forced.tokensAfter < tokens) {
                onEvent("Compaction failed; force-offloaded ${forced.offloaded.size} tool result(s) instead.")
                val post = ContextPolicy.forContextWindow(contextWindow).check(forced.tokensAfter, contextWindow)
                if (post == ContextPolicy.CheckResult.OK) return Managed(forced.messages)
                return Managed(
                    messages = forced.messages,
                    exhausted = true,
                    exhaustedMessage = "Context remains full (${forced.tokensAfter} / $contextWindow tokens) after compaction failed; start a new analysis.",
                )
            }
            return Managed(
                messages = messages,
                exhausted = true,
                exhaustedMessage = "Context is full ($tokens / $contextWindow tokens) and compaction failed. " +
                    "Start a new analysis to continue.",
            )
        }
        val rebuilt = ContextCompactor.applySummary(plan, summary)
        val after = ContextOffload.estimateConversationTokens(rebuilt)
        onEvent(
            "Compacted ${plan.toCompact.size} earlier message(s) into a summary, " +
                "keeping the last ${plan.toKeep.size} verbatim (~$tokens → ~$after tokens).",
        )
        return Managed(rebuilt)
    }
}

/**
 * The request exceeded the model's context window.
 *
 * [reportedLimit] is the true limit when the provider stated one, which the caller
 * persists so later runs budget against a measured value instead of a guess.
 */
class ContextOverflowException(
    message: String,
    val reportedLimit: Int?,
    cause: Throwable? = null,
) : Exception(message, cause)

/** Per-turn usage plus the running total across an agent run. */
data class RikkaRunUsage(
    val lastTurn: RikkaUsage = RikkaUsage(),
    val cumulative: RikkaUsage = RikkaUsage(),
    val turns: Int = 0,
)

internal class RikkaAgentEngine(
    private val client: OkHttpClient,
    private val provider: String,
    private val endpoint: String,
    private val apiKey: String,
    private val model: String,
    private val temperature: Float,
    private val customHeaders: Map<String, String>,
    private val customBody: Map<String, JsonElement>,
) {
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * Usage reported by the most recent stream. Written by the SSE listeners and
     * read after each turn completes; the streams are collected sequentially so a
     * plain volatile is sufficient.
     */
    @Volatile
    private var lastStreamUsage: RikkaUsage = RikkaUsage()

    /** Cumulative usage for the whole [run], exposed for budget decisions and UI. */
    @Volatile
    var runUsage: RikkaRunUsage = RikkaRunUsage()
        private set

    /**
     * Extract a usage object from either wire format. Called on whichever SSE
     * frame carries it: OpenAI puts a `usage` object on a late chunk (only when
     * `stream_options.include_usage` is set), Anthropic splits it across
     * `message_start` (input) and `message_delta` (output).
     */
    private fun parseUsage(usage: JsonObject?): RikkaUsage {
        if (usage == null) return RikkaUsage()
        fun int(vararg keys: String): Int {
            for (key in keys) {
                usage[key]?.jsonPrimitive?.contentOrNull?.toIntOrNull()?.let { return it }
            }
            return 0
        }
        val completionDetails = usage["completion_tokens_details"]?.jsonObject
        val promptDetails = usage["prompt_tokens_details"]?.jsonObject
        val promptTokens = int("prompt_tokens")
        val cachedPromptTokens = if (promptTokens > 0) {
            int("cached_tokens").takeIf { it > 0 }
                ?: promptDetails?.get("cached_tokens")?.jsonPrimitive?.contentOrNull?.toIntOrNull()
                ?: 0
        } else {
            int("cache_read_input_tokens")
        }
        // OpenAI reports cached_tokens as a component of prompt_tokens. Store the
        // uncached portion in inputTokens so contextTokens does not double-count it;
        // Anthropic reports input_tokens and cache_read_input_tokens separately.
        val inputTokens = if (promptTokens > 0) {
            (promptTokens - cachedPromptTokens).coerceAtLeast(0)
        } else {
            int("input_tokens")
        }
        return RikkaUsage(
            inputTokens = inputTokens,
            outputTokens = int("completion_tokens", "output_tokens"),
            cacheReadTokens = cachedPromptTokens,
            cacheWriteTokens = int("cache_creation_input_tokens"),
            reasoningTokens = completionDetails?.get("reasoning_tokens")?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: 0,
        )
    }

    /** Merge a partial usage frame into [lastStreamUsage], keeping non-zero fields. */
    private fun recordUsage(parsed: RikkaUsage) {
        if (parsed.isEmpty()) return
        val prev = lastStreamUsage
        lastStreamUsage = RikkaUsage(
            inputTokens = parsed.inputTokens.takeIf { it > 0 } ?: prev.inputTokens,
            outputTokens = parsed.outputTokens.takeIf { it > 0 } ?: prev.outputTokens,
            cacheReadTokens = parsed.cacheReadTokens.takeIf { it > 0 } ?: prev.cacheReadTokens,
            cacheWriteTokens = parsed.cacheWriteTokens.takeIf { it > 0 } ?: prev.cacheWriteTokens,
            reasoningTokens = parsed.reasoningTokens.takeIf { it > 0 } ?: prev.reasoningTokens,
        )
    }

    suspend fun run(
        systemPrompt: String,
        userPrompt: String,
        tools: List<RikkaTool>,
        maxSteps: Int = MAX_AGENT_TURNS,
        requiredTools: List<String> = emptyList(),
        contextManager: ContextManager? = null,
        contextBudgetTokens: Int = ContextWindow.CONSERVATIVE_FLOOR,
        summaryRequest: Boolean = false,
        onParts: (List<RikkaPart>) -> Unit,
    ): String {
        val messages = mutableListOf(
            RikkaMessage("system", listOf(RikkaPart.Text(systemPrompt))),
            RikkaMessage("user", listOf(RikkaPart.Text(userPrompt))),
        )
        val visibleParts = mutableListOf<RikkaPart>()
        val executedTools = linkedSetOf<String>()
        runUsage = RikkaRunUsage()
        repeat(maxSteps.coerceIn(1, MAX_AGENT_TURNS)) {
            // Manage context before sending, not after: the offload decision has to
            // be made while the request can still be changed.
            contextManager?.prepare(messages, runUsage.lastTurn)?.let { managed ->
                if (managed.exhausted) {
                    error(managed.exhaustedMessage ?: "Context window exhausted and compaction cannot recover")
                }
                if (managed.messages !== messages) {
                    messages.clear()
                    messages.addAll(managed.messages)
                }
            }
            var assistant = RikkaMessage("assistant", emptyList())
            lastStreamUsage = RikkaUsage()
            val budget = if (summaryRequest) {
                ContextBudget.allocateSummary(
                    inputTokens = ContextOffload.estimateConversationTokens(messages),
                    contextBudgetTokens = contextManager?.budgetTokens ?: contextBudgetTokens,
                )
            } else {
                ContextBudget.allocate(
                    inputTokens = ContextOffload.estimateConversationTokens(messages),
                    contextBudgetTokens = contextManager?.budgetTokens ?: contextBudgetTokens,
                    requestedCeiling = requestedOutputCeiling(),
                )
            }
            if (!budget.canSend) {
                error("Context budget exhausted before request: ${budget.reason}")
            }
            stream(messages, tools, budget.maxTokens).collect { delta ->
                assistant = assistant.copy(parts = mergeParts(assistant.parts, delta))
                onParts(visibleParts + assistant.parts)
            }
            val turnUsage = lastStreamUsage
            if (!turnUsage.isEmpty()) {
                runUsage = RikkaRunUsage(
                    lastTurn = turnUsage,
                    cumulative = runUsage.cumulative + turnUsage,
                    turns = runUsage.turns + 1,
                )
            }
            messages += assistant
            val calls = assistant.parts.filterIsInstance<RikkaPart.Tool>().filter { it.result == null }
            if (calls.isEmpty()) {
                val missing = requiredTools.filterNot(executedTools::contains)
                if (missing.isNotEmpty()) {
                    visibleParts += assistant.parts
                    messages += RikkaMessage(
                        "user",
                        listOf(RikkaPart.Text("Continue the analysis. Complete these required tools before the final answer: ${missing.joinToString(" → ")}.")),
                    )
                    return@repeat
                }
                return assistant.parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }.trim()
            }
            calls.forEach { call ->
                val requestedName = call.name.trim()
                val shortName = requestedName.substringAfterLast('.').substringAfterLast('/')
                val tool = tools.firstOrNull { it.name == requestedName }
                    ?: tools.firstOrNull { it.name.equals(requestedName, ignoreCase = true) }
                    ?: tools.firstOrNull { it.name.equals(shortName, ignoreCase = true) }
                val result = if (tool == null) {
                    JSONObject()
                        .put("status", "error")
                        .put("error", "unknown_tool")
                        .put("tool", requestedName)
                        .put("available_tools", tools.map { it.name })
                        .toString()
                } else {
                    val args = runCatching { JSONObject(call.arguments.ifBlank { "{}" }) }
                        .getOrElse {
                            JSONObject()
                                .put("status", "error")
                                .put("error", "invalid_arguments")
                                .put("tool", requestedName)
                                .put("details", it.message.orEmpty())
                                .toString()
                        }
                    if (args is String) {
                        args
                    } else {
                        tool.execute(args as JSONObject).also { executedTools += tool.name }
                    }
                }
                val completed = call.copy(result = result)
                messages[messages.lastIndex] = messages.last().copy(
                    parts = messages.last().parts.map { if (it is RikkaPart.Tool && it.id == call.id) completed else it },
                )
                onParts(visibleParts + messages.last().parts)
            }
            visibleParts += messages.last().parts
        }
        // Hitting the ceiling is a runaway guard, not a normal outcome. Report it as
        // resumable and hand back whatever was produced, rather than discarding the
        // whole run with a bare error.
        throw AgentTurnLimitException(
            limit = maxSteps.coerceIn(1, MAX_AGENT_TURNS),
            partialText = visibleParts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }.trim(),
        )
    }

    private fun stream(messages: List<RikkaMessage>, tools: List<RikkaTool>, maxTokens: Int): Flow<List<RikkaPart>> =
        if (provider == "anthropic") streamAnthropic(messages, tools, maxTokens) else streamOpenAi(messages, tools, maxTokens)

    private fun streamOpenAi(messages: List<RikkaMessage>, tools: List<RikkaTool>, maxTokens: Int): Flow<List<RikkaPart>> = callbackFlow {
        val body = buildOpenAiBody(messages, tools, maxTokens)
        val request = requestBuilder(openAiUrl())
            .safeHeader("Authorization", "Bearer $apiKey")
            .applyCustomHeaders()
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        val toolMetadata = mutableMapOf<Int, Pair<String, String>>()
        val source = EventSources.createFactory(client).newEventSource(request, object : EventSourceListener() {
            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                if (data == "[DONE]") {
                    close()
                    return
                }
                runCatching {
                    val root = json.parseToJsonElement(data).jsonObject
                    root["error"]?.let { error(it.toString()) }
                    // The usage chunk arrives near the end and carries an empty
                    // choices array, so read it before the delta early-return.
                    recordUsage(parseUsage(root["usage"]?.jsonObject))
                    val delta = root["choices"]?.jsonArray?.firstOrNull()?.jsonObject?.get("delta")?.jsonObject
                        ?: return@runCatching
                    val parts = buildList {
                        delta["reasoning_content"]?.jsonPrimitive?.contentOrNull?.takeIf(String::isNotEmpty)?.let { add(RikkaPart.Reasoning(it)) }
                        delta["reasoning"]?.jsonPrimitive?.contentOrNull?.takeIf(String::isNotEmpty)?.let { add(RikkaPart.Reasoning(it)) }
                        delta["content"]?.jsonPrimitive?.contentOrNull?.takeIf(String::isNotEmpty)?.let { add(RikkaPart.Text(it)) }
                        delta["tool_calls"]?.jsonArray?.forEach { item ->
                            val tool = item.jsonObject
                            val index = tool["index"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0
                            val function = tool["function"]?.jsonObject ?: JsonObject(emptyMap())
                            val previous = toolMetadata[index]
                            val resolvedId = tool["id"]?.jsonPrimitive?.contentOrNull
                                ?.takeIf(String::isNotBlank)
                                ?: previous?.first
                                ?: "tool_call_$index"
                            val resolvedName = function["name"]?.jsonPrimitive?.contentOrNull
                                ?.takeIf(String::isNotBlank)
                                ?: previous?.second.orEmpty()
                            toolMetadata[index] = resolvedId to resolvedName
                            add(
                                RikkaPart.Tool(
                                    id = resolvedId,
                                    name = resolvedName,
                                    arguments = function["arguments"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                                    index = index,
                                ),
                            )
                        }
                    }
                    if (parts.isNotEmpty()) trySend(parts)
                }.onFailure { close(it) }
            }

            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                close(eventSourceFailure(t, response))
            }

            override fun onClosed(eventSource: EventSource) {
                close()
            }
        })
        awaitClose { source.cancel() }
    }.buffer(Channel.UNLIMITED)

    private fun streamAnthropic(messages: List<RikkaMessage>, tools: List<RikkaTool>, maxTokens: Int): Flow<List<RikkaPart>> = callbackFlow {
        val request = requestBuilder(anthropicUrl())
            .safeHeader("x-api-key", apiKey)
            .header("anthropic-version", "2023-06-01")
            .applyCustomHeaders()
            .post(buildAnthropicBody(messages, tools, maxTokens).toString().toRequestBody("application/json".toMediaType()))
            .build()
        val toolNames = mutableMapOf<Int, Pair<String, String>>()
        val source = EventSources.createFactory(client).newEventSource(request, object : EventSourceListener() {
            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                runCatching {
                    val root = json.parseToJsonElement(data).jsonObject
                    // Anthropic splits usage across frames: message_start carries
                    // input/cache counts, message_delta carries output_tokens.
                    recordUsage(parseUsage(root["message"]?.jsonObject?.get("usage")?.jsonObject))
                    recordUsage(parseUsage(root["usage"]?.jsonObject))
                    when (root["type"]?.jsonPrimitive?.contentOrNull) {
                        "content_block_start" -> {
                            val index = root["index"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0
                            val block = root["content_block"]?.jsonObject ?: return@runCatching
                            if (block["type"]?.jsonPrimitive?.contentOrNull == "tool_use") {
                                toolNames[index] = block["id"]?.jsonPrimitive?.contentOrNull.orEmpty() to block["name"]?.jsonPrimitive?.contentOrNull.orEmpty()
                                val pair = toolNames[index]!!
                                trySend(listOf(RikkaPart.Tool(pair.first, pair.second, "", index = index)))
                            }
                        }
                        "content_block_delta" -> {
                            val index = root["index"]?.jsonPrimitive?.content?.toIntOrNull() ?: 0
                            val delta = root["delta"]?.jsonObject ?: return@runCatching
                            when (delta["type"]?.jsonPrimitive?.contentOrNull) {
                                "text_delta" -> delta["text"]?.jsonPrimitive?.contentOrNull?.let { trySend(listOf(RikkaPart.Text(it))) }
                                "thinking_delta" -> delta["thinking"]?.jsonPrimitive?.contentOrNull?.let { trySend(listOf(RikkaPart.Reasoning(it))) }
                                "input_json_delta" -> toolNames[index]?.let { pair ->
                                    trySend(listOf(RikkaPart.Tool(pair.first, pair.second, delta["partial_json"]?.jsonPrimitive?.contentOrNull.orEmpty(), index = index)))
                                }
                            }
                        }
                        "message_stop" -> close()
                        "error" -> error(root["error"].toString())
                    }
                }.onFailure { close(it) }
            }

            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) {
                close(eventSourceFailure(t, response))
            }

            override fun onClosed(eventSource: EventSource) {
                close()
            }
        })
        awaitClose { source.cancel() }
    }.buffer(Channel.UNLIMITED)

    private fun eventSourceFailure(t: Throwable?, response: Response?): Throwable {
        if (response == null) {
            return t ?: IllegalStateException("SSE connection failed without an HTTP response")
        }
        val body = response.body
        val metadata = buildList {
            body.contentType()?.let { add("content-type=$it") }
            body.contentLength().takeIf { it >= 0L }?.let { add("content-length=$it") }
        }.joinToString(", ")
        // Read the error body. A context overflow states the model's real limit
        // here, and it was previously discarded — leaving the only authoritative
        // source of the window size unused. Capped because this is an error path
        // and the body is not necessarily small.
        val payload = runCatching { body.string().take(ERROR_BODY_LIMIT) }.getOrDefault("")
        val message = buildString {
            append("SSE HTTP ${response.code}")
            response.message.takeIf(String::isNotBlank)?.let { append(" $it") }
            if (metadata.isNotEmpty()) append(" ($metadata)")
            t?.message?.takeIf(String::isNotBlank)?.let { append(": $it") }
            payload.takeIf(String::isNotBlank)?.let { append(" body=$it") }
        }
        if (ContextWindow.isOverflowError(message)) {
            return ContextOverflowException(message, ContextWindow.parseLimitFromError(message), t)
        }
        return IllegalStateException(message, t)
    }

    private fun mergeParts(current: List<RikkaPart>, deltas: List<RikkaPart>): List<RikkaPart> =
        deltas.fold(current) { parts, delta ->
            when (delta) {
                is RikkaPart.Text -> if (parts.lastOrNull() is RikkaPart.Text) parts.dropLast(1) + RikkaPart.Text((parts.last() as RikkaPart.Text).text + delta.text) else parts + delta
                is RikkaPart.Reasoning -> if (parts.lastOrNull() is RikkaPart.Reasoning) parts.dropLast(1) + RikkaPart.Reasoning((parts.last() as RikkaPart.Reasoning).text + delta.text) else parts + delta
                is RikkaPart.Tool -> {
                    val target = parts.indexOfLast {
                        it is RikkaPart.Tool && (it.index == delta.index || (delta.id.isNotBlank() && it.id == delta.id))
                    }
                    if (target < 0) parts + delta else parts.toMutableList().apply {
                        val old = this[target] as RikkaPart.Tool
                        this[target] = old.copy(
                            id = delta.id.ifBlank { old.id },
                            name = delta.name.ifBlank { old.name },
                            arguments = old.arguments + delta.arguments,
                            result = delta.result ?: old.result,
                        )
                    }
                }
            }
        }

    private fun buildOpenAiBody(messages: List<RikkaMessage>, tools: List<RikkaTool>, maxTokens: Int) = buildJsonObject {
        put("model", model)
        put("stream", true)
        put("max_tokens", maxTokens)
        // OpenAI-compatible endpoints omit `usage` from streamed responses unless
        // this is set. Without it every chunk lacks token counts and the context
        // budget has nothing to measure. Gateways that reject the field can drop it
        // via the custom-body setting, which is applied last and overwrites this.
        put("stream_options", buildJsonObject { put("include_usage", true) })
        put("temperature", temperature)
        putJsonArray("messages") {
            messages.forEach { message ->
                add(buildJsonObject {
                    put("role", message.role)
                    put("content", message.parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text })
                    val calls = message.parts.filterIsInstance<RikkaPart.Tool>()
                    if (message.role == "assistant" && calls.isNotEmpty()) {
                        putJsonArray("tool_calls") {
                            calls.forEach { call -> add(buildJsonObject {
                                put("id", call.id)
                                put("type", "function")
                                put("function", buildJsonObject { put("name", call.name); put("arguments", call.arguments) })
                            }) }
                        }
                    }
                })
                message.parts.filterIsInstance<RikkaPart.Tool>().filter { it.result != null }.forEach { call ->
                    add(buildJsonObject { put("role", "tool"); put("tool_call_id", call.id); put("content", call.result.orEmpty()) })
                }
            }
        }
        putJsonArray("tools") {
            tools.forEach { tool -> add(buildJsonObject {
                put("type", "function")
                put("function", buildJsonObject {
                    put("name", tool.name); put("description", tool.description)
                    put("parameters", json.parseToJsonElement(tool.schema.toString()))
                })
            }) }
        }
        customBody.filterKeys { it != "max_tokens" }.forEach { (key, value) -> put(key, value) }
    }

    private fun buildAnthropicBody(messages: List<RikkaMessage>, tools: List<RikkaTool>, maxTokens: Int) = buildJsonObject {
        put("model", model); put("stream", true); put("max_tokens", maxTokens); put("temperature", temperature)
        put("system", messages.firstOrNull { it.role == "system" }?.parts?.filterIsInstance<RikkaPart.Text>()?.joinToString("") { it.text }.orEmpty())
        putJsonArray("messages") {
            messages.filter { it.role != "system" }.forEach { message ->
                if (message.role != "assistant") {
                    add(buildJsonObject {
                        put("role", message.role)
                        putJsonArray("content") {
                            message.parts.filterIsInstance<RikkaPart.Text>().forEach { part ->
                                add(buildJsonObject { put("type", "text"); put("text", part.text) })
                            }
                        }
                    })
                } else {
                    add(buildJsonObject {
                        put("role", "assistant")
                        putJsonArray("content") {
                            message.parts.forEach { part -> when (part) {
                                is RikkaPart.Text -> add(buildJsonObject { put("type", "text"); put("text", part.text) })
                                is RikkaPart.Reasoning -> Unit
                                is RikkaPart.Tool -> add(buildJsonObject {
                                    put("type", "tool_use"); put("id", part.id); put("name", part.name)
                                    put("input", runCatching { json.parseToJsonElement(part.arguments) }.getOrElse { JsonObject(emptyMap()) })
                                })
                            } }
                        }
                    })
                    val completed = message.parts.filterIsInstance<RikkaPart.Tool>().filter { it.result != null }
                    if (completed.isNotEmpty()) {
                        add(buildJsonObject {
                            put("role", "user")
                            putJsonArray("content") {
                                completed.forEach { part -> add(buildJsonObject {
                                    put("type", "tool_result"); put("tool_use_id", part.id); put("content", part.result.orEmpty())
                                }) }
                            }
                        })
                    }
                }
            }
        }
        putJsonArray("tools") { tools.forEach { tool -> add(buildJsonObject { put("name", tool.name); put("description", tool.description); put("input_schema", json.parseToJsonElement(tool.schema.toString())) }) } }
        customBody.filterKeys { it != "max_tokens" }.forEach { (key, value) -> put(key, value) }
    }

    private fun requestedOutputCeiling(): Int = customBody["max_tokens"]
        ?.jsonPrimitive?.contentOrNull?.toIntOrNull()
        ?.coerceIn(ContextBudget.MIN_OUTPUT_TOKENS, ContextBudget.GLOBAL_OUTPUT_CEILING)
        ?: ContextBudget.DEFAULT_OUTPUT_CEILING

    private fun requestBuilder(url: String) = Request.Builder().url(url).header("Accept", "text/event-stream")

    private fun Request.Builder.applyCustomHeaders() = apply {
        customHeaders.forEach { (name, value) -> safeHeader(name, value) }
    }

    private fun openAiUrl(): String = endpoint.trimEnd('/').let { if (it.endsWith("/chat/completions")) it else "$it/chat/completions" }
    private fun anthropicUrl(): String = endpoint.trimEnd('/').let { if (it.endsWith("/messages")) it else if (it.endsWith("/v1")) "$it/messages" else "$it/v1/messages" }
}
