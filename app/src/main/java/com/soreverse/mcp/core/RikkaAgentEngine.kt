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

    suspend fun run(
        systemPrompt: String,
        userPrompt: String,
        tools: List<RikkaTool>,
        maxSteps: Int,
        requiredTools: List<String> = emptyList(),
        onParts: (List<RikkaPart>) -> Unit,
    ): String {
        val messages = mutableListOf(
            RikkaMessage("system", listOf(RikkaPart.Text(systemPrompt))),
            RikkaMessage("user", listOf(RikkaPart.Text(userPrompt))),
        )
        val visibleParts = mutableListOf<RikkaPart>()
        val executedTools = linkedSetOf<String>()
        repeat(maxSteps.coerceIn(1, 256)) {
            var assistant = RikkaMessage("assistant", emptyList())
            stream(messages, tools).collect { delta ->
                assistant = assistant.copy(parts = mergeParts(assistant.parts, delta))
                onParts(visibleParts + assistant.parts)
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
        error("Maximum tool steps exceeded")
    }

    private fun stream(messages: List<RikkaMessage>, tools: List<RikkaTool>): Flow<List<RikkaPart>> =
        if (provider == "anthropic") streamAnthropic(messages, tools) else streamOpenAi(messages, tools)

    private fun streamOpenAi(messages: List<RikkaMessage>, tools: List<RikkaTool>): Flow<List<RikkaPart>> = callbackFlow {
        val body = buildOpenAiBody(messages, tools)
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

    private fun streamAnthropic(messages: List<RikkaMessage>, tools: List<RikkaTool>): Flow<List<RikkaPart>> = callbackFlow {
        val request = requestBuilder(anthropicUrl())
            .safeHeader("x-api-key", apiKey)
            .header("anthropic-version", "2023-06-01")
            .applyCustomHeaders()
            .post(buildAnthropicBody(messages, tools).toString().toRequestBody("application/json".toMediaType()))
            .build()
        val toolNames = mutableMapOf<Int, Pair<String, String>>()
        val source = EventSources.createFactory(client).newEventSource(request, object : EventSourceListener() {
            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                runCatching {
                    val root = json.parseToJsonElement(data).jsonObject
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
        val message = buildString {
            append("SSE HTTP ${response.code}")
            response.message.takeIf(String::isNotBlank)?.let { append(" $it") }
            if (metadata.isNotEmpty()) append(" ($metadata)")
            t?.message?.takeIf(String::isNotBlank)?.let { append(": $it") }
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

    private fun buildOpenAiBody(messages: List<RikkaMessage>, tools: List<RikkaTool>) = buildJsonObject {
        put("model", model)
        put("stream", true)
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
        customBody.forEach { (key, value) -> put(key, value) }
    }

    private fun buildAnthropicBody(messages: List<RikkaMessage>, tools: List<RikkaTool>) = buildJsonObject {
        put("model", model); put("stream", true); put("max_tokens", 16_384); put("temperature", temperature)
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
        customBody.forEach { (key, value) -> put(key, value) }
    }

    private fun requestBuilder(url: String) = Request.Builder().url(url).header("Accept", "text/event-stream")

    private fun Request.Builder.applyCustomHeaders() = apply {
        customHeaders.forEach { (name, value) -> safeHeader(name, value) }
    }

    private fun openAiUrl(): String = endpoint.trimEnd('/').let { if (it.endsWith("/chat/completions")) it else "$it/chat/completions" }
    private fun anthropicUrl(): String = endpoint.trimEnd('/').let { if (it.endsWith("/messages")) it else if (it.endsWith("/v1")) "$it/messages" else "$it/v1/messages" }
}
