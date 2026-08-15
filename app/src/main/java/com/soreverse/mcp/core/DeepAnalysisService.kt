package com.soreverse.mcp.core

import android.content.Context
import android.util.Log
import com.soreverse.mcp.mcp.SchemaBuilder
import com.soreverse.mcp.mcp.ToolCatalog
import com.soreverse.mcp.mcp.ToolContext
import com.soreverse.mcp.service.McpForegroundService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONObject as OrgJSONObject
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

data class DeepAnalysisEvent(
    val kind: Kind,
    val text: String,
    val toolName: String = "",
) {
    enum class Kind { STATUS, THINKING, TOOL, FINALIZING, TEXT, ERROR, DONE }
}

class DeepAnalysisService(private val appContext: Context) {
    private val _events = MutableSharedFlow<DeepAnalysisEvent>(extraBufferCapacity = 256)
    val events: SharedFlow<DeepAnalysisEvent> = _events
    private val _reportDraft = MutableStateFlow("")
    val reportDraft: StateFlow<String> = _reportDraft
    private val _partsDraft = MutableStateFlow<List<RikkaPart>>(emptyList())
    val partsDraft: StateFlow<List<RikkaPart>> = _partsDraft
    private val _workspaceId = MutableStateFlow("")
    val workspaceId: StateFlow<String> = _workspaceId
    private var analysisRunId = 0L

    /**
     * Token usage reported by the provider for the run in progress, updated after
     * each agent turn. Empty when the endpoint returns no `usage` (some gateways
     * strip it, and OpenAI-compatible servers only send it when
     * `stream_options.include_usage` is accepted).
     */
    private val _usage = MutableStateFlow(RikkaRunUsage())
    val usage: StateFlow<RikkaRunUsage> = _usage

    fun resetReportDraft(resetWorkspace: Boolean = true) {
        _reportDraft.value = ""
        _partsDraft.value = emptyList()
        _usage.value = RikkaRunUsage()
        if (resetWorkspace) _workspaceId.value = ""
    }

    suspend fun listModels(settings: SettingsStore): Result<List<String>> = withContext(Dispatchers.IO) {
        runCatching {
            requireModelCatalogConfigured(settings)
            fetchModelCatalog(settings)
        }.onFailure { Log.e("SOMCP-DeepAnalysis", "Model listing failed", it) }
    }

    private fun fetchModelCatalog(settings: SettingsStore): List<String> {
        val client = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build()
        val customHeaders = parseStringMap(settings.aiCustomHeadersJson)
        val models = linkedSetOf<String>()
        val windows = mutableMapOf<String, Int>()
        val seenCursors = mutableSetOf<String>()
        var cursor: String? = null
        var nextUrl: String? = null

        repeat(50) {
            val baseUrl = nextUrl ?: modelCatalogUrl(settings, cursor)
            val request = Request.Builder()
                .url(baseUrl)
                .header("Accept", "application/json")
                .apply {
                    if (settings.aiProvider == "anthropic") {
                        safeHeader("x-api-key", settings.aiApiKey)
                        header("anthropic-version", "2023-06-01")
                    } else {
                        safeHeader("Authorization", "Bearer ${settings.aiApiKey}")
                    }
                    customHeaders.forEach { (name, value) -> safeHeader(name, value) }
                }
                .build()
            val page = client.newCall(request).execute().use { response ->
                val body = response.body.string()
                if (!response.isSuccessful) {
                    error("Model listing failed: HTTP ${response.code} ${body.take(300)}")
                }
                parseModelPage(body)
            }
            models.addAll(page.models)
            windows.putAll(page.contextWindows)
            if (models.size >= 5_000) {
                settings.cacheModelContextWindows(windows)
                return models.take(5_000).sorted()
            }
            val continuation = page.nextUrl ?: page.cursor
            if (!page.hasMore || continuation.isNullOrBlank()) {
                settings.cacheModelContextWindows(windows)
                return models.sorted()
            }
            if (!seenCursors.add(continuation)) error("Model pagination cursor did not advance")
            nextUrl = page.nextUrl
            cursor = page.cursor
        }
        settings.cacheModelContextWindows(windows)
        return models.sorted()
    }

    private fun modelCatalogUrl(settings: SettingsStore, cursor: String?): String {
        val endpoint = settings.aiEndpoint.trimEnd('/')
        val path = when {
            endpoint.endsWith("/models") -> endpoint
            settings.aiProvider == "anthropic" && endpoint.endsWith("/v1") -> "$endpoint/models"
            settings.aiProvider == "anthropic" -> "$endpoint/v1/models"
            else -> "$endpoint/models"
        }
        return path.toHttpUrl().newBuilder().apply {
            if (settings.aiProvider == "anthropic") {
                addQueryParameter("limit", "100")
                cursor?.let { addQueryParameter("after_id", it) }
            } else {
                cursor?.let { addQueryParameter("cursor", it) }
            }
        }.build().toString()
    }

    private fun parseModelPage(raw: String): ModelPage {
        val text = raw.trim()
        val rootArray = if (text.startsWith("[")) JSONArray(text) else null
        val root = if (rootArray == null) OrgJSONObject(text) else null
        val array = rootArray
            ?: listOf("data", "models", "items")
                .firstNotNullOfOrNull { root?.optJSONArray(it) }
            ?: JSONArray()
        val models = buildList {
            for (index in 0 until array.length()) {
                when (val item = array.opt(index)) {
                    is String -> item.takeIf(String::isNotBlank)?.let(::add)
                    is OrgJSONObject -> listOf("id", "model_id", "model", "name")
                        .firstNotNullOfOrNull { key -> item.optString(key).takeIf(String::isNotBlank) }
                        ?.let(::add)
                }
            }
        }
        // Capture the context window alongside the id. This is the authoritative
        // source when the provider publishes it; entries without one are simply
        // absent from the map, which keeps the window honestly unknown rather than
        // inviting a guess from the model name.
        val windows = buildMap {
            for (index in 0 until array.length()) {
                val item = array.opt(index) as? OrgJSONObject ?: continue
                val id = listOf("id", "model_id", "model", "name")
                    .firstNotNullOfOrNull { key -> item.optString(key).takeIf(String::isNotBlank) }
                    ?: continue
                ContextWindow.parseFromModelEntry(item)?.let { put(id, it) }
            }
        }
        val pagination = root?.optJSONObject("pagination")
        val nextValue = listOfNotNull(
            root?.optString("next_cursor")?.takeIf(String::isNotBlank),
            root?.optString("last_id")?.takeIf(String::isNotBlank),
            pagination?.optString("next_cursor")?.takeIf(String::isNotBlank),
        ).firstOrNull()
        val nextUrl = listOfNotNull(
            root?.optString("next")?.takeIf { it.startsWith("http") },
            pagination?.optString("next")?.takeIf { it.startsWith("http") },
        ).firstOrNull()
        val hasMore = root?.optBoolean("has_more", false) == true ||
            nextValue != null || nextUrl != null
        return ModelPage(models, windows, hasMore, nextValue, nextUrl)
    }

    private data class ModelPage(
        val models: List<String>,
        /** Model id to context window, for entries that report one. */
        val contextWindows: Map<String, Int>,
        val hasMore: Boolean,
        val cursor: String?,
        val nextUrl: String?,
    )

    suspend fun analyze(path: String, settings: SettingsStore, zh: Boolean, request: String = ""): Result<String> = withContext(Dispatchers.IO) {
        _reportDraft.value = ""
        var lastFailure: Throwable? = null
        repeat(3) { attempt ->
            val result = analyzeOnce(path, settings, zh, request)
            if (result.isSuccess) return@withContext result
            val failure = result.exceptionOrNull() ?: return@withContext result
            if (failure is CancellationException) throw failure
            lastFailure = failure
            if (attempt == 2 || !isRetryable(failure)) {
                val message = friendlyError(failure, zh)
                emit(DeepAnalysisEvent.Kind.ERROR, message)
                return@withContext Result.failure(IllegalStateException(message, failure))
            }
            val waitSeconds = retryAfterSeconds(failure)
            emit(
                DeepAnalysisEvent.Kind.STATUS,
                if (zh) "服务繁忙，${waitSeconds} 秒后自动重试（${attempt + 2}/3）…" else "Service busy. Retrying in ${waitSeconds}s (${attempt + 2}/3)…",
            )
            delay(waitSeconds * 1_000L)
        }
        Result.failure(lastFailure ?: IllegalStateException(if (zh) "AI 深度分析失败" else "AI deep analysis failed"))
    }

    private suspend fun analyzeOnce(path: String, settings: SettingsStore, zh: Boolean, request: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            // Declared here so the AgentTurnLimitException handler below can reach it.
            if (!McpForegroundService.isRunning()) {
                error(if (zh) "请先开启 MCP 服务后再进行 AI 深度分析" else "Start the MCP service before AI deep analysis")
            }
            requireConfigured(settings)
            emit(DeepAnalysisEvent.Kind.STATUS, if (zh) "正在初始化 AI 会话…" else "Initializing AI session…")
            val userPrompt = buildUserPrompt(path, zh, request)
            val engine = RikkaAgentEngine(
                client = OkHttpClient.Builder().connectTimeout(20, TimeUnit.SECONDS).readTimeout(10, TimeUnit.MINUTES).writeTimeout(120, TimeUnit.SECONDS).retryOnConnectionFailure(true).build(),
                provider = settings.aiProvider,
                endpoint = settings.aiEndpoint,
                apiKey = settings.aiApiKey,
                model = settings.aiModel,
                temperature = settings.aiTemperature,
                customHeaders = parseStringMap(settings.aiCustomHeadersJson),
                customBody = buildAdditionalProperties(settings),
            )
            val tools = buildRikkaTools(settings, zh)
            var lastReasoning = ""
            // Context management runs inside the loop but needs a model call for
            // summarisation, so it is supplied from here.
            val runDir = java.io.File(appContext.cacheDir, "ai-offload/run-${++analysisRunId}").apply {
                if (!exists()) mkdirs()
            }
            val contextManager = ContextManager(
                contextWindow = settings.contextBudgetTokens,
                offloadDir = runDir,
                summarise = { messages -> summariseMessages(messages, settings) },
                onEvent = { note -> emit(DeepAnalysisEvent.Kind.STATUS, note) },
            )
            val finalReport = engine.run(
                systemPrompt = settings.aiSystemPrompt,
                userPrompt = userPrompt,
                tools = tools,
                maxSteps = settings.aiMaxIterations,
                requiredTools = REQUIRED_EVIDENCE_TOOLS,
                contextManager = contextManager,
            ) { parts ->
                _partsDraft.value = parts
                // engine.runUsage is refreshed once per completed turn; mirror it so
                // the UI can show real context pressure instead of a guessed limit.
                if (engine.runUsage.turns != _usage.value.turns) _usage.value = engine.runUsage
                val report = parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }
                if (report.isNotEmpty()) _reportDraft.value = report
                val reasoning = parts.filterIsInstance<RikkaPart.Reasoning>().joinToString("") { it.text }
                if (reasoning.length > lastReasoning.length) {
                    emit(DeepAnalysisEvent.Kind.THINKING, reasoning.drop(lastReasoning.length))
                    lastReasoning = reasoning
                }
            }
            _usage.value = engine.runUsage
            if (finalReport.isBlank()) error(if (zh) "模型返回了空的分析结果" else "The model returned an empty analysis result")
            _reportDraft.value = finalReport
            emit(DeepAnalysisEvent.Kind.DONE, finalReport)
            finalReport
        }.recoverCatching { error ->
            // Hitting the turn ceiling is a stop condition, not a lost run: keep the
            // prose already produced and label it, instead of discarding everything.
            val limit = generateSequence(error) { it.cause }
                .filterIsInstance<AgentTurnLimitException>()
                .firstOrNull() ?: throw error
            val note = if (zh) {
                "已达到 ${limit.limit} 轮工具调用上限并停止，以防止无限循环。以下是已完成的部分分析。"
            } else {
                "Stopped at the ${limit.limit}-turn tool-call ceiling to prevent a runaway loop. Partial analysis follows."
            }
            emit(DeepAnalysisEvent.Kind.STATUS, note)
            val partial = limit.partialText.ifBlank { _reportDraft.value }
            if (partial.isBlank()) throw error
            val combined = "$note\n\n$partial"
            _reportDraft.value = combined
            emit(DeepAnalysisEvent.Kind.DONE, combined)
            combined
        }.onFailure { error ->
            recordContextOverflow(error, settings)
            Log.e("SOMCP-DeepAnalysis", "AI deep analysis failed", error)
        }
    }

    /**
     * When a run fails because the context window overflowed, persist the limit the
     * provider reported so subsequent runs budget against a measured number rather
     * than a name-derived guess.
     *
     * Only a strictly smaller value is stored: some gateways report the limit of a
     * larger upstream model, and raising the figure on a failure would leave the
     * budget higher than the request that just failed.
     */
    private suspend fun summariseMessages(
        messages: List<RikkaMessage>,
        settings: SettingsStore,
        depth: Int = 0,
    ): String {
        val transcript = ContextCompactor.buildTranscript(messages)
        return try {
            summariseTranscript(transcript, settings)
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            if (!ContextWindow.isOverflowError(error.message) || messages.size < 2 || depth >= 3) throw error
            val midpoint = messages.size / 2
            val older = summariseMessages(messages.take(midpoint), settings, depth + 1)
            val newer = summariseMessages(messages.drop(midpoint), settings, depth + 1)
            summariseTranscript(
                buildString {
                    append("Merge these partial context summaries into one. Frame all facts as past events, not an ongoing goal or todo list. ")
                    append("Preserve paths, identifiers, tool outcomes, decisions, and constraints verbatim. Prefer Part 2 when space is tight.\n\n")
                    append("Part 1:\n").append(older).append("\n\nPart 2:\n").append(newer)
                },
                settings,
            )
        }
    }

    /**
     * One-shot summarisation call used by [ContextManager].
     *
     * Deliberately does not reuse the agent engine: no tools are offered, so the
     * model cannot start doing work while summarising, and a low temperature keeps
     * identifiers verbatim. [summariseMessages] retries an overflow by splitting
     * on message boundaries, matching OpenMinis' bounded split/merge ladder.
     */
    private suspend fun summariseTranscript(transcript: String, settings: SettingsStore): String {
        val engine = RikkaAgentEngine(
            client = OkHttpClient.Builder()
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(4, TimeUnit.MINUTES)
                .writeTimeout(120, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build(),
            provider = settings.aiProvider,
            endpoint = settings.aiEndpoint,
            apiKey = settings.aiApiKey,
            model = settings.aiModel,
            temperature = 0f,
            customHeaders = parseStringMap(settings.aiCustomHeadersJson),
            customBody = buildAdditionalProperties(settings),
        )
        return engine.run(
            systemPrompt = ContextCompactor.SUMMARY_SYSTEM_PROMPT,
            userPrompt = "Compact this conversation into a context summary:\n\n$transcript",
            tools = emptyList(),
            maxSteps = 1,
            contextBudgetTokens = settings.contextBudgetTokens,
            summaryRequest = true,
        ) { }
    }

    private fun recordContextOverflow(error: Throwable, settings: SettingsStore) {
        val overflow = generateSequence(error) { it.cause }.filterIsInstance<ContextOverflowException>().firstOrNull()
            ?: return
        val limit = overflow.reportedLimit ?: return
        if (limit < AI_MIN_CONTEXT_WINDOW) return
        val current = settings.effectiveContextWindow
        // Accept the measured value when nothing was known, or when it is strictly
        // smaller than what is in force. Raising the budget after a failure would
        // leave it above the request that just failed — some gateways report the
        // limit of a larger upstream model.
        if (current <= 0 || limit < current) {
            settings.aiContextWindowMeasured = limit
            Log.i("SOMCP-DeepAnalysis", "context window measured from provider error: $limit (was ${if (current <= 0) "unknown" else current.toString()})")
        }
    }

    private fun isRetryable(error: Throwable): Boolean {
        val message = generateSequence(error) { it.cause }.joinToString("\n") { it.message.orEmpty() }
        // A context overflow is deterministic: the same oversized request fails
        // identically every time, so retrying only burns quota. Some gateways
        // return it as HTTP 400 or 500, which the status regex below would
        // otherwise treat as transient.
        if (ContextWindow.isOverflowError(message)) return false
        return Regex("(?:Status code:|SSE HTTP|HTTP)\\s*(408|409|425|429|5\\d\\d)", RegexOption.IGNORE_CASE).containsMatchIn(message) ||
            message.contains("rate_limit_error", true) ||
            message.contains("rate limit", true) ||
            message.contains("concurrency limit", true) ||
            message.contains("retry later", true) ||
            message.contains("timeout", true) ||
            message.contains("temporarily unavailable", true)
    }

    private fun retryAfterSeconds(error: Throwable): Int {
        val message = generateSequence(error) { it.cause }.joinToString("\n") { it.message.orEmpty() }
        return Regex("retry_after[\\\"']?\\s*[:=]\\s*(\\d+)", RegexOption.IGNORE_CASE)
            .find(message)?.groupValues?.getOrNull(1)?.toIntOrNull()?.coerceIn(3, 120)
            ?: if (message.contains("concurrency limit", true)) 5 else 10
    }

    private fun friendlyError(error: Throwable, zh: Boolean): String {
        val message = generateSequence(error) { it.cause }.joinToString("\n") { it.message.orEmpty() }
        val status = Regex("(?:Status code:|SSE HTTP|HTTP)\\s*(\\d{3})", RegexOption.IGNORE_CASE).find(message)?.groupValues?.getOrNull(1)
        val retryAfter = retryAfterSeconds(error)
        return when {
            status == "504" -> if (zh) "模型服务网关超时（504）。已自动重试仍未恢复，请等待约 $retryAfter 秒后再试。" else "Model gateway timed out (504). Automatic retry did not recover; try again in about ${retryAfter}s."
            status == "429" -> if (zh) "模型服务请求过于频繁（429），请等待约 $retryAfter 秒后重试。" else "Model service rate limit reached (429). Retry in about ${retryAfter}s."
            message.contains("concurrency limit", true) || message.contains("rate_limit_error", true) -> if (zh) "模型服务并发额度仍然繁忙，已自动重试 3 次，请稍后再试。" else "The model service concurrency limit is still busy after 3 retries. Try again later."
            status != null -> if (zh) "模型服务请求失败（HTTP $status），请检查端点状态或稍后重试。" else "Model request failed (HTTP $status). Check the endpoint or retry later."
            else -> error.message?.lineSequence()?.firstOrNull()?.take(220) ?: if (zh) "AI 深度分析失败" else "AI deep analysis failed"
        }
    }

    private fun buildUserPrompt(path: String, zh: Boolean, request: String): String {
        val focus = request.trim().takeIf(String::isNotBlank)
        return if (zh) {
            """请对以下 Android native SO 执行深度逆向分析，并输出结构化报告。
目标文件: $path
${focus?.let { "用户本轮问题: $it" }.orEmpty()}

必须按以下阶段调用 MCP 工具取证：
so_open → analyze_functions → analyze_cfg → analyze_xrefs → analyze_crypto → analysis_report
每个阶段都必须依据前序工具结果填写 workspaceId、函数定位符等参数，不得用中间文字代替工具调用。

最终报告请包含：概览、安全特征、关键函数、加密/网络、攻击面、可行性、下一步建议。
只有完成必要取证后，才返回最终 Markdown 报告；不要把中间计划当作最终报告，也不要在报告前后添加“接下来将……”之类的过程性文字。"""
        } else {
            """Perform a deep reverse-engineering analysis of this Android native SO and produce a structured report.
Target file: $path
${focus?.let { "User request for this turn: $it" }.orEmpty()}

Gather evidence through every MCP stage in this order:
so_open → analyze_functions → analyze_cfg → analyze_xrefs → analyze_crypto → analysis_report
Use workspace IDs, function locators, and other arguments from prior tool results. Never replace a required tool call with intermediate prose.

Final report sections: Overview, Security, Key Functions, Crypto/Network, Attack Surface, Feasibility, Next Steps.
Only after gathering the necessary evidence, return the final Markdown report. Do not present an intermediate plan as the final report, and do not add process text such as “next I will…” before or after it."""
        }
    }

    private fun buildRikkaTools(settings: SettingsStore, zh: Boolean): List<RikkaTool> {
        val engine = EngineProvider.get(appContext)
        val ctx = ToolContext(appContext, settings, engine)
        return DEEP_TOOL_NAMES.mapNotNull { name ->
            val handler = ToolCatalog.byName[name] ?: return@mapNotNull null
            val schema = handler.meta.schemaBuilder.invoke(SchemaBuilder)
            RikkaTool(
                name = name,
                description = if (zh) handler.meta.zh else handler.meta.en,
                schema = schema,
            ) { args ->
                emit(DeepAnalysisEvent.Kind.TOOL, if (zh) "调用工具 $name" else "Calling tool $name", name)
                AppLog.i("AI tool call $name args=${args.toString().take(600)}")
                val effectiveArgs = JSONObject(args.toString()).apply {
                    if (name != "so_open" && optString("workspaceId").isBlank()) {
                        _workspaceId.value.takeIf(String::isNotBlank)?.let { put("workspaceId", it) }
                    }
                }
                runCatching { handler.handle(ctx, effectiveArgs) }
                    .onSuccess { payload ->
                        if (name == "so_open") {
                            payload.optString("workspaceId").takeIf(String::isNotBlank)?.let {
                                _workspaceId.value = it
                            }
                        }
                        AppLog.i("AI tool completed $name result=${payload.toString().take(600)}")
                    }
                    .onFailure { error ->
                        AppLog.e("AI tool failed $name", error)
                    }
                    .getOrThrow()
                    .let { payload ->
                        val text = payload.toString()
                        val limit = settings.toolResultMaxChars
                        val result = if (limit <= 0 || text.length <= limit) text else text.take(limit) + "…"
                        emit(DeepAnalysisEvent.Kind.TOOL, if (zh) "工具完成 $name" else "Tool completed $name", name)
                        if (name == "analysis_report") emit(DeepAnalysisEvent.Kind.FINALIZING, if (zh) "MCP 取证已完成" else "MCP evidence complete")
                        result
                    }
            }
        }
    }

    private fun parseStringMap(raw: String): Map<String, String> {
        val obj = runCatching { OrgJSONObject(raw.ifBlank { "{}" }) }.getOrNull() ?: return emptyMap()
        return buildMap {
            val keys = obj.keys()
            while (keys.hasNext()) {
                val key = keys.next().trim()
                if (key.isNotBlank()) put(key, obj.optString(key))
            }
        }
    }

    private fun buildAdditionalProperties(settings: SettingsStore): Map<String, JsonElement> {
        val properties = LinkedHashMap<String, JsonElement>()
        val body = runCatching { OrgJSONObject(settings.aiCustomBodyJson.ifBlank { "{}" }) }.getOrNull()
            ?: return properties
        val keys = body.keys()
        while (keys.hasNext()) {
            val key = keys.next().trim()
            if (key.isBlank()) continue
            val value = body.opt(key)
            properties[key] = runCatching {
                Json.parseToJsonElement(
                    when (value) {
                        null, OrgJSONObject.NULL -> "null"
                        is String -> OrgJSONObject.quote(value)
                        else -> value.toString()
                    },
                )
            }.getOrElse { JsonPrimitive(value?.toString().orEmpty()) }
        }
        return properties
    }


    private fun requireConfigured(settings: SettingsStore) {
        if (settings.aiApiKey.isBlank()) error("AI API key is empty")
        if (settings.aiModel.isBlank()) error("AI model is empty")
        if (settings.aiEndpoint.isBlank()) error("AI endpoint is empty")
    }

    private fun requireModelCatalogConfigured(settings: SettingsStore) {
        if (settings.aiApiKey.isBlank()) error("AI API key is empty")
        if (settings.aiEndpoint.isBlank()) error("AI endpoint is empty")
    }

    private fun emit(kind: DeepAnalysisEvent.Kind, text: String, toolName: String = "") {
        _events.tryEmit(DeepAnalysisEvent(kind, text, toolName))
    }

    private companion object {
        val DEEP_TOOL_NAMES = listOf(
            "so_open",
            "analyze_functions",
            "analyze_cfg",
            "analyze_xrefs",
            "analyze_crypto",
            "analysis_report",
            "search_strings",
            "search_bytes",
            "read_disasm",
            "read_hexdump",
            "list_sos",
            "meta_info",
        )
        val REQUIRED_EVIDENCE_TOOLS = listOf(
            "so_open",
            "analyze_functions",
            "analyze_cfg",
            "analyze_xrefs",
            "analyze_crypto",
            "analysis_report",
        )

    }
}
