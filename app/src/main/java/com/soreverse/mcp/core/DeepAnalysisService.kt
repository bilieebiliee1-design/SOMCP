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

    fun resetReportDraft(resetWorkspace: Boolean = true) {
        _reportDraft.value = ""
        _partsDraft.value = emptyList()
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
            if (models.size >= 5_000) return models.take(5_000).sorted()
            val continuation = page.nextUrl ?: page.cursor
            if (!page.hasMore || continuation.isNullOrBlank()) return models.sorted()
            if (!seenCursors.add(continuation)) error("Model pagination cursor did not advance")
            nextUrl = page.nextUrl
            cursor = page.cursor
        }
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
        return ModelPage(models, hasMore, nextValue, nextUrl)
    }

    private data class ModelPage(
        val models: List<String>,
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
            val finalReport = engine.run(
                settings.aiSystemPrompt,
                userPrompt,
                tools,
                settings.aiMaxIterations.coerceIn(20, 256),
                requiredTools = REQUIRED_EVIDENCE_TOOLS,
            ) { parts ->
                _partsDraft.value = parts
                val report = parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }
                if (report.isNotEmpty()) _reportDraft.value = report
                val reasoning = parts.filterIsInstance<RikkaPart.Reasoning>().joinToString("") { it.text }
                if (reasoning.length > lastReasoning.length) {
                    emit(DeepAnalysisEvent.Kind.THINKING, reasoning.drop(lastReasoning.length))
                    lastReasoning = reasoning
                }
            }
            if (finalReport.isBlank()) error(if (zh) "模型返回了空的分析结果" else "The model returned an empty analysis result")
            _reportDraft.value = finalReport
            emit(DeepAnalysisEvent.Kind.DONE, finalReport)
            finalReport
        }.onFailure { Log.e("SOMCP-DeepAnalysis", "AI deep analysis failed", it) }
    }

    private fun isRetryable(error: Throwable): Boolean {
        val message = generateSequence(error) { it.cause }.joinToString("\n") { it.message.orEmpty() }
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
