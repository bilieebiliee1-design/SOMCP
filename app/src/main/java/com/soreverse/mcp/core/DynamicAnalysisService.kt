// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// DynamicAnalysisService: the standalone AI analysis that consumes the
// dynamicRun evidence produced by the dynamic-analysis MCP workflow
// (unidbg emulation and/or Frida on-device hooking). It is deliberately
// independent from the static DeepAnalysisService loop: the input is the
// runtime evidence envelope, and the AI may call dynamic MCP tools for
// follow-up before producing a Markdown report.
package com.soreverse.mcp.core

import android.content.Context
import android.util.Log
import com.soreverse.mcp.mcp.SchemaBuilder
import com.soreverse.mcp.mcp.ToolCatalog
import com.soreverse.mcp.mcp.ToolContext
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import org.json.JSONObject

data class DynamicAnalysisEvent(val kind: Kind, val text: String, val toolName: String = "") {
    enum class Kind { STATUS, THINKING, TOOL, FINALIZING, TEXT, ERROR, DONE }
}

class DynamicAnalysisService(private val appContext: Context) {
    private val _events = MutableSharedFlow<DynamicAnalysisEvent>(extraBufferCapacity = 128)
    val events: SharedFlow<DynamicAnalysisEvent> = _events
    private val _reportDraft = MutableStateFlow("")
    val reportDraft: StateFlow<String> = _reportDraft
    private val _partsDraft = MutableStateFlow<List<RikkaPart>>(emptyList())
    val partsDraft: StateFlow<List<RikkaPart>> = _partsDraft

    /** Blocking entry used by the MCP dynamic_analyze_ai tool (heavy tool). */
    fun analyzeSync(dynamicRun: String, path: String, settings: SettingsStore, zh: Boolean, request: String): Result<String> =
        runBlocking(Dispatchers.IO) { analyze(dynamicRun, path, settings, zh, request) }

    suspend fun analyze(dynamicRun: String, path: String, settings: SettingsStore, zh: Boolean, request: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            requireConfigured(settings)
            emit(DynamicAnalysisEvent.Kind.STATUS, if (zh) "正在初始化动态分析 AI 会话…" else "Initializing dynamic-analysis AI session…")
            val userPrompt = buildUserPrompt(dynamicRun, path, zh, request)
            val engine = RikkaAgentEngine(
                client = OkHttpClient.Builder().connectTimeout(20, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.MINUTES)
                    .writeTimeout(120, TimeUnit.SECONDS)
                    .retryOnConnectionFailure(true).build(),
                provider = settings.aiProvider,
                endpoint = settings.aiEndpoint,
                apiKey = settings.aiApiKey,
                model = settings.aiModel,
                temperature = settings.aiTemperature,
                customHeaders = parseStringMap(settings.aiCustomHeadersJson),
                customBody = buildAdditionalProperties(settings)
            )
            val tools = buildRikkaTools(settings, zh)
            var lastReasoning = ""
            val finalReport = engine.run(
                settings.aiSystemPrompt,
                userPrompt,
                tools,
                settings.aiMaxIterations.coerceIn(20, 256)
            ) { parts ->
                _partsDraft.value = parts
                val report = parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }
                if (report.isNotEmpty()) _reportDraft.value = report
                val reasoning = parts.filterIsInstance<RikkaPart.Reasoning>().joinToString("") { it.text }
                if (reasoning.length > lastReasoning.length) {
                    emit(DynamicAnalysisEvent.Kind.THINKING, reasoning.drop(lastReasoning.length))
                    lastReasoning = reasoning
                }
            }
            if (finalReport.isBlank()) error(if (zh) "模型返回了空的分析结果" else "The model returned an empty analysis result")
            _reportDraft.value = finalReport
            emit(DynamicAnalysisEvent.Kind.DONE, finalReport)
            finalReport
        }.onFailure { Log.e("SOMCP-Dynamic", "AI dynamic analysis failed", it) }
    }

    private fun buildUserPrompt(dynamicRun: String, path: String, zh: Boolean, request: String): String {
        val focus = request.trim().takeIf(String::isNotBlank)
        return if (zh) {
            """请对以下 Android native SO 的动态运行证据做独立逆向分析，输出结构化报告。
目标文件: $path
${focus?.let { "用户本轮问题: $it" }.orEmpty()}

以下是已经手动加载目标 .so（或附加到真机进程）并执行后采集到的动态运行证据（dynamicRun 信封）：
```json
$dynamicRun
```

要求：
1. 依据动态证据解读函数实际行为（参数、返回值、寄存器、内存、hook 命中、backtrace/trace）。
2. 需要补充取证时，必须调用 dynamic_api / unidbg_api / so_open 等 MCP 工具，凭证据用工具结果，不得用文字代替。
3. 明确区分 unidbg 模拟环境证据与 Frida 真机证据，标注各自的置信度和失效模式。
4. 最终报告包含：动态行为概述、关键函数运行时语义、输入/输出契约、反调试/反模拟对抗证据、安全风险、可行性、下一步建议。
5. 只有完成必要取证后才返回最终 Markdown 报告，前后不要加“接下来将……”之类过程性文字。"""
        } else {
            """Perform an independent reverse-engineering analysis of the following dynamic runtime evidence for an Android native SO and produce a structured report.
Target file: $path
${focus?.let { "User request for this turn: $it" }.orEmpty()}

The target .so was manually loaded into an execution context (or attached to a live device process) and run; the collected runtime evidence (the dynamicRun envelope) is:
```json
$dynamicRun
```

Requirements:
1. Interpret actual function behavior from the dynamic evidence: arguments, return values, registers, memory, hook hits, backtrace/trace.
2. If more forensics are needed, MUST call dynamic_api / unidbg_api / so_open MCP tools and rely on their results; never replace a tool call with prose.
3. Clearly distinguish unidbg-emulated evidence from Frida on-device evidence, noting confidence and failure modes for each.
4. Final report sections: Dynamic Behavior, Runtime Semantics of Key Functions, Input/Output Contract, Anti-debug/Anti-emulation Evidence, Security Risk, Feasibility, Next Steps.
5. Only after gathering the necessary evidence, return the final Markdown report; do not add process text such as 'next I will…' before or after it."""
        }
    }

    private fun buildRikkaTools(settings: SettingsStore, zh: Boolean): List<RikkaTool> {
        val engine = EngineProvider.get(appContext)
        val ctx = ToolContext(appContext, settings, engine)
        return DYNAMIC_TOOL_NAMES.mapNotNull { name ->
            val handler = ToolCatalog.byName[name] ?: return@mapNotNull null
            val schema = handler.meta.schemaBuilder.invoke(SchemaBuilder)
            RikkaTool(
                name = name,
                description = if (zh) handler.meta.zh else handler.meta.en,
                schema = schema
            ) { args ->
                emit(DynamicAnalysisEvent.Kind.TOOL, if (zh) "调用工具 $name" else "Calling tool $name", name)
                runCatching { handler.handle(ctx, args) }
                    .onSuccess { AppLog.i("dynamic AI tool completed $name") }
                    .onFailure { AppLog.e("dynamic AI tool failed $name", it) }
                    .getOrThrow()
                    .let { payload ->
                        val text = payload.toString()
                        val limit = settings.toolResultMaxChars
                        if (limit <= 0 || text.length <= limit) text else text.take(limit) + "…"
                    }
            }
        }
    }

    private fun parseStringMap(raw: String): Map<String, String> {
        val obj = runCatching { org.json.JSONObject(raw.ifBlank { "{}" }) }.getOrNull() ?: return emptyMap()
        val map = linkedMapOf<String, String>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val key = keys.next().trim()
            if (key.isNotBlank()) map[key] = obj.optString(key)
        }
        return map
    }

    private fun buildAdditionalProperties(settings: SettingsStore): Map<String, kotlinx.serialization.json.JsonElement> {
        val properties = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        val body = runCatching { JsonUtilBody.parse(settings.aiCustomBodyJson) }.getOrNull() ?: return properties
        val keys = body.keys()
        val json = kotlinx.serialization.json.Json
        while (keys.hasNext()) {
            val key = keys.next().trim()
            if (key.isBlank()) continue
            val value = body.opt(key)
            properties[key] = runCatching {
                json.parseToJsonElement(
                    when (value) {
                        null, org.json.JSONObject.NULL -> "null"
                        is String -> org.json.JSONObject.quote(value)
                        else -> value.toString()
                    }
                )
            }.getOrElse { kotlinx.serialization.json.JsonPrimitive(value?.toString().orEmpty()) }
        }
        return properties
    }

    private fun requireConfigured(settings: SettingsStore) {
        if (settings.aiApiKey.isBlank()) error("AI API key is empty")
        if (settings.aiModel.isBlank()) error("AI model is empty")
        if (settings.aiEndpoint.isBlank()) error("AI endpoint is empty")
    }

    private suspend fun emit(kind: DynamicAnalysisEvent.Kind, text: String, toolName: String = "") {
        // suspend emit() rather than tryEmit() so a temporarily-full consumer
        // suspends instead of silently dropping analysis state events.
        _events.emit(DynamicAnalysisEvent(kind, text, toolName))
    }

    private companion object {
        val DYNAMIC_TOOL_NAMES = listOf(
            "dynamic_api",
            "unidbg_api",
            "so_open",
            "analyze_functions",
            "analysis_report",
            "meta_info"
        )
    }
}

/** Minimal org.json holder to avoid pulling JsonUtil internals into the AI path. */
private object JsonUtilBody {
    fun parse(raw: String): org.json.JSONObject = org.json.JSONObject(raw.ifBlank { "{}" })
}
