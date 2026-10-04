// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// AgentKernel: the plumbing every in-process agent run shares — one provider
// configuration source, one HTTP client, and one adapter that exposes MCP
// catalog tools to the model. Handlers are invoked directly through
// [ToolContext] instead of over the MCP HTTP endpoint, so a nested (sub-agent)
// run never re-enters the heavy-tool gate and cannot deadlock against itself.
package com.soreverse.mcp.core

import com.soreverse.mcp.mcp.SchemaBuilder
import com.soreverse.mcp.mcp.ToolCatalog
import com.soreverse.mcp.mcp.ToolContext
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.OkHttpClient
import org.json.JSONObject

/** Per-run callbacks for [AgentKernel.catalogTools]. */
internal class AgentToolHooks(
    val zh: Boolean,
    val workspaceId: () -> String = { "" },
    val onWorkspaceOpened: (String) -> Unit = {},
    val onToolStart: suspend (String) -> Unit = {},
    val onToolDone: suspend (String) -> Unit = {}
)

internal data class AgentToolSet(
    val tools: List<RikkaTool>,
    /** Declared names with no catalog handler: a role typo, never a silent drop. */
    val unresolved: List<String>
)

internal object AgentKernel {
    fun httpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.MINUTES)
        .writeTimeout(120, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    fun engine(settings: SettingsStore): RikkaAgentEngine = RikkaAgentEngine(
        client = httpClient(),
        provider = settings.aiProvider,
        endpoint = settings.aiEndpoint,
        apiKey = settings.aiApiKey,
        model = settings.aiModel,
        temperature = settings.aiTemperature,
        customHeaders = stringMap(settings.aiCustomHeadersJson),
        customBody = additionalBody(settings)
    )

    /** The single prerequisite every agent path shares. */
    fun missingConfig(settings: SettingsStore): List<String> = buildList {
        if (settings.aiEndpoint.isBlank()) add("aiEndpoint")
        if (settings.aiApiKey.isBlank()) add("aiApiKey")
        if (settings.aiModel.isBlank()) add("aiModel")
    }

    fun requireConfigured(settings: SettingsStore) {
        missingConfig(settings).firstOrNull()?.let { error("AI $it is empty") }
    }

    fun isConfigured(settings: SettingsStore): Boolean = missingConfig(settings).isEmpty()

    fun stringMap(raw: String): Map<String, String> {
        val obj = runCatching { JSONObject(raw.ifBlank { "{}" }) }.getOrNull() ?: return emptyMap()
        return buildMap {
            val keys = obj.keys()
            while (keys.hasNext()) {
                val key = keys.next().trim()
                if (key.isNotBlank()) put(key, obj.optString(key))
            }
        }
    }

    fun additionalBody(settings: SettingsStore): Map<String, JsonElement> {
        val properties = LinkedHashMap<String, JsonElement>()
        val body = runCatching { JSONObject(settings.aiCustomBodyJson.ifBlank { "{}" }) }.getOrNull()
            ?: return properties
        val keys = body.keys()
        while (keys.hasNext()) {
            val key = keys.next().trim()
            if (key.isBlank()) continue
            val value = body.opt(key)
            properties[key] = runCatching {
                Json.parseToJsonElement(
                    when (value) {
                        null, JSONObject.NULL -> "null"
                        is String -> JSONObject.quote(value)
                        else -> value.toString()
                    }
                )
            }.getOrElse { JsonPrimitive(value?.toString().orEmpty()) }
        }
        return properties
    }

    fun truncate(text: String, limit: Int): String = if (limit <= 0 || text.length <= limit) text else text.take(limit) + "…"

    /**
     * Wraps catalog handlers as model-callable tools. A handler that throws is
     * reported to the model as a structured error payload instead of aborting the
     * run, which is what the system prompt already promises ("if a tool fails,
     * explain the failure and continue with alternative tools").
     */
    fun catalogTools(ctx: ToolContext, names: List<String>, hooks: AgentToolHooks): AgentToolSet {
        val unresolved = names.filterNot(ToolCatalog.byName::containsKey)
        val tools = names.mapNotNull { name ->
            val handler = ToolCatalog.byName[name] ?: return@mapNotNull null
            RikkaTool(
                name = name,
                description = if (hooks.zh) handler.meta.zh else handler.meta.en,
                schema = handler.meta.schemaBuilder.invoke(SchemaBuilder)
            ) { args ->
                hooks.onToolStart(name)
                val effective = inheritWorkspace(name, args, hooks.workspaceId())
                AppLog.i("AI tool call $name args=${effective.toString().take(600)}")
                val payload = runCatching { handler.handle(ctx, effective) }
                    .onSuccess {
                        if (name == "so_open") {
                            it.optString("workspaceId")
                                .takeIf(String::isNotBlank)
                                ?.let(hooks.onWorkspaceOpened)
                        }
                        AppLog.i("AI tool completed $name result=${it.toString().take(600)}")
                    }
                    .getOrElse { error ->
                        AppLog.e("AI tool failed $name", error)
                        err(
                            "TOOL_EXECUTION_FAILED",
                            error.message ?: error.javaClass.simpleName,
                            "tool",
                            name
                        )
                    }
                hooks.onToolDone(name)
                truncate(payload.toString(), ctx.settings.toolResultMaxChars)
            }
        }
        return AgentToolSet(tools, unresolved)
    }

    /** Children of a workspace-scoped run must not have to re-open the target. */
    private fun inheritWorkspace(name: String, args: JSONObject, current: String): JSONObject {
        if (name == "so_open" || current.isBlank()) return args
        if (args.optString("workspaceId").isNotBlank()) return args
        return JSONObject(args.toString()).apply { put("workspaceId", current) }
    }
}
