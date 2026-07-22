package com.soreverse.mcp

import android.content.Context
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.DeepReportStore
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.RikkaPart
import org.json.JSONArray
import org.json.JSONObject

internal fun loadWorkspaces(context: Context): List<WorkspaceUi> {
    val payload = EngineProvider.get(context).listWorkspaces()
    val items = payload.optJSONArray("items") ?: return emptyList()
    val localReports = DeepReportStore.ids(context)
    return (0 until items.length()).mapNotNull { index ->
        val item = items.optJSONObject(index) ?: return@mapNotNull null
        val workspaceId = item.optString("workspaceId")
        WorkspaceUi(
            id = workspaceId,
            name = item.optString("soFileName", "lib.so"),
            path = item.optString("path"),
            abi = item.optString("abi", ""),
            architecture = item.optString("architecture", "unknown"),
            bits = item.optInt("bits", 0),
            temporary = item.optBoolean("temporary", true),
            hasLocalAiReport = workspaceId in localReports,
        )
    }
}

internal fun deepReportSnapshot(path: String, model: String, messages: List<DeepChatMessage>): JSONObject =
    JSONObject()
        .put("path", path)
        .put("model", model)
        .put(
            "messages",
            JSONArray().apply {
                messages.forEach { message ->
                    put(
                        JSONObject()
                            .put("id", message.id)
                            .put("role", message.role.name)
                            .put("text", message.text)
                            .put("error", message.error)
                            .put(
                                "parts",
                                JSONArray().apply {
                                    message.parts.forEach { part ->
                                        put(
                                            when (part) {
                                                is RikkaPart.Text -> JSONObject().put("type", "text").put("text", part.text)
                                                is RikkaPart.Reasoning -> JSONObject().put("type", "reasoning").put("text", part.text)
                                                is RikkaPart.Tool -> JSONObject()
                                                    .put("type", "tool")
                                                    .put("id", part.id)
                                                    .put("name", part.name)
                                                    .put("arguments", part.arguments)
                                                    .put("result", part.result)
                                                    .put("index", part.index)
                                            },
                                        )
                                    }
                                },
                            ),
                    )
                }
            },
        )

internal fun restoreDeepReport(state: AnalyzeUiState, snapshot: JSONObject) {
    val messages = snapshot.optJSONArray("messages") ?: JSONArray()
    state.deepTargetPath = snapshot.optString("path")
    state.deepMessages = (0 until messages.length()).mapNotNull { index ->
        val message = messages.optJSONObject(index) ?: return@mapNotNull null
        val parts = message.optJSONArray("parts") ?: JSONArray()
        DeepChatMessage(
            id = message.optLong("id", System.currentTimeMillis() + index),
            role = runCatching { DeepChatRole.valueOf(message.optString("role")) }.getOrDefault(DeepChatRole.ASSISTANT),
            text = message.optString("text"),
            parts = (0 until parts.length()).mapNotNull { partIndex ->
                val part = parts.optJSONObject(partIndex) ?: return@mapNotNull null
                when (part.optString("type")) {
                    "text" -> RikkaPart.Text(part.optString("text"))
                    "reasoning" -> RikkaPart.Reasoning(part.optString("text"))
                    "tool" -> RikkaPart.Tool(
                        id = part.optString("id"),
                        name = part.optString("name"),
                        arguments = part.optString("arguments"),
                        result = part.optString("result").takeUnless { part.isNull("result") },
                        index = part.optInt("index"),
                    )
                    else -> null
                }
            },
            error = message.optString("error"),
        )
    }
    state.deepReport = state.deepMessages.lastOrNull { it.role == DeepChatRole.ASSISTANT }?.text.orEmpty()
    state.deepAnalyzingPath = null
    state.deepJob = null
    state.restoreDeepReportOnAnalyzeEntry = false
    state.showDeepReport = true
}

internal fun loadSoSources(context: Context, limit: Int, zh: Boolean = false): Pair<List<SoSourceUi>, String> {
    val payload = runCatching { EngineProvider.get(context).listAvailableSos(limit = limit.coerceIn(20, 500)) }.getOrElse {
        AppLog.e("SO browser scan failed: ${it.message}")
        return emptyList<SoSourceUi>() to if (zh) "扫描失败：${it.message ?: it.javaClass.simpleName}" else "Scan failed: ${it.message ?: it.javaClass.simpleName}"
    }
    if (!payload.optBoolean("ok", true)) {
        return emptyList<SoSourceUi>() to payload.optJSONObject("error")?.optString("message", if (zh) "扫描失败" else "Scan failed").orEmpty()
    }
    val items = payload.optJSONArray("items") ?: return emptyList<SoSourceUi>() to "0"
    val sources = (0 until items.length()).mapNotNull { index ->
        val item = items.optJSONObject(index) ?: return@mapNotNull null
        SoSourceUi(
            name = item.optString("name", item.optString("path").substringAfterLast('/')),
            path = item.optString("path"),
            source = item.optString("source", "filesystem"),
            abi = item.optString("abi", ""),
            architecture = item.optString("architecture", "unknown"),
            bits = item.optInt("bits", 0),
            size = item.optLong("size", 0L),
            stripped = item.optBoolean("stripped", false),
        )
    }
    val page = payload.optJSONObject("pagination")
    val more = if (page?.optBoolean("hasMore") == true) " + more" else ""
    return sources to "${sources.size}$more"
}

internal fun openSoForUi(context: Context, path: String, zh: Boolean = false): Pair<SoDetailUi?, String> {
    val engine = EngineProvider.get(context)
    val opened = engine.open(path, temporary = true)
    if (!opened.optBoolean("ok", true)) {
        return null to opened.optJSONObject("error")?.optString("message", "Open failed").orEmpty()
    }
    val workspaceId = opened.optString("workspaceId")
    return try {
        val analyzed = engine.analyze(workspaceId, "")
        if (!analyzed.optBoolean("ok", true)) {
            null to analyzed.optJSONObject("error")?.optString("message", "Analyze failed").orEmpty()
        } else {
            val counts = opened.optJSONObject("counts") ?: JSONObject()
            val overview = analyzed.optJSONObject("overview")
                ?: analyzed.takeIf { it.has("securityFeatures") || it.has("entropy") || it.has("difficulty") }
                ?: engine.overview(workspaceId)
            val detail = SoDetailUi(
                workspaceId = "",
                name = opened.optString("soFileName", overview.optString("fileName", "lib.so")),
                path = opened.optString("inputPath", path),
                architecture = opened.optString("architecture", overview.optString("architectureCode", "unknown")),
                bits = opened.optInt("bits", overview.optInt("bits", 0)),
                entryPoint = opened.optString("entryPoint", overview.optString("entryPoint", "0x0")),
                stripped = analyzed.optBoolean("stripped", overview.optBoolean("stripped", counts.optInt("symbols", 0) == 0)),
                hasDebugInfo = analyzed.optBoolean("hasDebugInfo", overview.optBoolean("hasDebugInfo", false)),
                hasJniOnLoad = analyzed.optBoolean("hasJniOnLoad", overview.optBoolean("hasJniOnLoad", false)),
                sectionCount = counts.optInt("sections", overview.optInt("sectionCount", 0)),
                symbolCount = counts.optInt("symbols", overview.optInt("symbolCount", 0)),
                dynsymCount = counts.optInt("dynsyms", overview.optInt("dynsymCount", 0)),
                stringCount = counts.optInt("strings", overview.optInt("stringCount", 0)),
                overview = overview,
            )
            detail to if (zh) "已完成 ${detail.name} 的程序基础分析" else "Basic analysis completed for ${detail.name}"
        }
    } finally {
        engine.close(workspaceId)
    }
}
