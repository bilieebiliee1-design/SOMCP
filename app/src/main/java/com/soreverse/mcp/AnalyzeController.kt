package com.soreverse.mcp

import android.content.Context
import com.soreverse.mcp.core.DeepAnalysisEvent
import com.soreverse.mcp.core.DeepAnalysisService
import com.soreverse.mcp.core.DeepReportStore
import com.soreverse.mcp.core.RikkaPart
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.service.McpForegroundService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal fun launchSoScan(
    context: Context,
    settings: SettingsStore,
    state: AnalyzeUiState,
    scope: CoroutineScope,
    zh: Boolean,
): Job? {
    if (state.scanning) return null
    state.scanning = true
    state.message = if (zh) "正在扫描 SO 文件…" else "Scanning SO files…"
    return scope.launch {
        try {
            val loaded = withContext(Dispatchers.IO) { loadSoSources(context.applicationContext, settings.defaultLimit, zh) }
            state.soSources = loaded.first
            state.message = loaded.second
            state.perSoDetail = state.perSoDetail.filterKeys { path -> loaded.first.any { it.path == path } }
            state.expandedSoPath = state.expandedSoPath?.takeIf { path -> loaded.first.any { it.path == path } }
            state.scannedTreeUri = settings.treeUri?.toString() ?: "default"
        } finally {
            state.scanning = false
        }
    }
}

internal fun launchBasicAnalysis(
    context: Context,
    path: String,
    name: String,
    state: AnalyzeUiState,
    scope: CoroutineScope,
    zh: Boolean,
): Job? {
    if (state.analyzingSoPath != null || state.deepAnalyzingPath != null) return null
    state.analyzingSoPath = path
    state.message = if (zh) "正在分析 $name…" else "Analyzing $name…"
    return scope.launch {
        try {
            val detail = withContext(Dispatchers.IO) { openSoForUi(context.applicationContext, path, zh) }
            state.message = detail.second
            val opened = detail.first
            if (opened != null) {
                state.perSoDetail = state.perSoDetail + (path to opened)
                state.expandedSoPath = path
            } else {
                state.expandedSoPath = null
            }
        } finally {
            state.analyzingSoPath = null
        }
    }
}

internal fun launchDeepAnalysis(
    context: Context,
    path: String,
    request: String,
    settings: SettingsStore,
    state: AnalyzeUiState,
    scope: CoroutineScope,
    deepService: DeepAnalysisService,
    zh: Boolean,
): Job? {
    if (state.deepAnalyzingPath != null) return null
    val turnRequest = buildDeepTurnRequest(
        request = request,
        messages = state.deepMessages,
        historySoftLimit = settings.aiHistorySoftLimit,
    )
    if (request.isBlank()) state.deepMessages = emptyList()
    state.deepTargetPath = path
    state.restoreDeepReportOnAnalyzeEntry = false
    state.showDeepPanel = false
    state.showDeepReport = true
    if (!McpForegroundService.isRunning()) {
        state.deepMessages = state.deepMessages + DeepChatMessage(
            id = System.currentTimeMillis(),
            role = DeepChatRole.ASSISTANT,
            text = "",
            error = if (zh) "请先开启 MCP 服务后再进行 AI 深度分析" else "Start the MCP service before AI deep analysis",
        )
        return null
    }
    if (settings.aiApiKey.isBlank() || settings.aiEndpoint.isBlank() || settings.aiModel.isBlank()) {
        state.deepMessages = state.deepMessages + DeepChatMessage(
            id = System.currentTimeMillis(),
            role = DeepChatRole.ASSISTANT,
            text = "",
            error = if (zh) "请先在设置页配置 AI 端点、API Key 和模型" else "Configure AI endpoint, API key and model in Settings first",
        )
        return null
    }
    val userText = request.ifBlank {
        if (zh) "请对 ${path.substringAfterLast('/')} 进行 AI 深度分析" else "Deeply analyze ${path.substringAfterLast('/')}"
    }
    val assistantId = System.currentTimeMillis() + 1
    state.deepMessages = state.deepMessages +
        DeepChatMessage(System.currentTimeMillis(), DeepChatRole.USER, userText) +
        DeepChatMessage(assistantId, DeepChatRole.ASSISTANT, "", streaming = true)
    state.deepAnalyzingPath = path
    state.deepEvents = emptyList()
    state.deepReport = ""
    state.deepEvidencePreview = ""
    state.deepError = ""
    deepService.resetReportDraft(resetWorkspace = request.isBlank())
    return scope.launch {
        val collector = launch {
            deepService.events.collect { event ->
                if (event.kind != DeepAnalysisEvent.Kind.DONE && event.kind != DeepAnalysisEvent.Kind.TEXT) {
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(events = (message.events + event).takeLast(100)) else message
                    }
                }
            }
        }
        val draftCollector = launch {
            deepService.partsDraft.collect { parts ->
                if (parts.isNotEmpty()) {
                    val draft = parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }
                    state.deepReport = draft
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(text = draft, parts = parts) else message
                    }
                }
            }
        }
        try {
            deepService.analyze(path, settings, zh, turnRequest)
                .onSuccess { report ->
                    state.deepReport = report
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(text = report, streaming = false) else message
                    }
                    deepService.workspaceId.value.takeIf(String::isNotBlank)?.let { workspaceId ->
                        DeepReportStore.save(
                            context.applicationContext,
                            workspaceId,
                            deepReportSnapshot(path, settings.aiModel, state.deepMessages),
                        )
                    }
                }
                .onFailure { error ->
                    val messageText = error.message ?: if (zh) "AI 深度分析失败" else "AI deep analysis failed"
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(streaming = false, error = messageText) else message
                    }
                }
        } catch (_: CancellationException) {
            state.deepMessages = state.deepMessages.map { message ->
                if (message.id == assistantId) message.copy(streaming = false) else message
            }
        } finally {
            collector.cancel()
            draftCollector.cancel()
            state.deepAnalyzingPath = null
            state.deepJob = null
        }
    }.also { state.deepJob = it }
}

internal fun buildDeepTurnRequest(
    request: String,
    messages: List<DeepChatMessage>,
    historySoftLimit: Int,
): String {
    if (request.isBlank()) return request
    val history = messages
        .takeLast(6)
        .joinToString("\n\n") { message ->
            val role = if (message.role == DeepChatRole.USER) "用户" else "AI"
            "$role: ${message.text}"
        }
        .takeLast(historySoftLimit.coerceAtLeast(4_000))
    return if (history.isBlank()) request else """以下是最近对话上下文：
$history

用户本轮问题：$request"""
}
