package com.soreverse.mcp

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.DeepAnalysisService
import com.soreverse.mcp.core.DeepReportStore
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.withContext

@Composable
internal fun AnalyzeTab(
    t: UiText,
    settings: SettingsStore,
    state: AnalyzeUiState,
    scope: CoroutineScope,
    deepService: DeepAnalysisService,
    backProgress: Float,
    onLeaveDeepReport: () -> Unit,
) {
    val context = LocalContext.current
    val deepChatListState = rememberLazyListState()
    var followDeepOutput by remember { mutableStateOf(true) }
    val deepAtBottom by remember {
        derivedStateOf {
            val info = deepChatListState.layoutInfo
            val lastVisible = info.visibleItemsInfo.lastOrNull() ?: return@derivedStateOf true
            lastVisible.index >= info.totalItemsCount - 1 &&
                lastVisible.offset + lastVisible.size <= info.viewportEndOffset + 2
        }
    }
    var showWorkspaces by remember { mutableStateOf(false) }
    val pickTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }
            settings.treeUri = uri
            settings.useDefaultWorkDir = false
            EngineProvider.get(context).setWorkDirectory(uri)
            state.scannedTreeUri = null
        }
    }

    fun startDeepAnalysis(path: String, request: String = "") {
        launchDeepAnalysis(context, path, request, settings, state, scope, deepService, t.zh)
    }

    LaunchedEffect(settings.treeUri?.toString(), settings.defaultLimit) {
        val treeKey = settings.treeUri?.toString()
        if (treeKey == null) {
            state.message = if (t.zh) "尚未选择目录，请先选择工作目录" else "No directory selected. Choose a work directory first."
        } else if (state.scannedTreeUri != treeKey && !state.scanning) {
            EngineProvider.get(context).let { engine -> settings.treeUri?.let(engine::setWorkDirectory) }
            launchSoScan(context, settings, state, scope, t.zh)
        }
    }

    LaunchedEffect(deepChatListState.isScrollInProgress, deepAtBottom) {
        when {
            deepAtBottom -> followDeepOutput = true
            deepChatListState.isScrollInProgress && deepChatListState.lastScrolledBackward -> followDeepOutput = false
        }
    }

    LaunchedEffect(state.showDeepReport) {
        if (state.showDeepReport) followDeepOutput = true
    }

    val latestDeepMessage = state.deepMessages.lastOrNull()
    LaunchedEffect(
        state.deepMessages.size,
        latestDeepMessage?.text?.length,
        latestDeepMessage?.parts,
        latestDeepMessage?.events?.size,
        latestDeepMessage?.error,
        followDeepOutput,
    ) {
        if (state.showDeepReport && state.deepMessages.isNotEmpty() && followDeepOutput) {
            deepChatListState.scrollToItem(state.deepMessages.size)
        }
    }

    LaunchedEffect(deepChatListState, state.showDeepReport, followDeepOutput) {
        snapshotFlow {
            deepChatListState.layoutInfo.visibleItemsInfo.lastOrNull()?.let {
                Triple(it.index, it.offset, it.size)
            }
        }.distinctUntilChanged().collect {
            if (state.showDeepReport && followDeepOutput && !deepAtBottom && state.deepMessages.isNotEmpty()) {
                deepChatListState.scrollToItem(state.deepMessages.size)
            }
        }
    }

    LaunchedEffect(showWorkspaces) {
        if (showWorkspaces) state.workspaces = withContext(Dispatchers.IO) { loadWorkspaces(context.applicationContext) }
    }

    Box(Modifier.fillMaxSize()) {
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = if (t.zh) "分析" else "Analyze",
            subtitle = if (t.zh) "SO 文件程序基础分析" else "Program-level SO analysis",
            trailing = {
                TextButton(onClick = { showWorkspaces = true }) {
                    Icon(Icons.Default.Storage, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (t.zh) "工作区" else "Workspaces")
                }
            },
        )
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 12.dp),
        ) {
            Row(Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (state.scanning) (if (t.zh) "扫描中…" else "Scanning…") else if (state.soSources.isNotEmpty()) (if (t.zh) "共计 ${state.soSources.size} 个 SO 文件" else "${state.soSources.size} SO files") else (if (t.zh) "选择目录后自动扫描" else "Choose a directory to scan"),
                    Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (settings.treeUri == null) {
                    TextButton(onClick = { pickTree.launch(null) }) { Text(if (t.zh) "选择目录" else "Choose") }
                }
            }
            if (state.scanning) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = LocalUiMetrics.current.pagePad))
                Spacer(Modifier.height(8.dp))
            }
            if (state.analyzingSoPath != null) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = 14.dp))
                Text(
                    state.message.ifBlank { if (t.zh) "正在进行程序基础分析…" else "Running program analysis…" },
                    modifier = Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 6.dp),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            if (state.soSources.isEmpty()) {
                Text(
                    state.message.ifBlank { if (t.zh) "选择目录后会自动扫描 SO 文件。" else "SO files will be scanned automatically after choosing a directory." },
                    modifier = Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                state.soSources.take(30).forEachIndexed { idx, src ->
                    if (idx > 0) GroupDivider()
                    Column {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            IndexedBadge(idx)
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(src.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("${if (t.zh) (if (src.source == "filesystem") "文件系统" else src.source) else src.source} ${src.abi} ${src.architecture}/${src.bits} ${formatBytes(src.size)}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                Text(src.path, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                TextButton(
                                    enabled = state.analyzingSoPath == null && state.deepAnalyzingPath == null,
                                    onClick = {
                                        if (state.perSoDetail[src.path] != null) {
                                            state.expandedSoPath = src.path
                                        } else {
                                            launchBasicAnalysis(context, src.path, src.name, state, scope, t.zh)
                                        }
                                    },
                                ) {
                                    Text(
                                        when {
                                            state.analyzingSoPath == src.path -> if (t.zh) "分析中" else "Analyzing"
                                            else -> if (t.zh) "程序基础分析" else "Basic analysis"
                                        },
                                    )
                                }
                                TextButton(
                                    enabled = state.analyzingSoPath == null && state.deepAnalyzingPath == null,
                                    onClick = { startDeepAnalysis(src.path) },
                                ) {
                                    Text(
                                        if (state.deepAnalyzingPath == src.path) {
                                            if (t.zh) "AI 分析中" else "AI analyzing"
                                        } else {
                                            if (t.zh) "AI 深度分析" else "AI deep analysis"
                                        },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    state.expandedSoPath?.let(state.perSoDetail::get)?.let { selectedDetail ->
        Surface(
            modifier = Modifier.fillMaxSize().graphicsLayer {
                translationX = size.width * backProgress
                alpha = 1f - 0.12f * backProgress
            },
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(Modifier.fillMaxSize()) {
                ScreenHeader(
                    title = selectedDetail.name,
                    subtitle = if (t.zh) "ELF 程序基础分析" else "ELF basic analysis",
                    showBack = true,
                    onBack = { state.expandedSoPath = null },
                )
                Column(
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = LocalUiMetrics.current.pagePad)
                        .padding(bottom = 12.dp),
                ) {
                    ElfOverviewPanel(detail = selectedDetail, zh = t.zh, onCopy = { text -> copy(context, text, t.copied) })
                }
            }
        }
    }
    if (state.showDeepReport) {
        Surface(
            modifier = Modifier.fillMaxSize().graphicsLayer {
                translationX = size.width * backProgress
                alpha = 1f - 0.12f * backProgress
            },
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(Modifier.fillMaxSize()) {
                ScreenHeader(
                    title = state.deepTargetPath.substringAfterLast('/').ifBlank { if (t.zh) "AI 深度分析" else "AI Deep Analysis" },
                    subtitle = if (state.deepAnalyzingPath != null) (if (t.zh) "正在生成" else "Generating") else settings.aiModel,
                    showBack = true,
                    onBack = onLeaveDeepReport,
                    trailing = {
                        if (state.deepMessages.isNotEmpty()) {
                            IconButton(onClick = {
                                state.deepMessages.lastOrNull { it.role == DeepChatRole.ASSISTANT }?.text?.let { copy(context, it, t.copied) }
                            }) {
                                Icon(Icons.Default.ContentCopy, if (t.zh) "复制最新回复" else "Copy latest reply")
                            }
                        }
                    },
                )
                LazyColumn(
                    state = deepChatListState,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = LocalUiMetrics.current.pagePad, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(22.dp),
                ) {
                    items(state.deepMessages, key = { it.id }) { message ->
                        DeepChatMessageItem(message = message, zh = t.zh)
                    }
                    item(key = "deep-output-bottom") {
                        Spacer(Modifier.height(1.dp))
                    }
                }
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = 0.96f),
                    tonalElevation = 1.dp,
                    shadowElevation = 3.dp,
                ) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .navigationBarsPadding()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.Bottom,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        OutlinedTextField(
                            value = state.deepInput,
                            onValueChange = { state.deepInput = it },
                            modifier = Modifier.weight(1f).heightIn(min = 50.dp, max = 132.dp),
                            placeholder = { Text(if (t.zh) "继续提问" else "Ask a follow-up", maxLines = 1) },
                            shape = RoundedCornerShape(18.dp),
                            maxLines = 5,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = MaterialTheme.colorScheme.surface,
                                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                                focusedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.55f),
                                unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.65f),
                            ),
                        )
                        FilledIconButton(
                            onClick = {
                                if (state.deepAnalyzingPath != null) {
                                    state.deepJob?.cancel(CancellationException("Stopped by user"))
                                } else {
                                    val input = state.deepInput.trim()
                                    if (input.isNotBlank() && state.deepTargetPath.isNotBlank()) {
                                        state.deepInput = ""
                                        startDeepAnalysis(state.deepTargetPath, input)
                                    }
                                }
                            },
                            enabled = state.deepAnalyzingPath != null || state.deepInput.isNotBlank(),
                            modifier = Modifier.size(50.dp),
                            shape = CircleShape,
                            colors = androidx.compose.material3.IconButtonDefaults.filledIconButtonColors(
                                containerColor = if (state.deepAnalyzingPath != null) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.primary
                                },
                            ),
                        ) {
                            Icon(
                                if (state.deepAnalyzingPath != null) Icons.Default.Stop else Icons.Default.ArrowUpward,
                                if (state.deepAnalyzingPath != null) (if (t.zh) "停止" else "Stop") else (if (t.zh) "发送" else "Send"),
                            )
                        }
                    }
                }
            }
        }
    }
    }
    if (showWorkspaces) {
        AlertDialog(
            onDismissRequest = { showWorkspaces = false },
            title = { Text(if (t.zh) "工作区" else "Workspaces") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (state.workspaces.isEmpty()) {
                        Text(if (t.zh) "暂无通过 MCP 打开的工作区。程序基础分析不会创建工作区。" else "No MCP workspaces. Basic analysis does not create workspaces.")
                    } else {
                        state.workspaces.forEach { ws ->
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(ws.name, fontWeight = FontWeight.SemiBold)
                                    Text("${ws.architecture}/${ws.bits} ${ws.abi}", style = MaterialTheme.typography.labelSmall)
                                }
                                if (ws.hasLocalAiReport) {
                                    TextButton(onClick = {
                                        DeepReportStore.load(context.applicationContext, ws.id)?.let { snapshot ->
                                            restoreDeepReport(state, snapshot)
                                            showWorkspaces = false
                                        }
                                    }) { Text(if (t.zh) "查看" else "View") }
                                }
                                TextButton(onClick = {
                                    EngineProvider.get(context).close(ws.id)
                                    DeepReportStore.remove(context.applicationContext, ws.id)
                                    state.workspaces = loadWorkspaces(context)
                                }) { Text(if (t.zh) "关闭" else "Close") }
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showWorkspaces = false }) { Text(if (t.zh) "完成" else "Done") } },
        )
    }
}
