package com.soreverse.mcp

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.service.McpForegroundService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

@Composable
internal fun ServiceTab(
    t: UiText,
    settings: SettingsStore,
    onOpenApkBridge: () -> Unit,
    onOpenKeepAlive: () -> Unit,
    onOpenTunnel: () -> Unit,
) {
    val context = LocalContext.current
    var treeUri by remember { mutableStateOf(settings.treeUri) }
    var port by remember { mutableStateOf(settings.port.toString()) }
    var running by remember { mutableStateOf(McpForegroundService.isRunning()) }
    var portStatus by remember { mutableStateOf(portStatusText(settings.port, running, t.zh)) }
    var endpoints by remember { mutableStateOf(filteredEndpoints(context, settings, settings.port)) }
    var setupPrompt by remember { mutableStateOf<SetupTarget?>(null) }
    var showStartDiagnosis by remember { mutableStateOf(false) }
    var quickPublicUrl by remember { mutableStateOf<String?>(null) }
    var apkConnected by remember { mutableStateOf(false) }
    var apkToolNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var showToolCatalog by remember { mutableStateOf(false) }
    var keepAliveReady by remember { mutableStateOf(isKeepAliveReady(context, settings)) }
    val pickTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }.onFailure { AppLog.w("Unable to persist directory permission: ${it.message}") }
            settings.treeUri = uri
            settings.useDefaultWorkDir = false
            treeUri = uri
            EngineProvider.get(context).setWorkDirectory(uri)
        }
    }

    LaunchedEffect(Unit) {
        treeUri?.let { EngineProvider.get(context).setWorkDirectory(it) }
        apkConnected = withContext(Dispatchers.IO) {
            val bridge = activeBridge(context)
            when {
                settings.apkMcpUrl.isNotBlank() -> bridge.probe().online
                settings.apkMcpAutoProbe -> bridge.autoDiscover(ApkMcpBridge.DEFAULT_PORT).online
                else -> false
            }
        }
        while (true) {
            running = McpForegroundService.isRunning()
            val typedPort = port.toIntOrNull() ?: settings.port
            portStatus = portStatusText(typedPort, running && typedPort == settings.port, t.zh)
            val currentEndpoints = filteredEndpoints(context, settings, typedPort)
            if (currentEndpoints != endpoints) endpoints = currentEndpoints
            val ts = activeServer(context)?.tunnel?.status()
            val url = ts?.publicUrl?.takeIf { it.isNotBlank() && ts.state == CloudflareTunnelManager.State.RUNNING }
            if (url != quickPublicUrl) quickPublicUrl = url
            val liveBridge = activeServer(context)?.apkBridge
            val bridgeState = liveBridge?.state()
            apkToolNames = bridgeState?.tools?.map { it.name }.orEmpty()
            if (bridgeState?.online == true) {
                apkConnected = true
            } else if (settings.apkMcpAutoProbe) {
                apkConnected = withContext(Dispatchers.IO) {
                    val bridge = activeBridge(context)
                    val result = if (settings.apkMcpUrl.isNotBlank()) bridge.probe() else bridge.autoDiscover(ApkMcpBridge.DEFAULT_PORT)
                    result.online
                }
            } else if (liveBridge != null || settings.apkMcpUrl.isBlank()) {
                apkConnected = false
            }
            keepAliveReady = isKeepAliveReady(context, settings)
            delay(if (settings.apkMcpAutoProbe) 10_000 else 1_000)
        }
    }
    LaunchedEffect(t.zh, running, port) {
        val typedPort = port.toIntOrNull() ?: settings.port
        portStatus = portStatusText(typedPort, running && typedPort == settings.port, t.zh)
    }

    fun applyPort() {
        val nextPort = port.toIntOrNull()?.coerceIn(1024, 65535) ?: 8000
        port = nextPort.toString()
        val conflict = !isPortAvailable(nextPort, running && nextPort == settings.port)
        portStatus = portStatusText(nextPort, running, t.zh, conflict)
        if (conflict) return
        settings.port = nextPort
        endpoints = filteredEndpoints(context, settings, nextPort)
        if (running) {
            McpForegroundService.start(context)
        }
    }
    fun startServerUnchecked() {
        val nextPort = port.toIntOrNull()?.coerceIn(1024, 65535) ?: 8000
        port = nextPort.toString()
        if (!isPortAvailable(nextPort, false)) {
            portStatus = portStatusText(nextPort, false, t.zh, conflict = true)
            Toast.makeText(context, if (t.zh) "端口被占用" else "Port is in use", Toast.LENGTH_SHORT).show()
            return
        }
        settings.port = nextPort
        settings.useDefaultWorkDir = treeUri == null
        runCatching { McpForegroundService.start(context) }
            .onSuccess {
                portStatus = if (t.zh) "正在启动服务…" else "Starting service…"
                endpoints = filteredEndpoints(context, settings, settings.port)
            }
            .onFailure { error ->
                AppLog.e("Unable to start MCP service: ${error.message}")
                portStatus = if (t.zh) "服务启动失败" else "Service failed to start"
                Toast.makeText(
                    context,
                    error.message ?: if (t.zh) "服务启动失败" else "Service failed to start",
                    Toast.LENGTH_LONG,
                ).show()
            }
    }

    val toggleServer = {
        if (running) {
            McpForegroundService.stop(context)
            running = false
        } else if (treeUri == null || !apkConnected || !keepAliveReady) {
            showStartDiagnosis = true
        } else {
            startServerUnchecked()
        }
    }

    val loopbackUrl = endpoints.firstOrNull { it.url.contains("127.0.0.1") }?.url ?: "http://127.0.0.1:${settings.port}/mcp"
    val lanUrl = endpoints.firstOrNull { !it.url.contains("127.0.0.1") && !it.url.contains("[::1]") }?.url.orEmpty()
    fun secured(url: String): String = if (settings.authEnabled && settings.accessToken.isNotBlank()) "$url?token=${settings.accessToken}" else url
    val workDirReady = treeUri != null
    val publicUrl = quickPublicUrl?.let { secured("$it/mcp") }.orEmpty()
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = if (t.zh) "控制台" else "Console",
            subtitle = if (t.zh) "本地 MCP 服务" else "Local MCP service",
            trailing = {
                TextButton(onClick = { showToolCatalog = true }) {
                    Text(if (t.zh) "工具列表" else "Tools", color = MaterialTheme.colorScheme.primary)
                }
            },
        )
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val compact = maxHeight < 700.dp
            val pad = LocalUiMetrics.current.pagePad
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(horizontal = pad)
                    .padding(bottom = 6.dp),
                verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 14.dp),
            ) {
                PowerSurface(
                    t = t,
                    running = running,
                    port = settings.port,
                    compact = compact,
                    onPower = toggleServer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(if (compact) 0.42f else 0.46f),
                )

                ReadinessStrip(
                    items = listOf(
                        ReadinessItem(
                            label = if (t.zh) "目录" else "Directory",
                            value = if (workDirReady) (if (t.zh) "已设置" else "Set") else (if (t.zh) "未设置" else "Not set"),
                            ok = workDirReady,
                            onClick = { setupPrompt = SetupTarget.Directory },
                        ),
                        ReadinessItem(
                            label = "APK MCP",
                            value = if (apkConnected) (if (t.zh) "已连接" else "Online") else (if (t.zh) "未连接" else "Offline"),
                            ok = apkConnected,
                            onClick = { setupPrompt = SetupTarget.ApkMcp },
                        ),
                        ReadinessItem(
                            label = if (t.zh) "保活" else "Keep-alive",
                            value = if (keepAliveReady) (if (t.zh) "已就绪" else "Ready") else (if (t.zh) "未就绪" else "Not ready"),
                            ok = keepAliveReady,
                            onClick = { setupPrompt = SetupTarget.KeepAlive },
                        ),
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )

                EndpointBoard(
                    t = t,
                    loopback = secured(loopbackUrl),
                    lan = lanUrl,
                    publicUrl = publicUrl,
                    onCopyLoopback = { copy(context, secured(loopbackUrl), t.copied) },
                    onCopyLan = { copy(context, secured(lanUrl), t.copied) },
                    onCopyPublic = { copy(context, publicUrl, t.copied) },
                    onOpenTunnel = onOpenTunnel,
                    compact = compact,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(if (compact) 0.58f else 0.54f),
                )
            }
        }
    }

    if (showToolCatalog) {
        AlertDialog(
            onDismissRequest = { showToolCatalog = false },
            title = { Text(if (t.zh) "MCP 工具列表" else "MCP Tool Catalog") },
            text = {
                Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                    ToolSummary(t, apkToolNames)
                }
            },
            confirmButton = { TextButton(onClick = { showToolCatalog = false }) { Text(if (t.zh) "完成" else "Done") } },
        )
    }

    setupPrompt?.let { target ->
        AlertDialog(
            onDismissRequest = { setupPrompt = null },
            title = { Text(setupPromptTitle(target, t.zh)) },
            text = {
                Text(setupPromptBody(target, t.zh, workDirReady, apkConnected, keepAliveReady))
            },
            confirmButton = {
                Button(onClick = {
                    setupPrompt = null
                    when (target) {
                        SetupTarget.Directory -> pickTree.launch(null)
                        SetupTarget.ApkMcp -> onOpenApkBridge()
                        SetupTarget.KeepAlive -> onOpenKeepAlive()
                    }
                }) { Text(if (t.zh) "继续设置" else "Continue setup") }
            },
            dismissButton = {
                TextButton(onClick = { setupPrompt = null }) { Text(if (t.zh) "暂不设置" else "Not now") }
            },
        )
    }
    if (showStartDiagnosis) {
        AlertDialog(
            onDismissRequest = { showStartDiagnosis = false },
            title = { Text(if (t.zh) "启动前诊断" else "Pre-start diagnosis") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DiagnosisLine(if (t.zh) "目录" else "Directory", workDirReady, if (t.zh) "未设置时无法扫描和打开 SO" else "SO scan/open will be unavailable")
                    DiagnosisLine("APK MCP", apkConnected, if (t.zh) "未连接时无法使用 APK 协同工具" else "APK bridge tools will be unavailable")
                    DiagnosisLine(if (t.zh) "保活" else "Keep-alive", keepAliveReady, if (t.zh) "后台运行可能被系统中断" else "The system may stop background work")
                    Text(if (t.zh) "仍要启动吗？" else "Start anyway?", fontWeight = FontWeight.SemiBold)
                }
            },
            confirmButton = {
                Button(onClick = { showStartDiagnosis = false; startServerUnchecked() }) { Text(if (t.zh) "仍然启动" else "Start anyway") }
            },
            dismissButton = {
                TextButton(onClick = { showStartDiagnosis = false }) { Text(if (t.zh) "返回设置" else "Review settings") }
            },
        )
    }
}

private data class ReadinessItem(
    val label: String,
    val value: String,
    val ok: Boolean,
    val onClick: () -> Unit,
)

@Composable
private fun PowerSurface(
    t: UiText,
    running: Boolean,
    port: Int,
    compact: Boolean,
    onPower: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val statusColor = if (running) statusSuccess() else MaterialTheme.colorScheme.primary
    val shape = RoundedCornerShape(if (compact) 28.dp else 32.dp)
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) 0.985f else 1f,
        animationSpec = tween(durationMillis = 120),
        label = "power-press",
    )
    val reduceMotion = LocalReduceMotion.current
    Box(
        modifier
            .graphicsLayer {
                scaleX = if (reduceMotion) 1f else scale
                scaleY = if (reduceMotion) 1f else scale
            }
            .clip(shape)
            .background(
                Brush.verticalGradient(
                    listOf(
                        statusColor.copy(alpha = if (running) 0.20f else 0.16f),
                        statusColor.copy(alpha = if (running) 0.08f else 0.05f),
                        MaterialTheme.colorScheme.surface.copy(alpha = 0.92f),
                    ),
                ),
            )
            .border(BorderStroke(1.dp, statusColor.copy(alpha = if (running) 0.34f else 0.22f)), shape)
            .clickable(interactionSource = interaction, indication = null, onClick = onPower)
            .padding(horizontal = if (compact) 18.dp else 22.dp, vertical = if (compact) 16.dp else 20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 14.dp),
        ) {
            Box(
                Modifier
                    .size(if (compact) 64.dp else 76.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.16f))
                    .border(BorderStroke(1.5.dp, statusColor.copy(alpha = 0.42f)), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    if (running) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = t.power,
                    tint = statusColor,
                    modifier = Modifier.size(if (compact) 30.dp else 34.dp),
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    if (running) (if (t.zh) "运行中" else "Running") else (if (t.zh) "已停止" else "Stopped"),
                    style = if (compact) MaterialTheme.typography.headlineMedium else MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    letterSpacing = (-0.8).sp,
                )
                Text(
                    if (running) {
                        if (t.zh) "端口 $port · 轻点停止" else "Port $port · tap to stop"
                    } else {
                        if (t.zh) "端口 $port · 轻点启动" else "Port $port · tap to start"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = statusColor,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

@Composable
private fun ReadinessStrip(
    items: List<ReadinessItem>,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(20.dp)
    Row(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.94f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), shape)
            .height(if (items.any { it.value.length > 8 }) 74.dp else 68.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items.forEachIndexed { index, item ->
            if (index > 0) {
                Box(
                    Modifier
                        .width(1.dp)
                        .fillMaxHeight()
                        .padding(vertical = 14.dp)
                        .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)),
                )
            }
            ReadinessCell(
                item = item,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight(),
            )
        }
    }
}

@Composable
private fun ReadinessCell(
    item: ReadinessItem,
    modifier: Modifier = Modifier,
) {
    val color = if (item.ok) statusSuccess() else MaterialTheme.colorScheme.error
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val alpha by animateFloatAsState(if (pressed) 0.10f else 0f, label = "ready-press")
    Column(
        modifier
            .background(color.copy(alpha = alpha))
            .clickable(interactionSource = interaction, indication = null, onClick = item.onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            item.label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(color))
            Text(
                item.value,
                style = MaterialTheme.typography.labelLarge,
                color = color,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun EndpointBoard(
    t: UiText,
    loopback: String,
    lan: String,
    publicUrl: String,
    onCopyLoopback: () -> Unit,
    onCopyLan: () -> Unit,
    onCopyPublic: () -> Unit,
    onOpenTunnel: () -> Unit,
    compact: Boolean,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(if (compact) 22.dp else 26.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.94f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), shape)
            .padding(if (compact) 12.dp else 14.dp),
    ) {
        Text(
            if (t.zh) "连接" else "Connect",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
        )
        Spacer(Modifier.height(if (compact) 6.dp else 8.dp))
        EndpointCell(
            label = if (t.zh) "本机回环" else "Loopback",
            value = loopback,
            enabled = true,
            onCopy = onCopyLoopback,
            modifier = Modifier.weight(1f),
        )
        EndpointDivider()
        EndpointCell(
            label = if (t.zh) "局域网" else "LAN",
            value = lan.ifBlank { if (t.zh) "暂无可用局域网地址" else "No LAN address" },
            enabled = lan.isNotBlank(),
            onCopy = onCopyLan,
            modifier = Modifier.weight(1f),
        )
        EndpointDivider()
        EndpointCell(
            label = if (t.zh) "公网隧道" else "Public",
            value = publicUrl.ifBlank { if (t.zh) "未开启 · 轻点去设置" else "Off · tap to set up" },
            enabled = publicUrl.isNotBlank(),
            onCopy = onCopyPublic,
            onUnavailableClick = onOpenTunnel,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun EndpointDivider() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp)
            .height(1.dp)
            .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.12f)),
    )
}

@Composable
private fun EndpointCell(
    label: String,
    value: String,
    enabled: Boolean,
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
    onUnavailableClick: (() -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    Row(
        modifier
            .fillMaxWidth()
            .then(
                if (!enabled && onUnavailableClick != null) {
                    Modifier.clickable(interactionSource = interaction, indication = null, onClick = onUnavailableClick)
                } else {
                    Modifier
                },
            )
            .padding(horizontal = 4.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(
            Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(
                label,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = FontWeight.Medium,
            )
            Text(
                value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val chipShape = RoundedCornerShape(12.dp)
        Box(
            Modifier
                .clip(chipShape)
                .background(
                    if (enabled) MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                )
                .then(
                    if (enabled) Modifier.clickable(onClick = onCopy)
                    else if (onUnavailableClick != null) Modifier.clickable(onClick = onUnavailableClick)
                    else Modifier,
                )
                .padding(horizontal = 10.dp, vertical = 8.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (enabled) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp),
                )
            } else {
                Text(
                    if (onUnavailableClick != null) "→" else "—",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun AddressRow(label: String, value: String, copyEnabled: Boolean, onCopy: () -> Unit, onUnavailableClick: (() -> Unit)? = null) {
    EndpointCell(
        label = label,
        value = value,
        enabled = copyEnabled,
        onCopy = onCopy,
        onUnavailableClick = onUnavailableClick,
    )
}

@Composable
private fun DiagnosisLine(label: String, ok: Boolean, detail: String) {
    val color = if (ok) statusSuccess() else MaterialTheme.colorScheme.error
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.padding(top = 6.dp).size(8.dp).clip(CircleShape).background(color))
        Column {
            Text("$label · ${if (ok) "OK" else "!"}", fontWeight = FontWeight.SemiBold, color = color)
            if (!ok) Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun setupPromptTitle(target: SetupTarget, zh: Boolean): String = when (target) {
    SetupTarget.Directory -> if (zh) "工作目录状态" else "Work directory status"
    SetupTarget.ApkMcp -> if (zh) "APK MCP 状态" else "APK MCP status"
    SetupTarget.KeepAlive -> if (zh) "保活状态" else "Keep-alive status"
}

private fun setupPromptBody(target: SetupTarget, zh: Boolean, dirReady: Boolean, apkReady: Boolean, keepAliveReady: Boolean): String = when (target) {
    SetupTarget.Directory -> if (zh) {
        if (dirReady) "目录已设置。是否重新选择用于扫描、打开和导出 SO 的目录？" else "目录尚未设置，SO 浏览器和读盘工具将不可用。是否继续设置？"
    } else if (dirReady) "A directory is set. Choose a different SO workspace?" else "No directory is set. SO browser and disk tools will be unavailable. Continue setup?"
    SetupTarget.ApkMcp -> if (zh) {
        if (apkReady) "APK MCP 已连接。是否查看桥接地址、工具合并和探测设置？" else "APK MCP 尚未连接，MT 管理器协同工具不可用。是否继续设置？"
    } else if (apkReady) "APK MCP is connected. Review bridge settings?" else "APK MCP is not connected. MT Manager bridge tools are unavailable. Continue setup?"
    SetupTarget.KeepAlive -> if (zh) {
        if (keepAliveReady) "保活已就绪。是否查看唤醒锁、电池优化和开机自启设置？" else "保活尚未就绪，服务在后台可能被系统中断。是否继续设置？"
    } else if (keepAliveReady) "Keep-alive is ready. Review its settings?" else "Keep-alive is not ready. Background service may be stopped. Continue setup?"
}

@Composable
private fun QuickLinkCard(title: String, subtitle: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(18.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
