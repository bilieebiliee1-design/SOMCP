package com.soreverse.mcp

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun SettingsTunnelPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tunnelMode by remember { mutableStateOf(settings.tunnelMode) }
    var tunnelAutoStart by remember { mutableStateOf(settings.tunnelAutoStart) }
    var tunnelPort by remember { mutableStateOf(settings.tunnelTargetPort.toString()) }
    var namedToken by remember { mutableStateOf(settings.tunnelNamedToken) }
    var tunnelProtocol by remember { mutableStateOf(settings.tunnelProtocol) }
    var edgeIpVersion by remember { mutableStateOf(settings.tunnelEdgeIpVersion) }
    var tunnelLogLevel by remember { mutableStateOf(settings.tunnelLogLevel) }
    var tunnelReconnect by remember { mutableStateOf(settings.tunnelReconnect) }
    var tunnelKeepAlive by remember { mutableStateOf(settings.tunnelKeepAlive) }
    var keepaliveInterval by remember { mutableStateOf(settings.tunnelKeepaliveIntervalSec.toString()) }
    var reconnectBackoff by remember { mutableStateOf(settings.tunnelReconnectBackoffSec.toString()) }
    var historyEnabled by remember { mutableStateOf(settings.tunnelHistoryEnabled) }
    var history by remember { mutableStateOf(settings.tunnelHistoryUrls.split('\n').map { it.trim() }.filter { it.isNotBlank() }) }
    var tunnelStatus by remember { mutableStateOf<CloudflareTunnelManager.TunnelStatus?>(null) }
    var showExport by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        tunnelStatus = tunnelStatusOf(context)
        while (true) {
            delay(3_000)
            tunnelStatus = tunnelStatusOf(context)
        }
    }
    val stateColor = when (tunnelStatus?.state) {
        CloudflareTunnelManager.State.RUNNING -> AppleColors.systemGreen
        CloudflareTunnelManager.State.STARTING -> AppleColors.systemOrange
        CloudflareTunnelManager.State.FAILED -> AppleColors.systemRed
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    PageScroll {
        GlassGroup(title = if (t.zh) "状态" else "Status") {
            Text("${if (t.zh) "隧道状态" else "Tunnel state"}: ${tunnelStatus?.state?.name ?: "STOPPED"}", color = stateColor, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(14.dp))
            if (tunnelStatus?.message?.isNotBlank() == true) {
                Text(tunnelStatus!!.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp))
            }
            tunnelStatus?.publicUrl?.takeIf { it.isNotBlank() }?.let { url ->
                GroupDivider()
                NavRow(url, if (t.zh) "点击复制公网地址" else "Tap to copy public URL", Icons.Default.Public, onClick = { copy(context, url, t.copied) })
                if (settings.authEnabled && settings.accessToken.isNotBlank() && url.startsWith("https://")) {
                    GroupDivider()
                    val full = "$url/mcp?token=${settings.accessToken}"
                    NavRow(if (t.zh) "带 token 的 MCP 链接" else "MCP URL with token", full, Icons.Default.Link, onClick = { copy(context, full, t.copied) })
                }
            }
        }
        GlassGroup(title = if (t.zh) "模式" else "Mode", footer = if (t.zh) "临时隧道无需账号，URL 重启变化；永久隧道需 Cloudflare Tunnel token。" else "Quick tunnel needs no account; named tunnel needs a Cloudflare token.") {
            ChipRow(
                listOf("off" to if (t.zh) "关闭" else "Off", "quick" to if (t.zh) "临时隧道" else "Quick", "named" to if (t.zh) "永久隧道" else "Named"),
                tunnelMode,
            ) { tunnelMode = it; settings.tunnelMode = it }
            if (tunnelMode == "named") {
                OutlinedTextField(
                    value = namedToken,
                    onValueChange = { namedToken = it; settings.tunnelNamedToken = it },
                    label = { Text(if (t.zh) "Tunnel token" else "Tunnel token") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                )
            }
        }
        GlassGroup(title = if (t.zh) "传输" else "Transport") {
            NumberSettingRow(if (t.zh) "代理目标端口" else "Proxy target port", tunnelPort, { tunnelPort = it }, { settings.tunnelTargetPort = it }, if (t.zh) "端口" else "port")
            GroupDivider()
            Text(if (t.zh) "传输协议" else "Protocol", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("auto" to "Auto", "http2" to "HTTP/2", "quic" to "QUIC"), tunnelProtocol) { tunnelProtocol = it; settings.tunnelProtocol = it }
            GroupDivider()
            Text(if (t.zh) "边缘 IP 版本" else "Edge IP version", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("4" to "IPv4", "6" to "IPv6", "auto" to if (t.zh) "自动" else "Auto"), edgeIpVersion) { edgeIpVersion = it; settings.tunnelEdgeIpVersion = it }
            GroupDivider()
            Text(if (t.zh) "隧道日志级别" else "Tunnel log level", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("info" to "Info", "debug" to "Debug", "warn" to "Warn", "error" to "Error"), tunnelLogLevel) { tunnelLogLevel = it; settings.tunnelLogLevel = it }
        }
        GlassGroup {
            ToggleRow(if (t.zh) "随服务自动启动" else "Auto-start with service", tunnelAutoStart) { tunnelAutoStart = it; settings.tunnelAutoStart = it }
            GroupDivider()
            ToggleRow(if (t.zh) "断线自动重连" else "Auto reconnect", tunnelReconnect) { tunnelReconnect = it; settings.tunnelReconnect = it }
            GroupDivider()
            ToggleRow(if (t.zh) "隧道保活" else "Tunnel keepalive", tunnelKeepAlive) { tunnelKeepAlive = it; settings.tunnelKeepAlive = it }
            GroupDivider()
            NumberSettingRow(if (t.zh) "保活探测间隔" else "Probe interval", keepaliveInterval, { keepaliveInterval = it }, {
                settings.tunnelKeepaliveIntervalSec = it.coerceIn(5, 300)
                keepaliveInterval = settings.tunnelKeepaliveIntervalSec.toString()
            }, if (t.zh) "秒" else "s")
            GroupDivider()
            NumberSettingRow(if (t.zh) "重连退避" else "Reconnect backoff", reconnectBackoff, { reconnectBackoff = it }, {
                settings.tunnelReconnectBackoffSec = it.coerceIn(1, 60)
                reconnectBackoff = settings.tunnelReconnectBackoffSec.toString()
            }, if (t.zh) "秒" else "s")
        }
        GlassGroup {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(if (t.zh) "启动" else "Start", {
                    val mode = if (tunnelMode == "named") CloudflareTunnelManager.Mode.NAMED else CloudflareTunnelManager.Mode.QUICK
                    val tunnel = activeTunnel(context)
                    if (tunnel == null) {
                        Toast.makeText(context, if (t.zh) "请先启动 MCP 服务器总开关" else "Turn on the MCP server master switch first", Toast.LENGTH_SHORT).show()
                    } else {
                        scope.launch {
                            withContext(Dispatchers.IO) { tunnel.start(settings.tunnelTargetPort, mode, namedToken) }
                            tunnelStatus = tunnelStatusOf(context)
                        }
                        Toast.makeText(context, if (t.zh) "隧道启动中…" else "Starting tunnel…", Toast.LENGTH_SHORT).show()
                    }
                })
                SecondaryActionButton(if (t.zh) "停止" else "Stop") {
                    val tunnel = activeTunnel(context)
                    if (tunnel == null) {
                        Toast.makeText(context, if (t.zh) "服务器未运行，无需停止隧道" else "Server not running, nothing to stop", Toast.LENGTH_SHORT).show()
                    } else {
                        scope.launch {
                            withContext(Dispatchers.IO) { tunnel.stop() }
                            tunnelStatus = tunnelStatusOf(context)
                        }
                    }
                }
                SecondaryActionButton(if (t.zh) "刷新状态" else "Refresh") { tunnelStatus = tunnelStatusOf(context) }
                SecondaryActionButton(if (t.zh) "导出配置" else "Export") { showExport = true }
                SecondaryActionButton(if (t.zh) "导入配置" else "Import") { showImport = true; importText = "" }
            }
        }
        GlassGroup(title = if (t.zh) "历史隧道 URL" else "History tunnel URLs") {
            ToggleRow(if (t.zh) "记录隧道 URL" else "Record tunnel URLs", historyEnabled) {
                historyEnabled = it
                settings.tunnelHistoryEnabled = it
            }
            if (history.isNotEmpty()) {
                GroupDivider()
                history.forEachIndexed { idx, h ->
                    if (idx > 0) GroupDivider()
                    NavRow(h, if (t.zh) "点击复制；长按不可用，可用下方按钮删除" else "Tap to copy; use the button below to delete", onClick = { copy(context, h, t.copied) })
                    TextButton(onClick = {
                        history = history.filterNot { it == h }
                        settings.tunnelHistoryUrls = history.joinToString("\n")
                    }, modifier = Modifier.padding(horizontal = 8.dp)) { Text(if (t.zh) "删除" else "Delete") }
                }
                GroupDivider()
                TextButton(onClick = { history = emptyList(); settings.tunnelHistoryUrls = "" }, modifier = Modifier.padding(horizontal = 8.dp)) { Text(if (t.zh) "清空历史" else "Clear history") }
            }
        }
    }
    if (showExport) {
        val yaml = buildString {
            appendLine("# SOMCP tunnel config (token masked)")
            appendLine("mode: ${settings.tunnelMode}")
            appendLine("protocol: ${settings.tunnelProtocol}")
            appendLine("edgeIpVersion: ${settings.tunnelEdgeIpVersion}")
            appendLine("targetPort: ${settings.tunnelTargetPort}")
            appendLine("logLevel: ${settings.tunnelLogLevel}")
            appendLine("autoStart: ${settings.tunnelAutoStart}")
            appendLine("reconnect: ${settings.tunnelReconnect}")
            appendLine("keepAlive: ${settings.tunnelKeepAlive}")
            appendLine("keepaliveIntervalSec: ${settings.tunnelKeepaliveIntervalSec}")
            appendLine("reconnectBackoffSec: ${settings.tunnelReconnectBackoffSec}")
            appendLine("token: ${maskToken(settings.tunnelNamedToken)}")
        }
        AlertDialog(
            onDismissRequest = { showExport = false },
            title = { Text(if (t.zh) "导出配置（token 已脱敏）" else "Export config (token masked)") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text(yaml, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            },
            confirmButton = {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { copy(context, yaml, t.copied) }) { Text(if (t.zh) "复制" else "Copy") }
                    TextButton(onClick = { showExport = false }) { Text(if (t.zh) "关闭" else "Close") }
                }
            },
        )
    }
    if (showImport) {
        AlertDialog(
            onDismissRequest = { showImport = false },
            title = { Text(if (t.zh) "导入配置" else "Import config") },
            text = {
                Column {
                    Text(if (t.zh) "粘贴导出的 YAML（token 行可选）。" else "Paste exported YAML (token optional).", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(value = importText, onValueChange = { importText = it }, modifier = Modifier.fillMaxWidth().height(160.dp))
                }
            },
            confirmButton = {
                Button(onClick = {
                    applyTunnelConfigYaml(settings, importText)
                    tunnelMode = settings.tunnelMode
                    tunnelProtocol = settings.tunnelProtocol
                    edgeIpVersion = settings.tunnelEdgeIpVersion
                    tunnelPort = settings.tunnelTargetPort.toString()
                    tunnelLogLevel = settings.tunnelLogLevel
                    tunnelAutoStart = settings.tunnelAutoStart
                    tunnelReconnect = settings.tunnelReconnect
                    tunnelKeepAlive = settings.tunnelKeepAlive
                    keepaliveInterval = settings.tunnelKeepaliveIntervalSec.toString()
                    reconnectBackoff = settings.tunnelReconnectBackoffSec.toString()
                    namedToken = settings.tunnelNamedToken
                    showImport = false
                    Toast.makeText(context, if (t.zh) "配置已导入" else "Imported", Toast.LENGTH_SHORT).show()
                }) { Text(if (t.zh) "应用" else "Apply") }
            },
            dismissButton = { TextButton(onClick = { showImport = false }) { Text(if (t.zh) "取消" else "Cancel") } },
        )
    }
}

private fun activeTunnel(context: Context): CloudflareTunnelManager? =
    activeServer(context)?.tunnel

private fun tunnelStatusOf(context: Context): CloudflareTunnelManager.TunnelStatus =
    activeServer(context)?.tunnel?.status() ?: CloudflareTunnelManager.TunnelStatus()

private fun maskToken(token: String): String {
    if (token.length <= 8) return if (token.isBlank()) "(empty)" else "****"
    return token.take(4) + "…(" + token.length + ")…" + token.takeLast(4)
}

private fun applyTunnelConfigYaml(settings: SettingsStore, yaml: String) {
    val map = HashMap<String, String>()
    yaml.lines().forEach { line ->
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
        val idx = trimmed.indexOf(':')
        if (idx <= 0) return@forEach
        val key = trimmed.substring(0, idx).trim()
        val value = trimmed.substring(idx + 1).trim()
        if (key.isNotEmpty()) map[key] = value
    }
    map["mode"]?.let { if (it in setOf("off", "quick", "named")) settings.tunnelMode = it }
    map["protocol"]?.let { if (it in setOf("http2", "quic", "auto")) settings.tunnelProtocol = it }
    map["edgeIpVersion"]?.let { if (it in setOf("4", "6", "auto")) settings.tunnelEdgeIpVersion = it }
    map["targetPort"]?.toIntOrNull()?.let { settings.tunnelTargetPort = it }
    map["logLevel"]?.let { if (it in setOf("debug", "info", "warn", "error", "fatal")) settings.tunnelLogLevel = it }
    map["autoStart"]?.lowercase()?.let { settings.tunnelAutoStart = it == "true" || it == "1" }
    map["reconnect"]?.lowercase()?.let { settings.tunnelReconnect = it == "true" || it == "1" }
    map["keepAlive"]?.lowercase()?.let { settings.tunnelKeepAlive = it == "true" || it == "1" }
    map["keepaliveIntervalSec"]?.toIntOrNull()?.let { settings.tunnelKeepaliveIntervalSec = it.coerceIn(5, 300) }
    map["reconnectBackoffSec"]?.toIntOrNull()?.let { settings.tunnelReconnectBackoffSec = it.coerceIn(1, 60) }
    map["token"]?.takeIf { it.isNotBlank() && !it.contains("…") && it != "(empty)" }?.let { settings.tunnelNamedToken = it }
}
