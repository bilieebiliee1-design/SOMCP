package com.soreverse.mcp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.EndpointInfo
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.NetworkInspector
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.engine.WorkDirectory
import com.soreverse.mcp.service.McpForegroundService
import org.json.JSONArray
import org.json.JSONObject

@Composable
internal fun SettingsServiceConfigPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var treeUri by remember { mutableStateOf(settings.treeUri) }
    var portText by remember { mutableStateOf(settings.port.toString()) }
    var bindHost by remember { mutableStateOf(settings.bindHost) }
    var authEnabled by remember { mutableStateOf(settings.authEnabled) }
    var accessToken by remember { mutableStateOf(settings.accessToken) }
    var refreshKey by remember { mutableStateOf(0) }
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
    val endpoints = remember(settings.port, settings.bindHost, refreshKey) { filteredEndpoints(context, settings, settings.port) }
    val loopback = endpoints.firstOrNull { it.url.contains("127.0.0.1") }?.url ?: "http://127.0.0.1:${settings.port}/mcp"
    val preferred = endpoints.firstOrNull { !it.url.contains("127.0.0.1") && !it.url.contains("[::1]") }?.url ?: loopback
    val publicUrl = activeServer(context)?.tunnel?.status()?.publicUrl?.takeIf { it.isNotBlank() }
    PageScroll {
        GlassGroup(title = if (t.zh) "工作目录" else "Work directory") {
            NavRow(
                title = treeUri?.let(WorkDirectory::displayPath) ?: if (t.zh) "未设置" else "Not set",
                subtitle = if (t.zh) "用于扫描、打开、修改与导出 SO" else "Used to scan, open, edit and export SO files",
                icon = Icons.Default.FolderOpen,
                trailing = if (t.zh) "选择" else "Choose",
                onClick = { pickTree.launch(null) },
            )
        }
        GlassGroup(title = if (t.zh) "服务端口" else "Service port", footer = portStatusText(portText.toIntOrNull() ?: settings.port, McpForegroundService.isRunning(), t.zh)) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = { Text(t.port) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.weight(1f),
                )
                PrimaryActionButton(if (t.zh) "应用" else "Apply", {
                    val next = portText.toIntOrNull()?.coerceIn(1024, 65535) ?: settings.port
                    if (isPortAvailable(next, McpForegroundService.isRunning() && next == settings.port)) {
                        settings.port = next
                        portText = next.toString()
                        refreshKey++
                    } else {
                        Toast.makeText(context, if (t.zh) "端口不可用" else "Port unavailable", Toast.LENGTH_SHORT).show()
                    }
                })
            }
        }
        GlassGroup(title = if (t.zh) "全部地址" else "All endpoints") {
            endpoints.forEachIndexed { index, endpoint ->
                if (index > 0) GroupDivider()
                val display = displayEndpoint(endpoint, t.zh)
                val url = if (settings.authEnabled) "${endpoint.url}?token=${settings.accessToken}" else endpoint.url
                NavRow(display.first, url, Icons.Default.Link, trailing = if (t.zh) "复制" else "Copy", onClick = { copy(context, url, t.copied) })
            }
            if (publicUrl != null) {
                GroupDivider()
                NavRow(if (t.zh) "公网隧道" else "Public tunnel", "$publicUrl/mcp", Icons.Default.Public, trailing = if (t.zh) "复制" else "Copy", onClick = { copy(context, "$publicUrl/mcp", t.copied) })
            }
        }
        GlassGroup(title = if (t.zh) "客户端配置" else "Client configuration", footer = if (t.zh) "桌面客户端优先使用 NPX 或 UVX 配置" else "Prefer NPX or UVX for desktop clients") {
            Text(clientConfig(preferred, settings), modifier = Modifier.padding(14.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            FlowRow(Modifier.padding(horizontal = 14.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PrimaryActionButton(if (t.zh) "复制 NPX" else "Copy NPX", { copy(context, clientConfig(preferred, settings), t.copied) })
                PrimaryActionButton(if (t.zh) "复制 UVX" else "Copy UVX", { copy(context, clientConfigUvx(preferred, settings), t.copied) })
                SecondaryActionButton(if (t.zh) "复制直连" else "Copy direct") { copy(context, clientConfigDirect(preferred, settings), t.copied) }
            }
        }
        GlassGroup(title = if (t.zh) "访问控制" else "Access control", footer = if (t.zh) "修改端口、绑定地址或 Token 后需重启服务。" else "Restart the service after changing port, bind address, or token.") {
            ToggleRow(if (t.zh) "启用访问 Token" else "Require access token", authEnabled) {
                authEnabled = it
                settings.authEnabled = it
            }
            GroupDivider()
            Text(if (t.zh) "绑定地址" else "Bind address", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.labelMedium)
            ChipRow(
                listOf("0.0.0.0" to if (t.zh) "允许局域网" else "LAN", "127.0.0.1" to if (t.zh) "仅本机" else "Local only"),
                bindHost,
            ) {
                bindHost = it
                settings.bindHost = it
                refreshKey++
            }
            GroupDivider()
            OutlinedTextField(
                value = accessToken,
                onValueChange = { accessToken = it; settings.accessToken = it },
                label = { Text(if (t.zh) "访问 Token" else "Access token") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                PrimaryActionButton(if (t.zh) "重新生成" else "Regenerate", { accessToken = settings.resetAccessToken() })
                SecondaryActionButton(if (t.zh) "复制 Token" else "Copy token") { copy(context, accessToken, t.copied) }
            }
        }
    }
}

private fun displayEndpoint(endpoint: EndpointInfo, zh: Boolean): Pair<String, String> {
    if (zh) return endpoint.label to endpoint.note
    val label = when (endpoint.label) {
        "本机回环" -> "Loopback"
        "IPv6 地址" -> "IPv6 address"
        "局域网地址" -> "LAN address"
        else -> endpoint.label
    }
    val note = when (endpoint.note) {
        "仅本机/ADB 端口转发可用" -> "Only local device or ADB port forwarding"
        "通常仅同一局域网可访问" -> "Usually reachable only from the same LAN"
        "地址看起来可公网路由，仍取决于运营商/防火墙/客户端网络" -> "Looks publicly routable, still depends on carrier, firewall, and client network"
        else -> endpoint.note
    }
    return label to note
}

internal fun filteredEndpoints(context: Context, settings: SettingsStore, port: Int): List<EndpointInfo> {
    val endpoints = NetworkInspector.endpoints(context, port)
    return if (settings.bindHost == "127.0.0.1") endpoints.filter { it.url.contains("127.0.0.1") } else endpoints
}

private fun clientConfig(url: String, settings: SettingsStore): String {
    val args = JSONArray().put("-y").put("mcp-remote").put(url)
    if (needsAllowHttp(url)) {
        args.put("--allow-http")
    }
    if (settings.authEnabled) {
        args.put("--header").put("Authorization: Bearer ${settings.accessToken}")
    }
    val server = JSONObject()
        .put("command", "npx")
        .put("args", args)
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun clientConfigUvx(url: String, settings: SettingsStore): String {
    val args = JSONArray().put("mcp-proxy").put(url)
    if (settings.authEnabled) {
        args.put("--headers").put("Authorization=Bearer ${settings.accessToken}")
    }
    val server = JSONObject()
        .put("command", "uvx")
        .put("args", args)
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun clientConfigDirect(url: String, settings: SettingsStore): String {
    val server = JSONObject().put("type", "http").put("url", url)
    if (settings.authEnabled) {
        server.put("headers", JSONObject().put("Authorization", "Bearer ${settings.accessToken}"))
    }
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun prettyJson(obj: JSONObject): String = obj.toString(2).replace("\\/", "/")

private fun needsAllowHttp(url: String): Boolean {
    val lower = url.lowercase()
    return lower.startsWith("http://") &&
        !lower.startsWith("http://localhost") &&
        !lower.startsWith("http://127.0.0.1") &&
        !lower.startsWith("http://[::1]")
}
