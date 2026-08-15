package com.soreverse.mcp

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

@Composable
internal fun SettingsApkBridgePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var configs by remember { mutableStateOf(settings.apkMcpConfigs) }
    var apkAutoProbe by remember { mutableStateOf(settings.apkMcpAutoProbe) }
    var apkMerge by remember { mutableStateOf(settings.apkMcpMergeTools) }
    var showAddForm by remember { mutableStateOf(false) }
    var newUrl by remember { mutableStateOf("") }
    var newToken by remember { mutableStateOf("") }
    var snapshot by remember { mutableStateOf<JSONObject?>(null) }

    val bridge = activeBridge(context.applicationContext)

    fun refreshSnapshot() {
        scope.launch {
            snapshot = withContext(Dispatchers.IO) {
                bridge.probe()
                bridge.snapshotJson()
            }
        }
    }

    fun bridgeState(url: String): JSONObject? {
        val bridges = snapshot?.optJSONArray("bridges") ?: return null
        for (i in 0 until bridges.length()) {
            val b = bridges.optJSONObject(i) ?: continue
            if (b.optString("url") == url) return b
        }
        return null
    }

    PageScroll {
        // ---- Bridge list ----
        GlassGroup(title = if (t.zh) "桥接列表" else "Bridge List") {
            if (configs.isEmpty()) {
                Text(
                    if (t.zh) "尚未添加任何桥接" else "No bridges configured",
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            configs.forEachIndexed { index, config ->
                if (index > 0) GroupDivider()
                val st = bridgeState(config.url)
                val online = st?.optBoolean("online") == true
                val toolCount = st?.optInt("toolCount") ?: 0
                val lastError = st?.optString("lastError") ?: ""
                val latencyMs = st?.optLong("lastLatencyMs") ?: 0L

                Row(
                    Modifier.fillMaxWidth().padding(
                        start = 14.dp,
                        end = 4.dp,
                        top = 8.dp,
                        bottom = 8.dp
                    ),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Status dot
                    Box(
                        Modifier.size(10.dp).clip(CircleShape).background(
                            if (online) {
                                AppleColors.systemGreen
                            } else if (st != null) {
                                AppleColors.systemRed
                            } else {
                                Color.Gray
                            }
                        )
                    )
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            config.url,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (config.token.isNotBlank()) {
                                Text(
                                    "token: ${"\u2022".repeat(
                                        config.token.length.coerceIn(4, 12)
                                    )}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                            if (online) {
                                Text(
                                    "$toolCount tools",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = AppleColors.systemGreen
                                )
                                if (latencyMs > 0) {
                                    Text(
                                        "  ${latencyMs}ms",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            } else if (st != null && lastError.isNotBlank()) {
                                Text(
                                    lastError,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = AppleColors.systemRed,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            } else if (st != null) {
                                Text(
                                    if (t.zh) "离线" else "offline",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = AppleColors.systemRed
                                )
                            }
                        }
                    }
                    // Delete button
                    IconButton(onClick = {
                        bridge.removeBridge(config.url)
                        configs = settings.apkMcpConfigs
                        snapshot = null
                    }) {
                        Icon(
                            Icons.Default.Close,
                            if (t.zh) "移除" else "Remove",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ---- Add bridge form ----
            GroupDivider()
            if (showAddForm) {
                OutlinedTextField(
                    value = newUrl,
                    onValueChange = { newUrl = it },
                    label = { Text(if (t.zh) "APK MCP /mcp URL" else "APK MCP /mcp URL") },
                    placeholder = { Text("http://192.168.x.x:8787/mcp") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(
                            alpha = 0.35f
                        ),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(
                            alpha = 0.35f
                        )
                    ),
                    modifier = Modifier.fillMaxWidth().padding(
                        start = 14.dp,
                        end = 14.dp,
                        top = 8.dp
                    )
                )
                OutlinedTextField(
                    value = newToken,
                    onValueChange = { newToken = it },
                    label = { Text(if (t.zh) "Bearer token（可选）" else "Bearer token (optional)") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(
                            alpha = 0.35f
                        ),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(
                            alpha = 0.35f
                        )
                    ),
                    modifier = Modifier.fillMaxWidth().padding(
                        start = 14.dp,
                        end = 14.dp,
                        top = 8.dp
                    )
                )
                Row(
                    Modifier.fillMaxWidth().padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    SecondaryActionButton(
                        if (t.zh) "取消" else "Cancel",
                        {
                            showAddForm = false
                            newUrl = ""
                            newToken = ""
                        },
                        modifier = Modifier.weight(1f)
                    )
                    PrimaryActionButton(
                        if (t.zh) "添加" else "Add",
                        {
                            val url = newUrl.trim()
                            if (url.isNotBlank()) {
                                scope.launch {
                                    withContext(Dispatchers.IO) { bridge.probeUrl(url, newToken) }
                                    configs = settings.apkMcpConfigs
                                    refreshSnapshot()
                                    showAddForm = false
                                    newUrl = ""
                                    newToken = ""
                                }
                            }
                        },
                        modifier = Modifier.weight(1f)
                    )
                }
            } else {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 4.dp)) {
                    TextButton(onClick = { showAddForm = true }) {
                        Icon(Icons.Default.Add, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (t.zh) "添加桥接" else "Add Bridge")
                    }
                }
                Text(
                    if (t.zh) "支持同时连接多个 APK MCP 桥接（如 MT 管理器 + NP 管理器）" else "Supports multiple concurrent APK MCP bridges (e.g. MT Manager + NP Manager)",
                    modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // ---- Options ----
        GlassGroup(title = if (t.zh) "选项" else "Options") {
            ToggleRow(if (t.zh) "持续自动探测" else "Continuous auto-probe", apkAutoProbe) {
                apkAutoProbe =
                    it
                settings.apkMcpAutoProbe = it
            }
            GroupDivider()
            ToggleRow(if (t.zh) "合并工具到 tools/list" else "Merge tools into tools/list", apkMerge) {
                apkMerge =
                    it
                settings.apkMcpMergeTools = it
            }
        }

        // ---- Actions ----
        GlassGroup {
            Row(Modifier.padding(14.dp)) {
                PrimaryActionButton(
                    if (t.zh) "探测全部" else "Probe All",
                    { refreshSnapshot() },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            snapshot?.let { snap ->
                val bridges = snap.optJSONArray("bridges") ?: JSONArray()
                val onlineCount = snap.optInt("onlineCount")
                val text = if (t.zh) "状态：$onlineCount/${bridges.length()} 个桥接在线" else "State: $onlineCount/${bridges.length()} bridge(s) online"
                Text(
                    text,
                    color = if (onlineCount > 0) AppleColors.systemGreen else AppleColors.systemRed,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp)
                )
                // Show per-bridge status in probe results
                if (bridges.length() > 0) {
                    for (i in 0 until bridges.length()) {
                        val b = bridges.optJSONObject(i) ?: continue
                        val url = b.optString("url")
                        val online = b.optBoolean("online")
                        val tools = b.optInt("toolCount")
                        val prefix = b.optString("toolPrefix")
                        val label = ApkMcpBridge.prefixLabel(prefix)
                        val line = if (online) {
                            if (t.zh) "  \u2022 $label ($url) 在线 - $tools 工具" else "  \u2022 $label ($url) online - $tools tools"
                        } else {
                            if (t.zh) "  \u2022 $url 离线" else "  \u2022 $url offline"
                        }
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (online) AppleColors.systemGreen else AppleColors.systemRed,
                            modifier = Modifier.padding(horizontal = 14.dp),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
            Text(
                if (t.zh) {
                    "MT 管理器或 NP 管理器负责 APK 主流程；本应用补充 SO 分析与远程 MCP。离线时桥接工具会自动隐藏。"
                } else {
                    "MT Manager or NP Manager owns the APK workflow; this app assists with SO analysis. Bridged tools hide when offline."
                },
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
