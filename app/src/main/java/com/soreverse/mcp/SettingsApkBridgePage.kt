package com.soreverse.mcp

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun SettingsApkBridgePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var apkUrl by remember { mutableStateOf(settings.apkMcpUrl) }
    var apkToken by remember { mutableStateOf(settings.apkMcpToken) }
    var apkAutoProbe by remember { mutableStateOf(settings.apkMcpAutoProbe) }
    var apkMerge by remember { mutableStateOf(settings.apkMcpMergeTools) }
    var probeState by remember { mutableStateOf<ApkMcpBridge.State?>(null) }
    PageScroll {
        GlassGroup {
            OutlinedTextField(
                value = apkUrl,
                onValueChange = { apkUrl = it; settings.apkMcpUrl = it },
                label = { Text(if (t.zh) "APK MCP /mcp URL" else "APK MCP /mcp URL") },
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
            Text(
                if (t.zh) "例如 MT 管理器侧边栏 APK MCP：http://192.168.x.x:8787/mcp" else "e.g. MT Manager APK MCP: http://192.168.x.x:8787/mcp",
                modifier = Modifier.padding(horizontal = 14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            OutlinedTextField(
                value = apkToken,
                onValueChange = { apkToken = it; settings.apkMcpToken = it },
                label = { Text(if (t.zh) "Bearer token（可选）" else "Bearer token (optional)") },
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
        GlassGroup {
            ToggleRow(if (t.zh) "持续自动探测" else "Continuous auto-probe", apkAutoProbe) { apkAutoProbe = it; settings.apkMcpAutoProbe = it }
            GroupDivider()
            ToggleRow(if (t.zh) "合并工具到 tools/list" else "Merge tools into tools/list", apkMerge) { apkMerge = it; settings.apkMcpMergeTools = it }
        }
        GlassGroup {
            Row(Modifier.padding(14.dp)) {
                PrimaryActionButton(
                    if (t.zh) "立即探测" else "Probe now",
                    {
                        scope.launch {
                            val bridge = activeBridge(context.applicationContext)
                            probeState = withContext(Dispatchers.IO) { bridge.probe() }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            probeState?.let {
                val color = if (it.online) AppleColors.systemGreen else AppleColors.systemRed
                Text(
                    "${if (t.zh) "状态" else "State"}: ${if (it.online) (if (t.zh) "在线" else "online") else (if (t.zh) "离线" else "offline")}   ${if (t.zh) "工具数" else "tools"}: ${it.tools.size}",
                    color = color,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                )
                if (it.lastError.isNotBlank()) {
                    Text(it.lastError, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp))
                }
            }
            Text(
                if (t.zh)
                    "MT 管理器负责 APK 主流程；本应用补充 SO 分析与远程 MCP。离线时桥接工具会自动隐藏。"
                else
                    "MT Manager owns the APK workflow; this app assists with SO analysis. Bridged tools hide when offline.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
