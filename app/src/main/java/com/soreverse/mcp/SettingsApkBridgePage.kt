package com.soreverse.mcp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.ApkBridgeConfig
import com.soreverse.mcp.core.ApkBridgeInstance
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

@Composable
internal fun SettingsApkBridgePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var bridgeConfigs by remember { mutableStateOf(settings.apkBridgeConfigs) }
    var apkAutoProbe by remember { mutableStateOf(settings.apkMcpAutoProbe) }
    var apkMerge by remember { mutableStateOf(settings.apkMcpMergeTools) }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingConfig by remember { mutableStateOf<ApkBridgeConfig?>(null) }
    var probeStates by remember { mutableStateOf<Map<String, ApkBridgeInstance.State>>(emptyMap()) }

    fun saveConfigs(configs: List<ApkBridgeConfig>) {
        bridgeConfigs = configs
        settings.apkBridgeConfigs = configs
    }

    fun probeBridge(config: ApkBridgeConfig) {
        scope.launch {
            val instance = ApkBridgeConfig(config, settings)
            val state = withContext(Dispatchers.IO) { instance.probe() }
            probeStates = probeStates + (config.id to state)
        }
    }

    fun probeAllBridges() {
        bridgeConfigs.forEach { config -> probeBridge(config) }
    }

    fun addBridge(label: String, url: String, token: String) {
        val config = ApkBridgeConfig(
            id = UUID.randomUUID().toString(),
            label = label,
            url = url,
            token = token,
            enabled = true
        )
        saveConfigs(bridgeConfigs + config)
    }

    fun updateBridge(config: ApkBridgeConfig) {
        saveConfigs(bridgeConfigs.map { if (it.id == config.id) config else it })
    }

    fun removeBridge(id: String) {
        saveConfigs(bridgeConfigs.filter { it.id != id })
        probeStates = probeStates - id
    }

    PageScroll {
        // Bridge list
        GlassGroup {
            Text(
                if (t.zh) "桥接列表" else "Bridge List",
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
            )
            if (bridgeConfigs.isEmpty()) {
                Text(
                    if (t.zh) "暂无桥接配置，点击下方按钮添加" else "No bridges configured. Tap below to add.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                )
            } else {
                bridgeConfigs.forEach { config ->
                    val probeState = probeStates[config.id]
                    BridgeConfigRow(
                        t = t,
                        config = config,
                        probeState = probeState,
                        onProbe = { probeBridge(config) },
                        onEdit = { editingConfig = config },
                        onRemove = { removeBridge(config.id) },
                        onToggle = { updateBridge(config.copy(enabled = !config.enabled)) }
                    )
                }
            }
            TextButton(
                onClick = { showAddDialog = true },
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp)
            ) {
                Text(if (t.zh) "+ 添加桥接" else "+ Add Bridge")
            }
        }

        // Global settings
        GlassGroup {
            ToggleRow(if (t.zh) "持续自动探测" else "Continuous auto-probe", apkAutoProbe) {
                apkAutoProbe = it
                settings.apkMcpAutoProbe = it
            }
            GroupDivider()
            ToggleRow(if (t.zh) "合并工具到 tools/list" else "Merge tools into tools/list", apkMerge) {
                apkMerge = it
                settings.apkMcpMergeTools = it
            }
        }

        // Probe all
        GlassGroup {
            Row(Modifier.padding(14.dp).fillMaxWidth()) {
                PrimaryActionButton(
                    if (t.zh) "探测全部" else "Probe All",
                    { probeAllBridges() },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }

    // Add dialog
    if (showAddDialog) {
        BridgeConfigDialog(
            t = t,
            title = if (t.zh) "添加桥接" else "Add Bridge",
            initialLabel = "",
            initialUrl = "http://192.168.x.x:8788/mcp",
            initialToken = "",
            onConfirm = { label, url, token ->
                addBridge(label, url, token)
                showAddDialog = false
            },
            onDismiss = { showAddDialog = false }
        )
    }

    // Edit dialog
    editingConfig?.let { config ->
        BridgeConfigDialog(
            t = t,
            title = if (t.zh) "编辑桥接" else "Edit Bridge",
            initialLabel = config.label,
            initialUrl = config.url,
            initialToken = config.token,
            onConfirm = { label, url, token ->
                updateBridge(config.copy(label = label, url = url, token = token))
                editingConfig = null
            },
            onDismiss = { editingConfig = null }
        )
    }
}

@Composable
private fun BridgeConfigRow(
    t: UiText,
    config: ApkBridgeConfig,
    probeState: ApkBridgeInstance.State?,
    onProbe: () -> Unit,
    onEdit: () -> Unit,
    onRemove: () -> Unit,
    onToggle: () -> Unit,
) {
    val statusColor = when {
        !config.enabled -> MaterialTheme.colorScheme.onSurfaceVariant
        probeState == null -> MaterialTheme.colorScheme.onSurfaceVariant
        probeState.online -> AppleColors.systemGreen
        else -> AppleColors.systemRed
    }
    val statusText = when {
        !config.enabled -> if (t.zh) "已禁用" else "Disabled"
        probeState == null -> if (t.zh) "未探测" else "Not probed"
        probeState.online -> "${if (t.zh) "在线" else "Online"} · ${probeState.tools.size} tools"
        else -> if (t.zh) "离线" else "Offline"
    }

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    config.label,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
                )
                Text(
                    config.url,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    statusText,
                    style = MaterialTheme.typography.bodySmall,
                    color = statusColor
                )
            }
        }
        Row {
            TextButton(onClick = onProbe) { Text(if (t.zh) "探测" else "Probe") }
            TextButton(onClick = onEdit) { Text(if (t.zh) "编辑" else "Edit") }
            TextButton(onClick = onToggle) { Text(if (config.enabled) (if (t.zh) "禁用" else "Disable") else (if (t.zh) "启用" else "Enable")) }
            TextButton(onClick = onRemove) { Text(if (t.zh) "删除" else "Delete") }
        }
        GroupDivider()
    }
}

@Composable
private fun BridgeConfigDialog(
    t: UiText,
    title: String,
    initialLabel: String,
    initialUrl: String,
    initialToken: String,
    onConfirm: (label: String, url: String, token: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var label by remember { mutableStateOf(initialLabel) }
    var url by remember { mutableStateOf(initialUrl) }
    var token by remember { mutableStateOf(initialToken) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text(if (t.zh) "名称" else "Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("MCP URL") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                )
                OutlinedTextField(
                    value = token,
                    onValueChange = { token = it },
                    label = { Text(if (t.zh) "Token（可选）" else "Token (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(label, url, token) },
                enabled = label.isNotBlank() && url.isNotBlank()
            ) { Text(if (t.zh) "保存" else "Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(if (t.zh) "取消" else "Cancel") }
        }
    )
}

private fun AppLog.w(message: String) {
    android.util.Log.w("ApkBridgeConfig", message)
}
