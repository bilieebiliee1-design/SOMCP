package com.soreverse.mcp

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.ApkBridgeConfig
import com.soreverse.mcp.core.ApkBridgeInstance
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

@Composable
internal fun SettingsApkBridgePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var configs by remember { mutableStateOf(settings.apkBridgeConfigs) }
    var apkAutoProbe by remember { mutableStateOf(settings.apkMcpAutoProbe) }
    var apkMerge by remember { mutableStateOf(settings.apkMcpMergeTools) }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingConfig by remember { mutableStateOf<ApkBridgeConfig?>(null) }
    var probeStates by remember { mutableStateOf<Map<String, ApkBridgeInstance.State>>(emptyMap()) }

    fun saveConfigs(newConfigs: List<ApkBridgeConfig>) {
        configs = newConfigs
        settings.apkBridgeConfigs = newConfigs
    }

    fun probeBridge(config: ApkBridgeConfig) {
        scope.launch {
            val instance = ApkBridgeConfig.newInstance(config)
            val state = withContext(Dispatchers.IO) { instance.probe() }
            probeStates = probeStates + (config.id to state)
        }
    }

    fun probeAll() {
        configs.forEach { probeBridge(it) }
    }

    PageScroll {
        // Bridge list
        GlassGroup {
            Row(
                Modifier.fillMaxWidth().padding(14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    if (t.zh) "桥接列表" else "Bridge List",
                    style = MaterialTheme.typography.titleMedium
                )
                IconButton(onClick = { showAddDialog = true }) {
                    Icon(Icons.Default.Add, contentDescription = if (t.zh) "添加" else "Add")
                }
            }
            if (configs.isEmpty()) {
                Text(
                    if (t.zh) "暂无桥接配置，点击右上角添加" else "No bridge configs. Tap + to add.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                )
            } else {
                configs.forEach { config ->
                    BridgeConfigItem(
                        t = t,
                        config = config,
                        probeState = probeStates[config.id],
                        onEdit = { editingConfig = config },
                        onDelete = {
                            saveConfigs(configs.filter { it.id != config.id })
                        },
                        onProbe = { probeBridge(config) }
                    )
                }
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

        // Probe all button
        if (configs.isNotEmpty()) {
            GlassGroup {
                Row(Modifier.padding(14.dp)) {
                    PrimaryActionButton(
                        if (t.zh) "探测全部" else "Probe All",
                        { probeAll() },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Info text
        Text(
            if (t.zh)
                "MT 管理器或 NP 管理器负责 APK 主流程；本应用补充 SO 分析与远程 MCP。离线时桥接工具会自动隐藏。"
            else
                "MT Manager or NP Manager owns the APK workflow; this app assists with SO analysis. Bridged tools hide when offline.",
            modifier = Modifier.padding(14.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    // Add dialog
    if (showAddDialog) {
        BridgeConfigDialog(
            t = t,
            config = null,
            onDismiss = { showAddDialog = false },
            onSave = { newConfig ->
                saveConfigs(configs + newConfig)
                showAddDialog = false
            }
        )
    }

    // Edit dialog
    editingConfig?.let { config ->
        BridgeConfigDialog(
            t = t,
            config = config,
            onDismiss = { editingConfig = null },
            onSave = { updated ->
                saveConfigs(configs.map { if (it.id == config.id) updated else it })
                editingConfig = null
            }
        )
    }
}

@Composable
private fun BridgeConfigItem(
    t: UiText,
    config: ApkBridgeConfig,
    probeState: ApkBridgeInstance.State?,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onProbe: () -> Unit,
) {
    val color = when {
        probeState == null -> MaterialTheme.colorScheme.onSurfaceVariant
        probeState.online -> AppleColors.systemGreen
        else -> AppleColors.systemRed
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 8.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
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
                if (probeState != null) {
                    Text(
                        "${if (t.zh) "状态" else "State"}: ${if (probeState.online) (if (t.zh) "在线" else "online") else (if (t.zh) "离线" else "offline")}   ${if (t.zh) "工具" else "tools"}: ${probeState.tools.size}",
                        style = MaterialTheme.typography.bodySmall,
                        color = color
                    )
                }
            }
            Row {
                IconButton(onClick = onProbe) {
                    Box(
                        Modifier.size(8.dp).background(color, CircleShape)
                    )
                }
                IconButton(onClick = onEdit) {
                    Icon(Icons.Default.Edit, contentDescription = if (t.zh) "编辑" else "Edit", modifier = Modifier.size(18.dp))
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Default.Delete, contentDescription = if (t.zh) "删除" else "Delete", modifier = Modifier.size(18.dp))
                }
            }
        }
        GroupDivider()
    }
}

@Composable
private fun BridgeConfigDialog(
    t: UiText,
    config: ApkBridgeConfig?,
    onDismiss: () -> Unit,
    onSave: (ApkBridgeConfig) -> Unit,
) {
    var label by remember { mutableStateOf(config?.label ?: "") }
    var url by remember { mutableStateOf(config?.url ?: "") }
    var token by remember { mutableStateOf(config?.token ?: "") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (config == null) (if (t.zh) "添加桥接" else "Add Bridge") else (if (t.zh) "编辑桥接" else "Edit Bridge")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text(if (t.zh) "名称" else "Label") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(if (t.zh) "URL" else "URL") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = token,
                    onValueChange = { token = it },
                    label = { Text(if (t.zh) "Token（可选）" else "Token (optional)") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (url.isNotBlank()) {
                        onSave(
                            ApkBridgeConfig(
                                id = config?.id ?: UUID.randomUUID().toString(),
                                label = label.ifBlank { url },
                                url = url.trim(),
                                token = token,
                                enabled = true
                            )
                        )
                    }
                },
                enabled = url.isNotBlank()
            ) { Text(if (t.zh) "保存" else "Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(if (t.zh) "取消" else "Cancel") }
        }
    )
}
