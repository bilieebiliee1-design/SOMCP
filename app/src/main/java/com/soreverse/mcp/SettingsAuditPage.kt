package com.soreverse.mcp

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.FilterChip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.mcp.ToolCatalog

@Composable
internal fun SettingsAuditPage(t: UiText, settings: SettingsStore) {
    var autoSnapshotBeforeEdit by remember { mutableStateOf(settings.autoSnapshotBeforeEdit) }
    var auditLogEnabled by remember { mutableStateOf(settings.auditLogEnabled) }
    var auditPersist by remember { mutableStateOf(settings.auditPersist) }
    var toolStatsPersist by remember { mutableStateOf(settings.toolStatsPersist) }
    var maxConcurrentTools by remember { mutableStateOf(settings.maxConcurrentTools.toString()) }
    var maxSnapshots by remember { mutableStateOf(settings.maxSnapshots.toString()) }
    var maxCompareRanges by remember { mutableStateOf(settings.maxCompareRanges.toString()) }
    var maxAudits by remember { mutableStateOf(settings.maxAudits.toString()) }
    var logMaxLines by remember { mutableStateOf(settings.logMaxLines.toString()) }
    var collectToolStats by remember { mutableStateOf(settings.collectToolStats) }
    var requestTimeoutMs by remember { mutableStateOf(settings.requestTimeoutMs.toString()) }
    var emulationEnabled by remember { mutableStateOf(settings.emulationEnabled) }
    var toolResultMaxChars by remember { mutableStateOf(settings.toolResultMaxChars.toString()) }
    var toolCallRateLimitPerMin by remember { mutableStateOf(settings.toolCallRateLimitPerMin.toString()) }
    var disabledTools by remember { mutableStateOf(settings.disabledTools) }
    PageScroll {
        GlassGroup {
            ToggleRow(if (t.zh) "编辑前自动快照" else "Auto-snapshot before edit", autoSnapshotBeforeEdit) { autoSnapshotBeforeEdit = it; settings.autoSnapshotBeforeEdit = it }
            GroupDivider()
            ToggleRow(if (t.zh) "启用审计日志" else "Enable audit log", auditLogEnabled) { auditLogEnabled = it; settings.auditLogEnabled = it }
            GroupDivider()
            ToggleRow(if (t.zh) "审计持久化到磁盘" else "Persist audit to disk", auditPersist) { auditPersist = it; settings.auditPersist = it }
            GroupDivider()
            ToggleRow(if (t.zh) "收集工具调用统计" else "Collect tool stats", collectToolStats) { collectToolStats = it; settings.collectToolStats = it }
            GroupDivider()
            ToggleRow(if (t.zh) "持久化工具统计" else "Persist tool stats", toolStatsPersist) {
                toolStatsPersist = it
                settings.toolStatsPersist = it
                com.soreverse.mcp.core.ToolStats.setPersistEnabled(it)
            }
            GroupDivider()
            ToggleRow(if (t.zh) "启用模拟执行 (Unidbg)" else "Enable emulation (Unidbg)", emulationEnabled) { emulationEnabled = it; settings.emulationEnabled = it }
            Text(
                if (t.zh) "启用模拟后允许 emulate_call / emulate_dump 验证补丁语义。" else "Emulation enables emulate_call / emulate_dump for patch validation.",
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        GlassGroup {
            NumberSettingRow(if (t.zh) "重型工具并发上限" else "Heavy tool concurrency cap", maxConcurrentTools, { maxConcurrentTools = it }, { settings.maxConcurrentTools = it }, if (t.zh) "个" else "tasks")
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大快照数" else "Max snapshots", maxSnapshots, { maxSnapshots = it }, { settings.maxSnapshots = it }, if (t.zh) "个" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大审计文件数" else "Max audit files", maxAudits, { maxAudits = it }, { settings.maxAudits = it }, if (t.zh) "个" else "files")
            GroupDivider()
            NumberSettingRow(if (t.zh) "diff 最大范围数" else "Max diff ranges", maxCompareRanges, { maxCompareRanges = it }, { settings.maxCompareRanges = it }, if (t.zh) "段" else "ranges")
            GroupDivider()
            NumberSettingRow(if (t.zh) "日志显示上限" else "Max log lines", logMaxLines, { logMaxLines = it }, { settings.logMaxLines = it }, if (t.zh) "行" else "lines")
            GroupDivider()
            NumberSettingRow(if (t.zh) "请求超时" else "Request timeout", requestTimeoutMs, { requestTimeoutMs = it }, { settings.requestTimeoutMs = it }, "ms")
            GroupDivider()
            NumberSettingRow(if (t.zh) "工具结果上限" else "Tool result limit", toolResultMaxChars, { toolResultMaxChars = it }, { settings.toolResultMaxChars = it }, if (t.zh) "字符" else "chars")
            GroupDivider()
            NumberSettingRow(if (t.zh) "工具调用频率限制" else "Tool call rate limit", toolCallRateLimitPerMin, { toolCallRateLimitPerMin = it }, { settings.toolCallRateLimitPerMin = it }, if (t.zh) "次/分" else "/min")
        }
        GlassGroup {
            Text(if (t.zh) "禁用工具" else "Disabled tools", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(horizontal = 14.dp)) {
                val disabled = disabledTools.split(',').map(String::trim).filter(String::isNotBlank).toSet()
                ToolCatalog.names.forEach { name ->
                    FilterChip(selected = name in disabled, onClick = {
                        val next = disabled.toMutableSet().apply { if (!add(name)) remove(name) }
                        disabledTools = next.sorted().joinToString(",")
                        settings.disabledTools = disabledTools
                    }, label = { Text(name) })
                }
            }
            OutlinedTextField(
                value = disabledTools,
                onValueChange = { disabledTools = it; settings.disabledTools = it },
                label = { Text(if (t.zh) "禁用工具列表(逗号分隔)" else "Disabled tools (comma-separated)") },
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
            Text(if (t.zh) "勾选结果会同步到原始逗号分隔配置；高级用户仍可直接编辑。" else "Selections sync to the raw comma-separated configuration, which remains editable.", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
