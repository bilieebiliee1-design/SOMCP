package com.soreverse.mcp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.SettingsStore

@Composable
internal fun NumberSettingRow(
    label: String,
    value: String,
    onValue: (String) -> Unit,
    onApply: (Int) -> Unit,
    suffix: String = "",
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
        OutlinedTextField(
            value = value,
            onValueChange = { onValue(it.filter(Char::isDigit).take(5)) },
            singleLine = true,
            suffix = if (suffix.isBlank()) null else ({ Text(suffix) }),
            shape = shape,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                focusedContainerColor = Color.Transparent,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            ),
            modifier = Modifier.width(116.dp),
        )
        TextButton(onClick = { value.toIntOrNull()?.let(onApply) }) { Text("OK") }
    }
}

@Composable
internal fun DecimalSettingRow(
    label: String,
    value: String,
    suffix: String,
    supporting: String,
    onValue: (String) -> Unit,
    onApply: (Float) -> Unit,
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
            OutlinedTextField(
                value = value,
                onValueChange = { raw ->
                    val filtered = raw.filter { it.isDigit() || it == '.' }
                    if (filtered.count { it == '.' } <= 1) onValue(filtered.take(5))
                },
                singleLine = true,
                suffix = { Text(suffix) },
                shape = shape,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.width(140.dp),
            )
            TextButton(onClick = { value.toFloatOrNull()?.let(onApply) }) { Text("OK") }
        }
        Text(supporting, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
internal fun ChipRow(items: List<Pair<String, String>>, selected: String, onSelected: (String) -> Unit) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        items.forEach { (value, label) ->
            FilterChip(
                selected = selected == value,
                onClick = { onSelected(value) },
                label = { Text(label) },
                shape = RoundedCornerShape(999.dp),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primary,
                    selectedLabelColor = Color.White,
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                    labelColor = MaterialTheme.colorScheme.onSurface,
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = selected == value,
                    borderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.28f),
                    selectedBorderColor = Color.Transparent,
                ),
            )
        }
    }
}

@Composable
internal fun SecondaryActionButton(text: String, onClick: () -> Unit) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Button(
        onClick = onClick,
        shape = shape,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
            contentColor = MaterialTheme.colorScheme.primary,
        ),
        border = BorderStroke(0.5.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.28f)),
    ) { Text(text, fontWeight = FontWeight.Medium) }
}

@Composable
internal fun SurfacePanel(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(LocalUiMetrics.current.cardRadius)
    Column(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .padding(14.dp),
        content = content,
    )
}

@Composable
internal fun SettingsKeepAlivePage(t: UiText, settings: SettingsStore) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var floating by remember { mutableStateOf(settings.floatingEnabled) }
    var wakeLock by remember { mutableStateOf(settings.wakeLockEnabled) }
    var bootAutoStart by remember { mutableStateOf(settings.bootAutoStart) }
    PageScroll {
        GlassGroup {
            ToggleRow(t.wakeLock, wakeLock) { wakeLock = it; settings.wakeLockEnabled = it }
            GroupDivider()
            ToggleRow(t.floating, floating) {
                if (it && !AndroidSettings.canDrawOverlays(context)) {
                    context.startActivity(Intent(AndroidSettings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:${context.packageName}")))
                }
                floating = it
                settings.floatingEnabled = it
                com.soreverse.mcp.service.McpForegroundService.refreshFloating(context)
            }
            GroupDivider()
            ToggleRow(if (t.zh) "开机自启 MCP 服务" else "Autostart MCP service on boot", bootAutoStart) {
                bootAutoStart = it
                settings.bootAutoStart = it
            }
        }
        GlassGroup(footer = keepAliveAdvice(t.zh)) {
            Text(
                if (t.zh) "开机自启依赖系统允许自启动/后台启动，并与隧道自动启动相互独立。" else "Boot autostart depends on system permissions and is independent from tunnel auto-start.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(t.battery, { openBatterySettings(context) })
                SecondaryActionButton(t.permissions) {
                    context.startActivity(Intent(AndroidSettings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")))
                }
            }
        }
    }
}

internal fun isKeepAliveReady(context: Context, settings: SettingsStore): Boolean {
    val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    val batteryReady = Build.VERSION.SDK_INT < 23 || powerManager.isIgnoringBatteryOptimizations(context.packageName)
    return settings.wakeLockEnabled && batteryReady
}

internal fun keepAliveAdvice(zh: Boolean): String {
    val brand = Build.BRAND.lowercase()
    val base = if (zh) {
        "请允许自启动、后台活动、不限制电池、通知、悬浮窗，并在最近任务中锁定应用。"
    } else {
        "Allow auto-start, background activity, unrestricted battery, notifications, overlay, and lock the app in recents."
    }
    return when {
        brand.contains("xiaomi") || brand.contains("redmi") -> if (zh) "$base\n小米/红米/HyperOS：安全中心 -> 自启动；省电策略 -> 无限制。" else "$base\nMIUI/HyperOS: Security -> Autostart; Battery saver -> No restrictions."
        brand.contains("huawei") || brand.contains("honor") -> if (zh) "$base\n华为/荣耀：手机管家 -> 应用启动管理 -> 手动管理并允许后台活动。" else "$base\nHuawei/Honor: Phone Manager -> App launch -> Manage manually and allow background activity."
        brand.contains("oppo") || brand.contains("realme") || brand.contains("oneplus") -> if (zh) "$base\nOPPO/realme/OnePlus：电池 -> 后台耗电管理 -> 允许。" else "$base\nOPPO/realme/OnePlus: Battery -> Background power usage -> Allow."
        brand.contains("vivo") || brand.contains("iqoo") -> if (zh) "$base\nvivo/iQOO：电池 -> 后台高耗电 -> 允许；权限 -> 自启动。" else "$base\nvivo/iQOO: Battery -> Background high power usage -> Allow; Permissions -> Autostart."
        else -> base
    }
}

@Composable
internal fun SettingsAccessPage(t: UiText, settings: SettingsStore) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var bindHost by remember { mutableStateOf(settings.bindHost) }
    var authEnabled by remember { mutableStateOf(settings.authEnabled) }
    var accessToken by remember { mutableStateOf(settings.accessToken) }
    PageScroll {
        GlassGroup {
            ToggleRow(if (t.zh) "启用访问 token" else "Require access token", authEnabled) {
                authEnabled = it
                settings.authEnabled = it
            }
        }
        GlassGroup(title = if (t.zh) "绑定地址" else "Bind address") {
            ChipRow(
                listOf("0.0.0.0" to if (t.zh) "允许局域网" else "LAN", "127.0.0.1" to if (t.zh) "仅本机" else "Local only"),
                bindHost,
                {
                    bindHost = it
                    settings.bindHost = it
                },
            )
        }
        GlassGroup(footer = if (t.zh) "修改端口、绑定地址或 token 后，重启服务生效。" else "Restart the service after changing port, bind address, or token.") {
            OutlinedTextField(
                value = accessToken,
                onValueChange = { accessToken = it; settings.accessToken = it },
                label = { Text(if (t.zh) "访问 token" else "Access token") },
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
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(if (t.zh) "重新生成" else "Regenerate", { accessToken = settings.resetAccessToken() })
                SecondaryActionButton(if (t.zh) "复制 token" else "Copy token") { copy(context, accessToken, t.copied) }
            }
        }
    }
}

@Composable
internal fun SettingsLimitsPage(t: UiText, settings: SettingsStore) {
    var defaultLimit by remember { mutableStateOf(settings.defaultLimit.toString()) }
    var stringLimit by remember { mutableStateOf(settings.stringLimit.toString()) }
    var disasmLimit by remember { mutableStateOf(settings.disasmLimit.toString()) }
    var disasmBytes by remember { mutableStateOf(settings.disasmMaxBytes.toString()) }
    var hexdumpBytes by remember { mutableStateOf(settings.hexdumpMaxBytes.toString()) }
    var maxRequestKb by remember { mutableStateOf(settings.maxRequestKb.toString()) }
    PageScroll {
        GlassGroup {
            NumberSettingRow(if (t.zh) "默认 limit" else "Default limit", defaultLimit, { defaultLimit = it }, { settings.defaultLimit = it }, if (t.zh) "条" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "字符串 limit" else "String limit", stringLimit, { stringLimit = it }, { settings.stringLimit = it }, if (t.zh) "条" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "反汇编指令数" else "Disasm instructions", disasmLimit, { disasmLimit = it }, { settings.disasmLimit = it }, if (t.zh) "条" else "insns")
            GroupDivider()
            NumberSettingRow(if (t.zh) "反汇编窗口" else "Disasm window", disasmBytes, { disasmBytes = it }, { settings.disasmMaxBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "Hexdump 读取量" else "Hexdump size", hexdumpBytes, { hexdumpBytes = it }, { settings.hexdumpMaxBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "请求上限" else "Request limit", maxRequestKb, { maxRequestKb = it }, { settings.maxRequestKb = it }, "KB")
        }
    }
}

@Composable
internal fun SettingsExportPage(t: UiText, settings: SettingsStore) {
    var conflictStrategy by remember { mutableStateOf(settings.outputConflictStrategy) }
    var writePatchReport by remember { mutableStateOf(settings.writePatchReport) }
    var buildCopyToWorkDir by remember { mutableStateOf(settings.buildCopyToWorkDir) }
    var maxPatchBytes by remember { mutableStateOf(settings.maxPatchBytes.toString()) }
    var maxBuildOutputs by remember { mutableStateOf(settings.maxBuildOutputs.toString()) }
    PageScroll {
        GlassGroup(title = if (t.zh) "文件名冲突" else "File conflict") {
            ChipRow(listOf("rename" to if (t.zh) "自动改名" else "Auto rename", "overwrite" to if (t.zh) "覆盖" else "Overwrite"), conflictStrategy) {
                conflictStrategy = it
                settings.outputConflictStrategy = it
            }
        }
        GlassGroup {
            ToggleRow(if (t.zh) "导出 patch report" else "Write patch report", writePatchReport) {
                writePatchReport = it
                settings.writePatchReport = it
            }
            GroupDivider()
            ToggleRow(if (t.zh) "构建后镜像到工作目录" else "Mirror build to work dir", buildCopyToWorkDir) {
                buildCopyToWorkDir = it
                settings.buildCopyToWorkDir = it
            }
            GroupDivider()
            NumberSettingRow(if (t.zh) "单 patch 上限" else "Max patch size", maxPatchBytes, { maxPatchBytes = it }, { settings.maxPatchBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "构建产物列表上限" else "Max build outputs", maxBuildOutputs, { maxBuildOutputs = it }, { settings.maxBuildOutputs = it }, if (t.zh) "项" else "items")
        }
    }
}

@Composable
internal fun SettingsProbePage(t: UiText, settings: SettingsStore) {
    var probeUrl by remember { mutableStateOf(settings.externalProbeUrl) }
    PageScroll {
        GlassGroup(footer = t.reachabilityHelp) {
            OutlinedTextField(
                value = probeUrl,
                onValueChange = { probeUrl = it; settings.externalProbeUrl = it },
                label = { Text(t.probeServiceUrl) },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            Text(t.externalProbeExample, modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun openBatterySettings(context: Context) {
    runCatching {
        context.startActivity(Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")))
    }.onFailure {
        context.startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }
}
