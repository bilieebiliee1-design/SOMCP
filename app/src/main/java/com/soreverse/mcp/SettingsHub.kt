package com.soreverse.mcp

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.GitHubRelease
import com.soreverse.mcp.core.GitHubUpdateManager
import com.soreverse.mcp.core.SettingsStore

private fun settingsTitle(t: UiText, dest: SettingsDest): String = when (dest) {
    SettingsDest.Root -> t.settings
    SettingsDest.ServiceConfig -> if (t.zh) "服务配置" else "Service Configuration"
    SettingsDest.Appearance -> if (t.zh) "外观与语言" else "Appearance"
    SettingsDest.KeepAlive -> t.keepAlive
    SettingsDest.Access -> if (t.zh) "MCP 访问控制" else "MCP Access"
    SettingsDest.Limits -> if (t.zh) "返回数量" else "Result Limits"
    SettingsDest.Export -> if (t.zh) "导出" else "Export"
    SettingsDest.Audit -> if (t.zh) "编辑校验与审计" else "Edit & Audit"
    SettingsDest.Blutter -> "Blutter"
    SettingsDest.Tunnel -> if (t.zh) "Cloudflare 隧道" else "Cloudflare Tunnel"
    SettingsDest.ApkBridge -> if (t.zh) "APK MCP 桥接" else "APK MCP Bridge"
    SettingsDest.AiDeep -> if (t.zh) "AI 深度分析" else "AI Deep Analysis"
    SettingsDest.Updates -> if (t.zh) "版本更新" else "Software Update"
    SettingsDest.Probe -> t.externalProbe
    SettingsDest.ToolStats -> if (t.zh) "工具调用审计" else "Tool Call Audit"
    SettingsDest.TunnelStats -> if (t.zh) "隧道稳定性" else "Tunnel Stability"
    SettingsDest.Instructions -> t.instructions
    SettingsDest.Credits -> if (t.zh) "开源致谢" else "Credits"
    SettingsDest.Disclaimer -> t.disclaimer
    SettingsDest.About -> t.about
}

@Composable
private fun SettingsTile(
    title: String,
    subtitle: String,
    icon: ImageVector,
    tint: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(18.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(tint.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(18.dp))
        }
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.titleSmall)
        Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
internal fun SettingsHub(
    modifier: Modifier = Modifier,
    backProgress: Float,
    t: UiText,
    settings: SettingsStore,
    updateManager: GitHubUpdateManager,
    availableRelease: GitHubRelease?,
    onRelease: (GitHubRelease?) -> Unit,
    language: String,
    onLanguage: (String) -> Unit,
    themeMode: String,
    onTheme: (String) -> Unit,
    accentColor: String,
    onAccent: (String) -> Unit,
    pureBlackDark: Boolean,
    onPureBlack: (Boolean) -> Unit,
    uiDensity: String,
    onDensity: (String) -> Unit,
    cornerStyle: String,
    onCorner: (String) -> Unit,
    motionMode: String,
    onMotion: (String) -> Unit,
    showAdvancedHome: Boolean,
    onShowAdvancedHome: (Boolean) -> Unit,
    highContrast: Boolean,
    onHighContrast: (Boolean) -> Unit,
    textScale: String,
    onTextScale: (String) -> Unit,
    predictiveBack: Boolean,
    onPredictiveBack: (Boolean) -> Unit,
    dest: SettingsDest,
    onDest: (SettingsDest) -> Unit,
    onBack: () -> Unit,
) {
    Box(modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            ScreenHeader(
                title = t.settings,
                subtitle = if (t.zh) "常用在前，极客选项更深一层" else "Common first, power options deeper",
            )
            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = LocalUiMetrics.current.pagePad)
                    .padding(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(if (t.zh) "常用" else "Essentials", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile(if (t.zh) "服务配置" else "Service", if (t.zh) "目录 / 端口 / 地址 / 工具" else "Directory / port / URLs / tools", Icons.Default.Settings, MaterialTheme.colorScheme.primary, { onDest(SettingsDest.ServiceConfig) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "外观" else "Look", if (t.zh) "主题 / 强调色 / 密度" else "Theme / accent / density", Icons.Default.Tune, AppPalette.indigo, { onDest(SettingsDest.Appearance) }, Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile(if (t.zh) "AI 深度分析" else "AI Deep", if (t.zh) "端点 / Key / 模型" else "Endpoint / key / model", Icons.Default.Memory, AppPalette.indigo, { onDest(SettingsDest.AiDeep) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "保活" else "Keep-alive", if (t.zh) "唤醒锁 / 自启" else "Wake lock / boot", Icons.Default.PowerSettingsNew, AppPalette.green, { onDest(SettingsDest.KeepAlive) }, Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile("APK MCP", if (t.zh) "MT 管理器协同" else "MT Manager bridge", Icons.Default.Link, AppPalette.orange, { onDest(SettingsDest.ApkBridge) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "隧道" else "Tunnel", if (t.zh) "公网暴露 / 保活" else "Public expose", Icons.Default.Cloud, AppPalette.purple, { onDest(SettingsDest.Tunnel) }, Modifier.weight(1f))
                }
                Text(if (t.zh) "引擎" else "Engine", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 4.dp))
                SurfacePanel {
                    NavRow(if (t.zh) "返回数量" else "Result limits", "limit / disasm / hexdump", Icons.Default.Analytics, onClick = { onDest(SettingsDest.Limits) })
                    GroupDivider()
                    NavRow(if (t.zh) "导出" else "Export", if (t.zh) "冲突策略与构建镜像" else "Conflict strategy", Icons.Default.Storage, onClick = { onDest(SettingsDest.Export) })
                    GroupDivider()
                    NavRow(if (t.zh) "编辑校验与审计" else "Edit & Audit", if (t.zh) "快照 / 并发 / 模拟" else "Snapshot / concurrency", Icons.Default.Security, onClick = { onDest(SettingsDest.Audit) })
                    GroupDivider()
                    NavRow("Blutter", if (t.zh) "Flutter 3.44 / Dart 3.12.2 / 完全离线" else "Flutter 3.44 / Dart 3.12.2 / fully offline", Icons.Default.Memory, onClick = { onDest(SettingsDest.Blutter) })
                }

                Text(if (t.zh) "诊断与关于" else "Diagnostics & about", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 4.dp))
                SurfacePanel {
                    NavRow(if (t.zh) "版本更新" else "Software update", if (t.zh) "GitHub Releases / 自动检查" else "GitHub Releases / automatic checks", Icons.Default.Info, trailing = availableRelease?.tag.orEmpty(), onClick = { onDest(SettingsDest.Updates) })
                    GroupDivider()
                    NavRow(if (t.zh) "工具调用审计" else "Tool audit", if (t.zh) "调用统计与失败率" else "Stats and failures", Icons.Default.Analytics, onClick = { onDest(SettingsDest.ToolStats) })
                    GroupDivider()
                    NavRow(if (t.zh) "隧道稳定性" else "Tunnel stability", if (t.zh) "重启与探查" else "Restart and probe", Icons.Default.Cloud, onClick = { onDest(SettingsDest.TunnelStats) })
                    GroupDivider()
                    NavRow(t.instructions, if (t.zh) "推荐工作流" else "Workflow", Icons.Default.Description, onClick = { onDest(SettingsDest.Instructions) })
                    GroupDivider()
                    NavRow(if (t.zh) "开源致谢" else "Credits", if (t.zh) "依赖与参考" else "Dependencies", Icons.Default.Build, onClick = { onDest(SettingsDest.Credits) })
                    GroupDivider()
                    NavRow(t.disclaimer, icon = Icons.Default.Info, onClick = { onDest(SettingsDest.Disclaimer) })
                    GroupDivider()
                    NavRow(t.about, icon = Icons.Default.Info, onClick = { onDest(SettingsDest.About) })
                }
            }
        }
        if (dest != SettingsDest.Root) {
    Surface(
        modifier = Modifier.fillMaxSize().graphicsLayer {
            translationX = size.width * backProgress
            alpha = 1f - 0.12f * backProgress
        },
        color = MaterialTheme.colorScheme.background,
    ) {
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = settingsTitle(t, dest),
            showBack = true,
            onBack = onBack,
        )
        Box(Modifier.fillMaxSize()) {
        when (dest) {
            SettingsDest.ServiceConfig -> SettingsServiceConfigPage(t, settings)
            SettingsDest.Appearance -> SettingsAppearancePage(t, language, onLanguage, themeMode, onTheme, accentColor, onAccent, pureBlackDark, onPureBlack, uiDensity, onDensity, cornerStyle, onCorner, motionMode, onMotion, showAdvancedHome, onShowAdvancedHome, highContrast, onHighContrast, textScale, onTextScale, predictiveBack, onPredictiveBack)
            SettingsDest.KeepAlive -> SettingsKeepAlivePage(t, settings)
            SettingsDest.Access -> SettingsAccessPage(t, settings)
            SettingsDest.Limits -> SettingsLimitsPage(t, settings)
            SettingsDest.Export -> SettingsExportPage(t, settings)
            SettingsDest.Audit -> SettingsAuditPage(t, settings)
            SettingsDest.Blutter -> SettingsBlutterPage(t)
            SettingsDest.Tunnel -> SettingsTunnelPage(t, settings)
            SettingsDest.ApkBridge -> SettingsApkBridgePage(t, settings)
            SettingsDest.AiDeep -> SettingsAiDeepPage(t, settings)
            SettingsDest.Updates -> SettingsUpdatesPage(t, settings, updateManager, availableRelease, onRelease)
            SettingsDest.Probe -> SettingsProbePage(t, settings)
            SettingsDest.ToolStats -> PageScroll { GlassGroup { Column(Modifier.padding(12.dp)) { ToolStatsSection(t, settings) } } }
            SettingsDest.TunnelStats -> PageScroll { GlassGroup { Column(Modifier.padding(12.dp)) { TunnelStatsSection(t) } } }
            SettingsDest.Instructions -> PageScroll {
                GlassGroup {
                    Text(t.instructionsBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        if (t.zh)
                            "详细流程：先在服务页启动 SO MCP；需要电脑访问时开启 Cloudflare Tunnel，或 adb forward tcp:8000 tcp:8000。客户端配置 /mcp 后按 so_open -> analyze_* -> read_disasm/search_* 分析；修改前 session_open，dryRun 预览后再 patch，最后 build_so 导出。"
                        else
                            "Start SO MCP on Service tab; enable Cloudflare Tunnel or adb forward for desktop access; then follow so_open -> analyze_* -> read/search -> session_open -> dryRun patch -> build_so.",
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            SettingsDest.Credits -> SettingsCreditsPage(t)
            SettingsDest.Disclaimer -> PageScroll { GlassGroup { Text(t.disclaimerBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium) } }
            SettingsDest.About -> {
                val aboutContext = LocalContext.current
                PageScroll {
                    GlassGroup {
                        Text(t.aboutBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium)
                        Row(Modifier.padding(14.dp)) {
                            PrimaryActionButton(t.joinQqGroup, { joinQqGroup(aboutContext, t.zh) }, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            }
            SettingsDest.Root -> Unit
        }
        }
    }
    }
    }
}
}
