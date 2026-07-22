package com.soreverse.mcp

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.delay
import org.json.JSONObject

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun MetricPill(label: String, value: String, color: Color) {
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.10f))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = color)
        Text(value, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun MetricProgressRow(label: String, value: String, progress: Float, color: Color, monospace: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default)
            Text(value, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.72f), fontFamily = FontFamily.Monospace)
        }
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { progress.coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(999.dp)),
            color = color,
            trackColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f),
        )
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
internal fun ToolStatsSection(t: UiText, settings: SettingsStore) {
    var refreshKey by remember { mutableStateOf(0) }
    var snapshot by remember(refreshKey) { mutableStateOf(com.soreverse.mcp.core.ToolStats.snapshot()) }
    val context = LocalContext.current
    LaunchedEffect(refreshKey, settings.collectToolStats) {
        if (settings.collectToolStats) {
            delay(50)
            snapshot = com.soreverse.mcp.core.ToolStats.snapshot()
        }
    }
    if (!settings.collectToolStats) {
        Text(if (t.zh) "工具调用统计已关闭，可在「编辑校验与审计」中开启。" else "Tool-call statistics are off. Enable in 'Edit validation and audit'.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        return
    }
    val totalCalls = snapshot.optLong("totalCalls", 0)
    val totalOk = snapshot.optLong("totalOk", 0)
    val totalFailed = snapshot.optLong("totalFailed", 0)
    val distinct = snapshot.optInt("distinctTools", 0)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        MetricPill(if (t.zh) "总调用" else "Calls", totalCalls.toString(), MaterialTheme.colorScheme.primary)
        MetricPill("OK", totalOk.toString(), AppleColors.systemGreen)
        MetricPill(if (t.zh) "失败" else "Failed", totalFailed.toString(), AppleColors.systemRed)
        MetricPill(if (t.zh) "工具" else "Tools", distinct.toString(), AppleColors.systemIndigo)
    }
    Spacer(Modifier.height(8.dp))
    val toolsArr = snapshot.optJSONArray("tools")
    val entries = (0 until (toolsArr?.length() ?: 0)).mapNotNull { i ->
        val obj = toolsArr?.optJSONObject(i) ?: return@mapNotNull null
        Triple(obj.optString("tool"), obj.optLong("calls"), obj.optLong("failed"))
    }.sortedByDescending { it.second }
    if (entries.isEmpty()) {
        Text(if (t.zh) "暂无工具调用记录。" else "No tool calls recorded yet.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f))
    } else {
        val maxCalls = entries.maxOf { it.second }.coerceAtLeast(1)
        entries.take(14).forEach { (name, calls, failed) ->
            MetricProgressRow(
                label = name,
                value = if (failed > 0) "$calls / $failed" else calls.toString(),
                progress = calls.toFloat() / maxCalls,
                color = if (failed > 0 && failed >= calls) AppleColors.systemRed else MaterialTheme.colorScheme.primary,
                monospace = true,
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryActionButton(if (t.zh) "刷新" else "Refresh") { refreshKey++; snapshot = com.soreverse.mcp.core.ToolStats.snapshot() }
        SecondaryActionButton(if (t.zh) "重置" else "Reset") {
            com.soreverse.mcp.core.ToolStats.reset()
            refreshKey++
            snapshot = com.soreverse.mcp.core.ToolStats.snapshot()
            Toast.makeText(context, if (t.zh) "统计已重置" else "Reset", Toast.LENGTH_SHORT).show()
        }
    }
}

@Composable
internal fun TunnelStatsSection(t: UiText) {
    var refreshKey by remember { mutableStateOf(0) }
    val context = LocalContext.current
    var stats by remember(refreshKey) { mutableStateOf(activeServer(context)?.tunnel?.tunnelStats() ?: JSONObject()) }
    LaunchedEffect(refreshKey) {
        while (true) {
            stats = activeServer(context)?.tunnel?.tunnelStats() ?: JSONObject()
            delay(2000)
        }
    }
    val totalRunningMs = stats.optLong("totalRunningMs", 0)
    val totalRestarts = stats.optInt("totalRestarts", 0)
    val keepaliveRestarts = stats.optInt("keepaliveRestarts", 0)
    val probeOks = stats.optInt("probeOks", 0)
    val probeFailures = stats.optInt("probeFailures", 0)
    val state = stats.optString("state", "STOPPED")
    val totalProbes = probeOks + probeFailures
    val lossRate = if (totalProbes > 0) (probeFailures.toFloat() / totalProbes * 1000).toInt() / 10f else 0f
    val keepaliveEnabled = stats.optBoolean("keepaliveEnabled")
    fun fmtDuration(ms: Long): String {
        val s = ms / 1000
        val h = s / 3600; val m = (s % 3600) / 60; val sec = s % 60
        return if (h > 0) "${h}h ${m}m ${sec}s" else if (m > 0) "${m}m ${sec}s" else "${sec}s"
    }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        MetricPill(if (t.zh) "状态" else "State", state, if (state == "RUNNING") AppleColors.systemGreen else AppleColors.systemOrange)
        MetricPill(if (t.zh) "运行" else "Uptime", fmtDuration(totalRunningMs), MaterialTheme.colorScheme.primary)
        MetricPill(if (t.zh) "保活" else "Keepalive", if (keepaliveEnabled) "ON" else "OFF", if (keepaliveEnabled) AppleColors.systemGreen else Color(0xFF8E8E93))
    }
    Spacer(Modifier.height(10.dp))
    val maxCount = maxOf(totalRestarts, keepaliveRestarts, probeOks, probeFailures, 1)
    MetricProgressRow(if (t.zh) "总重启" else "Total restarts", totalRestarts.toString(), totalRestarts.toFloat() / maxCount, AppleColors.systemOrange)
    MetricProgressRow(if (t.zh) "保活重启" else "Keepalive restarts", keepaliveRestarts.toString(), keepaliveRestarts.toFloat() / maxCount, AppleColors.systemRed)
    MetricProgressRow(if (t.zh) "探查成功" else "Probe OK", probeOks.toString(), probeOks.toFloat() / maxCount, AppleColors.systemGreen)
    MetricProgressRow(if (t.zh) "探查失败" else "Probe failed", probeFailures.toString(), probeFailures.toFloat() / maxCount, AppleColors.systemRed)
    Spacer(Modifier.height(6.dp))
    Text(if (t.zh) "探查失败率 ≈ ${lossRate}%  ($probeFailures / $totalProbes)" else "Probe failure rate ≈ ${lossRate}%  ($probeFailures / $totalProbes)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
    Spacer(Modifier.height(8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryActionButton(if (t.zh) "刷新" else "Refresh") { refreshKey++ }
        SecondaryActionButton(if (t.zh) "重置" else "Reset") {
            activeServer(context)?.tunnel?.resetTunnelStats()
            refreshKey++
            Toast.makeText(context, if (t.zh) "隧道统计已重置" else "Tunnel stats reset", Toast.LENGTH_SHORT).show()
        }
    }
}
