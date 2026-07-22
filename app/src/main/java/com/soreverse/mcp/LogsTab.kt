package com.soreverse.mcp

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.SettingsStore

@Composable
internal fun LogsTab(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var logPaused by remember { mutableStateOf(false) }
    var logFilter by remember { mutableStateOf("all") }
    var contentVersion by remember { mutableStateOf(0L) }
    val logs = remember { mutableStateListOf<String>().also { list -> list.addAll(AppLog.snapshot().takeLast(120)) } }

    DisposableEffect(Unit) {
        val cap = settings.logMaxLines
        val onLine: (String) -> Unit = { line ->
            if (line == "__CLEAR__") {
                logs.clear()
            } else {
                logs.add(line)
                while (logs.size > cap) logs.removeAt(0)
            }
            contentVersion++
        }
        AppLog.addListener(onLine)
        onDispose { AppLog.removeListener(onLine) }
    }

    val visibleLogs = logs
        .filter { line ->
            when (logFilter) {
                "E" -> " E " in line
                "W" -> " W " in line
                "I" -> " I " in line
                else -> true
            }
        }
        .takeLast(settings.logMaxLines)

    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = t.logs,
            subtitle = if (logPaused) (if (t.zh) "已暂停自动跟随 · 日志仍在缓存" else "Auto-follow paused · still buffering") else (if (t.zh) "实时跟随 · ${visibleLogs.size} 行" else "Live follow · ${visibleLogs.size} lines"),
        )
        Column(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = LocalUiMetrics.current.pagePad),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            ChipRow(
                listOf("all" to if (t.zh) "全部" else "All", "I" to if (t.zh) "信息" else "Info", "W" to if (t.zh) "警告" else "Warnings", "E" to if (t.zh) "错误" else "Errors"),
                logFilter,
                { logFilter = it },
            )
        }
        ModernLogPanel(
            lines = visibleLogs,
            zh = t.zh,
            autoFollow = !logPaused,
            contentVersion = contentVersion,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(top = 8.dp),
        )
        Row(
            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface.copy(alpha = 0.96f)).padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LogActionButton(if (logPaused) if (t.zh) "继续" else "Resume" else if (t.zh) "暂停" else "Pause", if (logPaused) Icons.Default.PlayArrow else Icons.Default.Pause, Modifier.weight(1f)) { logPaused = !logPaused }
            LogActionButton(if (t.zh) "清空" else "Clear", Icons.Default.Delete, Modifier.weight(1f)) { AppLog.clear(); logs.clear() }
            LogActionButton(if (t.zh) "复制结果" else "Copy results", Icons.Default.ContentCopy, Modifier.weight(1f)) { copy(context, visibleLogs.joinToString("\n") { localizeLogLine(it, t.zh) }, t.copied) }
        }
    }
}

@Composable
private fun LogActionButton(label: String, icon: ImageVector, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    Row(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

private data class LogLineUi(val time: String, val level: String, val message: String)

private fun parseLogLine(line: String, zh: Boolean): LogLineUi {
    val localized = localizeLogLine(line, zh)
    val match = Regex("^(\\d{2}:\\d{2}:\\d{2}\\.\\d{3})\\s+([IWE])\\s+(.*)$").find(localized)
    return if (match != null) {
        LogLineUi(match.groupValues[1], match.groupValues[2], match.groupValues[3])
    } else {
        LogLineUi("--:--:--.---", "I", localized)
    }
}

@Composable
private fun ModernLogPanel(lines: List<String>, zh: Boolean, autoFollow: Boolean, contentVersion: Long, modifier: Modifier = Modifier) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size, autoFollow, contentVersion) {
        if (autoFollow && lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    if (lines.isEmpty()) {
        Box(modifier, contentAlignment = Alignment.Center) {
            Text(if (zh) "暂无日志" else "No logs yet", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        return
    }
    LazyColumn(
        state = listState,
        modifier = modifier.background(MaterialTheme.colorScheme.surface.copy(alpha = 0.72f)),
        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
    ) {
        itemsIndexed(lines, key = { index, line -> "$index:$line" }) { index, raw ->
            val line = parseLogLine(raw, zh)
            val levelColor = when (line.level) {
                "E" -> MaterialTheme.colorScheme.error
                "W" -> statusWarning()
                else -> MaterialTheme.colorScheme.primary
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(if (index % 2 == 0) Color.Transparent else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.18f))
                    .padding(horizontal = 6.dp, vertical = 7.dp),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    (index + 1).toString().padStart(3, '0'),
                    modifier = Modifier.width(30.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.62f),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    line.level,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(levelColor.copy(alpha = 0.13f))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                    color = levelColor,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(line.time, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
                    Text(line.message, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

private fun localizeLogLine(line: String, zh: Boolean): String {
    if (!zh) return line
    return line
        .replace("SOMCP initialized", "SOMCP 已初始化")
        .replace("Work directory selected:", "已选择工作目录：")
        .replace("Ktor MCP server listening on", "MCP 服务器监听于")
        .replace("Ktor MCP server stopped", "MCP 服务器已停止")
        .replace("Foreground service destroyed", "前台服务已销毁")
        .replace("Floating window shown", "悬浮窗已显示")
        .replace("Tool failed", "工具调用失败")
        .replace("Tool call", "工具调用")
        .replace("Reachability", "可达性探测")
        .replace("Opened", "已打开")
        .replace("Closed", "已关闭")
        .replace("Built", "已构建")
}
