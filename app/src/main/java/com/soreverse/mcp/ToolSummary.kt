package com.soreverse.mcp

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.mcp.ToolCatalog

@Composable
internal fun ToolSummary(t: UiText, apkTools: List<String> = emptyList()) {
    val groups = toolGroups(t, apkTools)
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            "${if (t.zh) "共计" else "Total"} ${groups.sumOf { it.items.size }} ${if (t.zh) "个工具" else "tools"}",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold,
        )
        groups.forEach { (cat, color, items) ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(color.copy(alpha = 0.10f))
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(color))
                    Text(cat, style = MaterialTheme.typography.labelLarge, color = color, fontWeight = FontWeight.SemiBold)
                }
                items.forEach { (name, desc) ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(name, modifier = Modifier.weight(0.9f), style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurface)
                        Text(desc, modifier = Modifier.weight(1.1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

private data class ToolGroup(val category: String, val color: Color, val items: List<Pair<String, String>>)

private val groupColor: Map<String, Color> = mapOf(
    "workspace" to AppleColors.systemGreen,
    "analyze" to AppleColors.systemOrange,
    "search" to AppleColors.systemTeal,
    "read" to AppleColors.systemIndigo,
    "edit" to AppleColors.systemRed,
    "emulate" to AppleColors.systemPurple,
    "diff" to AppleColors.systemBlue,
    "session" to AppleColors.systemOrange,
    "build" to AppleColors.systemPurple,
    "system" to AppleColors.systemTeal,
    "meta" to AppleColors.systemBlue,
    "apk-bridge" to Color(0xFF8E8E93),
)

private fun toolGroups(t: UiText, apkTools: List<String> = emptyList()): List<ToolGroup> {
    val zh = t.zh
    val reg = ToolCatalog.grouped(zh, apkTools).toMap()
    val catLabels = ToolCatalog.categoryDescriptions(zh).toMap()
    return ToolCatalog.categoryDescriptions(zh).map { (cat, _) ->
        val label = catLabels[cat] ?: cat
        val items = reg[cat].orEmpty()
        if (items.isEmpty()) null else ToolGroup(label, groupColor[cat] ?: Color(0xFF8E8E93), items)
    }.filterNotNull()
}
