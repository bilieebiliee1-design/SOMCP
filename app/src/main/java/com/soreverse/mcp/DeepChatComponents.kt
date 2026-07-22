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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.soreverse.mcp.core.RikkaPart

@Composable
internal fun DeepChatMessageItem(message: DeepChatMessage, zh: Boolean) {
    if (message.role == DeepChatRole.USER) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Surface(
                modifier = Modifier.widthIn(max = 320.dp),
                shape = RoundedCornerShape(20.dp, 20.dp, 6.dp, 20.dp),
                color = MaterialTheme.colorScheme.primaryContainer,
            ) {
                Text(
                    message.text,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 11.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        return
    }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(
                Modifier.size(28.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text("AI", color = MaterialTheme.colorScheme.onPrimary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
            Text("SOMCP", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            if (message.streaming) CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
        }
        if (message.parts.isNotEmpty()) {
            DeepMessageParts(parts = message.parts, streaming = message.streaming, zh = zh)
        } else if (message.text.isNotBlank()) {
            MarkdownMessageContent(message.text, selectable = !message.streaming)
        } else if (message.streaming) {
            Text(if (zh) "正在分析并调用工具…" else "Analyzing and calling tools…", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
        }
        if (message.error.isNotBlank()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Icon(
                        Icons.Default.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.size(20.dp),
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            if (zh) "本次分析未完成" else "Analysis incomplete",
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            message.error,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun DeepMessageParts(parts: List<RikkaPart>, streaming: Boolean, zh: Boolean) {
    val groups = remember(parts) {
        buildList<List<RikkaPart>> {
            var process = mutableListOf<RikkaPart>()
            parts.forEach { part ->
                if (part is RikkaPart.Reasoning || part is RikkaPart.Tool) {
                    process += part
                } else {
                    if (process.isNotEmpty()) {
                        add(process)
                        process = mutableListOf()
                    }
                    add(listOf(part))
                }
            }
            if (process.isNotEmpty()) add(process)
        }
    }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        groups.forEachIndexed { index, group ->
            if (group.firstOrNull() is RikkaPart.Text) {
                MarkdownMessageContent((group.first() as RikkaPart.Text).text, selectable = !streaming)
            } else {
                DeepProcessTimeline(group, streaming && index == groups.lastIndex, zh)
            }
        }
    }
}

@Composable
internal fun DeepProcessTimeline(parts: List<RikkaPart>, streaming: Boolean, zh: Boolean) {
    var expanded by remember(parts.firstOrNull()) { mutableStateOf(streaming) }
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
    ) {
        Row(
            Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                if (streaming) (if (zh) "正在思考" else "Thinking") else (if (zh) "思考过程" else "Thought process"),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(if (expanded) "−" else "+", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (expanded) {
            Column(Modifier.padding(start = 14.dp, end = 12.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                parts.forEach { part ->
                    when (part) {
                        is RikkaPart.Reasoning -> RikkaMarkdown(part.text, Modifier.fillMaxWidth())
                        is RikkaPart.Tool -> {
                            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(
                                    "● ${part.name}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (part.result == null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    if (part.result == null) (if (zh) "调用中" else "Running") else (if (zh) "已完成" else "Completed"),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        is RikkaPart.Text -> Unit
                    }
                }
            }
        }
    }
}

@Composable
internal fun MarkdownMessageContent(markdown: String, selectable: Boolean) {
    RikkaMarkdown(content = markdown, modifier = Modifier.fillMaxWidth(), selectable = selectable)
}
