package com.soreverse.mcp

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.UpdateDownloadEvent

@Composable
internal fun UpdateDownloadStatus(
    phase: String,
    progress: Int,
    probeCompleted: Int,
    probeTotal: Int,
    probeAvailable: Int,
    selectedSource: String,
    probeResults: List<UpdateDownloadEvent.ProbeResult>,
    zh: Boolean,
    verifyNote: String = "",
    onPickSource: (String) -> Unit = {}
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (phase == "probing") {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Text(
                if (zh) "正在测速 $probeCompleted/$probeTotal · $probeAvailable 个可用（点选任一线路可手动切换）" else "Testing sources $probeCompleted/$probeTotal · $probeAvailable available (tap one to switch)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            probeResults.sortedWith(
                compareByDescending<UpdateDownloadEvent.ProbeResult> {
                    it.reachable
                }.thenBy { it.latencyMs }
            ).forEach { result ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(enabled = result.reachable) { onPickSource(result.source) },
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        result.source,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        if (result.reachable) {
                            "${result.latencyMs} ms"
                        } else if (zh) {
                            "不可用"
                        } else {
                            "Unavailable"
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = if (result.reachable) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    )
                }
            }
        } else {
            LinearProgressIndicator(progress = {
                progress / 100f
            }, modifier = Modifier.fillMaxWidth())
            Text(
                when (phase) {
                    "verifying" -> if (zh) "正在校验 SHA-256…" else "Verifying SHA-256…"
                    else -> "${if (selectedSource.isNotBlank()) "$selectedSource · " else ""}$progress%"
                },
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (phase == "downloading") {
                Text(
                    if (zh) "下载慢？点选下方线路可立即切换加速源" else "Slow? Tap a source below to switch mirror instantly",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                probeResults.sortedWith(
                    compareByDescending<UpdateDownloadEvent.ProbeResult> {
                        it.reachable
                    }.thenBy { it.latencyMs }
                ).forEach { result ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable(
                                enabled = result.reachable && result.source != selectedSource
                            ) {
                                onPickSource(result.source)
                            },
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            (if (result.source == selectedSource) "▶ " else "") + result.source,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            color = if (result.source ==
                                selectedSource
                            ) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurface
                            }
                        )
                        Text(
                            if (result.reachable) {
                                "${result.latencyMs} ms"
                            } else if (zh) {
                                "不可用"
                            } else {
                                "Unavailable"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = if (result.reachable) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
            if (verifyNote.isNotBlank()) {
                Text(
                    verifyNote,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
