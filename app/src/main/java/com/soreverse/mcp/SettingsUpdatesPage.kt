// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
package com.soreverse.mcp

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RocketLaunch
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.GitHubRelease
import com.soreverse.mcp.core.GitHubUpdateManager
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.UpdateCheckResult
import com.soreverse.mcp.core.UpdateDownloadEvent
import java.io.File
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
internal fun SettingsUpdatesPage(
    t: UiText,
    settings: SettingsStore,
    manager: GitHubUpdateManager,
    initialRelease: GitHubRelease?,
    onRelease: (GitHubRelease?) -> Unit
) {
    val scope = rememberCoroutineScope()
    var autoCheck by remember { mutableStateOf(settings.autoCheckUpdates) }
    var release by remember(initialRelease) { mutableStateOf(initialRelease) }
    var checking by remember { mutableStateOf(false) }
    var downloading by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var probeCompleted by remember { mutableStateOf(0) }
    var probeTotal by remember { mutableStateOf(0) }
    var probeAvailable by remember { mutableStateOf(0) }
    var selectedSource by remember { mutableStateOf("") }
    var probeResults by remember {
        mutableStateOf<List<UpdateDownloadEvent.ProbeResult>>(emptyList())
    }
    var downloadPhase by remember { mutableStateOf("") }
    var downloadJob by remember { mutableStateOf<Job?>(null) }
    var downloadedFile by remember { mutableStateOf<File?>(null) }
    var verifyNote by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var channel by remember { mutableStateOf("stable") }

    LaunchedEffect(release?.tag) {
        downloadedFile = release?.let(manager::cachedDownload)
        if (!downloading) {
            progress = 0
            probeCompleted = 0
            probeTotal = 0
            probeAvailable = 0
            probeResults = emptyList()
            selectedSource = ""
            downloadPhase = ""
        }
    }

    fun checkUpdates() {
        if (checking) return
        checking = true
        error = ""
        status = if (t.zh) "正在检查 GitHub Releases…" else "Checking GitHub Releases…"
        scope.launch {
            manager.check()
                .onSuccess { result ->
                    when (result) {
                        is UpdateCheckResult.Available -> {
                            release = result.release
                            onRelease(result.release)
                            status =
                                if (t.zh) "发现新版本 ${result.release.tag}" else "Version ${result.release.tag} is available"
                        }

                        UpdateCheckResult.Current -> {
                            release = null
                            onRelease(null)
                            status =
                                if (t.zh) "当前已是最新正式发行版" else "You are using the latest stable release"
                        }
                    }
                }
                .onFailure {
                    error = it.message ?: if (t.zh) "检查更新失败" else "Update check failed"
                    status = ""
                }
            checking = false
        }
    }

    fun startDownload(update: GitHubRelease, forced: String?) {
        downloadJob?.cancel()
        downloading = true
        status = ""
        progress = 0
        if (forced == null) {
            probeCompleted = 0
            probeTotal = 0
            probeAvailable = 0
            probeResults = emptyList()
        }
        selectedSource = forced ?: ""
        verifyNote = ""
        downloadPhase = if (forced != null) "downloading" else "probing"
        error = ""
        downloadJob = scope.launch {
            try {
                manager.download(update, forced) { event ->
                    when (event) {
                        is UpdateDownloadEvent.Probing -> {
                            downloadPhase = "probing"
                            probeTotal = event.total
                        }

                        is UpdateDownloadEvent.ProbeResult -> {
                            probeCompleted = event.completed
                            if (event.reachable) probeAvailable++
                            probeResults = probeResults + event
                        }

                        is UpdateDownloadEvent.Selected -> {
                            downloadPhase = "downloading"
                            selectedSource = event.source
                            progress = 0
                        }

                        is UpdateDownloadEvent.Downloading -> {
                            downloadPhase = "downloading"
                            selectedSource = event.source
                            progress = event.percent
                        }

                        UpdateDownloadEvent.Verifying -> downloadPhase = "verifying"

                        is UpdateDownloadEvent.VerifySkipped -> {
                            verifyNote =
                                if (t.zh) {
                                    "已跳过 SHA-256 校验（${event.reason}），文件为有效 APK，可安装。"
                                } else {
                                    "SHA-256 check skipped (${event.reason}); file is a valid APK and installable."
                                }
                        }
                    }
                }
                    .onSuccess {
                        downloadedFile = it
                        status = if (verifyNote.isNotBlank()) {
                            if (t.zh) "下载完成（未校验 SHA-256），可以安装。" else "Download complete (SHA-256 not verified). Ready to install."
                        } else {
                            if (t.zh) "下载并校验完成，可以安装。" else "Download and verification complete. Ready to install."
                        }
                    }
                    .onFailure { error = it.message ?: if (t.zh) "下载失败" else "Download failed" }
            } finally {
                downloading = false
                downloadPhase = ""
                downloadJob = null
            }
        }
    }

    val isBeta = channel == "beta"
    val accent = MaterialTheme.colorScheme.primary
    val available = release != null
    val heroIcon: ImageVector = when {
        isBeta -> Icons.Default.Science
        available -> Icons.Default.RocketLaunch
        else -> Icons.Default.Verified
    }
    val headline = when {
        checking -> if (t.zh) "正在检查更新…" else "Checking for updates…"
        available -> if (t.zh) "发现新版本" else "New update available"
        isBeta -> if (t.zh) "测试版通道" else "Beta channel"
        else -> if (t.zh) "已是最新版本" else "You're up to date"
    }
    val subtitle = when {
        checking -> if (t.zh) "正在查询 GitHub Releases…" else "Querying GitHub Releases…"
        available -> release?.name?.ifBlank {
            if (t.zh) "体验最新的实验性功能与架构优化" else "Experience the latest experimental features"
        } ?: ""
        isBeta -> if (t.zh) {
            "测试版通道暂未开放，请切换到正式版通道检查发行版。"
        } else {
            "The beta channel is not available yet; switch to the stable channel."
        }
        else -> if (t.zh) {
            "您的 SOMCP 客户端当前已更新至最新稳定版，无需进行更新操作。"
        } else {
            "Your SOMCP client is already on the latest stable version."
        }
    }
    val tagLower = release?.tag?.lowercase().orEmpty()
    val versionBadge = when {
        isBeta -> if (t.zh) "测试版" else "BETA"
        listOf("beta", "alpha", "rc", "pre", "snapshot").any { it in tagLower } -> "BETA"
        else -> null
    }
    val versionText = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"

    PageScroll {
        // Channel pill (正式版 / 测试版)
        ChannelSegmentsPill(
            selected = channel,
            onSelect = { channel = it },
            zh = t.zh
        )
        // Hero: glowing app icon + dynamic state headline
        UpdateHero(
            icon = heroIcon,
            headline = headline,
            subtitle = subtitle,
            tint = if (isBeta) MaterialTheme.colorScheme.tertiary else accent
        )
        // Current-version "power card"
        UpdateVersionCard(
            versionText = versionText,
            badge = versionBadge,
            accent = accent,
            zh = t.zh
        )
        // Update source + auto-check controls
        GlassGroup {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    if (t.zh) "GitHub 正式发行版" else "Official GitHub releases",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
                )
                Text(
                    if (t.zh) {
                        "只检查 bilieebiliee1-design/SOMCP 的正式 Release。普通构建、提交、分支和标签均不会被视为更新。"
                    } else {
                        "Only stable releases from bilieebiliee1-design/SOMCP are checked. Builds, commits, branches and tags do not count as updates."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            GroupDivider()
            ToggleRow(if (t.zh) "启动时自动检查" else "Check automatically at startup", autoCheck) {
                autoCheck = it
                settings.autoCheckUpdates = it
            }
            GroupDivider()
            NavRow(
                if (checking) (if (t.zh) "正在检查…" else "Checking…") else (if (t.zh) "立即检查更新" else "Check now"),
                status,
                Icons.Default.Refresh,
                onClick = ::checkUpdates
            )
        }
        if (error.isNotBlank()) {
            Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    error,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
        release?.let { update ->
            GlassGroup(title = if (t.zh) "更新日志" else "Changelog") {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            update.name,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
                        )
                        Spacer(Modifier.weight(1f))
                        Box(
                            Modifier
                                .clip(RoundedCornerShape(999.dp))
                                .background(accent.copy(alpha = 0.16f))
                                .border(
                                    BorderStroke(1.dp, accent.copy(alpha = 0.3f)),
                                    RoundedCornerShape(999.dp)
                                )
                                .padding(horizontal = 9.dp, vertical = 3.dp)
                        ) {
                            Text(
                                update.tag,
                                style = MaterialTheme.typography.labelSmall,
                                color = accent,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                    if (update.notes.isNotBlank()) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            IconSmall(Icons.Default.History, MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                if (t.zh) "更新内容" else "What's new",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        MarkdownMessageContent(
                            update.notes,
                            selectable = true
                        )
                    }
                    if (downloading) {
                        UpdateDownloadStatus(
                            downloadPhase, progress, probeCompleted, probeTotal, probeAvailable, selectedSource, probeResults, t.zh,
                            verifyNote = verifyNote,
                            onPickSource = { source -> startDownload(update, source) }
                        )
                    } else if (verifyNote.isNotBlank() && downloadedFile != null) {
                        Text(
                            verifyNote,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    PrimaryActionButton(
                        text = when {
                            downloadedFile != null -> if (t.zh) "安装更新" else "Install update"
                            downloading -> if (t.zh) "取消下载" else "Cancel download"
                            else -> if (t.zh) "下载 APK" else "Download APK"
                        },
                        onClick = {
                            val file = downloadedFile
                            if (file != null) {
                                if (!manager.install(file)) {
                                    status =
                                        if (t.zh) "请允许 SOMCP 安装未知应用，返回后再次点击安装。" else "Allow SOMCP to install unknown apps, then return and tap Install again."
                                }
                            } else if (!downloading) {
                                startDownload(update, null)
                            } else {
                                downloadJob?.cancel()
                                downloadJob = null
                                downloading = false
                                downloadPhase = ""
                                status = if (t.zh) "下载已取消" else "Download cancelled"
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (status.isNotBlank()) {
                        Text(
                            status,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun IconSmall(imageVector: ImageVector, tint: Color) {
    androidx.compose.material3.Icon(
        imageVector,
        null,
        tint = tint,
        modifier = Modifier.size(16.dp)
    )
}

@Composable
private fun ChannelSegmentsPill(selected: String, onSelect: (String) -> Unit, zh: Boolean) {
    val options = listOf(
        "stable" to (if (zh) "正式版" else "Stable"),
        "beta" to (if (zh) "测试版" else "Beta")
    )
    val shape = RoundedCornerShape(999.dp)
    Row(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.72f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), shape)
            .padding(3.dp)
    ) {
        options.forEach { (key, label) ->
            val active = selected == key
            Text(
                label,
                Modifier
                    .weight(1f)
                    .clip(shape)
                    .background(if (active) MaterialTheme.colorScheme.surfaceVariant else Color.Transparent)
                    .clickable { onSelect(key) }
                    .padding(vertical = 9.dp),
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodyMedium,
                color = if (active) {
                    MaterialTheme.colorScheme.onSurface
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                fontWeight = if (active) FontWeight.SemiBold else FontWeight.Medium
            )
        }
    }
}

@Composable
private fun UpdateHero(icon: ImageVector, headline: String, subtitle: String, tint: Color) {
    Column(
        Modifier.fillMaxWidth().padding(top = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.padding(bottom = 20.dp)
        ) {
            // Glowing halo
            Box(
                Modifier
                    .size(104.dp)
                    .background(tint.copy(alpha = 0.30f), CircleShape)
                    .blur(30.dp)
            )
            // Icon tile
            Box(
                Modifier
                    .size(84.dp)
                    .clip(CircleShape)
                    .background(Brush.verticalGradient(listOf(Color(0xFF1D2027), Color(0xFF14161C))))
                    .border(BorderStroke(1.dp, tint.copy(alpha = 0.35f)), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                androidx.compose.material3.Icon(
                    icon,
                    null,
                    tint = tint,
                    modifier = Modifier.size(42.dp)
                )
            }
        }
        Text(
            headline,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(10.dp))
        Text(
            subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun UpdateVersionCard(versionText: String, badge: String?, accent: Color, zh: Boolean) {
    val shape = RoundedCornerShape(26.dp)
    val bg = Brush.verticalGradient(listOf(Color(0xFF1E2026), Color(0xFF15171D)))
    Row(
        Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(bg)
            .border(BorderStroke(1.dp, Color.White.copy(alpha = 0.08f)), shape)
            .padding(horizontal = 18.dp, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            Modifier.weight(1f),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(accent.copy(alpha = 0.14f)),
                contentAlignment = Alignment.Center
            ) {
                androidx.compose.material3.Icon(
                    Icons.Default.Terminal,
                    null,
                    tint = accent,
                    modifier = Modifier.size(22.dp)
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    if (zh) "当前版本" else "Current version",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFF9AA0AF)
                )
                Text(
                    versionText,
                    style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    fontWeight = FontWeight.SemiBold,
                    color = Color.White
                )
            }
        }
        if (badge != null) {
            Box(
                Modifier
                    .clip(RoundedCornerShape(999.dp))
                    .background(accent.copy(alpha = 0.18f))
                    .border(BorderStroke(1.dp, accent.copy(alpha = 0.34f)), RoundedCornerShape(999.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp)
            ) {
                Text(
                    badge,
                    style = MaterialTheme.typography.labelSmall,
                    color = accent,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}