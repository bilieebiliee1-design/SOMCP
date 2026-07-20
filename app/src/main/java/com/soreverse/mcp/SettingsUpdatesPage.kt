package com.soreverse.mcp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.GitHubRelease
import com.soreverse.mcp.core.GitHubUpdateManager
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.UpdateCheckResult
import com.soreverse.mcp.core.UpdateDownloadEvent
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.File

@Composable
internal fun SettingsUpdatesPage(
    t: UiText,
    settings: SettingsStore,
    manager: GitHubUpdateManager,
    initialRelease: GitHubRelease?,
    onRelease: (GitHubRelease?) -> Unit,
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
    var probeResults by remember { mutableStateOf<List<UpdateDownloadEvent.ProbeResult>>(emptyList()) }
    var downloadPhase by remember { mutableStateOf("") }
    var downloadJob by remember { mutableStateOf<Job?>(null) }
    var downloadedFile by remember { mutableStateOf<File?>(null) }
    var status by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    LaunchedEffect(release?.tag) {
        downloadedFile = null
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
                            status = if (t.zh) "发现新版本 ${result.release.tag}" else "Version ${result.release.tag} is available"
                        }
                        UpdateCheckResult.Current -> {
                            release = null
                            onRelease(null)
                            status = if (t.zh) "当前已是最新正式发行版" else "You are using the latest stable release"
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

    PageScroll {
        GlassGroup {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(if (t.zh) "GitHub 正式发行版" else "Official GitHub releases", style = MaterialTheme.typography.titleMedium, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                Text(
                    if (t.zh) "只检查 bilieebiliee1-design/SOMCP 的正式 Release。普通构建、提交、分支和标签均不会被视为更新。" else "Only stable releases from bilieebiliee1-design/SOMCP are checked. Builds, commits, branches and tags do not count as updates.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("${if (t.zh) "当前版本" else "Current version"}: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", style = MaterialTheme.typography.bodyMedium)
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
                Icons.Default.Info,
                onClick = ::checkUpdates,
            )
        }
        if (error.isNotBlank()) {
            Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(error, color = MaterialTheme.colorScheme.onErrorContainer, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
        release?.let { update ->
            GlassGroup {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(update.name, style = MaterialTheme.typography.titleMedium, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                    Text(update.tag, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                    if (update.notes.isNotBlank()) MarkdownMessageContent(update.notes, selectable = true)
                    if (downloading) {
                        UpdateDownloadStatus(downloadPhase, progress, probeCompleted, probeTotal, probeAvailable, selectedSource, probeResults, t.zh)
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
                                    status = if (t.zh) "请允许 SOMCP 安装未知应用，返回后再次点击安装。" else "Allow SOMCP to install unknown apps, then return and tap Install again."
                                }
                            } else if (!downloading) {
                                downloading = true
                                progress = 0
                                probeCompleted = 0
                                probeTotal = 0
                                probeAvailable = 0
                                probeResults = emptyList()
                                selectedSource = ""
                                downloadPhase = "probing"
                                error = ""
                                downloadJob = scope.launch {
                                    try {
                                        manager.download(update) { event ->
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
                                            }
                                        }
                                            .onSuccess {
                                                downloadedFile = it
                                                status = if (t.zh) "下载并校验完成，可以安装。" else "Download and verification complete. Ready to install."
                                            }
                                            .onFailure { error = it.message ?: if (t.zh) "下载失败" else "Download failed" }
                                    } finally {
                                        downloading = false
                                        downloadPhase = ""
                                        downloadJob = null
                                    }
                                }
                            } else {
                                downloadJob?.cancel()
                                status = if (t.zh) "下载已取消" else "Download cancelled"
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
