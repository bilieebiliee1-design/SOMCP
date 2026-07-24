package com.soreverse.mcp

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.BackupManager
import com.soreverse.mcp.core.BackupPrefs
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun SettingsBackupRestorePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val backupPrefs = remember { BackupPrefs(context) }

    var includeSecrets by remember { mutableStateOf(backupPrefs.includeSecrets) }
    var importSecrets by remember { mutableStateOf(true) }
    var status by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    var remoteType by remember { mutableStateOf(backupPrefs.remoteType) }
    // WebDAV
    var webdavUrl by remember { mutableStateOf(backupPrefs.webdavUrl) }
    var webdavUser by remember { mutableStateOf(backupPrefs.webdavUser) }
    var webdavPassword by remember { mutableStateOf(backupPrefs.webdavPassword) }
    // S3
    var s3Endpoint by remember { mutableStateOf(backupPrefs.s3Endpoint) }
    var s3Region by remember { mutableStateOf(backupPrefs.s3Region) }
    var s3Bucket by remember { mutableStateOf(backupPrefs.s3Bucket) }
    var s3AccessKey by remember { mutableStateOf(backupPrefs.s3AccessKey) }
    var s3SecretKey by remember { mutableStateOf(backupPrefs.s3SecretKey) }
    var s3Prefix by remember { mutableStateOf(backupPrefs.s3Prefix) }

    fun setStatus(msg: String) { status = msg }

    // ---- Local export via SAF create-document ----
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val envelope = BackupManager.build(context, settings, includeSecrets)
            val bytes = BackupManager.serialize(envelope)
            context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                ?: error("cannot open output stream")
            bytes.size
        }.onSuccess { size ->
            setStatus(if (t.zh) "已导出配置（$size 字节，${secretLabel(t, includeSecrets)}）" else "Exported ($size bytes, ${secretLabel(t, includeSecrets)})")
        }.onFailure {
            setStatus((if (t.zh) "导出失败：" else "Export failed: ") + (it.message ?: it.toString()))
        }
    }

    // ---- Local import via SAF open-document ----
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("cannot open input stream")
            val envelope = BackupManager.parse(bytes)
            val result = BackupManager.restore(settings, envelope, importSecrets)
            result.optInt("changedCount")
        }.onSuccess { changed ->
            setStatus(
                if (t.zh) "已导入 $changed 项设置，重启应用后全部生效" else "Imported $changed keys; restart the app to fully apply",
            )
        }.onFailure {
            setStatus((if (t.zh) "导入失败：" else "Import failed: ") + (it.message ?: it.toString()))
        }
    }

    fun persistRemote() {
        backupPrefs.remoteType = remoteType
        backupPrefs.webdavUrl = webdavUrl
        backupPrefs.webdavUser = webdavUser
        backupPrefs.webdavPassword = webdavPassword
        backupPrefs.s3Endpoint = s3Endpoint
        backupPrefs.s3Region = s3Region
        backupPrefs.s3Bucket = s3Bucket
        backupPrefs.s3AccessKey = s3AccessKey
        backupPrefs.s3SecretKey = s3SecretKey
        backupPrefs.s3Prefix = s3Prefix
    }

    fun remoteUpload() {
        persistRemote()
        busy = true
        setStatus(if (t.zh) "正在上传…" else "Uploading…")
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val envelope = BackupManager.build(context, settings, includeSecrets)
                    val bytes = BackupManager.serialize(envelope)
                    val fileName = BackupManager.suggestedFileName()
                    when (remoteType) {
                        "webdav" -> BackupManager.webdavUpload(webdavUrl, webdavUser, webdavPassword, fileName, bytes)
                        "s3" -> BackupManager.s3Upload(s3ConfigOf(s3Endpoint, s3Region, s3Bucket, s3AccessKey, s3SecretKey, s3Prefix), fileName, bytes)
                        else -> error("no remote selected")
                    }
                    fileName
                }
            }
            busy = false
            outcome.onSuccess { setStatus((if (t.zh) "已上传：" else "Uploaded: ") + it) }
                .onFailure { setStatus((if (t.zh) "上传失败：" else "Upload failed: ") + (it.message ?: it.toString())) }
        }
    }

    fun remoteDownload(fileName: String) {
        persistRemote()
        if (fileName.isBlank()) {
            setStatus(if (t.zh) "请先填写要恢复的远程文件名" else "Enter the remote file name to restore")
            return
        }
        busy = true
        setStatus(if (t.zh) "正在下载…" else "Downloading…")
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = when (remoteType) {
                        "webdav" -> BackupManager.webdavDownload(webdavUrl, webdavUser, webdavPassword, fileName)
                        "s3" -> BackupManager.s3Download(s3ConfigOf(s3Endpoint, s3Region, s3Bucket, s3AccessKey, s3SecretKey, s3Prefix), fileName)
                        else -> error("no remote selected")
                    }
                    val envelope = BackupManager.parse(bytes)
                    BackupManager.restore(settings, envelope, importSecrets).optInt("changedCount")
                }
            }
            busy = false
            outcome.onSuccess { setStatus(if (t.zh) "已从远程恢复 $it 项设置，重启应用后全部生效" else "Restored $it keys from remote; restart to fully apply") }
                .onFailure { setStatus((if (t.zh) "下载失败：" else "Download failed: ") + (it.message ?: it.toString())) }
        }
    }

    var remoteFileToRestore by remember { mutableStateOf("") }

    PageScroll {
        // ---- Local backup ----
        GlassGroup(
            title = if (t.zh) "本地备份" else "Local backup",
            footer = if (t.zh)
                "导出为可移植的 JSON 配置快照，可通过系统文件选择器保存到任意位置。导入后重启应用以完全生效。"
            else
                "Export a portable JSON config snapshot to any location via the system file picker. Restart the app after import to fully apply.",
        ) {
            ToggleRow(
                if (t.zh) "包含密钥（token / key）" else "Include secrets (token / key)",
                includeSecrets,
            ) {
                includeSecrets = it
                backupPrefs.includeSecrets = it
            }
            GroupDivider()
            Text(
                if (t.zh)
                    "默认脱敏：token、访问密钥等敏感字段以 **** 形式导出，不会泄露。勾选后才会写入真实密钥，请妥善保管备份文件。"
                else
                    "Masked by default: tokens and keys are exported as **** and never leak. Only when ticked are real secrets written — keep such a backup safe.",
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            ToggleRow(
                if (t.zh) "导入时恢复备份内的密钥" else "Restore secrets contained in backup",
                importSecrets,
            ) { importSecrets = it }
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(14.dp),
            ) {
                PrimaryActionButton(
                    if (t.zh) "导出配置" else "Export config",
                    { exportLauncher.launch(BackupManager.suggestedFileName()) },
                )
                SecondaryActionButton(if (t.zh) "导入配置" else "Import config") {
                    importLauncher.launch(arrayOf("application/json", "text/*", "*/*"))
                }
            }
        }

        // ---- Remote backup (optional) ----
        GlassGroup(
            title = if (t.zh) "远程备份（可选）" else "Remote backup (optional)",
            footer = if (t.zh)
                "选择远程后，上传会以带时间戳的文件名保存快照；恢复时填写要拉取的远程文件名。凭据仅保存在本机。"
            else
                "Uploads store a timestamped snapshot; to restore, enter the remote file name to pull. Credentials stay on-device only.",
        ) {
            ChipRow(
                listOf(
                    "none" to (if (t.zh) "关闭" else "Off"),
                    "webdav" to "WebDAV",
                    "s3" to "S3",
                ),
                remoteType,
            ) {
                remoteType = it
                backupPrefs.remoteType = it
            }

            when (remoteType) {
                "webdav" -> {
                    BackupField(t, if (t.zh) "WebDAV 目录 URL" else "WebDAV base URL", webdavUrl) { webdavUrl = it }
                    BackupField(t, if (t.zh) "用户名" else "Username", webdavUser) { webdavUser = it }
                    BackupField(t, if (t.zh) "密码" else "Password", webdavPassword, secret = true) { webdavPassword = it }
                }
                "s3" -> {
                    BackupField(t, if (t.zh) "Endpoint" else "Endpoint", s3Endpoint) { s3Endpoint = it }
                    BackupField(t, "Region", s3Region) { s3Region = it }
                    BackupField(t, "Bucket", s3Bucket) { s3Bucket = it }
                    BackupField(t, "Access Key", s3AccessKey) { s3AccessKey = it }
                    BackupField(t, "Secret Key", s3SecretKey, secret = true) { s3SecretKey = it }
                    BackupField(t, if (t.zh) "路径前缀（可选）" else "Key prefix (optional)", s3Prefix) { s3Prefix = it }
                }
            }

            if (remoteType != "none") {
                BackupField(
                    t,
                    if (t.zh) "恢复的远程文件名" else "Remote file to restore",
                    remoteFileToRestore,
                    placeholder = "somcp-backup-….json",
                ) { remoteFileToRestore = it }
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(14.dp),
                ) {
                    PrimaryActionButton(if (t.zh) "上传到远程" else "Upload", { if (!busy) remoteUpload() })
                    SecondaryActionButton(if (t.zh) "从远程恢复" else "Restore from remote") { if (!busy) remoteDownload(remoteFileToRestore.trim()) }
                }
            }
        }

        if (status.isNotBlank()) {
            GlassGroup(title = if (t.zh) "状态" else "Status") {
                Text(
                    status,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

private fun s3ConfigOf(
    endpoint: String,
    region: String,
    bucket: String,
    accessKey: String,
    secretKey: String,
    prefix: String,
) = BackupManager.S3Config(
    endpoint = endpoint.trim(),
    region = region.trim().ifBlank { "us-east-1" },
    bucket = bucket.trim(),
    accessKey = accessKey.trim(),
    secretKey = secretKey.trim(),
    prefix = prefix.trim(),
)

private fun secretLabel(t: UiText, includeSecrets: Boolean): String = when {
    includeSecrets && t.zh -> "含密钥"
    includeSecrets -> "with secrets"
    t.zh -> "已脱敏"
    else -> "masked"
}

@Composable
private fun BackupField(
    t: UiText,
    label: String,
    value: String,
    secret: Boolean = false,
    placeholder: String = "",
    onValue: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValue,
        label = { Text(label) },
        placeholder = if (placeholder.isBlank()) null else ({ Text(placeholder) }),
        singleLine = true,
        visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
        shape = RoundedCornerShape(12.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = MaterialTheme.colorScheme.primary,
            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
            focusedContainerColor = Color.Transparent,
            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
        ),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 6.dp),
    )
}
