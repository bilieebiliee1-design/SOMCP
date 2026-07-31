package com.soreverse.mcp

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

@Composable
internal fun SettingsBackupRestorePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = androidx.compose.material3.SnackbarHostState()
    var exportResult by remember { mutableStateOf<String?>(null) }
    var importResult by remember { mutableStateOf<String?>(null) }

    // Include secrets toggle
    var includeSecrets by remember { mutableStateOf(false) }

    // Remote provider
    var remoteProvider by remember { mutableStateOf(settings.remoteBackupProvider) }

    // WebDAV fields
    var webdavUrl by remember { mutableStateOf(settings.webdavUrl) }
    var webdavUsername by remember { mutableStateOf(settings.webdavUsername) }
    var webdavPassword by remember { mutableStateOf("") }

    // S3 fields
    var s3Endpoint by remember { mutableStateOf(settings.s3Endpoint) }
    var s3Bucket by remember { mutableStateOf(settings.s3Bucket) }
    var s3Region by remember { mutableStateOf(settings.s3Region) }
    var s3AccessKey by remember { mutableStateOf("") }
    var s3SecretKey by remember { mutableStateOf("") }

    // Export file picker (creates a new file)
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            exportResult = try {
                val json = settings.toJsonString(maskSecrets = !includeSecrets)
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(json.toByteArray(Charsets.UTF_8))
                    }
                }
                t.backupExportSuccess
            } catch (e: Exception) {
                e.message ?: "Export failed"
            }
        }
    }

    // Import file picker (reads an existing file)
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            importResult = try {
                val json = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        BufferedReader(InputStreamReader(input)).readText()
                    } ?: throw IllegalStateException("Cannot read file")
                }
                val result = settings.fromJsonString(json, allowSecrets = includeSecrets)
                if (result.optBoolean("ok", false)) {
                    t.backupImportSuccess
                } else {
                    t.backupImportError
                }
            } catch (e: Exception) {
                "${t.backupImportError}: ${e.message}"
            }
        }
    }

    androidx.compose.material3.Scaffold(
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbar) }
    ) { pad ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp)
                .padding(bottom = 12.dp),
            verticalArrangement = Arrangement.spacedBy(LocalUiMetrics.current.sectionGap),
        ) {
            // ---- Local backup ----
            GlassGroup(title = t.backupLocal) {
                // Include secrets toggle
                ToggleRow(t.backupIncludeSecrets, includeSecrets) { includeSecrets = it }
                GroupDivider()
                Text(
                    t.backupSecretsMasked,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                GroupDivider()
                Row(
                    Modifier.fillMaxWidth().padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    PrimaryActionButton(
                        text = t.backupExport,
                        onClick = { exportLauncher.launch("somcp_settings_backup.json") },
                        modifier = Modifier.weight(1f),
                    )
                    SecondaryActionButton(
                        text = t.backupImport,
                        onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            // Result feedback
            if (exportResult != null) {
                GlassGroup {
                    Text(
                        exportResult!!,
                        modifier = Modifier.padding(14.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (exportResult == t.backupExportSuccess || exportResult == t.backupImportSuccess)
                            MaterialTheme.colorScheme.primary
                        else
                            MaterialTheme.colorScheme.error,
                    )
                }
            }

            // ---- Remote backup ----
            GlassGroup(title = t.backupRemote) {
                // Provider selector
                ChipRow(
                    listOf(
                        "webdav" to "WebDAV",
                        "s3" to "S3",
                    ),
                    remoteProvider,
                ) {
                    remoteProvider = it
                    settings.remoteBackupProvider = it
                }

                if (remoteProvider == "webdav") {
                    OutlinedTextField(
                        value = webdavUrl,
                        onValueChange = { webdavUrl = it; settings.webdavUrl = it },
                        label = { Text(t.backupWebdavUrl) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = webdavUsername,
                        onValueChange = { webdavUsername = it; settings.webdavUsername = it },
                        label = { Text(t.backupWebdavUsername) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = webdavPassword,
                        onValueChange = { webdavPassword = it; settings.webdavPassword = it },
                        label = { Text(t.backupWebdavPassword) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    )
                } else {
                    OutlinedTextField(
                        value = s3Endpoint,
                        onValueChange = { s3Endpoint = it; settings.s3Endpoint = it },
                        label = { Text(t.backupS3Endpoint) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = s3Bucket,
                        onValueChange = { s3Bucket = it; settings.s3Bucket = it },
                        label = { Text(t.backupS3Bucket) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = s3Region,
                        onValueChange = { s3Region = it; settings.s3Region = it },
                        label = { Text(t.backupS3Region) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = s3AccessKey,
                        onValueChange = { s3AccessKey = it; settings.s3AccessKey = it },
                        label = { Text(t.backupS3AccessKey) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                    )
                    OutlinedTextField(
                        value = s3SecretKey,
                        onValueChange = { s3SecretKey = it; settings.s3SecretKey = it },
                        label = { Text(t.backupS3SecretKey) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = outlinedFieldColors(),
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    )
                }

                GroupDivider()
                Row(
                    Modifier.fillMaxWidth().padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    SecondaryActionButton(
                        text = t.backupRemoteTest,
                        onClick = {
                            scope.launch {
                                val result = testRemoteConnection(
                                    context, settings, includeSecrets, t.zh,
                                )
                                importResult = result
                            }
                        },
                        modifier = Modifier.weight(1f),
                    )
                    PrimaryActionButton(
                        text = t.backupRemoteUpload,
                        onClick = {
                            scope.launch {
                                val result = remoteBackup(
                                    context, settings, includeSecrets, t.zh,
                                )
                                importResult = result
                            }
                        },
                        modifier = Modifier.weight(1f),
                    )
                    SecondaryActionButton(
                        text = t.backupRemoteDownload,
                        onClick = {
                            scope.launch {
                                val result = remoteRestore(
                                    context, settings, includeSecrets, t.zh,
                                )
                                importResult = result
                            }
                        },
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            // Remote result feedback
            if (importResult != null && exportResult == null) {
                GlassGroup {
                    Text(
                        importResult!!,
                        modifier = Modifier.padding(14.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (importResult == t.backupRemoteSuccess || importResult == t.backupImportSuccess)
                            MaterialTheme.colorScheme.primary
                        else
                            MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
private fun outlinedFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = MaterialTheme.colorScheme.primary,
    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
    focusedContainerColor = Color.Transparent,
    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
)

private suspend fun testRemoteConnection(
    context: Context,
    settings: SettingsStore,
    includeSecrets: Boolean,
    zh: Boolean,
): String = withContext(Dispatchers.IO) {
    try {
        when (settings.remoteBackupProvider) {
            "webdav" -> {
                val url = settings.webdavUrl
                if (url.isBlank()) return@withContext if (zh) "请输入 WebDAV 地址" else "Enter WebDAV URL"
                val conn = URL(url).openConnection() as HttpURLConnection
                conn.requestMethod = "PROPFIND"
                conn.setRequestProperty("Depth", "0")
                if (settings.webdavUsername.isNotBlank()) {
                    val auth = android.util.Base64.encodeToString(
                        "${settings.webdavUsername}:${settings.webdavPassword}".toByteArray(),
                        android.util.Base64.NO_WRAP,
                    )
                    conn.setRequestProperty("Authorization", "Basic $auth")
                }
                conn.connectTimeout = 10000
                conn.readTimeout = 10000
                val code = conn.responseCode
                conn.disconnect()
                if (code in 200..299) {
                    if (zh) "WebDAV 连接成功 ($code)" else "WebDAV connected ($code)"
                } else {
                    if (zh) "WebDAV 连接失败 ($code)" else "WebDAV failed ($code)"
                }
            }
            "s3" -> {
                val endpoint = settings.s3Endpoint
                if (endpoint.isBlank()) return@withContext if (zh) "请输入 S3 端点" else "Enter S3 endpoint"
                // Simple HEAD request to test S3 endpoint reachability
                val conn = URL(endpoint).openConnection() as HttpURLConnection
                conn.requestMethod = "HEAD"
                conn.connectTimeout = 10000
                conn.readTimeout = 10000
                val code = conn.responseCode
                conn.disconnect()
                if (code in 200..499) {
                    if (zh) "S3 端点可达 ($code)" else "S3 endpoint reachable ($code)"
                } else {
                    if (zh) "S3 连接失败 ($code)" else "S3 connection failed ($code)"
                }
            }
            else -> if (zh) "未知提供商" else "Unknown provider"
        }
    } catch (e: Exception) {
        "${if (zh) "连接失败" else "Connection failed"}: ${e.message}"
    }
}

private suspend fun remoteBackup(
    context: Context,
    settings: SettingsStore,
    includeSecrets: Boolean,
    zh: Boolean,
): String = withContext(Dispatchers.IO) {
    try {
        val json = settings.toJsonString(maskSecrets = !includeSecrets)
        when (settings.remoteBackupProvider) {
            "webdav" -> {
                val url = settings.webdavUrl
                if (url.isBlank()) return@withContext if (zh) "请输入 WebDAV 地址" else "Enter WebDAV URL"
                val targetUrl = if (url.endsWith("/")) "${url}somcp_settings_backup.json" else "$url/somcp_settings_backup.json"
                val conn = URL(targetUrl).openConnection() as HttpURLConnection
                conn.requestMethod = "PUT"
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                if (settings.webdavUsername.isNotBlank()) {
                    val auth = android.util.Base64.encodeToString(
                        "${settings.webdavUsername}:${settings.webdavPassword}".toByteArray(),
                        android.util.Base64.NO_WRAP,
                    )
                    conn.setRequestProperty("Authorization", "Basic $auth")
                }
                conn.connectTimeout = 15000
                conn.readTimeout = 15000
                OutputStreamWriter(conn.outputStream).use { it.write(json) }
                val code = conn.responseCode
                conn.disconnect()
                if (code in 200..299) {
                    if (zh) "备份已上传到 WebDAV" else "Backup uploaded to WebDAV"
                } else {
                    if (zh) "上传失败 ($code)" else "Upload failed ($code)"
                }
            }
            "s3" -> {
                // S3 upload via presigned URL approach — for now return a guidance message
                if (zh) "S3 上传需要实现签名逻辑，请使用本地导出后自行上传" else "S3 upload requires signature logic; export locally and upload manually"
            }
            else -> if (zh) "未知提供商" else "Unknown provider"
        }
    } catch (e: Exception) {
        "${if (zh) "备份失败" else "Backup failed"}: ${e.message}"
    }
}

private suspend fun remoteRestore(
    context: Context,
    settings: SettingsStore,
    includeSecrets: Boolean,
    zh: Boolean,
): String = withContext(Dispatchers.IO) {
    try {
        when (settings.remoteBackupProvider) {
            "webdav" -> {
                val url = settings.webdavUrl
                if (url.isBlank()) return@withContext if (zh) "请输入 WebDAV 地址" else "Enter WebDAV URL"
                val targetUrl = if (url.endsWith("/")) "${url}somcp_settings_backup.json" else "$url/somcp_settings_backup.json"
                val conn = URL(targetUrl).openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.setRequestProperty("Accept", "application/json")
                if (settings.webdavUsername.isNotBlank()) {
                    val auth = android.util.Base64.encodeToString(
                        "${settings.webdavUsername}:${settings.webdavPassword}".toByteArray(),
                        android.util.Base64.NO_WRAP,
                    )
                    conn.setRequestProperty("Authorization", "Basic $auth")
                }
                conn.connectTimeout = 15000
                conn.readTimeout = 15000
                val code = conn.responseCode
                if (code != 200) {
                    conn.disconnect()
                    return@withContext if (zh) "下载失败 ($code)" else "Download failed ($code)"
                }
                val json = BufferedReader(InputStreamReader(conn.inputStream)).readText()
                conn.disconnect()
                val result = settings.fromJsonString(json, allowSecrets = includeSecrets)
                if (result.optBoolean("ok", false)) {
                    if (zh) "已从 WebDAV 恢复设置" else "Settings restored from WebDAV"
                } else {
                    if (zh) "恢复失败" else "Restore failed"
                }
            }
            "s3" -> {
                if (zh) "S3 下载需要实现签名逻辑，请下载后本地导入" else "S3 download requires signature logic; download and import locally"
            }
            else -> if (zh) "未知提供商" else "Unknown provider"
        }
    } catch (e: Exception) {
        "${if (zh) "恢复失败" else "Restore failed"}: ${e.message}"
    }
}