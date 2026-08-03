package com.soreverse.mcp

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.soreverse.mcp.core.BackupCrypto
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


@Composable
internal fun SettingsBackupRestorePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var includeSecrets by remember { mutableStateOf(false) }
    var encryptEnabled by remember { mutableStateOf(false) }
    var encryptPassword by remember { mutableStateOf("") }
    var encryptConfirm by remember { mutableStateOf("") }
    var resultMessage by remember { mutableStateOf<String?>(null) }
    var resultOk by remember { mutableStateOf(false) }

    // Warning dialog state
    var showEncryptWarning by remember { mutableStateOf(false) }
    var pendingEncryptEnable by remember { mutableStateOf(false) }

    // Decrypt dialog state (for import)
    var decryptDialogVisible by remember { mutableStateOf(false) }
    var decryptPassword by remember { mutableStateOf("") }
    var decryptError by remember { mutableStateOf<String?>(null) }
    var pendingEncryptedBytes by remember { mutableStateOf<ByteArray?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json"),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val json = settings.toJsonString(maskSecrets = !includeSecrets)
                val bytes = if (encryptEnabled && encryptPassword.isNotBlank()) {
                    withContext(Dispatchers.IO) {
                        BackupCrypto.encrypt(json, encryptPassword)
                    }
                } else {
                    json.toByteArray(Charsets.UTF_8)
                }
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        output.write(bytes)
                    } ?: error("Cannot open output file")
                }
            }.onSuccess {
                resultOk = true
                resultMessage = t.backupExportSuccess
            }.onFailure { error ->
                resultOk = false
                resultMessage = error.message ?: t.backupImportError
            }
        }
    }

    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        input.readBytes()
                    } ?: error("Cannot read input file")
                }
                if (BackupCrypto.isEncrypted(bytes)) {
                    // File is encrypted — show password dialog
                    pendingEncryptedBytes = bytes
                    decryptPassword = ""
                    decryptError = null
                    decryptDialogVisible = true
                } else {
                    // Plaintext JSON — import directly
                    val json = bytes.decodeToString()
                    check(settings.fromJsonString(json, allowSecrets = includeSecrets).optBoolean("ok", false))
                    resultOk = true
                    resultMessage = t.backupImportSuccess
                }
            }.onFailure { error ->
                resultOk = false
                resultMessage = "${t.backupImportError}: ${error.message.orEmpty()}"
            }
        }
    }

    // Decrypt dialog
    if (decryptDialogVisible) {
        AlertDialog(
            onDismissRequest = {
                decryptDialogVisible = false
                pendingEncryptedBytes = null
                decryptPassword = ""
                decryptError = null
            },
            title = { Text(t.backupDecryptPassword) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        t.backupDecryptPasswordHint,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = decryptPassword,
                        onValueChange = { decryptPassword = it; decryptError = null },
                        label = { Text(t.backupEncryptPassword) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                            focusedContainerColor = Color.Transparent,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    decryptError?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            val bytes = pendingEncryptedBytes ?: return@launch
                            runCatching {
                                val json = withContext(Dispatchers.IO) {
                                    BackupCrypto.decrypt(bytes, decryptPassword)
                                }
                                check(settings.fromJsonString(json, allowSecrets = includeSecrets).optBoolean("ok", false))
                                decryptDialogVisible = false
                                pendingEncryptedBytes = null
                                decryptPassword = ""
                                resultOk = true
                                resultMessage = t.backupImportSuccess
                            }.onFailure { error ->
                                decryptError = error.message?.let {
                                    if (it.contains("password") || it.contains("tag mismatch") || it.contains("AEADBadTagException")) {
                                        t.backupDecryptFailed
                                    } else {
                                        "${t.backupImportError}: $it"
                                    }
                                } ?: t.backupDecryptFailed
                            }
                        }
                    },
                    enabled = decryptPassword.isNotBlank(),
                ) { Text(t.backupImport) }
            },
            dismissButton = {
                TextButton(onClick = {
                    decryptDialogVisible = false
                    pendingEncryptedBytes = null
                    decryptPassword = ""
                    decryptError = null
                }) { Text(if (t.zh) "取消" else "Cancel") }
            },
        )
    }

    // Encryption warning dialog
    if (showEncryptWarning) {
        AlertDialog(
            onDismissRequest = {
                showEncryptWarning = false
                pendingEncryptEnable = false
            },
            title = { Text(t.backupEncryptWarningTitle) },
            text = {
                Text(
                    t.backupEncryptWarning,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                Button(onClick = {
                    showEncryptWarning = false
                    encryptEnabled = true
                }) {
                    Text(if (t.zh) "我已知晓" else "I understand")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showEncryptWarning = false
                    pendingEncryptEnable = false
                }) { Text(if (t.zh) "取消" else "Cancel") }
            },
        )
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp)
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(LocalUiMetrics.current.sectionGap),
    ) {
        GlassGroup(title = t.backupLocal) {
            ToggleRow(t.backupIncludeSecrets, includeSecrets) { includeSecrets = it }
            GroupDivider()
            Text(
                t.backupSecretsMasked,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            ToggleRow(t.backupEncryptToggle, encryptEnabled) { enabled ->
                if (enabled) {
                    showEncryptWarning = true
                    pendingEncryptEnable = true
                } else {
                    encryptEnabled = false
                    encryptPassword = ""
                    encryptConfirm = ""
                }
            }
            if (encryptEnabled) {
                GroupDivider()
                OutlinedTextField(
                    value = encryptPassword,
                    onValueChange = { encryptPassword = it },
                    label = { Text(t.backupEncryptPassword) },
                    placeholder = { Text(t.backupEncryptPasswordHint) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, top = 8.dp),
                )
                OutlinedTextField(
                    value = encryptConfirm,
                    onValueChange = { encryptConfirm = it },
                    label = { Text(t.backupEncryptConfirm) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    isError = encryptConfirm.isNotEmpty() && encryptPassword != encryptConfirm,
                    supportingText = if (encryptConfirm.isNotEmpty() && encryptPassword != encryptConfirm) {
                        { Text(t.backupPasswordMismatch, color = MaterialTheme.colorScheme.error) }
                    } else null,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, top = 8.dp),
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    t.backupEncryptWarning,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            GroupDivider()
            Row(
                Modifier.fillMaxWidth().padding(14.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                val exportEnabled = !encryptEnabled || (encryptPassword.isNotBlank() && encryptPassword == encryptConfirm)
                PrimaryActionButton(
                    text = t.backupExport,
                    onClick = {
                        if (encryptEnabled && encryptPassword.isBlank()) {
                            resultOk = false
                            resultMessage = t.backupPasswordRequired
                        } else if (encryptEnabled && encryptPassword != encryptConfirm) {
                            resultOk = false
                            resultMessage = t.backupPasswordMismatch
                        } else {
                            exportLauncher.launch("somcp_settings_backup.json")
                        }
                    },
                    modifier = Modifier.weight(1f),
                )
                SecondaryActionButton(
                    text = t.backupImport,
                    onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                    modifier = Modifier.weight(1f),
                )
            }
        }
        resultMessage?.let { message ->
            GlassGroup {
                Text(
                    message,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (resultOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}