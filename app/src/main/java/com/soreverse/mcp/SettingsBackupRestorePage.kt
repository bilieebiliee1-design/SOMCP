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
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.BackupCrypto
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

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

    // ----- export password dialog state (REMOTE) -----
    var showExportPasswordDialog by remember { mutableStateOf(false) }
    var exportPassword by remember { mutableStateOf("") }
    var exportPasswordConfirm by remember { mutableStateOf("") }
    var exportPasswordError by remember { mutableStateOf<String?>(null) }

    // ----- import password dialog state (REMOTE) -----
    var showImportPasswordDialog by remember { mutableStateOf(false) }
    var importPassword by remember { mutableStateOf("") }
    var importPasswordError by remember { mutableStateOf<String?>(null) }
    var pendingImportContent by remember { mutableStateOf<String?>(null) }

    // ----- export state (REMOTE) -----
    var pendingExportPassword by remember { mutableStateOf<String?>(null) }

    // ----- export: encrypted file launcher (REMOTE) -----
    val encryptedExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        val password = pendingExportPassword ?: return@rememberLauncherForActivityResult
        if (uri == null) {
            pendingExportPassword = null
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            runCatching {
                val json = settings.toJsonString(maskSecrets = !includeSecrets)
                val encrypted = withContext(Dispatchers.Default) {
                    BackupCrypto.encrypt(json.toByteArray(Charsets.UTF_8), password)
                }
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        output.write(encrypted.toString(2).toByteArray(Charsets.UTF_8))
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
        pendingExportPassword = null
    }

    // ----- export: plain file launcher (REMOTE, no encryption) -----
    val plainExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
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

    // ----- import launcher -----
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        input.readBytes()
                    } ?: error("Cannot read input file")
                }
                // Try binary format first (HEAD)
                if (BackupCrypto.isEncrypted(bytes)) {
                    pendingEncryptedBytes = bytes
                    decryptPassword = ""
                    decryptError = null
                    decryptDialogVisible = true
                } else {
                    // Try JSON format (REMOTE)
                    val content = bytes.decodeToString()
                    val json = withContext(Dispatchers.Default) {
                        try {
                            JSONObject(content)
                        } catch (_: Exception) {
                            null
                        }
                    }
                    if (json != null && BackupCrypto.isEncryptedBackup(json)) {
                        pendingImportContent = content
                        importPassword = ""
                        importPasswordError = null
                        showImportPasswordDialog = true
                    } else {
                        // Plain JSON — import directly
                        applyImport(content, t, settings, includeSecrets) { ok, msg ->
                            resultOk = ok
                            resultMessage = msg
                        }
                    }
                }
            }.onFailure { error ->
                resultOk = false
                resultMessage = "${t.backupImportError}: ${error.message.orEmpty()}"
            }
        }
    }

    // Decrypt dialog (HEAD — binary format)
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
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = decryptPassword,
                        onValueChange = {
                            decryptPassword = it
                            decryptError = null
                        },
                        label = { Text(t.backupEncryptPassword) },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(
                                alpha = 0.35f
                            ),
                            focusedContainerColor = Color.Transparent,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(
                                alpha = 0.35f
                            )
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                    decryptError?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
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
                                check(
                                    settings.fromJsonString(
                                        json,
                                        allowSecrets = includeSecrets
                                    ).optBoolean("ok", false)
                                )
                                decryptDialogVisible = false
                                pendingEncryptedBytes = null
                                decryptPassword = ""
                                resultOk = true
                                resultMessage = t.backupImportSuccess
                            }.onFailure { error ->
                                decryptError = error.message?.let {
                                    if (it.contains("password") ||
                                        it.contains("tag mismatch") ||
                                        it.contains("AEADBadTagException")
                                    ) {
                                        t.backupDecryptFailed
                                    } else {
                                        "${t.backupImportError}: $it"
                                    }
                                } ?: t.backupDecryptFailed
                            }
                        }
                    },
                    enabled = decryptPassword.isNotBlank()
                ) { Text(t.backupImport) }
            },
            dismissButton = {
                TextButton(onClick = {
                    decryptDialogVisible = false
                    pendingEncryptedBytes = null
                    decryptPassword = ""
                    decryptError = null
                }) { Text(if (t.zh) "取消" else "Cancel") }
            }
        )
    }

    // Encryption warning dialog (HEAD)
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
                    style = MaterialTheme.typography.bodyMedium
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
            }
        )
    }

    // --- export password dialog (REMOTE) ---
    if (showExportPasswordDialog) {
        AlertDialog(
            onDismissRequest = { showExportPasswordDialog = false },
            title = { Text(t.backupPasswordPrompt) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = exportPassword,
                        onValueChange = {
                            exportPassword = it
                            exportPasswordError = null
                        },
                        label = { Text(t.backupPasswordLabel) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = exportPasswordConfirm,
                        onValueChange = {
                            exportPasswordConfirm = it
                            exportPasswordError = null
                        },
                        label = { Text(t.backupPasswordConfirm) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    exportPasswordError?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (exportPassword.length < 4) {
                        exportPasswordError = t.backupPasswordPrompt
                    } else if (exportPassword != exportPasswordConfirm) {
                        exportPasswordError = t.backupPasswordMismatch
                    } else {
                        showExportPasswordDialog = false
                        pendingExportPassword = exportPassword
                        encryptedExportLauncher.launch("somcp_settings_backup_encrypted.json")
                    }
                }) {
                    Text(t.confirm)
                }
            },
            dismissButton = {
                TextButton(onClick = { showExportPasswordDialog = false }) {
                    Text(t.cancel)
                }
            }
        )
    }

    // --- import password dialog (REMOTE) ---
    if (showImportPasswordDialog) {
        AlertDialog(
            onDismissRequest = {
                showImportPasswordDialog = false
                pendingImportContent = null
            },
            title = { Text(t.backupDecryptPrompt) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        t.backupEncryptWarning,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                    OutlinedTextField(
                        value = importPassword,
                        onValueChange = {
                            importPassword = it
                            importPasswordError = null
                        },
                        label = { Text(t.backupPasswordLabel) },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    importPasswordError?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (importPassword.isBlank()) {
                        importPasswordError = t.backupPasswordLabel
                    } else {
                        val content = pendingImportContent ?: return@TextButton
                        showImportPasswordDialog = false
                        pendingImportContent = null
                        scope.launch {
                            runCatching {
                                val decrypted = withContext(Dispatchers.Default) {
                                    BackupCrypto.decrypt(JSONObject(content), importPassword)
                                }
                                val decryptedText = decrypted.toString(Charsets.UTF_8)
                                applyImport(decryptedText, t, settings, includeSecrets) { ok, msg ->
                                    resultOk = ok
                                    resultMessage = msg
                                }
                            }.onFailure { error ->
                                val msg = if (error.message?.contains("tag mismatch") == true ||
                                    error.message?.contains("AEADBadTagException") == true ||
                                    error.message?.contains("GCM") == true
                                ) {
                                    t.backupWrongPassword
                                } else {
                                    "${t.backupImportError}: ${error.message.orEmpty()}"
                                }
                                resultOk = false
                                resultMessage = msg
                            }
                        }
                    }
                }) {
                    Text(t.confirm)
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showImportPasswordDialog = false
                    pendingImportContent = null
                }) {
                    Text(t.cancel)
                }
            }
        )
    }

    // --- main UI ---
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp)
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(LocalUiMetrics.current.sectionGap)
    ) {
        GlassGroup(title = t.backupLocal) {
            ToggleRow(t.backupIncludeSecrets, includeSecrets) { includeSecrets = it }
            GroupDivider()
            Text(
                t.backupSecretsMasked,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
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
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(
                            alpha = 0.35f
                        ),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(
                            alpha = 0.35f
                        )
                    ),
                    modifier = Modifier.fillMaxWidth().padding(
                        start = 14.dp,
                        end = 14.dp,
                        top = 8.dp
                    )
                )
                OutlinedTextField(
                    value = encryptConfirm,
                    onValueChange = { encryptConfirm = it },
                    label = { Text(t.backupEncryptConfirm) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    isError = encryptConfirm.isNotEmpty() && encryptPassword != encryptConfirm,
                    supportingText = if (encryptConfirm.isNotEmpty() &&
                        encryptPassword != encryptConfirm
                    ) {
                        { Text(t.backupPasswordMismatch, color = MaterialTheme.colorScheme.error) }
                    } else {
                        null
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(
                            alpha = 0.35f
                        ),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(
                            alpha = 0.35f
                        )
                    ),
                    modifier = Modifier.fillMaxWidth().padding(
                        start = 14.dp,
                        end = 14.dp,
                        top = 8.dp
                    )
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    t.backupEncryptWarning,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            GroupDivider()
            Row(
                Modifier.fillMaxWidth().padding(14.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
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
                            plainExportLauncher.launch("somcp_settings_backup.json")
                        }
                    },
                    modifier = Modifier.weight(1f)
                )
                SecondaryActionButton(
                    text = t.backupImport,
                    onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                    modifier = Modifier.weight(1f)
                )
            }
        }

        resultMessage?.let { message ->
            GlassGroup {
                Text(
                    message,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (resultOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

private fun applyImport(content: String, t: UiText, settings: SettingsStore, includeSecrets: Boolean, onResult: (Boolean, String) -> Unit) {
    runCatching {
        check(
            settings.fromJsonString(content, allowSecrets = includeSecrets).optBoolean("ok", false)
        )
    }.onSuccess {
        onResult(true, t.backupImportSuccess)
    }.onFailure { error ->
        onResult(false, "${t.backupImportError}: ${error.message.orEmpty()}")
    }
}
