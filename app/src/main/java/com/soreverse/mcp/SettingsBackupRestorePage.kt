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

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.BackupCrypto
import com.soreverse.mcp.core.SettingsStore
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
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
    var resultMessage by remember { mutableStateOf<String?>(null) }
    var resultOk by remember { mutableStateOf(false) }

    // Decrypt dialog state (for import)
    var decryptDialogVisible by remember { mutableStateOf(false) }
    var decryptPassword by remember { mutableStateOf("") }
    var decryptError by remember { mutableStateOf<String?>(null) }
    var pendingEncryptedBytes by remember { mutableStateOf<ByteArray?>(null) }

    // ----- import password dialog state (REMOTE) -----
    var showImportPasswordDialog by remember { mutableStateOf(false) }
    var importPassword by remember { mutableStateOf("") }
    var importPasswordError by remember { mutableStateOf<String?>(null) }
    var pendingImportContent by remember { mutableStateOf<String?>(null) }

    // ----- recent backup history -----
    var history by remember { mutableStateOf(settings.backupHistory()) }

    // ----- export: file launcher -----
    val plainExportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val json = settings.toJsonString(maskSecrets = !includeSecrets)
                val bytes = when {
                    encryptEnabled -> {
                        if (encryptPassword.isBlank()) {
                            // Never write an encrypted backup without a password.
                            throw IllegalStateException(t.backupPasswordRequired)
                        }
                        withContext(Dispatchers.Default) {
                            BackupCrypto.encrypt(json, encryptPassword)
                        }
                    }
                    includeSecrets -> {
                        // Never write a plaintext backup that includes secrets.
                        throw IllegalStateException(t.backupSecretsRequireEncryption)
                    }
                    else -> json.toByteArray(Charsets.UTF_8)
                }
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        output.write(bytes)
                    } ?: error("Cannot open output file")
                }
                settings.recordBackup(System.currentTimeMillis(), bytes.size.toLong())
                history = settings.backupHistory()
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
            BackupToggleRow(
                text = t.backupIncludeSecrets,
                subtitle = t.backupIncludeSecretsSubtitle,
                checked = includeSecrets
            ) { enabled ->
                includeSecrets = enabled
            }
            GroupDivider()
            BackupToggleRow(
                text = t.backupEncryptToggle,
                subtitle = t.backupEncryptToggleSubtitle,
                checked = encryptEnabled
            ) { enabled ->
                if (enabled) {
                    showEncryptWarning = true
                } else {
                    encryptEnabled = false
                    encryptPassword = ""
                }
            }
            AnimatedVisibility(visible = encryptEnabled) {
                Column {
                    GroupDivider()
                    OutlinedTextField(
                        value = encryptPassword,
                        onValueChange = { encryptPassword = it },
                        label = { Text(t.backupEncryptPassword) },
                        placeholder = { Text(t.backupPasswordPlaceholder) },
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
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 8.dp)
                    )
                    Text(
                        t.backupEncryptWarning,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            BackupActionCard(
                label = t.backupExport,
                icon = Icons.Default.Upload,
                onClick = {
                    when {
                        encryptEnabled && encryptPassword.isBlank() -> {
                            resultOk = false
                            resultMessage = t.backupPasswordRequired
                        }
                        includeSecrets && !encryptEnabled -> {
                            resultOk = false
                            resultMessage = t.backupSecretsRequireEncryption
                        }
                        else -> plainExportLauncher.launch("somcp_settings_backup.json")
                    }
                },
                modifier = Modifier.weight(1f)
            )
            BackupActionCard(
                label = t.backupImport,
                icon = Icons.Default.Download,
                onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                modifier = Modifier.weight(1f)
            )
        }

        GlassGroup(title = t.backupHistory) {
            if (history.isEmpty()) {
                Text(
                    t.backupHistoryEmpty,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                history.forEachIndexed { index, entry ->
                    if (index > 0) {
                        GroupDivider()
                    }
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text(
                                formatBackupTime(entry.timestamp),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                formatBackupSize(entry.sizeBytes),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Text(
                            t.backupRestore,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    importLauncher.launch(arrayOf("application/json", "*/*"))
                                }
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
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

@Composable
private fun BackupToggleRow(
    text: String,
    subtitle: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    val metrics = LocalUiMetrics.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text,
                color = MaterialTheme.colorScheme.onSurface,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
            Text(
                subtitle,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )
        }
        BackupSwitch(
            checked = checked,
            onCheckedChange = onChange
        )
    }
}

/**
 * Custom switch matching the design spec: a soft gray track that turns
 * Primary Blue when toggled on, with a pure white circular thumb. The thumb
 * animates to the right when ON (LTR), unlike the design's HTML reference
 * where the thumb incorrectly stayed pinned to the left.
 */
@Composable
private fun BackupSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val trackWidth = 48.dp
    val trackHeight = 28.dp
    val thumbSize = 24.dp
    val thumbInset = 2.dp
    val thumbOffset by animateDpAsState(
        targetValue = if (checked) trackWidth - thumbSize - thumbInset else thumbInset,
        animationSpec = tween(durationMillis = 200, easing = FastOutSlowInEasing),
        label = "backupSwitchThumb"
    )
    Box(
        modifier = modifier
            .size(width = trackWidth, height = trackHeight)
            .clip(RoundedCornerShape(trackHeight / 2))
            .background(
                if (checked) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
                }
            )
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = onCheckedChange
            ),
        contentAlignment = Alignment.CenterStart
    ) {
        Box(
            modifier = Modifier
                .offset(x = thumbOffset)
                .size(thumbSize)
                .clip(CircleShape)
                .background(Color.White)
        )
    }
}

@Composable
private fun BackupActionCard(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val shape = RoundedCornerShape(LocalUiMetrics.current.cardRadius)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(
                BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)),
                shape
            )
            .clickable(onClick = onClick)
            .padding(vertical = 18.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Box(
            Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                icon,
                null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(22.dp)
            )
        }
        Text(
            label,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

private val backupTimeFormatter: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")

private fun formatBackupTime(timestamp: Long): String = runCatching {
    Instant.ofEpochMilli(timestamp)
        .atZone(ZoneId.systemDefault())
        .format(backupTimeFormatter)
}.getOrDefault("")

private fun formatBackupSize(bytes: Long): String = when {
    bytes >= 1024L * 1024 * 1024 ->
        String.format(Locale.US, "%.1f GB", bytes / (1024.0 * 1024 * 1024))
    bytes >= 1024L * 1024 ->
        String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024))
    bytes >= 1024L ->
        String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
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
