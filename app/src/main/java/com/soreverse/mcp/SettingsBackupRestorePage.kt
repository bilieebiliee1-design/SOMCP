package com.soreverse.mcp

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

@Composable
internal fun SettingsBackupRestorePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var includeSecrets by remember { mutableStateOf(false) }
    var resultMessage by remember { mutableStateOf<String?>(null) }
    var resultOk by remember { mutableStateOf(false) }

    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json"),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                val json = settings.toJsonString(maskSecrets = !includeSecrets)
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        output.write(json.toByteArray(Charsets.UTF_8))
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
                val json = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        BufferedReader(InputStreamReader(input)).readText()
                    } ?: error("Cannot read input file")
                }
                check(settings.fromJsonString(json, allowSecrets = includeSecrets).optBoolean("ok", false))
            }.onSuccess {
                resultOk = true
                resultMessage = t.backupImportSuccess
            }.onFailure { error ->
                resultOk = false
                resultMessage = "${t.backupImportError}: ${error.message.orEmpty()}"
            }
        }
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
