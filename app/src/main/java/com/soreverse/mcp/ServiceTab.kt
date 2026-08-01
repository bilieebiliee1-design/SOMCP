package com.soreverse.mcp

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.soreverse.mcp.core.ApkBridgeManager
import com.soreverse.mcp.core.ApkBridgeInstance
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.service.McpForegroundService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

@Composable
internal fun ServiceTab(
    t: UiText,
    settings: SettingsStore,
    onOpenApkBridge: () -> Unit,
    onOpenKeepAlive: () -> Unit,
    onOpenTunnel: () -> Unit,
) {
    val context = LocalContext.current
    var treeUri by remember { mutableStateOf(settings.treeUri) }
    var port by remember { mutableStateOf(settings.port.toString()) }
    var running by remember { mutableStateOf(McpForegroundService.isRunning()) }
    var portStatus by remember { mutableStateOf(portStatusText(settings.port, running, t.zh)) }
    var endpoints by remember { mutableStateOf(filteredEndpoints(context, settings, settings.port)) }
    var setupPrompt by remember { mutableStateOf<SetupTarget?>(null) }
    var showStartDiagnosis by remember { mutableStateOf(false) }
    var quickPublicUrl by remember { mutableStateOf<String?>(null) }
    var apkConnected by remember { mutableStateOf<Boolean?>(null) }
    var apkToolNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var onlineBridgeCount by remember { mutableStateOf(0) }
    var showToolCatalog by remember { mutableStateOf(false) }
    var keepAliveReady by remember { mutableStateOf(isKeepAliveReady(context, settings)) }
    val pickTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }.onFailure { AppLog.w("Unable to persist directory permission: ${it.message}") }
            settings.treeUri = uri
            settings.useDefaultWorkDir = false
            treeUri = uri
            EngineProvider.get(context).setWorkDirectory(uri)
        }
    }

    LaunchedEffect(Unit) {
        treeUri?.let { EngineProvider.get(context).setWorkDirectory(it) }
        apkConnected = withContext(Dispatchers.IO) {
            val manager = activeServer(context)?.apkBridgeManager
            manager?.refreshFromSettings()
            manager?.allOnlineBridges()?.isNotEmpty() == true
        }
        while (true) {
            running = McpForegroundService.isRunning()
            val typedPort = port.toIntOrNull() ?: settings.port
            portStatus = portStatusText(typedPort, running && typedPort == settings.port, t.zh)
            val currentEndpoints = filteredEndpoints(context, settings, typedPort)
            if (currentEndpoints != endpoints) endpoints = currentEndpoints
            val ts = activeServer(context)?.tunnel?.status()
            val url = ts?.publicUrl?.takeIf { it.isNotBlank() && ts.state == CloudflareTunnelManager.State.RUNNING }
            if (url != quickPublicUrl) quickPublicUrl = url
            val manager = activeServer(context)?.apkBridgeManager
            val onlineBridges = manager?.allOnlineBridges() ?: emptyList()
            onlineBridgeCount = onlineBridges.size
            apkToolNames = onlineBridges.flatMap { it.state().tools.map { t -> t.name } }.distinct()
            apkConnected = onlineBridges.isNotEmpty()
            keepAliveReady = isKeepAliveReady(context, settings)
            delay(if (settings.apkMcpAutoProbe) 10_000 else 1_000)
        }
    }
}