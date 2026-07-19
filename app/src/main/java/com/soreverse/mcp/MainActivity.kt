package com.soreverse.mcp

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.Configuration
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.PredictiveBackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.ExperimentalAnimationApi
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.ui.unit.sp
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.draw.drawBehind
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.BorderStroke
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SwitchDefaults
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.DeepAnalysisEvent
import com.soreverse.mcp.core.DeepAnalysisService
import com.soreverse.mcp.core.DeepReportStore
import com.soreverse.mcp.core.RikkaPart
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.GitHubRelease
import com.soreverse.mcp.core.GitHubUpdateManager
import com.soreverse.mcp.core.NetworkInspector
import com.soreverse.mcp.core.PublicReachability
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.engine.WorkDirectory
import com.soreverse.mcp.mcp.ToolCatalog
import com.soreverse.mcp.service.McpForegroundService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.ServerSocket
import java.util.Locale

typealias AndroidSettings = android.provider.Settings

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 12)
        }
        setContent { IntegrityGate { SoReverseApp() } }
    }
}

private enum class MainTab { Service, Analyze, Logs, Settings }
private enum class SetupTarget { Directory, ApkMcp, KeepAlive }
private enum class SettingsDest {
    Root, ServiceConfig, Appearance, KeepAlive, Access, Limits, Export, Audit, Tunnel, ApkBridge, AiDeep, Updates, Probe, ToolStats, TunnelStats, Instructions, Credits, Disclaimer, About
}

/** Clean control-console design tokens for SOMCP. */
private object AppPalette {
    val blue = Color(0xFF0A84FF)
    val teal = Color(0xFF64D2FF)
    val indigo = Color(0xFF5E5CE6)
    val purple = Color(0xFFBF5AF2)
    val green = Color(0xFF30D158)
    val orange = Color(0xFFFF9F0A)
    val red = Color(0xFFFF453A)
    val mono = Color(0xFF8E8E93)

    fun accent(name: String, dark: Boolean): Color = when (name) {
        "teal" -> if (dark) Color(0xFF64D2FF) else Color(0xFF0891B2)
        "indigo" -> if (dark) Color(0xFF5E5CE6) else Color(0xFF4F46E5)
        "purple" -> if (dark) Color(0xFFBF5AF2) else Color(0xFF9333EA)
        "green" -> if (dark) Color(0xFF30D158) else Color(0xFF16A34A)
        "orange" -> if (dark) Color(0xFFFF9F0A) else Color(0xFFEA580C)
        "red" -> if (dark) Color(0xFFFF453A) else Color(0xFFDC2626)
        "mono" -> if (dark) Color(0xFFD1D1D6) else Color(0xFF3A3A3C)
        else -> if (dark) Color(0xFF0A84FF) else Color(0xFF007AFF)
    }
}

private data class UiMetrics(
    val pagePad: androidx.compose.ui.unit.Dp,
    val sectionGap: androidx.compose.ui.unit.Dp,
    val rowPadV: androidx.compose.ui.unit.Dp,
    val cardRadius: androidx.compose.ui.unit.Dp,
    val controlRadius: androidx.compose.ui.unit.Dp,
)

private fun uiMetrics(density: String, corner: String): UiMetrics {
    val pagePad = when (density) {
        "compact" -> 12.dp
        "spacious" -> 20.dp
        else -> 16.dp
    }
    val sectionGap = when (density) {
        "compact" -> 12.dp
        "spacious" -> 22.dp
        else -> 16.dp
    }
    val rowPadV = when (density) {
        "compact" -> 8.dp
        "spacious" -> 14.dp
        else -> 11.dp
    }
    val cardRadius = when (corner) {
        "small" -> 10.dp
        "large" -> 18.dp
        "xlarge" -> 24.dp
        else -> 14.dp
    }
    val controlRadius = when (corner) {
        "small" -> 8.dp
        "large" -> 14.dp
        "xlarge" -> 18.dp
        else -> 11.dp
    }
    return UiMetrics(pagePad, sectionGap, rowPadV, cardRadius, controlRadius)
}

private fun textScaleFactor(textScale: String): Float = when (textScale) {
    "large" -> 1.08f
    "xlarge" -> 1.16f
    else -> 1f
}

private fun TextStyle.scaledBy(scale: Float): TextStyle = copy(
    fontSize = (fontSize.value * scale).sp,
    lineHeight = (lineHeight.value * scale).sp,
)

private fun scaledTypography(scale: Float): Typography {
    val base = Typography()
    return Typography(
        displayLarge = base.displayLarge.scaledBy(scale),
        displayMedium = base.displayMedium.scaledBy(scale),
        displaySmall = base.displaySmall.scaledBy(scale),
        headlineLarge = base.headlineLarge.scaledBy(scale),
        headlineMedium = base.headlineMedium.scaledBy(scale),
        headlineSmall = base.headlineSmall.scaledBy(scale),
        titleLarge = base.titleLarge.scaledBy(scale),
        titleMedium = base.titleMedium.scaledBy(scale),
        titleSmall = base.titleSmall.scaledBy(scale),
        bodyLarge = base.bodyLarge.scaledBy(scale),
        bodyMedium = base.bodyMedium.scaledBy(scale),
        bodySmall = base.bodySmall.scaledBy(scale),
        labelLarge = base.labelLarge.scaledBy(scale),
        labelMedium = base.labelMedium.scaledBy(scale),
        labelSmall = base.labelSmall.scaledBy(scale),
    )
}

private fun appLightColors(accent: Color, highContrast: Boolean) = lightColorScheme(
    primary = accent,
    onPrimary = Color.White,
    primaryContainer = accent.copy(alpha = 0.12f),
    onPrimaryContainer = Color(0xFF0B1B33),
    secondary = Color(0xFFE8E8ED),
    onSecondary = Color(0xFF1C1C1E),
    secondaryContainer = Color(0xFFF2F2F7),
    onSecondaryContainer = Color(0xFF1C1C1E),
    tertiary = AppPalette.indigo,
    onTertiary = Color.White,
    background = Color(0xFFF2F2F7),
    onBackground = if (highContrast) Color(0xFF000000) else Color(0xFF1C1C1E),
    surface = Color(0xFFFFFFFF),
    onSurface = if (highContrast) Color(0xFF000000) else Color(0xFF1C1C1E),
    surfaceVariant = Color(0xFFE5E5EA),
    onSurfaceVariant = if (highContrast) Color(0xFF3A3A3C) else Color(0xFF636366),
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFF7F7FA),
    surfaceContainerHighest = Color(0xFFE5E5EA),
    outline = if (highContrast) Color(0xFF8E8E93) else Color(0xFFC6C6C8),
    outlineVariant = Color(0xFFE5E5EA),
    error = Color(0xFFFF3B30),
    onError = Color.White,
    errorContainer = Color(0xFFFFECEA),
    onErrorContainer = Color(0xFF93000A),
)

private fun appDarkColors(accent: Color, pureBlack: Boolean, highContrast: Boolean) = darkColorScheme(
    primary = accent,
    onPrimary = Color.White,
    primaryContainer = accent.copy(alpha = 0.18f),
    onPrimaryContainer = Color(0xFFE8F1FF),
    secondary = Color(0xFF2C2C2E),
    onSecondary = Color(0xFFF5F5F7),
    secondaryContainer = Color(0xFF3A3A3C),
    onSecondaryContainer = Color(0xFFF5F5F7),
    tertiary = Color(0xFF5E5CE6),
    onTertiary = Color.White,
    background = if (pureBlack) Color(0xFF000000) else Color(0xFF0B0B0D),
    onBackground = if (highContrast) Color(0xFFFFFFFF) else Color(0xFFF5F5F7),
    surface = if (pureBlack) Color(0xFF1C1C1E) else Color(0xFF161618),
    onSurface = if (highContrast) Color(0xFFFFFFFF) else Color(0xFFF5F5F7),
    surfaceVariant = Color(0xFF2C2C2E),
    onSurfaceVariant = if (highContrast) Color(0xFFD1D1D6) else Color(0xFF8E8E93),
    surfaceContainer = if (pureBlack) Color(0xFF1C1C1E) else Color(0xFF161618),
    surfaceContainerHigh = Color(0xFF2C2C2E),
    surfaceContainerHighest = Color(0xFF3A3A3C),
    outline = if (highContrast) Color(0xFFAEAEB2) else Color(0xFF3A3A3C),
    outlineVariant = Color(0xFF2C2C2E),
    error = Color(0xFFFF453A),
    onError = Color.White,
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

private fun statusSuccess(dark: Boolean = false): Color = if (dark) Color(0xFF30D158) else Color(0xFF34C759)
private fun statusError(dark: Boolean = false): Color = if (dark) Color(0xFFFF453A) else Color(0xFFFF3B30)
private fun statusWarning(dark: Boolean = false): Color = if (dark) Color(0xFFFF9F0A) else Color(0xFFFF9500)

// Backward-compatible aliases used across the file.
private object AppleColors {
    val systemBlue = AppPalette.blue
    val systemBlueDark = AppPalette.blue
    val systemGreen = AppPalette.green
    val systemGreenDark = AppPalette.green
    val systemRed = AppPalette.red
    val systemRedDark = AppPalette.red
    val systemOrange = AppPalette.orange
    val systemOrangeDark = AppPalette.orange
    val systemIndigo = AppPalette.indigo
    val systemTeal = AppPalette.teal
    val systemPurple = AppPalette.purple
    object Light {
        val background = Color(0xFFF2F2F7)
        val secondaryBackground = Color(0xFFFFFFFF)
        val tertiaryBackground = Color(0xFFF2F2F7)
        val groupedBackground = Color(0xFFF2F2F7)
        val card = Color(0xFFFFFFFF)
        val fill = Color(0xFFE5E5EA)
        val fillSecondary = Color(0xFFF2F2F7)
        val separator = Color(0xFFC6C6C8)
        val label = Color(0xFF1C1C1E)
        val secondaryLabel = Color(0xFF636366)
        val tertiaryLabel = Color(0xFF8E8E93)
        val primary = AppPalette.blue
        val onPrimary = Color.White
        val success = AppPalette.green
        val error = AppPalette.red
        val warning = AppPalette.orange
        val glass = Color(0xFFFFFFFF)
        val glassStrong = Color(0xFFFFFFFF)
        val glassStroke = Color(0x33C6C6C8)
    }
    object Dark {
        val background = Color(0xFF000000)
        val secondaryBackground = Color(0xFF1C1C1E)
        val tertiaryBackground = Color(0xFF2C2C2E)
        val groupedBackground = Color(0xFF000000)
        val card = Color(0xFF1C1C1E)
        val fill = Color(0xFF3A3A3C)
        val fillSecondary = Color(0xFF2C2C2E)
        val separator = Color(0xFF38383A)
        val label = Color(0xFFF5F5F7)
        val secondaryLabel = Color(0xFF8E8E93)
        val tertiaryLabel = Color(0xFF636366)
        val primary = AppPalette.blue
        val onPrimary = Color.White
        val success = AppPalette.green
        val error = AppPalette.red
        val warning = AppPalette.orange
        val glass = Color(0xFF1C1C1E)
        val glassStrong = Color(0xFF1C1C1E)
        val glassStroke = Color(0x33FFFFFF)
    }
}

private fun appleLightColors() = appLightColors(AppPalette.blue, false)
private fun appleDarkColors() = appDarkColors(AppPalette.blue, true, false)
private fun appleSuccess(dark: Boolean = false): Color = statusSuccess(dark)
private fun appleError(dark: Boolean = false): Color = statusError(dark)
private fun appleWarning(dark: Boolean = false): Color = statusWarning(dark)

private val LocalUiMetrics = androidx.compose.runtime.staticCompositionLocalOf {
    uiMetrics("comfortable", "medium")
}
private val LocalReduceMotion = androidx.compose.runtime.staticCompositionLocalOf { false }

private data class WorkspaceUi(
    val id: String,
    val name: String,
    val path: String,
    val abi: String,
    val architecture: String,
    val bits: Int,
    val temporary: Boolean,
    val hasLocalAiReport: Boolean,
)

private data class SoSourceUi(
    val name: String,
    val path: String,
    val source: String,
    val abi: String,
    val architecture: String,
    val bits: Int,
    val size: Long,
    val stripped: Boolean,
)

private data class SoDetailUi(
    val workspaceId: String,
    val name: String,
    val path: String,
    val architecture: String,
    val bits: Int,
    val entryPoint: String,
    val stripped: Boolean,
    val hasDebugInfo: Boolean,
    val hasJniOnLoad: Boolean,
    val sectionCount: Int,
    val symbolCount: Int,
    val dynsymCount: Int,
    val stringCount: Int,
    val overview: JSONObject = JSONObject(),
)

private enum class DeepChatRole { USER, ASSISTANT }

private data class DeepChatMessage(
    val id: Long,
    val role: DeepChatRole,
    val text: String,
    val events: List<DeepAnalysisEvent> = emptyList(),
    val parts: List<RikkaPart> = emptyList(),
    val streaming: Boolean = false,
    val error: String = "",
)

private class AnalyzeUiState {
    var workspaces by mutableStateOf<List<WorkspaceUi>>(emptyList())
    var soSources by mutableStateOf<List<SoSourceUi>>(emptyList())
    var perSoDetail by mutableStateOf<Map<String, SoDetailUi>>(emptyMap())
    var expandedSoPath by mutableStateOf<String?>(null)
    var message by mutableStateOf("")
    var scanning by mutableStateOf(false)
    var analyzingSoPath by mutableStateOf<String?>(null)
    var scannedTreeUri by mutableStateOf<String?>(null)
    var deepAnalyzingPath by mutableStateOf<String?>(null)
    var deepEvents by mutableStateOf<List<DeepAnalysisEvent>>(emptyList())
    var deepReport by mutableStateOf("")
    var deepEvidencePreview by mutableStateOf("")
    var showDeepReport by mutableStateOf(false)
    var deepError by mutableStateOf("")
    var showDeepPanel by mutableStateOf(false)
    var deepTargetPath by mutableStateOf("")
    var deepInput by mutableStateOf("")
    var deepMessages by mutableStateOf<List<DeepChatMessage>>(emptyList())
    var restoreDeepReportOnAnalyzeEntry by mutableStateOf(false)
    var deepJob: Job? = null
}

@Composable
private fun IntegrityGate(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val activity = context as? Activity
    var result by remember { mutableStateOf(IntegrityGuard.verify(context.applicationContext)) }
    LaunchedEffect(result.trusted) {
        while (result.trusted) {
            delay(3_000)
            result = IntegrityGuard.verify(context.applicationContext)
        }
    }
    if (result.trusted) {
        content()
        return
    }
    var remaining by remember { mutableStateOf(10) }
    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1000)
            remaining--
        }
        activity?.let { IntegrityGuard.terminate(it) }
    }
    MaterialTheme(colorScheme = appleDarkColors()) {
        Box(Modifier.fillMaxSize().background(AppleColors.Dark.background), contentAlignment = Alignment.Center) {
            AlertDialog(
                onDismissRequest = {},
                containerColor = AppleColors.Dark.card,
                titleContentColor = AppleColors.Dark.label,
                textContentColor = AppleColors.Dark.secondaryLabel,
                title = { Text("应用完整性校验失败", fontWeight = FontWeight.SemiBold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("检测到当前安装包签名与官方发布签名不一致，或运行环境存在调试、注入、Hook 风险。为保护本地数据、MCP 服务和原生编辑能力，应用将在 $remaining 秒后退出。")
                        Text("原因: ${result.reason}", style = MaterialTheme.typography.bodySmall)
                        if (result.expected.isNotBlank()) Text("期望: ${result.expected.take(16)}...${result.expected.takeLast(16)}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        if (result.actual.isNotEmpty()) Text("实际: ${result.actual.joinToString { it.take(16) + "..." + it.takeLast(16) }}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        if (result.threats.isNotEmpty()) Text("威胁: ${result.threats.joinToString()}", style = MaterialTheme.typography.bodySmall)
                    }
                },
                confirmButton = {},
            )
        }
    }
}

private data class UiText(
    val zh: Boolean,
    val appTitle: String,
    val subtitle: String,
    val state: String,
    val running: String,
    val stopped: String,
    val power: String,
    val directory: String,
    val chooseDirectory: String,
    val noDirectory: String,
    val port: String,
    val links: String,
    val logs: String,
    val tools: String,
    val settings: String,
    val language: String,
    val theme: String,
    val keepAlive: String,
    val floating: String,
    val wakeLock: String,
    val predictiveBack: String,
    val battery: String,
    val permissions: String,
    val test: String,
    val copied: String,
    val externalProbe: String,
    val probeServiceUrl: String,
    val reachabilityHelp: String,
    val instructions: String,
    val instructionsBody: String,
    val disclaimer: String,
    val disclaimerBody: String,
    val about: String,
    val aboutBody: String,
    val joinQqGroup: String,
    val accept: String,
    val decline: String,
    val firstRunDisclaimerTitle: String,
    val externalProbeExample: String,
)

private fun localizedResources(context: Context, locale: java.util.Locale): android.content.res.Resources {
    val config = Configuration(context.resources.configuration).apply { setLocale(locale) }
    return context.createConfigurationContext(config).resources
}

private fun textFor(mode: String, context: Context): UiText {
    val forcedZh = mode == "zh"
    val forcedEn = mode == "en"
    val systemZh = Locale.getDefault().language == "zh"
    val zh = forcedZh || (!forcedEn && mode == "system" && systemZh)
    // When the user forces a language, override the resource configuration so
    // values-zh/ vs values/ resolves deterministically regardless of device locale.
    val res = when {
        forcedZh -> localizedResources(context, java.util.Locale.CHINESE)
        forcedEn -> localizedResources(context, java.util.Locale.ENGLISH)
        // system mode respects the device locale, including zh systems.
        systemZh -> localizedResources(context, java.util.Locale.CHINESE)
        else -> context.resources
    }
    fun s(id: Int): String = res.getString(id)
    return UiText(
        zh = zh,
        appTitle = s(R.string.app_title),
        subtitle = s(R.string.app_subtitle),
        state = s(R.string.state),
        running = s(R.string.running),
        stopped = s(R.string.stopped),
        power = s(R.string.power),
        directory = s(R.string.directory),
        chooseDirectory = s(R.string.choose_directory),
        noDirectory = s(R.string.no_directory),
        port = s(R.string.port),
        links = s(R.string.links),
        logs = s(R.string.logs),
        tools = s(R.string.toolset),
        settings = s(R.string.settings),
        language = s(R.string.language),
        theme = s(R.string.theme),
        keepAlive = s(R.string.keep_alive),
        floating = s(R.string.floating),
        wakeLock = s(R.string.wake_lock),
        predictiveBack = s(R.string.predictive_back),
        battery = s(R.string.battery),
        permissions = s(R.string.permissions),
        test = s(R.string.test),
        copied = s(R.string.copied),
        externalProbe = s(R.string.external_probe),
        probeServiceUrl = s(R.string.probe_service_url),
        reachabilityHelp = s(R.string.reachability_help),
        instructions = s(R.string.instructions),
        instructionsBody = s(R.string.instructions_body),
        disclaimer = s(R.string.disclaimer),
        disclaimerBody = s(R.string.disclaimer_body),
        about = s(R.string.about),
        aboutBody = s(R.string.about_body),
        joinQqGroup = s(R.string.join_qq_group),
        accept = s(R.string.accept),
        decline = s(R.string.decline),
        firstRunDisclaimerTitle = s(R.string.first_run_disclaimer_title),
        externalProbeExample = s(R.string.external_probe_example),
    )
}


@OptIn(ExperimentalMaterial3Api::class, ExperimentalAnimationApi::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun SoReverseApp() {
    val context = LocalContext.current
    val settings = remember { SettingsStore(context) }
    val appScope = rememberCoroutineScope()
    val deepService = remember { DeepAnalysisService(context.applicationContext) }
    val updateManager = remember { GitHubUpdateManager(context.applicationContext) }
    var availableRelease by remember { mutableStateOf<GitHubRelease?>(null) }
    var showUpdatePrompt by remember { mutableStateOf(false) }
    var tab by remember { mutableStateOf(MainTab.Service) }
    var settingsDest by remember { mutableStateOf(SettingsDest.Root) }
    var language by remember { mutableStateOf(settings.language) }
    var themeMode by remember { mutableStateOf(settings.themeMode) }
    var accentColor by remember { mutableStateOf(settings.accentColor) }
    var pureBlackDark by remember { mutableStateOf(settings.pureBlackDark) }
    var uiDensity by remember { mutableStateOf(settings.uiDensity) }
    var cornerStyle by remember { mutableStateOf(settings.cornerStyle) }
    var motionMode by remember { mutableStateOf(settings.motionMode) }
    var showAdvancedHome by remember { mutableStateOf(settings.showAdvancedHome) }
    var highContrast by remember { mutableStateOf(settings.highContrast) }
    var textScale by remember { mutableStateOf(settings.textScale) }
    var predictiveBack by remember { mutableStateOf(settings.predictiveBackEnabled) }
    var disclaimerAccepted by remember { mutableStateOf(settings.disclaimerAccepted) }
    val analyzeState = remember { AnalyzeUiState() }
    var pendingDeepLeave by remember { mutableStateOf<(() -> Unit)?>(null) }
    var backProgress by remember { mutableStateOf(0f) }
    val t = textFor(language, context)
    val dark = when (themeMode) {
        "dark" -> true
        "light" -> false
        else -> isSystemInDarkTheme()
    }
    val accent = AppPalette.accent(accentColor, dark)
    val colors = if (dark) appDarkColors(accent, pureBlackDark, highContrast) else appLightColors(accent, highContrast)
    val metrics = remember(uiDensity, cornerStyle) { uiMetrics(uiDensity, cornerStyle) }
    val typography = remember(textScale) { scaledTypography(textScaleFactor(textScale)) }
    val reduceMotion = when (motionMode) {
        "reduced" -> true
        "full" -> false
        else -> false
    }
    LaunchedEffect(Unit) {
        if (settings.autoCheckUpdates) {
            updateManager.check()
                .onSuccess { result ->
                    if (result is com.soreverse.mcp.core.UpdateCheckResult.Available) {
                        availableRelease = result.release
                        showUpdatePrompt = true
                    }
                }
                .onFailure { AppLog.w("Background update check failed: ${it.message}") }
        }
    }
    val inSettingsDetail = tab == MainTab.Settings && settingsDest != SettingsDest.Root
    val inAnalyzeDetail = tab == MainTab.Analyze && (analyzeState.showDeepReport || analyzeState.expandedSoPath != null)
    val inInternalDetail = inSettingsDetail || inAnalyzeDetail

    LaunchedEffect(tab) {
        if (tab == MainTab.Analyze && analyzeState.restoreDeepReportOnAnalyzeEntry) {
            analyzeState.restoreDeepReportOnAnalyzeEntry = false
            analyzeState.showDeepReport = true
        }
    }

    fun requestDeepLeave(action: () -> Unit) {
        if (tab == MainTab.Analyze && analyzeState.showDeepReport && analyzeState.deepAnalyzingPath != null) {
            pendingDeepLeave = action
        } else {
            action()
        }
    }

    fun closeInternalDetail() {
        when {
            inSettingsDetail -> settingsDest = SettingsDest.Root
            inAnalyzeDetail && analyzeState.showDeepReport -> requestDeepLeave { analyzeState.showDeepReport = false }
            inAnalyzeDetail -> analyzeState.expandedSoPath = null
        }
    }

    if (Build.VERSION.SDK_INT >= 34) {
        PredictiveBackHandler(enabled = inInternalDetail && predictiveBack) { progress ->
            try {
                progress.collect { event -> backProgress = event.progress }
                closeInternalDetail()
                backProgress = 0f
            } catch (_: CancellationException) {
                backProgress = 0f
            }
        }
    }

    LaunchedEffect(tab, settingsDest, analyzeState.expandedSoPath, analyzeState.showDeepReport, predictiveBack) {
        if (!inInternalDetail || !predictiveBack) backProgress = 0f
    }

    DisposableEffect(predictiveBack, tab, settingsDest, analyzeState.expandedSoPath, analyzeState.showDeepReport) {
        val callback = object : OnBackPressedCallback(inInternalDetail && (!predictiveBack || Build.VERSION.SDK_INT < 34)) {
            override fun handleOnBackPressed() {
                closeInternalDetail()
            }
        }
        (context as ComponentActivity).onBackPressedDispatcher.addCallback(callback)
        onDispose { callback.remove() }
    }

    androidx.compose.runtime.CompositionLocalProvider(
        LocalUiMetrics provides metrics,
        LocalReduceMotion provides reduceMotion,
    ) {
        MaterialTheme(colorScheme = colors, typography = typography) {
            Box(
                Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background),
            ) {
                // Soft ambient wash — depth without fake glass blobs.
                Box(
                    Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                listOf(
                                    MaterialTheme.colorScheme.primary.copy(alpha = if (dark) 0.10f else 0.06f),
                                    Color.Transparent,
                                    MaterialTheme.colorScheme.background,
                                ),
                            ),
                        ),
                )
                Scaffold(
                    containerColor = Color.Transparent,
                    contentWindowInsets = WindowInsets(0, 0, 0, 0),
                    bottomBar = {
                        FloatingDock(
                            tab = tab,
                            t = t,
                            onTab = {
                                if (it != tab) {
                                    requestDeepLeave {
                                        tab = it
                                        if (it != MainTab.Settings) settingsDest = SettingsDest.Root
                                    }
                                }
                            },
                        )
                    },
                ) { padding ->
                    Box(
                        Modifier
                            .padding(padding)
                            .fillMaxSize(),
                    ) {
                        val animMs = if (reduceMotion) 0 else 180
                        AnimatedContent(
                            targetState = tab,
                            transitionSpec = {
                                (fadeIn(tween(animMs)) + scaleIn(initialScale = 0.985f, animationSpec = tween(animMs))) togetherWith
                                    (fadeOut(tween((animMs * 0.75f).toInt().coerceAtLeast(0))) + scaleOut(targetScale = 0.99f, animationSpec = tween((animMs * 0.75f).toInt().coerceAtLeast(0))))
                            },
                            label = "main-nav",
                        ) { currentTab ->
                            when (currentTab) {
                                MainTab.Service -> ServiceTab(
                                    t = t,
                                    settings = settings,
                                    onOpenApkBridge = {
                                        tab = MainTab.Settings
                                        settingsDest = SettingsDest.ApkBridge
                                    },
                                    onOpenKeepAlive = {
                                        tab = MainTab.Settings
                                        settingsDest = SettingsDest.KeepAlive
                                    },
                                    onOpenTunnel = {
                                        tab = MainTab.Settings
                                        settingsDest = SettingsDest.Tunnel
                                    },
                                )
                                MainTab.Analyze -> AnalyzeTab(
                                    t = t,
                                    settings = settings,
                                    state = analyzeState,
                                    scope = appScope,
                                    deepService = deepService,
                                    backProgress = backProgress,
                                    onGoToService = { requestDeepLeave { tab = MainTab.Service } },
                                    onLeaveDeepReport = { requestDeepLeave { analyzeState.showDeepReport = false } },
                                )
                                MainTab.Logs -> LogsTab(t = t, settings = settings)
                                MainTab.Settings -> SettingsHub(
                                    modifier = Modifier,
                                    backProgress = backProgress,
                                    t = t,
                                    settings = settings,
                                    updateManager = updateManager,
                                    availableRelease = availableRelease,
                                    onRelease = { availableRelease = it },
                                    language = language,
                                    onLanguage = { language = it; settings.language = it },
                                    themeMode = themeMode,
                                    onTheme = { themeMode = it; settings.themeMode = it },
                                    accentColor = accentColor,
                                    onAccent = { accentColor = it; settings.accentColor = it },
                                    pureBlackDark = pureBlackDark,
                                    onPureBlack = { pureBlackDark = it; settings.pureBlackDark = it },
                                    uiDensity = uiDensity,
                                    onDensity = { uiDensity = it; settings.uiDensity = it },
                                    cornerStyle = cornerStyle,
                                    onCorner = { cornerStyle = it; settings.cornerStyle = it },
                                    motionMode = motionMode,
                                    onMotion = { motionMode = it; settings.motionMode = it },
                                    showAdvancedHome = showAdvancedHome,
                                    onShowAdvancedHome = { showAdvancedHome = it; settings.showAdvancedHome = it },
                                    highContrast = highContrast,
                                    onHighContrast = { highContrast = it; settings.highContrast = it },
                                    textScale = textScale,
                                    onTextScale = { textScale = it; settings.textScale = it },
                                    predictiveBack = predictiveBack,
                                    onPredictiveBack = { predictiveBack = it; settings.predictiveBackEnabled = it },
                                    dest = settingsDest,
                                    onDest = { settingsDest = it },
                                    onBack = { settingsDest = SettingsDest.Root },
                                )
                            }
                        }
                    }
                }
            }
            if (!disclaimerAccepted) {
                AlertDialog(
                    onDismissRequest = {},
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    title = { Text(t.firstRunDisclaimerTitle, fontWeight = FontWeight.SemiBold) },
                    text = { Text(t.disclaimerBody) },
                    confirmButton = {
                        Button(
                            onClick = {
                                settings.disclaimerAccepted = true
                                disclaimerAccepted = true
                            },
                            shape = RoundedCornerShape(LocalUiMetrics.current.controlRadius),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary,
                                contentColor = Color.White,
                            ),
                        ) { Text(t.accept) }
                    },
                    dismissButton = {
                        TextButton(onClick = { (context as? Activity)?.finish() }) { Text(t.decline) }
                    },
                )
            }
            pendingDeepLeave?.let { leave ->
                AlertDialog(
                    onDismissRequest = { pendingDeepLeave = null },
                    title = { Text(if (t.zh) "AI 分析仍在进行" else "AI analysis is still running") },
                    text = {
                        Text(
                            if (t.zh) {
                                "离开对话页后，可以让分析在后台继续；下次打开分析页时会恢复当前对话。也可以立即终止本次分析。"
                            } else {
                                "Continue the analysis in the background and restore this conversation next time you open Analyze, or stop this analysis now."
                            },
                        )
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            pendingDeepLeave = null
                            analyzeState.restoreDeepReportOnAnalyzeEntry = tab == MainTab.Analyze
                            leave()
                        }) { Text(if (t.zh) "后台继续" else "Continue in background") }
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            pendingDeepLeave = null
                            analyzeState.restoreDeepReportOnAnalyzeEntry = false
                            analyzeState.deepJob?.cancel(CancellationException("Stopped by user while leaving"))
                            leave()
                        }) { Text(if (t.zh) "终止分析" else "Stop analysis") }
                    },
                )
            }
            if (showUpdatePrompt && availableRelease != null) {
                val release = availableRelease!!
                AlertDialog(
                    onDismissRequest = { showUpdatePrompt = false },
                    title = { Text(if (t.zh) "发现新版本 ${release.tag}" else "Update ${release.tag} available") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(release.name, fontWeight = FontWeight.SemiBold)
                            if (release.notes.isNotBlank()) {
                                Text(release.notes.take(800), style = MaterialTheme.typography.bodySmall, maxLines = 12, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    },
                    dismissButton = { TextButton(onClick = { showUpdatePrompt = false }) { Text(if (t.zh) "稍后" else "Later") } },
                    confirmButton = {
                        TextButton(onClick = {
                            showUpdatePrompt = false
                            tab = MainTab.Settings
                            settingsDest = SettingsDest.Updates
                        }) { Text(if (t.zh) "查看更新" else "View update") }
                    },
                )
            }
        }
    }
}

private fun settingsTitle(t: UiText, dest: SettingsDest): String = when (dest) {
    SettingsDest.Root -> t.settings
    SettingsDest.ServiceConfig -> if (t.zh) "服务配置" else "Service Configuration"
    SettingsDest.Appearance -> if (t.zh) "外观与语言" else "Appearance"
    SettingsDest.KeepAlive -> t.keepAlive
    SettingsDest.Access -> if (t.zh) "MCP 访问控制" else "MCP Access"
    SettingsDest.Limits -> if (t.zh) "返回数量" else "Result Limits"
    SettingsDest.Export -> if (t.zh) "导出" else "Export"
    SettingsDest.Audit -> if (t.zh) "编辑校验与审计" else "Edit & Audit"
    SettingsDest.Tunnel -> if (t.zh) "Cloudflare 隧道" else "Cloudflare Tunnel"
    SettingsDest.ApkBridge -> if (t.zh) "APK MCP 桥接" else "APK MCP Bridge"
    SettingsDest.AiDeep -> if (t.zh) "AI 深度分析" else "AI Deep Analysis"
    SettingsDest.Updates -> if (t.zh) "版本更新" else "Software Update"
    SettingsDest.Probe -> t.externalProbe
    SettingsDest.ToolStats -> if (t.zh) "工具调用审计" else "Tool Call Audit"
    SettingsDest.TunnelStats -> if (t.zh) "隧道稳定性" else "Tunnel Stability"
    SettingsDest.Instructions -> t.instructions
    SettingsDest.Credits -> if (t.zh) "开源致谢" else "Credits"
    SettingsDest.Disclaimer -> t.disclaimer
    SettingsDest.About -> t.about
}

@Composable
private fun FloatingDock(tab: MainTab, t: UiText, onTab: (MainTab) -> Unit) {
    val items = listOf(
        Triple(MainTab.Service, Icons.Default.Home, if (t.zh) "控制" else "Console"),
        Triple(MainTab.Analyze, Icons.Default.Memory, if (t.zh) "分析" else "Analyze"),
        Triple(MainTab.Logs, Icons.Default.Terminal, t.logs),
        Triple(MainTab.Settings, Icons.Default.Settings, t.settings),
    )
    val dockShape = RoundedCornerShape(28.dp)
    Box(
        Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(horizontal = 20.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Row(
            Modifier
                .clip(dockShape)
                .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.94f))
                .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), dockShape)
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            items.forEach { (value, icon, label) ->
                val selected = tab == value
                val bg by animateFloatAsState(
                    targetValue = if (selected) 1f else 0f,
                    animationSpec = tween(durationMillis = 160),
                    label = "dock-sel",
                )
                Column(
                    Modifier
                        .clip(RoundedCornerShape(24.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f * bg))
                        .clickable { onTab(value) }
                        .padding(horizontal = 14.dp, vertical = 8.dp)
                        .width(58.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    Icon(
                        icon,
                        contentDescription = label,
                        tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                    Text(
                        label,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                    )
                }
            }
        }
    }
}

@Composable
private fun ScreenHeader(
    title: String,
    subtitle: String? = null,
    showBack: Boolean = false,
    onBack: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val metrics = LocalUiMetrics.current
    Row(
        Modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .padding(horizontal = metrics.pagePad, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (showBack && onBack != null) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = MaterialTheme.colorScheme.primary)
            }
        }
        Column(Modifier.weight(1f)) {
            Text(
                title,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
                letterSpacing = (-0.3).sp,
            )
            if (!subtitle.isNullOrBlank()) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        trailing?.invoke()
    }
}

@Composable
private fun GlassGroup(
    title: String? = null,
    footer: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.cardRadius)
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (!title.isNullOrBlank()) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 2.dp),
                fontWeight = FontWeight.SemiBold,
            )
        }
        Column(
            Modifier
                .fillMaxWidth()
                .clip(shape)
                .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
                .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)), shape)
                .padding(vertical = 2.dp),
            content = content,
        )
        if (!footer.isNullOrBlank()) {
            Text(
                footer,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 2.dp),
            )
        }
    }
}

@Composable
private fun GroupDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(start = 16.dp),
        thickness = 0.5.dp,
        color = MaterialTheme.colorScheme.outline.copy(alpha = 0.22f),
    )
}

@Composable
private fun NavRow(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null,
    iconTint: Color? = null,
    trailing: String? = null,
    onClick: (() -> Unit)? = null,
) {
    val metrics = LocalUiMetrics.current
    val resolvedTint = iconTint ?: MaterialTheme.colorScheme.primary
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 14.dp, vertical = metrics.rowPadV),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (icon != null) {
            Box(
                Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(resolvedTint.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, null, tint = resolvedTint, modifier = Modifier.size(18.dp))
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Medium)
            if (!subtitle.isNullOrBlank()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
        if (!trailing.isNullOrBlank()) {
            Text(trailing, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
        }
        if (onClick != null) {
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ToggleRow(text: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    val metrics = LocalUiMetrics.current
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(text, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.bodyLarge)
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = MaterialTheme.colorScheme.primary,
                uncheckedThumbColor = Color.White,
                uncheckedTrackColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f),
                uncheckedBorderColor = Color.Transparent,
            ),
        )
    }
}

@Composable
private fun NumberSettingRow(
    label: String,
    value: String,
    onValue: (String) -> Unit,
    onApply: (Int) -> Unit,
    suffix: String = "",
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
        OutlinedTextField(
            value = value,
            onValueChange = { onValue(it.filter(Char::isDigit).take(5)) },
            singleLine = true,
            suffix = if (suffix.isBlank()) null else ({ Text(suffix) }),
            shape = shape,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                focusedContainerColor = Color.Transparent,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            ),
            modifier = Modifier.width(116.dp),
        )
        TextButton(onClick = { value.toIntOrNull()?.let(onApply) }) { Text("OK") }
    }
}

@Composable
private fun DecimalSettingRow(
    label: String,
    value: String,
    suffix: String,
    supporting: String,
    onValue: (String) -> Unit,
    onApply: (Float) -> Unit,
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = metrics.rowPadV - 2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurface)
            OutlinedTextField(
                value = value,
                onValueChange = { raw ->
                    val filtered = raw.filter { it.isDigit() || it == '.' }
                    if (filtered.count { it == '.' } <= 1) onValue(filtered.take(5))
                },
                singleLine = true,
                suffix = { Text(suffix) },
                shape = shape,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.width(140.dp),
            )
            TextButton(onClick = { value.toFloatOrNull()?.let(onApply) }) { Text("OK") }
        }
        Text(
            supporting,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private data class RequestField(val key: String, val value: String)

private fun parseRequestFields(raw: String): List<RequestField> {
    val json = runCatching { JSONObject(raw.ifBlank { "{}" }) }.getOrNull() ?: return emptyList()
    return buildList {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val value = json.opt(key)
            add(RequestField(key, if (value == JSONObject.NULL) "null" else value?.toString().orEmpty()))
        }
    }
}

private fun serializeRequestFields(fields: List<RequestField>, typedValues: Boolean): String {
    val json = JSONObject()
    fields.filter { it.key.isNotBlank() }.forEach { field ->
        val value = field.value.trim()
        val parsed = if (!typedValues) {
            field.value
        } else {
            when {
                value.equals("null", true) -> JSONObject.NULL
                value.equals("true", true) -> true
                value.equals("false", true) -> false
                value.toLongOrNull() != null -> value.toLong()
                value.toDoubleOrNull() != null -> value.toDouble()
                value.startsWith("{") -> runCatching { JSONObject(value) }.getOrElse { field.value }
                value.startsWith("[") -> runCatching { JSONArray(value) }.getOrElse { field.value }
                else -> field.value
            }
        }
        json.put(field.key.trim(), parsed)
    }
    return json.toString()
}

@Composable
private fun RequestFieldsEditor(
    title: String,
    fields: List<RequestField>,
    keyHint: String,
    valueHint: String,
    emptyText: String,
    onChange: (List<RequestField>) -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(title, Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
            TextButton(onClick = { onChange(fields + RequestField("", "")) }) { Text("+") }
        }
        if (fields.isEmpty()) {
            Text(emptyText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        fields.forEachIndexed { index, field ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    value = field.key,
                    onValueChange = { next -> onChange(fields.toMutableList().also { it[index] = field.copy(key = next) }) },
                    label = { Text(keyHint) },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.weight(0.9f),
                )
                Text(":", color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(
                    value = field.value,
                    onValueChange = { next -> onChange(fields.toMutableList().also { it[index] = field.copy(value = next) }) },
                    label = { Text(valueHint) },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.weight(1.1f),
                )
                TextButton(onClick = { onChange(fields.filterIndexed { itemIndex, _ -> itemIndex != index }) }) { Text("−") }
            }
        }
    }
}

@Composable
private fun ChipRow(items: List<Pair<String, String>>, selected: String, onSelected: (String) -> Unit) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        items.forEach { (value, label) ->
            FilterChip(
                selected = selected == value,
                onClick = { onSelected(value) },
                label = { Text(label) },
                shape = RoundedCornerShape(999.dp),
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primary,
                    selectedLabelColor = Color.White,
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                    labelColor = MaterialTheme.colorScheme.onSurface,
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = selected == value,
                    borderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.28f),
                    selectedBorderColor = Color.Transparent,
                ),
            )
        }
    }
}

@Composable
private fun PrimaryActionButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    leading: ImageVector? = null,
    container: Color? = null,
) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    val resolved = container ?: MaterialTheme.colorScheme.primary
    Button(
        onClick = onClick,
        shape = shape,
        colors = ButtonDefaults.buttonColors(containerColor = resolved, contentColor = Color.White),
        modifier = modifier.height(50.dp),
    ) {
        if (leading != null) {
            Icon(leading, null)
            Spacer(Modifier.width(8.dp))
        }
        Text(text, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SecondaryActionButton(text: String, onClick: () -> Unit) {
    val metrics = LocalUiMetrics.current
    val shape = RoundedCornerShape(metrics.controlRadius)
    Button(
        onClick = onClick,
        shape = shape,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
            contentColor = MaterialTheme.colorScheme.primary,
        ),
        border = BorderStroke(0.5.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.28f)),
    ) { Text(text, fontWeight = FontWeight.Medium) }
}

@Composable
private fun PageScroll(content: @Composable ColumnScope.() -> Unit) {
    val metrics = LocalUiMetrics.current
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = metrics.pagePad, vertical = 8.dp)
            .padding(bottom = 12.dp),
        verticalArrangement = Arrangement.spacedBy(metrics.sectionGap),
        content = content,
    )
}

@Composable
private fun SettingsTile(
    title: String,
    subtitle: String,
    icon: ImageVector,
    tint: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(18.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(tint.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(18.dp))
        }
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.titleSmall)
        Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun ServiceTab(
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
    var apkConnected by remember { mutableStateOf(false) }
    var apkToolNames by remember { mutableStateOf<List<String>>(emptyList()) }
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
            val bridge = activeBridge(context)
            when {
                settings.apkMcpUrl.isNotBlank() -> bridge.probe().online
                settings.apkMcpAutoProbe -> bridge.autoDiscover(ApkMcpBridge.DEFAULT_PORT).online
                else -> false
            }
        }
        while (true) {
            running = McpForegroundService.isRunning()
            val typedPort = port.toIntOrNull() ?: settings.port
            portStatus = portStatusText(typedPort, running && typedPort == settings.port, t.zh)
            val ts = activeServer(context)?.tunnel?.status()
            val url = ts?.publicUrl?.takeIf { it.isNotBlank() && ts.state == CloudflareTunnelManager.State.RUNNING }
            if (url != quickPublicUrl) quickPublicUrl = url
            val liveBridge = activeServer(context)?.apkBridge
            val bridgeState = liveBridge?.state()
            apkToolNames = bridgeState?.tools?.map { it.name }.orEmpty()
            if (bridgeState?.online == true) {
                apkConnected = true
            } else if (settings.apkMcpAutoProbe) {
                apkConnected = withContext(Dispatchers.IO) {
                    val bridge = activeBridge(context)
                    val result = if (settings.apkMcpUrl.isNotBlank()) bridge.probe() else bridge.autoDiscover(ApkMcpBridge.DEFAULT_PORT)
                    result.online
                }
            } else if (liveBridge != null || settings.apkMcpUrl.isBlank()) {
                apkConnected = false
            }
            keepAliveReady = isKeepAliveReady(context, settings)
            delay(if (settings.apkMcpAutoProbe) 10_000 else 1_000)
        }
    }
    LaunchedEffect(t.zh, running, port) {
        val typedPort = port.toIntOrNull() ?: settings.port
        portStatus = portStatusText(typedPort, running && typedPort == settings.port, t.zh)
    }

    fun applyPort() {
        val nextPort = port.toIntOrNull()?.coerceIn(1024, 65535) ?: 8000
        port = nextPort.toString()
        val conflict = !isPortAvailable(nextPort, running && nextPort == settings.port)
        portStatus = portStatusText(nextPort, running, t.zh, conflict)
        if (conflict) return
        settings.port = nextPort
        endpoints = filteredEndpoints(context, settings, nextPort)
        if (running) {
            McpForegroundService.start(context)
            running = true
        }
    }
    fun startServerUnchecked() {
        val nextPort = port.toIntOrNull()?.coerceIn(1024, 65535) ?: 8000
        port = nextPort.toString()
        if (!isPortAvailable(nextPort, false)) {
            portStatus = portStatusText(nextPort, false, t.zh, conflict = true)
            Toast.makeText(context, if (t.zh) "端口被占用" else "Port is in use", Toast.LENGTH_SHORT).show()
            return
        }
        settings.port = nextPort
        settings.useDefaultWorkDir = treeUri == null
        McpForegroundService.start(context)
        running = true
        endpoints = filteredEndpoints(context, settings, settings.port)
    }

    val toggleServer = {
        if (running) {
            McpForegroundService.stop(context)
            running = false
        } else if (treeUri == null || !apkConnected || !keepAliveReady) {
            showStartDiagnosis = true
        } else {
            startServerUnchecked()
        }
    }

    val loopbackUrl = endpoints.firstOrNull { it.url.contains("127.0.0.1") }?.url ?: "http://127.0.0.1:${settings.port}/mcp"
    val lanUrl = endpoints.firstOrNull { !it.url.contains("127.0.0.1") && !it.url.contains("[::1]") }?.url.orEmpty()
    fun secured(url: String): String = if (settings.authEnabled && settings.accessToken.isNotBlank()) "$url?token=${settings.accessToken}" else url
    val workDirReady = treeUri != null
    val publicUrl = quickPublicUrl?.let { secured("$it/mcp") }.orEmpty()
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = if (t.zh) "控制台" else "Console",
            subtitle = if (t.zh) "本地 MCP 服务" else "Local MCP service",
            trailing = {
                TextButton(onClick = { showToolCatalog = true }) {
                    Text(if (t.zh) "工具列表" else "Tools", color = MaterialTheme.colorScheme.primary)
                }
            },
        )
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val compact = maxHeight < 700.dp
            val pad = LocalUiMetrics.current.pagePad
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(horizontal = pad)
                    .padding(bottom = 6.dp),
                verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 14.dp),
            ) {
                PowerSurface(
                    t = t,
                    running = running,
                    port = settings.port,
                    compact = compact,
                    onPower = toggleServer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(if (compact) 0.42f else 0.46f),
                )

                ReadinessStrip(
                    items = listOf(
                        ReadinessItem(
                            label = if (t.zh) "目录" else "Directory",
                            value = if (workDirReady) (if (t.zh) "已设置" else "Set") else (if (t.zh) "未设置" else "Not set"),
                            ok = workDirReady,
                            onClick = { setupPrompt = SetupTarget.Directory },
                        ),
                        ReadinessItem(
                            label = "APK MCP",
                            value = if (apkConnected) (if (t.zh) "已连接" else "Online") else (if (t.zh) "未连接" else "Offline"),
                            ok = apkConnected,
                            onClick = { setupPrompt = SetupTarget.ApkMcp },
                        ),
                        ReadinessItem(
                            label = if (t.zh) "保活" else "Keep-alive",
                            value = if (keepAliveReady) (if (t.zh) "已就绪" else "Ready") else (if (t.zh) "未就绪" else "Not ready"),
                            ok = keepAliveReady,
                            onClick = { setupPrompt = SetupTarget.KeepAlive },
                        ),
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )

                EndpointBoard(
                    t = t,
                    loopback = secured(loopbackUrl),
                    lan = lanUrl,
                    publicUrl = publicUrl,
                    onCopyLoopback = { copy(context, secured(loopbackUrl), t.copied) },
                    onCopyLan = { copy(context, secured(lanUrl), t.copied) },
                    onCopyPublic = { copy(context, publicUrl, t.copied) },
                    onOpenTunnel = onOpenTunnel,
                    compact = compact,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(if (compact) 0.58f else 0.54f),
                )
            }
        }
    }

    if (showToolCatalog) {
        AlertDialog(
            onDismissRequest = { showToolCatalog = false },
            title = { Text(if (t.zh) "MCP 工具列表" else "MCP Tool Catalog") },
            text = {
                Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                    ToolSummary(t, apkToolNames)
                }
            },
            confirmButton = { TextButton(onClick = { showToolCatalog = false }) { Text(if (t.zh) "完成" else "Done") } },
        )
    }

    setupPrompt?.let { target ->
        AlertDialog(
            onDismissRequest = { setupPrompt = null },
            title = { Text(setupPromptTitle(target, t.zh)) },
            text = {
                Text(setupPromptBody(target, t.zh, workDirReady, apkConnected, keepAliveReady))
            },
            confirmButton = {
                Button(onClick = {
                    setupPrompt = null
                    when (target) {
                        SetupTarget.Directory -> pickTree.launch(null)
                        SetupTarget.ApkMcp -> onOpenApkBridge()
                        SetupTarget.KeepAlive -> onOpenKeepAlive()
                    }
                }) { Text(if (t.zh) "继续设置" else "Continue setup") }
            },
            dismissButton = {
                TextButton(onClick = { setupPrompt = null }) { Text(if (t.zh) "暂不设置" else "Not now") }
            },
        )
    }
    if (showStartDiagnosis) {
        AlertDialog(
            onDismissRequest = { showStartDiagnosis = false },
            title = { Text(if (t.zh) "启动前诊断" else "Pre-start diagnosis") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DiagnosisLine(if (t.zh) "目录" else "Directory", workDirReady, if (t.zh) "未设置时无法扫描和打开 SO" else "SO scan/open will be unavailable")
                    DiagnosisLine("APK MCP", apkConnected, if (t.zh) "未连接时无法使用 APK 协同工具" else "APK bridge tools will be unavailable")
                    DiagnosisLine(if (t.zh) "保活" else "Keep-alive", keepAliveReady, if (t.zh) "后台运行可能被系统中断" else "The system may stop background work")
                    Text(if (t.zh) "仍要启动吗？" else "Start anyway?", fontWeight = FontWeight.SemiBold)
                }
            },
            confirmButton = {
                Button(onClick = { showStartDiagnosis = false; startServerUnchecked() }) { Text(if (t.zh) "仍然启动" else "Start anyway") }
            },
            dismissButton = {
                TextButton(onClick = { showStartDiagnosis = false }) { Text(if (t.zh) "返回设置" else "Review settings") }
            },
        )
    }
}

private data class ReadinessItem(
    val label: String,
    val value: String,
    val ok: Boolean,
    val onClick: () -> Unit,
)

@Composable
private fun PowerSurface(
    t: UiText,
    running: Boolean,
    port: Int,
    compact: Boolean,
    onPower: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val statusColor = if (running) statusSuccess() else MaterialTheme.colorScheme.primary
    val shape = RoundedCornerShape(if (compact) 28.dp else 32.dp)
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) 0.985f else 1f,
        animationSpec = tween(durationMillis = 120),
        label = "power-press",
    )
    val reduceMotion = LocalReduceMotion.current
    Box(
        modifier
            .graphicsLayer {
                scaleX = if (reduceMotion) 1f else scale
                scaleY = if (reduceMotion) 1f else scale
            }
            .clip(shape)
            .background(
                Brush.verticalGradient(
                    listOf(
                        statusColor.copy(alpha = if (running) 0.20f else 0.16f),
                        statusColor.copy(alpha = if (running) 0.08f else 0.05f),
                        MaterialTheme.colorScheme.surface.copy(alpha = 0.92f),
                    ),
                ),
            )
            .border(BorderStroke(1.dp, statusColor.copy(alpha = if (running) 0.34f else 0.22f)), shape)
            .clickable(interactionSource = interaction, indication = null, onClick = onPower)
            .padding(horizontal = if (compact) 18.dp else 22.dp, vertical = if (compact) 16.dp else 20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 14.dp),
        ) {
            Box(
                Modifier
                    .size(if (compact) 64.dp else 76.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.16f))
                    .border(BorderStroke(1.5.dp, statusColor.copy(alpha = 0.42f)), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    if (running) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = t.power,
                    tint = statusColor,
                    modifier = Modifier.size(if (compact) 30.dp else 34.dp),
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    if (running) (if (t.zh) "运行中" else "Running") else (if (t.zh) "已停止" else "Stopped"),
                    style = if (compact) MaterialTheme.typography.headlineMedium else MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    letterSpacing = (-0.8).sp,
                )
                Text(
                    if (running) {
                        if (t.zh) "端口 $port · 轻点停止" else "Port $port · tap to stop"
                    } else {
                        if (t.zh) "端口 $port · 轻点启动" else "Port $port · tap to start"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = statusColor,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

@Composable
private fun ReadinessStrip(
    items: List<ReadinessItem>,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(20.dp)
    Row(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.94f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), shape)
            .height(if (items.any { it.value.length > 8 }) 74.dp else 68.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items.forEachIndexed { index, item ->
            if (index > 0) {
                Box(
                    Modifier
                        .width(1.dp)
                        .fillMaxHeight()
                        .padding(vertical = 14.dp)
                        .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)),
                )
            }
            ReadinessCell(
                item = item,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight(),
            )
        }
    }
}

@Composable
private fun ReadinessCell(
    item: ReadinessItem,
    modifier: Modifier = Modifier,
) {
    val color = if (item.ok) statusSuccess() else MaterialTheme.colorScheme.error
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val alpha by animateFloatAsState(if (pressed) 0.10f else 0f, label = "ready-press")
    Column(
        modifier
            .background(color.copy(alpha = alpha))
            .clickable(interactionSource = interaction, indication = null, onClick = item.onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            item.label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(color))
            Text(
                item.value,
                style = MaterialTheme.typography.labelLarge,
                color = color,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun EndpointBoard(
    t: UiText,
    loopback: String,
    lan: String,
    publicUrl: String,
    onCopyLoopback: () -> Unit,
    onCopyLan: () -> Unit,
    onCopyPublic: () -> Unit,
    onOpenTunnel: () -> Unit,
    compact: Boolean,
    modifier: Modifier = Modifier,
) {
    val shape = RoundedCornerShape(if (compact) 22.dp else 26.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.94f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), shape)
            .padding(if (compact) 12.dp else 14.dp),
    ) {
        Text(
            if (t.zh) "连接" else "Connect",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
        )
        Spacer(Modifier.height(if (compact) 6.dp else 8.dp))
        EndpointCell(
            label = if (t.zh) "本机回环" else "Loopback",
            value = loopback,
            enabled = true,
            onCopy = onCopyLoopback,
            modifier = Modifier.weight(1f),
        )
        EndpointDivider()
        EndpointCell(
            label = if (t.zh) "局域网" else "LAN",
            value = lan.ifBlank { if (t.zh) "暂无可用局域网地址" else "No LAN address" },
            enabled = lan.isNotBlank(),
            onCopy = onCopyLan,
            modifier = Modifier.weight(1f),
        )
        EndpointDivider()
        EndpointCell(
            label = if (t.zh) "公网隧道" else "Public",
            value = publicUrl.ifBlank { if (t.zh) "未开启 · 轻点去设置" else "Off · tap to set up" },
            enabled = publicUrl.isNotBlank(),
            onCopy = onCopyPublic,
            onUnavailableClick = onOpenTunnel,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun EndpointDivider() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp)
            .height(1.dp)
            .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.12f)),
    )
}

@Composable
private fun EndpointCell(
    label: String,
    value: String,
    enabled: Boolean,
    onCopy: () -> Unit,
    modifier: Modifier = Modifier,
    onUnavailableClick: (() -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    Row(
        modifier
            .fillMaxWidth()
            .then(
                if (!enabled && onUnavailableClick != null) {
                    Modifier.clickable(interactionSource = interaction, indication = null, onClick = onUnavailableClick)
                } else {
                    Modifier
                },
            )
            .padding(horizontal = 4.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(
            Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(
                label,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = FontWeight.Medium,
            )
            Text(
                value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val chipShape = RoundedCornerShape(12.dp)
        Box(
            Modifier
                .clip(chipShape)
                .background(
                    if (enabled) MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                )
                .then(
                    if (enabled) Modifier.clickable(onClick = onCopy)
                    else if (onUnavailableClick != null) Modifier.clickable(onClick = onUnavailableClick)
                    else Modifier,
                )
                .padding(horizontal = 10.dp, vertical = 8.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (enabled) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp),
                )
            } else {
                Text(
                    if (onUnavailableClick != null) "→" else "—",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun SurfacePanel(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(LocalUiMetrics.current.cardRadius)
    Column(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .padding(14.dp),
        content = content,
    )
}

@Composable
private fun AddressRow(label: String, value: String, copyEnabled: Boolean, onCopy: () -> Unit, onUnavailableClick: (() -> Unit)? = null) {
    EndpointCell(
        label = label,
        value = value,
        enabled = copyEnabled,
        onCopy = onCopy,
        onUnavailableClick = onUnavailableClick,
    )
}

@Composable
private fun DiagnosisLine(label: String, ok: Boolean, detail: String) {
    val color = if (ok) statusSuccess() else MaterialTheme.colorScheme.error
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(Modifier.padding(top = 6.dp).size(8.dp).clip(CircleShape).background(color))
        Column {
            Text("$label · ${if (ok) "OK" else "!"}", fontWeight = FontWeight.SemiBold, color = color)
            if (!ok) Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun setupPromptTitle(target: SetupTarget, zh: Boolean): String = when (target) {
    SetupTarget.Directory -> if (zh) "工作目录状态" else "Work directory status"
    SetupTarget.ApkMcp -> if (zh) "APK MCP 状态" else "APK MCP status"
    SetupTarget.KeepAlive -> if (zh) "保活状态" else "Keep-alive status"
}

private fun setupPromptBody(target: SetupTarget, zh: Boolean, dirReady: Boolean, apkReady: Boolean, keepAliveReady: Boolean): String = when (target) {
    SetupTarget.Directory -> if (zh) {
        if (dirReady) "目录已设置。是否重新选择用于扫描、打开和导出 SO 的目录？" else "目录尚未设置，SO 浏览器和读盘工具将不可用。是否继续设置？"
    } else if (dirReady) "A directory is set. Choose a different SO workspace?" else "No directory is set. SO browser and disk tools will be unavailable. Continue setup?"
    SetupTarget.ApkMcp -> if (zh) {
        if (apkReady) "APK MCP 已连接。是否查看桥接地址、工具合并和探测设置？" else "APK MCP 尚未连接，MT 管理器协同工具不可用。是否继续设置？"
    } else if (apkReady) "APK MCP is connected. Review bridge settings?" else "APK MCP is not connected. MT Manager bridge tools are unavailable. Continue setup?"
    SetupTarget.KeepAlive -> if (zh) {
        if (keepAliveReady) "保活已就绪。是否查看唤醒锁、电池优化和开机自启设置？" else "保活尚未就绪，服务在后台可能被系统中断。是否继续设置？"
    } else if (keepAliveReady) "Keep-alive is ready. Review its settings?" else "Keep-alive is not ready. Background service may be stopped. Continue setup?"
}

@Composable
private fun QuickLinkCard(title: String, subtitle: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val shape = RoundedCornerShape(18.dp)
    Column(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.92f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.16f)), shape)
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ComboBanner(t: UiText, settings: SettingsStore, running: Boolean, onGoToApkMcpSettings: () -> Unit) {
    val context = LocalContext.current
    var comboState by remember { mutableStateOf<ApkMcpBridge.State?>(null) }
    LaunchedEffect(settings.apkMcpUrl, running) {
        if (settings.apkMcpUrl.isNotBlank()) {
            comboState = withContext(Dispatchers.IO) {
                activeBridge(context).let { if (!it.state().online) it.probe() else it.state() }
            }
        } else if (settings.apkMcpAutoProbe) {
            comboState = withContext(Dispatchers.IO) {
                activeBridge(context).autoDiscover(ApkMcpBridge.DEFAULT_PORT)
            }
        } else comboState = null
    }
    val st = comboState
    val online = st?.online == true
    val accent = if (online) statusSuccess() else statusWarning()
    val surface = accent.copy(alpha = 0.10f)
    val bodyColor = MaterialTheme.colorScheme.onSurfaceVariant
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surface)
            .border(BorderStroke(0.5.dp, accent.copy(alpha = 0.28f)), RoundedCornerShape(14.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(
                Modifier.size(34.dp).clip(CircleShape).background(accent.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Default.Link, null, tint = accent, modifier = Modifier.size(18.dp))
            }
            Text(
                if (online) {
                    if (t.zh) "MT 管理器协同已就绪：APK MCP + SO 辅助" else "MT Manager workflow ready"
                } else {
                    if (t.zh) "推荐开启 MT 管理器侧边栏 APK MCP 功能" else "Enable MT Manager APK MCP"
                },
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                style = MaterialTheme.typography.titleSmall,
            )
        }
        Text(
            when {
                online -> if (t.zh) "已接入 MT 管理器侧边栏 APK MCP 功能（${st?.tools?.size ?: 0} 个工具）。MT 管理器负责 APK 主流程，本应用补充 SO 辅助能力。" else "APK MCP connected (${st?.tools?.size ?: 0} tools)."
                settings.apkMcpUrl.isNotBlank() -> if (t.zh) "已配置 APK MCP 地址但当前离线。" else "APK MCP URL set but offline."
                else -> if (t.zh) "推荐配合 MT 管理器使用，并在设置中填入它的 /mcp 地址。" else "Recommended with MT Manager; enter its /mcp URL in Settings."
            },
            style = MaterialTheme.typography.bodySmall,
            color = bodyColor,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (settings.apkMcpUrl.isNotBlank()) {
                PrimaryActionButton(if (t.zh) "重新探测" else "Re-probe", { Thread { comboState = activeBridge(context).probe() }.start() }, container = accent)
            }
            SecondaryActionButton(if (t.zh) "去设置" else "Settings") { onGoToApkMcpSettings() }
        }
    }
}

@Composable
private fun AnalyzeTab(
    t: UiText,
    settings: SettingsStore,
    state: AnalyzeUiState,
    scope: CoroutineScope,
    deepService: DeepAnalysisService,
    backProgress: Float,
    onGoToService: () -> Unit,
    onLeaveDeepReport: () -> Unit,
) {
    val context = LocalContext.current
    val deepChatListState = rememberLazyListState()
    var followDeepOutput by remember { mutableStateOf(true) }
    val deepAtBottom by remember {
        derivedStateOf {
            val info = deepChatListState.layoutInfo
            val lastVisible = info.visibleItemsInfo.lastOrNull() ?: return@derivedStateOf true
            lastVisible.index >= info.totalItemsCount - 1 &&
                lastVisible.offset + lastVisible.size <= info.viewportEndOffset + 2
        }
    }
    var showWorkspaces by remember { mutableStateOf(false) }
    val pickTree = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }
            settings.treeUri = uri
            settings.useDefaultWorkDir = false
            EngineProvider.get(context).setWorkDirectory(uri)
            state.scannedTreeUri = null
        }
    }

    fun scan() {
        if (state.scanning) return
        state.scanning = true
        state.message = if (t.zh) "正在扫描 SO 文件…" else "Scanning SO files…"
        scope.launch {
            val loaded = withContext(Dispatchers.IO) { loadSoSources(context.applicationContext, settings.defaultLimit, t.zh) }
            state.soSources = loaded.first
            state.message = loaded.second
            state.perSoDetail = state.perSoDetail.filterKeys { path -> loaded.first.any { it.path == path } }
            state.expandedSoPath = state.expandedSoPath?.takeIf { path -> loaded.first.any { it.path == path } }
            state.scannedTreeUri = settings.treeUri?.toString() ?: "default"
            state.scanning = false
        }
    }

    fun startDeepAnalysis(path: String, request: String = "") {
        if (state.deepAnalyzingPath != null) return
        val history = if (request.isBlank()) {
            ""
        } else {
            state.deepMessages
                .takeLast(6)
                .joinToString("\n\n") { message ->
                    val role = if (message.role == DeepChatRole.USER) "用户" else "AI"
                    "$role: ${message.text}"
                }
                .takeLast(settings.aiHistorySoftLimit.coerceAtLeast(4_000))
        }
        val turnRequest = if (history.isBlank()) request else """以下是最近对话上下文：
$history

用户本轮问题：$request"""
        if (request.isBlank()) state.deepMessages = emptyList()
        state.deepTargetPath = path
        state.restoreDeepReportOnAnalyzeEntry = false
        state.showDeepPanel = false
        state.showDeepReport = true
        if (!McpForegroundService.isRunning()) {
            state.deepMessages = state.deepMessages + DeepChatMessage(
                id = System.currentTimeMillis(),
                role = DeepChatRole.ASSISTANT,
                text = "",
                error = if (t.zh) "请先开启 MCP 服务后再进行 AI 深度分析" else "Start the MCP service before AI deep analysis",
            )
            return
        }
        if (settings.aiApiKey.isBlank() || settings.aiEndpoint.isBlank() || settings.aiModel.isBlank()) {
            state.deepMessages = state.deepMessages + DeepChatMessage(
                id = System.currentTimeMillis(),
                role = DeepChatRole.ASSISTANT,
                text = "",
                error = if (t.zh) "请先在设置页配置 AI 端点、API Key 和模型" else "Configure AI endpoint, API key and model in Settings first",
            )
            return
        }
        val userText = request.ifBlank {
            if (t.zh) "请对 ${path.substringAfterLast('/')} 进行 AI 深度分析" else "Deeply analyze ${path.substringAfterLast('/')}"
        }
        val assistantId = System.currentTimeMillis() + 1
        state.deepMessages = state.deepMessages +
            DeepChatMessage(System.currentTimeMillis(), DeepChatRole.USER, userText) +
            DeepChatMessage(assistantId, DeepChatRole.ASSISTANT, "", streaming = true)
        state.deepAnalyzingPath = path
        state.deepEvents = emptyList()
        state.deepReport = ""
        state.deepEvidencePreview = ""
        state.deepError = ""
        deepService.resetReportDraft(resetWorkspace = request.isBlank())
        state.deepJob = scope.launch {
            val collector = launch {
                deepService.events.collect { event ->
                    if (event.kind != DeepAnalysisEvent.Kind.DONE && event.kind != DeepAnalysisEvent.Kind.TEXT) {
                        state.deepMessages = state.deepMessages.map { message ->
                            if (message.id == assistantId) message.copy(events = (message.events + event).takeLast(100)) else message
                        }
                    }
                }
            }
            val draftCollector = launch {
                deepService.partsDraft.collect { parts ->
                    if (parts.isNotEmpty()) {
                        val draft = parts.filterIsInstance<RikkaPart.Text>().joinToString("") { it.text }
                        state.deepReport = draft
                        state.deepMessages = state.deepMessages.map { message ->
                            if (message.id == assistantId) message.copy(text = draft, parts = parts) else message
                        }
                    }
                }
            }
            try {
                val result = deepService.analyze(path, settings, t.zh, turnRequest)
                result.onSuccess { report ->
                    state.deepReport = report
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(text = report, streaming = false) else message
                    }
                    deepService.workspaceId.value.takeIf(String::isNotBlank)?.let { workspaceId ->
                        DeepReportStore.save(
                            context.applicationContext,
                            workspaceId,
                            deepReportSnapshot(path, settings.aiModel, state.deepMessages),
                        )
                    }
                }.onFailure { err ->
                    val error = err.message ?: (if (t.zh) "AI 深度分析失败" else "AI deep analysis failed")
                    state.deepMessages = state.deepMessages.map { message ->
                        if (message.id == assistantId) message.copy(streaming = false, error = error) else message
                    }
                }
            } catch (_: CancellationException) {
                state.deepMessages = state.deepMessages.map { message ->
                    if (message.id == assistantId) message.copy(streaming = false) else message
                }
            } finally {
                collector.cancel()
                draftCollector.cancel()
                state.deepAnalyzingPath = null
                state.deepJob = null
            }
        }
    }

    LaunchedEffect(settings.treeUri?.toString(), settings.defaultLimit) {
        val treeKey = settings.treeUri?.toString()
        if (treeKey == null) {
            state.message = if (t.zh) "尚未选择目录，请先选择工作目录" else "No directory selected. Choose a work directory first."
        } else if (state.scannedTreeUri != treeKey && !state.scanning) {
            EngineProvider.get(context).let { engine -> settings.treeUri?.let(engine::setWorkDirectory) }
            scan()
        }
    }

    LaunchedEffect(deepChatListState.isScrollInProgress, deepAtBottom) {
        when {
            deepAtBottom -> followDeepOutput = true
            deepChatListState.isScrollInProgress && deepChatListState.lastScrolledBackward -> followDeepOutput = false
        }
    }

    LaunchedEffect(state.showDeepReport) {
        if (state.showDeepReport) followDeepOutput = true
    }

    val latestDeepMessage = state.deepMessages.lastOrNull()
    LaunchedEffect(
        state.deepMessages.size,
        latestDeepMessage?.text?.length,
        latestDeepMessage?.parts,
        latestDeepMessage?.events?.size,
        latestDeepMessage?.error,
        followDeepOutput,
    ) {
        if (state.showDeepReport && state.deepMessages.isNotEmpty() && followDeepOutput) {
            deepChatListState.scrollToItem(state.deepMessages.size)
        }
    }

    LaunchedEffect(deepChatListState, state.showDeepReport, followDeepOutput) {
        snapshotFlow {
            deepChatListState.layoutInfo.visibleItemsInfo.lastOrNull()?.let {
                Triple(it.index, it.offset, it.size)
            }
        }.distinctUntilChanged().collect {
            if (state.showDeepReport && followDeepOutput && !deepAtBottom && state.deepMessages.isNotEmpty()) {
                deepChatListState.scrollToItem(state.deepMessages.size)
            }
        }
    }

    LaunchedEffect(showWorkspaces) {
        if (showWorkspaces) state.workspaces = withContext(Dispatchers.IO) { loadWorkspaces(context.applicationContext) }
    }

    Box(Modifier.fillMaxSize()) {
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = if (t.zh) "分析" else "Analyze",
            subtitle = if (t.zh) "SO 文件程序基础分析" else "Program-level SO analysis",
            trailing = {
                TextButton(onClick = { showWorkspaces = true }) {
                    Icon(Icons.Default.Storage, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (t.zh) "工作区" else "Workspaces")
                }
            },
        )
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 12.dp),
        ) {
            Row(Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (state.scanning) (if (t.zh) "扫描中…" else "Scanning…") else if (state.soSources.isNotEmpty()) (if (t.zh) "共计 ${state.soSources.size} 个 SO 文件" else "${state.soSources.size} SO files") else (if (t.zh) "选择目录后自动扫描" else "Choose a directory to scan"),
                    Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (settings.treeUri == null) {
                    TextButton(onClick = { pickTree.launch(null) }) { Text(if (t.zh) "选择目录" else "Choose") }
                }
            }
            if (state.scanning) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = LocalUiMetrics.current.pagePad))
                Spacer(Modifier.height(8.dp))
            }
            if (state.analyzingSoPath != null) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = 14.dp))
                Text(
                    state.message.ifBlank { if (t.zh) "正在进行程序基础分析…" else "Running program analysis…" },
                    modifier = Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 6.dp),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            if (state.soSources.isEmpty()) {
                Text(
                    state.message.ifBlank { if (t.zh) "选择目录后会自动扫描 SO 文件。" else "SO files will be scanned automatically after choosing a directory." },
                    modifier = Modifier.padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                state.soSources.take(30).forEachIndexed { idx, src ->
                    if (idx > 0) GroupDivider()
                    Column {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            IndexedBadge(idx)
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(src.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("${if (t.zh) (if (src.source == "filesystem") "文件系统" else src.source) else src.source} ${src.abi} ${src.architecture}/${src.bits} ${formatBytes(src.size)}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                Text(src.path, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                TextButton(
                                    enabled = state.analyzingSoPath == null && state.deepAnalyzingPath == null,
                                    onClick = {
                                        if (state.perSoDetail[src.path] != null) {
                                            state.expandedSoPath = src.path
                                        } else {
                                            state.analyzingSoPath = src.path
                                            state.message = if (t.zh) "正在分析 ${src.name}…" else "Analyzing ${src.name}…"
                                            scope.launch {
                                                val detail = withContext(Dispatchers.IO) { openSoForUi(context.applicationContext, src.path, t.zh) }
                                                state.message = detail.second
                                                val opened = detail.first
                                                if (opened != null) {
                                                    state.perSoDetail = state.perSoDetail + (src.path to opened)
                                                    state.expandedSoPath = src.path
                                                } else {
                                                    state.expandedSoPath = null
                                                }
                                                state.analyzingSoPath = null
                                            }
                                        }
                                    },
                                ) {
                                    Text(
                                        when {
                                            state.analyzingSoPath == src.path -> if (t.zh) "分析中" else "Analyzing"
                                            else -> if (t.zh) "程序基础分析" else "Basic analysis"
                                        },
                                    )
                                }
                                TextButton(
                                    enabled = state.analyzingSoPath == null && state.deepAnalyzingPath == null,
                                    onClick = { startDeepAnalysis(src.path) },
                                ) {
                                    Text(
                                        if (state.deepAnalyzingPath == src.path) {
                                            if (t.zh) "AI 分析中" else "AI analyzing"
                                        } else {
                                            if (t.zh) "AI 深度分析" else "AI deep analysis"
                                        },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    state.expandedSoPath?.let(state.perSoDetail::get)?.let { selectedDetail ->
        Surface(
            modifier = Modifier.fillMaxSize().graphicsLayer {
                translationX = size.width * backProgress
                alpha = 1f - 0.12f * backProgress
            },
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(Modifier.fillMaxSize()) {
                ScreenHeader(
                    title = selectedDetail.name,
                    subtitle = if (t.zh) "ELF 程序基础分析" else "ELF basic analysis",
                    showBack = true,
                    onBack = { state.expandedSoPath = null },
                )
                Column(
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = LocalUiMetrics.current.pagePad)
                        .padding(bottom = 12.dp),
                ) {
                    ElfOverviewPanel(detail = selectedDetail, zh = t.zh, onCopy = { text -> copy(context, text, t.copied) })
                }
            }
        }
    }
    if (state.showDeepReport) {
        Surface(
            modifier = Modifier.fillMaxSize().graphicsLayer {
                translationX = size.width * backProgress
                alpha = 1f - 0.12f * backProgress
            },
            color = MaterialTheme.colorScheme.background,
        ) {
            Column(Modifier.fillMaxSize()) {
                ScreenHeader(
                    title = state.deepTargetPath.substringAfterLast('/').ifBlank { if (t.zh) "AI 深度分析" else "AI Deep Analysis" },
                    subtitle = if (state.deepAnalyzingPath != null) (if (t.zh) "正在生成" else "Generating") else settings.aiModel,
                    showBack = true,
                    onBack = onLeaveDeepReport,
                    trailing = {
                        if (state.deepMessages.isNotEmpty()) {
                            IconButton(onClick = {
                                state.deepMessages.lastOrNull { it.role == DeepChatRole.ASSISTANT }?.text?.let { copy(context, it, t.copied) }
                            }) {
                                Icon(Icons.Default.ContentCopy, if (t.zh) "复制最新回复" else "Copy latest reply")
                            }
                        }
                    },
                )
                LazyColumn(
                    state = deepChatListState,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = LocalUiMetrics.current.pagePad, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(22.dp),
                ) {
                    items(state.deepMessages, key = { it.id }) { message ->
                        DeepChatMessageItem(message = message, zh = t.zh)
                    }
                    item(key = "deep-output-bottom") {
                        Spacer(Modifier.height(1.dp))
                    }
                }
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = 0.96f),
                    tonalElevation = 1.dp,
                    shadowElevation = 3.dp,
                ) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .navigationBarsPadding()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.Bottom,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        OutlinedTextField(
                            value = state.deepInput,
                            onValueChange = { state.deepInput = it },
                            modifier = Modifier.weight(1f).heightIn(min = 50.dp, max = 132.dp),
                            placeholder = { Text(if (t.zh) "继续提问" else "Ask a follow-up", maxLines = 1) },
                            shape = RoundedCornerShape(18.dp),
                            maxLines = 5,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = MaterialTheme.colorScheme.surface,
                                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                                focusedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.55f),
                                unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.65f),
                            ),
                        )
                        FilledIconButton(
                            onClick = {
                                if (state.deepAnalyzingPath != null) {
                                    state.deepJob?.cancel(CancellationException("Stopped by user"))
                                } else {
                                    val input = state.deepInput.trim()
                                    if (input.isNotBlank() && state.deepTargetPath.isNotBlank()) {
                                        state.deepInput = ""
                                        startDeepAnalysis(state.deepTargetPath, input)
                                    }
                                }
                            },
                            enabled = state.deepAnalyzingPath != null || state.deepInput.isNotBlank(),
                            modifier = Modifier.size(50.dp),
                            shape = CircleShape,
                            colors = androidx.compose.material3.IconButtonDefaults.filledIconButtonColors(
                                containerColor = if (state.deepAnalyzingPath != null) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.primary
                                },
                            ),
                        ) {
                            Icon(
                                if (state.deepAnalyzingPath != null) Icons.Default.Stop else Icons.Default.ArrowUpward,
                                if (state.deepAnalyzingPath != null) (if (t.zh) "停止" else "Stop") else (if (t.zh) "发送" else "Send"),
                            )
                        }
                    }
                }
            }
        }
    }
    }
    if (showWorkspaces) {
        AlertDialog(
            onDismissRequest = { showWorkspaces = false },
            title = { Text(if (t.zh) "工作区" else "Workspaces") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (state.workspaces.isEmpty()) {
                        Text(if (t.zh) "暂无通过 MCP 打开的工作区。程序基础分析不会创建工作区。" else "No MCP workspaces. Basic analysis does not create workspaces.")
                    } else {
                        state.workspaces.forEach { ws ->
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(ws.name, fontWeight = FontWeight.SemiBold)
                                    Text("${ws.architecture}/${ws.bits} ${ws.abi}", style = MaterialTheme.typography.labelSmall)
                                }
                                if (ws.hasLocalAiReport) {
                                    TextButton(onClick = {
                                        DeepReportStore.load(context.applicationContext, ws.id)?.let { snapshot ->
                                            restoreDeepReport(state, snapshot)
                                            showWorkspaces = false
                                        }
                                    }) { Text(if (t.zh) "查看" else "View") }
                                }
                                TextButton(onClick = {
                                    EngineProvider.get(context).close(ws.id)
                                    DeepReportStore.remove(context.applicationContext, ws.id)
                                    state.workspaces = loadWorkspaces(context)
                                }) { Text(if (t.zh) "关闭" else "Close") }
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showWorkspaces = false }) { Text(if (t.zh) "完成" else "Done") } },
        )
    }
}

@Composable
private fun DeepChatMessageItem(message: DeepChatMessage, zh: Boolean) {
    if (message.role == DeepChatRole.USER) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Surface(
                modifier = Modifier.widthIn(max = 320.dp),
                shape = RoundedCornerShape(20.dp, 20.dp, 6.dp, 20.dp),
                color = MaterialTheme.colorScheme.primaryContainer,
            ) {
                Text(
                    message.text,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 11.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        return
    }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(
                Modifier.size(28.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text("AI", color = MaterialTheme.colorScheme.onPrimary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
            Text("SOMCP", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            if (message.streaming) CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
        }
        if (message.parts.isNotEmpty()) {
            DeepMessageParts(parts = message.parts, streaming = message.streaming, zh = zh)
        } else if (message.text.isNotBlank()) {
            MarkdownMessageContent(message.text, selectable = !message.streaming)
        } else if (message.streaming) {
            Text(if (zh) "正在分析并调用工具…" else "Analyzing and calling tools…", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
        }
        if (message.error.isNotBlank()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
            ) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Icon(
                        Icons.Default.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.size(20.dp),
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            if (zh) "本次分析未完成" else "Analysis incomplete",
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            message.error,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DeepMessageParts(parts: List<RikkaPart>, streaming: Boolean, zh: Boolean) {
    val groups = remember(parts) {
        buildList<List<RikkaPart>> {
            var process = mutableListOf<RikkaPart>()
            parts.forEach { part ->
                if (part is RikkaPart.Reasoning || part is RikkaPart.Tool) {
                    process += part
                } else {
                    if (process.isNotEmpty()) {
                        add(process)
                        process = mutableListOf()
                    }
                    add(listOf(part))
                }
            }
            if (process.isNotEmpty()) add(process)
        }
    }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        groups.forEachIndexed { index, group ->
            if (group.firstOrNull() is RikkaPart.Text) {
                MarkdownMessageContent((group.first() as RikkaPart.Text).text, selectable = !streaming)
            } else {
                DeepProcessTimeline(group, streaming && index == groups.lastIndex, zh)
            }
        }
    }
}

@Composable
private fun DeepProcessTimeline(parts: List<RikkaPart>, streaming: Boolean, zh: Boolean) {
    var expanded by remember(parts.firstOrNull()) { mutableStateOf(streaming) }
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
    ) {
        Row(
            Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                if (streaming) (if (zh) "正在思考" else "Thinking") else (if (zh) "思考过程" else "Thought process"),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(if (expanded) "−" else "+", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (expanded) {
            Column(Modifier.padding(start = 14.dp, end = 12.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                parts.forEach { part ->
                    when (part) {
                        is RikkaPart.Reasoning -> RikkaMarkdown(part.text, Modifier.fillMaxWidth())
                        is RikkaPart.Tool -> {
                            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(
                                    "● ${part.name}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (part.result == null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    if (part.result == null) (if (zh) "调用中" else "Running") else (if (zh) "已完成" else "Completed"),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        is RikkaPart.Text -> Unit
                    }
                }
            }
        }
    }
}

@Composable
private fun MarkdownMessageContent(markdown: String, selectable: Boolean) {
    RikkaMarkdown(content = markdown, modifier = Modifier.fillMaxWidth(), selectable = selectable)
}

@Composable
private fun LogsTab(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var logPaused by remember { mutableStateOf(false) }
    var logFilter by remember { mutableStateOf("all") }
    val logs = remember { mutableStateListOf<String>().also { list -> list.addAll(AppLog.snapshot().takeLast(120)) } }

    DisposableEffect(Unit) {
        val cap = settings.logMaxLines
        val onLine: (String) -> Unit = { line ->
            if (line == "__CLEAR__") {
                logs.clear()
            } else {
                logs.add(line)
                while (logs.size > cap) logs.removeAt(0)
            }
        }
        AppLog.addListener(onLine)
        onDispose { AppLog.removeListener(onLine) }
    }

    val visibleLogs = logs
        .filter { line ->
            when (logFilter) {
                "E" -> " E " in line
                "W" -> " W " in line
                "I" -> " I " in line
                else -> true
            }
        }
        .takeLast(settings.logMaxLines)

    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = t.logs,
            subtitle = if (logPaused) (if (t.zh) "已暂停自动跟随 · 日志仍在缓存" else "Auto-follow paused · still buffering") else (if (t.zh) "实时跟随 · ${visibleLogs.size} 行" else "Live follow · ${visibleLogs.size} lines"),
        )
        Column(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = LocalUiMetrics.current.pagePad),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            ChipRow(
                listOf("all" to if (t.zh) "全部" else "All", "I" to if (t.zh) "信息" else "Info", "W" to if (t.zh) "警告" else "Warnings", "E" to if (t.zh) "错误" else "Errors"),
                logFilter,
                { logFilter = it },
            )
        }
        ModernLogPanel(
            lines = visibleLogs,
            zh = t.zh,
            autoFollow = !logPaused,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(top = 8.dp),
        )
        Row(
            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface.copy(alpha = 0.96f)).padding(horizontal = LocalUiMetrics.current.pagePad, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LogActionButton(if (logPaused) if (t.zh) "继续" else "Resume" else if (t.zh) "暂停" else "Pause", if (logPaused) Icons.Default.PlayArrow else Icons.Default.Pause, Modifier.weight(1f)) { logPaused = !logPaused }
            LogActionButton(if (t.zh) "清空" else "Clear", Icons.Default.Delete, Modifier.weight(1f)) { AppLog.clear(); logs.clear() }
            LogActionButton(if (t.zh) "复制结果" else "Copy results", Icons.Default.ContentCopy, Modifier.weight(1f)) { copy(context, visibleLogs.joinToString("\n") { localizeLogLine(it, t.zh) }, t.copied) }
        }
    }
}

@Composable
private fun LogActionButton(label: String, icon: ImageVector, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    Row(
        modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(6.dp))
        Text(label, style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun SettingsHub(
    modifier: Modifier = Modifier,
    backProgress: Float,
    t: UiText,
    settings: SettingsStore,
    updateManager: GitHubUpdateManager,
    availableRelease: GitHubRelease?,
    onRelease: (GitHubRelease?) -> Unit,
    language: String,
    onLanguage: (String) -> Unit,
    themeMode: String,
    onTheme: (String) -> Unit,
    accentColor: String,
    onAccent: (String) -> Unit,
    pureBlackDark: Boolean,
    onPureBlack: (Boolean) -> Unit,
    uiDensity: String,
    onDensity: (String) -> Unit,
    cornerStyle: String,
    onCorner: (String) -> Unit,
    motionMode: String,
    onMotion: (String) -> Unit,
    showAdvancedHome: Boolean,
    onShowAdvancedHome: (Boolean) -> Unit,
    highContrast: Boolean,
    onHighContrast: (Boolean) -> Unit,
    textScale: String,
    onTextScale: (String) -> Unit,
    predictiveBack: Boolean,
    onPredictiveBack: (Boolean) -> Unit,
    dest: SettingsDest,
    onDest: (SettingsDest) -> Unit,
    onBack: () -> Unit,
) {
    Box(modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            ScreenHeader(
                title = t.settings,
                subtitle = if (t.zh) "常用在前，极客选项更深一层" else "Common first, power options deeper",
            )
            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = LocalUiMetrics.current.pagePad)
                    .padding(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(if (t.zh) "常用" else "Essentials", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile(if (t.zh) "服务配置" else "Service", if (t.zh) "目录 / 端口 / 地址 / 工具" else "Directory / port / URLs / tools", Icons.Default.Settings, MaterialTheme.colorScheme.primary, { onDest(SettingsDest.ServiceConfig) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "外观" else "Look", if (t.zh) "主题 / 强调色 / 密度" else "Theme / accent / density", Icons.Default.Tune, AppPalette.indigo, { onDest(SettingsDest.Appearance) }, Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile(if (t.zh) "AI 深度分析" else "AI Deep", if (t.zh) "端点 / Key / 模型" else "Endpoint / key / model", Icons.Default.Memory, AppPalette.indigo, { onDest(SettingsDest.AiDeep) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "保活" else "Keep-alive", if (t.zh) "唤醒锁 / 自启" else "Wake lock / boot", Icons.Default.PowerSettingsNew, AppPalette.green, { onDest(SettingsDest.KeepAlive) }, Modifier.weight(1f))
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingsTile("APK MCP", if (t.zh) "MT 管理器协同" else "MT Manager bridge", Icons.Default.Link, AppPalette.orange, { onDest(SettingsDest.ApkBridge) }, Modifier.weight(1f))
                    SettingsTile(if (t.zh) "隧道" else "Tunnel", if (t.zh) "公网暴露 / 保活" else "Public expose", Icons.Default.Cloud, AppPalette.purple, { onDest(SettingsDest.Tunnel) }, Modifier.weight(1f))
                }
                Text(if (t.zh) "引擎" else "Engine", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 4.dp))
                SurfacePanel {
                    NavRow(if (t.zh) "返回数量" else "Result limits", "limit / disasm / hexdump", Icons.Default.Analytics, onClick = { onDest(SettingsDest.Limits) })
                    GroupDivider()
                    NavRow(if (t.zh) "导出" else "Export", if (t.zh) "冲突策略与构建镜像" else "Conflict strategy", Icons.Default.Storage, onClick = { onDest(SettingsDest.Export) })
                    GroupDivider()
                    NavRow(if (t.zh) "编辑校验与审计" else "Edit & Audit", if (t.zh) "快照 / 并发 / 模拟" else "Snapshot / concurrency", Icons.Default.Security, onClick = { onDest(SettingsDest.Audit) })
                }

                Text(if (t.zh) "诊断与关于" else "Diagnostics & about", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 4.dp))
                SurfacePanel {
                    NavRow(if (t.zh) "版本更新" else "Software update", if (t.zh) "GitHub Releases / 自动检查" else "GitHub Releases / automatic checks", Icons.Default.Info, trailing = availableRelease?.tag.orEmpty(), onClick = { onDest(SettingsDest.Updates) })
                    GroupDivider()
                    NavRow(if (t.zh) "工具调用审计" else "Tool audit", if (t.zh) "调用统计与失败率" else "Stats and failures", Icons.Default.Analytics, onClick = { onDest(SettingsDest.ToolStats) })
                    GroupDivider()
                    NavRow(if (t.zh) "隧道稳定性" else "Tunnel stability", if (t.zh) "重启与探查" else "Restart and probe", Icons.Default.Cloud, onClick = { onDest(SettingsDest.TunnelStats) })
                    GroupDivider()
                    NavRow(t.instructions, if (t.zh) "推荐工作流" else "Workflow", Icons.Default.Description, onClick = { onDest(SettingsDest.Instructions) })
                    GroupDivider()
                    NavRow(if (t.zh) "开源致谢" else "Credits", if (t.zh) "依赖与参考" else "Dependencies", Icons.Default.Build, onClick = { onDest(SettingsDest.Credits) })
                    GroupDivider()
                    NavRow(t.disclaimer, icon = Icons.Default.Info, onClick = { onDest(SettingsDest.Disclaimer) })
                    GroupDivider()
                    NavRow(t.about, icon = Icons.Default.Info, onClick = { onDest(SettingsDest.About) })
                }
            }
        }
        if (dest != SettingsDest.Root) {
    Surface(
        modifier = Modifier.fillMaxSize().graphicsLayer {
            translationX = size.width * backProgress
            alpha = 1f - 0.12f * backProgress
        },
        color = MaterialTheme.colorScheme.background,
    ) {
    Column(Modifier.fillMaxSize()) {
        ScreenHeader(
            title = settingsTitle(t, dest),
            showBack = true,
            onBack = onBack,
        )
        Box(Modifier.fillMaxSize()) {
        when (dest) {
            SettingsDest.ServiceConfig -> SettingsServiceConfigPage(t, settings)
            SettingsDest.Appearance -> SettingsAppearancePage(t, language, onLanguage, themeMode, onTheme, accentColor, onAccent, pureBlackDark, onPureBlack, uiDensity, onDensity, cornerStyle, onCorner, motionMode, onMotion, showAdvancedHome, onShowAdvancedHome, highContrast, onHighContrast, textScale, onTextScale, predictiveBack, onPredictiveBack)
            SettingsDest.KeepAlive -> SettingsKeepAlivePage(t, settings)
            SettingsDest.Access -> SettingsAccessPage(t, settings)
            SettingsDest.Limits -> SettingsLimitsPage(t, settings)
            SettingsDest.Export -> SettingsExportPage(t, settings)
            SettingsDest.Audit -> SettingsAuditPage(t, settings)
            SettingsDest.Tunnel -> SettingsTunnelPage(t, settings)
            SettingsDest.ApkBridge -> SettingsApkBridgePage(t, settings)
            SettingsDest.AiDeep -> SettingsAiDeepPage(t, settings)
            SettingsDest.Updates -> SettingsUpdatesPage(t, settings, updateManager, availableRelease, onRelease)
            SettingsDest.Probe -> SettingsProbePage(t, settings)
            SettingsDest.ToolStats -> PageScroll { GlassGroup { Column(Modifier.padding(12.dp)) { ToolStatsSection(t, settings) } } }
            SettingsDest.TunnelStats -> PageScroll { GlassGroup { Column(Modifier.padding(12.dp)) { TunnelStatsSection(t) } } }
            SettingsDest.Instructions -> PageScroll {
                GlassGroup {
                    Text(t.instructionsBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium)
                    Text(
                        if (t.zh)
                            "详细流程：先在服务页启动 SO MCP；需要电脑访问时开启 Cloudflare Tunnel，或 adb forward tcp:8000 tcp:8000。客户端配置 /mcp 后按 so_open -> analyze_* -> read_disasm/search_* 分析；修改前 session_open，dryRun 预览后再 patch，最后 build_so 导出。"
                        else
                            "Start SO MCP on Service tab; enable Cloudflare Tunnel or adb forward for desktop access; then follow so_open -> analyze_* -> read/search -> session_open -> dryRun patch -> build_so.",
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            SettingsDest.Credits -> SettingsCreditsPage(t)
            SettingsDest.Disclaimer -> PageScroll { GlassGroup { Text(t.disclaimerBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium) } }
            SettingsDest.About -> {
                val aboutContext = LocalContext.current
                PageScroll {
                    GlassGroup {
                        Text(t.aboutBody, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodyMedium)
                        Row(Modifier.padding(14.dp)) {
                            PrimaryActionButton(t.joinQqGroup, { joinQqGroup(aboutContext, t.zh) }, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            }
            SettingsDest.Root -> Unit
        }
        }
    }
    }
    }
}
}

@Composable
private fun SettingsUpdatesPage(
    t: UiText,
    settings: SettingsStore,
    manager: GitHubUpdateManager,
    initialRelease: GitHubRelease?,
    onRelease: (GitHubRelease?) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var autoCheck by remember { mutableStateOf(settings.autoCheckUpdates) }
    var release by remember(initialRelease) { mutableStateOf(initialRelease) }
    var checking by remember { mutableStateOf(false) }
    var downloading by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var downloadedFile by remember { mutableStateOf<File?>(null) }
    var status by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }

    fun checkUpdates() {
        if (checking) return
        checking = true
        error = ""
        status = if (t.zh) "正在检查 GitHub Releases…" else "Checking GitHub Releases…"
        scope.launch {
            manager.check()
                .onSuccess { result ->
                    when (result) {
                        is com.soreverse.mcp.core.UpdateCheckResult.Available -> {
                            release = result.release
                            onRelease(result.release)
                            status = if (t.zh) "发现新版本 ${result.release.tag}" else "Version ${result.release.tag} is available"
                        }
                        com.soreverse.mcp.core.UpdateCheckResult.Current -> {
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
                Text(if (t.zh) "GitHub 正式发行版" else "Official GitHub releases", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
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
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.72f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(error, color = MaterialTheme.colorScheme.onErrorContainer, modifier = Modifier.padding(14.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
        release?.let { update ->
            GlassGroup {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(update.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(update.tag, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                    if (update.notes.isNotBlank()) MarkdownMessageContent(update.notes, selectable = true)
                    if (downloading) {
                        LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
                        Text("$progress%", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    PrimaryActionButton(
                        text = when {
                            downloadedFile != null -> if (t.zh) "安装更新" else "Install update"
                            downloading -> if (t.zh) "正在下载…" else "Downloading…"
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
                                error = ""
                                scope.launch {
                                    manager.download(update) { progress = it }
                                        .onSuccess {
                                            downloadedFile = it
                                            status = if (t.zh) "下载并校验完成，可以安装。" else "Download and verification complete. Ready to install."
                                        }
                                        .onFailure { error = it.message ?: if (t.zh) "下载失败" else "Download failed" }
                                    downloading = false
                                }
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

@Composable
private fun SettingsServiceConfigPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var treeUri by remember { mutableStateOf(settings.treeUri) }
    var portText by remember { mutableStateOf(settings.port.toString()) }
    var bindHost by remember { mutableStateOf(settings.bindHost) }
    var authEnabled by remember { mutableStateOf(settings.authEnabled) }
    var accessToken by remember { mutableStateOf(settings.accessToken) }
    var refreshKey by remember { mutableStateOf(0) }
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
    val endpoints = remember(settings.port, settings.bindHost, refreshKey) { filteredEndpoints(context, settings, settings.port) }
    val loopback = endpoints.firstOrNull { it.url.contains("127.0.0.1") }?.url ?: "http://127.0.0.1:${settings.port}/mcp"
    val preferred = endpoints.firstOrNull { !it.url.contains("127.0.0.1") && !it.url.contains("[::1]") }?.url ?: loopback
    val publicUrl = activeServer(context)?.tunnel?.status()?.publicUrl?.takeIf { it.isNotBlank() }
    PageScroll {
        GlassGroup(title = if (t.zh) "工作目录" else "Work directory") {
            NavRow(
                title = treeUri?.let(WorkDirectory::displayPath) ?: if (t.zh) "未设置" else "Not set",
                subtitle = if (t.zh) "用于扫描、打开、修改与导出 SO" else "Used to scan, open, edit and export SO files",
                icon = Icons.Default.FolderOpen,
                trailing = if (t.zh) "选择" else "Choose",
                onClick = { pickTree.launch(null) },
            )
        }
        GlassGroup(title = if (t.zh) "服务端口" else "Service port", footer = portStatusText(portText.toIntOrNull() ?: settings.port, McpForegroundService.isRunning(), t.zh)) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = { Text(t.port) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.weight(1f),
                )
                PrimaryActionButton(if (t.zh) "应用" else "Apply", {
                    val next = portText.toIntOrNull()?.coerceIn(1024, 65535) ?: settings.port
                    if (isPortAvailable(next, McpForegroundService.isRunning() && next == settings.port)) {
                        settings.port = next
                        portText = next.toString()
                        refreshKey++
                    } else {
                        Toast.makeText(context, if (t.zh) "端口不可用" else "Port unavailable", Toast.LENGTH_SHORT).show()
                    }
                })
            }
        }
        GlassGroup(title = if (t.zh) "全部地址" else "All endpoints") {
            endpoints.forEachIndexed { index, endpoint ->
                if (index > 0) GroupDivider()
                val display = displayEndpoint(endpoint, t.zh)
                val url = if (settings.authEnabled) "${endpoint.url}?token=${settings.accessToken}" else endpoint.url
                NavRow(display.first, url, Icons.Default.Link, trailing = if (t.zh) "复制" else "Copy", onClick = { copy(context, url, t.copied) })
            }
            if (publicUrl != null) {
                GroupDivider()
                NavRow(if (t.zh) "公网隧道" else "Public tunnel", "$publicUrl/mcp", Icons.Default.Public, trailing = if (t.zh) "复制" else "Copy", onClick = { copy(context, "$publicUrl/mcp", t.copied) })
            }
        }
        GlassGroup(title = if (t.zh) "客户端配置" else "Client configuration", footer = if (t.zh) "桌面客户端优先使用 NPX 或 UVX 配置" else "Prefer NPX or UVX for desktop clients") {
            Text(clientConfig(preferred, settings), modifier = Modifier.padding(14.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            FlowRow(Modifier.padding(horizontal = 14.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PrimaryActionButton(if (t.zh) "复制 NPX" else "Copy NPX", { copy(context, clientConfig(preferred, settings), t.copied) })
                PrimaryActionButton(if (t.zh) "复制 UVX" else "Copy UVX", { copy(context, clientConfigUvx(preferred, settings), t.copied) })
                SecondaryActionButton(if (t.zh) "复制直连" else "Copy direct") { copy(context, clientConfigDirect(preferred, settings), t.copied) }
            }
        }
        GlassGroup(title = if (t.zh) "访问控制" else "Access control", footer = if (t.zh) "修改端口、绑定地址或 Token 后需重启服务。" else "Restart the service after changing port, bind address, or token.") {
            ToggleRow(if (t.zh) "启用访问 Token" else "Require access token", authEnabled) {
                authEnabled = it
                settings.authEnabled = it
            }
            GroupDivider()
            Text(if (t.zh) "绑定地址" else "Bind address", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.labelMedium)
            ChipRow(
                listOf("0.0.0.0" to if (t.zh) "允许局域网" else "LAN", "127.0.0.1" to if (t.zh) "仅本机" else "Local only"),
                bindHost,
            ) {
                bindHost = it
                settings.bindHost = it
                refreshKey++
            }
            GroupDivider()
            OutlinedTextField(
                value = accessToken,
                onValueChange = { accessToken = it; settings.accessToken = it },
                label = { Text(if (t.zh) "访问 Token" else "Access token") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                PrimaryActionButton(if (t.zh) "重新生成" else "Regenerate", { accessToken = settings.resetAccessToken() })
                SecondaryActionButton(if (t.zh) "复制 Token" else "Copy token") { copy(context, accessToken, t.copied) }
            }
        }
    }
}

@Composable
private fun SettingsAppearancePage(
    t: UiText,
    language: String,
    onLanguage: (String) -> Unit,
    themeMode: String,
    onTheme: (String) -> Unit,
    accentColor: String,
    onAccent: (String) -> Unit,
    pureBlackDark: Boolean,
    onPureBlack: (Boolean) -> Unit,
    uiDensity: String,
    onDensity: (String) -> Unit,
    cornerStyle: String,
    onCorner: (String) -> Unit,
    motionMode: String,
    onMotion: (String) -> Unit,
    showAdvancedHome: Boolean,
    onShowAdvancedHome: (Boolean) -> Unit,
    highContrast: Boolean,
    onHighContrast: (Boolean) -> Unit,
    textScale: String,
    onTextScale: (String) -> Unit,
    predictiveBack: Boolean,
    onPredictiveBack: (Boolean) -> Unit,
) {
    PageScroll {
        SurfacePanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Text(if (t.zh) "实时预览" else "Live preview", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Box(
                    Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.16f))
                        .border(BorderStroke(2.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)), CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.PlayArrow, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
                }
                Text(if (t.zh) "强调色会立刻影响按钮与选中态" else "Accent updates buttons and selection immediately", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                PrimaryActionButton(if (t.zh) "示例主按钮" else "Sample primary", onClick = {}, modifier = Modifier.fillMaxWidth())
            }
        }
        GlassGroup(title = t.language) {
            ChipRow(listOf("system" to if (t.zh) "跟随系统" else "System", "zh" to "中文", "en" to "English"), language, onLanguage)
        }
        GlassGroup(title = t.theme) {
            ChipRow(listOf("system" to if (t.zh) "跟随系统" else "System", "light" to if (t.zh) "浅色" else "Light", "dark" to if (t.zh) "深色" else "Dark"), themeMode, onTheme)
        }
        GlassGroup(title = if (t.zh) "强调色" else "Accent") {
            ChipRow(
                listOf(
                    "blue" to if (t.zh) "蓝" else "Blue",
                    "teal" to if (t.zh) "青" else "Teal",
                    "indigo" to if (t.zh) "靛" else "Indigo",
                    "purple" to if (t.zh) "紫" else "Purple",
                    "green" to if (t.zh) "绿" else "Green",
                    "orange" to if (t.zh) "橙" else "Orange",
                    "red" to if (t.zh) "红" else "Red",
                    "mono" to if (t.zh) "灰" else "Mono",
                ),
                accentColor,
                onAccent,
            )
        }
        GlassGroup(title = if (t.zh) "布局密度" else "Density") {
            ChipRow(
                listOf(
                    "compact" to if (t.zh) "紧凑" else "Compact",
                    "comfortable" to if (t.zh) "舒适" else "Comfortable",
                    "spacious" to if (t.zh) "宽松" else "Spacious",
                ),
                uiDensity,
                onDensity,
            )
        }
        GlassGroup(title = if (t.zh) "圆角" else "Corners") {
            ChipRow(
                listOf(
                    "small" to if (t.zh) "小" else "Small",
                    "medium" to if (t.zh) "中" else "Medium",
                    "large" to if (t.zh) "大" else "Large",
                    "xlarge" to if (t.zh) "特大" else "XL",
                ),
                cornerStyle,
                onCorner,
            )
        }
        GlassGroup(title = if (t.zh) "字号" else "Text size") {
            ChipRow(
                listOf(
                    "normal" to if (t.zh) "标准" else "Normal",
                    "large" to if (t.zh) "大" else "Large",
                    "xlarge" to if (t.zh) "特大" else "XL",
                ),
                textScale,
                onTextScale,
            )
        }
        GlassGroup(title = if (t.zh) "动效" else "Motion") {
            ChipRow(
                listOf(
                    "system" to if (t.zh) "跟随系统" else "System",
                    "full" to if (t.zh) "标准" else "Full",
                    "reduced" to if (t.zh) "减弱" else "Reduced",
                ),
                motionMode,
                onMotion,
            )
        }
        GlassGroup {
            ToggleRow(if (t.zh) "纯黑深色背景" else "Pure black dark mode", pureBlackDark, onPureBlack)
            GroupDivider()
            ToggleRow(if (t.zh) "高对比" else "High contrast", highContrast, onHighContrast)
            GroupDivider()
            ToggleRow(t.predictiveBack, predictiveBack, onPredictiveBack)
        }
    }
}

@Composable
private fun SettingsKeepAlivePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var floating by remember { mutableStateOf(settings.floatingEnabled) }
    var wakeLock by remember { mutableStateOf(settings.wakeLockEnabled) }
    var bootAutoStart by remember { mutableStateOf(settings.bootAutoStart) }
    PageScroll {
        GlassGroup {
            ToggleRow(t.wakeLock, wakeLock) { wakeLock = it; settings.wakeLockEnabled = it }
            GroupDivider()
            ToggleRow(t.floating, floating) {
                if (it && !AndroidSettings.canDrawOverlays(context)) {
                    context.startActivity(Intent(AndroidSettings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:${context.packageName}")))
                }
                floating = it
                settings.floatingEnabled = it
                McpForegroundService.refreshFloating(context)
            }
            GroupDivider()
            ToggleRow(if (t.zh) "开机自启 MCP 服务" else "Autostart MCP service on boot", bootAutoStart) {
                bootAutoStart = it
                settings.bootAutoStart = it
            }
        }
        GlassGroup(footer = keepAliveAdvice(t.zh)) {
            Text(
                if (t.zh) "开机自启依赖系统允许自启动/后台启动，并与隧道自动启动相互独立。" else "Boot autostart depends on system permissions and is independent from tunnel auto-start.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(t.battery, { openBatterySettings(context) })
                SecondaryActionButton(t.permissions) {
                    context.startActivity(Intent(AndroidSettings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")))
                }
            }
        }
    }
}

@Composable
private fun SettingsAccessPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var bindHost by remember { mutableStateOf(settings.bindHost) }
    var authEnabled by remember { mutableStateOf(settings.authEnabled) }
    var accessToken by remember { mutableStateOf(settings.accessToken) }
    PageScroll {
        GlassGroup {
            ToggleRow(if (t.zh) "启用访问 token" else "Require access token", authEnabled) {
                authEnabled = it
                settings.authEnabled = it
            }
        }
        GlassGroup(title = if (t.zh) "绑定地址" else "Bind address") {
            ChipRow(
                listOf("0.0.0.0" to if (t.zh) "允许局域网" else "LAN", "127.0.0.1" to if (t.zh) "仅本机" else "Local only"),
                bindHost,
                {
                    bindHost = it
                    settings.bindHost = it
                },
            )
        }
        GlassGroup(footer = if (t.zh) "修改端口、绑定地址或 token 后，重启服务生效。" else "Restart the service after changing port, bind address, or token.") {
            OutlinedTextField(
                value = accessToken,
                onValueChange = { accessToken = it; settings.accessToken = it },
                label = { Text(if (t.zh) "访问 token" else "Access token") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(if (t.zh) "重新生成" else "Regenerate", { accessToken = settings.resetAccessToken() })
                SecondaryActionButton(if (t.zh) "复制 token" else "Copy token") { copy(context, accessToken, t.copied) }
            }
        }
    }
}

@Composable
private fun SettingsLimitsPage(t: UiText, settings: SettingsStore) {
    var defaultLimit by remember { mutableStateOf(settings.defaultLimit.toString()) }
    var stringLimit by remember { mutableStateOf(settings.stringLimit.toString()) }
    var disasmLimit by remember { mutableStateOf(settings.disasmLimit.toString()) }
    var disasmBytes by remember { mutableStateOf(settings.disasmMaxBytes.toString()) }
    var hexdumpBytes by remember { mutableStateOf(settings.hexdumpMaxBytes.toString()) }
    var maxRequestKb by remember { mutableStateOf(settings.maxRequestKb.toString()) }
    PageScroll {
        GlassGroup {
            NumberSettingRow(if (t.zh) "默认 limit" else "Default limit", defaultLimit, { defaultLimit = it }, { settings.defaultLimit = it }, if (t.zh) "条" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "字符串 limit" else "String limit", stringLimit, { stringLimit = it }, { settings.stringLimit = it }, if (t.zh) "条" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "反汇编指令数" else "Disasm instructions", disasmLimit, { disasmLimit = it }, { settings.disasmLimit = it }, if (t.zh) "条" else "insns")
            GroupDivider()
            NumberSettingRow(if (t.zh) "反汇编窗口" else "Disasm window", disasmBytes, { disasmBytes = it }, { settings.disasmMaxBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "Hexdump 读取量" else "Hexdump size", hexdumpBytes, { hexdumpBytes = it }, { settings.hexdumpMaxBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "请求上限" else "Request limit", maxRequestKb, { maxRequestKb = it }, { settings.maxRequestKb = it }, "KB")
        }
    }
}

@Composable
private fun SettingsExportPage(t: UiText, settings: SettingsStore) {
    var conflictStrategy by remember { mutableStateOf(settings.outputConflictStrategy) }
    var writePatchReport by remember { mutableStateOf(settings.writePatchReport) }
    var buildCopyToWorkDir by remember { mutableStateOf(settings.buildCopyToWorkDir) }
    var maxPatchBytes by remember { mutableStateOf(settings.maxPatchBytes.toString()) }
    var maxBuildOutputs by remember { mutableStateOf(settings.maxBuildOutputs.toString()) }
    PageScroll {
        GlassGroup(title = if (t.zh) "文件名冲突" else "File conflict") {
            ChipRow(listOf("rename" to if (t.zh) "自动改名" else "Auto rename", "overwrite" to if (t.zh) "覆盖" else "Overwrite"), conflictStrategy) {
                conflictStrategy = it
                settings.outputConflictStrategy = it
            }
        }
        GlassGroup {
            ToggleRow(if (t.zh) "导出 patch report" else "Write patch report", writePatchReport) {
                writePatchReport = it
                settings.writePatchReport = it
            }
            GroupDivider()
            ToggleRow(if (t.zh) "构建后镜像到工作目录" else "Mirror build to work dir", buildCopyToWorkDir) {
                buildCopyToWorkDir = it
                settings.buildCopyToWorkDir = it
            }
            GroupDivider()
            NumberSettingRow(if (t.zh) "单 patch 上限" else "Max patch size", maxPatchBytes, { maxPatchBytes = it }, { settings.maxPatchBytes = it }, "B")
            GroupDivider()
            NumberSettingRow(if (t.zh) "构建产物列表上限" else "Max build outputs", maxBuildOutputs, { maxBuildOutputs = it }, { settings.maxBuildOutputs = it }, if (t.zh) "项" else "items")
        }
    }
}

@Composable
private fun SettingsAuditPage(t: UiText, settings: SettingsStore) {
    var autoSnapshotBeforeEdit by remember { mutableStateOf(settings.autoSnapshotBeforeEdit) }
    var auditLogEnabled by remember { mutableStateOf(settings.auditLogEnabled) }
    var auditPersist by remember { mutableStateOf(settings.auditPersist) }
    var toolStatsPersist by remember { mutableStateOf(settings.toolStatsPersist) }
    var maxConcurrentTools by remember { mutableStateOf(settings.maxConcurrentTools.toString()) }
    var maxSnapshots by remember { mutableStateOf(settings.maxSnapshots.toString()) }
    var maxCompareRanges by remember { mutableStateOf(settings.maxCompareRanges.toString()) }
    var maxAudits by remember { mutableStateOf(settings.maxAudits.toString()) }
    var logMaxLines by remember { mutableStateOf(settings.logMaxLines.toString()) }
    var collectToolStats by remember { mutableStateOf(settings.collectToolStats) }
    var requestTimeoutMs by remember { mutableStateOf(settings.requestTimeoutMs.toString()) }
    var emulationEnabled by remember { mutableStateOf(settings.emulationEnabled) }
    var toolResultMaxChars by remember { mutableStateOf(settings.toolResultMaxChars.toString()) }
    var toolCallRateLimitPerMin by remember { mutableStateOf(settings.toolCallRateLimitPerMin.toString()) }
    var disabledTools by remember { mutableStateOf(settings.disabledTools) }
    PageScroll {
        GlassGroup {
            ToggleRow(if (t.zh) "编辑前自动快照" else "Auto-snapshot before edit", autoSnapshotBeforeEdit) { autoSnapshotBeforeEdit = it; settings.autoSnapshotBeforeEdit = it }
            GroupDivider()
            ToggleRow(if (t.zh) "启用审计日志" else "Enable audit log", auditLogEnabled) { auditLogEnabled = it; settings.auditLogEnabled = it }
            GroupDivider()
            ToggleRow(if (t.zh) "审计持久化到磁盘" else "Persist audit to disk", auditPersist) { auditPersist = it; settings.auditPersist = it }
            GroupDivider()
            ToggleRow(if (t.zh) "收集工具调用统计" else "Collect tool stats", collectToolStats) { collectToolStats = it; settings.collectToolStats = it }
            GroupDivider()
            ToggleRow(if (t.zh) "持久化工具统计" else "Persist tool stats", toolStatsPersist) {
                toolStatsPersist = it
                settings.toolStatsPersist = it
                com.soreverse.mcp.core.ToolStats.setPersistEnabled(it)
            }
            GroupDivider()
            ToggleRow(if (t.zh) "启用模拟执行 (Unidbg)" else "Enable emulation (Unidbg)", emulationEnabled) { emulationEnabled = it; settings.emulationEnabled = it }
        }
        GlassGroup {
            NumberSettingRow(if (t.zh) "重型工具并发上限" else "Heavy tool concurrency cap", maxConcurrentTools, { maxConcurrentTools = it }, { settings.maxConcurrentTools = it }, if (t.zh) "个" else "tasks")
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大快照数" else "Max snapshots", maxSnapshots, { maxSnapshots = it }, { settings.maxSnapshots = it }, if (t.zh) "个" else "items")
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大审计文件数" else "Max audit files", maxAudits, { maxAudits = it }, { settings.maxAudits = it }, if (t.zh) "个" else "files")
            GroupDivider()
            NumberSettingRow(if (t.zh) "diff 最大范围数" else "Max diff ranges", maxCompareRanges, { maxCompareRanges = it }, { settings.maxCompareRanges = it }, if (t.zh) "段" else "ranges")
            GroupDivider()
            NumberSettingRow(if (t.zh) "日志显示上限" else "Max log lines", logMaxLines, { logMaxLines = it }, { settings.logMaxLines = it }, if (t.zh) "行" else "lines")
            GroupDivider()
            NumberSettingRow(if (t.zh) "请求超时" else "Request timeout", requestTimeoutMs, { requestTimeoutMs = it }, { settings.requestTimeoutMs = it }, "ms")
            GroupDivider()
            NumberSettingRow(if (t.zh) "工具结果上限" else "Tool result limit", toolResultMaxChars, { toolResultMaxChars = it }, { settings.toolResultMaxChars = it }, if (t.zh) "字符" else "chars")
            GroupDivider()
            NumberSettingRow(if (t.zh) "工具调用频率限制" else "Tool call rate limit", toolCallRateLimitPerMin, { toolCallRateLimitPerMin = it }, { settings.toolCallRateLimitPerMin = it }, if (t.zh) "次/分" else "/min")
        }
        GlassGroup {
            OutlinedTextField(
                value = disabledTools,
                onValueChange = { disabledTools = it; settings.disabledTools = it },
                label = { Text(if (t.zh) "禁用工具列表(逗号分隔)" else "Disabled tools (comma-separated)") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            Text(
                if (t.zh) "启用模拟后允许 emulate_call / emulate_dump 验证补丁语义。" else "Emulation enables emulate_call / emulate_dump for patch validation.",
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SettingsTunnelPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var tunnelMode by remember { mutableStateOf(settings.tunnelMode) }
    var tunnelAutoStart by remember { mutableStateOf(settings.tunnelAutoStart) }
    var tunnelPort by remember { mutableStateOf(settings.tunnelTargetPort.toString()) }
    var namedToken by remember { mutableStateOf(settings.tunnelNamedToken) }
    var tunnelProtocol by remember { mutableStateOf(settings.tunnelProtocol) }
    var edgeIpVersion by remember { mutableStateOf(settings.tunnelEdgeIpVersion) }
    var tunnelLogLevel by remember { mutableStateOf(settings.tunnelLogLevel) }
    var tunnelReconnect by remember { mutableStateOf(settings.tunnelReconnect) }
    var tunnelKeepAlive by remember { mutableStateOf(settings.tunnelKeepAlive) }
    var keepaliveInterval by remember { mutableStateOf(settings.tunnelKeepaliveIntervalSec.toString()) }
    var reconnectBackoff by remember { mutableStateOf(settings.tunnelReconnectBackoffSec.toString()) }
    var tunnelStatus by remember { mutableStateOf<CloudflareTunnelManager.TunnelStatus?>(null) }
    var showExport by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        tunnelStatus = tunnelStatusOf(context)
        while (true) {
            delay(3_000)
            tunnelStatus = tunnelStatusOf(context)
        }
    }
    val stateColor = when (tunnelStatus?.state) {
        CloudflareTunnelManager.State.RUNNING -> AppleColors.systemGreen
        CloudflareTunnelManager.State.STARTING -> AppleColors.systemOrange
        CloudflareTunnelManager.State.FAILED -> AppleColors.systemRed
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    PageScroll {
        GlassGroup(title = if (t.zh) "状态" else "Status") {
            Text("${if (t.zh) "隧道状态" else "Tunnel state"}: ${tunnelStatus?.state?.name ?: "STOPPED"}", color = stateColor, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(14.dp))
            if (tunnelStatus?.message?.isNotBlank() == true) {
                Text(tunnelStatus!!.message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp))
            }
            tunnelStatus?.publicUrl?.takeIf { it.isNotBlank() }?.let { url ->
                GroupDivider()
                NavRow(url, if (t.zh) "点击复制公网地址" else "Tap to copy public URL", Icons.Default.Public, onClick = { copy(context, url, t.copied) })
                if (settings.authEnabled && settings.accessToken.isNotBlank() && url.startsWith("https://")) {
                    GroupDivider()
                    val full = "$url/mcp?token=${settings.accessToken}"
                    NavRow(if (t.zh) "带 token 的 MCP 链接" else "MCP URL with token", full, Icons.Default.Link, onClick = { copy(context, full, t.copied) })
                }
            }
        }
        GlassGroup(title = if (t.zh) "模式" else "Mode", footer = if (t.zh) "临时隧道无需账号，URL 重启变化；永久隧道需 Cloudflare Tunnel token。" else "Quick tunnel needs no account; named tunnel needs a Cloudflare token.") {
            ChipRow(
                listOf("off" to if (t.zh) "关闭" else "Off", "quick" to if (t.zh) "临时隧道" else "Quick", "named" to if (t.zh) "永久隧道" else "Named"),
                tunnelMode,
            ) { tunnelMode = it; settings.tunnelMode = it }
            if (tunnelMode == "named") {
                OutlinedTextField(
                    value = namedToken,
                    onValueChange = { namedToken = it; settings.tunnelNamedToken = it },
                    label = { Text(if (t.zh) "Tunnel token" else "Tunnel token") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    ),
                    modifier = Modifier.fillMaxWidth().padding(14.dp),
                )
            }
        }
        GlassGroup(title = if (t.zh) "传输" else "Transport") {
            NumberSettingRow(if (t.zh) "代理目标端口" else "Proxy target port", tunnelPort, { tunnelPort = it }, { settings.tunnelTargetPort = it }, if (t.zh) "端口号" else "port")
            GroupDivider()
            Text(if (t.zh) "传输协议" else "Protocol", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("auto" to "Auto", "http2" to "HTTP/2", "quic" to "QUIC"), tunnelProtocol) { tunnelProtocol = it; settings.tunnelProtocol = it }
            GroupDivider()
            Text(if (t.zh) "边缘 IP 版本" else "Edge IP version", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("4" to "IPv4", "6" to "IPv6", "auto" to if (t.zh) "自动" else "Auto"), edgeIpVersion) { edgeIpVersion = it; settings.tunnelEdgeIpVersion = it }
            GroupDivider()
            Text(if (t.zh) "隧道日志级别" else "Tunnel log level", modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            ChipRow(listOf("info" to "Info", "debug" to "Debug", "warn" to "Warn", "error" to "Error"), tunnelLogLevel) { tunnelLogLevel = it; settings.tunnelLogLevel = it }
        }
        GlassGroup {
            ToggleRow(if (t.zh) "随服务自动启动" else "Auto-start with service", tunnelAutoStart) { tunnelAutoStart = it; settings.tunnelAutoStart = it }
            GroupDivider()
            ToggleRow(if (t.zh) "断线自动重连" else "Auto reconnect", tunnelReconnect) { tunnelReconnect = it; settings.tunnelReconnect = it }
            GroupDivider()
            ToggleRow(if (t.zh) "隧道保活" else "Tunnel keepalive", tunnelKeepAlive) { tunnelKeepAlive = it; settings.tunnelKeepAlive = it }
            GroupDivider()
            NumberSettingRow(if (t.zh) "保活探测间隔" else "Probe interval", keepaliveInterval, { keepaliveInterval = it }, {
                settings.tunnelKeepaliveIntervalSec = it.coerceIn(5, 300)
                keepaliveInterval = settings.tunnelKeepaliveIntervalSec.toString()
            }, if (t.zh) "秒" else "s")
            GroupDivider()
            NumberSettingRow(if (t.zh) "重连退避" else "Reconnect backoff", reconnectBackoff, { reconnectBackoff = it }, {
                settings.tunnelReconnectBackoffSec = it.coerceIn(1, 60)
                reconnectBackoff = settings.tunnelReconnectBackoffSec.toString()
            }, if (t.zh) "秒" else "s")
        }
        GlassGroup {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(14.dp)) {
                PrimaryActionButton(if (t.zh) "启动" else "Start", {
                    val mode = if (tunnelMode == "named") CloudflareTunnelManager.Mode.NAMED else CloudflareTunnelManager.Mode.QUICK
                    val tunnel = activeTunnel(context)
                    if (tunnel == null) {
                        Toast.makeText(context, if (t.zh) "请先启动 MCP 服务器总开关" else "Turn on the MCP server master switch first", Toast.LENGTH_SHORT).show()
                    } else {
                        Thread { tunnel.start(settings.tunnelTargetPort, mode, namedToken) }.start()
                        Toast.makeText(context, if (t.zh) "隧道启动中…" else "Starting tunnel…", Toast.LENGTH_SHORT).show()
                    }
                })
                SecondaryActionButton(if (t.zh) "停止" else "Stop") {
                    val tunnel = activeTunnel(context)
                    if (tunnel == null) {
                        Toast.makeText(context, if (t.zh) "服务器未运行，无需停止隧道" else "Server not running, nothing to stop", Toast.LENGTH_SHORT).show()
                    } else {
                        Thread { tunnel.stop() }.start()
                    }
                }
                SecondaryActionButton(if (t.zh) "刷新状态" else "Refresh") { tunnelStatus = tunnelStatusOf(context) }
                SecondaryActionButton(if (t.zh) "导出配置" else "Export") { showExport = true }
                SecondaryActionButton(if (t.zh) "导入配置" else "Import") { showImport = true; importText = "" }
            }
        }
        val history = settings.tunnelHistoryUrls.split('\n').map { it.trim() }.filter { it.isNotBlank() }
        if (history.isNotEmpty()) {
            GlassGroup(title = if (t.zh) "历史隧道 URL" else "History tunnel URLs") {
                history.take(5).forEachIndexed { idx, h ->
                    if (idx > 0) GroupDivider()
                    NavRow(h, onClick = { copy(context, h, t.copied) })
                }
            }
        }
    }
    if (showExport) {
        val yaml = buildString {
            appendLine("# SOMCP tunnel config (token masked)")
            appendLine("mode: ${settings.tunnelMode}")
            appendLine("protocol: ${settings.tunnelProtocol}")
            appendLine("edgeIpVersion: ${settings.tunnelEdgeIpVersion}")
            appendLine("targetPort: ${settings.tunnelTargetPort}")
            appendLine("logLevel: ${settings.tunnelLogLevel}")
            appendLine("autoStart: ${settings.tunnelAutoStart}")
            appendLine("reconnect: ${settings.tunnelReconnect}")
            appendLine("keepAlive: ${settings.tunnelKeepAlive}")
            appendLine("keepaliveIntervalSec: ${settings.tunnelKeepaliveIntervalSec}")
            appendLine("reconnectBackoffSec: ${settings.tunnelReconnectBackoffSec}")
            appendLine("token: ${maskToken(settings.tunnelNamedToken)}")
        }
        AlertDialog(
            onDismissRequest = { showExport = false },
            title = { Text(if (t.zh) "导出配置（token 已脱敏）" else "Export config (token masked)") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text(yaml, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            },
            confirmButton = {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { copy(context, yaml, t.copied) }) { Text(if (t.zh) "复制" else "Copy") }
                    TextButton(onClick = { showExport = false }) { Text(if (t.zh) "关闭" else "Close") }
                }
            },
        )
    }
    if (showImport) {
        AlertDialog(
            onDismissRequest = { showImport = false },
            title = { Text(if (t.zh) "导入配置" else "Import config") },
            text = {
                Column {
                    Text(if (t.zh) "粘贴导出的 YAML（token 行可选）。" else "Paste exported YAML (token optional).", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(value = importText, onValueChange = { importText = it }, modifier = Modifier.fillMaxWidth().height(160.dp))
                }
            },
            confirmButton = {
                Button(onClick = {
                    applyTunnelConfigYaml(settings, importText)
                    tunnelMode = settings.tunnelMode
                    tunnelProtocol = settings.tunnelProtocol
                    edgeIpVersion = settings.tunnelEdgeIpVersion
                    tunnelPort = settings.tunnelTargetPort.toString()
                    tunnelLogLevel = settings.tunnelLogLevel
                    tunnelAutoStart = settings.tunnelAutoStart
                    tunnelReconnect = settings.tunnelReconnect
                    tunnelKeepAlive = settings.tunnelKeepAlive
                    keepaliveInterval = settings.tunnelKeepaliveIntervalSec.toString()
                    reconnectBackoff = settings.tunnelReconnectBackoffSec.toString()
                    namedToken = settings.tunnelNamedToken
                    showImport = false
                    Toast.makeText(context, if (t.zh) "配置已导入" else "Imported", Toast.LENGTH_SHORT).show()
                }) { Text(if (t.zh) "应用" else "Apply") }
            },
            dismissButton = { TextButton(onClick = { showImport = false }) { Text(if (t.zh) "取消" else "Cancel") } },
        )
    }
}

@Composable
private fun SettingsApkBridgePage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    var apkUrl by remember { mutableStateOf(settings.apkMcpUrl) }
    var apkToken by remember { mutableStateOf(settings.apkMcpToken) }
    var apkAutoProbe by remember { mutableStateOf(settings.apkMcpAutoProbe) }
    var apkMerge by remember { mutableStateOf(settings.apkMcpMergeTools) }
    var comboBanner by remember { mutableStateOf(settings.comboBannerEnabled) }
    var probeState by remember { mutableStateOf<ApkMcpBridge.State?>(null) }
    PageScroll {
        GlassGroup {
            OutlinedTextField(
                value = apkUrl,
                onValueChange = { apkUrl = it; settings.apkMcpUrl = it },
                label = { Text(if (t.zh) "APK MCP /mcp URL" else "APK MCP /mcp URL") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            Text(
                if (t.zh) "例如 MT 管理器侧边栏 APK MCP：http://192.168.x.x:8787/mcp" else "e.g. MT Manager APK MCP: http://192.168.x.x:8787/mcp",
                modifier = Modifier.padding(horizontal = 14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GroupDivider()
            OutlinedTextField(
                value = apkToken,
                onValueChange = { apkToken = it; settings.apkMcpToken = it },
                label = { Text(if (t.zh) "Bearer token（可选）" else "Bearer token (optional)") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
        }
        GlassGroup {
            ToggleRow(if (t.zh) "持续自动探测" else "Continuous auto-probe", apkAutoProbe) { apkAutoProbe = it; settings.apkMcpAutoProbe = it }
            GroupDivider()
            ToggleRow(if (t.zh) "合并工具到 tools/list" else "Merge tools into tools/list", apkMerge) { apkMerge = it; settings.apkMcpMergeTools = it }
            GroupDivider()
            ToggleRow(if (t.zh) "主页显示桥接状态横幅" else "Show bridge banner on main page", comboBanner) { comboBanner = it; settings.comboBannerEnabled = it }
        }
        GlassGroup {
            Row(Modifier.padding(14.dp)) {
                PrimaryActionButton(if (t.zh) "立即探测" else "Probe now", { Thread { probeState = activeBridge(context).probe() }.start() }, modifier = Modifier.fillMaxWidth())
            }
            probeState?.let {
                val color = if (it.online) AppleColors.systemGreen else AppleColors.systemRed
                Text(
                    "${if (t.zh) "状态" else "State"}: ${if (it.online) (if (t.zh) "在线" else "online") else (if (t.zh) "离线" else "offline")}   ${if (t.zh) "工具数" else "tools"}: ${it.tools.size}",
                    color = color,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                )
                if (it.lastError.isNotBlank()) {
                    Text(it.lastError, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp))
                }
            }
            Text(
                if (t.zh)
                    "MT 管理器负责 APK 主流程；本应用补充 SO 分析与远程 MCP。离线时桥接工具会自动隐藏。"
                else
                    "MT Manager owns the APK workflow; this app assists with SO analysis. Bridged tools hide when offline.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SettingsAiDeepPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val deepService = remember { DeepAnalysisService(context.applicationContext) }
    var provider by remember { mutableStateOf(settings.aiProvider) }
    var endpoint by remember { mutableStateOf(settings.aiEndpoint) }
    var apiKey by remember { mutableStateOf(settings.aiApiKey) }
    var model by remember { mutableStateOf(settings.aiModel) }
    var temperature by remember { mutableStateOf(settings.aiTemperature.toString()) }
    var maxIterations by remember { mutableStateOf(settings.aiMaxIterations.toString()) }
    var historySoftLimit by remember { mutableStateOf(settings.aiHistorySoftLimit.toString()) }
    var headerFields by remember { mutableStateOf(parseRequestFields(settings.aiCustomHeadersJson)) }
    var bodyFields by remember { mutableStateOf(parseRequestFields(settings.aiCustomBodyJson)) }
    var systemPrompt by remember { mutableStateOf(settings.aiSystemPrompt) }
    var models by remember { mutableStateOf<List<String>>(emptyList()) }
    var modelQuery by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var loadingModels by remember { mutableStateOf(false) }

    PageScroll {
        GlassGroup(title = if (t.zh) "协议兼容" else "Provider") {
            ChipRow(
                listOf(
                    "openai" to "OpenAI",
                    "anthropic" to "Anthropic",
                ),
                provider,
            ) {
                provider = it
                settings.aiProvider = it
                if (it == "anthropic" && endpoint.contains("openai.com")) {
                    endpoint = "https://api.anthropic.com"
                    settings.aiEndpoint = endpoint
                } else if (it == "openai" && endpoint.contains("anthropic.com")) {
                    endpoint = "https://api.openai.com/v1"
                    settings.aiEndpoint = endpoint
                }
            }
        }
        GlassGroup(footer = if (t.zh) "兼容 OpenAI / Anthropic 及多数中转站。自定义 headers/body 用于服务商差异字段。" else "OpenAI/Anthropic compatible. Use custom headers/body for vendor-specific fields.") {
            OutlinedTextField(
                value = endpoint,
                onValueChange = { endpoint = it; settings.aiEndpoint = it },
                label = { Text(if (t.zh) "API 端点" else "API endpoint") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it; settings.aiApiKey = it },
                label = { Text("API Key") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
            )
            OutlinedTextField(
                value = model,
                onValueChange = { model = it; settings.aiModel = it },
                label = { Text(if (t.zh) "模型" else "Model") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(14.dp),
            ) {
                PrimaryActionButton(
                    if (loadingModels) (if (t.zh) "获取中…" else "Loading…") else (if (t.zh) "自动获取模型" else "Fetch models"),
                    {
                        if (!loadingModels) {
                            loadingModels = true
                            status = if (t.zh) "正在拉取模型列表…" else "Fetching models…"
                            scope.launch {
                                val result = deepService.listModels(settings)
                                loadingModels = false
                                result.onSuccess {
                                    models = it
                                    status = if (t.zh) "已获取 ${it.size} 个模型" else "Fetched ${it.size} models"
                                }.onFailure {
                                    status = it.message ?: (if (t.zh) "获取模型失败" else "Failed to fetch models")
                                }
                            }
                        }
                    },
                )
                SecondaryActionButton(if (t.zh) "恢复默认提示词" else "Reset prompt") {
                    systemPrompt = SettingsStore.DEFAULT_AI_SYSTEM_PROMPT
                    settings.aiSystemPrompt = systemPrompt
                }
            }
            if (status.isNotBlank()) {
                Text(status, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (models.isNotEmpty()) {
                Text(if (t.zh) "可选模型" else "Available models", modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp), style = MaterialTheme.typography.labelMedium)
                OutlinedTextField(
                    value = modelQuery,
                    onValueChange = { modelQuery = it },
                    label = { Text(if (t.zh) "搜索模型" else "Search models") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                )
                val visibleModels = remember(models, modelQuery) {
                    models.asSequence()
                        .filter { modelQuery.isBlank() || it.contains(modelQuery, ignoreCase = true) }
                        .take(50)
                        .toList()
                }
                Column(Modifier.padding(horizontal = 14.dp, vertical = 4.dp)) {
                    visibleModels.forEachIndexed { index, candidate ->
                        Text(
                            candidate,
                            color = if (candidate == model) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                            fontWeight = if (candidate == model) FontWeight.Bold else FontWeight.Normal,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    model = candidate
                                    settings.aiModel = candidate
                                }
                                .padding(vertical = 9.dp),
                        )
                        if (index < visibleModels.lastIndex) GroupDivider()
                    }
                    if (visibleModels.size == 50) {
                        Text(
                            if (t.zh) "仅显示前 50 项，请继续输入关键词缩小范围" else "Showing the first 50 results; refine your search",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
            }
        }
        GlassGroup(title = if (t.zh) "采样与深度" else "Sampling & depth") {
            DecimalSettingRow(
                label = "Temperature",
                value = temperature,
                suffix = "0–2",
                supporting = if (t.zh) "0.0 更稳定，数值越高输出越发散；常用范围 0.0–1.0。" else "0.0 is deterministic; higher values are more varied. Typical range: 0.0–1.0.",
                onValue = { temperature = it },
                onApply = {
                val v = it.coerceIn(0f, 2f)
                settings.aiTemperature = v
                temperature = v.toString()
            },
            )
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大迭代" else "Max iterations", maxIterations, { maxIterations = it }, {
                settings.aiMaxIterations = it
                maxIterations = settings.aiMaxIterations.toString()
            }, if (t.zh) "轮" else "runs")
            GroupDivider()
            NumberSettingRow(if (t.zh) "历史压缩阈值" else "History soft limit", historySoftLimit, { historySoftLimit = it }, {
                settings.aiHistorySoftLimit = it
                historySoftLimit = settings.aiHistorySoftLimit.toString()
            }, if (t.zh) "条消息" else "msgs")
        }
        GlassGroup(
            title = if (t.zh) "自定义请求" else "Custom request",
            footer = if (t.zh) "同名字段覆盖默认请求，不同名字段增量加入。请求体会自动识别数字、布尔值、null、对象和数组。" else "Matching keys override defaults; new keys are appended. Body values detect numbers, booleans, null, objects, and arrays.",
        ) {
            RequestFieldsEditor(
                title = if (t.zh) "请求头" else "Headers",
                fields = headerFields,
                keyHint = if (t.zh) "键名" else "Key",
                valueHint = if (t.zh) "值" else "Value",
                emptyText = if (t.zh) "未添加自定义请求头" else "No custom headers",
            ) {
                headerFields = it
                settings.aiCustomHeadersJson = serializeRequestFields(it, false)
            }
            GroupDivider()
            RequestFieldsEditor(
                title = if (t.zh) "请求体字段" else "Body fields",
                fields = bodyFields,
                keyHint = if (t.zh) "键名" else "Key",
                valueHint = if (t.zh) "值" else "Value",
                emptyText = if (t.zh) "未添加自定义请求体字段" else "No custom body fields",
            ) {
                bodyFields = it
                settings.aiCustomBodyJson = serializeRequestFields(it, true)
            }
        }
        GlassGroup(title = if (t.zh) "深度逆向提示词" else "Deep analysis prompt") {
            OutlinedTextField(
                value = systemPrompt,
                onValueChange = { systemPrompt = it; settings.aiSystemPrompt = it },
                label = { Text(if (t.zh) "系统提示词" else "System prompt") },
                minLines = 8,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
        }
    }
}

@Composable
private fun SettingsProbePage(t: UiText, settings: SettingsStore) {
    var probeUrl by remember { mutableStateOf(settings.externalProbeUrl) }
    PageScroll {
        GlassGroup(footer = t.reachabilityHelp) {
            OutlinedTextField(
                value = probeUrl,
                onValueChange = { probeUrl = it; settings.externalProbeUrl = it },
                label = { Text(t.probeServiceUrl) },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            Text(t.externalProbeExample, modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SettingsCreditsPage(t: UiText) {
    PageScroll {
        GlassGroup(footer = if (t.zh) "排名不分先后。点击条目可打开项目主页。" else "Listed in no particular order. Tap an item to open its homepage.") {
            Text(
                if (t.zh) "以下项目和工具提供了直接依赖、运行基础、工程参考或工作流参考。" else "These projects provide dependencies, runtime foundations, or workflow references.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        CreditGroup(if (t.zh) "核心逆向与原生能力" else "Reverse-engineering core", listOf(
            CreditProject("Rizin", if (t.zh) "反汇编、汇编、分析与搜索核心" else "Disasm / asm / analysis / search core", "https://github.com/rizinorg/rizin"),
            CreditProject("LIEF", if (t.zh) "ELF 解析、修复与重写基础" else "ELF parsing / repair / rewriting", "https://github.com/lief-project/LIEF"),
            CreditProject("Unidbg", if (t.zh) "Android SO 级原生模拟执行" else "Android native emulation", "https://github.com/zhkl0228/unidbg"),
            CreditProject("xAnSo", if (t.zh) "SO 节区头重建算法参考" else "Section header reconstruction reference", "https://github.com/HexHacking/xAnSo"),
            CreditProject("Capstone", if (t.zh) "依赖链中使用的反汇编引擎" else "Disassembly engine used by dependencies", "https://github.com/capstone-engine/capstone"),
            CreditProject("Keystone", if (t.zh) "依赖链中使用的汇编引擎" else "Assembly engine used by dependencies", "https://github.com/keystone-engine/keystone"),
            CreditProject("Unicorn", if (t.zh) "依赖链中使用的 CPU 模拟引擎" else "CPU emulation used by dependencies", "https://github.com/unicorn-engine/unicorn"),
        ))
        CreditGroup(if (t.zh) "Android 与界面基础" else "Android and UI foundation", listOf(
            CreditProject("AndroidX", if (t.zh) "Android 应用基础支持库" else "Android support libraries", "https://developer.android.com/jetpack/androidx"),
            CreditProject("Jetpack Compose", if (t.zh) "声明式界面框架" else "Declarative UI toolkit", "https://developer.android.com/jetpack/compose"),
            CreditProject("Material Design 3", if (t.zh) "界面组件与设计规范" else "UI components and design system", "https://m3.material.io/"),
            CreditProject("Kotlin", if (t.zh) "主要开发语言与工具链" else "Language and toolchain", "https://github.com/JetBrains/kotlin"),
            CreditProject("kotlinx.coroutines", if (t.zh) "协程与异步任务运行时" else "Coroutine runtime", "https://github.com/Kotlin/kotlinx.coroutines"),
            CreditProject("kotlinx.serialization", if (t.zh) "序列化能力基础" else "Serialization runtime", "https://github.com/Kotlin/kotlinx.serialization"),
        ))
        CreditGroup(if (t.zh) "网络、服务与构建" else "Networking, server, and build", listOf(
            CreditProject("Ktor", if (t.zh) "内置 MCP HTTP 服务基础" else "Embedded MCP HTTP server", "https://github.com/ktorio/ktor"),
            CreditProject("OkHttp", if (t.zh) "HTTP 客户端与探测请求" else "HTTP client", "https://github.com/square/okhttp"),
            CreditProject("Okio", if (t.zh) "高效 I/O 基础库" else "I/O primitives", "https://github.com/square/okio"),
            CreditProject("SLF4J", if (t.zh) "日志门面与依赖链日志基础" else "Logging facade", "https://github.com/qos-ch/slf4j"),
            CreditProject("Typesafe Config", if (t.zh) "配置解析基础库" else "Configuration library", "https://github.com/lightbend/config"),
            CreditProject("cloudflared", if (t.zh) "Cloudflare Tunnel 公网隧道能力" else "Cloudflare Tunnel", "https://github.com/cloudflare/cloudflared"),
            CreditProject("Gradle", if (t.zh) "项目构建系统" else "Build system", "https://github.com/gradle/gradle"),
            CreditProject("Android Gradle Plugin", if (t.zh) "Android 构建与打包集成" else "Android build integration", "https://developer.android.com/build"),
            CreditProject("Android NDK", if (t.zh) "原生库交叉编译工具链" else "Native build toolchain", "https://developer.android.com/ndk"),
        ))
        CreditGroup(if (t.zh) "依赖与参考工具" else "Dependencies and reference tools", listOf(
            CreditProject("JNA", if (t.zh) "依赖链中的原生访问能力" else "Native access used by dependencies", "https://github.com/java-native-access/jna"),
            CreditProject("apk-parser", if (t.zh) "依赖链中的 APK 解析能力" else "APK parsing used by dependencies", "https://github.com/hsiafan/apk-parser"),
            CreditProject("Apache Commons Codec", if (t.zh) "编解码工具基础库" else "Codec utilities", "https://commons.apache.org/proper/commons-codec/"),
            CreditProject("Apache Commons IO", if (t.zh) "I/O 工具基础库" else "I/O utilities", "https://commons.apache.org/proper/commons-io/"),
            CreditProject("Apache Commons Collections", if (t.zh) "集合工具基础库" else "Collection utilities", "https://commons.apache.org/proper/commons-collections/"),
            CreditProject("fastjson", if (t.zh) "依赖链中的 JSON 工具" else "JSON utilities used by dependencies", "https://github.com/alibaba/fastjson"),
            CreditProject("native-lib-loader", if (t.zh) "依赖链中的原生库加载工具" else "Native library loading", "https://github.com/scijava/native-lib-loader"),
            CreditProject("MT 管理器 / MT Manager", if (t.zh) "APK 工作流参考与 APK MCP 能力来源" else "APK workflow reference and APK MCP provider", "https://mt2.cn/"),
        ))
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun MetricPill(label: String, value: String, color: Color) {
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.10f))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = color)
        Text(value, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun MetricProgressRow(label: String, value: String, progress: Float, color: Color, monospace: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default)
            Text(value, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.72f), fontFamily = FontFamily.Monospace)
        }
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { progress.coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(999.dp)),
            color = color,
            trackColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f),
        )
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun ToolStatsSection(t: UiText, settings: SettingsStore) {
    var refreshKey by remember { mutableStateOf(0) }
    var snapshot by remember(refreshKey) { mutableStateOf(com.soreverse.mcp.core.ToolStats.snapshot()) }
    val context = LocalContext.current
    LaunchedEffect(refreshKey, settings.collectToolStats) {
        if (settings.collectToolStats) {
            delay(50)
            snapshot = com.soreverse.mcp.core.ToolStats.snapshot()
        }
    }
    if (!settings.collectToolStats) {
        Text(if (t.zh) "工具调用统计已关闭，可在「编辑校验与审计」中开启。" else "Tool-call statistics are off. Enable in 'Edit validation and audit'.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        return
    }
    val totalCalls = snapshot.optLong("totalCalls", 0)
    val totalOk = snapshot.optLong("totalOk", 0)
    val totalFailed = snapshot.optLong("totalFailed", 0)
    val distinct = snapshot.optInt("distinctTools", 0)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        MetricPill(if (t.zh) "总调用" else "Calls", totalCalls.toString(), MaterialTheme.colorScheme.primary)
        MetricPill("OK", totalOk.toString(), AppleColors.systemGreen)
        MetricPill(if (t.zh) "失败" else "Failed", totalFailed.toString(), AppleColors.systemRed)
        MetricPill(if (t.zh) "工具" else "Tools", distinct.toString(), AppleColors.systemIndigo)
    }
    Spacer(Modifier.height(8.dp))
    val toolsArr = snapshot.optJSONArray("tools")
    val entries = (0 until (toolsArr?.length() ?: 0)).mapNotNull { i ->
        val obj = toolsArr?.optJSONObject(i) ?: return@mapNotNull null
        Triple(obj.optString("tool"), obj.optLong("calls"), obj.optLong("failed"))
    }.sortedByDescending { it.second }
    if (entries.isEmpty()) {
        Text(if (t.zh) "暂无工具调用记录。" else "No tool calls recorded yet.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f))
    } else {
        val maxCalls = entries.maxOf { it.second }.coerceAtLeast(1)
        entries.take(14).forEach { (name, calls, failed) ->
            MetricProgressRow(
                label = name,
                value = if (failed > 0) "$calls / $failed" else calls.toString(),
                progress = calls.toFloat() / maxCalls,
                color = if (failed > 0 && failed >= calls) AppleColors.systemRed else MaterialTheme.colorScheme.primary,
                monospace = true,
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryActionButton(if (t.zh) "刷新" else "Refresh") { refreshKey++; snapshot = com.soreverse.mcp.core.ToolStats.snapshot() }
        SecondaryActionButton(if (t.zh) "重置" else "Reset") {
            com.soreverse.mcp.core.ToolStats.reset()
            refreshKey++
            snapshot = com.soreverse.mcp.core.ToolStats.snapshot()
            Toast.makeText(context, if (t.zh) "统计已重置" else "Reset", Toast.LENGTH_SHORT).show()
        }
    }
}

@Composable
private fun TunnelStatsSection(t: UiText) {
    var refreshKey by remember { mutableStateOf(0) }
    val context = LocalContext.current
    var stats by remember(refreshKey) { mutableStateOf(activeServer(context)?.tunnel?.tunnelStats() ?: JSONObject()) }
    LaunchedEffect(refreshKey) {
        while (true) {
            stats = activeServer(context)?.tunnel?.tunnelStats() ?: JSONObject()
            delay(2000)
        }
    }
    val totalRunningMs = stats.optLong("totalRunningMs", 0)
    val totalRestarts = stats.optInt("totalRestarts", 0)
    val keepaliveRestarts = stats.optInt("keepaliveRestarts", 0)
    val probeOks = stats.optInt("probeOks", 0)
    val probeFailures = stats.optInt("probeFailures", 0)
    val state = stats.optString("state", "STOPPED")
    val totalProbes = probeOks + probeFailures
    val lossRate = if (totalProbes > 0) (probeFailures.toFloat() / totalProbes * 1000).toInt() / 10f else 0f
    val keepaliveEnabled = stats.optBoolean("keepaliveEnabled")
    fun fmtDuration(ms: Long): String {
        val s = ms / 1000
        val h = s / 3600; val m = (s % 3600) / 60; val sec = s % 60
        return if (h > 0) "${h}h ${m}m ${sec}s" else if (m > 0) "${m}m ${sec}s" else "${sec}s"
    }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        MetricPill(if (t.zh) "状态" else "State", state, if (state == "RUNNING") AppleColors.systemGreen else AppleColors.systemOrange)
        MetricPill(if (t.zh) "运行" else "Uptime", fmtDuration(totalRunningMs), MaterialTheme.colorScheme.primary)
        MetricPill(if (t.zh) "保活" else "Keepalive", if (keepaliveEnabled) "ON" else "OFF", if (keepaliveEnabled) AppleColors.systemGreen else Color(0xFF8E8E93))
    }
    Spacer(Modifier.height(10.dp))
    val maxCount = maxOf(totalRestarts, keepaliveRestarts, probeOks, probeFailures, 1)
    MetricProgressRow(if (t.zh) "总重启" else "Total restarts", totalRestarts.toString(), totalRestarts.toFloat() / maxCount, AppleColors.systemOrange)
    MetricProgressRow(if (t.zh) "保活重启" else "Keepalive restarts", keepaliveRestarts.toString(), keepaliveRestarts.toFloat() / maxCount, AppleColors.systemRed)
    MetricProgressRow(if (t.zh) "探查成功" else "Probe OK", probeOks.toString(), probeOks.toFloat() / maxCount, AppleColors.systemGreen)
    MetricProgressRow(if (t.zh) "探查失败" else "Probe failed", probeFailures.toString(), probeFailures.toFloat() / maxCount, AppleColors.systemRed)
    Spacer(Modifier.height(6.dp))
    Text(if (t.zh) "探查失败率 ≈ ${lossRate}%  ($probeFailures / $totalProbes)" else "Probe failure rate ≈ ${lossRate}%  ($probeFailures / $totalProbes)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
    Spacer(Modifier.height(8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryActionButton(if (t.zh) "刷新" else "Refresh") { refreshKey++ }
        SecondaryActionButton(if (t.zh) "重置" else "Reset") {
            activeServer(context)?.tunnel?.resetTunnelStats()
            refreshKey++
            Toast.makeText(context, if (t.zh) "隧道统计已重置" else "Tunnel stats reset", Toast.LENGTH_SHORT).show()
        }
    }
}

private data class CreditProject(val name: String, val role: String, val url: String)

@Composable
private fun CreditGroup(title: String, projects: List<CreditProject>) {
    val context = LocalContext.current
    GlassGroup(title = title) {
        projects.forEachIndexed { idx, project ->
            if (idx > 0) GroupDivider()
            NavRow(project.name, project.role, Icons.Default.Link, onClick = { openUrl(context, project.url) })
        }
    }
}

@Composable
private fun IndexedBadge(index: Int) {
    Box(
        Modifier
            .size(28.dp)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
        contentAlignment = Alignment.Center,
    ) {
        Text("${index + 1}", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun EndpointRow(t: UiText, label: String, url: String, note: String, onCopy: () -> Unit, onProbe: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onCopy() }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(label, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
            Text(url, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            Text(note, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
        }
        TextButton(onClick = onProbe) { Text(t.test) }
        IconButton(onClick = onCopy) { Icon(Icons.Default.ContentCopy, null, tint = MaterialTheme.colorScheme.primary) }
    }
}

private data class LogLineUi(val time: String, val level: String, val message: String)

private fun parseLogLine(line: String, zh: Boolean): LogLineUi {
    val localized = localizeLogLine(line, zh)
    val match = Regex("^(\\d{2}:\\d{2}:\\d{2}\\.\\d{3})\\s+([IWE])\\s+(.*)$").find(localized)
    return if (match != null) {
        LogLineUi(match.groupValues[1], match.groupValues[2], match.groupValues[3])
    } else {
        LogLineUi("--:--:--.---", "I", localized)
    }
}

@Composable
private fun ModernLogPanel(lines: List<String>, zh: Boolean, autoFollow: Boolean, modifier: Modifier = Modifier) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size, autoFollow) {
        if (autoFollow && lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    if (lines.isEmpty()) {
        Box(modifier, contentAlignment = Alignment.Center) {
            Text(if (zh) "暂无日志" else "No logs yet", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        return
    }
    LazyColumn(
        state = listState,
        modifier = modifier.background(MaterialTheme.colorScheme.surface.copy(alpha = 0.72f)),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 10.dp, vertical = 8.dp),
    ) {
        itemsIndexed(lines, key = { index, line -> "$index:$line" }) { index, raw ->
            val line = parseLogLine(raw, zh)
            val levelColor = when (line.level) {
                "E" -> MaterialTheme.colorScheme.error
                "W" -> statusWarning()
                else -> MaterialTheme.colorScheme.primary
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(if (index % 2 == 0) Color.Transparent else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.18f))
                    .padding(horizontal = 6.dp, vertical = 7.dp),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    (index + 1).toString().padStart(3, '0'),
                    modifier = Modifier.width(30.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.62f),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    line.level,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(levelColor.copy(alpha = 0.13f))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                    color = levelColor,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(line.time, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
                    Text(line.message, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

@Composable
private fun DetailGrid(items: List<Pair<String, String>>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
        items.forEach { (label, value) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(label, modifier = Modifier.weight(0.8f), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(value, modifier = Modifier.weight(1.2f), style = MaterialTheme.typography.labelMedium, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurface)
            }
        }
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun ElfOverviewPanel(detail: SoDetailUi, zh: Boolean, onCopy: (String) -> Unit) {
    val ov = detail.overview
    val sc = ov.optJSONObject("segmentClass") ?: JSONObject()
    val sp = ov.optJSONObject("segmentPermissions") ?: JSONObject()
    val entropy = ov.optJSONObject("entropy") ?: JSONObject()
    val difficulty = ov.optJSONObject("difficulty") ?: JSONObject()
    val security = ov.optJSONArray("securityFeatures") ?: org.json.JSONArray()
    val needed = ov.optJSONArray("neededLibraries") ?: org.json.JSONArray()
    val factors = difficulty.optJSONArray("factors") ?: org.json.JSONArray()
    val recommend = difficulty.optJSONArray("recommend") ?: org.json.JSONArray()
    val attack = ov.optJSONArray("attackSurface") ?: org.json.JSONArray()
    val buckets = entropy.optJSONArray("buckets") ?: org.json.JSONArray()
    val bucketValues = remember(buckets.toString()) {
        (0 until buckets.length()).map { buckets.optDouble(it, 0.0) }
    }
    val strippedFallback = ov.optBoolean("stripped", detail.stripped)
    val totallyStripped = ov.optBoolean("totallyStripped", false)
    var selectedSecurityId by remember(detail.path) { mutableStateOf<String?>(null) }

    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (strippedFallback) {
            OverviewAlert(
                title = if (zh) "检测到符号表严重缺失 (Stripped)" else "Symbol table heavily stripped",
                body = if (zh) {
                    buildString {
                        append("该二进制的内部符号表（.symtab）已被剥离，未导出函数通常不再保留原始名称，静态按名定位会更困难。")
                        if (totallyStripped) append("当前动态符号也非常稀少，可用命名线索更有限。")
                        append("MCP 实际分析不会把函数强制命名为 sub_xxx；有符号时沿用真实符号名，无符号时多通过地址定位（如 fcn.xxxx / so_function:...@0x...），并由反汇编/启发式恢复函数边界。")
                    }
                } else {
                    buildString {
                        append("The internal symbol table (.symtab) appears stripped, so unrecovered functions usually lack original names. ")
                        if (totallyStripped) append("Dynamic symbols are also scarce. ")
                        append("MCP analysis does not force sub_xxx names; it keeps real symbol names when present, otherwise uses address-based locators (fcn.xxxx / so_function:...@0x...) with disassembly heuristics.")
                    }
                },
            )
        }

        OverviewSectionCard(title = if (zh) "📦 文件基础属性" else "📦 File basics") {
            OverviewKv(if (zh) "名称" else "Name", ov.optString("fileName", detail.name))
            OverviewKv(if (zh) "大小" else "Size", formatBytes(ov.optLong("size", 0L)))
            OverviewKv(if (zh) "类型" else "Type", ov.optString("elfType", "—"))
            OverviewKv(if (zh) "架构" else "Arch", ov.optString("architecture", "${detail.architecture}/${detail.bits}"))
            OverviewKv(if (zh) "位数" else "Bits", if (ov.optInt("bits", detail.bits) == 64) "64-bit" else "${ov.optInt("bits", detail.bits)}-bit")
            OverviewKv(if (zh) "字节序" else "Endian", ov.optString("endian", "—"))
            OverviewKv(if (zh) "入口" else "Entry", ov.optString("entryPoint", detail.entryPoint), mono = true)
            OverviewKv(if (zh) "加载基址" else "Base", ov.optString("baseAddr", "0x0"), mono = true)
            OverviewKv("SHA-256", ov.optString("sha256", "—"), mono = true, maxLines = 2, onClick = {
                val hash = ov.optString("sha256")
                if (hash.isNotBlank()) onCopy(hash)
            })
            val buildId = ov.optString("buildId")
            if (buildId.isNotBlank()) OverviewKv("Build ID", buildId, mono = true)
            val soname = ov.optString("soname")
            if (soname.isNotBlank()) OverviewKv("SONAME", soname, mono = true)
        }

        OverviewSectionCard(title = if (zh) "📊 结构与规模" else "📊 Structure & scale") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OverviewMetric(if (zh) "节区" else "Sections", ov.optInt("sectionCount", detail.sectionCount).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "程序段" else "Segments", ov.optInt("segmentCount", 0).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "函数" else "Functions", ov.optInt("functionCount", 0).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "字符串" else "Strings", ov.optInt("stringCount", detail.stringCount).toString(), Modifier.weight(1f))
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OverviewMetric(if (zh) "代码段" else "Exec", "${sc.optInt("execCount")} · ${formatBytes(sc.optLong("execSize"))}", Modifier.weight(1f), Color(0xFFDC3545))
                OverviewMetric(if (zh) "只读段" else "Read", "${sc.optInt("readCount")} · ${formatBytes(sc.optLong("readSize"))}", Modifier.weight(1f), Color(0xFF28A745))
                OverviewMetric(if (zh) "可写段" else "Write", "${sc.optInt("writeCount")} · ${formatBytes(sc.optLong("writeSize"))}", Modifier.weight(1f), Color(0xFFFFA000))
            }
            OverviewKv(
                if (zh) "加载权限" else "Load permissions",
                "R ${sp.optInt("readable")}  ·  W ${sp.optInt("writable")}  ·  X ${sp.optInt("executable")}  ·  PT_LOAD ${sp.optInt("loadable")}",
                mono = true,
            )
            OverviewKv(if (zh) "导入符号" else "Imports", ov.optInt("importCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "导出符号" else "Exports", ov.optInt("exportCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "依赖库数" else "Needed libs", ov.optInt("neededCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "符号 / 动态符号" else "Sym / Dynsym", "${detail.symbolCount} / ${detail.dynsymCount}")
        }

        OverviewSectionCard(title = if (zh) "🛡️ 逆向与系统级安全特征检测" else "🛡️ Security features") {
            Text(
                if (zh) "点击标签查看说明，再次点击可收起" else "Tap a chip for details; tap again to collapse",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SecurityFeatureCloud(
                security = security,
                selectedId = selectedSecurityId,
                onSelect = { id -> selectedSecurityId = if (selectedSecurityId == id) null else id },
            )
            AnimatedContent(
                targetState = selectedSecurityId,
                transitionSpec = {
                    (fadeIn(tween(130)) + expandVertically(tween(150), expandFrom = Alignment.Top)) togetherWith
                        (fadeOut(tween(80)) + shrinkVertically(tween(100), shrinkTowards = Alignment.Top))
                },
                label = "security-detail",
            ) { selectedId ->
                (0 until security.length())
                    .mapNotNull { security.optJSONObject(it) }
                    .firstOrNull { it.optString("id") == selectedId }
                    ?.let { item ->
                    SecurityFeatureDetail(
                        label = item.optString("label"),
                        tone = item.optString("tone", "ok"),
                        description = item.optString("description"),
                    )
                }
            }
        }

        ReferenceOverviewCard(title = if (zh) "🎯 逆向可行性分析报告" else "🎯 Reverse feasibility") {
            val diffCls = difficulty.optString("cls", "ok")
            DifficultyHeader(
                score = difficulty.optString("score", "0.0"),
                level = difficulty.optString("level", if (zh) "简单" else "Easy"),
                cls = diffCls,
                zh = zh,
            )
            SectionTitleColored(
                text = if (zh) "🔴 难度加分因素：" else "🔴 Difficulty factors:",
                color = Color(0xFF495566),
            )
            if (factors.length() == 0) {
                Text(
                    if (zh) "未检测到显著加固/混淆特征" else "No major hardening/obfuscation signals",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF28A745),
                    fontWeight = FontWeight.SemiBold,
                )
            } else {
                Column {
                    for (i in 0 until factors.length()) {
                        val raw = factors.opt(i)
                        val item = raw as? JSONObject
                        val text = item?.optString("text")?.takeIf(String::isNotBlank)
                            ?: item?.optString("title")?.takeIf(String::isNotBlank)
                            ?: factors.optString(i)
                        ReferenceReportLine("• ${text.removePrefix("• ")}", divider = i < factors.length() - 1)
                    }
                }
            }
            SectionTitleColored(
                text = if (zh) "💡 推荐逆向方法与工具：" else "💡 Recommended methods:",
                color = Color(0xFF495566),
            )
            Column(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(Color(0xFFF8FAF9))
                    .border(BorderStroke(1.dp, Color(0xFFE8ECE9)), RoundedCornerShape(4.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                for (i in 0 until recommend.length()) {
                    val raw = recommend.opt(i)
                    val item = raw as? JSONObject
                    val text = item?.optString("text")?.takeIf(String::isNotBlank)
                        ?: item?.optString("detail")?.takeIf(String::isNotBlank)
                        ?: recommend.optString(i)
                    Text(
                        "• ${text.removePrefix("• ").trim()}",
                        fontSize = 12.sp,
                        lineHeight = 22.sp,
                        color = Color(0xFF444444),
                    )
                }
            }
            SectionTitleColored(
                text = if (zh) "📋 攻击面与入口点分析：" else "📋 Attack surface:",
                color = Color(0xFF495566),
            )
            Column {
                for (i in 0 until attack.length()) {
                    val raw = attack.opt(i)
                    val item = raw as? JSONObject
                    val id = item?.optString("id").orEmpty()
                    if (id == "dlopen") continue
                    val text = item?.optString("text")?.takeIf(String::isNotBlank)
                        ?: buildString {
                            append("• ")
                            append(item?.optString("title").orEmpty())
                            item?.optString("value").orEmpty().takeIf(String::isNotBlank)?.let { append("：$it") }
                            item?.optString("detail").orEmpty().takeIf(String::isNotBlank)?.let { append(it) }
                        }.takeIf(String::isNotBlank)
                        ?: attack.optString(i)
                    Text(
                        text,
                        fontSize = 12.sp,
                        lineHeight = 22.sp,
                        color = if (id == "dyn_reg" || id == "init_array" || text.contains("⚠")) Color(0xFFD73A49) else Color(0xFF444444),
                        fontWeight = if (id == "dyn_reg" || id == "init_array" || text.contains("⚠")) FontWeight.Bold else FontWeight.Normal,
                    )
                }
            }
        }

        OverviewSectionCard(title = if (zh) "📈 信息熵分析 (加壳/混淆评估)" else "📈 Entropy analysis") {
            OverviewKv(if (zh) "前 64KB 熵" else "Head 64KB entropy", "%.3f".format(java.util.Locale.US, entropy.optDouble("head64k", 0.0)), mono = true, boldValue = true)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (zh) "全局抽样熵" else "Global sample",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(0.9f),
                )
                Text(
                    "%.3f".format(java.util.Locale.US, entropy.optDouble("globalSample", 0.0)),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                StatusToneBadge(entropy.optString("level", "—"), entropy.optString("levelClass", "ok"))
            }
            EntropySparkline(values = bucketValues)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(if (zh) "文件头 (0x0)" else "Head (0x0)", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(if (zh) "文件尾" else "Tail", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                if (zh) {
                    "信息熵范围通常在 0 ~ 8，用于衡量二进制文件的无序度：\n• 4.0 ~ 6.0：常见普通未加密的结构化代码或明文数据。\n• 6.0 ~ 7.2：正常编译优化后的二进制文件（指令密集）。\n• 7.2 ~ 8.0：大概率使用了代码混淆、加固壳、强压缩或内部嵌有庞大的加密资源。"
                } else {
                    "Entropy is typically 0–8 and measures disorder:\n• 4.0–6.0: plain structured code/data\n• 6.0–7.2: normal optimized binaries\n• 7.2–8.0: likely packing/encryption/heavy obfuscation"
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.06f))
                    .padding(10.dp),
            )
        }

        OverviewSectionCard(title = if (zh) "🔗 依赖库（DT_NEEDED）说明" else "🔗 Needed libraries") {
            if (needed.length() == 0) {
                Text(
                    if (zh) "无依赖或无法解析" else "No dependencies or unresolved",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                for (i in 0 until needed.length()) {
                    val item = needed.optJSONObject(i) ?: continue
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Text(
                            item.optString("name"),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            item.optString("description"),
                            modifier = Modifier.weight(1.1f),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.End,
                        )
                    }
                    if (i < needed.length() - 1) {
                        HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outline.copy(alpha = 0.14f))
                    }
                }
            }
        }
    }
}

@Composable
private fun OverviewSectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), RoundedCornerShape(14.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(bottom = 4.dp),
            )
            HorizontalDivider(thickness = 0.6.dp, color = MaterialTheme.colorScheme.outline.copy(alpha = 0.18f))
            Spacer(Modifier.height(2.dp))
            content()
        },
    )
}

@Composable
private fun ReferenceOverviewCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(Color.White)
            .border(BorderStroke(1.dp, Color(0xFFEDF1F5)), RoundedCornerShape(6.dp))
            .padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            title,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp,
            color = Color(0xFF2F3B45),
            modifier = Modifier.padding(bottom = 4.dp),
        )
        HorizontalDivider(thickness = 1.dp, color = Color(0xFFEEEEEE))
        content()
    }
}

@Composable
private fun OverviewAlert(title: String, body: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFFFFF3CD))
            .border(BorderStroke(1.dp, Color(0xFFFFE08A)), RoundedCornerShape(12.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("⚠️", style = MaterialTheme.typography.titleMedium)
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontWeight = FontWeight.Bold, color = Color(0xFF664D03), style = MaterialTheme.typography.bodyMedium)
            Text(body, color = Color(0xFF664D03), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun OverviewKv(
    label: String,
    value: String,
    mono: Boolean = false,
    boldValue: Boolean = false,
    maxLines: Int = 3,
    onClick: (() -> Unit)? = null,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            label,
            modifier = Modifier.weight(0.85f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value.ifBlank { "—" },
            modifier = Modifier.weight(1.15f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
            fontWeight = if (boldValue) FontWeight.Bold else FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun OverviewMetric(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: Color = MaterialTheme.colorScheme.primary,
) {
    Column(
        modifier
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))
            .padding(horizontal = 8.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        Text(value, style = MaterialTheme.typography.labelMedium, color = accent, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun StatusToneBadge(text: String, tone: String, selected: Boolean = false) {
    val bg = toneColor(tone)
    val fg = if (tone == "warn") Color(0xFF1A1A1A) else Color.White
    Text(
        text,
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(bg)
            .then(
                if (selected) {
                    Modifier.border(BorderStroke(1.5.dp, MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)), RoundedCornerShape(999.dp))
                } else {
                    Modifier
                },
            )
            .padding(horizontal = 8.dp, vertical = 3.dp),
        color = fg,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.SemiBold,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun SecurityFeatureCloud(
    security: org.json.JSONArray,
    selectedId: String?,
    onSelect: (String) -> Unit,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp, bottom = 2.dp),
    ) {
        for (i in 0 until security.length()) {
            val item = security.optJSONObject(i) ?: continue
            val id = item.optString("id", "item_$i")
            val label = item.optString("label")
            val tone = item.optString("tone", "ok")
            val selected = selectedId == id
            Box(
                Modifier
                    .clip(RoundedCornerShape(999.dp))
                    .clickable { onSelect(id) },
            ) {
                StatusToneBadge(label, tone, selected = selected)
            }
        }
    }
}

@Composable
private fun SecurityFeatureDetail(label: String, tone: String, description: String) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(toneColor(tone).copy(alpha = 0.10f))
            .border(BorderStroke(1.dp, toneColor(tone).copy(alpha = 0.28f)), RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StatusToneBadge(label, tone, selected = true)
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun DifficultyHeader(score: String, level: String, cls: String, zh: Boolean) {
    val bg = toneColor(cls)
    val fg = if (cls == "warn") Color(0xFF1A1A1A) else Color.White
    Row(
        Modifier.padding(bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(80.dp)
                .clip(CircleShape)
                .background(bg),
            contentAlignment = Alignment.Center,
        ) {
            Text(score, color = fg, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        }
        Column {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(if (zh) "逆向难度：" else "Difficulty: ", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color(0xFF222222))
                StatusToneBadge(level, cls)
            }
            Text(
                if (zh) "评分范围 0-10，分值越高逆向难度越大" else "Score 0–10; higher means harder to reverse",
                modifier = Modifier.padding(top = 4.dp),
                fontSize = 12.sp,
                color = Color(0xFF666666),
            )
        }
    }
}

@Composable
private fun ReferenceReportLine(text: String, divider: Boolean) {
    Column(Modifier.fillMaxWidth()) {
        Text(text, fontSize = 12.sp, lineHeight = 22.sp, color = Color(0xFF444444), modifier = Modifier.padding(vertical = 2.dp))
        if (divider) HorizontalDivider(thickness = 0.5.dp, color = Color(0xFFF0F0F0))
    }
}

@Composable
private fun SectionTitleColored(text: String, color: Color) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
        color = color,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun FeasibilityFactorRow(title: String, detail: String, weight: Double, tone: String, zh: Boolean) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .border(BorderStroke(0.dp, Color.Transparent))
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = color,
                modifier = Modifier.weight(1f),
            )
            if (weight > 0.0) {
                Text(
                    if (zh) "+${trimWeight(weight)}" else "+${trimWeight(weight)}",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = color,
                )
            }
            }
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun FeasibilityRecommendRow(title: String, detail: String, tone: String) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = color)
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun AttackSurfaceRow(title: String, value: String, detail: String, tone: String) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(title, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = color)
                if (value.isNotBlank()) {
                    Text(value, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                }
            }
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

private fun toneColor(tone: String): Color = when (tone) {
    "danger" -> Color(0xFFDC3545)
    "warn" -> Color(0xFFFFC107)
    "info" -> Color(0xFF0B6BFF)
    else -> Color(0xFF28A745)
}

private fun trimWeight(weight: Double): String =
    if (weight == weight.toLong().toDouble()) weight.toLong().toString() else "%.1f".format(java.util.Locale.US, weight)

@Composable
private fun EntropySparkline(values: List<Double>) {
    val maxV = values.maxOrNull()?.coerceAtLeast(0.1) ?: 8.0
    Row(
        Modifier
            .fillMaxWidth()
            .height(60.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))
            .padding(horizontal = 4.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(1.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        if (values.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("—", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            values.forEach { v ->
                val ratio = (v / maxV).toFloat().coerceIn(0.04f, 1f)
                val color = when {
                    v >= 7.2 -> Color(0xFFDC3545)
                    v >= 6.0 -> Color(0xFFFFC107)
                    else -> Color(0xFF0B6BFF)
                }
                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxHeight(ratio)
                        .clip(RoundedCornerShape(2.dp))
                        .background(color),
                )
            }
        }
    }
}

@Composable
private fun ToolSummary(t: UiText, apkTools: List<String> = emptyList()) {
    val groups = toolGroups(t, apkTools)
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            "${if (t.zh) "共计" else "Total"} ${groups.sumOf { it.items.size }} ${if (t.zh) "个工具" else "tools"}",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold,
        )
        groups.forEach { (cat, color, items) ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(color.copy(alpha = 0.10f))
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(color))
                    Text(cat, style = MaterialTheme.typography.labelLarge, color = color, fontWeight = FontWeight.SemiBold)
                }
                items.forEach { (name, desc) ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(name, modifier = Modifier.weight(0.9f), style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurface)
                        Text(desc, modifier = Modifier.weight(1.1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

private data class ToolGroup(val category: String, val color: Color, val items: List<Pair<String, String>>)

private val groupColor: Map<String, Color> = mapOf(
    "workspace" to AppleColors.systemGreen,
    "analyze" to AppleColors.systemOrange,
    "search" to AppleColors.systemTeal,
    "read" to AppleColors.systemIndigo,
    "edit" to AppleColors.systemRed,
    "emulate" to AppleColors.systemPurple,
    "diff" to AppleColors.systemBlue,
    "session" to AppleColors.systemOrange,
    "build" to AppleColors.systemPurple,
    "system" to AppleColors.systemTeal,
    "meta" to AppleColors.systemBlue,
    "apk-bridge" to Color(0xFF8E8E93),
)

private fun toolGroups(t: UiText, apkTools: List<String> = emptyList()): List<ToolGroup> {
    val zh = t.zh
    val reg = ToolCatalog.grouped(zh, apkTools).toMap()
    val catLabels = ToolCatalog.categoryDescriptions(zh).toMap()
    return ToolCatalog.categoryDescriptions(zh).map { (cat, _) ->
        val label = catLabels[cat] ?: cat
        val items = reg[cat].orEmpty()
        if (items.isEmpty()) null else ToolGroup(label, groupColor[cat] ?: Color(0xFF8E8E93), items)
    }.filterNotNull()
}

private fun toolItems(t: UiText): List<Pair<String, String>> {
    val zh = t.zh
    return ToolCatalog.grouped(zh).flatMap { it.second }
}


private fun localizeLogLine(line: String, zh: Boolean): String {
    if (!zh) return line
    return line
        .replace("SOMCP initialized", "SOMCP 已初始化")
        .replace("Work directory selected:", "已选择工作目录：")
        .replace("Ktor MCP server listening on", "MCP 服务器监听于")
        .replace("Ktor MCP server stopped", "MCP 服务器已停止")
        .replace("Foreground service destroyed", "前台服务已销毁")
        .replace("Floating window shown", "悬浮窗已显示")
        .replace("Tool failed", "工具调用失败")
        .replace("Tool call", "工具调用")
        .replace("Reachability", "可达性探测")
        .replace("Opened", "已打开")
        .replace("Closed", "已关闭")
        .replace("Built", "已构建")
}

private fun displayEndpoint(endpoint: com.soreverse.mcp.core.EndpointInfo, zh: Boolean): Pair<String, String> {
    if (zh) return endpoint.label to endpoint.note
    val label = when (endpoint.label) {
        "本机回环" -> "Loopback"
        "IPv6 地址" -> "IPv6 address"
        "局域网地址" -> "LAN address"
        else -> endpoint.label
    }
    val note = when (endpoint.note) {
        "仅本机/ADB 端口转发可用" -> "Only local device or ADB port forwarding"
        "通常仅同一局域网可访问" -> "Usually reachable only from the same LAN"
        "地址看起来可公网路由，仍取决于运营商/防火墙/客户端网络" -> "Looks publicly routable, still depends on carrier, firewall, and client network"
        else -> endpoint.note
    }
    return label to note
}

private fun filteredEndpoints(context: Context, settings: SettingsStore, port: Int): List<com.soreverse.mcp.core.EndpointInfo> {
    val endpoints = NetworkInspector.endpoints(context, port)
    return if (settings.bindHost == "127.0.0.1") endpoints.filter { it.url.contains("127.0.0.1") } else endpoints
}

private fun activeServer(context: Context): com.soreverse.mcp.mcp.McpHttpServer? =
    com.soreverse.mcp.service.McpForegroundService.currentServer

/**
 * Resolve the live tunnel manager from the running Service, or null when the
 * MCP server is off. We intentionally do NOT fall back to constructing a
 * standalone [CloudflareTunnelManager] here: the previous fallback spawned an
 * orphan manager whose cloudflared child process and watch threads lived
 * outside any Service lifecycle, so when the user later toggled the MCP
 * master switch off, onDestroy's `sv?.tunnel?.stop()` would target a
 * *different* manager instance (the one inside the Service), leaving the
 * orphan's cloudflared running and the watch thread continuing to call
 * context.sendBroadcast on a Context that the OS was tearing down —
 * manifesting as the crash the user reported.
 *
 * Callers must handle null (e.g. show a toast "start the MCP server first"),
 * which accurately informs the user that they need the server running for
 * tunnel operations to be bound to its lifecycle.
 */
private fun activeTunnel(context: Context): CloudflareTunnelManager? =
    activeServer(context)?.tunnel

/**
 * Resolve the ApkMcpBridge. Unlike [activeTunnel], a standalone
 * [ApkMcpBridge] is harmless — it holds no Process/child threads, only an
 * OkHttp client — so the fallback is kept so UI probing works even before
 * the MCP server is switched on.
 */
private fun activeBridge(context: Context): ApkMcpBridge =
    activeServer(context)?.apkBridge ?: ApkMcpBridge(SettingsStore(context))

private fun tunnelStatusOf(context: Context): CloudflareTunnelManager.TunnelStatus =
    activeServer(context)?.tunnel?.status() ?: CloudflareTunnelManager.TunnelStatus()

private fun loadWorkspaces(context: Context): List<WorkspaceUi> {
    val payload = EngineProvider.get(context).listWorkspaces()
    val items = payload.optJSONArray("items") ?: return emptyList()
    val localReports = DeepReportStore.ids(context)
    return (0 until items.length()).mapNotNull { index ->
        val item = items.optJSONObject(index) ?: return@mapNotNull null
        val workspaceId = item.optString("workspaceId")
        WorkspaceUi(
            id = workspaceId,
            name = item.optString("soFileName", "lib.so"),
            path = item.optString("path"),
            abi = item.optString("abi", ""),
            architecture = item.optString("architecture", "unknown"),
            bits = item.optInt("bits", 0),
            temporary = item.optBoolean("temporary", true),
            hasLocalAiReport = workspaceId in localReports,
        )
    }
}

private fun deepReportSnapshot(path: String, model: String, messages: List<DeepChatMessage>): JSONObject =
    JSONObject()
        .put("path", path)
        .put("model", model)
        .put(
            "messages",
            JSONArray().apply {
                messages.forEach { message ->
                    put(
                        JSONObject()
                            .put("id", message.id)
                            .put("role", message.role.name)
                            .put("text", message.text)
                            .put("error", message.error)
                            .put(
                                "parts",
                                JSONArray().apply {
                                    message.parts.forEach { part ->
                                        put(
                                            when (part) {
                                                is RikkaPart.Text -> JSONObject().put("type", "text").put("text", part.text)
                                                is RikkaPart.Reasoning -> JSONObject().put("type", "reasoning").put("text", part.text)
                                                is RikkaPart.Tool -> JSONObject()
                                                    .put("type", "tool")
                                                    .put("id", part.id)
                                                    .put("name", part.name)
                                                    .put("arguments", part.arguments)
                                                    .put("result", part.result)
                                                    .put("index", part.index)
                                            },
                                        )
                                    }
                                },
                            ),
                    )
                }
            },
        )

private fun restoreDeepReport(state: AnalyzeUiState, snapshot: JSONObject) {
    val messages = snapshot.optJSONArray("messages") ?: JSONArray()
    state.deepTargetPath = snapshot.optString("path")
    state.deepMessages = (0 until messages.length()).mapNotNull { index ->
        val message = messages.optJSONObject(index) ?: return@mapNotNull null
        val parts = message.optJSONArray("parts") ?: JSONArray()
        DeepChatMessage(
            id = message.optLong("id", System.currentTimeMillis() + index),
            role = runCatching { DeepChatRole.valueOf(message.optString("role")) }.getOrDefault(DeepChatRole.ASSISTANT),
            text = message.optString("text"),
            parts = (0 until parts.length()).mapNotNull { partIndex ->
                val part = parts.optJSONObject(partIndex) ?: return@mapNotNull null
                when (part.optString("type")) {
                    "text" -> RikkaPart.Text(part.optString("text"))
                    "reasoning" -> RikkaPart.Reasoning(part.optString("text"))
                    "tool" -> RikkaPart.Tool(
                        id = part.optString("id"),
                        name = part.optString("name"),
                        arguments = part.optString("arguments"),
                        result = part.optString("result").takeUnless { part.isNull("result") },
                        index = part.optInt("index"),
                    )
                    else -> null
                }
            },
            error = message.optString("error"),
        )
    }
    state.deepReport = state.deepMessages.lastOrNull { it.role == DeepChatRole.ASSISTANT }?.text.orEmpty()
    state.deepAnalyzingPath = null
    state.deepJob = null
    state.restoreDeepReportOnAnalyzeEntry = false
    state.showDeepReport = true
}

private fun clientConfig(url: String, settings: SettingsStore): String {
    val args = org.json.JSONArray().put("-y").put("mcp-remote").put(url)
    if (needsAllowHttp(url)) {
        args.put("--allow-http")
    }
    if (settings.authEnabled) {
        args.put("--header").put("Authorization: Bearer ${settings.accessToken}")
    }
    val server = JSONObject()
        .put("command", "npx")
        .put("args", args)
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun clientConfigUvx(url: String, settings: SettingsStore): String {
    val args = org.json.JSONArray().put("mcp-proxy").put(url)
    if (settings.authEnabled) {
        args.put("--headers").put("Authorization=Bearer ${settings.accessToken}")
    }
    val server = JSONObject()
        .put("command", "uvx")
        .put("args", args)
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun clientConfigDirect(url: String, settings: SettingsStore): String {
    val server = JSONObject().put("type", "http").put("url", url)
    if (settings.authEnabled) {
        server.put("headers", JSONObject().put("Authorization", "Bearer ${settings.accessToken}"))
    }
    return prettyJson(JSONObject().put("mcpServers", JSONObject().put("somcp", server)))
}

private fun prettyJson(obj: JSONObject): String = obj.toString(2).replace("\\/", "/")

private fun needsAllowHttp(url: String): Boolean {
    val lower = url.lowercase()
    return lower.startsWith("http://") &&
        !lower.startsWith("http://localhost") &&
        !lower.startsWith("http://127.0.0.1") &&
        !lower.startsWith("http://[::1]")
}

private fun loadSoSources(context: Context, limit: Int, zh: Boolean = false): Pair<List<SoSourceUi>, String> {
    val payload = runCatching { EngineProvider.get(context).listAvailableSos(limit = limit.coerceIn(20, 500)) }.getOrElse {
        AppLog.e("SO browser scan failed: ${it.message}")
        return emptyList<SoSourceUi>() to if (zh) "扫描失败：${it.message ?: it.javaClass.simpleName}" else "Scan failed: ${it.message ?: it.javaClass.simpleName}"
    }
    if (!payload.optBoolean("ok", true)) {
        return emptyList<SoSourceUi>() to payload.optJSONObject("error")?.optString("message", if (zh) "扫描失败" else "Scan failed").orEmpty()
    }
    val items = payload.optJSONArray("items") ?: return emptyList<SoSourceUi>() to "0"
    val sources = (0 until items.length()).mapNotNull { index ->
        val item = items.optJSONObject(index) ?: return@mapNotNull null
        SoSourceUi(
            name = item.optString("name", item.optString("path").substringAfterLast('/')),
            path = item.optString("path"),
            source = item.optString("source", "filesystem"),
            abi = item.optString("abi", ""),
            architecture = item.optString("architecture", "unknown"),
            bits = item.optInt("bits", 0),
            size = item.optLong("size", 0L),
            stripped = item.optBoolean("stripped", false),
        )
    }
    val page = payload.optJSONObject("pagination")
    val more = if (page?.optBoolean("hasMore") == true) " + more" else ""
    return sources to "${sources.size}$more"
}

private fun openSoForUi(context: Context, path: String, zh: Boolean = false): Pair<SoDetailUi?, String> {
    val engine = EngineProvider.get(context)
    val opened = engine.open(path, temporary = true)
    if (!opened.optBoolean("ok", true)) {
        return null to opened.optJSONObject("error")?.optString("message", "Open failed").orEmpty()
    }
    val workspaceId = opened.optString("workspaceId")
    return try {
        val analyzed = engine.analyze(workspaceId, "")
        if (!analyzed.optBoolean("ok", true)) {
            null to analyzed.optJSONObject("error")?.optString("message", "Analyze failed").orEmpty()
        } else {
            val counts = opened.optJSONObject("counts") ?: JSONObject()
            val overview = analyzed.optJSONObject("overview")
                ?: analyzed.takeIf { it.has("securityFeatures") || it.has("entropy") || it.has("difficulty") }
                ?: engine.overview(workspaceId)
            val detail = SoDetailUi(
                workspaceId = "",
                name = opened.optString("soFileName", overview.optString("fileName", "lib.so")),
                path = opened.optString("inputPath", path),
                architecture = opened.optString("architecture", overview.optString("architectureCode", "unknown")),
                bits = opened.optInt("bits", overview.optInt("bits", 0)),
                entryPoint = opened.optString("entryPoint", overview.optString("entryPoint", "0x0")),
                stripped = analyzed.optBoolean("stripped", overview.optBoolean("stripped", counts.optInt("symbols", 0) == 0)),
                hasDebugInfo = analyzed.optBoolean("hasDebugInfo", overview.optBoolean("hasDebugInfo", false)),
                hasJniOnLoad = analyzed.optBoolean("hasJniOnLoad", overview.optBoolean("hasJniOnLoad", false)),
                sectionCount = counts.optInt("sections", overview.optInt("sectionCount", 0)),
                symbolCount = counts.optInt("symbols", overview.optInt("symbolCount", 0)),
                dynsymCount = counts.optInt("dynsyms", overview.optInt("dynsymCount", 0)),
                stringCount = counts.optInt("strings", overview.optInt("stringCount", 0)),
                overview = overview,
            )
            detail to if (zh) "已完成 ${detail.name} 的程序基础分析" else "Basic analysis completed for ${detail.name}"
        }
    } finally {
        engine.close(workspaceId)
    }
}

private fun formatBytes(value: Long): String {
    if (value < 1024) return "${value}B"
    val kb = value / 1024.0
    if (kb < 1024) return "%.1fKB".format(Locale.US, kb)
    val mb = kb / 1024.0
    return "%.1fMB".format(Locale.US, mb)
}

private fun portStatusText(port: Int, running: Boolean, zh: Boolean, conflict: Boolean = false): String {
    if (port !in 1024..65535) return if (zh) "端口无效" else "Invalid port"
    if (conflict) return if (zh) "端口冲突" else "Port conflict"
    return if (running) {
        if (zh) "当前运行在 $port 端口" else "Current port: $port"
    } else {
        if (isPortAvailable(port, false)) {
            if (zh) "端口 $port 可用" else "Port $port available"
        } else {
            if (zh) "端口 $port 不可用（已被占用）" else "Port $port unavailable"
        }
    }
}

private fun isPortAvailable(port: Int, allowCurrentRunningPort: Boolean): Boolean {
    if (port !in 1024..65535) return false
    if (allowCurrentRunningPort) return true
    return runCatching {
        ServerSocket(port).use { socket ->
            socket.reuseAddress = true
            true
        }
    }.getOrDefault(false)
}

private fun copy(context: Context, text: String, copiedText: String) {
    (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("MCP URL", text))
    Toast.makeText(context, copiedText, Toast.LENGTH_SHORT).show()
}

private fun maskToken(token: String): String {
    if (token.length <= 8) return if (token.isBlank()) "(empty)" else "****"
    return token.take(4) + "…(" + token.length + ")…" + token.takeLast(4)
}

private fun applyTunnelConfigYaml(settings: SettingsStore, yaml: String) {
    val map = HashMap<String, String>()
    yaml.lines().forEach { line ->
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
        val idx = trimmed.indexOf(':')
        if (idx <= 0) return@forEach
        val key = trimmed.substring(0, idx).trim()
        val value = trimmed.substring(idx + 1).trim()
        if (key.isNotEmpty()) map[key] = value
    }
    map["mode"]?.let { if (it in setOf("off", "quick", "named")) settings.tunnelMode = it }
    map["protocol"]?.let { if (it in setOf("http2", "quic", "auto")) settings.tunnelProtocol = it }
    map["edgeIpVersion"]?.let { if (it in setOf("4", "6", "auto")) settings.tunnelEdgeIpVersion = it }
    map["targetPort"]?.toIntOrNull()?.let { settings.tunnelTargetPort = it }
    map["logLevel"]?.let { if (it in setOf("debug", "info", "warn", "error", "fatal")) settings.tunnelLogLevel = it }
    map["autoStart"]?.lowercase()?.let { settings.tunnelAutoStart = it == "true" || it == "1" }
    map["reconnect"]?.lowercase()?.let { settings.tunnelReconnect = it == "true" || it == "1" }
    map["keepAlive"]?.lowercase()?.let { settings.tunnelKeepAlive = it == "true" || it == "1" }
    map["keepaliveIntervalSec"]?.toIntOrNull()?.let { settings.tunnelKeepaliveIntervalSec = it.coerceIn(5, 300) }
    map["reconnectBackoffSec"]?.toIntOrNull()?.let { settings.tunnelReconnectBackoffSec = it.coerceIn(1, 60) }
    map["token"]?.takeIf { it.isNotBlank() && !it.contains("…") && it != "(empty)" }?.let { settings.tunnelNamedToken = it }
}

private fun openBatterySettings(context: Context) {
    val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    if (Build.VERSION.SDK_INT >= 23 && !pm.isIgnoringBatteryOptimizations(context.packageName)) {
        context.startActivity(Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")))
    } else {
        context.startActivity(Intent(AndroidSettings.ACTION_SETTINGS))
    }
}

private fun isKeepAliveReady(context: Context, settings: SettingsStore): Boolean {
    val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    val batteryReady = Build.VERSION.SDK_INT < 23 || powerManager.isIgnoringBatteryOptimizations(context.packageName)
    return settings.wakeLockEnabled && batteryReady
}

private fun keepAliveAdvice(zh: Boolean): String {
    val brand = Build.BRAND.lowercase()
    val base = if (zh) {
        "请允许自启动、后台活动、不限制电池、通知、悬浮窗，并在最近任务中锁定应用。"
    } else {
        "Allow auto-start, background activity, unrestricted battery, notifications, overlay, and lock the app in recents."
    }
    return when {
        brand.contains("xiaomi") || brand.contains("redmi") -> if (zh) "$base\n小米/红米/HyperOS：安全中心 -> 自启动；省电策略 -> 无限制。" else "$base\nMIUI/HyperOS: Security -> Autostart; Battery saver -> No restrictions."
        brand.contains("huawei") || brand.contains("honor") -> if (zh) "$base\n华为/荣耀：手机管家 -> 应用启动管理 -> 手动管理并允许后台活动。" else "$base\nHuawei/Honor: Phone Manager -> App launch -> Manage manually and allow background activity."
        brand.contains("oppo") || brand.contains("realme") || brand.contains("oneplus") -> if (zh) "$base\nOPPO/realme/OnePlus：电池 -> 后台耗电管理 -> 允许。" else "$base\nOPPO/realme/OnePlus: Battery -> Background power usage -> Allow."
        brand.contains("vivo") || brand.contains("iqoo") -> if (zh) "$base\nvivo/iQOO：电池 -> 后台高耗电 -> 允许；权限 -> 自启动。" else "$base\nvivo/iQOO: Battery -> Background high power usage -> Allow; Permissions -> Autostart."
        else -> base
    }
}

private fun joinQqGroup(context: Context, zh: Boolean) {
    val uris = listOf(
        "mqqapi://card/show_pslcard?src_type=internal&version=1&uin=1079912856&card_type=group&source=qrcode",
        "tencent://groupwpa/?subcmd=all&uin=1079912856",
        "mqqwpa://im/chat?chat_type=group&uin=1079912856&version=1&src_type=web",
    )
    val packages = listOf(null, "com.tencent.mobileqq", "com.tencent.tim")
    for (uri in uris) {
        for (pkg in packages) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (pkg != null) intent.setPackage(pkg)
            runCatching {
                context.startActivity(intent)
                return
            }
        }
    }
    for (pkg in listOf("com.tencent.mobileqq", "com.tencent.tim")) {
        for (uri in uris) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri))
                .setClassName(pkg, "com.tencent.mobileqq.activity.JumpActivity")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            runCatching {
                context.startActivity(intent)
                return
            }
        }
        context.packageManager.getLaunchIntentForPackage(pkg)?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)?.let { launcher ->
            runCatching {
                context.startActivity(launcher)
                Toast.makeText(context, if (zh) "已打开 QQ/TIM，请手动搜索群号 1079912856" else "Opened QQ/TIM. Search group 1079912856 manually.", Toast.LENGTH_LONG).show()
                return
            }
        }
    }
    Toast.makeText(context, if (zh) "无法唤起 QQ/TIM，请确认已安装并允许打开应用链接" else "Cannot open QQ/TIM. Check installation and app-link handling.", Toast.LENGTH_SHORT).show()
}

private fun openUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { Toast.makeText(context, url, Toast.LENGTH_SHORT).show() }
}
