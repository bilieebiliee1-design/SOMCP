package com.soreverse.mcp

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.res.Configuration
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.PredictiveBackHandler
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.ExperimentalAnimationApi
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.draw.drawBehind
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBar
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.BorderStroke
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.DeepAnalysisService
import com.soreverse.mcp.core.DeepReportStore
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.GitHubRelease
import com.soreverse.mcp.core.GitHubUpdateManager
import com.soreverse.mcp.core.PublicReachability
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
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
