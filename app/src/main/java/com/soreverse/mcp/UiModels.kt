package com.soreverse.mcp

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.soreverse.mcp.core.DeepAnalysisEvent
import com.soreverse.mcp.core.RikkaPart
import kotlinx.coroutines.Job
import org.json.JSONObject

internal enum class MainTab { Service, Analyze, Logs, Settings }
internal enum class SetupTarget { Directory, ApkMcp, KeepAlive }
internal enum class SettingsDest {
    Root, ServiceConfig, Appearance, KeepAlive, Access, Limits, Export, Audit, Tunnel, ApkBridge, AiDeep, Updates, Probe, ToolStats, TunnelStats, Instructions, Credits, Disclaimer, About
}

internal data class WorkspaceUi(
    val id: String,
    val name: String,
    val path: String,
    val abi: String,
    val architecture: String,
    val bits: Int,
    val temporary: Boolean,
    val hasLocalAiReport: Boolean,
)

internal data class SoSourceUi(
    val name: String,
    val path: String,
    val source: String,
    val abi: String,
    val architecture: String,
    val bits: Int,
    val size: Long,
    val stripped: Boolean,
)

internal data class SoDetailUi(
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

internal enum class DeepChatRole { USER, ASSISTANT }

internal data class DeepChatMessage(
    val id: Long,
    val role: DeepChatRole,
    val text: String,
    val events: List<DeepAnalysisEvent> = emptyList(),
    val parts: List<RikkaPart> = emptyList(),
    val streaming: Boolean = false,
    val error: String = "",
)

internal class AnalyzeUiState {
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

internal data class UiText(
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
