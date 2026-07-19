package com.soreverse.mcp.core

import android.content.Context
import android.net.Uri
import java.security.SecureRandom

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("so_reverse_mcp", Context.MODE_PRIVATE)

    init {
        if (!prefs.getBoolean("apkAutoProbeDefaultMigrated", false)) {
            prefs.edit()
                .putBoolean("apkMcpAutoProbe", false)
                .putBoolean("apkAutoProbeDefaultMigrated", true)
                .apply()
        }
    }

    var treeUri: Uri?
        get() = prefs.getString("treeUri", null)?.let(Uri::parse)
        set(value) = prefs.edit().putString("treeUri", value?.toString()).apply()

    /** True when the user explicitly accepted the "start service without a work directory"
     *  option from the no-work-directory prompt. When true the MCP server is allowed to start
     *  even though [treeUri] is null. The server, tunnel, and most meta/system tools keep working;
     *  only SO scanning or open-by-path operations will return `SO_NOT_FOUND / WORK_DIRECTORY_NOT_SELECTED`
     *  until the user actually picks a directory with the SAF tree picker. (The engine is fully SAF-based,
     *  so `/storage/emulated/0/MT2/mcp` is shown only as a human-readable suggestion — [defaultWorkDirPath]
     *  cannot be used as a real filesystem fallback without `MANAGE_EXTERNAL_STORAGE`.) Cleared whenever a
     *  real SAF tree is picked or the service is stopped. */
    var useDefaultWorkDir: Boolean
        get() = prefs.getBoolean("useDefaultWorkDir", false)
        set(value) = prefs.edit().putBoolean("useDefaultWorkDir", value).apply()

    /** Human-readable hint path shown when no SAF tree has been picked. Use as the suggested
     *  default workspace location so the app always has a sensible default even before the user
     *  opens the directory picker. The actual read still goes through SAF after the user grants it. */
    var defaultWorkDirPath: String
        get() = prefs.getString("defaultWorkDirPath", "/storage/emulated/0/MT2/mcp") ?: "/storage/emulated/0/MT2/mcp"
        set(value) = prefs.edit().putString("defaultWorkDirPath", value).apply()

    var port: Int
        get() = prefs.getInt("port", 8000)
        set(value) = prefs.edit().putInt("port", value.coerceIn(1024, 65535)).apply()

    var bindHost: String
        get() = prefs.getString("bindHost", "0.0.0.0") ?: "0.0.0.0"
        set(value) = prefs.edit().putString("bindHost", if (value == "127.0.0.1") "127.0.0.1" else "0.0.0.0").apply()

    var authEnabled: Boolean
        get() = prefs.getBoolean("authEnabled", true)
        set(value) = prefs.edit().putBoolean("authEnabled", value).apply()

    var accessToken: String
        get() {
            val existing = prefs.getString("accessToken", "").orEmpty()
            if (existing.isNotBlank()) return existing
            return resetAccessToken()
        }
        set(value) = prefs.edit().putString("accessToken", value.trim()).apply()

    var floatingEnabled: Boolean
        get() = prefs.getBoolean("floatingEnabled", false)
        set(value) = prefs.edit().putBoolean("floatingEnabled", value).apply()

    var wakeLockEnabled: Boolean
        get() = prefs.getBoolean("wakeLockEnabled", true)
        set(value) = prefs.edit().putBoolean("wakeLockEnabled", value).apply()

    var language: String
        get() = prefs.getString("language", "system") ?: "system"
        set(value) = prefs.edit().putString("language", value).apply()

    var themeMode: String
        get() = prefs.getString("themeMode", "system") ?: "system"
        set(value) = prefs.edit().putString("themeMode", if (value in setOf("system", "light", "dark")) value else "system").apply()

    /** Accent color preset for the whole UI. */
    var accentColor: String
        get() = prefs.getString("accentColor", "teal") ?: "teal"
        set(value) = prefs.edit().putString(
            "accentColor",
            if (value in setOf("blue", "teal", "indigo", "purple", "green", "orange", "red", "mono")) value else "teal",
        ).apply()

    /** true = pure black OLED dark background; false = elevated dark gray. */
    var pureBlackDark: Boolean
        get() = prefs.getBoolean("pureBlackDark", true)
        set(value) = prefs.edit().putBoolean("pureBlackDark", value).apply()

    /** compact | comfortable | spacious */
    var uiDensity: String
        get() = prefs.getString("uiDensity", "comfortable") ?: "comfortable"
        set(value) = prefs.edit().putString(
            "uiDensity",
            if (value in setOf("compact", "comfortable", "spacious")) value else "comfortable",
        ).apply()

    /** small | medium | large | xlarge for corner radii */
    var cornerStyle: String
        get() = prefs.getString("cornerStyle", "medium") ?: "medium"
        set(value) = prefs.edit().putString(
            "cornerStyle",
            if (value in setOf("small", "medium", "large", "xlarge")) value else "medium",
        ).apply()

    /** system | reduced | full — full keeps standard UI motion; reduced softens; system follows OS. */
    var motionMode: String
        get() = prefs.getString("motionMode", "system") ?: "system"
        set(value) = prefs.edit().putString(
            "motionMode",
            if (value in setOf("system", "reduced", "full")) value else "system",
        ).apply()

    /** Show advanced client-config / tool-catalog blocks on the home tab. */
    var showAdvancedHome: Boolean
        get() = prefs.getBoolean("showAdvancedHome", false)
        set(value) = prefs.edit().putBoolean("showAdvancedHome", value).apply()

    /** Use high-contrast labels and stronger separators. */
    var highContrast: Boolean
        get() = prefs.getBoolean("highContrast", false)
        set(value) = prefs.edit().putBoolean("highContrast", value).apply()

    /** Optional larger type scale multiplier: normal | large | xlarge */
    var textScale: String
        get() = prefs.getString("textScale", "normal") ?: "normal"
        set(value) = prefs.edit().putString(
            "textScale",
            if (value in setOf("normal", "large", "xlarge")) value else "normal",
        ).apply()

    var predictiveBackEnabled: Boolean
        get() = prefs.getBoolean("predictiveBackEnabled", true)
        set(value) = prefs.edit().putBoolean("predictiveBackEnabled", value).apply()

    var autoStartGuideAcknowledged: Boolean
        get() = prefs.getBoolean("autoStartGuideAcknowledged", false)
        set(value) = prefs.edit().putBoolean("autoStartGuideAcknowledged", value).apply()

    var externalProbeUrl: String
        get() = prefs.getString("externalProbeUrl", "") ?: ""
        set(value) = prefs.edit().putString("externalProbeUrl", value).apply()

    var disclaimerAccepted: Boolean
        get() = prefs.getBoolean("disclaimerAccepted", false)
        set(value) = prefs.edit().putBoolean("disclaimerAccepted", value).apply()

    var indexCacheEnabled: Boolean
        get() = prefs.getBoolean("indexCacheEnabled", true)
        set(value) = prefs.edit().putBoolean("indexCacheEnabled", value).apply()

    var parseMetadataInList: Boolean
        get() = prefs.getBoolean("parseMetadataInList", true)
        set(value) = prefs.edit().putBoolean("parseMetadataInList", value).apply()

    var defaultLimit: Int
        get() = prefs.getInt("defaultLimit", 80)
        set(value) = prefs.edit().putInt("defaultLimit", value.coerceIn(10, 500)).apply()

    var stringLimit: Int
        get() = prefs.getInt("stringLimit", 120)
        set(value) = prefs.edit().putInt("stringLimit", value.coerceIn(10, 1000)).apply()

    var disasmLimit: Int
        get() = prefs.getInt("disasmLimit", 240)
        set(value) = prefs.edit().putInt("disasmLimit", value.coerceIn(20, 5000)).apply()

    var disasmMaxBytes: Int
        get() = prefs.getInt("disasmMaxBytes", 4096)
        set(value) = prefs.edit().putInt("disasmMaxBytes", value.coerceIn(256, 65536)).apply()

    /** Active native disassembly/assembly backend.
     *  - "rizin": Rizin librz_* backend, statically linked into librz_native.so (sole backend).
     *  Capstone/Keystone have been fully removed; Rizin is the only disassembly/assembly engine.
     *  The selection is applied through NativeEngine.select() at server start. */
    var nativeBackend: String
        get() = prefs.getString("nativeBackend", "rizin") ?: "rizin"
        set(value) = prefs.edit().putString("nativeBackend", "rizin").apply()

    /** Emulation readiness flag for the Unidbg integration. When true, the emulate_call
     *  tool can load and execute exported functions of the SO under Unidbg to verify
     *  patch semantics. UnidbgEmulator.available() is checked at runtime so the flag
     *  is safe to leave on even if the device cannot emulate. */
    var emulationEnabled: Boolean
        get() = prefs.getBoolean("emulationEnabled", true)
        set(value) = prefs.edit().putBoolean("emulationEnabled", value).apply()

    /** Hard cap on the textual size of a single tool result (characters). 0 disables it.
     *  When set, McpHttpServer truncates the JSON payload text past this limit and appends
     *  a "[truncated]" marker — bounding the LLM context cost of chatty tools
     *  (read_disasm, list, search) without losing the ability to page via cursors. */
    var toolResultMaxChars: Int
        get() = prefs.getInt("toolResultMaxChars", 0)
        set(value) = prefs.edit().putInt("toolResultMaxChars", value.coerceIn(0, 1_000_000)).apply()

    /** When true, a failed disassembly falls back to .byte pseudo-instructions so the
     *  disasm window always returns something readable. When false, an engine failure
     *  yields an empty text window (useful for detecting backend regressions). */
    var disasmPseudoFallback: Boolean
        get() = prefs.getBoolean("disasmPseudoFallback", true)
        set(value) = prefs.edit().putBoolean("disasmPseudoFallback", value).apply()

    var hexdumpMaxBytes: Int
        get() = prefs.getInt("hexdumpMaxBytes", 512)
        set(value) = prefs.edit().putInt("hexdumpMaxBytes", value.coerceIn(16, 4096)).apply()

    var maxRequestKb: Int
        get() = prefs.getInt("maxRequestKb", 1024)
        set(value) = prefs.edit().putInt("maxRequestKb", value.coerceIn(64, 16384)).apply()

    var outputConflictStrategy: String
        get() = prefs.getString("outputConflictStrategy", "rename") ?: "rename"
        set(value) = prefs.edit().putString("outputConflictStrategy", if (value == "overwrite") "overwrite" else "rename").apply()

    var writePatchReport: Boolean
        get() = prefs.getBoolean("writePatchReport", true)
        set(value) = prefs.edit().putBoolean("writePatchReport", value).apply()

    var editStrictValidation: Boolean
        get() = prefs.getBoolean("editStrictValidation", true)
        set(value) = prefs.edit().putBoolean("editStrictValidation", value).apply()

    var editCheckDeep: Boolean
        get() = prefs.getBoolean("editCheckDeep", true)
        set(value) = prefs.edit().putBoolean("editCheckDeep", value).apply()

    var buildCopyToWorkDir: Boolean
        get() = prefs.getBoolean("buildCopyToWorkDir", false)
        set(value) = prefs.edit().putBoolean("buildCopyToWorkDir", value).apply()

    var maxPatchBytes: Int
        get() = prefs.getInt("maxPatchBytes", 4096)
        set(value) = prefs.edit().putInt("maxPatchBytes", value.coerceIn(1, 65536)).apply()

    var maxBuildOutputs: Int
        get() = prefs.getInt("maxBuildOutputs", 200)
        set(value) = prefs.edit().putInt("maxBuildOutputs", value.coerceIn(10, 2000)).apply()

    var maxSnapshots: Int
        get() = prefs.getInt("maxSnapshots", 20)
        set(value) = prefs.edit().putInt("maxSnapshots", value.coerceIn(1, 100)).apply()

    var auditLogEnabled: Boolean
        get() = prefs.getBoolean("auditLogEnabled", true)
        set(value) = prefs.edit().putBoolean("auditLogEnabled", value).apply()

    var autoSnapshotBeforeEdit: Boolean
        get() = prefs.getBoolean("autoSnapshotBeforeEdit", false)
        set(value) = prefs.edit().putBoolean("autoSnapshotBeforeEdit", value).apply()

    var auditPersist: Boolean
        get() = prefs.getBoolean("auditPersist", true)
        set(value) = prefs.edit().putBoolean("auditPersist", value).apply()

    var maxCompareRanges: Int
        get() = prefs.getInt("maxCompareRanges", 500)
        set(value) = prefs.edit().putInt("maxCompareRanges", value.coerceIn(10, 5000)).apply()

    var defaultBuildVariants: Int
        get() = prefs.getInt("defaultBuildVariants", 8)
        set(value) = prefs.edit().putInt("defaultBuildVariants", value.coerceIn(1, 64)).apply()

    var maxAudits: Int
        get() = prefs.getInt("maxAudits", 100)
        set(value) = prefs.edit().putInt("maxAudits", value.coerceIn(10, 1000)).apply()

    var editAutoPersist: Boolean
        get() = prefs.getBoolean("editAutoPersist", false)
        set(value) = prefs.edit().putBoolean("editAutoPersist", value).apply()

    var defaultDisasmBytes: Int
        get() = prefs.getInt("defaultDisasmBytes", 256)
        set(value) = prefs.edit().putInt("defaultDisasmBytes", value.coerceIn(16, 16384)).apply()

    var includeCategoryInSchema: Boolean
        get() = prefs.getBoolean("includeCategoryInSchema", true)
        set(value) = prefs.edit().putBoolean("includeCategoryInSchema", value).apply()

    /** Lean tool exposure: when true, tools/list only advertises a compact core set plus the
     *  meta/discovery tools instead of the full 25-tool surface. The full per-tool schema is
     *  still available via meta_info (action=describe), dramatically reducing LLM
     *  context usage while keeping every capability reachable. */
    var leanTools: Boolean
        get() = prefs.getBoolean("leanTools", true)
        set(value) = prefs.edit().putBoolean("leanTools", value).apply()

    var logMaxLines: Int
        get() = prefs.getInt("logMaxLines", 180)
        set(value) = prefs.edit().putInt("logMaxLines", value.coerceIn(50, 2000)).apply()

    var collectToolStats: Boolean
        get() = prefs.getBoolean("collectToolStats", true)
        set(value) = prefs.edit().putBoolean("collectToolStats", value).apply()

    var toolStatsPersist: Boolean
        get() = prefs.getBoolean("toolStatsPersist", true)
        set(value) = prefs.edit().putBoolean("toolStatsPersist", value).apply()

    var adaptiveLeanTools: Boolean
        get() = prefs.getBoolean("adaptiveLeanTools", true)
        set(value) = prefs.edit().putBoolean("adaptiveLeanTools", value).apply()

    var maxConcurrentTools: Int
        get() = prefs.getInt("maxConcurrentTools", 1)
        set(value) = prefs.edit().putInt("maxConcurrentTools", value.coerceIn(1, 16)).apply()

    var requestTimeoutMs: Int
        get() = prefs.getInt("requestTimeoutMs", 30000)
        set(value) = prefs.edit().putInt("requestTimeoutMs", value.coerceIn(5000, 300000)).apply()

    /**
     * Per-tool rate limit expressed as max calls per minute. 0 disables
     * the limiter. When set, a sliding 60s window is enforced per tool
     * name in McpHttpServer.callTool; over-the-limit calls are rejected
     * with code RATE_LIMITED before any heavy work runs.
     */
    var toolCallRateLimitPerMin: Int
        get() = prefs.getInt("toolCallRateLimitPerMin", 0)
        set(value) = prefs.edit().putInt("toolCallRateLimitPerMin", value.coerceIn(0, 60000)).apply()

    /**
     * Comma-separated list of tool names refused with code TOOL_DISABLED
     * regardless of presence in the catalog. Lets an operator disable a
     * destructive tool (edit_asm, edit_hex, ...) without
     * rebuilding the binary. Whitespace is tolerated.
     */
    var disabledTools: String
        get() = prefs.getString("disabledTools", "") ?: ""
        set(value) = prefs.edit().putString("disabledTools", value).apply()

    var scanApks: Boolean
        get() = prefs.getBoolean("scanApks", true)
        set(value) = prefs.edit().putBoolean("scanApks", value).apply()

    var scanSubdirectories: Boolean
        get() = prefs.getBoolean("scanSubdirectories", true)
        set(value) = prefs.edit().putBoolean("scanSubdirectories", value).apply()

    var maxScanDepth: Int
        get() = prefs.getInt("maxScanDepth", 8)
        set(value) = prefs.edit().putInt("maxScanDepth", value.coerceIn(0, 32)).apply()

    var skipFilesLargerThanMb: Int
        get() = prefs.getInt("skipFilesLargerThanMb", 512)
        set(value) = prefs.edit().putInt("skipFilesLargerThanMb", value.coerceIn(16, 4096)).apply()

    var logLevel: String
        get() = prefs.getString("logLevel", "I") ?: "I"
        set(value) = prefs.edit().putString("logLevel", if (value in setOf("I", "W", "E")) value else "I").apply()

    var autoCheckUpdates: Boolean
        get() = prefs.getBoolean("autoCheckUpdates", true)
        set(value) = prefs.edit().putBoolean("autoCheckUpdates", value).apply()

    // ---- Cloudflare Tunnel ----
    var tunnelMode: String
        get() = prefs.getString("tunnelMode", "off") ?: "off"
        set(value) = prefs.edit().putString("tunnelMode", if (value in setOf("off", "quick", "named")) value else "off").apply()

    var tunnelAutoStart: Boolean
        get() = prefs.getBoolean("tunnelAutoStart", false)
        set(value) = prefs.edit().putBoolean("tunnelAutoStart", value).apply()

    /**
     * Independent gate for [com.soreverse.mcp.service.BootReceiver]: when true the foreground
     * service is started after `BOOT_COMPLETED`. Until this existed, [BootReceiver] borrowed
     * [tunnelAutoStart] as its only gate, which conflated two unrelated concepts — flipping
     * "auto-start the tunnel with the service" on would also pull the entire MCP server up at
     * every phone reboot, which surprised users who only meant to switch the tunnel on. This
     * flag deliberately defaults to `false`.
     */
    var bootAutoStart: Boolean
        get() = prefs.getBoolean("bootAutoStart", false)
        set(value) = prefs.edit().putBoolean("bootAutoStart", value).apply()

    var tunnelTargetPort: Int
        get() = prefs.getInt("tunnelTargetPort", 8000)
        set(value) = prefs.edit().putInt("tunnelTargetPort", value.coerceIn(1, 65535)).apply()

    var tunnelNamedToken: String
        get() = prefs.getString("tunnelNamedToken", "") ?: ""
        set(value) = prefs.edit().putString("tunnelNamedToken", value.trim()).apply()

    var tunnelHistoryUrls: String
        get() = prefs.getString("tunnelHistoryUrls", "") ?: ""
        set(value) = prefs.edit().putString("tunnelHistoryUrls", value).apply()

    var tunnelProtocol: String
        get() = prefs.getString("tunnelProtocol", "http2") ?: "http2"
        set(value) = prefs.edit().putString("tunnelProtocol", if (value in setOf("http2", "quic", "auto")) value else "http2").apply()

    var tunnelEdgeIpVersion: String
        get() = prefs.getString("tunnelEdgeIpVersion", "4") ?: "4"
        set(value) = prefs.edit().putString("tunnelEdgeIpVersion", if (value in setOf("4", "6", "auto")) value else "4").apply()

    var tunnelReconnect: Boolean
        get() = prefs.getBoolean("tunnelReconnect", true)
        set(value) = prefs.edit().putBoolean("tunnelReconnect", value).apply()

    /** Periodic liveness ping to keep the cloudflared process from being considered idle by the OS. */
    var tunnelKeepAlive: Boolean
        get() = prefs.getBoolean("tunnelKeepAlive", true)
        set(value) = prefs.edit().putBoolean("tunnelKeepAlive", value).apply()

    /**
     * Seconds between cloudflared process liveness probes when [tunnelKeepAlive]
     * is enabled. The earlier hard-coded value of 8s was too eager on devices
     * with congested radio and false-triggered the restart path; defaulting
     * to 15s gives the local socket probe more breathing room before a single
     * flaky connect flips the tunnel into restart churn.
     */
    var tunnelKeepaliveIntervalSec: Int
        get() = prefs.getInt("tunnelKeepaliveIntervalSec", 15)
        set(value) = prefs.edit().putInt("tunnelKeepaliveIntervalSec", value.coerceIn(5, 300)).apply()

    /**
     * Seconds to wait after a tunnel FAILED broadcast before attempting an
     * auto reconnect. The previous hard-coded 3s was too short for the user
     * toggling the MCP master switch off — the reconnect thread would start
     * cloudflared again before onDestroy's tunnel.stop() had finished joining
     * the watch thread, leading to the reported crash. Default 5s;
     * increasing this gives the Service teardown a clear window.
     */
    var tunnelReconnectBackoffSec: Int
        get() = prefs.getInt("tunnelReconnectBackoffSec", 5)
        set(value) = prefs.edit().putInt("tunnelReconnectBackoffSec", value.coerceIn(1, 60)).apply()

    var tunnelLogLevel: String
        get() = prefs.getString("tunnelLogLevel", "info") ?: "info"
        set(value) = prefs.edit().putString("tunnelLogLevel", if (value in setOf("debug", "info", "warn", "error", "fatal")) value else "info").apply()

    // ---- APK MCP bridge ----
    var apkMcpUrl: String
        get() = prefs.getString("apkMcpUrl", "") ?: ""
        set(value) = prefs.edit().putString("apkMcpUrl", value.trim()).apply()

    var apkMcpToken: String
        get() = prefs.getString("apkMcpToken", "") ?: ""
        set(value) = prefs.edit().putString("apkMcpToken", value.trim()).apply()

    var apkMcpAutoProbe: Boolean
        get() = prefs.getBoolean("apkMcpAutoProbe", false)
        set(value) = prefs.edit().putBoolean("apkMcpAutoProbe", value).apply()

    var apkMcpMergeTools: Boolean
        get() = prefs.getBoolean("apkMcpMergeTools", true)
        set(value) = prefs.edit().putBoolean("apkMcpMergeTools", value).apply()

    var apkMcpProbeTimeoutMs: Int
        get() = prefs.getInt("apkMcpProbeTimeoutMs", 8000)
        set(value) = prefs.edit().putInt("apkMcpProbeTimeoutMs", value.coerceIn(2000, 30000)).apply()

    // ---- UX / combo ----
    var comboBannerEnabled: Boolean
        get() = prefs.getBoolean("comboBannerEnabled", true)
        set(value) = prefs.edit().putBoolean("comboBannerEnabled", value).apply()

    // ---- AI deep analysis ----
    var aiProvider: String
        get() = prefs.getString("aiProvider", "openai") ?: "openai"
        set(value) = prefs.edit().putString("aiProvider", if (value in setOf("openai", "anthropic")) value else "openai").apply()

    var aiEndpoint: String
        get() = prefs.getString("aiEndpoint", "https://api.openai.com/v1") ?: "https://api.openai.com/v1"
        set(value) = prefs.edit().putString("aiEndpoint", value.trim().trimEnd('/')).apply()

    var aiApiKey: String
        get() = prefs.getString("aiApiKey", "") ?: ""
        set(value) = prefs.edit().putString("aiApiKey", value.trim()).apply()

    var aiModel: String
        get() = prefs.getString("aiModel", "gpt-4.1-mini") ?: "gpt-4.1-mini"
        set(value) = prefs.edit().putString("aiModel", value.trim()).apply()

    var aiTemperature: Float
        get() = prefs.getFloat("aiTemperature", 0.2f)
        set(value) = prefs.edit().putFloat("aiTemperature", value.coerceIn(0f, 2f)).apply()

    var aiMaxIterations: Int
        get() = prefs.getInt("aiMaxIterations", 28)
        set(value) = prefs.edit().putInt("aiMaxIterations", value.coerceIn(4, 80)).apply()

    var aiHistorySoftLimit: Int
        get() = prefs.getInt("aiHistorySoftLimit", 24)
        set(value) = prefs.edit().putInt("aiHistorySoftLimit", value.coerceIn(8, 120)).apply()

    var aiCustomHeadersJson: String
        get() = prefs.getString("aiCustomHeadersJson", "{}") ?: "{}"
        set(value) = prefs.edit().putString("aiCustomHeadersJson", value.ifBlank { "{}" }).apply()

    var aiCustomBodyJson: String
        get() = prefs.getString("aiCustomBodyJson", "{}") ?: "{}"
        set(value) = prefs.edit().putString("aiCustomBodyJson", value.ifBlank { "{}" }).apply()

    var aiSystemPrompt: String
        get() = prefs.getString("aiSystemPrompt", DEFAULT_AI_SYSTEM_PROMPT) ?: DEFAULT_AI_SYSTEM_PROMPT
        set(value) = prefs.edit().putString(
            "aiSystemPrompt",
            value.ifBlank { DEFAULT_AI_SYSTEM_PROMPT },
        ).apply()

    fun resetAccessToken(): String {
        val bytes = ByteArray(18)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        prefs.edit().putString("accessToken", token).apply()
        return token
    }

    fun snapshot(maskSecrets: Boolean = true): org.json.JSONObject {
        fun mask(value: String): String {
            if (!maskSecrets || value.isBlank()) return value
            if (value.length <= 8) return "****"
            return value.take(4) + "…" + value.takeLast(4)
        }
        return org.json.JSONObject()
            .put("appearance", org.json.JSONObject()
                .put("language", language)
                .put("themeMode", themeMode)
                .put("accentColor", accentColor)
                .put("pureBlackDark", pureBlackDark)
                .put("uiDensity", uiDensity)
                .put("cornerStyle", cornerStyle)
                .put("motionMode", motionMode)
                .put("showAdvancedHome", showAdvancedHome)
                .put("highContrast", highContrast)
                .put("textScale", textScale)
                .put("predictiveBackEnabled", predictiveBackEnabled)
                .put("comboBannerEnabled", comboBannerEnabled))
            .put("service", org.json.JSONObject()
                .put("port", port)
                .put("bindHost", bindHost)
                .put("authEnabled", authEnabled)
                .put("accessToken", mask(accessToken))
                .put("defaultWorkDirPath", defaultWorkDirPath)
                .put("useDefaultWorkDir", useDefaultWorkDir)
                .put("hasTreeUri", treeUri != null)
                .put("floatingEnabled", floatingEnabled)
                .put("wakeLockEnabled", wakeLockEnabled)
                .put("bootAutoStart", bootAutoStart))
            .put("engine", org.json.JSONObject()
                .put("indexCacheEnabled", indexCacheEnabled)
                .put("parseMetadataInList", parseMetadataInList)
                .put("defaultLimit", defaultLimit)
                .put("stringLimit", stringLimit)
                .put("disasmLimit", disasmLimit)
                .put("disasmMaxBytes", disasmMaxBytes)
                .put("nativeBackend", nativeBackend)
                .put("emulationEnabled", emulationEnabled)
                .put("toolResultMaxChars", toolResultMaxChars)
                .put("disasmPseudoFallback", disasmPseudoFallback)
                .put("hexdumpMaxBytes", hexdumpMaxBytes)
                .put("maxRequestKb", maxRequestKb)
                .put("outputConflictStrategy", outputConflictStrategy)
                .put("writePatchReport", writePatchReport)
                .put("editStrictValidation", editStrictValidation)
                .put("editCheckDeep", editCheckDeep)
                .put("buildCopyToWorkDir", buildCopyToWorkDir)
                .put("maxPatchBytes", maxPatchBytes)
                .put("maxBuildOutputs", maxBuildOutputs)
                .put("maxSnapshots", maxSnapshots)
                .put("auditLogEnabled", auditLogEnabled)
                .put("autoSnapshotBeforeEdit", autoSnapshotBeforeEdit)
                .put("auditPersist", auditPersist)
                .put("maxCompareRanges", maxCompareRanges)
                .put("defaultBuildVariants", defaultBuildVariants)
                .put("maxAudits", maxAudits)
                .put("editAutoPersist", editAutoPersist)
                .put("defaultDisasmBytes", defaultDisasmBytes)
                .put("includeCategoryInSchema", includeCategoryInSchema)
                .put("leanTools", leanTools)
                .put("logMaxLines", logMaxLines)
                .put("collectToolStats", collectToolStats)
                .put("toolStatsPersist", toolStatsPersist)
                .put("adaptiveLeanTools", adaptiveLeanTools)
                .put("maxConcurrentTools", maxConcurrentTools)
                .put("requestTimeoutMs", requestTimeoutMs)
                .put("toolCallRateLimitPerMin", toolCallRateLimitPerMin)
                .put("disabledTools", disabledTools)
                .put("scanApks", scanApks)
                .put("scanSubdirectories", scanSubdirectories)
                .put("maxScanDepth", maxScanDepth)
                .put("skipFilesLargerThanMb", skipFilesLargerThanMb)
                .put("logLevel", logLevel)
                .put("externalProbeUrl", externalProbeUrl))
            .put("tunnel", org.json.JSONObject()
                .put("tunnelMode", tunnelMode)
                .put("tunnelAutoStart", tunnelAutoStart)
                .put("tunnelTargetPort", tunnelTargetPort)
                .put("tunnelNamedToken", mask(tunnelNamedToken))
                .put("tunnelProtocol", tunnelProtocol)
                .put("tunnelEdgeIpVersion", tunnelEdgeIpVersion)
                .put("tunnelReconnect", tunnelReconnect)
                .put("tunnelKeepAlive", tunnelKeepAlive)
                .put("tunnelKeepaliveIntervalSec", tunnelKeepaliveIntervalSec)
                .put("tunnelReconnectBackoffSec", tunnelReconnectBackoffSec)
                .put("tunnelLogLevel", tunnelLogLevel))
            .put("apkBridge", org.json.JSONObject()
                .put("apkMcpUrl", apkMcpUrl)
                .put("apkMcpToken", mask(apkMcpToken))
                .put("apkMcpAutoProbe", apkMcpAutoProbe)
                .put("apkMcpMergeTools", apkMcpMergeTools)
                .put("apkMcpProbeTimeoutMs", apkMcpProbeTimeoutMs))
            .put("ai", org.json.JSONObject()
                .put("provider", aiProvider)
                .put("endpoint", aiEndpoint)
                .put("apiKey", mask(aiApiKey))
                .put("model", aiModel)
                .put("temperature", aiTemperature.toDouble())
                .put("maxIterations", aiMaxIterations)
                .put("historySoftLimit", aiHistorySoftLimit)
                .put("customHeadersJson", aiCustomHeadersJson)
                .put("customBodyJson", aiCustomBodyJson)
                .put("systemPromptChars", aiSystemPrompt.length))
    }

    fun applyPatch(patch: org.json.JSONObject, allowSecrets: Boolean = true): org.json.JSONObject {
        val changed = org.json.JSONArray()
        fun touch(key: String) { changed.put(key) }
        fun obj(name: String): org.json.JSONObject? = patch.optJSONObject(name)
        fun applyBool(source: org.json.JSONObject?, key: String, apply: (Boolean) -> Unit) {
            if (source != null && source.has(key) && !source.isNull(key)) {
                apply(source.optBoolean(key))
                touch(key)
            }
        }
        fun applyInt(source: org.json.JSONObject?, key: String, apply: (Int) -> Unit) {
            if (source != null && source.has(key) && !source.isNull(key)) {
                apply(source.optInt(key))
                touch(key)
            }
        }
        fun applyStr(source: org.json.JSONObject?, key: String, apply: (String) -> Unit) {
            if (source != null && source.has(key) && !source.isNull(key)) {
                apply(source.optString(key))
                touch(key)
            }
        }
        val appearance = obj("appearance") ?: patch
        applyStr(appearance, "language") { language = it }
        applyStr(appearance, "themeMode") { themeMode = it }
        applyStr(appearance, "accentColor") { accentColor = it }
        applyBool(appearance, "pureBlackDark") { pureBlackDark = it }
        applyStr(appearance, "uiDensity") { uiDensity = it }
        applyStr(appearance, "cornerStyle") { cornerStyle = it }
        applyStr(appearance, "motionMode") { motionMode = it }
        applyBool(appearance, "showAdvancedHome") { showAdvancedHome = it }
        applyBool(appearance, "highContrast") { highContrast = it }
        applyStr(appearance, "textScale") { textScale = it }
        applyBool(appearance, "predictiveBackEnabled") { predictiveBackEnabled = it }
        applyBool(appearance, "comboBannerEnabled") { comboBannerEnabled = it }

        val service = obj("service") ?: patch
        applyInt(service, "port") { port = it }
        applyStr(service, "bindHost") { bindHost = it }
        applyBool(service, "authEnabled") { authEnabled = it }
        if (allowSecrets) applyStr(service, "accessToken") { accessToken = it }
        applyStr(service, "defaultWorkDirPath") { defaultWorkDirPath = it }
        applyBool(service, "useDefaultWorkDir") { useDefaultWorkDir = it }
        applyBool(service, "floatingEnabled") { floatingEnabled = it }
        applyBool(service, "wakeLockEnabled") { wakeLockEnabled = it }
        applyBool(service, "bootAutoStart") { bootAutoStart = it }

        val engine = obj("engine") ?: patch
        applyBool(engine, "indexCacheEnabled") { indexCacheEnabled = it }
        applyBool(engine, "parseMetadataInList") { parseMetadataInList = it }
        applyInt(engine, "defaultLimit") { defaultLimit = it }
        applyInt(engine, "stringLimit") { stringLimit = it }
        applyInt(engine, "disasmLimit") { disasmLimit = it }
        applyInt(engine, "disasmMaxBytes") { disasmMaxBytes = it }
        applyStr(engine, "nativeBackend") { nativeBackend = it }
        applyBool(engine, "emulationEnabled") { emulationEnabled = it }
        applyInt(engine, "toolResultMaxChars") { toolResultMaxChars = it }
        applyBool(engine, "disasmPseudoFallback") { disasmPseudoFallback = it }
        applyInt(engine, "hexdumpMaxBytes") { hexdumpMaxBytes = it }
        applyInt(engine, "maxRequestKb") { maxRequestKb = it }
        applyStr(engine, "outputConflictStrategy") { outputConflictStrategy = it }
        applyBool(engine, "writePatchReport") { writePatchReport = it }
        applyBool(engine, "editStrictValidation") { editStrictValidation = it }
        applyBool(engine, "editCheckDeep") { editCheckDeep = it }
        applyBool(engine, "buildCopyToWorkDir") { buildCopyToWorkDir = it }
        applyInt(engine, "maxPatchBytes") { maxPatchBytes = it }
        applyInt(engine, "maxBuildOutputs") { maxBuildOutputs = it }
        applyInt(engine, "maxSnapshots") { maxSnapshots = it }
        applyBool(engine, "auditLogEnabled") { auditLogEnabled = it }
        applyBool(engine, "autoSnapshotBeforeEdit") { autoSnapshotBeforeEdit = it }
        applyBool(engine, "auditPersist") { auditPersist = it }
        applyInt(engine, "maxCompareRanges") { maxCompareRanges = it }
        applyInt(engine, "defaultBuildVariants") { defaultBuildVariants = it }
        applyInt(engine, "maxAudits") { maxAudits = it }
        applyBool(engine, "editAutoPersist") { editAutoPersist = it }
        applyInt(engine, "defaultDisasmBytes") { defaultDisasmBytes = it }
        applyBool(engine, "includeCategoryInSchema") { includeCategoryInSchema = it }
        applyBool(engine, "leanTools") { leanTools = it }
        applyInt(engine, "logMaxLines") { logMaxLines = it }
        applyBool(engine, "collectToolStats") { collectToolStats = it }
        applyBool(engine, "toolStatsPersist") { toolStatsPersist = it }
        applyBool(engine, "adaptiveLeanTools") { adaptiveLeanTools = it }
        applyInt(engine, "maxConcurrentTools") { maxConcurrentTools = it }
        applyInt(engine, "requestTimeoutMs") { requestTimeoutMs = it }
        applyInt(engine, "toolCallRateLimitPerMin") { toolCallRateLimitPerMin = it }
        applyStr(engine, "disabledTools") { disabledTools = it }
        applyBool(engine, "scanApks") { scanApks = it }
        applyBool(engine, "scanSubdirectories") { scanSubdirectories = it }
        applyInt(engine, "maxScanDepth") { maxScanDepth = it }
        applyInt(engine, "skipFilesLargerThanMb") { skipFilesLargerThanMb = it }
        applyStr(engine, "logLevel") { logLevel = it }
        applyStr(engine, "externalProbeUrl") { externalProbeUrl = it }

        val tunnel = obj("tunnel") ?: patch
        applyStr(tunnel, "tunnelMode") { tunnelMode = it }
        applyBool(tunnel, "tunnelAutoStart") { tunnelAutoStart = it }
        applyInt(tunnel, "tunnelTargetPort") { tunnelTargetPort = it }
        if (allowSecrets) applyStr(tunnel, "tunnelNamedToken") { tunnelNamedToken = it }
        applyStr(tunnel, "tunnelProtocol") { tunnelProtocol = it }
        applyStr(tunnel, "tunnelEdgeIpVersion") { tunnelEdgeIpVersion = it }
        applyBool(tunnel, "tunnelReconnect") { tunnelReconnect = it }
        applyBool(tunnel, "tunnelKeepAlive") { tunnelKeepAlive = it }
        applyInt(tunnel, "tunnelKeepaliveIntervalSec") { tunnelKeepaliveIntervalSec = it }
        applyInt(tunnel, "tunnelReconnectBackoffSec") { tunnelReconnectBackoffSec = it }
        applyStr(tunnel, "tunnelLogLevel") { tunnelLogLevel = it }

        val apk = obj("apkBridge") ?: patch
        applyStr(apk, "apkMcpUrl") { apkMcpUrl = it }
        if (allowSecrets) applyStr(apk, "apkMcpToken") { apkMcpToken = it }
        applyBool(apk, "apkMcpAutoProbe") { apkMcpAutoProbe = it }
        applyBool(apk, "apkMcpMergeTools") { apkMcpMergeTools = it }
        applyInt(apk, "apkMcpProbeTimeoutMs") { apkMcpProbeTimeoutMs = it }

        // Flat key support for AI convenience: app_config set key=value
        val flatKeys = listOf(
            "language", "themeMode", "accentColor", "pureBlackDark", "uiDensity", "cornerStyle",
            "motionMode", "showAdvancedHome", "highContrast", "textScale", "predictiveBackEnabled",
            "comboBannerEnabled", "port", "bindHost", "authEnabled", "accessToken", "floatingEnabled",
            "wakeLockEnabled", "bootAutoStart", "defaultLimit", "stringLimit", "disasmLimit",
            "disasmMaxBytes", "emulationEnabled", "leanTools", "adaptiveLeanTools", "logLevel",
            "tunnelMode", "tunnelAutoStart", "tunnelTargetPort", "tunnelNamedToken", "tunnelProtocol",
            "apkMcpUrl", "apkMcpToken", "apkMcpAutoProbe", "apkMcpMergeTools", "disabledTools",
            "maxConcurrentTools", "requestTimeoutMs", "toolResultMaxChars", "toolCallRateLimitPerMin",
        )
        for (key in flatKeys) {
            if (!patch.has(key) || patch.isNull(key)) continue
            if (patch.opt(key) is org.json.JSONObject) continue
            when (key) {
                "language" -> { language = patch.optString(key); touch(key) }
                "themeMode" -> { themeMode = patch.optString(key); touch(key) }
                "accentColor" -> { accentColor = patch.optString(key); touch(key) }
                "pureBlackDark" -> { pureBlackDark = patch.optBoolean(key); touch(key) }
                "uiDensity" -> { uiDensity = patch.optString(key); touch(key) }
                "cornerStyle" -> { cornerStyle = patch.optString(key); touch(key) }
                "motionMode" -> { motionMode = patch.optString(key); touch(key) }
                "showAdvancedHome" -> { showAdvancedHome = patch.optBoolean(key); touch(key) }
                "highContrast" -> { highContrast = patch.optBoolean(key); touch(key) }
                "textScale" -> { textScale = patch.optString(key); touch(key) }
                "predictiveBackEnabled" -> { predictiveBackEnabled = patch.optBoolean(key); touch(key) }
                "comboBannerEnabled" -> { comboBannerEnabled = patch.optBoolean(key); touch(key) }
                "port" -> { port = patch.optInt(key); touch(key) }
                "bindHost" -> { bindHost = patch.optString(key); touch(key) }
                "authEnabled" -> { authEnabled = patch.optBoolean(key); touch(key) }
                "accessToken" -> if (allowSecrets) { accessToken = patch.optString(key); touch(key) }
                "floatingEnabled" -> { floatingEnabled = patch.optBoolean(key); touch(key) }
                "wakeLockEnabled" -> { wakeLockEnabled = patch.optBoolean(key); touch(key) }
                "bootAutoStart" -> { bootAutoStart = patch.optBoolean(key); touch(key) }
                "defaultLimit" -> { defaultLimit = patch.optInt(key); touch(key) }
                "stringLimit" -> { stringLimit = patch.optInt(key); touch(key) }
                "disasmLimit" -> { disasmLimit = patch.optInt(key); touch(key) }
                "disasmMaxBytes" -> { disasmMaxBytes = patch.optInt(key); touch(key) }
                "emulationEnabled" -> { emulationEnabled = patch.optBoolean(key); touch(key) }
                "leanTools" -> { leanTools = patch.optBoolean(key); touch(key) }
                "adaptiveLeanTools" -> { adaptiveLeanTools = patch.optBoolean(key); touch(key) }
                "logLevel" -> { logLevel = patch.optString(key); touch(key) }
                "tunnelMode" -> { tunnelMode = patch.optString(key); touch(key) }
                "tunnelAutoStart" -> { tunnelAutoStart = patch.optBoolean(key); touch(key) }
                "tunnelTargetPort" -> { tunnelTargetPort = patch.optInt(key); touch(key) }
                "tunnelNamedToken" -> if (allowSecrets) { tunnelNamedToken = patch.optString(key); touch(key) }
                "tunnelProtocol" -> { tunnelProtocol = patch.optString(key); touch(key) }
                "apkMcpUrl" -> { apkMcpUrl = patch.optString(key); touch(key) }
                "apkMcpToken" -> if (allowSecrets) { apkMcpToken = patch.optString(key); touch(key) }
                "apkMcpAutoProbe" -> { apkMcpAutoProbe = patch.optBoolean(key); touch(key) }
                "apkMcpMergeTools" -> { apkMcpMergeTools = patch.optBoolean(key); touch(key) }
                "disabledTools" -> { disabledTools = patch.optString(key); touch(key) }
                "maxConcurrentTools" -> { maxConcurrentTools = patch.optInt(key); touch(key) }
                "requestTimeoutMs" -> { requestTimeoutMs = patch.optInt(key); touch(key) }
                "toolResultMaxChars" -> { toolResultMaxChars = patch.optInt(key); touch(key) }
                "toolCallRateLimitPerMin" -> { toolCallRateLimitPerMin = patch.optInt(key); touch(key) }
            }
        }
        return org.json.JSONObject()
            .put("ok", true)
            .put("changed", changed)
            .put("changedCount", changed.length())
            .put("config", snapshot(maskSecrets = true))
    }

    fun schema(): org.json.JSONObject {
        fun enums(vararg values: String) = org.json.JSONArray(values.toList())
        return org.json.JSONObject()
            .put("appearance", org.json.JSONObject()
                .put("themeMode", enums("system", "light", "dark"))
                .put("accentColor", enums("blue", "teal", "indigo", "purple", "green", "orange", "red", "mono"))
                .put("uiDensity", enums("compact", "comfortable", "spacious"))
                .put("cornerStyle", enums("small", "medium", "large", "xlarge"))
                .put("motionMode", enums("system", "reduced", "full"))
                .put("textScale", enums("normal", "large", "xlarge"))
                .put("language", enums("system", "zh", "en")))
            .put("notes", "Use app_config action=get|set|schema|reset_token. Nested groups or flat keys both work. Secret fields are masked on get.")
    }

    companion object {
        const val DEFAULT_AI_SYSTEM_PROMPT =
            """You are SOMCP Deep Reverse Agent for Android native .so analysis.
Always call MCP tools to gather evidence before concluding. Prefer this workflow:
1) so_open (or reuse workspace if already open)
2) analyze_functions / analyze_cfg / analyze_xrefs / analyze_crypto as needed
3) analysis_report for structured findings
4) targeted disasm/hex/string/search only when necessary

Rules:
- Never invent symbols, addresses, or conclusions without tool evidence.
- Prefer real symbol names; if stripped, locate by address (fcn.xxxx / so_function:...@0x...).
- Keep intermediate tool results concise; final answer must be a structured reverse-engineering report with sections:
  Overview, Security, Key Functions, Crypto/Network, Attack Surface, Feasibility, Next Steps.
- Use Chinese if the user message is Chinese, otherwise English.
- If a tool fails, explain the failure and continue with alternative tools when possible."""
    }
}
