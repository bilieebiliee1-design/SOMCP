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
        if (!prefs.getBoolean("lanDefaultsRestored_v1_0_12", false)) {
            prefs.edit()
                .putString("bindHost", "0.0.0.0")
                .putBoolean("authEnabled", false)
                .putBoolean("lanDefaultsRestored_v1_0_12", true)
                .apply()
        }
        ApkBridgeConfigMigration.migrateIfNeeded(this)
    }

    var treeUri: Uri?
        get() = prefs.getString("treeUri", null)?.let(Uri::parse)
        set(value) = prefs.edit().putString("treeUri", value?.toString()).apply()

    var useDefaultWorkDir: Boolean
        get() = prefs.getBoolean("useDefaultWorkDir", false)
        set(value) = prefs.edit().putBoolean("useDefaultWorkDir", value).apply()

    var defaultWorkDirPath: String
        get() = prefs.getString("defaultWorkDirPath", "/storage/emulated/0/MT2/mcp") ?: "/storage/emulated/0/MT2/mcp"
        set(value) = prefs.edit().putString("defaultWorkDirPath", value).apply()

    var port: Int
        get() = prefs.getInt("port", 8000)
        set(value) = prefs.edit().putInt("port", value.coerceIn(1024, 65535)).apply()

    var bindHost: String
        get() = prefs.getString("bindHost", "0.0.0.0") ?: "0.0.0.0"
        set(value) = prefs.edit().putString("bindHost", if (value == "0.0.0.0") "0.0.0.0" else "127.0.0.1").apply()

    var authEnabled: Boolean
        get() = prefs.getBoolean("authEnabled", false)
        set(value) = prefs.edit().putBoolean("authEnabled", value).apply()

    var accessToken: String
        get() {
            val existing = sanitizeCredential(prefs.getString("accessToken", "").orEmpty())
            if (existing.isNotBlank()) return existing
            return resetAccessToken()
        }
        set(value) = prefs.edit().putString("accessToken", sanitizeCredential(value)).apply()

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

    var accentColor: String
        get() = prefs.getString("accentColor", "teal") ?: "teal"
        set(value) = prefs.edit().putString("accentColor", if (value in setOf("blue", "teal", "indigo", "purple", "green", "orange", "red", "mono")) value else "teal").apply()

    var pureBlackDark: Boolean
        get() = prefs.getBoolean("pureBlackDark", true)
        set(value) = prefs.edit().putBoolean("pureBlackDark", value).apply()

    var uiDensity: String
        get() = prefs.getString("uiDensity", "comfortable") ?: "comfortable"
        set(value) = prefs.edit().putString("uiDensity", if (value in setOf("compact", "comfortable", "spacious")) value else "comfortable").apply()

    var cornerStyle: String
        get() = prefs.getString("cornerStyle", "medium") ?: "medium"
        set(value) = prefs.edit().putString("cornerStyle", if (value in setOf("small", "medium", "large", "xlarge")) value else "medium").apply()

    var motionMode: String
        get() = prefs.getString("motionMode", "system") ?: "system"
        set(value) = prefs.edit().putString("motionMode", if (value in setOf("system", "reduced", "full")) value else "system").apply()

    var showAdvancedHome: Boolean
        get() = prefs.getBoolean("showAdvancedHome", false)
        set(value) = prefs.edit().putBoolean("showAdvancedHome", value).apply()

    var highContrast: Boolean
        get() = prefs.getBoolean("highContrast", false)
        set(value) = prefs.edit().putBoolean("highContrast", value).apply()

    var textScale: String
        get() = prefs.getString("textScale", "normal") ?: "normal"
        set(value) = prefs.edit().putString("textScale", if (value in setOf("normal", "large", "xlarge")) value else "normal").apply()

    var apkMcpUrl: String
        get() = prefs.getString("apkMcpUrl", "") ?: ""
        set(value) = prefs.edit().putString("apkMcpUrl", value.trim()).apply()

    var apkMcpToken: String
        get() = sanitizeCredential(prefs.getString("apkMcpToken", "").orEmpty())
        set(value) = prefs.edit().putString("apkMcpToken", sanitizeCredential(value)).apply()

    // ---- Multi-bridge support ----
    var apkBridgeConfigs: List<ApkBridgeConfig>
        get() {
            val json = prefs.getString("apkBridgeConfigs", null) ?: return emptyList()
            return try {
                val arr = JSONArray(json)
                (0 until arr.length()).map { ApkBridgeConfig.fromJson(arr.getJSONObject(it)) }
            } catch (_: Exception) {
                emptyList()
            }
        }
        set(value) {
            val arr = JSONArray()
            value.forEach { arr.put(it.toJson()) }
            prefs.edit().putString("apkBridgeConfigs", arr.toString()).apply()
        }

    var apkMcpAutoProbe: Boolean
        get() = prefs.getBoolean("apkMcpAutoProbe", false)
        set(value) = prefs.edit().putBoolean("apkMcpAutoProbe", value).apply()

    var apkMcpMergeTools: Boolean
        get() = prefs.getBoolean("apkMcpMergeTools", true)
        set(value) = prefs.edit().putBoolean("apkMcpMergeTools", value).apply()

    var apkMcpProbeTimeoutMs: Int
        get() = prefs.getInt("apkMcpProbeTimeoutMs", 8000)
        set(value) = prefs.edit().putInt("apkMcpProbeTimeoutMs", value.coerceIn(2000, 30000)).apply()
}