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

    var apkMcpUrl: String
        get() = prefs.getString("apkMcpUrl", "") ?: ""
        set(value) = prefs.edit().putString("apkMcpUrl", value.trim()).apply()

    var apkMcpToken: String
        get() = sanitizeCredential(prefs.getString("apkMcpToken", "").orEmpty())
        set(value) = prefs.edit().putString("apkMcpToken", sanitizeCredential(value)).apply()

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

    fun snapshot(maskSecrets: Boolean = true): org.json.JSONObject {
        fun mask(value: String): String {
            if (!maskSecrets || value.isBlank()) return value
            if (value.length <= 8) return "****"
            return value.take(4) + "…" + value.takeLast(4)
        }
        return org.json.JSONObject()
            .put("apkBridge", org.json.JSONObject()
                .put("apkMcpUrl", apkMcpUrl)
                .put("apkMcpToken", mask(apkMcpToken))
                .put("apkMcpAutoProbe", apkMcpAutoProbe)
                .put("apkMcpMergeTools", apkMcpMergeTools)
                .put("apkMcpProbeTimeoutMs", apkMcpProbeTimeoutMs)
                .put("bridgeConfigs", org.json.JSONArray().apply {
                    apkBridgeConfigs.forEach { put(it.toJson()) }
                })
                .put("bridgeCount", apkBridgeConfigs.size))
    }

    fun applyPatch(patch: org.json.JSONObject, allowSecrets: Boolean = true, allowSecurityFields: Boolean = false): org.json.JSONObject {
        val changed = org.json.JSONArray()
        fun touch(key: String) { changed.put(key) }
        fun obj(name: String): org.json.JSONObject? = patch.optJSONObject(name)
        fun applyStr(source: org.json.JSONObject?, key: String, apply: (String) -> Unit) {
            if (source != null && source.has(key) && !source.isNull(key)) {
                apply(source.optString(key))
                touch(key)
            }
        }
        val apk = obj("apkBridge") ?: patch
        applyStr(apk, "apkMcpUrl") { apkMcpUrl = it }
        if (allowSecrets) applyStr(apk, "apkMcpToken") { apkMcpToken = it }
        applyBool(apk, "apkMcpAutoProbe") { apkMcpAutoProbe = it }
        applyBool(apk, "apkMcpMergeTools") { apkMcpMergeTools = it }
        applyInt(apk, "apkMcpProbeTimeoutMs") { apkMcpProbeTimeoutMs = it }
        if (apk.has("bridgeConfigs") && !apk.isNull("bridgeConfigs")) {
            val arr = apk.getJSONArray("bridgeConfigs")
            apkBridgeConfigs = (0 until arr.length()).map { ApkBridgeConfig.fromJson(arr.getJSONObject(it)) }
            touch("bridgeConfigs")
        }
        return org.json.JSONObject()
            .put("ok", true)
            .put("changed", changed)
            .put("changedCount", changed.length())
            .put("config", snapshot(maskSecrets = true))
    }

    fun schema(): org.json.JSONObject {
        return org.json.JSONObject()
            .put("notes", "Multi-bridge support. Use app_config to manage bridge configs.")
    }

    fun resetAccessToken(): String {
        val bytes = ByteArray(18)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        prefs.edit().putString("accessToken", token).apply()
        return token
    }

    companion object {
        const val DEFAULT_AI_SYSTEM_PROMPT = "You are SOMCP Deep Reverse Agent."
    }
}
