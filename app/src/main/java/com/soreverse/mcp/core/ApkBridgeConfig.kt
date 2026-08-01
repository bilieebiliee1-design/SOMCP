package com.soreverse.mcp.core

import org.json.JSONObject

/**
 * Configuration for a single APK MCP bridge connection.
 */
data class ApkBridgeConfig(
    val id: String,
    val label: String,
    val url: String,
    val token: String = "",
    val enabled: Boolean = true,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("label", label)
        put("url", url)
        put("token", token)
        put("enabled", enabled)
    }

    companion object {
        fun fromJson(json: JSONObject): ApkBridgeConfig {
            return ApkBridgeConfig(
                id = json.optString("id"),
                label = json.optString("label", "Bridge"),
                url = json.optString("url", "").trim(),
                token = json.optString("token", ""),
                enabled = json.optBoolean("enabled", true),
            )
        }
    }
}
