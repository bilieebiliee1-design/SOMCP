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
        // One-time correction of misconfiguration introduced by the 1.0.10/1.0.11
        // updates, which silently forced bindHost=127.0.0.1 and authEnabled=true
        // onto existing installs and broke the LAN-link experience. Per the
        // emergency 1.0.12 patch we reset these back to the user-friendly
        // defaults (LAN on, no token) exactly once; users who prefer the stricter
        // setup can re-enable it afterwards.
        if (!prefs.getBoolean("lanDefaultsRestored_v1_0_12", false)) {
            prefs.edit()
                .putString("bindHost", "0.0.0.0")
                .putBoolean("authEnabled", false)
                .putBoolean("lanDefaultsRestored_v1_0_12", true)
                .apply()
        }
        // Migrate legacy single-bridge settings to multi-bridge configs
        ApkBridgeConfigMigration.migrateIfNeeded(this)
    }