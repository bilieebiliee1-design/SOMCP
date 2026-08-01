package com.soreverse.mcp.core

import java.util.UUID

/**
 * Migrate legacy single-bridge settings to the new multi-bridge config format.
 */
object ApkBridgeConfigMigration {

    /**
     * Perform migration from legacy apkMcpUrl/apkMcpToken to apkBridgeConfigs.
     * Only runs once when legacy values exist and no bridge configs are present.
     */
    fun migrateIfNeeded(settings: SettingsStore) {
        // Check if migration is needed
        val legacyUrl = settings.apkMcpUrl
        val legacyToken = settings.apkMcpToken
        val existingConfigs = settings.apkBridgeConfigs

        if (legacyUrl.isBlank() && legacyToken.isBlank()) return
        if (existingConfigs.isNotEmpty()) return

        // Create a bridge config from legacy settings
        val config = ApkBridgeConfig(
            id = UUID.randomUUID().toString(),
            label = "Default Bridge",
            url = legacyUrl,
            token = legacyToken,
            enabled = legacyUrl.isNotBlank(),
        )
        settings.apkBridgeConfigs = listOf(config)
    }
}
