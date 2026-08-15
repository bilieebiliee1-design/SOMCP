package com.soreverse.mcp

import android.content.Context
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.mcp.McpHttpServer
import com.soreverse.mcp.service.McpForegroundService

private val fallbackBridgeLock = Any()
private var fallbackBridge: ApkMcpBridge? = null

internal fun activeServer(context: Context): McpHttpServer? =
    McpForegroundService.currentServer

internal fun activeBridge(context: Context): ApkMcpBridge {
    activeServer(context)?.let { return it.apkBridge }
    return fallbackBridge ?: synchronized(fallbackBridgeLock) {
        fallbackBridge ?: ApkMcpBridge(SettingsStore(context.applicationContext)).also { fallbackBridge = it }
    }
}
