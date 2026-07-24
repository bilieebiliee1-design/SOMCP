package com.soreverse.mcp

import android.content.Context
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.mcp.McpHttpServer
import com.soreverse.mcp.service.McpForegroundService

internal fun activeServer(context: Context): McpHttpServer? =
    McpForegroundService.currentServer

internal fun activeBridge(context: Context): ApkMcpBridge =
    activeServer(context)?.apkBridge ?: ApkMcpBridge(SettingsStore(context))
