package com.soreverse.mcp

import java.net.ServerSocket

internal fun portStatusText(port: Int, running: Boolean, zh: Boolean, conflict: Boolean = false): String {
    if (port !in 1024..65535) return if (zh) "端口无效" else "Invalid port"
    if (conflict) return if (zh) "端口冲突" else "Port conflict"
    return if (running) {
        if (zh) "当前运行在 $port 端口" else "Current port: $port"
    } else {
        if (isPortAvailable(port, false)) {
            if (zh) "端口 $port 可用" else "Port $port available"
        } else {
            if (zh) "端口 $port 不可用（已被占用）" else "Port $port unavailable"
        }
    }
}

internal fun isPortAvailable(port: Int, allowCurrentRunningPort: Boolean): Boolean {
    if (port !in 1024..65535) return false
    if (allowCurrentRunningPort) return true
    return runCatching {
        ServerSocket(port).use { socket ->
            socket.reuseAddress = true
            true
        }
    }.getOrDefault(false)
}
