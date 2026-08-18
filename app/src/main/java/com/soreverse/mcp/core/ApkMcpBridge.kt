package com.soreverse.mcp.core

import com.soreverse.mcp.core.AppLog
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

/**
 * Bridge to external "APK MCP" servers (MT Manager).
 *
 * Acts as an MCP gateway: discovers each remote server's tools via tools/list,
 * merges them under their native prefix (mt_apk_*) into our own
 * tools/list responses, and transparently forwards tools/call invocations
 * back to the correct remote server based on the tool name prefix.
 *
 * When all remotes are unreachable, tools are hidden so the local server behaves
 * as a standalone SO-only MCP. When any remote is reachable, the client gets a
 * combined SO+APK reverse-engineering toolset ("combo") without re-implementing
 * APK analysis from scratch.
 */
class ApkMcpBridge(private val settings: SettingsStore) {

    data class ToolDef(val name: String, val title: String?, val description: String?, val inputSchema: JSONObject?, val outputSchema: JSONObject?)

    data class State(
        val url: String = "",
        val online: Boolean = false,
        val lastError: String = "",
        val tools: List<ToolDef> = emptyList(),
        val toolPrefix: String = MT_PREFIX,
        val lastCheckedAt: Long = 0,
        val lastLatencyMs: Long = 0,
        val probes: Long = 0,
        val probeFailures: Long = 0,
        val totalLatencyMs: Long = 0,
        val maxLatencyMs: Long = 0
    ) {
        fun avgLatencyMs(): Long = if (probes > 0) totalLatencyMs / probes else 0
        fun lossRate(): Double = if (probes == 0L) 0.0 else probeFailures.toDouble() / probes
    }

    /**
     * Internal representation of a single bridge connection.
     */
    private class BridgeConnection(val url: String, val token: String) {
        @Volatile var state: State = State(url = url)
        private val client: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(20, TimeUnit.SECONDS)
                .build()
        }

        @Volatile private var healthThread: Thread? = null

        @Volatile private var healthStop = false

        @Synchronized
        fun probe(timeoutMs: Int = 8000): State {
            try {
                val req =
                    buildJsonRpc(
                        url,
                        "tools/list",
                        JSONObject(),
                        id = connIdCounter.incrementAndGet()
                    )
                val start = System.nanoTime()
                val resp = post(req)
                val latencyMs = (System.nanoTime() - start) / 1_000_000
                val parsed = parseTools(resp)
                val prefix = detectPrefix(parsed)
                val prev = state
                val s = State(
                    url = url,
                    online = true,
                    lastError = "",
                    tools = parsed,
                    toolPrefix = prefix ?: prev.toolPrefix,
                    lastCheckedAt = System.currentTimeMillis(),
                    lastLatencyMs = latencyMs,
                    probes = prev.probes + 1,
                    probeFailures = prev.probeFailures,
                    totalLatencyMs = prev.totalLatencyMs + latencyMs,
                    maxLatencyMs = maxOf(prev.maxLatencyMs, latencyMs)
                )
                state = s
                val label = prefixLabel(prefix)
                AppLog.i(
                    "apk-mcp bridge online: ${parsed.size} tools from $url ($label, ${latencyMs}ms)"
                )
                return s
            } catch (e: Exception) {
                val prev = state
                val s = State(
                    url = url,
                    online = false,
                    lastError =
                    e.message ?: e.javaClass.simpleName,
                    probes = prev.probes + 1,
                    probeFailures = prev.probeFailures + 1,
                    totalLatencyMs = prev.totalLatencyMs,
                    maxLatencyMs = prev.maxLatencyMs
                )
                state = s
                AppLog.w("apk-mcp probe failed: $url ${e.message}")
                return s
            }
        }

        @Synchronized
        fun ping(): State = try {
            val req =
                buildJsonRpc(
                    url,
                    "initialize",
                    JSONObject().put("client", "somcp-ping"),
                    id = connIdCounter.incrementAndGet()
                )
            val start = System.nanoTime()
            post(req)
            val latencyMs = (System.nanoTime() - start) / 1_000_000
            val prev = state
            val s = if (!prev.online) {
                prev.copy(
                    lastLatencyMs = latencyMs,
                    lastCheckedAt = System.currentTimeMillis(),
                    probes = prev.probes + 1,
                    lastError = "",
                    online = false,
                    tools = prev.tools
                )
            } else {
                State(
                    url = url, online = true, lastError = "", tools = prev.tools,
                    lastCheckedAt = System.currentTimeMillis(), lastLatencyMs = latencyMs,
                    probes = prev.probes + 1, probeFailures = prev.probeFailures,
                    totalLatencyMs = prev.totalLatencyMs + latencyMs,
                    maxLatencyMs = maxOf(
                        prev.maxLatencyMs,
                        latencyMs
                    )
                )
            }
            state = s
            s
        } catch (e: Exception) {
            val prev = state
            val s = State(
                url = url,
                online = false,
                lastError =
                e.message ?: e.javaClass.simpleName,
                probes = prev.probes + 1,
                probeFailures = prev.probeFailures + 1,
                totalLatencyMs = prev.totalLatencyMs,
                maxLatencyMs = prev.maxLatencyMs
            )
            state = s
            s
        }

        fun callTool(name: String, arguments: JSONObject): JSONObject {
            val st = state
            if (!st.online || st.url.isBlank()) {
                return errorResult(name, "APK MCP $url is offline or not configured")
            }
            val params = JSONObject().put("name", name).put("arguments", arguments)
            return try {
                val req =
                    buildJsonRpc(url, "tools/call", params, id = connIdCounter.incrementAndGet())
                val resp = post(req)
                parseToolResult(resp)
            } catch (e: Exception) {
                errorResult(name, "forward failed: ${e.message}")
            }
        }

        fun startHealthMonitor(intervalMs: Long = 30_000) {
            stopHealthMonitor()
            healthStop = false
            healthThread = Thread({
                while (!healthStop && !Thread.currentThread().isInterrupted) {
                    try {
                        Thread.sleep(intervalMs)
                    } catch (_: InterruptedException) {
                        break
                    }
                    if (healthStop) break
                    try {
                        val req =
                            buildJsonRpc(
                                url,
                                "tools/list",
                                JSONObject(),
                                id = connIdCounter.incrementAndGet()
                            )
                        val resp = post(req)
                        val parsed = parseTools(resp)
                        val prefix = detectPrefix(parsed)
                        if (prefix != null) {
                            val cur = state
                            state =
                                State(
                                    url = url,
                                    online = true,
                                    lastError = "",
                                    tools = parsed,
                                    toolPrefix = prefix,
                                    lastCheckedAt = System.currentTimeMillis()
                                )
                            if (!cur.online) {
                                AppLog.i(
                                    "apk-mcp health: $url back online (${parsed.size} tools, prefix=$prefix)"
                                )
                            }
                        }
                    } catch (e: Exception) {
                        val cur = state
                        if (cur.online) {
                            state =
                                State(
                                    url = url,
                                    online = false,
                                    lastError =
                                    e.message ?: e.javaClass.simpleName,
                                    tools = emptyList(),
                                    lastCheckedAt = System.currentTimeMillis()
                                )
                            AppLog.w("apk-mcp health: $url marked offline (${e.message})")
                        }
                    }
                }
            }, "apk-mcp-health-$url").apply {
                isDaemon = true
                start()
            }
        }

        fun stopHealthMonitor() {
            healthStop = true
            healthThread?.interrupt()
            healthThread = null
        }

        private fun buildJsonRpc(url: String, method: String, params: JSONObject, id: Int): Request {
            val body = JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", id)
                .put("method", method)
                .put("params", params)
                .toString()
            val builder = Request.Builder().url(
                url
            ).post(body.toRequestBody("application/json".toMediaType()))
            if (token.isNotBlank()) builder.safeHeader("Authorization", "Bearer $token")
            return builder.build()
        }

        private fun post(req: Request): String {
            client.newCall(req).execute().use { r ->
                val body = r.body?.string().orEmpty()
                if (!r.isSuccessful) throw IllegalStateException("HTTP ${r.code}")
                return body
            }
        }

        private fun parseTools(body: String): List<ToolDef> {
            val root = JSONObject(body)
            val result = root.opt("result") as? JSONObject ?: return emptyList()
            val tools = result.optJSONArray("tools") ?: return emptyList()
            val out = ArrayList<ToolDef>(tools.length())
            for (i in 0 until tools.length()) {
                val t = tools.getJSONObject(i)
                out.add(
                    ToolDef(
                        name = t.optString("name"),
                        title = t.optString("title").takeIf { it.isNotBlank() },
                        description = t.optString("description").takeIf { it.isNotBlank() },
                        inputSchema = t.optJSONObject("inputSchema"),
                        outputSchema = t.optJSONObject("outputSchema")
                    )
                )
            }
            return out
        }

        private fun parseToolResult(body: String): JSONObject {
            val root = JSONObject(body)
            val result = root.opt("result")
            return (result as? JSONObject) ?: JSONObject().put("raw", body)
        }

        private fun errorResult(name: String, msg: String): JSONObject = JSONObject().put(
            "content",
            JSONArray().put(
                JSONObject().put("type", "text").put("text", "APK MCP error [$name]: $msg")
            )
        )
            .put("isError", true)
            .put("source", "apk-mcp-bridge")

        private fun detectPrefix(tools: List<ToolDef>): String? {
            tools.firstOrNull { it.name.startsWith(MT_PREFIX) }?.let { return MT_PREFIX }
            return null
        }

        private fun prefixLabel(prefix: String?): String = when (prefix) {
            MT_PREFIX -> "MT Manager"
            else -> "Unknown"
        }
    }

    private val connections = CopyOnWriteArrayList<BridgeConnection>()

    init {
        syncConnectionsFromSettings()
    }

    /**
     * Return a merged State representing the first online bridge,
     * or the first configured bridge if none are online.
     * This is used for backward compatibility with caller code that
     * expects a single-bridge view.
     */
    fun state(): State {
        val firstOnline = connections.firstOrNull { it.state.online }
        if (firstOnline != null) return firstOnline.state
        val first = connections.firstOrNull()
        if (first != null) return first.state
        return State()
    }

    /** Sync the internal connection list from settings. */
    private fun syncConnectionsFromSettings() {
        val configs = settings.apkMcpConfigs
        // Remove connections whose URLs are no longer in config
        val activeUrls = configs.map { it.url }.toSet()
        connections.removeAll { it.url !in activeUrls }
        // Add new connections
        val existingUrls = connections.map { it.url }.toSet()
        for (config in configs) {
            if (config.url !in existingUrls) {
                connections.add(BridgeConnection(config.url, config.token))
            }
        }
    }

    /** Ensure a connection exists for the given URL, adding it if new. */
    private fun ensureConnection(url: String, token: String = ""): BridgeConnection {
        syncConnectionsFromSettings()
        return connections.firstOrNull { it.url == url } ?: run {
            val conn = BridgeConnection(url, token)
            connections.add(conn)
            conn
        }
    }

    fun configured(): Boolean = settings.apkMcpConfigs.isNotEmpty() || settings.apkMcpUrl.isNotBlank()

    /**
     * Auto-discover APK MCP servers on the standard ports.
     * Returns the state of the first discovered server (for backward compatibility),
     * but adds all discovered servers to the connection list.
     */
    @Synchronized
    fun autoDiscover(port: Int = DEFAULT_PORT): State {
        syncConnectionsFromSettings()
        val allPorts = listOf(port).distinct()
        var firstState: State? = null
        for (p in allPorts) {
            if (connections.any { it.url.contains(":$p/") }) continue
            val candidates = listOf(
                "http://127.0.0.1:$p/mcp",
                "http://localhost:$p/mcp"
            )
            for (url in candidates) {
                try {
                    val conn = BridgeConnection(url, "")
                    val st = conn.probe()
                    if (st.online) {
                        connections.add(conn)
                        // Save to settings
                        val configs = settings.apkMcpConfigs.toMutableList()
                        if (configs.none { it.url == url }) {
                            configs.add(SettingsStore.BridgeConfig(url, ""))
                            settings.apkMcpConfigs = configs
                        }
                        if (firstState == null) firstState = st
                        AppLog.i(
                            "apk-mcp auto-discovered ${prefixLabel(
                                st.toolPrefix
                            )} at $url (${st.tools.size} tools)"
                        )
                        break
                    }
                } catch (_: Exception) {}
            }
        }
        if (firstState == null) {
            AppLog.i("apk-mcp auto-discovery: no APK MCP found on ports $allPorts")
        }
        return firstState ?: State()
    }

    /** Probe all configured bridge connections in parallel. Returns the state of the first connection (backward compat). */
    @Synchronized
    fun probe(): State {
        syncConnectionsFromSettings()
        if (connections.isEmpty()) return State()
        // Probe all bridges concurrently so multi-bridge users see both
        // bridges come up at the same time, not one-after-another.
        val exec = java.util.concurrent.Executors.newFixedThreadPool(
            connections.size.coerceIn(1, 4)
        )
        try {
            val results = connections.map { conn ->
                exec.submit<State> { conn.probe() }
            }
            results.forEach { it.get() }
            return connections.firstOrNull()?.state ?: State()
        } finally {
            exec.shutdown()
        }
    }

    /**
     * Probe a specific URL (used when user adds a new bridge URL from UI).
     * Adds the connection if successful.
     */
    @Synchronized
    fun probeUrl(url: String, token: String = ""): State {
        val conn = ensureConnection(url, token)
        val st = conn.probe()
        // Always save to settings so the bridge appears in the UI list
        // even when it is currently offline (user can retry later).
        val configs = settings.apkMcpConfigs.toMutableList()
        if (configs.none { it.url == url }) {
            configs.add(SettingsStore.BridgeConfig(url, token))
            settings.apkMcpConfigs = configs
        }
        return st
    }

    /**
     * Remove a bridge connection by URL.
     */
    @Synchronized
    fun removeBridge(url: String) {
        connections.removeAll { it.url == url }
        val configs = settings.apkMcpConfigs.toMutableList()
        configs.removeAll { it.url == url }
        settings.apkMcpConfigs = configs
    }

    /** Lightweight liveness ping for all connections. */
    @Synchronized
    fun ping(): State {
        syncConnectionsFromSettings()
        if (connections.isEmpty()) return State()
        val exec = java.util.concurrent.Executors.newFixedThreadPool(
            connections.size.coerceIn(1, 4)
        )
        try {
            val results = connections.map { conn -> exec.submit<State> { conn.ping() } }
            results.forEach { it.get() }
        } finally {
            exec.shutdown()
        }
        return connections.firstOrNull()?.state ?: State()
    }

    /** Collect all tools from all online bridge connections. */
    fun mergedTools(): List<ToolDef> {
        val all = mutableListOf<ToolDef>()
        for (conn in connections) {
            val st = conn.state
            if (st.online) {
                all.addAll(st.tools.filter { it.name.startsWith(st.toolPrefix) })
            }
        }
        return all
    }

    /** Check if a tool name is handled by any bridged connection. */
    fun isBridgedTool(name: String): Boolean {
        for (conn in connections) {
            val st = conn.state
            if (st.online && name.startsWith(st.toolPrefix)) return true
        }
        return false
    }

    /** Returns the prefix of the first online bridge, or the first connection's prefix. */
    fun bridgedPrefix(): String {
        for (conn in connections) {
            val st = conn.state
            if (st.online) return st.toolPrefix
        }
        return connections.firstOrNull()?.state?.toolPrefix ?: MT_PREFIX
    }

    /** Get all known prefixes from all connections (both online and offline). */
    fun allPrefixes(): List<String> {
        val prefixes = mutableSetOf<String>()
        for (conn in connections) {
            val st = conn.state
            if (st.online) prefixes.add(st.toolPrefix)
        }
        return prefixes.toList()
    }

    /**
     * Call a tool on the correct bridge connection based on the tool name prefix.
     */
    fun callTool(name: String, arguments: JSONObject): JSONObject {
        // Find the connection whose prefix matches this tool name
        for (conn in connections) {
            val st = conn.state
            if (st.online && name.startsWith(st.toolPrefix)) {
                return conn.callTool(name, arguments)
            }
        }
        // If no online connection matches, try finding any connection that was configured for this prefix
        val offlineMsg = StringBuilder("APK MCP bridge is offline. Configured: ")
        for (conn in connections) {
            offlineMsg.append("${conn.url} (${conn.state.online}) ")
        }
        if (connections.isEmpty()) offlineMsg.append("(none)")
        return JSONObject().put(
            "content",
            JSONArray().put(JSONObject().put("type", "text").put("text", offlineMsg.toString()))
        )
            .put("isError", true)
            .put("source", "apk-mcp-bridge")
    }

    @Synchronized
    fun startHealthMonitor(intervalMs: Long = 30_000) {
        for (conn in connections) {
            conn.startHealthMonitor(intervalMs)
        }
    }

    @Synchronized
    fun stopHealthMonitor() {
        for (conn in connections) {
            conn.stopHealthMonitor()
        }
    }

    fun snapshotJson(): JSONObject {
        val configs = settings.apkMcpConfigs
        val bridges = JSONArray()
        for (config in configs) {
            val conn = connections.firstOrNull { it.url == config.url }
            val st = conn?.state ?: State(url = config.url)
            bridges.put(
                JSONObject()
                    .put("url", config.url)
                    .put("online", st.online)
                    .put("toolPrefix", st.toolPrefix)
                    .put("toolCount", st.tools.size)
                    .put("lastError", st.lastError)
                    .put("lastCheckedAt", st.lastCheckedAt)
                    .put("lastLatencyMs", st.lastLatencyMs)
                    .put("avgLatencyMs", st.avgLatencyMs())
                    .put("maxLatencyMs", st.maxLatencyMs)
                    .put("probes", st.probes)
                    .put("probeFailures", st.probeFailures)
                    .put("lossRate", st.lossRate())
                    .put("tools", JSONArray().apply { st.tools.forEach { put(it.name) } })
            )
        }
        val firstOnline = connections.firstOrNull { it.state.online }
        val first = connections.firstOrNull()
        return JSONObject().apply {
            put("configured", configs.isNotEmpty())
            put("bridgeCount", configs.size)
            put("onlineCount", connections.count { it.state.online })
            put("bridges", bridges)
            // Backward compat fields
            put("url", first?.url ?: "")
            put("online", firstOnline?.state?.online == true)
            put("toolPrefix", firstOnline?.state?.toolPrefix ?: first?.state?.toolPrefix ?: "")
            put("toolCount", firstOnline?.state?.tools?.size ?: 0)
            put("lastError", firstOnline?.state?.lastError ?: first?.state?.lastError ?: "")
            put(
                "lastCheckedAt",
                firstOnline?.state?.lastCheckedAt ?: first?.state?.lastCheckedAt ?: 0
            )
            put(
                "lastLatencyMs",
                firstOnline?.state?.lastLatencyMs ?: first?.state?.lastLatencyMs ?: 0
            )
            put(
                "avgLatencyMs",
                firstOnline?.state?.avgLatencyMs() ?: first?.state?.avgLatencyMs() ?: 0
            )
            put("maxLatencyMs", firstOnline?.state?.maxLatencyMs ?: first?.state?.maxLatencyMs ?: 0)
            put("probes", firstOnline?.state?.probes ?: first?.state?.probes ?: 0)
            put(
                "probeFailures",
                firstOnline?.state?.probeFailures ?: first?.state?.probeFailures ?: 0
            )
            put("lossRate", firstOnline?.state?.lossRate() ?: first?.state?.lossRate() ?: 0.0)
            put(
                "tools",
                JSONArray().apply {
                    (firstOnline?.state?.tools ?: first?.state?.tools ?: emptyList()).forEach {
                        put(it.name)
                    }
                }
            )
        }
    }

    companion object {
        const val DEFAULT_PORT = 8787
        const val MT_PREFIX = "mt_apk_"
        val KNOWN_PREFIXES = listOf(MT_PREFIX)
        private val connIdCounter = AtomicInteger(1000)

        fun prefixLabel(prefix: String?): String = when (prefix) {
            MT_PREFIX -> "MT Manager"
            else -> "Unknown"
        }
    }
}

private fun String?.ifNotBlank(block: (String) -> Unit) {
    if (this != null && isNotBlank()) block(this)
}
