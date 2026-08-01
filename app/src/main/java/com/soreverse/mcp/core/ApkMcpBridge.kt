package com.soreverse.mcp.core

import com.soreverse.mcp.core.AppLog
import org.json.JSONArray
import org.json.JSONObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Bridge to an external "APK MCP" server (MT Manager or NP Manager).
 *
 * Acts as an MCP gateway: discovers the remote server's tools via tools/list,
 * merges them under their native prefix (mt_apk_* or np_*) into our own
 * tools/list responses, and transparently forwards tools/call invocations
 * back to the remote server.
 *
 * When the remote is unreachable, tools are hidden so the local server behaves
 * as a standalone SO-only MCP. When reachable, the client gets a combined
 * SO+APK reverse-engineering toolset ("combo") without re-implementing APK
 * analysis from scratch.
 */
class ApkMcpBridge(private val settings: SettingsStore) {

    data class ToolDef(
        val name: String,
        val title: String?,
        val description: String?,
        val inputSchema: JSONObject?,
        val outputSchema: JSONObject?,
    )

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
        val maxLatencyMs: Long = 0,
    ) {
        fun avgLatencyMs(): Long = if (probes > 0) totalLatencyMs / probes else 0
        fun lossRate(): Double = if (probes == 0L) 0.0 else probeFailures.toDouble() / probes
    }

    private val _state = AtomicReference(State())
    fun state(): State = _state.get()

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    fun configured(): Boolean = settings.apkMcpUrl.isNotBlank()

    @Synchronized
    fun autoDiscover(port: Int = DEFAULT_PORT): State {
        val allPorts = if (port == DEFAULT_PORT) listOf(port, NP_PORT) else listOf(port)
        for (p in allPorts) {
            val candidates = listOf(
                "http://127.0.0.1:$p/mcp",
                "http://localhost:$p/mcp",
            )
            for (url in candidates) {
                try {
                    val req = buildJsonRpc(url, "tools/list", JSONObject(), id = 1)
                    val resp = post(req)
                    val parsed = parseTools(resp)
                    val prefix = parsed.firstOrNull { it.name.startsWith(MT_PREFIX) }?.let { MT_PREFIX }
                        ?: parsed.firstOrNull { it.name.startsWith(NP_PREFIX) }?.let { NP_PREFIX }
                        ?: continue
                    settings.apkMcpUrl = url
                    val s = State(url = url, online = true, lastError = "", tools = parsed, toolPrefix = prefix, lastCheckedAt = System.currentTimeMillis())
                    _state.set(s)
                    val label = if (prefix == MT_PREFIX) "MT Manager" else "NP Manager"
                    AppLog.i("apk-mcp auto-discovered $label at $url (${parsed.size} tools, prefix=$prefix)")
                    return s
                } catch (_: Exception) {
                }
            }
        }
        AppLog.i("apk-mcp auto-discovery: no APK MCP found on ports $allPorts")
        return _state.get()
    }

    @Synchronized
    fun probe(): State {
        val url = settings.apkMcpUrl
        if (url.isBlank()) {
            val s = State(url = "", online = false, lastError = "not configured")
            _state.set(s)
            return s
        }
        try {
            val req = buildJsonRpc(url, "tools/list", JSONObject(), id = 1)
            val start = System.nanoTime()
            val resp = post(req)
            val latencyMs = (System.nanoTime() - start) / 1_000_000
            val parsed = parseTools(resp)
            val prefix = parsed.firstOrNull { it.name.startsWith(MT_PREFIX) }?.let { MT_PREFIX }
                ?: parsed.firstOrNull { it.name.startsWith(NP_PREFIX) }?.let { NP_PREFIX }
                ?: _state.get().toolPrefix
            val prev = _state.get()
            val s = State(
                url = url,
                online = true,
                lastError = "",
                tools = parsed,
                toolPrefix = prefix,
                lastCheckedAt = System.currentTimeMillis(),
                lastLatencyMs = latencyMs,
                probes = prev.probes + 1,
                probeFailures = prev.probeFailures,
                totalLatencyMs = prev.totalLatencyMs + latencyMs,
                maxLatencyMs = maxOf(prev.maxLatencyMs, latencyMs),
            )
            _state.set(s)
            val label = if (prefix == MT_PREFIX) "MT Manager" else "NP Manager"
            AppLog.i("apk-mcp bridge online: ${parsed.size} tools from $url ($label, ${latencyMs}ms)")
            return s
        } catch (e: Exception) {
            val prev = _state.get()
            val s = State(url = url, online = false, lastError = e.message ?: e.javaClass.simpleName, probes = prev.probes + 1, probeFailures = prev.probeFailures + 1, totalLatencyMs = prev.totalLatencyMs, maxLatencyMs = prev.maxLatencyMs)
            _state.set(s)
            AppLog.w("apk-mcp probe failed: ${e.message}")
            return s
        }
    }

    /**
     * Lightweight liveness probe (initialize round-trip). Cheaper than probe()
     * since it parses the JSON-RPC envelope only and skips tool-schema
     * decoding. Updates latency/failure counters but does NOT rewrite the
     * tool list — call probe() after connectivity is (re)established to also
     * refresh tools.
     */
    @Synchronized
    fun ping(): State {
        val url = settings.apkMcpUrl
        if (url.isBlank()) {
            return _state.get()
        }
        return try {
            val req = buildJsonRpc(url, "initialize", JSONObject().put("client", "somcp-ping"), id = nextId())
            val start = System.nanoTime()
            post(req)
            val latencyMs = (System.nanoTime() - start) / 1_000_000
            val prev = _state.get()
            val s = if (!prev.online) {
                prev.copy(lastLatencyMs = latencyMs, lastCheckedAt = System.currentTimeMillis(), probes = prev.probes + 1, lastError = "", online = false, tools = prev.tools)
            } else {
                State(url = url, online = true, lastError = "", tools = prev.tools, lastCheckedAt = System.currentTimeMillis(), lastLatencyMs = latencyMs, probes = prev.probes + 1, probeFailures = prev.probeFailures, totalLatencyMs = prev.totalLatencyMs + latencyMs, maxLatencyMs = maxOf(prev.maxLatencyMs, latencyMs))
            }
            _state.set(s)
            s
        } catch (e: Exception) {
            val prev = _state.get()
            val s = State(url = url, online = false, lastError = e.message ?: e.javaClass.simpleName, probes = prev.probes + 1, probeFailures = prev.probeFailures + 1, totalLatencyMs = prev.totalLatencyMs, maxLatencyMs = prev.maxLatencyMs)
            _state.set(s)
            s
        }
    }

    fun mergedTools(): List<ToolDef> {
        val st = _state.get()
        val prefix = st.toolPrefix
        return if (st.online) st.tools.filter { it.name.startsWith(prefix) } else emptyList()
    }

    fun isBridgedTool(name: String): Boolean {
        val prefix = _state.get().toolPrefix
        return name.startsWith(prefix) && _state.get().online
    }

    /** Returns the current tool prefix (mt_apk_ or np_). */
    fun bridgedPrefix(): String = _state.get().toolPrefix

    @Synchronized
    fun callTool(name: String, arguments: JSONObject): JSONObject {
        val st = _state.get()
        if (!st.online || st.url.isBlank()) {
            return errorResult(name, "APK MCP is offline or not configured")
        }
        val params = JSONObject().put("name", name).put("arguments", arguments)
        return try {
            val req = buildJsonRpc(st.url, "tools/call", params, id = nextId())
            val resp = post(req)
            // remote returns a JSON-RPC envelope; unwrap returnContent into our shape
            parseToolResult(resp)
        } catch (e: Exception) {
            errorResult(name, "forward failed: ${e.message}")
        }
    }

    @Volatile private var healthThread: Thread? = null
    @Volatile private var healthStop = false

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
                val url = settings.apkMcpUrl
                if (url.isBlank()) continue
                try {
                    val req = buildJsonRpc(url, "tools/list", JSONObject(), id = 1)
                    val resp = post(req)
                    val parsed = parseTools(resp)
                    val prefix = parsed.firstOrNull { it.name.startsWith(MT_PREFIX) }?.let { MT_PREFIX }
                        ?: parsed.firstOrNull { it.name.startsWith(NP_PREFIX) }?.let { NP_PREFIX }
                    if (prefix != null) {
                        val cur = _state.get()
                        _state.set(State(url = url, online = true, lastError = "", tools = parsed, toolPrefix = prefix, lastCheckedAt = System.currentTimeMillis()))
                        if (!cur.online) AppLog.i("apk-mcp health: back online (${parsed.size} tools, prefix=$prefix)")
                    }
                } catch (e: Exception) {
                    val cur = _state.get()
                    if (cur.online) {
                        _state.set(State(url = url, online = false, lastError = e.message ?: e.javaClass.simpleName, tools = emptyList(), lastCheckedAt = System.currentTimeMillis()))
                        AppLog.w("apk-mcp health: marked offline (${e.message})")
                    }
                }
            }
        }, "apk-mcp-health").apply { isDaemon = true; start() }
    }

    fun stopHealthMonitor() {
        healthStop = true
        healthThread?.interrupt()
        healthThread = null
    }

    fun snapshotJson(): JSONObject {
        val st = _state.get()
        return JSONObject().apply {
            put("configured", st.url.isNotBlank())
            put("url", st.url)
            put("online", st.online)
            put("toolPrefix", st.toolPrefix)
            put("toolCount", st.tools.size)
            put("lastError", st.lastError)
            put("lastCheckedAt", st.lastCheckedAt)
            put("lastLatencyMs", st.lastLatencyMs)
            put("avgLatencyMs", st.avgLatencyMs())
            put("maxLatencyMs", st.maxLatencyMs)
            put("probes", st.probes)
            put("probeFailures", st.probeFailures)
            put("lossRate", st.lossRate())
            put("tools", JSONArray().apply { st.tools.forEach { put(it.name) } })
        }
    }

    private fun buildJsonRpc(url: String, method: String, params: JSONObject, id: Int): Request {
        val body = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", method)
            .put("params", params)
            .toString()
        val builder = Request.Builder().url(url).post(body.toRequestBody("application/json".toMediaType()))
        settings.apkMcpToken.ifNotBlank { builder.safeHeader("Authorization", "Bearer $it") }
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
                    outputSchema = t.optJSONObject("outputSchema"),
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

    private fun errorResult(name: String, msg: String): JSONObject {
        return JSONObject().put("content", JSONArray().put(JSONObject().put("type", "text").put("text", "APK MCP error [$name]: $msg")))
            .put("isError", true)
            .put("source", "apk-mcp-bridge")
    }

    private fun nextId(): Int = idCounter++

    companion object {
        const val DEFAULT_PORT = 8787
        const val NP_PORT = 8788
        const val MT_PREFIX = "mt_apk_"
        const val NP_PREFIX = "np_"
        val KNOWN_PREFIXES = listOf(MT_PREFIX, NP_PREFIX)
        private var idCounter = 100
    }
}

private fun String?.ifNotBlank(block: (String) -> Unit) {
    if (this != null && isNotBlank()) block(this)
}
