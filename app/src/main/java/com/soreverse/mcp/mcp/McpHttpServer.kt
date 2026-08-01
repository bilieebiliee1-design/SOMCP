package com.soreverse.mcp.mcp

import android.content.Context
import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.ApkBridgeInstance
import com.soreverse.mcp.core.ApkBridgeManager
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.obj
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import com.soreverse.mcp.core.ToolStats
import com.soreverse.mcp.nativecore.NativeEngine
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.header
import io.ktor.server.request.receiveText
import io.ktor.server.request.uri
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.Semaphore

class McpHttpServer(private val context: Context, private val port: Int, private val host: String) {
    private val startedAt = System.currentTimeMillis()
    private var engine: EmbeddedServer<*, *>? = null
    @Volatile private var heavyPermits = 1
    private var heavyGate: Semaphore = Semaphore(1)

    private object RateLimiter {
        private val window = 60_000L
        private val lock = Any()
        private val byTool = HashMap<String, ArrayDeque<Long>>()
        fun tryAcquire(name: String, limit: Int): Boolean = synchronized(lock) {
            if (limit <= 0) return@synchronized true
            val now = System.currentTimeMillis()
            val timestamps = byTool.getOrPut(name) { ArrayDeque() }
            while (timestamps.firstOrNull()?.let { now - it > window } == true) timestamps.removeFirst()
            if (timestamps.size >= limit) return@synchronized false
            timestamps.addLast(now)
            true
        }
        fun reset(name: String? = null) = synchronized(lock) {
            if (name == null) byTool.clear() else byTool.remove(name)
        }
    }

    fun reconfigureHeavyPermits(permits: Int) {
        val p = permits.coerceIn(1, 16)
        if (p == heavyPermits) return
        heavyPermits = p
        heavyGate = Semaphore(p)
        AppLog.i("heavy tool gate permits=$p")
    }

    val apkBridgeManager: ApkBridgeManager get() = bridgeManagerHolder ?: ApkBridgeManager(SettingsStore(context)).also { bridgeManagerHolder = it }
    private var bridgeManagerHolder: ApkBridgeManager? = null
    val tunnel: CloudflareTunnelManager get() = tunnelHolder ?: CloudflareTunnelManager(context, SettingsStore(context)).also { tunnelHolder = it }
    private var tunnelHolder: CloudflareTunnelManager? = null

    fun ensureBridgeProbed() {
        val s = SettingsStore(context)
        if (!s.apkMcpAutoProbe) return
        apkBridgeManager.refreshFromSettings()
        if (s.apkBridgeConfigs.isNotEmpty()) {
            Thread { apkBridgeManager.probeAll() }.start()
        }
    }

    fun start() {
        if (engine != null) return
        NativeEngine.select(SettingsStore(context).nativeBackend)
        engine = embeddedServer(CIO, host = host, port = port) {
            routing {
                get("/") { call.respondText(serverDiscovery().toString(), ContentType.Application.Json) }
                get("/.well-known/mcp") { call.respondText(serverDiscovery().toString(), ContentType.Application.Json) }
                get("/health") { call.respondText(JSONObject().put("ok", true).put("server", "SOMCP").put("endpoint", "/mcp").toString(), ContentType.Application.Json) }
                get("/mcp") {
                    if (!call.authorized()) { call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized); return@get }
                    val accept = call.request.header("Accept").orEmpty()
                    if (accept.contains("text/event-stream")) { call.respondText(sseHello(), ContentType.Text.EventStream) } else { call.respondText(serverDiscovery().toString(), ContentType.Application.Json) }
                }
                get("/sse") { if (!call.authorized()) { call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized); return@get }; call.respondText(sseHello(), ContentType.Text.EventStream) }
                post("/mcp") { handleJsonRpcPost(call) }
                post("/rpc") { handleJsonRpcPost(call) }
                post("/messages") { handleJsonRpcPost(call) }
            }
        }.start(wait = false)
        val settings = SettingsStore(context)
        reconfigureHeavyPermits(settings.maxConcurrentTools)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        AppLog.i("Ktor MCP server listening on $host:$port/mcp (permits=${settings.maxConcurrentTools})")
        ensureBridgeProbed()
        apkBridgeManager.startAllHealthMonitors()
    }

    fun stop() {
        apkBridgeManager.stopAllHealthMonitors()
        engine?.stop(gracePeriodMillis = 400, timeoutMillis = 1_500)
        engine = null
        AppLog.i("Ktor MCP server stopped")
    }

    private suspend fun handleJsonRpcPost(call: ApplicationCall) {
        if (!call.authorized()) { call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized); return }
        val settings = SettingsStore(context)
        val maxBytes = settings.maxRequestKb * 1024
        val contentLength = call.request.header("Content-Length")?.toLongOrNull()
        if (contentLength != null && contentLength > maxBytes) { call.respondText(requestTooLarge(maxBytes).toString(), ContentType.Application.Json, status = HttpStatusCode.PayloadTooLarge); return }
        val body = call.receiveText()
        if (body.toByteArray(Charsets.UTF_8).size > maxBytes) { call.respondText(requestTooLarge(maxBytes).toString(), ContentType.Application.Json, status = HttpStatusCode.PayloadTooLarge); return }
        val response = dispatchBody(body)
        if (response === NoResponse) { call.respondText("", ContentType.Application.Json, status = HttpStatusCode.Accepted); return }
        val accept = call.request.header("Accept").orEmpty()
        if (accept.contains("text/event-stream")) { call.respondText("event: message\ndata: $response\n\n", ContentType.Text.EventStream) } else { call.respondText(response.toString(), ContentType.Application.Json) }
    }

    private fun serverDiscovery(): JSONObject = JSONObject()
        .put("ok", true).put("name", "SOMCP").put("protocol", "MCP JSON-RPC 2.0").put("endpoint", "/mcp").put("sseEndpoint", "/sse").put("messagesEndpoint", "/messages")
        .put("methods", JSONArray(listOf("initialize", "notifications/initialized", "ping", "tools/list", "tools/call", "resources/list", "prompts/list")))
        .put("hint", "POST JSON-RPC to /mcp. GET /mcp with Accept: text/event-stream returns an SSE compatibility hello.")

    private fun sseHello(): String = "event: endpoint\ndata: ${JSONObject().put("uri", "/messages").put("method", "POST")}\n\n: SOMCP ready\n\n"

    private fun dispatchBody(body: String): Any {
        val trimmed = body.trim()
        if (trimmed.isEmpty()) return jsonRpcError(JSONObject.NULL, -32700, "Parse error")
        if (trimmed.startsWith("[")) {
            val arr = try { JSONArray(trimmed) } catch (_: JSONException) { return jsonRpcError(JSONObject.NULL, -32700, "Parse error") }
            val out = JSONArray()
            if (arr.length() == 0) return jsonRpcError(JSONObject.NULL, -32600, "Invalid Request")
            for (i in 0 until arr.length()) { val req = arr.optJSONObject(i); val res = if (req == null) jsonRpcError(JSONObject.NULL, -32600, "Invalid Request") else dispatch(req); if (res !== NoResponse) out.put(res) }
            return if (out.length() == 0) NoResponse else out
        }
        val req = try { JSONObject(trimmed) } catch (_: JSONException) { return jsonRpcError(JSONObject.NULL, -32700, "Parse error") }
        return dispatch(req)
    }

    private fun dispatch(req: JSONObject): JSONObject {
        val id = req.opt("id")
        val method = req.optString("method")
        if (!req.has("jsonrpc") || req.optString("jsonrpc") != "2.0" || method.isBlank()) return jsonRpcError(id ?: JSONObject.NULL, -32600, "Invalid Request")
        val isNotification = !req.has("id") || method.startsWith("notifications/")
        if (isNotification) return NoResponse
        val params = req.optJSONObject("params") ?: JSONObject()
        val result = when (method) {
            "initialize" -> JSONObject().put("protocolVersion", "2025-06-18").put("capabilities", JSONObject().put("tools", JSONObject().put("listChanged", false))).put("serverInfo", JSONObject().put("name", "SOMCP").put("version", BuildConfig.VERSION_NAME))
            "ping" -> JSONObject().put("ok", true)
            "resources/list" -> JSONObject().put("resources", JSONArray())
            "prompts/list" -> JSONObject().put("prompts", JSONArray())
            "tools/list" -> { val advertised = advertisedTools(); JSONObject().put("tools", advertised) }
            "tools/call" -> callTool(params)
            else -> return jsonRpcError(id ?: JSONObject.NULL, -32601, "Method not found")
        }
        return JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result)
    }

    private fun jsonRpcError(id: Any?, code: Int, message: String): JSONObject = JSONObject().put("jsonrpc", "2.0").put("id", id ?: JSONObject.NULL).put("error", JSONObject().put("code", code).put("message", message))
    private val NoResponse: JSONObject = JSONObject().put("__noResponse", true)

    private fun callTool(params: JSONObject): JSONObject {
        val name = params.str("name")
        val args = params.obj("arguments")
        return wrapToolResult(callToolWithPolicy(name, args))
    }

    private fun callToolWithPolicy(name: String, args: JSONObject): JSONObject {
        val settings = SettingsStore(context)
        if (name.isNotEmpty() && isToolDisabled(settings, name)) return err("TOOL_DISABLED", "Tool $name is disabled by server policy (settings.disabledTools).")
        val rateLimit = settings.toolCallRateLimitPerMin
        if (rateLimit > 0 && !RateLimiter.tryAcquire(name, rateLimit)) return err("RATE_LIMITED", "Tool $name hit the per-minute rate limit ($rateLimit/min). Retry shortly.")
        val heavy = name in ToolCatalog.heavyNames
        val acquiredGate = heavyGate
        if (heavy && !acquiredGate.tryAcquire()) { val busy = err("SERVER_BUSY", "Another analysis task is running. Retry the same call shortly."); busy.getJSONObject("error").put("retrySameArguments", true).put("retryAfterMillis", 750); busy.put("nextActions", JSONArray(listOf("Retry the exact same tool call after a short delay."))); return busy }
        return try { callToolPayload(name, args) } finally { if (heavy) acquiredGate.release() }
    }

    private fun isToolDisabled(settings: SettingsStore, name: String): Boolean { val raw = settings.disabledTools; if (raw.isBlank()) return false; return raw.split(',').any { it.trim() == name } }

    private fun tools(): JSONArray {
        val settings = SettingsStore(context)
        val includeCategory = settings.includeCategoryInSchema
        val out = JSONArray()
        ToolCatalog.ALL.forEach { handler -> out.put(ToolCatalog.toolDescriptor(handler, includeCategory)) }
        if (settings.apkMcpMergeTools) {
            val aggregatedTools = apkBridgeManager.aggregatedTools()
            aggregatedTools.forEach { td ->
                val schema = td.inputSchema ?: JSONObject().put("type", "object").put("properties", JSONObject())
                val obj = JSONObject().put("name", td.name).put("description", "[APK ONLY — NOT for SO/native files] ${td.description ?: td.title ?: "APK MCP tool"} Use so_open + analyze_* + edit_* for SO file tasks.").put("inputSchema", schema)
                if (includeCategory) obj.put("category", "apk-bridge")
                if (td.outputSchema != null) obj.put("outputSchema", td.outputSchema)
                out.put(obj)
            }
        }
        return out
    }

    private fun callToolPayload(name: String, args: JSONObject): JSONObject {
        val native = EngineProvider.get(context)
        val settings = SettingsStore(context)
        ToolStats.setEnabled(settings.collectToolStats)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        val started = System.nanoTime()
        val ctx = createHookedContext(native, settings)
        val handler = ToolCatalog.byName[name]
        val payload = if (handler != null) { handler.handle(ctx, args) } else { val bridge = apkBridgeManager.bridgeForTool(name); if (bridge != null && bridge.isBridgedTool(name)) bridge.callTool(name, args) else err("APK_MCP_OFFLINE", "APK MCP bridge is offline for tool $name. Check bridge connections.", "tool", name) }
        val elapsedMicros = (System.nanoTime() - started) / 1000
        val isOk = payload.optBoolean("ok", true)
        val errMsg = payload.optJSONObject("error")?.optString("message").orEmpty()
        ToolStats.record(name, isOk, elapsedMicros, errMsg)
        AppLog.i("Tool call $name -> ok=$isOk (${elapsedMicros / 1000.0}ms)")
        return payload
    }

    private fun createHookedContext(native: com.soreverse.mcp.core.NativeEngine, settings: SettingsStore): HookedContext {
        return HookedContext(
            context = context, settings = settings, engine = native,
            healthHook = { health() }, statsHook = { ToolStats.snapshot() }, resetStatsHook = { ToolStats.reset() },
            toolsCountHook = { toolsCount() }, helpHook = { help() }, listToolsHook = { cat, q -> listTools(cat, q) },
            describeToolsHook = { names -> describeTools(names) }, workflowsHook = { workflows() }, suggestHook = { args -> suggestions(args) },
            errorsHook = { errorCatalog() }, reportHook = { args -> native.analysisReport(args.str("workspaceId"), args.str("editSessionId"), args.bool("writeToFile", true)) },
            capabilitiesHook = { ok(native.capabilityRegistry()) }, batchHook = { batchArgs -> batchTool(batchArgs) },
            continueHook = { cursor -> native.continuePage(cursor) }, sysStatusHook = { probe -> sysStatus(probe) },
            tunnelStatusHook = { ok(tunnel.snapshotJson()) }, tunnelStatsHook = { reset -> if (reset) tunnel.resetTunnelStats(); ok(tunnel.tunnelStats()) },
            tunnelStartHook = { mode, port, token, publicUrl -> val resolvedMode = if (mode == "named") CloudflareTunnelManager.Mode.NAMED else CloudflareTunnelManager.Mode.QUICK; val targetPort = if (port > 0) port else settings.tunnelTargetPort; val tok = if (token.isNotBlank()) token else settings.tunnelNamedToken; if (resolvedMode == CloudflareTunnelManager.Mode.NAMED && !publicUrl.isNullOrBlank()) { settings.tunnelNamedPublicUrl = publicUrl }; val ts = tunnel.start(targetPort, resolvedMode, tok); ok(tunnel.snapshotJson().put("message", ts.message).put("publicUrl", ts.publicUrl ?: JSONObject.NULL)) },
            tunnelStopHook = { tunnel.stop(); ok(JSONObject().put("stopped", true)) },
            apkStatusHook = { probe -> apkBridgeManager.probeAll(); ok(apkBridgeManager.snapshotJson()) },
            apkProbeHook = { apkBridgeManager.probeAll(); ok(apkBridgeManager.snapshotJson()) },
            apkPingHook = { apkBridgeManager.probeAll(); ok(apkBridgeManager.snapshotJson()) },
        )
    }

    private fun wrapToolResult(payload: JSONObject): JSONObject {
        val settings = SettingsStore(context)
        val payloadText = payload.toString().replace("\\/", "/")
        val cap = settings.toolResultMaxChars
        val rendered = if (cap > 0 && payloadText.length > cap) { err("RESULT_TRUNCATED", "Tool result exceeded configured character limit", "limit", cap).put("truncated", true).put("originalLength", payloadText.length).put("preview", payloadText.substring(0, cap)).toString() } else payloadText
        return JSONObject().put("isError", payload.optBoolean("ok", true).not()).put("content", JSONArray().put(JSONObject().put("type", "text").put("text", rendered)))
    }

    private fun io.ktor.server.application.ApplicationCall.authorized(): Boolean {
        val settings = SettingsStore(context)
        if (!settings.authEnabled) return true
        val token = settings.accessToken
        if (token.isBlank()) return false
        val auth = request.header("Authorization").orEmpty()
        val bearer = auth.removePrefix("Bearer").trim()
        val queryToken = request.uri.substringAfter("token=", "").substringBefore('&')
        return constantTimeEquals(bearer, token) || constantTimeEquals(queryToken, token)
    }

    private fun constantTimeEquals(candidate: String, secret: String): Boolean = java.security.MessageDigest.isEqual(candidate.toByteArray(Charsets.UTF_8), secret.toByteArray(Charsets.UTF_8))

    private fun authError(): JSONObject = JSONObject().put("jsonrpc", "2.0").put("id", JSONObject.NULL).put("error", JSONObject().put("code", -32001).put("message", "Unauthorized: missing or invalid SOMCP token"))

    private fun requestTooLarge(maxBytes: Int): JSONObject = JSONObject().put("jsonrpc", "2.0").put("id", JSONObject.NULL).put("error", JSONObject().put("code", -32002).put("message", "Request body is larger than configured SOMCP limit").put("data", JSONObject().put("maxBytes", maxBytes)))

    private fun health(): JSONObject = ok(JSONObject().put("status", "ok").put("server", "somcp").put("uptimeMillis", System.currentTimeMillis() - startedAt).put("toolCount", advertisedTools().length()).put("apkMcp", apkBridgeManager.snapshotJson()))

    private fun sysStatus(probe: Boolean): JSONObject {
        val s = SettingsStore(context)
        return ok(JSONObject()
            .put("soMcp", JSONObject().put("running", engine != null).put("host", host).put("port", port))
            .put("apkMcp", apkBridgeManager.snapshotJson())
            .put("tunnel", tunnel.snapshotJson())
            .put("integration", JSONObject().put("online", apkBridgeManager.allOnlineBridges().isNotEmpty()).put("apkMcpUrl", s.apkMcpUrl)
                .put("hint", if (apkBridgeManager.allOnlineBridges().isNotEmpty()) { val labels = apkBridgeManager.allOnlineBridges().joinToString(" + ") { it.config.label }; "Online bridges: $labels. Use bridged tools for APK tasks, built-in tools for SO analysis." } else "APK MCP is offline. Install MT Manager or NP Manager, enable the APK MCP feature, keep it running in background, then set its /mcp URL in settings and call system_control (action=apk_probe).")))
    }

    private fun toolsCount(): JSONObject = ok(JSONObject().put("totalCatalogCount", ToolCatalog.ALL.size).put("advertisedCount", advertisedTools().length()).put("apkBridge", apkBridgeManager.snapshotJson()))

    private fun advertisedTools(): JSONArray { val full = tools(); return full }

    private fun help(): JSONObject = ok(JSONObject().put("usage", "Use so_open for SO analysis, bridged tools for APK tasks.").put("bridges", apkBridgeManager.snapshotJson()))

    private fun workflows(): JSONObject = ok(JSONObject().put("templates", JSONArray()))

    private fun suggestions(args: JSONObject): JSONObject = ok(JSONObject().put("nextActions", JSONArray()))

    private fun errorCatalog(): JSONObject = ok(JSONObject().put("codes", JSONArray(listOf("TOOL_DISABLED", "RATE_LIMITED", "SERVER_BUSY", "APK_MCP_OFFLINE", "TOOL_NOT_FOUND"))))

    private fun listTools(category: String, query: String): JSONObject = ok(JSONObject().put("category", category).put("query", query).put("tools", JSONArray()))

    private fun describeTools(names: List<String>): JSONObject = ok(JSONObject().put("tools", JSONArray()))

    private fun batchTool(args: JSONObject): JSONObject = ok(JSONObject())

    private fun bridgeLabel(): String {
        val bridges = apkBridgeManager.allOnlineBridges()
        val hasNp = bridges.any { it.bridgedPrefix() == ApkBridgeInstance.NP_PREFIX }
        val hasMt = bridges.any { it.bridgedPrefix() == ApkBridgeInstance.MT_PREFIX }
        return when { hasNp && hasMt -> "MT+NP Manager"; hasNp -> "NP Manager"; hasMt -> "MT Manager"; else -> "APK MCP" }
    }
}

internal fun tokenConstantTimeEquals(candidate: String, secret: String): Boolean {
    if (candidate.isEmpty() || secret.isEmpty()) return false
    return java.security.MessageDigest.isEqual(candidate.toByteArray(Charsets.UTF_8), secret.toByteArray(Charsets.UTF_8))
}