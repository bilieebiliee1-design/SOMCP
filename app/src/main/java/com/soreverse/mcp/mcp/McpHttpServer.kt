package com.soreverse.mcp.mcp

import android.content.Context
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.ApkMcpBridge
import com.soreverse.mcp.core.CloudflareTunnelManager
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.intValue
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

    /**
     * Per-tool sliding-window rate limiter. A 60s deque of call timestamps
     * per tool name; entries older than 60s are evicted lazily on each probe.
     * When `SettingsStore.toolCallRateLimitPerMin > 0`, callTool rejects new
     * calls for that tool once the in-window count reaches the limit. The
     * limiter is independent of the heavy concurrency gate so that even
     * lightweight tools (meta_info help/tools/describe) can be throttled.
     */
    private object RateLimiter {
        private val window = 60_000L
        private val byTool = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.ConcurrentLinkedDeque<Long>>()
        fun tryAcquire(name: String, limit: Int): Boolean {
            if (limit <= 0) return true
            val now = System.currentTimeMillis()
            val dq = byTool.computeIfAbsent(name) { java.util.concurrent.ConcurrentLinkedDeque() }
            // Evict stale entries.
            while (true) {
                val head = dq.peekFirst() ?: break
                if (now - head > window) dq.pollFirst() else break
            }
            if (dq.size >= limit) return false
            dq.addLast(now)
            return true
        }
        fun reset(name: String? = null) {
            if (name == null) byTool.clear() else byTool.remove(name)
        }
    }

    /**
     * Reconfigure the heavy-tool concurrency gate. Lower permits ⇒ stricter
     * serialization (default 1 — one big analysis/patch at a time, same
     * conservative behavior as before). Bumping permits lets a host pipeline
     * parallel read/inspect calls while one heavy edit runs. Caller must
     * reconfigure to current settings on every start.
     */
    fun reconfigureHeavyPermits(permits: Int) {
        val p = permits.coerceIn(1, 16)
        if (p == heavyPermits) return
        heavyPermits = p
        heavyGate = Semaphore(p)
        AppLog.i("heavy tool gate permits=$p")
    }

    val apkBridge: ApkMcpBridge get() = bridgeHolder ?: ApkMcpBridge(SettingsStore(context)).also { bridgeHolder = it }
    private var bridgeHolder: ApkMcpBridge? = null
    val tunnel: CloudflareTunnelManager get() = tunnelHolder ?: CloudflareTunnelManager(context, SettingsStore(context)).also { tunnelHolder = it }
    private var tunnelHolder: CloudflareTunnelManager? = null

    fun ensureBridgeProbed() {
        val s = SettingsStore(context)
        if (!s.apkMcpAutoProbe) return
        if (s.apkMcpUrl.isNotBlank()) {
            if (!apkBridge.state().online) Thread { apkBridge.probe() }.start()
        } else {
            Thread { apkBridge.autoDiscover(ApkMcpBridge.DEFAULT_PORT) }.start()
        }
    }

    fun start() {
        if (engine != null) return
        NativeEngine.select(SettingsStore(context).nativeBackend)
        engine = embeddedServer(CIO, host = host, port = port) {
            routing {
                get("/") {
                    call.respondText(serverDiscovery().toString(), ContentType.Application.Json)
                }
                get("/.well-known/mcp") {
                    call.respondText(serverDiscovery().toString(), ContentType.Application.Json)
                }
                get("/health") {
                    call.respondText(JSONObject().put("ok", true).put("server", "SOMCP").put("endpoint", "/mcp").toString(), ContentType.Application.Json)
                }
                get("/mcp") {
                    if (!call.authorized()) {
                        call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized)
                        return@get
                    }
                    val accept = call.request.header("Accept").orEmpty()
                    if (accept.contains("text/event-stream")) {
                        call.respondText(sseHello(), ContentType.Text.EventStream)
                    } else {
                        call.respondText(serverDiscovery().toString(), ContentType.Application.Json)
                    }
                }
                get("/sse") {
                    if (!call.authorized()) {
                        call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized)
                        return@get
                    }
                    call.respondText(sseHello(), ContentType.Text.EventStream)
                }
                post("/mcp") {
                    handleJsonRpcPost(call)
                }
                post("/rpc") {
                    handleJsonRpcPost(call)
                }
                post("/messages") {
                    handleJsonRpcPost(call)
                }
            }
        }.start(wait = false)
        val settings = SettingsStore(context)
        reconfigureHeavyPermits(settings.maxConcurrentTools)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        AppLog.i("Ktor MCP server listening on $host:$port/mcp (permits=${settings.maxConcurrentTools})")
        ensureBridgeProbed()
        apkBridge.startHealthMonitor()
    }

    fun stop() {
        apkBridge.stopHealthMonitor()
        engine?.stop(gracePeriodMillis = 400, timeoutMillis = 1_500)
        engine = null
        AppLog.i("Ktor MCP server stopped")
    }

    private suspend fun handleJsonRpcPost(call: ApplicationCall) {
        if (!call.authorized()) {
            call.respondText(authError().toString(), ContentType.Application.Json, status = HttpStatusCode.Unauthorized)
            return
        }
        val settings = SettingsStore(context)
        val maxBytes = settings.maxRequestKb * 1024
        val contentLength = call.request.header("Content-Length")?.toLongOrNull()
        if (contentLength != null && contentLength > maxBytes) {
            call.respondText(requestTooLarge(maxBytes).toString(), ContentType.Application.Json, status = HttpStatusCode.PayloadTooLarge)
            return
        }
        val body = call.receiveText()
        if (body.toByteArray(Charsets.UTF_8).size > maxBytes) {
            call.respondText(requestTooLarge(maxBytes).toString(), ContentType.Application.Json, status = HttpStatusCode.PayloadTooLarge)
            return
        }
        val response = dispatchBody(body)
        val accept = call.request.header("Accept").orEmpty()
        if (accept.contains("text/event-stream")) {
            call.respondText("event: message\ndata: $response\n\n", ContentType.Text.EventStream)
        } else {
            call.respondText(response.toString(), ContentType.Application.Json)
        }
    }

    private fun serverDiscovery(): JSONObject = JSONObject()
        .put("ok", true)
        .put("name", "SOMCP")
        .put("protocol", "MCP JSON-RPC 2.0")
        .put("endpoint", "/mcp")
        .put("sseEndpoint", "/sse")
        .put("messagesEndpoint", "/messages")
        .put("methods", JSONArray(listOf("initialize", "notifications/initialized", "ping", "tools/list", "tools/call", "resources/list", "prompts/list")))
        .put("hint", "POST JSON-RPC to /mcp. GET /mcp with Accept: text/event-stream returns an SSE compatibility hello.")

    private fun sseHello(): String {
        val endpoint = JSONObject().put("uri", "/messages").put("method", "POST")
        return "event: endpoint\ndata: $endpoint\n\n: SOMCP ready\n\n"
    }

    private fun dispatchBody(body: String): Any {
        val trimmed = body.trim()
        if (trimmed.isEmpty()) return jsonRpcError(JSONObject.NULL, -32700, "Parse error")
        if (trimmed.startsWith("[")) {
            val arr = try {
                JSONArray(trimmed)
            } catch (_: JSONException) {
                return jsonRpcError(JSONObject.NULL, -32700, "Parse error")
            }
            val out = JSONArray()
            if (arr.length() == 0) return jsonRpcError(JSONObject.NULL, -32600, "Invalid Request")
            for (i in 0 until arr.length()) {
                val req = arr.optJSONObject(i)
                out.put(if (req == null) jsonRpcError(JSONObject.NULL, -32600, "Invalid Request") else dispatch(req))
            }
            return out
        }
        val req = try {
            JSONObject(trimmed)
        } catch (_: JSONException) {
            return jsonRpcError(JSONObject.NULL, -32700, "Parse error")
        }
        return dispatch(req)
    }

    private fun dispatch(req: JSONObject): JSONObject {
        val id = req.opt("id")
        val method = req.optString("method")
        if (!req.has("jsonrpc") || req.optString("jsonrpc") != "2.0" || method.isBlank()) {
            return jsonRpcError(id ?: JSONObject.NULL, -32600, "Invalid Request")
        }
        val params = req.optJSONObject("params") ?: JSONObject()
        val result = when (method) {
            "initialize" -> JSONObject()
                .put("protocolVersion", "2025-06-18")
                .put("capabilities", JSONObject()
                    .put("tools", JSONObject().put("listChanged", false)))
                .put("serverInfo", JSONObject().put("name", "SOMCP").put("version", "1.0.0"))
                .put("_meta", JSONObject()
                    .put("builtInToolsAlwaysAdvertised", true)
                    .put("fullToolCount", ToolCatalog.ALL.size)
                    .put("hint", "tools/list advertises the complete built-in catalog. Only oversized APK-bridge tool sets may be compacted automatically."))
            "notifications/initialized" -> JSONObject()
            "ping" -> JSONObject().put("ok", true)
            "resources/list" -> JSONObject().put("resources", JSONArray())
            "prompts/list" -> JSONObject().put("prompts", JSONArray())
            "tools/list" -> {
                val advertised = advertisedTools()
                JSONObject()
                .put("tools", advertised)
                .put("_meta", JSONObject()
                    .put("builtInToolsAlwaysAdvertised", true)
                    .put("returnedCount", advertised.length())
                    .put("totalCatalogCount", ToolCatalog.ALL.size)
                    .put("hint", "tools/list returns the complete built-in catalog. Oversized APK-bridge additions may be compacted automatically."))
            }
            "tools/call" -> callTool(params)
            else -> return jsonRpcError(id ?: JSONObject.NULL, -32601, "Method not found")
        }
        return JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result)
    }

    private fun jsonRpcError(id: Any?, code: Int, message: String): JSONObject = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", id ?: JSONObject.NULL)
        .put("error", JSONObject().put("code", code).put("message", message))

    private fun callTool(params: JSONObject): JSONObject {
        val name = params.str("name")
        val args = params.obj("arguments")
        return wrapToolResult(callToolWithPolicy(name, args))
    }

    private fun callToolWithPolicy(name: String, args: JSONObject): JSONObject {
        val settings = SettingsStore(context)
        if (name.isNotEmpty() && isToolDisabled(settings, name)) {
            return err("TOOL_DISABLED", "Tool $name is disabled by server policy (settings.disabledTools).")
        }
        val rateLimit = settings.toolCallRateLimitPerMin
        if (rateLimit > 0 && !RateLimiter.tryAcquire(name, rateLimit)) {
            return err("RATE_LIMITED", "Tool $name hit the per-minute rate limit ($rateLimit/min). Retry shortly.")
        }
        val heavy = name in ToolCatalog.heavyNames
        if (heavy && !heavyGate.tryAcquire()) {
            val busy = err("SERVER_BUSY", "Another analysis task is running. Retry the same call shortly.")
            busy.getJSONObject("error").put("retrySameArguments", true).put("retryAfterMillis", 750)
            busy.put("nextActions", JSONArray(listOf("Retry the exact same tool call after a short delay.")))
            return busy
        }
        return try {
            callToolPayload(name, args)
        } finally {
            if (heavy) heavyGate.release()
        }
    }

    private fun isToolDisabled(settings: SettingsStore, name: String): Boolean {
        val raw = settings.disabledTools
        if (raw.isBlank()) return false
        return raw.split(',').any { it.trim() == name }
    }

    private fun toolsCount(): JSONObject {
        val settings = SettingsStore(context)
        val total = ToolCatalog.ALL.size
        val advertised = advertisedTools()
        val advertisedCount = advertised.length()
        val perCategory = JSONObject()
        ToolCatalog.categoryDescriptions(false).forEach { (cat, _) ->
            perCategory.put(cat, JSONObject()
                .put("total", ToolCatalog.ALL.count { it.meta.category == cat })
                .put("advertised", advertisedCountOf(advertised, cat)))
        }
        val apkBridged = (0 until advertised.length()).count { advertised.getJSONObject(it).optString("name").startsWith("mt_apk_") }
        return ok(JSONObject()
            .put("totalCatalogCount", total)
            .put("advertisedCount", advertisedCount)
            .put("builtInToolsAlwaysAdvertised", true)
            .put("apkBridgeAutoCompaction", true)
            .put("apkBridgedAdvertised", apkBridged)
            .put("perCategory", perCategory)
            .put("hint", "Use meta_info (action=tools/describe) to fetch schemas for tools not in the advertised list."))
    }

    private fun advertisedCountOf(arr: JSONArray, category: String): Int {
        var count = 0
        for (i in 0 until arr.length()) {
            if (ToolCatalog.categoryOf(arr.getJSONObject(i).optString("name")) == category || (category == "apk-bridge" && arr.getJSONObject(i).optString("name").startsWith("mt_apk_"))) count++
        }
        return count
    }

    private val batchKeyPattern = java.util.regex.Pattern.compile("\\$\\{([a-zA-Z0-9_]+)((?:\\.[^\\s\"\\}]+)*?)\\}")

    /**
     * Execute a serial pipeline of tool calls in one round trip.
     *
     * Each step's `arguments` object may carry `${resultKey.jsonPath}` placeholders.
     * Substitution walks the JSON value tree of prior step results: each segment
     * after the key is either a `.field` lookup on an object or a `[index]` lookup
     * on an array. String placeholders are replaced with the textual form of the
     * referenced JSON node (object/array rendered compactly, scalar by toString()).
     * This lets a client build a "describe then call" workflow without a second
     * HTTP round trip:
     *   steps=[{tool:meta_info, arguments:{action:describe, tools:["so_open"]}, resultKey:"a0"},
     *          {tool:so_open, arguments:{path:"${a0.inputSchema.properties.path.exampleOrPre}"}}]
     * More commonly the placeholder just threads a workspaceId or path out of step N
     * into step N+1. stopOnError aborts on the first ok=false; otherwise every step
     * runs and the per-step envelope is reported back.
     */
    private fun batchTool(args: JSONObject): JSONObject {
        val stepsArr = args.optJSONArray("steps") ?: JSONArray()
        val stopOnError = if (args.has("stopOnError")) args.bool("stopOnError", true) else true
        val transactional = args.bool("transactional", false)
        val cap = args.intValue("maxSteps", 20).coerceIn(1, 50)
        if (stepsArr.length() == 0) return err("BAD_REQUEST", "steps[] is required and must not be empty", "steps", JSONArray())
        if (stepsArr.length() > cap) return err("TOO_MANY_STEPS", "Too many steps (got ${stepsArr.length()}, max $cap). Split the pipeline or pass maxSteps (<=50).", "steps", stepsArr.length())

        val results = JSONArray()
        val keyed = HashMap<String, JSONObject>()
        val snapshots = LinkedHashSet<String>()
        for (i in 0 until stepsArr.length()) {
            val step = stepsArr.optJSONObject(i) ?: continue
            val toolName = step.optString("tool")
            if (toolName.isBlank()) {
                results.put(JSONObject().put("step", i).put("ok", false).put("error", JSONObject().put("code", "BAD_REQUEST").put("message", "step.tool is required")))
                if (stopOnError) return ok(JSONObject().put("steps", results).put("executedCount", i).put("aborted", true))
                continue
            }
            val rawArgs = step.optJSONObject("arguments") ?: JSONObject()
            val resultKey = step.optString("resultKey", "").trim()
            val resolvedArgs = substituteBatchPlaceholders(rawArgs, keyed)
            if (transactional) ensureBatchSnapshot(resolvedArgs, snapshots)
            val stepEnvelope = JSONObject()
                .put("step", i)
                .put("tool", toolName)
                .put("resultKey", resultKey)
                .put("arguments", resolvedArgs)
            val payload = try {
                callToolWithPolicy(toolName, resolvedArgs)
            } catch (e: Exception) {
                JSONObject().put("ok", false).put("error", JSONObject().put("code", "STEP_EXCEPTION").put("message", e.message ?: e.javaClass.simpleName))
            }
            val isOk = payload.optBoolean("ok", true)
            val stepResult = stepEnvelope.put("ok", isOk).put("result", payload)
            results.put(stepResult)
            if (resultKey.isNotEmpty() && resultKey.matches(Regex("^[a-zA-Z0-9_]+$"))) {
                keyed[resultKey] = payload
            }
            if (!isOk && stopOnError) {
                val rollback = if (transactional) rollbackBatchSnapshots(snapshots) else JSONArray()
                return ok(JSONObject()
                    .put("steps", results)
                    .put("executedCount", i + 1)
                    .put("aborted", true)
                    .put("transactional", transactional)
                    .put("rollback", rollback)
                    .put("hint", "stopOnError=true aborted the pipeline at the first failing step. Pass stopOnError=false to execute every step regardless."))
            }
        }
        return ok(JSONObject()
            .put("steps", results)
            .put("executedCount", results.length())
            .put("transactional", transactional)
            .put("aborted", false))
    }

    private fun ensureBatchSnapshot(args: JSONObject, snapshots: MutableSet<String>) {
        val workspaceId = args.optString("workspaceId")
        val editSessionId = args.optString("editSessionId")
        if (workspaceId.isBlank() || editSessionId.isBlank()) return
        val key = "$workspaceId::$editSessionId"
        if (!snapshots.add(key)) return
        EngineProvider.get(context).editSnapshot(workspaceId, editSessionId, "batch-transaction-${System.currentTimeMillis()}")
    }

    private fun rollbackBatchSnapshots(snapshots: Set<String>): JSONArray {
        val out = JSONArray()
        val engine = EngineProvider.get(context)
        for (key in snapshots.toList().asReversed()) {
            val parts = key.split("::", limit = 2)
            val workspaceId = parts.getOrNull(0).orEmpty()
            val editSessionId = parts.getOrNull(1).orEmpty()
            val result = engine.editRollback(workspaceId, editSessionId, -1)
            out.put(JSONObject().put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("result", result))
        }
        return out
    }

    private fun substituteBatchPlaceholders(node: JSONObject, keyed: Map<String, JSONObject>): JSONObject {
        val out = JSONObject()
        for (key in node.keys()) {
            val v = node.get(key)
            out.put(key, substituteBatchValue(v, keyed))
        }
        return out
    }

    private fun substituteBatchValue(v: Any?, keyed: Map<String, JSONObject>): Any? = when (v) {
        is String -> substituteBatchInString(v, keyed)
        is JSONObject -> substituteBatchPlaceholders(v, keyed)
        is JSONArray -> JSONArray().also { for (i in 0 until v.length()) it.put(substituteBatchValue(v.get(i), keyed)) }
        else -> v
    }

    private fun substituteBatchInString(s: String, keyed: Map<String, JSONObject>): Any {
        if (!s.contains("\${")) return s
        var anyComplex = false
        val sb = StringBuffer(s.length + 16)
        val m = batchKeyPattern.matcher(s)
        while (m.find()) {
            val key = m.group(1) ?: ""
            val path = m.group(2) ?: ""
            val node = keyed[key]
            if (node == null) {
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(m.group()))
                continue
            }
            val resolved = resolveJsonPath(node, path)
            if (resolved == null) {
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(m.group()))
                continue
            }
            if (resolved is JSONObject || resolved is JSONArray) {
                anyComplex = true
            }
            val textual = when (resolved) {
                is JSONObject -> resolved.toString()
                is JSONArray -> resolved.toString()
                is String -> resolved
                else -> resolved.toString()
            }
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(textual))
        }
        m.appendTail(sb)
        return if (anyComplex) tryParseJson(sb.toString()) else sb.toString()
    }

    private fun tryParseJson(s: String): Any = try {
        val trimmed = s.trim()
        when {
            trimmed.startsWith("{") -> JSONObject(trimmed)
            trimmed.startsWith("[") -> JSONArray(trimmed)
            else -> s
        }
    } catch (_: Exception) { s }

    private fun resolveJsonPath(root: Any?, path: String): Any? {
        var cur: Any? = root
        val tokens = path.split('.').filter { it.isNotEmpty() }
        for (raw in tokens) {
            if (cur == null) return null
            cur = when (cur) {
                is JSONObject -> {
                    val idx = raw.indexOf('[')
                    if (idx < 0) {
                        val key = raw.replace("]", "")
                        if (cur.has(key)) cur.get(key) else null
                    } else {
                        val fieldPart = raw.substring(0, idx)
                        val rest = raw.substring(idx)
                        val stepped = if (fieldPart.isBlank() || fieldPart == "]") cur else (if (cur.has(fieldPart)) cur.get(fieldPart) else null)
                        stepArrayAccess(stepped, rest)
                    }
                }
                is JSONArray -> stepArrayAccess(cur, raw)
                else -> null
            }
            if (cur == null) return null
        }
        return cur
    }

    private fun stepArrayAccess(node: Any?, raw: String): Any? {
        var cur: Any? = node
        var i = 0
        while (i < raw.length && cur != null) {
            if (raw[i] != '[') { i++; continue }
            val end = raw.indexOf(']', i)
            if (end < 0) return null
            val idxStr = raw.substring(i + 1, end).trim()
            val idx = idxStr.toIntOrNull() ?: return null
            cur = when (cur) {
                is JSONArray -> if (idx in 0 until cur.length()) cur.get(idx) else null
                is JSONObject -> if (cur.has(idxStr)) cur.get(idxStr) else null
                else -> null
            }
            i = end + 1
        }
        return cur
    }

    private fun callToolPayload(name: String, args: JSONObject): JSONObject {
        val native = EngineProvider.get(context)
        val settings = SettingsStore(context)
        ToolStats.setEnabled(settings.collectToolStats)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        val started = System.nanoTime()
        val ctx = HookedContext(
            context = context,
            settings = settings,
            engine = native,
            healthHook = { health() },
            statsHook = { ToolStats.snapshot() },
            resetStatsHook = { ToolStats.reset() },
            toolsCountHook = { toolsCount() },
            helpHook = { help() },
            listToolsHook = { cat, q -> listTools(cat, q) },
            describeToolsHook = { names -> describeTools(names) },
            workflowsHook = { workflows() },
            suggestHook = { args -> suggestions(args) },
            errorsHook = { errorCatalog() },
            reportHook = { args -> EngineProvider.get(context).analysisReport(args.str("workspaceId"), args.str("editSessionId"), args.bool("writeToFile", true)) },
            capabilitiesHook = { ok(EngineProvider.get(context).capabilityRegistry()) },
            batchHook = { batchArgs -> batchTool(batchArgs) },
            continueHook = { cursor -> native.continuePage(cursor) },
            sysStatusHook = { probe -> sysStatus(probe) },
            tunnelStatusHook = { ok(tunnel.snapshotJson()) },
            tunnelStatsHook = { reset -> if (reset) tunnel.resetTunnelStats(); ok(tunnel.tunnelStats()) },
            tunnelStartHook = { mode, port, token ->
                val resolvedMode = if (mode == "named") CloudflareTunnelManager.Mode.NAMED else CloudflareTunnelManager.Mode.QUICK
                val targetPort = if (port > 0) port else settings.tunnelTargetPort
                val tok = if (token.isNotBlank()) token else settings.tunnelNamedToken
                val ts = tunnel.start(targetPort, resolvedMode, tok)
                ok(tunnel.snapshotJson().put("message", ts.message).put("publicUrl", ts.publicUrl ?: JSONObject.NULL))
            },
            tunnelStopHook = { tunnel.stop(); ok(JSONObject().put("stopped", true)) },
            apkStatusHook = { probe -> if (probe) apkBridge.probe(); ok(apkBridge.snapshotJson()) },
            apkProbeHook = { val st = apkBridge.probe(); ok(apkBridge.snapshotJson().put("tools", JSONArray().apply { st.tools.forEach { put(it.name) } })) },
            apkPingHook = { apkBridge.ping(); ok(apkBridge.snapshotJson()) },
        )
        val handler = ToolCatalog.byName[name]
        val payload = if (handler != null) {
            handler.handle(ctx, args)
        } else if (name.startsWith("mt_apk_")) {
            if (apkBridge.isBridgedTool(name)) apkBridge.callTool(name, args) else err("APK_MCP_OFFLINE", "APK MCP bridge is offline. Run system_control (action=apk_probe) after starting MT Manager's APK MCP.", "tool", name)
        } else {
            JSONObject().put("ok", false).put("error", JSONObject().put("code", "TOOL_NOT_FOUND").put("message", name))
        }
        val elapsedMicros = (System.nanoTime() - started) / 1000
        val isOk = payload.optBoolean("ok", true)
        val errMsg = payload.optJSONObject("error")?.optString("message").orEmpty()
        ToolStats.record(name, isOk, elapsedMicros, errMsg)
        AppLog.i("Tool call $name -> ok=$isOk (${elapsedMicros / 1000.0}ms)")
        return payload
    }

    private fun wrapToolResult(payload: JSONObject): JSONObject {
        val settings = SettingsStore(context)
        val payloadText = payload.toString().replace("\\/", "/")
        val cap = settings.toolResultMaxChars
        val rendered = if (cap > 0 && payloadText.length > cap) {
            err("RESULT_TRUNCATED", "Tool result exceeded configured character limit", "limit", cap)
                .put("truncated", true)
                .put("originalLength", payloadText.length)
                .put("preview", payloadText.substring(0, cap))
                .toString()
        } else payloadText
        return JSONObject()
            .put("isError", payload.optBoolean("ok", true).not())
            .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", rendered)))
    }

    private fun io.ktor.server.application.ApplicationCall.authorized(): Boolean {
        val settings = SettingsStore(context)
        if (!settings.authEnabled) return true
        val token = settings.accessToken
        if (token.isBlank()) return true
        val auth = request.header("Authorization").orEmpty()
        val bearer = auth.removePrefix("Bearer").trim()
        val queryToken = request.uri.substringAfter("token=", "").substringBefore('&')
        return bearer == token || queryToken == token
    }

    private fun authError(): JSONObject =
        JSONObject().put("jsonrpc", "2.0").put("id", JSONObject.NULL).put("error", JSONObject().put("code", -32001).put("message", "Unauthorized: missing or invalid SOMCP token"))

    private fun requestTooLarge(maxBytes: Int): JSONObject =
        JSONObject().put("jsonrpc", "2.0").put("id", JSONObject.NULL).put("error", JSONObject().put("code", -32002).put("message", "Request body is larger than configured SOMCP limit").put("data", JSONObject().put("maxBytes", maxBytes)))

    /**
     * Full tools/list payload built from `ToolCatalog.ALL`. Each entry's
     * input schema is built lazily via `ToolCatalog.toolDescriptor` from the
     * inline `SchemaBuilder` DSL in the catalog, eliminating the historical
     * duplication between this server's `tools()` literal and the catalog
     * metadata. APK-merged tools are appended when the bridge is configured.
     */
    private fun tools(): JSONArray {
        val settings = SettingsStore(context)
        val includeCategory = settings.includeCategoryInSchema
        val out = JSONArray()
        ToolCatalog.ALL.forEach { handler -> out.put(ToolCatalog.toolDescriptor(handler, includeCategory)) }
        if (settings.apkMcpMergeTools) {
            val state = apkBridge.state()
            val toolsToShow = if (state.online) state.tools else if (settings.apkMcpAutoProbe) apkBridge.probe().tools else emptyList()
            toolsToShow.filter { it.name.startsWith("mt_apk_") }.forEach { td ->
                val schema = td.inputSchema ?: JSONObject().put("type", "object").put("properties", JSONObject())
                val obj = JSONObject()
                    .put("name", td.name)
                    .put("description", "[APK MCP bridge] ${td.description ?: td.title ?: "APK MCP tool"}")
                    .put("inputSchema", schema)
                if (includeCategory) obj.put("category", "apk-bridge")
                if (td.outputSchema != null) obj.put("outputSchema", td.outputSchema)
                out.put(obj)
            }
        }
        return out
    }

    private fun health(): JSONObject = ok(JSONObject()
        .put("status", "ok")
        .put("server", "somcp")
        .put("runtime", runtimeInfo())
        .put("toolCount", advertisedTools().length())
        .put("totalCatalogCount", ToolCatalog.ALL.size)
        .put("builtInToolsAlwaysAdvertised", true)
        .put("collectToolStats", SettingsStore(context).collectToolStats)
        .put("uptimeMillis", System.currentTimeMillis() - startedAt)
        .put("nativeBackends", nativeBackendStatus())
        .put("hint", "Call meta_info (action=stats) for per-tool call counts and latency. Call system_control (action=status) to check SO+APK combo, tunnel state, and native backend status."))

    private fun nativeBackendStatus(): JSONObject {
        val rizin = NativeEngine.active()
        val nativeEngine = com.soreverse.mcp.core.EngineProvider.get(context)
        val lief = nativeEngine.lief
        val settings = SettingsStore(context)
        return JSONObject()
            .put("rizin", JSONObject().put("available", rizin.available()).put("loadStatus", rizin.loadStatus()))
            .put("lief", JSONObject().put("available", lief.available()).put("loadStatus", lief.loadStatus()))
            .put("emulation", nativeEngine.emulationStatus().put("enabled", settings.emulationEnabled))
    }

    private fun sysStatus(probe: Boolean): JSONObject {
        if (probe) apkBridge.probe()
        val s = SettingsStore(context)
        return ok(JSONObject()
            .put("soMcp", JSONObject().put("running", engine != null).put("host", host).put("port", port))
            .put("runtime", runtimeInfo())
            .put("nativeBackends", nativeBackendStatus())
            .put("apkMcp", apkBridge.snapshotJson())
            .put("tunnel", tunnel.snapshotJson())
            .put("integration", JSONObject()
                .put("online", apkBridge.state().online)
                .put("apkMcpUrl", s.apkMcpUrl)
                .put("hint", if (apkBridge.state().online) "MT Manager APK MCP is online. Use MT Manager's mt_apk_* capabilities for APK open / smali+axml edit / signed APK build, and use this app as the SO assistant for so_open/analyze_*/edit_* on embedded lib/*/*.so. Workflow: mt_apk_open -> mt_apk_list (lib/<abi>) -> so_open -> analyze_*/edit_* -> build_so." else "APK MCP is offline. Install MT Manager, enable the APK MCP feature from its sidebar, keep MT Manager running in background, then set its /mcp URL in settings and call system_control (action=apk_probe)."))
            .put("cloudflaredAvailable", tunnel.binary()?.exists() == true)
        )
    }

    private fun runtimeInfo(): JSONObject {
        val pkg = runCatching { context.packageManager.getPackageInfo(context.packageName, 0) }.getOrNull()
        val appInfo = context.applicationInfo
        val nativeDir = appInfo.nativeLibraryDir.orEmpty()
        val rz = File(nativeDir, "librz_native.so")
        val cxx = File(nativeDir, "libc++_shared.so")
        return JSONObject()
            .put("packageName", context.packageName)
            .put("versionName", pkg?.versionName ?: "")
            .put("versionCode", pkg?.longVersionCode ?: 0L)
            .put("supportedAbis", JSONArray(android.os.Build.SUPPORTED_ABIS.toList()))
            .put("nativeLibraryDir", nativeDir)
            .put("librzNative", nativeFileInfo(rz))
            .put("libcxxShared", nativeFileInfo(cxx))
    }

    private fun nativeFileInfo(file: File): JSONObject = JSONObject()
        .put("exists", file.exists())
        .put("path", file.absolutePath)
        .put("sizeBytes", if (file.exists()) file.length() else 0L)
        .put("lastModified", if (file.exists()) file.lastModified() else 0L)
        .put("sha256_16", if (file.exists()) sha256Prefix(file, 16) else "")

    private fun sha256Prefix(file: File, chars: Int): String = runCatching {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }.take(chars.coerceIn(1, 64))
    }.getOrDefault("")

    private fun help(): JSONObject {
        val settings = SettingsStore(context)
        val catMap = JSONObject()
        ToolCatalog.categoryDescriptions(false).forEach { (cat, desc) ->
            val toolsInCat = ToolCatalog.ALL.filter { it.meta.category == cat }
            val names = JSONArray()
            toolsInCat.forEach { e ->
                val entry = JSONObject()
                    .put("name", e.meta.name)
                    .put("cls", e.meta.cls.name.lowercase())
                    .put("advertised", true)
                if (e.meta.heavy) entry.put("heavy", true)
                names.put(entry)
            }
            catMap.put(cat, JSONObject().put("description", desc).put("tools", names))
        }
        if (settings.apkMcpMergeTools && apkBridge.state().online) {
            val apkNames = JSONArray()
            apkBridge.state().tools.filter { it.name.startsWith("mt_apk_") }.forEach {
                apkNames.put(JSONObject().put("name", it.name).put("cls", "apk").put("advertised", true))
            }
            catMap.put("apk-bridge", JSONObject()
                .put("description", "Bridged APK MCP tools (MT Manager)")
                .put("tools", apkNames))
        }
        return JSONObject()
            .put("usage", "Use so_open (action=list to discover), then read/analyze tools with the returned workspaceId. Pass pagination.nextCursor to meta_info (action=continue) when hasMore=true.")
            .put("auth", "If token auth is enabled, send Authorization: Bearer <token> or append ?token=<token> to the MCP URL.")
            .put("exposure", JSONObject()
                .put("builtInToolsAlwaysAdvertised", true)
                .put("advertisedCount", advertisedTools().length())
                .put("totalCatalogCount", ToolCatalog.ALL.size)
                .put("discoveryHint", "tools/list advertises the complete built-in catalog; meta_info action=describe/tools remains available for focused schemas and search."))
            .put("categories", catMap)
            .put("workflows", JSONArray()
                .put(JSONObject().put("name", "standard patch").put("steps", listOf("so_open (action=list first)", "session_open", "edit_asm (dryRun=true first)", "session_history (action=check)", "build_so")))
                .put(JSONObject().put("name", "safe patch with rollback").put("steps", listOf("so_open", "session_history (action=snapshot)", "edit_asm", "session_history (action=check)", "session_history (action=undo) on failure", "session_history (action=rollback) on disaster", "build_so")))
                .put(JSONObject().put("name", "triage").put("steps", listOf("so_open", "analyze_elf (view=stats)", "analyze_functions")))
                .put(JSONObject().put("name", "deep analysis").put("steps", listOf("so_open", "analyze_functions", "analyze_cfg", "analyze_xrefs", "analyze_crypto")))
                .put(JSONObject().put("name", "audit recovery").put("steps", listOf("session_audit (action=persist)", "<process restart>", "session_audit (action=list)", "session_audit (action=load)")))
                .put(JSONObject().put("name", "APK+SO bridge (needs APK MCP bridge online)").put("steps", listOf("system_control (action=apk_probe)", "mt_apk_open", "mt_apk_list view=lib/<abi>", "so_open (path from apk list)", "analyze_functions", "edit_asm (dryRun first)", "session_history (action=check)", "build_so", "mt_apk_edit_open", "mt_apk_build")))
                .put(JSONObject().put("name", "emulation verify").put("steps", listOf("so_open", "session_open", "edit_asm", "emulate_call (symbolName=JNI_OnLoad)", "emulate_dump (addr=0x...)")))
                .put(JSONObject().put("name", "section rebuild (xAnSo)").put("steps", listOf("so_open", "edit_fix_sections", "analyze_elf")))
                .put(JSONObject().put("name", "public expose").put("steps", listOf("system_control (action=tunnel_start, mode=quick)", "read publicUrl from result", "client connects to publicUrl/mcp"))))
            .put("tips", JSONArray()
                .put("edits[] items schema is fully exposed via meta_info (action=describe) - no need to guess field names.")
                .put("dryRun=true on edit_asm/edit_hex previews oldHex/newHex without writing.")
                .put("session_history (action=check) detects claimed-but-unapplied patches - always run it before build_so.")
                .put("analyze_esil does instruction-level emulation tracing via Rizin ESIL VM - lighter than emulate_call for quick semantic checks.")
                .put("edit_fix_sections rebuilds stripped section headers (xAnSo) - essential for NDK SOs that IDA/Ghidra cannot parse."))
    }

    private fun workflows(): JSONObject = ok(JSONObject()
        .put("templates", JSONArray()
            .put(workflow("triage", "Open and summarize a SO", "so_open", "analyze_elf stats", "analyze_elf sections/dynsyms", "search_strings", "analyze_crypto", "meta_info suggest"))
            .put(workflow("packed_or_stripped", "When functions are missing", "so_open", "analyze_elf sections", "read_disasm addr=<.text.virtualAddr>", "search_strings prefix=<keyword>", "edit_fix_sections if sections are missing"))
            .put(workflow("safe_patch", "Atomic patch workflow", "so_open", "session_open", "session_history snapshot", "edit_hex/edit_asm dryRun=true", "edit_* dryRun=false", "session_history check", "session_audit persist", "build_so writeReport=true"))
            .put(workflow("emulation_verify", "Validate JNI/export behavior", "so_open", "analyze_elf dynsyms", "emulate_call symbolName=JNI_OnLoad", "emulate_call trace=true for small exported functions", "emulate_dump addr=0x..."))
            .put(workflow("full_report", "Persist complete analysis", "so_open", "meta_info report writeToFile=true", "read reportPath from result")))
        .put("batchPattern", JSONObject()
            .put("tool", "meta_info")
            .put("arguments", JSONObject().put("action", "batch").put("stopOnError", true).put("steps", JSONArray()
                .put(JSONObject().put("tool", "so_open").put("arguments", JSONObject().put("path", "<path>")).put("resultKey", "open"))
                .put(JSONObject().put("tool", "analyze_elf").put("arguments", JSONObject().put("workspaceId", "\${open.workspaceId}").put("view", "stats")).put("resultKey", "stats"))
                .put(JSONObject().put("tool", "meta_info").put("arguments", JSONObject().put("action", "suggest").put("workspaceId", "\${open.workspaceId}")))))))

    private fun workflow(name: String, description: String, vararg steps: String): JSONObject = JSONObject()
        .put("name", name)
        .put("description", description)
        .put("steps", JSONArray(steps.toList()))

    private fun suggestions(args: JSONObject): JSONObject {
        val workspaceId = args.str("workspaceId")
        val native = EngineProvider.get(context)
        val base = JSONArray()
            .put("Use meta_info(action=describe, tools=[...]) before calling unfamiliar tools")
            .put("Use dryRun=true before edit_hex/edit_asm, then session_history(action=check)")
            .put("Use meta_info(action=report, writeToFile=true) before final handoff")
        if (workspaceId.isBlank()) return ok(JSONObject().put("nextActions", base).put("workflow", "triage"))
        val stats = native.readStats(workspaceId, args.str("editSessionId"))
        val next = JSONArray()
        for (i in 0 until base.length()) next.put(base.get(i))
        val counts = stats.optJSONObject("counts") ?: JSONObject()
        if (counts.optInt("functions", 0) == 0) next.put("No functions were detected: use analyze_elf(view=list, subView=sections) then read_disasm(addr=<.text.virtualAddr>)")
        if (counts.optInt("sections", 0) == 0) next.put("No section headers were detected: try edit_fix_sections before section-based patching")
        next.put("For JNI behavior validation, inspect dynsyms then call emulate_call(symbolName=JNI_OnLoad or Java_*)")
        return ok(JSONObject().put("workspaceId", workspaceId).put("stats", stats).put("nextActions", next))
    }

    private fun errorCatalog(): JSONObject = ok(JSONObject()
        .put("codes", JSONArray(listOf(
            "INVALID_ARGUMENT", "UNKNOWN_ACTION", "UNKNOWN_TOOL", "BAD_REQUEST", "TOO_MANY_STEPS", "INVALID_CURSOR",
            "SO_NOT_FOUND", "WORKSPACE_NOT_FOUND", "EDIT_SESSION_NOT_FOUND", "SECTION_NOT_FOUND", "FUNCTION_NOT_FOUND",
            "INVALID_LOCATOR", "OFFSET_OUT_OF_RANGE", "INVALID_HEX", "PATCH_TOO_LARGE", "ASM_SYNTAX_ERROR", "SIZE_MISMATCH",
            "UNSUPPORTED_OPERATION", "ELF_PARSE_FAILED", "ELF_CORRUPTED", "DUMP_ERROR", "EMULATION_DISABLED", "EMULATION_ERROR", "EMULATOR_UNAVAILABLE", "NATIVE_UNAVAILABLE",
            "RIZIN_UNAVAILABLE", "RIZIN_CFG_FAILED", "RIZIN_SEARCH_FAILED", "RIZIN_COMMAND_FAILED", "LIEF_UNAVAILABLE", "PATCH_FAILED",
            "SYMBOL_NOT_FOUND", "MEMORY_MAP_ERROR", "MEMORY_WRITE_ERROR", "MEMORY_PROTECT_ERROR", "MEMORY_UNMAP_ERROR", "SERVER_BUSY", "RATE_LIMITED", "TOOL_DISABLED"
        )))
        .put("contract", JSONObject()
            .put("success", "All tool payloads include ok=true unless they are raw JSON-RPC transport errors")
            .put("failure", "Tool failures include ok=false and error.code/error.message plus argument/badValue when applicable")
            .put("recovery", "Call meta_info(action=suggest, workspaceId=...) after an error for next actions")))

    private fun listTools(category: String, query: String): JSONObject {
        val q = query.trim().lowercase()
        val hasQuery = q.isNotEmpty()
        val settings = SettingsStore(context)
        val grouped = JSONObject()
        var matched = 0
        ToolCatalog.ALL.forEach { e ->
            if (category.isNotBlank() && e.meta.category != category) return@forEach
            val desc = e.meta.en
            if (hasQuery) {
                val hay = (e.meta.name + "\n" + desc + "\n" + e.meta.category).lowercase()
                if (!hay.contains(q)) return@forEach
            }
            if (!grouped.has(e.meta.category)) grouped.put(e.meta.category, JSONArray())
            grouped.getJSONArray(e.meta.category).put(JSONObject().put("name", e.meta.name).put("description", desc))
            matched++
        }
        if (settings.apkMcpMergeTools && (category.isBlank() || category == "apk-bridge") && apkBridge.state().online) {
            val qLower = q
            apkBridge.state().tools.filter { it.name.startsWith("mt_apk_") }
                .filter { !hasQuery || (it.name + "\n" + (it.description ?: "")).lowercase().contains(qLower) }
                .forEach { td ->
                    if (!grouped.has("apk-bridge")) grouped.put("apk-bridge", JSONArray())
                    grouped.getJSONArray("apk-bridge").put(JSONObject().put("name", td.name).put("description", td.description ?: (td.title ?: "APK MCP tool")))
                    matched++
                }
        }
        val res = JSONObject()
            .put("categories", grouped)
            .put("totalCount", ToolCatalog.ALL.size)
            .put("filtered", category.isNotBlank() || hasQuery)
            .put("matchedCount", matched)
        if (hasQuery) res.put("query", query).put("hint", "Use meta_info (action=describe) to fetch full schema for any matched tool.")
        return ok(res)
    }

    private fun describeTools(names: List<String>): JSONObject {
        val includeCategory = SettingsStore(context).includeCategoryInSchema
        val found = JSONArray()
        val missing = JSONArray()
        names.forEach { n ->
            val handler = ToolCatalog.byName[n]
            if (handler != null) found.put(ToolCatalog.toolDescriptor(handler, includeCategory)) else missing.put(n)
        }
        val res = JSONObject()
            .put("tools", found)
            .put("descriptions", found)
            .put("foundCount", found.length())
        if (missing.length() > 0) res.put("missing", missing).put("missingCount", missing.length())
        return ok(res)
    }

    /** Advertise the full built-in catalog by default. 29 tools is small enough
     * for modern MCP clients and avoids hiding advanced SO workflows from AI.
     * Lean exposure only activates for oversized catalogs, typically after
     * dynamic APK-bridge tools are added, or if operators explicitly disable
     * tools through policy.
     */
    private fun advertisedTools(): JSONArray {
        val full = tools()
        if (full.length() <= ToolCatalog.ALL.size + 64) return full
        val out = JSONArray()
        for (i in 0 until full.length()) {
            val t = full.getJSONObject(i)
            val name = t.optString("name")
            if (!name.startsWith("mt_apk_") || out.length() < ToolCatalog.ALL.size + 64) out.put(t)
        }
        return out
    }
}
