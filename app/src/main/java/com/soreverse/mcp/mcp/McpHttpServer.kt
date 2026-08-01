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
}