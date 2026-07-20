package com.soreverse.mcp.core

import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.io.File
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference
import java.util.regex.Pattern
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class CloudflareTunnelManager(private val context: Context, private val settings: SettingsStore) {

    enum class Mode { OFF, QUICK, NAMED }
    enum class State { STOPPED, STARTING, RUNNING, FAILED }

    data class TunnelStatus(
        val state: State = State.STOPPED,
        val mode: Mode = Mode.OFF,
        val publicUrl: String? = null,
        val targetPort: Int = 0,
        val message: String = "",
        val pid: Int = 0,
    )

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(20, java.util.concurrent.TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    private val _status = AtomicReference(TunnelStatus())
    fun status(): TunnelStatus = _status.get()

    private var process: Process? = null
    private var watchThread: Thread? = null
    private var healthThread: Thread? = null
    @Volatile private var stopRequested = false
    private val generation = java.util.concurrent.atomic.AtomicInteger(0)

    @Volatile private var runningSinceMs = 0L
    @Volatile private var accumulatedRunningMs = 0L
    @Volatile private var lastKeepaliveRestartMs = 0L
    private val keepaliveRestarts = java.util.concurrent.atomic.AtomicInteger(0)
    private val probeFailures = java.util.concurrent.atomic.AtomicInteger(0)
    private val probeOks = java.util.concurrent.atomic.AtomicInteger(0)
    private val totalRestarts = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * Return the OS pid of a freshly spawned child [Process]. android.jar only
     * surfaced `Process.pid()` from API 35+ even though ART shipped it earlier;
     * fall back to reflection so we still surface a real pid on API 26..34
     * callers, and to 0 if neither path resolves (purely informational field
     * surfaced in the tunnel status JSON, not load-bearing).
     */
    private fun soReverseChildPid(p: Process): Int = try {
        val m = Process::class.java.getMethod("pid")
        (m.invoke(p) as Long).toInt()
    } catch (_: Throwable) {
        try {
            val m = Process::class.java.getMethod("getPid")
            (m.invoke(p) as Int)
        } catch (_: Throwable) { 0 }
    }

    /**
     * Single transition point for `_status`. Keeping every state mutation
     * here means the RUNNING wall-clock bookkeeping (runningSinceMs ⇄
     * accumulatedRunningMs) can never go out of sync — earlier versions
     * sprinkled this logic between `start()`, `stop()` and the watch
     * thread, which made double-accounting on a reentrant `start()` during
     * RUNNING trivial to introduce.
     *
     * Returns the new status so callers can chain on it.
     */
    @Synchronized
    private fun transitionTo(
        state: State,
        mode: Mode? = null,
        publicUrl: String? = null,
        message: String? = null,
        pid: Int = 0,
        targetPort: Int? = null,
    ): TunnelStatus {
        val prev = _status.get()
        if (state == State.RUNNING && prev.state != State.RUNNING) {
            runningSinceMs = System.currentTimeMillis()
        } else if (state != State.RUNNING && prev.state == State.RUNNING && runningSinceMs > 0) {
            accumulatedRunningMs += System.currentTimeMillis() - runningSinceMs
            runningSinceMs = 0L
        }
        val next = TunnelStatus(
            state = state,
            mode = mode ?: prev.mode,
            publicUrl = publicUrl ?: if (state == State.RUNNING) prev.publicUrl else null,
            targetPort = targetPort ?: prev.targetPort,
            message = message ?: prev.message,
            pid = if (pid != 0) pid else prev.pid,
        )
        _status.set(next)
        return next
    }

    fun binary(): File? {
        val dir = context.applicationInfo?.nativeLibraryDir ?: return null
        val f = File(dir, "libcloudflared.so")
        return if (f.exists() && f.canExecute()) f else f.takeIf { it.exists() }
    }

    fun start(targetPort: Int, mode: Mode, token: String): TunnelStatus =
        startInternal(targetPort, mode, token, userInitiated = true)

    @Synchronized
    private fun startInternal(targetPort: Int, mode: Mode, token: String, userInitiated: Boolean): TunnelStatus {
        if (userInitiated) stopRequested = false
        // Refuse re-entrant restart once stop() has been requested. The earlier
        // version allowed the keepalive health thread — which sits in a sibling
        // thread to stop() — to observe a probe failure and recurse into
        // start() while stop() was still joining the watch thread under the
        // same monitor. That nesting entangled monitor re-acquisition with
        // process destruction and a publish()/sendBroadcast to a Service
        // Context that was racing to be GC'd, manifesting as a process crash
        // when the user toggled the MCP master switch off while a tunnel was
        // healthy & auto-started. Treat stopRequested as a hard gate.
        if (stopRequested) {
            return _status.get()
        }
        // Already running on the same target with the same mode and a live
        // process — nothing to do. Avoids costly stop/restart churn from
        // keepalive or client retries when the tunnel is healthy.
        val cur = _status.get()
        if (cur.state == State.RUNNING && cur.mode == mode && cur.targetPort == targetPort && process?.isAlive == true) {
            return cur
        }
        val runGeneration = generation.incrementAndGet()
        // Graceful teardown WITHOUT taking the public stop() path: stop() also
        // interrupts the health/watch threads and sends a STOPPED broadcast,
        // which we do not want from inside start() (the keepalive restart
        // path runs on the health thread itself — interrupting yourself from
        // inside start() is a self-inflicted deadlock). teardownForRestart()
        // only kills the cloudflared process and joins its watcher.
        teardownForRestart()
        totalRestarts.incrementAndGet()
        val bin = binary()
        if (bin == null) {
            return fail(mode, targetPort, "libcloudflared.so not found in nativeLibraryDir")
        }
        transitionTo(State.STARTING, mode, publicUrl = null, message = "starting")
        publish()
        try {
            when (mode) {
                Mode.QUICK -> startQuick(bin, targetPort, runGeneration)
                Mode.NAMED -> startNamed(bin, targetPort, token, runGeneration)
                Mode.OFF -> {}
            }
        } catch (e: Exception) {
            return fail(mode, targetPort, e.message ?: e.javaClass.simpleName)
        }
        return _status.get()
    }

    /**
     * Internal-only graceful teardown used by [start] when it has to evict a
     * previous cloudflared process before re-launching. Differs from [stop]
     * in three load-bearing ways:
     *
     * 1. Does NOT flip [stopRequested] — we are about to start a new tunnel,
     *    not stop the manager.
     * 2. Does NOT interrupt the health/watch threads — they are mid-flight
     *    on the calling thread (start() may be invoked from the keepalive
     *    health thread), so interrupting them here would self-interrupt.
     * 3. Does NOT publish a STOPPED broadcast — we are about to flip
     *    state to STARTING, and a STOPPED broadcast racing the STARTING
     *    broadcast can confuse the reconnect Receiver in
     *    McpForegroundService into re-entry.
     *
     * Watch thread is given a brief join so its final state-publish side
     * effects cannot stomp on the STARTING transition just below.
     */
    @Synchronized
    private fun teardownForRestart() {
        process?.let { p ->
            // Same two-stage shutdown rationale as stop(): give the native
            // cloudflared child a brief orderly exit window before force-killing.
            runCatching { p.destroy() }
            val exited = runCatching { p.waitFor(800, java.util.concurrent.TimeUnit.MILLISECONDS) }.getOrDefault(false)
            if (!exited) {
                runCatching { p.destroyForcibly() }
                runCatching { p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) }
            }
        }
        process = null
    }

    private fun fail(mode: Mode, targetPort: Int, msg: String): TunnelStatus {
        val s = transitionTo(State.FAILED, mode, publicUrl = null, message = msg, targetPort = targetPort)
        AppLog.w("tunnel: $msg")
        publish()
        return s
    }

    /**
     * Lightweight, non-blocking prelude to [stop] intended to be called from
     * the **main** thread (e.g. inside [McpForegroundService.onStartCommand]
     * when ACTION_STOP arrives). It flips [stopRequested] synchronously so
     * that any in-flight health-thread restart cycle that races the upcoming
     * [stop] call sees the early-return guard inside [start] and DOES NOT
     * spawn a fresh `cloudflared` child against a Service Context that is
     * about to be torn down. The actual process teardown, thread joins, and
     * broadcast emission remain in [stop], which the teardown thread still
     * invokes once [McpForegroundService.onDestroy] runs. Callers that skip
     * this and rely solely on `stop()` leave a tens-of-milliseconds window
     * between `stopSelf()` and `onDestroy()` in which a restart can sneak in
     * — the exact race that surfaced as the app process being killed when
     * the user toggled the MCP master switch off while a tunnel was healthy
     * and auto-started.
     */
    fun requestStop() {
        stopRequested = true
        generation.incrementAndGet()
    }

    @Synchronized
    fun stop() {
        // Flip the gate FIRST so any concurrent start() (e.g. a keepalive
        // restart cycle) bails out before re-launching cloudflared. Combined
        // with the early-return guard in start(), this is what breaks the
        // stop/start interleaving that crashed the app when the user toggled
        // the MCP master switch off while the tunnel was auto-started.
        stopRequested = true
        healthThread?.interrupt()
        healthThread = null
        watchThread?.interrupt()
        watchThread = null
        // NULL-OUT process BEFORE signalling the child so the watch thread,
        // which terminates on inputStream EOF (not on the `process` field),
        // never sees a stale ProcessHandle once we mark it torn-down. We do
        // NOT call watchThread.join here, because the watch thread's finally
        // block emits publish() (= context.sendBroadcast), and joining it
        // from inside this @Synchronized method would block a Service-host
        // thread on cross-thread IPC for up to the broadcast's dispatch
        // window — which on a Service mid-teardown manifested as Android's
        // ActivityManagerService killing the entire host process. The watch
        // thread will run-to-completion on its own shortly after the child
        // dies; the `runCatching` around publish() tolerates an unregistered
        // receiver. The only thing we must guarantee synchronously here is
        // that the cloudflared child is dead and that `process = null` so
        // no later code can touch a half-destroyed Process object.
        val p = process
        process = null
        if (p != null) {
            // Two-stage shutdown so libcloudflared.so gets a chance to do its
            // clean teardown (HTTP/2 RST_STREAM, control-plane deregister,
            // edge quic drain) before we hit it with SIGKILL. The bare
            // `destroyForcibly()` we used before skipped that, which on
            // several Android devices allowed the unhandled SIGCHLD that
            // cloudflared emits while aborting an in-flight native cleanup to
            // be mis-handled by the Zygote watcher, manifesting as the
            // foreground Service host process getting killed when the user
            // toggled the MCP master switch off while a tunnel was running.
            // First, give the native cleanup a short window; on Android,
            // Process.destroy() is already SIGKILL, so use a tight 200ms
            // wait — past that the child cannot recover and we move on.
            runCatching { p.destroy() }
            val exited = runCatching { p.waitFor(200, java.util.concurrent.TimeUnit.MILLISECONDS) }.getOrDefault(false)
            if (!exited) {
                runCatching { p.destroyForcibly() }
                runCatching { p.waitFor(500, java.util.concurrent.TimeUnit.MILLISECONDS) }
            }
        }
        transitionTo(State.STOPPED, mode = Mode.OFF, publicUrl = null, message = "stopped")
        publish()
    }

    fun resetTunnelStats() {
        accumulatedRunningMs = 0L
        if (_status.get().state == State.RUNNING) runningSinceMs = System.currentTimeMillis() else runningSinceMs = 0L
        keepaliveRestarts.set(0)
        probeFailures.set(0)
        probeOks.set(0)
        totalRestarts.set(0)
        lastKeepaliveRestartMs = 0L
    }

    fun tunnelStats(): JSONObject {
        val s = _status.get()
        val currentRunningMs = if (s.state == State.RUNNING && runningSinceMs > 0) System.currentTimeMillis() - runningSinceMs else 0L
        val totalRunningMs = accumulatedRunningMs + currentRunningMs
        return JSONObject().apply {
            put("state", s.state.name)
            put("mode", s.mode.name)
            put("publicUrl", s.publicUrl ?: JSONObject.NULL)
            put("totalRunningMs", totalRunningMs)
            put("currentRunningMs", currentRunningMs)
            put("totalRestarts", totalRestarts.get())
            put("keepaliveRestarts", keepaliveRestarts.get())
            put("probeOks", probeOks.get())
            put("probeFailures", probeFailures.get())
            put("lastKeepaliveRestartMs", lastKeepaliveRestartMs)
            put("keepaliveEnabled", settings.tunnelKeepAlive)
        }
    }

    private fun startQuick(bin: File, targetPort: Int, runGeneration: Int) {
        AppLog.i("cloudflare tunnel: registering quick tunnel…")
        val tunnel = registerQuickTunnel()
        val credsFile = File(context.cacheDir, "tunnel_creds.json")
        credsFile.writeText(
            JSONObject().apply {
                put("AccountTag", tunnel.accountTag)
                put("TunnelID", tunnel.tunnelId)
                put("TunnelSecret", tunnel.secret)
            }.toString()
        )
        val configFile = File(context.cacheDir, "tunnel_config.yml")
        configFile.writeText(
            """
            tunnel: ${tunnel.tunnelId}
            credentials-file: ${credsFile.absolutePath}
            protocol: ${settings.tunnelProtocol}
            no-autoupdate: true
            edge-ip-version: "${settings.tunnelEdgeIpVersion}"
            retry-dns-errors: true
            ingress:
              - hostname: ${tunnel.hostname}
                service: http://localhost:$targetPort
              - service: http_status:404
            """.trimIndent()
        )
        val cmd = mutableListOf(
            bin.absolutePath, "tunnel", "--config", configFile.absolutePath,
            "--no-autoupdate", "run", tunnel.tunnelId,
        )
        val edges = edgeIps()
        if (edges.isNotEmpty()) {
            val insertAt = cmd.indexOf("run")
            edges.forEachIndexed { i, ip -> cmd.addAll(insertAt + i * 2, listOf("--edge", ip)) }
        }
        launch(bin, cmd, Mode.QUICK, "https://${tunnel.hostname}", targetPort, runGeneration)
        tunnelCredsFile = credsFile.absolutePath
        addHistoryUrl("https://${tunnel.hostname}")
    }

    private fun startNamed(bin: File, targetPort: Int, token: String, runGeneration: Int) {
        require(token.isNotBlank()) { "named tunnel token is empty" }
        val cmd = mutableListOf(
            bin.absolutePath, "tunnel", "--no-autoupdate",
            "--edge-ip-version", settings.tunnelEdgeIpVersion,
            "run", "--token", token,
        )
        val edges = edgeIps()
        if (edges.isNotEmpty()) {
            val insertAt = cmd.indexOf("run")
            edges.forEachIndexed { i, ip -> cmd.addAll(insertAt + i * 2, listOf("--edge", ip)) }
        }
        launch(bin, cmd, Mode.NAMED, null, targetPort, runGeneration)
    }

    private fun launch(bin: File, cmd: MutableList<String>, mode: Mode, url: String?, targetPort: Int, runGeneration: Int) {
        val safeCommand = cmd.mapIndexed { index, value ->
            if (index > 0 && cmd[index - 1] == "--token") "<redacted>" else value
        }
        AppLog.i("cloudflare tunnel command: ${safeCommand.joinToString(" ")}")
        val pb = ProcessBuilder(cmd).directory(context.cacheDir).redirectErrorStream(true)
        pb.environment()["NO_AUTOUPDATE"] = "true"
        // The bare pb.start() call below can throw IOException when the device
        // is under memory pressure (fork() failing on the Zygote) or when
        // libcloudflared.so's native loader aborts mid-flight — which used
        // to propagate up the startQuick/startNamed chain and out of
        // start()'s catch(e: Exception) handler. Wrap it here so a spawn
        // failure becomes a clean tunnel FAILED state instead of an
        // uncaught exception that risks tearing the Service down.
        val p = try {
            pb.start()
        } catch (e: Exception) {
            AppLog.w("cloudflared process spawn failed: ${e.message}")
            fail(mode, targetPort, "spawn failed: ${e.message ?: e.javaClass.simpleName}")
            return
        }
        process = p
        transitionTo(State.STARTING, mode, publicUrl = url, message = "starting", targetPort = targetPort, pid = soReverseChildPid(p))
        publish()
        val capturedUrl = url
        val t = Thread({
            try {
                InputStreamReader(p.inputStream, Charsets.UTF_8).use { reader ->
                    val buf = CharArray(2048)
                    while (true) {
                        val n = reader.read(buf)
                        if (n < 0) break
                        if (n > 0) {
                            val chunk = String(buf, 0, n)
                            chunk.split('\n').forEach { line ->
                                if (line.isNotBlank()) {
                                    AppLog.i("clfl: $line")
                                    parseTunnelLine(line, mode)?.let { detectedUrl ->
                                        if (generation.get() == runGeneration && _status.get().state == State.STARTING) {
                                            transitionTo(State.RUNNING, mode, publicUrl = _status.get().publicUrl ?: detectedUrl, message = "running")
                                            publish()
                                            if (mode == Mode.NAMED) addHistoryUrl(detectedUrl)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (_: InterruptedException) {
            } catch (e: Exception) {
                if (!stopRequested) AppLog.w("tunnel stream end: ${e.message}")
            } finally {
                val exit = runCatching { p.exitValue() }.getOrDefault(-1)
                val wasRunning = _status.get().state
                if (!stopRequested && generation.get() == runGeneration) {
                    transitionTo(
                        State.STOPPED,
                        mode = Mode.OFF,
                        publicUrl = null,
                        message = "process exited (code=$exit)",
                    )
                }
                if (generation.get() == runGeneration && wasRunning != State.STOPPED) {
                    AppLog.w("cloudflare tunnel process exited code=$exit stopRequested=$stopRequested")
                }
                if (generation.get() == runGeneration) publish()
            }
        }, "cloudflared-watch")
        t.isDaemon = true
        watchThread = t
        t.start()
        AppLog.i("cloudflare tunnel ${mode.name.lowercase()} started -> ${capturedUrl ?: "(url pending)"} targeting :$targetPort")
        startHealthCheck(mode, targetPort, runGeneration)
    }

    private fun startHealthCheck(mode: Mode, targetPort: Int, runGeneration: Int) {
        val probeIntervalMs = settings.tunnelKeepaliveIntervalSec.coerceIn(5, 300) * 1000L
        healthThread = Thread({
            var stable = 0
            var downSince = 0L
            var lastRestartAt = 0L
            // Wrap the entire probe loop in a try/catch for InterruptedException.
            // stop() interrupts this thread to wake it out of the long
            // Thread.sleep(probeIntervalMs) — but Thread.sleep throws
            // InterruptedException on interrupt, and that is a *checked*
            // exception in Java terms. Without a catch here the exception
            // propagates out of Thread.run() and becomes an uncaught
            // exception on the "cloudflared-health" thread, which Android's
            // default UncaughtExceptionHandler treats as a process-fatal
            // crash (FATAL EXCEPTION: cloudflared-health → SIGKILL of the
            // whole app). This is exactly the "open tunnel then press stop
            // → immediate app crash" report: stop() interrupted the health
            // thread while it was mid-sleep, the InterruptedException escaped
            // run(), and AMS killed com.soreverse.mcp. Catching it here and
            // breaking out of the loop lets the thread exit cleanly.
            try {
                while (!stopRequested && generation.get() == runGeneration && Thread.currentThread().isInterrupted.not()) {
                    Thread.sleep(probeIntervalMs)
                    if (stopRequested || generation.get() != runGeneration) break
                    val p = process ?: break
                    if (!p.isAlive) {
                        transitionTo(State.FAILED, message = "process not alive")
                        publish()
                        break
                    }
                    val s = _status.get()
                    if (s.state == State.RUNNING) {
                        val ok = probeLocal(targetPort)
                        if (ok) {
                            stable++
                            downSince = 0L
                            probeOks.incrementAndGet()
                        } else {
                            stable = 0
                            probeFailures.incrementAndGet()
                            if (downSince == 0L) downSince = System.currentTimeMillis()
                            val keep = settings.tunnelKeepAlive
                            if (keep && System.currentTimeMillis() - lastRestartAt > 15_000 && System.currentTimeMillis() - downSince > 8_000) {
                                lastRestartAt = System.currentTimeMillis()
                                lastKeepaliveRestartMs = lastRestartAt
                                keepaliveRestarts.incrementAndGet()
                                // Re-check the stop gate immediately before the
                                // restart: stopRequested is read at the top of the
                                // while loop, but the probe + time deltas above
                                // could have taken seconds, by which time the user
                                // may have flipped the MCP master switch off. The
                                // start() entry has the same guard, but adding it
                                // here too keeps the health thread from burning a
                                // cycle on cloudflared launch+kill right before
                                // stop() joins us.
                                if (stopRequested) {
                                    AppLog.i("tunnel keepalive: stop requested, skipping restart")
                                    break
                                }
                                AppLog.w("tunnel keepalive: local probe failed, restarting tunnel")
                                try {
                                    startInternal(targetPort, mode, settings.tunnelNamedToken, userInitiated = false)
                                    downSince = 0L
                                } catch (e: Exception) {
                                    AppLog.w("tunnel keepalive restart failed: ${e.message}")
                                }
                            }
                        }
                        if (stable >= 3 && s.publicUrl != null) {
                        }
                    }
                }
            } catch (_: InterruptedException) {
                // Expected when stop() interrupts us mid-sleep; just exit.
            }
        }, "cloudflared-health").apply { isDaemon = true }.also { it.start() }
    }

    private fun probeLocal(port: Int): Boolean = runCatching {
        java.net.Socket().use { s ->
            s.connect(java.net.InetSocketAddress("127.0.0.1", port), 800)
            s.isConnected
        }
    }.getOrDefault(false)

    private val urlPattern: Pattern = Pattern.compile("https://[a-z0-9-]+\\.(trycloudflare\\.com|cfargotunnel\\.com)", Pattern.CASE_INSENSITIVE)
    private val connPattern: Pattern = Pattern.compile("Registered tunnel connection|Registered tunnel connection connIndex=", Pattern.CASE_INSENSITIVE)

    private fun parseTunnelLine(line: String, mode: Mode): String? {
        val m = urlPattern.matcher(line)
        if (m.find()) return m.group()
        if (connPattern.matcher(line).find()) {
            val s = _status.get()
            if (s.state == State.STARTING) {
                transitionTo(State.RUNNING, mode, message = "registered")
                publish()
            }
        }
        if (line.contains("ERR", true) && (line.contains("tunnel") || line.contains("connect"))) {
            AppLog.w("tunnel error: $line")
        }
        return null
    }

    private data class QuickTunnel(val tunnelId: String, val hostname: String, val accountTag: String, val secret: String)

    private fun registerQuickTunnel(): QuickTunnel {
        // Two attempts with a short fixed backoff. Earlier 3-attempt ×
        // growing backoff could hold the caller for ~6s; the tunnel start
        // is for human-driven or health-thread requests, so we keep the
        // upper bound low and let the health loop retry on next tick.
        var lastErr: Exception? = null
        repeat(2) { attempt ->
            try {
                val req = Request.Builder()
                    .url("https://api.trycloudflare.com/tunnel")
                    .header("User-Agent", "SOMCP")
                    .post("".toRequestBody("application/json".toMediaType()))
                    .build()
                client.newCall(req).execute().use { resp ->
                    val body = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) throw IllegalStateException("trycloudflare ${resp.code}: ${body.take(200)}")
                    val result = JSONObject(body).getJSONObject("result")
                    return QuickTunnel(
                        tunnelId = result.getString("id"),
                        hostname = result.getString("hostname"),
                        accountTag = result.getString("account_tag"),
                        secret = result.getString("secret"),
                    )
                }
            } catch (e: Exception) {
                lastErr = e
                AppLog.w("tunnel register attempt ${attempt + 1} failed: ${e.message}")
                if (attempt < 1) Thread.sleep(800)
            }
        }
        throw lastErr ?: IllegalStateException("failed to register quick tunnel")
    }

    private fun edgeIps(): List<String> {
        val preferV4 = settings.tunnelEdgeIpVersion == "4"
        val hosts = when (settings.tunnelEdgeIpVersion) {
            "6" -> listOf("region1.v2.argotunnel.com", "region2.v2.argotunnel.com")
            else -> listOf("region1.argotunnel.com", "region2.argotunnel.com")
        }
        // Resolve hosts concurrently so the upper bound on DNS time is one
        // host lookup rather than N lookups serialised on the caller. Prior
        // version used InetAddress.getAllByName(h) in a loop, which on a
        // device with a flaky resolver could block the start path for ~10s.
        val executor = java.util.concurrent.Executors.newFixedThreadPool(hosts.size.coerceAtLeast(1)) { r ->
            Thread(r, "clfl-dns").apply { isDaemon = true }
        }
        val futures = hosts.map { h ->
            executor.submit<List<String>?> {
                try {
                    InetAddress.getAllByName(h)
                        .filter { !preferV4 || it is Inet4Address }
                        .map { "${it.hostAddress}:7844" }
                } catch (e: Exception) {
                    AppLog.w("edge resolve $h failed: ${e.message}")
                    null
                }
            }
        }
        return try {
            val out = mutableListOf<String>()
            futures.forEach { f ->
                try {
                    f.get(4_000, java.util.concurrent.TimeUnit.MILLISECONDS)?.let(out::addAll)
                } catch (_: Exception) {
                    f.cancel(true)
                }
            }
            out
        } finally {
            executor.shutdownNow()
        }
    }

    private var tunnelCredsFile: String? = null

    private fun addHistoryUrl(url: String) {
        if (url.isBlank()) return
        val cur = settings.tunnelHistoryUrls
            .split('\n').map { it.trim() }.filter { it.isNotBlank() }.toMutableList()
        if (url !in cur) {
            cur.add(0, url)
            while (cur.size > 10) cur.removeAt(cur.lastIndex)
        }
        settings.tunnelHistoryUrls = cur.joinToString("\n")
    }

    private fun publish() {
        // sendBroadcast on a Receiver/Context that has been unregistered or
        // whose hosting Service is mid-destroy can surface as an
        // IllegalStateException ("Receiver not registered") or worse a
        // RuntimeException re-thrown on the publishing thread. Both happened
        // during teardown racing the watch thread's final
        // transitionTo(STOPPED) + publish() call, manifesting as the app
        // crash the user saw when toggling the MCP master switch off with
        // a live tunnel. Swallow both — the broadcast is purely advisory
        // for the Service-side reconnect Receiver; missing the final
        // STOPPED broadcast is harmless because stop() already moved
        // state to STOPPED under the monitor and the Service is going
        // down anyway.
        runCatching {
            context.sendBroadcast(Intent("com.soreverse.mcp.TUNNEL_STATUS").putExtra("state", _status.get().state.name))
        }.onFailure { e ->
            AppLog.w("tunnel publish(): ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    fun snapshotJson(): JSONObject {
        val s = _status.get()
        val stats = tunnelStats()
        return JSONObject().apply {
            put("state", s.state.name)
            put("mode", s.mode.name)
            put("publicUrl", s.publicUrl ?: JSONObject.NULL)
            put("targetPort", s.targetPort)
            put("message", s.message)
            put("binaryAvailable", binary()?.exists() == true)
            put("history", settings.tunnelHistoryUrls)
            put("totalRunningMs", stats.optLong("totalRunningMs"))
            put("currentRunningMs", stats.optLong("currentRunningMs"))
            put("totalRestarts", stats.optInt("totalRestarts"))
            put("keepaliveRestarts", stats.optInt("keepaliveRestarts"))
            put("probeOks", stats.optInt("probeOks"))
            put("probeFailures", stats.optInt("probeFailures"))
            put("keepaliveEnabled", stats.optBoolean("keepaliveEnabled"))
        }
    }
}
