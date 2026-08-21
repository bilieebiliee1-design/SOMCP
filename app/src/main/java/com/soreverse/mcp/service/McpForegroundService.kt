package com.soreverse.mcp.service

import android.animation.ValueAnimator
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.WindowManager
import android.view.animation.OvershootInterpolator
import android.widget.TextView
import com.soreverse.mcp.MainActivity
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.EngineProvider
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.NetworkInspector
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.mcp.McpHttpServer
import java.util.Locale
import kotlin.math.abs

class McpForegroundService : Service() {
    private var server: McpHttpServer? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var floating: View? = null
    private var bubbleText: TextView? = null
    private var windowManager: WindowManager? = null
    private var pulseAnimator: ValueAnimator? = null
    private var activePort: Int = -1
    private var activeHost: String = ""

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        when (action) {
            ACTION_START -> startServer()

            ACTION_STOP -> {
                // Flip running=false the moment we receive the explicit STOP
                // intent, BEFORE stopSelf() schedules onDestroy(). The window
                // between stopSelf() and onDestroy() used to be tens of
                // milliseconds during which `running` was still true and
                // stopRequested was still false, so an in-flight keepalive
                // health probe that failed in that window would re-enter
                // tunnel.start() and spawn a fresh cloudflared child against
                // a Service Context that was mid-teardown — a race that
                // showed up as the app process getting killed when the user
                // toggled the MCP master switch off. Setting running=false
                // AND calling CloudflareTunnelManager.requestStop() here
                // synchronously mirrors what onDestroy() does on both gates,
                // so the two paths form a redundant gate and the window
                // collapses to zero.
                running = false
                runCatching { server?.tunnel?.requestStop() }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }

            ACTION_REFRESH_FLOATING -> {
                // Recreate the bubble so settings like floatingEdgeHide take
                // effect immediately even while the service is running.
                removeFloating()
                updateFloating()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        // Unregister the reconnect Receiver BEFORE calling tunnel.stop() so
        // the STOPPED broadcast that stop() emits cannot spawn a reconnect
        // sub-thread that re-enters tunnel.start() against a dying Service
        // Context.
        unregisterTunnelReconnect()
        // Flip running=false synchronously so any in-flight reconnect
        // thread spawned moments before unregisterTunnelReconnect() sees the
        // guard as false and exits without re-entering tunnel.start().
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        val sv = server
        server = null
        currentServer = null
        runCatching { sv?.tunnel?.requestStop() }
        Thread({
            try {
                sv?.tunnel?.stop()
            } catch (e: Throwable) {
                AppLog.e("tunnel.stop() failed during destroy", e)
            }
            try {
                sv?.stop()
            } catch (e: Throwable) {
                AppLog.e("server.stop() failed during destroy", e)
            }
        }, "mcp-teardown").apply { isDaemon = true }.start()
        wakeLock?.takeIf { it.isHeld }?.release()
        removeFloating()
        AppLog.i("Foreground service destroyed")
        super.onDestroy()
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        AppLog.w("Foreground service timeout: startId=$startId type=$fgsType")
        running = false
        runCatching { server?.tunnel?.requestStop() }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    private fun startServer() {
        if (!IntegrityGuard.isTrusted(applicationContext)) {
            AppLog.e("MCP service start blocked by integrity guard")
            running = false
            stopSelf()
            return
        }
        val settings = SettingsStore(this)
        val host = settings.bindHost
        createChannel()
        // Avoid showing the bind wildcard 0.0.0.0 in the notification: users kept
        // typing 0.0.0.0:8000/mcp as the client URL and it never connects. When
        // bound to all interfaces, surface a real reachable address (LAN IP if
        // available, otherwise 127.0.0.1) plus the required /mcp path.
        val displayText = buildNotificationText(host, settings.port)
        startForeground(1001, notification(displayText))
        updateWakeLock(settings.wakeLockEnabled)
        EngineProvider.restoreWorkDirectory(applicationContext)
        if (server != null && activePort == settings.port && activeHost == host) {
            running = true
            updateFloating()
            AppLog.i("MCP server already running on $host:${settings.port}/mcp")
            return
        }
        server?.stop()
        runCatching {
            server = McpHttpServer(applicationContext, settings.port, host).also { it.start() }
            currentServer = server
            activePort = settings.port
            activeHost = host
            running = true
            updateFloating()
            maybeAutoStartTunnel(settings)
            registerTunnelReconnect(settings)
        }.onFailure {
            running = false
            activePort = -1
            activeHost = ""
            AppLog.e("Failed to start MCP server", it)
            stopSelf()
        }
        AppLog.i("MCP server started on $host:${settings.port}/mcp")
    }

    private fun maybeAutoStartTunnel(settings: SettingsStore) {
        if (!settings.tunnelAutoStart) return
        // If the user enabled "auto-start with service" but kept tunnelMode=off (the default),
        // honour the switch by falling back to QUICK mode and persisting it so the choice sticks
        // across restarts. The previous behaviour silently swallowed the auto-start, which is
        // the root cause of "tunnelAutoStart is on yet Cloudflare never starts".
        val raw = settings.tunnelMode
        val mode = when (raw) {
            "quick" -> com.soreverse.mcp.core.CloudflareTunnelManager.Mode.QUICK

            "named" -> com.soreverse.mcp.core.CloudflareTunnelManager.Mode.NAMED

            else -> {
                AppLog.i(
                    "Auto-start tunnel: tunnelMode was '$raw', promoting to 'quick' to honour tunnelAutoStart=true"
                )
                settings.tunnelMode = "quick"
                com.soreverse.mcp.core.CloudflareTunnelManager.Mode.QUICK
            }
        }
        if (mode == com.soreverse.mcp.core.CloudflareTunnelManager.Mode.NAMED &&
            settings.tunnelNamedToken.isBlank()
        ) {
            AppLog.w("Auto-start tunnel: named mode selected but token is blank, skipping")
            return
        }
        Thread {
            // If the user toggled the master switch off again before this
            // thread got scheduled, abort cleanly instead of starting a
            // cloudflared child against a Service Context that is racing
            // to onDestroy. Same root cause as the reconnect race above.
            if (!running) {
                AppLog.i("Auto-start tunnel aborted: service stopped before launch")
                return@Thread
            }
            val target = settings.tunnelTargetPort.coerceAtLeast(settings.port)
            try {
                server?.tunnel?.start(target, mode, settings.tunnelNamedToken)
                AppLog.i(
                    "Auto-started Cloudflare tunnel: mode=${settings.tunnelMode} target=$target"
                )
            } catch (e: Throwable) {
                AppLog.w("Auto-start tunnel failed: ${e.message}")
            }
        }.apply {
            isDaemon = true
            name = "tunnel-autostart"
        }.start()
    }

    private var reconnectReceiver: android.content.BroadcastReceiver? = null
    private fun registerTunnelReconnect(settings: SettingsStore) {
        if (!settings.tunnelReconnect) return
        unregisterTunnelReconnect()
        val filter = android.content.IntentFilter("com.soreverse.mcp.TUNNEL_STATUS")
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                val state = intent?.getStringExtra("state") ?: return
                val terminal = intent.getBooleanExtra("terminal", false)
                if (state == "FAILED" && settings.tunnelAutoStart && !terminal) {
                    AppLog.w("Tunnel reported FAILED — scheduling reconnect")
                    Thread {
                        // Back off long enough that an in-flight onDestroy()
                        // has time to finish tearing the tunnel down; the
                        // previous hard-coded 3s was the exact cause of the
                        // crash: the reconnect thread re-entered
                        // CloudflareTunnelManager.start() while stop() was
                        // still joining the watch thread under the same
                        // monitor. Pull the backoff from settings so the
                        // operator can widen it if their device takes longer
                        // to release the cloudflared child.
                        Thread.sleep(settings.tunnelReconnectBackoffSec.coerceIn(1, 60) * 1000L)
                        // Double-gate: `running` flips false synchronously in
                        // both stop(context) and onDestroy, so by the time the
                        // backoff elapses after the FAILED broadcast (which
                        // usually accompanies a user toggle off) we expect
                        // to observe the false here. Skipping the restart
                        // prevents spawning a fresh cloudflared child against
                        // a dying Service Context — the original crash root
                        // cause.
                        if (!running) {
                            AppLog.i("Tunnel reconnect skipped: service no longer running")
                            return@Thread
                        }
                        val mode = when (settings.tunnelMode) {
                            "quick" -> com.soreverse.mcp.core.CloudflareTunnelManager.Mode.QUICK
                            "named" -> com.soreverse.mcp.core.CloudflareTunnelManager.Mode.NAMED
                            else -> com.soreverse.mcp.core.CloudflareTunnelManager.Mode.QUICK
                        }
                        try {
                            server?.tunnel?.start(
                                settings.tunnelTargetPort.coerceAtLeast(settings.port),
                                mode,
                                settings.tunnelNamedToken
                            )
                        } catch (e: Throwable) {
                            AppLog.w("Tunnel reconnect start failed: ${e.message}")
                        }
                    }.apply {
                        isDaemon = true
                        name = "tunnel-reconnect"
                    }.start()
                }
            }
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag", "DEPRECATION")
            registerReceiver(receiver, filter)
        }
        reconnectReceiver = receiver
    }

    private fun unregisterTunnelReconnect() {
        reconnectReceiver?.let { runCatching { unregisterReceiver(it) } }
        reconnectReceiver = null
    }

    private fun updateWakeLock(enabled: Boolean) {
        if (!enabled) {
            wakeLock?.takeIf { it.isHeld }?.release()
            wakeLock = null
            return
        }
        if (wakeLock?.isHeld == true) return
        runCatching {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SoReverseMcp:server").also {
                it.setReferenceCounted(false)
                it.acquire()
            }
        }.onFailure {
            AppLog.e("Failed to acquire WakeLock", it)
        }
    }

    private fun updateFloating() {
        val settings = SettingsStore(this)
        if (!settings.floatingEnabled || !Settings.canDrawOverlays(this)) {
            removeFloating()
            return
        }
        if (floating != null) return
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        val zh =
            settings.language == "zh" ||
                (settings.language == "system" && Locale.getDefault().language == "zh")
        val density = resources.displayMetrics.density
        val tv = TextView(this).apply {
            text = if (zh) "● SOMCP 运行中" else "● SOMCP running"
            setTextColor(Color.WHITE)
            textSize = 11f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            letterSpacing = 0.03f
            gravity = Gravity.CENTER
            setPadding(
                (14 * density).toInt(),
                (9 * density).toInt(),
                (14 * density).toInt(),
                (
                    9 *
                        density
                    ).toInt()
            )
            background = GradientDrawable().apply {
                setColor(Color.argb(238, 24, 30, 42))
                setStroke((1 * density).toInt(), Color.argb(110, 255, 255, 255))
                cornerRadius = 999f
            }
            elevation = 8 * density
            alpha = 0.96f
        }
        bubbleText = tv
        val type = if (Build.VERSION.SDK_INT >=
            26
        ) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = 0
            y = 280
        }
        val touchSlop = ViewConfiguration.get(this).scaledTouchSlop
        val edgeHide = settings.floatingEdgeHide
        // Visible tab width (dp) left on screen when the bubble is dock-hidden.
        val edgePx = (5 * density).toInt()
        var downX = 0f
        var downY = 0f
        var startX = 0
        var startY = 0
        var moved = false
        var dockedRight = false
        var collapsed = false
        var revealedByTouch = false
        var slideAnimator: ValueAnimator? = null

        fun relayout() {
            windowManager?.updateViewLayout(tv, params)
        }

        // x at which the bubble is fully shown against its nearest edge.
        fun dockX(): Int {
            val width = resources.displayMetrics.widthPixels
            dockedRight = params.x + tv.width / 2 > width / 2
            return if (dockedRight) width - tv.width else 0
        }

        // x at which only [edgePx] stays visible (the hidden/tabbed state).
        fun hiddenX(): Int {
            val width = resources.displayMetrics.widthPixels
            return if (dockedRight) width - edgePx else edgePx - tv.width
        }

        fun animateX(target: Int) {
            slideAnimator?.cancel()
            slideAnimator = ValueAnimator.ofInt(params.x, target).apply {
                duration = 240
                addUpdateListener {
                    params.x = it.animatedValue as Int
                    relayout()
                }
                start()
            }
        }

        tv.setOnClickListener { launchMainActivity() }
        tv.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    if (collapsed) {
                        // Tapping the tab slides the bubble back out; tracked
                        // from the fully-shown dock position so an immediate
                        // drag starts at the right spot.
                        collapsed = false
                        revealedByTouch = true
                        val dx = dockX()
                        startX = dx
                        animateX(dx)
                    } else {
                        tv.animate().scaleX(1.08f).scaleY(1.08f).setDuration(120).start()
                        startX = params.x
                    }
                    downX = event.rawX
                    downY = event.rawY
                    startY = params.y
                    moved = false
                    true
                }

                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - downX
                    val deltaY = event.rawY - downY
                    if (!moved && (abs(deltaX) > touchSlop || abs(deltaY) > touchSlop)) {
                        moved = true
                    }
                    if (moved) {
                        slideAnimator?.cancel()
                        params.x = startX + deltaX.toInt()
                        params.y = startY + deltaY.toInt()
                        relayout()
                    }
                    true
                }

                MotionEvent.ACTION_UP -> {
                    tv.animate().scaleX(
                        1f
                    ).scaleY(1f).setInterpolator(OvershootInterpolator()).setDuration(260).start()
                    when {
                        moved -> {
                            // Dock to the nearest edge, then slide most of the
                            // bubble off-screen when edge-hide is enabled.
                            dockX()
                            if (edgeHide) {
                                animateX(hiddenX())
                                collapsed = true
                            } else {
                                animateX(dockX())
                            }
                        }
                        revealedByTouch -> {
                            // A tap on a hidden tab just reveals the bubble.
                            revealedByTouch = false
                        }
                        else -> tv.performClick()
                    }
                    true
                }

                MotionEvent.ACTION_CANCEL -> {
                    tv.animate().scaleX(
                        1f
                    ).scaleY(1f).setInterpolator(OvershootInterpolator()).setDuration(180).start()
                    true
                }

                else -> false
            }
        }
        floating = tv
        windowManager?.addView(tv, params)
        startPulse(tv)
        AppLog.i("Floating window shown")
    }

    private fun launchMainActivity() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        startActivity(intent)
    }

    private fun removeFloating() {
        pulseAnimator?.cancel()
        pulseAnimator = null
        floating?.let { runCatching { windowManager?.removeView(it) } }
        floating = null
        bubbleText = null
    }

    private fun startPulse(view: View) {
        pulseAnimator = ValueAnimator.ofFloat(1f, 1.035f, 1f).apply {
            duration = 1800L
            repeatCount = ValueAnimator.INFINITE
            addUpdateListener {
                val v = it.animatedValue as Float
                view.scaleX = v
                view.scaleY = v
            }
            start()
        }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "SOMCP", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun buildNotificationText(host: String, port: Int): String {
        // The full MCP endpoint always requires the /mcp path. Show a concrete,
        // usable URL rather than the bind host so users don't type 0.0.0.0.
        return if (host == "0.0.0.0") {
            val lan = runCatching {
                NetworkInspector.primaryLanIpv4(applicationContext)
            }.getOrNull()
            if (lan != null) {
                "MCP 运行中 · 客户端填 http://$lan:$port/mcp（局域网）"
            } else {
                "MCP 运行中 · 客户端填 http://<本机IP>:$port/mcp（勿填 0.0.0.0）"
            }
        } else {
            "MCP 运行中 · 客户端填 http://127.0.0.1:$port/mcp（仅本机/ADB）"
        }
    }

    private fun notification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >=
            26
        ) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("SOMCP")
            .setContentText(text)
            .setSmallIcon(com.soreverse.mcp.R.drawable.ic_stat_somcp)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START = "com.soreverse.mcp.START"
        const val ACTION_STOP = "com.soreverse.mcp.STOP"
        const val ACTION_REFRESH_FLOATING = "com.soreverse.mcp.FLOATING"
        private const val CHANNEL_ID = "so_reverse_mcp"

        @Volatile private var running: Boolean = false

        @Volatile var currentServer: McpHttpServer? = null
            private set

        fun isRunning(): Boolean = running

        fun start(context: Context) {
            if (!IntegrityGuard.isTrusted(context.applicationContext)) {
                AppLog.e("MCP service start rejected before dispatch by integrity guard")
                return
            }
            val intent = Intent(context, McpForegroundService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >=
                26
            ) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            running = false
            context.startService(
                Intent(context, McpForegroundService::class.java).setAction(ACTION_STOP)
            )
        }

        fun refreshFloating(context: Context) {
            context.startService(
                Intent(context, McpForegroundService::class.java).setAction(ACTION_REFRESH_FLOATING)
            )
        }
    }
}
