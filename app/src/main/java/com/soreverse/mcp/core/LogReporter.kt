// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
package com.soreverse.mcp.core

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.nativecore.SignatureVerifier
import java.io.File
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

/**
 * 错误 / 崩溃自动上报客户端，上报协议对齐 `log-report-platform` 的 `/api/v1/report`。
 *
 * 设计要点：
 * - 零第三方依赖，仅使用 [HttpURLConnection]，不引入新 Gradle 依赖。
 * - 上报开关与服务器地址来自 [SettingsStore]；API Key 由构建期注入 **native 层**
 *   （`key_generated.h`，经 [SignatureVerifier.getReportingApiKey] 读取），仅作为 `X-API-Key`
 *   请求头发送，不进源码 / 设置 / 快照 / 日志。未开启或地址为空时完全静默（fail-closed），
 *   不会把任何数据发出去，也不会产生任何副作用。
 * - 崩溃时**先落盘到本地队列**（保证崩溃日志不丢），再尽力即时上报；进程可能在发送前就被系统杀掉，
 *   因此下次启动 [init] 会自动调用 [flushQueue] 补传上一次残留的崩溃日志。
 *
 * 用法：
 * ```
 * LogReporter.init(applicationContext)                 // 在 Application.onCreate 调用一次
 * LogReporter.report("error", "订单提交失败: code=500")  // 手动上报业务错误
 * // 未捕获崩溃由 CrashReporter 自动调用 reportCrash(...)
 * ```
 */
object LogReporter {

    private const val TAG = "LogReporter"
    private const val REPORT_PATH = "/api/v1/report"
    private const val CONNECT_TIMEOUT = 15_000
    private const val READ_TIMEOUT = 15_000
    private const val MAX_QUEUE_FILES = 50
    private const val MAX_LOG_CHARS = 2 * 1024 * 1024 // 与后端 LRP_MAX_LOG_BYTES 对齐

    /** [sendBlocking] 的返回码：连接 / IO 层失败，服务器根本没应答。 */
    private const val SEND_TRANSPORT_ERROR = -1

    @Volatile private var appContext: Context? = null
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "LogReporter").apply { isDaemon = true }
    }
    private val initialized = AtomicBoolean(false)

    // 防止捕获型错误高频重复上报（如重试循环）刷爆服务端：相同指纹在 30s 内只上报一次。
    private val recentReports = ArrayDeque<Pair<String, Long>>()
    private val recentLock = Any()
    private const val DEDUP_WINDOW_MS = 30_000L
    private const val MAX_RECENT = 64

    /** 在 [android.app.Application.onCreate] 中调用一次。下次启动会补传上一次残留的崩溃日志。 */
    fun init(context: Context) {
        this.appContext = context.applicationContext
        if (initialized.compareAndSet(false, true)) {
            executor.execute { flushQueue() }
        }
    }

    /**
     * 读取当前上报配置。返回 `(endpoint, enabled)`，endpoint 为 null 即视为未配置。
     * 每次都从 [SettingsStore] 读取，使运行期在设置页 / MCP 里的改动立即生效，无需重启。
     *
     * 隐私合规闸门：除用户开关外还必须已完成一次性隐私告知
     * （[SettingsStore.crashReportConsentAnswered]），否则一律视为未启用——
     * 既不外发，也不写入本地补传队列。
     */
    private fun config(): Pair<String?, Boolean> {
        val ctx = appContext ?: return Pair(null, false)
        val s = SettingsStore(ctx)
        return Pair(
            s.crashReportEndpoint.ifBlank { null },
            s.crashReportEnabled && s.crashReportConsentAnswered
        )
    }

    /**
     * 重复上报抑制：相同指纹（logType|tag|content）在 [DEDUP_WINDOW_MS] 内只放行一次。
     * 仅作用于 [report]（捕获型错误与手动上报）；崩溃上报 [reportCrash] 不受抑制，确保每条崩溃都送达。
     */
    private fun shouldSuppress(key: String): Boolean {
        // 单调时钟：设备时钟被手动改动 / NTP 回拨时，窗口不会突然放开或误抑制。
        val now = SystemClock.elapsedRealtime()
        synchronized(recentLock) {
            while (recentReports.isNotEmpty() && now - recentReports.first().second > DEDUP_WINDOW_MS) {
                recentReports.removeFirst()
            }
            if (recentReports.any { it.first == key && now - it.second < DEDUP_WINDOW_MS }) return true
            recentReports.addLast(key to now)
            while (recentReports.size > MAX_RECENT) recentReports.removeFirst()
            return false
        }
    }

    /** 手动上报一条错误 / 日志（异步，不阻塞调用方；网络不可用时落盘队列稍后补传）。 */
    fun report(logType: String = "error", content: String, throwable: Throwable? = null, tag: String? = null, extras: Map<String, Any?>? = null) {
        val (endpoint, enabled) = config()
        if (!enabled || endpoint == null) return
        if (shouldSuppress("$logType|${tag ?: ""}|$content")) return
        val stack = throwable?.let { Log.getStackTraceString(it) }
        val full = if (stack.isNullOrEmpty()) content else "$content\n$stack"
        val json = buildPayload(logType, full, stack, tag, Thread.currentThread().name, extras)
        executor.execute {
            if (sendBlocking(json, endpoint) !in 200..299) saveToQueue(json)
        }
    }

    /**
     * 未捕获崩溃专用：保证先把日志落盘（同步、不阻塞崩溃流程），再尽力即时上报。
     * 即时发送成功会删除落盘文件；失败则留给下次启动 [flushQueue] 补传。
     */
    fun reportCrash(content: String, stackTrace: String? = null, threadName: String? = null, extras: Map<String, Any?>? = null) {
        val (endpoint, enabled) = config()
        if (!enabled || endpoint == null) return
        val json = buildPayload("crash", content, stackTrace, "AndroidRuntime", threadName, extras)
        val file = saveToQueue(json) ?: return
        executor.execute {
            if (sendBlocking(json, endpoint) in 200..299) file.delete()
        }
    }

    // ---------------------------------------------------------------- 组装 payload

    private fun buildPayload(logType: String, content: String, stackTrace: String?, tag: String?, threadName: String?, extras: Map<String, Any?>?): JSONObject {
        val ctx = appContext
        val json = JSONObject()

        // ---- 上报必需字段（log-report-platform 要求）----
        json.put("device_name", deviceName())
        json.put("android_version", Build.VERSION.RELEASE ?: "unknown")
        json.put("architecture", architecture())
        json.put("app_version_name", versionName(ctx))
        json.put("app_version_code", versionCode(ctx).toString())
        json.put("package_name", ctx?.packageName ?: BuildConfig.APPLICATION_ID)
        json.put("log_content", content.take(MAX_LOG_CHARS))

        // ---- 可选字段 ----
        json.put("log_type", logType)
        json.put("occurred_at", System.currentTimeMillis())
        json.put("device_model", Build.MODEL ?: "")
        json.put("brand", Build.BRAND ?: "")
        json.put("sdk_int", Build.VERSION.SDK_INT)
        json.put("rom_version", Build.DISPLAY ?: "")
        tag?.let { json.put("tag", it) }
        threadName?.let { json.put("thread_name", it) }
        stackTrace?.let { json.put("stack_trace", it.take(MAX_LOG_CHARS)) }

        if (!extras.isNullOrEmpty()) {
            val extrasJson = JSONObject()
            extras.forEach { (k, v) -> extrasJson.put(k, v ?: JSONObject.NULL) }
            json.put("extras", extrasJson)
        }
        return json
    }

    private fun deviceName(): String {
        val manufacturer = Build.MANUFACTURER?.replaceFirstChar { it.uppercase() } ?: ""
        return "$manufacturer ${Build.MODEL}".trim().ifEmpty { "unknown" }
    }

    private fun architecture(): String {
        val abis = Build.SUPPORTED_ABIS
        return if (abis.isNotEmpty()) abis[0] else Build.CPU_ABI ?: "unknown"
    }

    private fun versionName(ctx: Context?): String {
        ctx ?: return BuildConfig.VERSION_NAME.ifBlank { "unknown" }
        return runCatching {
            ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName
                ?: BuildConfig.VERSION_NAME
        }.getOrDefault(BuildConfig.VERSION_NAME.ifBlank { "unknown" })
    }

    private fun versionCode(ctx: Context?): Long {
        ctx ?: return BuildConfig.VERSION_CODE.toLong()
        return runCatching {
            val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                info.versionCode.toLong()
            }
        }.getOrDefault(BuildConfig.VERSION_CODE.toLong())
    }

    // ---------------------------------------------------------------- 网络

    /**
     * 同步发送。返回 HTTP 状态码；连接 / IO 层失败返回 [SEND_TRANSPORT_ERROR]。
     * 调用方据此区分「服务器已应答但拒绝」与「网络不可达」：前者可以继续处理队列里的
     * 下一条，后者应立即中止整轮补传。
     */
    private fun sendBlocking(json: JSONObject, endpoint: String): Int {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(endpoint.trimEnd('/') + REPORT_PATH).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT
                readTimeout = READ_TIMEOUT
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                // API Key 来自构建期注入 native 层的 key_generated.h（经 JNI 读取），
                // 仅作为请求头发送；绝不打印到日志，也不进入上报 body / SettingsStore / 快照。
                // 只在 release 构建附带：debug 包可能被自由分发，不把生产密钥带进调试包。
                if (!BuildConfig.DEBUG) {
                    val apiKey = SignatureVerifier.getReportingApiKey()
                    if (apiKey.isNotBlank()) setRequestProperty("X-API-Key", apiKey)
                }
            }
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(json.toString()) }

            val code = conn.responseCode
            if (code in 200..299) {
                if (BuildConfig.DEBUG) Log.d(TAG, "上报成功: $code")
            } else {
                // 仅记录 HTTP 状态码，绝不回显响应体或 API Key。
                Log.w(TAG, "上报失败: HTTP $code")
            }
            code
        } catch (t: Throwable) {
            if (BuildConfig.DEBUG) Log.w(TAG, "上报异常: ${t.message}")
            SEND_TRANSPORT_ERROR
        } finally {
            conn?.disconnect()
        }
    }

    // ---------------------------------------------------------------- 本地队列（断网 / 崩溃兜底）

    private fun queueDir(): File? {
        val ctx = appContext ?: return null
        return File(ctx.filesDir, "logreport-queue").apply { if (!exists()) mkdirs() }
    }

    /** 把 payload 落盘到队列目录，返回所写文件（失败返回 null）。 */
    private fun saveToQueue(json: JSONObject): File? {
        val dir = queueDir() ?: return null
        return try {
            val files = dir.listFiles()?.sortedBy { it.lastModified() } ?: emptyList()
            // 队列超限时丢弃最旧的，避免占满存储
            while (files.size >= MAX_QUEUE_FILES) files.first().delete()
            val name = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) +
                "-" + UUID.randomUUID() + ".json"
            val file = File(dir, name)
            file.writeText(json.toString(), Charsets.UTF_8)
            file
        } catch (t: Throwable) {
            Log.e(TAG, "写入队列失败", t)
            null
        }
    }

    /** 补传队列里的日志（下次启动或调用 [flush] 时）。 */
    fun flush() {
        executor.execute { flushQueue() }
    }

    /**
     * 清空本地补传队列。用于用户拒绝隐私告知时丢弃尚未发送的残留日志，
     * 避免不同意上报的数据长期留在设备上。
     */
    fun clearQueue() {
        executor.execute {
            runCatching { queueDir()?.listFiles()?.forEach { it.delete() } }
        }
    }

    private fun flushQueue() {
        val (endpoint, enabled) = config()
        val dir = queueDir() ?: return
        if (!enabled || endpoint == null) return
        val files = dir.listFiles()?.sortedBy { it.lastModified() } ?: return
        for (file in files) {
            val code = try {
                sendBlocking(JSONObject(file.readText(Charsets.UTF_8)), endpoint)
            } catch (t: Throwable) {
                file.delete() // 内容损坏，直接丢弃，不阻断后续补传
                continue
            }
            // 2xx 视为送达并删除；连接层失败说明网络不可达，整轮中止（避免对剩余文件逐个
            // 空等连接超时）；其余是服务器已应答但拒绝（4xx / 5xx），保留该文件并继续尝试
            // 后续条目，避免一条永远失败的记录压住整个队列。
            if (code in 200..299) {
                file.delete()
            } else if (code == SEND_TRANSPORT_ERROR) {
                return
            }
        }
    }
}
