package com.soreverse.mcp.core

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Process
import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.CrashReportActivity
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

object CrashReporter {
    const val EXTRA_TOKEN = "crash_token"
    private const val FILE_PREFIX = "crash-report-"
    private const val READY_PREFIX = "crash-ready-"
    private const val ACK_PREFIX = "crash-ack-"
    private const val READY_TIMEOUT_MS = 8_000L
    private const val POLL_INTERVAL_MS = 50L
    private val handling = AtomicBoolean(false)

    fun isCrashProcess(): Boolean = currentProcessName().endsWith(":crash")

    fun currentProcessName(): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            android.app.Application.getProcessName()
        } else {
            runCatching {
                File("/proc/self/cmdline")
                    .readText()
                    .trimEnd('\u0000')
            }.getOrDefault("unknown")
        }

    fun install(context: Context) {
        if (isCrashProcess()) return
        val app = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            if (!handling.compareAndSet(false, true)) {
                waitForever()
            }
            val token = UUID.randomUUID().toString()
            val reportFile = reportFile(app, token)
            val readyFile = readyFile(app, token)
            val ackFile = ackFile(app, token)
            runCatching {
                cleanOldReports(app)
                writeAtomically(reportFile, buildReport(thread, throwable))
                app.startActivity(
                    Intent(app, CrashReportActivity::class.java)
                        .putExtra(EXTRA_TOKEN, token)
                        .addFlags(
                            Intent.FLAG_ACTIVITY_NEW_TASK or
                                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                                Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS,
                        ),
                )
            }
            if (waitForFile(readyFile, READY_TIMEOUT_MS)) {
                while (!ackFile.exists()) {
                    runCatching { Thread.sleep(POLL_INTERVAL_MS) }
                }
            }
            runCatching { readyFile.delete() }
            runCatching { ackFile.delete() }
            previous?.uncaughtException(thread, throwable)
                ?: run {
                    Process.killProcess(Process.myPid())
                    kotlin.system.exitProcess(10)
                }
        }
    }

    fun readReport(context: Context, token: String): String? =
        validatedToken(token)?.let { safeToken ->
            runCatching { reportFile(context, safeToken).readText() }.getOrNull()
        }

    fun markReady(context: Context, token: String): Boolean =
        validatedToken(token)?.let { safeToken ->
            runCatching {
                readyFile(context, safeToken).writeText("ready")
                true
            }.getOrDefault(false)
        } ?: false

    fun confirmExit(context: Context, token: String): Boolean =
        validatedToken(token)?.let { safeToken ->
            runCatching {
                ackFile(context, safeToken).writeText("confirmed")
                true
            }.getOrDefault(false)
        } ?: false

    private fun buildReport(thread: Thread, throwable: Throwable): String = buildString {
        appendLine("SOMCP crash report")
        appendLine("Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS Z", Locale.US).format(Date())}")
        appendLine("Version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Process: ${currentProcessName()} (${Process.myPid()})")
        appendLine("Thread: ${thread.name}")
        appendLine("Android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
        appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("ABI: ${Build.SUPPORTED_ABIS.joinToString()}")
        appendLine()
        appendLine("Exception")
        appendLine("=========")
        appendLine(throwable.stackTraceToString())
        appendLine()
        appendLine("Recent application logs")
        appendLine("=======================")
        val logs = AppLog.snapshot()
        if (logs.isEmpty()) appendLine("(none)") else logs.forEach(::appendLine)
    }

    private fun writeAtomically(target: File, content: String) {
        val temporary = File(target.parentFile, "${target.name}.tmp")
        temporary.writeText(content)
        if (!temporary.renameTo(target)) {
            target.writeText(content)
            temporary.delete()
        }
    }

    private fun cleanOldReports(context: Context) {
        context.filesDir.listFiles()?.forEach { file ->
            if (
                file.name.startsWith(FILE_PREFIX) ||
                file.name.startsWith(READY_PREFIX) ||
                file.name.startsWith(ACK_PREFIX)
            ) {
                runCatching { file.delete() }
            }
        }
    }

    private fun waitForFile(file: File, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (file.exists()) return true
            runCatching { Thread.sleep(POLL_INTERVAL_MS) }
        }
        return file.exists()
    }

    private fun waitForever(): Nothing {
        while (true) {
            runCatching { Thread.sleep(60_000L) }
        }
    }

    private fun validatedToken(token: String): String? =
        token.takeIf { it.length in 1..64 && it.all { char -> char.isLetterOrDigit() || char == '-' } }

    private fun reportFile(context: Context, token: String) =
        File(context.filesDir, "$FILE_PREFIX$token.txt")

    private fun readyFile(context: Context, token: String) =
        File(context.filesDir, "$READY_PREFIX$token")

    private fun ackFile(context: Context, token: String) =
        File(context.filesDir, "$ACK_PREFIX$token")
}
