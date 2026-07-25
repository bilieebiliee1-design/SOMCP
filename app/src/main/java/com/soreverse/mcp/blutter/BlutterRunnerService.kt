package com.soreverse.mcp.blutter

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class BlutterRunnerService : Service() {
    /**
     * Multi-threaded execution. A bounded thread pool runs several Blutter jobs
     * concurrently inside this isolated process.
     *
     * Concurrency safety:
     *  - Jobs targeting the SAME runner library are serialized via a
     *    per-library lock, because the underlying Dart VM runner keeps
     *    process-global state and must not be driven concurrently for one
     *    library. The native bridge loads each library with RTLD_LOCAL, so
     *    different libraries keep their symbols private per handle and run
     *    truly in parallel. (The "same-process multi-runner for one library"
     *    path stays serialized until a Dart VM global-state stress test
     *    confirms it is safe.)
     *  - The pool size is bounded (MAX_PARALLEL_JOBS) so a flood of requests
     *    cannot exhaust the device.
     *
     * Progress is HONEST: we forward whatever the native runner reports and
     * mark "disassembling" at 0% when work begins. We never synthesize a
     * percentage that ramps toward 100% on a timer — the only 100% is the
     * real commit emitted by the backend.
     *
     * Wall-clock timeout per job: ask the runner to cancel; if still stuck
     * after a grace period, report a structured RUNNER_TIMEOUT and tear the
     * process down. A hard timeout tears down the shared process, so co-running
     * jobs are also terminated; the backend fails/resubmits them via
     * onServiceDisconnected. Per-library serialization keeps a hung
     * same-library job from deadlocking other libraries' queues.
     */
    private val maxParallel = run { Runtime.getRuntime().availableProcessors().coerceIn(2, 8) }
    private val executor = Executors.newFixedThreadPool(maxParallel)
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val idleScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val tokens = ConcurrentHashMap<String, Long>()
    private val libraryLocks = ConcurrentHashMap<String, Any>()
    private val activeCount = AtomicInteger(0)
    private val nextToken = AtomicLong(1)

    override fun onCreate() {
        super.onCreate()
        // Promote to a started service so the process survives across concurrent
        // jobs even after clients unbind. We only stopSelf() once truly idle.
        runCatching { startService(Intent(this, BlutterRunnerService::class.java)) }
    }

    private val binder = object : IBlutterRunner.Stub() {
        override fun getManifestJson(): String = assets.open("blutter/runners.json").bufferedReader().use { it.readText() }

        override fun run(
            jobId: String,
            libraryName: String,
            libapp: ParcelFileDescriptor,
            libflutter: ParcelFileDescriptor,
            result: ParcelFileDescriptor,
            optionsJson: String,
            callback: IBlutterRunnerCallback,
        ) {
            val token = nextToken.getAndIncrement()
            tokens[jobId] = token
            val options = runCatching { JSONObject(optionsJson) }.getOrDefault(JSONObject())
            val timeoutMillis = options.optLong("timeoutMillis", DEFAULT_TIMEOUT_MILLIS)
                .let { if (it <= 0) DEFAULT_TIMEOUT_MILLIS else it.coerceIn(MIN_TIMEOUT_MILLIS, MAX_TIMEOUT_MILLIS) }
            // Increment before submitting so a job that lands in the 30s idle
            // window can never be killed by a pending idle shutdown (which only
            // fires after the count has returned to 0).
            activeCount.incrementAndGet()
            try {
                executor.execute {
                    val done = AtomicBoolean(false)
                    val emitCompleted: (Int, String, String, Long) -> Unit = { code, err, msg, bytes ->
                        if (done.compareAndSet(false, true)) {
                            runCatching { callback.onCompleted(jobId, code, err, msg, bytes, "") }
                        }
                    }
                    // Serialize same-library jobs. The watchdog only starts once
                    // the lock is held, so a queued job waiting for the lock is
                    // never falsely timed out.
                    val lock = libraryLocks.getOrPut(libraryName) { Any() }
                    synchronized(lock) {
                        runCatching { callback.onProgress(jobId, "disassembling", 0) }
                        val watchdog = scheduler.schedule({
                            if (done.get()) return@schedule
                            NativeBlutterBridge.cancel(token)
                            scheduler.schedule({
                                if (done.get()) return@schedule
                                emitCompleted(-1, "RUNNER_TIMEOUT", "Blutter disassembly exceeded the wall-clock timeout of ${timeoutMillis}ms", 0L)
                                stopSelf()
                            }, CANCEL_GRACE_MILLIS, TimeUnit.MILLISECONDS)
                        }, timeoutMillis, TimeUnit.MILLISECONDS)

                        var exitCode = -1
                        var errorCode = ""
                        var message = ""
                        try {
                            exitCode = NativeBlutterBridge.run(libraryName, libapp.fd, libflutter.fd, result.fd, optionsJson, token)
                            if (exitCode != 0) errorCode = "RUNNER_FAILED"
                        } catch (error: Exception) {
                            errorCode = "RUNNER_EXCEPTION"
                            message = error.message ?: error.javaClass.simpleName
                        } finally {
                            runCatching { watchdog.cancel(false) }
                            runCatching { libapp.close() }
                            runCatching { libflutter.close() }
                            runCatching { result.close() }
                            tokens.remove(jobId)
                        }
                        emitCompleted(exitCode, errorCode, message, 0L)
                    }
                    onJobFinished()
                }
            } catch (rejected: RejectedExecutionException) {
                activeCount.decrementAndGet()
                tokens.remove(jobId)
                runCatching { callback.onCompleted(jobId, -1, "RUNNER_REJECTED", "Runner executor is saturated", 0L, "") }
            }
        }

        override fun cancel(jobId: String) {
            tokens.remove(jobId)?.let(NativeBlutterBridge::cancel)
        }
    }

    private fun onJobFinished() {
        if (activeCount.decrementAndGet() <= 0) {
            idleScheduler.schedule({ if (activeCount.get() <= 0) stopSelf() }, IDLE_SHUTDOWN_SECONDS, TimeUnit.SECONDS)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        tokens.values.forEach(NativeBlutterBridge::cancel)
        tokens.clear()
        executor.shutdownNow()
        scheduler.shutdownNow()
        idleScheduler.shutdownNow()
        super.onDestroy()
    }

    private companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 30L * 60L * 1000L
        const val MIN_TIMEOUT_MILLIS = 60L * 1000L
        const val MAX_TIMEOUT_MILLIS = 60L * 60L * 1000L
        const val CANCEL_GRACE_MILLIS = 5000L
        const val IDLE_SHUTDOWN_SECONDS = 30L
    }
}
