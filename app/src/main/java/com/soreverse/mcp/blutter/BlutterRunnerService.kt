package com.soreverse.mcp.blutter

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class BlutterRunnerService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private val tokens = ConcurrentHashMap<String, Long>()
    private val nextToken = AtomicLong(1)

    private val binder = object : IBlutterRunner.Stub() {
        override fun getManifestJson(): String = assets.open("blutter/runners.json").bufferedReader().use { it.readText() }

        override fun run(jobId: String, libraryName: String, libapp: ParcelFileDescriptor, libflutter: ParcelFileDescriptor, result: ParcelFileDescriptor, optionsJson: String, callback: IBlutterRunnerCallback) {
            val token = nextToken.getAndIncrement()
            tokens[jobId] = token
            executor.execute {
                var exitCode = -1
                var errorCode = ""
                var message = ""
                try {
                    callback.onProgress(jobId, "running", 10)
                    exitCode = NativeBlutterBridge.run(libraryName, libapp.fd, libflutter.fd, result.fd, optionsJson, token)
                    if (exitCode != 0) errorCode = "RUNNER_FAILED"
                } catch (error: Exception) {
                    errorCode = "RUNNER_EXCEPTION"
                    message = error.message ?: error.javaClass.simpleName
                } finally {
                    runCatching { libapp.close() }
                    runCatching { libflutter.close() }
                    runCatching { result.close() }
                    tokens.remove(jobId)
                }
                runCatching { callback.onCompleted(jobId, exitCode, errorCode, message, 0L, "") }
                stopSelf()
            }
        }

        override fun cancel(jobId: String) {
            tokens.remove(jobId)?.let(NativeBlutterBridge::cancel)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        tokens.values.forEach(NativeBlutterBridge::cancel)
        tokens.clear()
        executor.shutdownNow()
        super.onDestroy()
    }
}
