package com.soreverse.mcp.engine

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import com.soreverse.mcp.blutter.BlutterRunnerService
import com.soreverse.mcp.blutter.IBlutterRunner
import com.soreverse.mcp.blutter.IBlutterRunnerCallback
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

internal class BlutterEmbeddedBackend(
    private val context: Context,
    private val store: BlutterResultStore,
) {
    private val active = ConcurrentHashMap<String, ActiveJob>()
    // Orchestration-level watchdogs. The runner process enforces its own
    // per-job wall-clock timeout; these only cover the gaps around it:
    //  - the connect watchdog fires if the isolated process never binds, and
    //  - the job watchdog (started only after onServiceConnected) fires if
    //    the process connects but then hangs without the runner reporting back.
    // The job watchdog is deliberately scheduled AFTER the runner connects so a
    // job merely queued behind the per-library lock in the runner process is
    // never falsely timed out.
    private val watchdog = Executors.newSingleThreadScheduledExecutor()

    fun start(jobId: String, runner: BlutterRunnerDescriptor, libraries: FlutterLibraries, options: JSONObject) {
        val jobDir = File(context.noBackupFilesDir, "blutter/v1/jobs/$jobId/input").apply { mkdirs() }
        val libapp = File(jobDir, "libapp.so").apply { writeBytes(libraries.libapp) }
        val libflutter = File(jobDir, "libflutter.so").apply { writeBytes(libraries.libflutter) }
        val output = File(jobDir.parentFile, "runner-result.json").apply { if (exists()) delete() }
        val timeoutMillis = options.optLong("timeoutMillis", DEFAULT_TIMEOUT_MILLIS)
            .let { if (it <= 0) DEFAULT_TIMEOUT_MILLIS else it.coerceIn(MIN_TIMEOUT_MILLIS, MAX_TIMEOUT_MILLIS) }
        val connection = RunnerConnection(jobId, runner, libraries, libapp, libflutter, output, options, timeoutMillis)
        // Connect watchdog: a job whose runner process never binds gets a
        // structured failure instead of hanging forever.
        val handle = watchdog.schedule({
            val job = active.remove(jobId) ?: return@schedule
            val problem = JSONObject().put("code", "RUNNER_TIMEOUT").put("message", "Blutter runner process never connected within the timeout").put("recoverable", false).put("stage", "binding_runner")
            store.update(jobId, "failed", "binding_runner", problem)
            runCatching { context.unbindService(job.connection) }
        }, CONNECT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        active[jobId] = ActiveJob(connection, timeoutHandle = handle)
        store.update(jobId, "running", "binding_runner")
        val intent = Intent(context, BlutterRunnerService::class.java)
        if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            active.remove(jobId)?.timeoutHandle?.let { runCatching { it.cancel(false) } }
            fail(jobId, "RUNNER_BIND_FAILED", "Cannot bind the isolated Blutter runner process", "binding_runner", true)
        }
    }

    fun cancel(jobId: String): Boolean {
        val job = active.remove(jobId) ?: return false
        job.timeoutHandle?.let { runCatching { it.cancel(false) } }
        runCatching { job.runner?.cancel(jobId) }
        store.update(jobId, "cancelling", "cancelling")
        runCatching { context.unbindService(job.connection) }
        return true
    }

    private inner class RunnerConnection(
        private val jobId: String,
        private val descriptor: BlutterRunnerDescriptor,
        private val libraries: FlutterLibraries,
        private val libapp: File,
        private val libflutter: File,
        private val output: File,
        private val options: JSONObject,
        private val timeoutMillis: Long,
    ) : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val runner = IBlutterRunner.Stub.asInterface(binder)
            val job = active[jobId] ?: return
            job.runner = runner
            store.update(jobId, "running", "runner_execution")
            // Swap the connect watchdog for the real job watchdog. It only
            // starts now that the runner is actually executing, so the wall-clock
            // budget is spent on the disassembly, not on waiting to be bound.
            job.timeoutHandle?.let { runCatching { it.cancel(false) } }
            job.timeoutHandle = watchdog.schedule({
                val j = active.remove(jobId) ?: return@schedule
                val problem = JSONObject().put("code", "RUNNER_TIMEOUT").put("message", "Blutter disassembly exceeded the wall-clock timeout of ${timeoutMillis}ms").put("recoverable", false).put("stage", "running")
                store.update(jobId, "failed", "running", problem)
                runCatching { context.unbindService(j.connection) }
            }, timeoutMillis, TimeUnit.MILLISECONDS)
            val appFd = ParcelFileDescriptor.open(libapp, ParcelFileDescriptor.MODE_READ_ONLY)
            val flutterFd = ParcelFileDescriptor.open(libflutter, ParcelFileDescriptor.MODE_READ_ONLY)
            val resultFd = ParcelFileDescriptor.open(output, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE or ParcelFileDescriptor.MODE_READ_WRITE)
            try {
                runner.run(jobId, descriptor.libraryName, appFd, flutterFd, resultFd, options.toString(), callback)
            } catch (error: Exception) {
                finishFailure("RUNNER_TRANSPORT_FAILED", error.message ?: "Runner transport failed", true)
            } finally {
                runCatching { appFd.close() }
                runCatching { flutterFd.close() }
                runCatching { resultFd.close() }
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            if (active.containsKey(jobId)) finishFailure("RUNNER_INTERRUPTED", "The isolated runner process disconnected", true, "interrupted")
        }

        override fun onBindingDied(name: ComponentName) {
            finishFailure("RUNNER_CRASHED", "The isolated runner process died", true, "interrupted")
        }

        override fun onNullBinding(name: ComponentName) {
            finishFailure("RUNNER_BIND_FAILED", "The isolated runner returned no Binder", true)
        }

        private val callback = object : IBlutterRunnerCallback.Stub() {
            override fun onProgress(callbackJobId: String, stage: String, percent: Int) {
                if (callbackJobId == jobId && active.containsKey(jobId)) store.progress(jobId, stage, percent, true)
            }

            override fun onCompleted(callbackJobId: String, exitCode: Int, errorCode: String, message: String, resultBytes: Long, resultSha256: String) {
                if (callbackJobId != jobId || !active.containsKey(jobId)) return
                if (exitCode != 0 || errorCode.isNotBlank()) {
                    finishFailure(errorCode.ifBlank { "RUNNER_FAILED" }, message.ifBlank { "Blutter runner exited with code $exitCode" }, true)
                    return
                }
                runCatching { commitOutput() }.onFailure { error ->
                    finishFailure("RUNNER_RESULT_INVALID", error.message ?: "Runner result is invalid", false)
                }
            }
        }

        private fun commitOutput() {
            check(output.isFile) { "Runner did not create a result" }
            check(output.length() in 2..MAX_RESULT_BYTES) { "Runner result exceeds the allowed size" }
            val result = JSONObject(output.readText())
            val generated = Instant.now().toString()
            val input = JSONObject()
                .put("displayName", libraries.displayName)
                .put("abi", libraries.abi)
                .put("libapp", fileJson(libraries.libappEntry, libraries.libapp))
                .put("libflutter", fileJson(libraries.libflutterEntry, libraries.libflutter))
            val nativeSummary = result.optJSONObject("summary") ?: error("Missing runner summary")
            for (kind in listOf("libraries", "classes", "functions", "objects")) {
                val page = result.optJSONObject(kind) ?: error("Missing result page: $kind")
                check(page.has("items") && page.has("total") && page.has("hasMore") && page.has("nextCursor")) { "Invalid result page: $kind" }
                validateEntities(page.optJSONArray("items"), kind)
            }
            result.put("jobId", jobId).put("status", "succeeded").put("backend", "embedded")
                .put("createdAt", generated).put("completedAt", generated).put("input", input)
                .put("flutter", JSONObject().put("dartVersion", JSONObject.NULL).put("engineRevision", JSONObject.NULL).put("compressedPointers", JSONObject.NULL).put("nullSafety", JSONObject.NULL).put("confidence", 0.0))
                .put("runner", JSONObject().put("runnerId", descriptor.runnerId).put("source", "embedded").put("upstreamCommit", descriptor.upstreamCommit).put("sha256", descriptor.sha256))
                .put("summary", nativeSummary)
                .put("provenance", JSONObject().put("protocolVersion", 1).put("normalizerVersion", "native-1").put("cacheHit", false).put("durationMillis", 0))
            val key = digest(libapp, libflutter, descriptor.sha256, options.toString())
            store.update(jobId, "running", "committing", progressPercent = 100, progressEstimated = false)
            store.commit(jobId, result, key)
            finish()
        }

        private fun finishFailure(code: String, message: String, recoverable: Boolean, status: String = "failed") {
            fail(jobId, code, message, "runner_execution", recoverable, status)
            finish()
        }

        private fun finish() {
            val job = active[jobId]
            job?.timeoutHandle?.let { runCatching { it.cancel(false) } }
            if (active.remove(jobId) != null) runCatching { context.unbindService(this) }
            runCatching { libapp.parentFile?.deleteRecursively() }
            runCatching { output.delete() }
        }
    }

    private fun fail(jobId: String, code: String, message: String, stage: String, recoverable: Boolean, status: String = "failed") {
        store.update(jobId, status, stage, JSONObject().put("code", code).put("message", message).put("recoverable", recoverable).put("stage", stage))
    }

    private fun digest(libapp: File, libflutter: File, runnerSha256: String, options: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        listOf(libapp.readBytes(), libflutter.readBytes(), runnerSha256.toByteArray(), options.toByteArray()).forEach(digest::update)
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun fileJson(name: String, bytes: ByteArray): JSONObject = JSONObject().put("name", name).put("size", bytes.size).put("sha256", sha256(bytes))
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun validateEntities(items: org.json.JSONArray?, kind: String) {
        require(items != null) { "Missing items for $kind" }
        for (index in 0 until items.length()) {
            val item = items.optJSONObject(index) ?: error("Invalid entity in $kind")
            val expectedKind = mapOf("libraries" to "library", "classes" to "class", "functions" to "function", "objects" to "object")[kind] ?: error("Unsupported result kind")
            require(item.optString("kind") == expectedKind) { "Invalid entity kind in $kind" }
            require(item.optString("id").isNotBlank() && item.has("name")) { "Invalid entity fields in $kind" }
            if (item.has("address") && !item.isNull("address")) require(item.optString("address").matches(Regex("^0x[0-9a-fA-F]+$"))) { "Invalid entity address" }
        }
    }

    private data class ActiveJob(val connection: ServiceConnection, var runner: IBlutterRunner? = null, var timeoutHandle: ScheduledFuture<*>? = null)

    private companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 30L * 60L * 1000L
        const val MIN_TIMEOUT_MILLIS = 60L * 1000L
        const val MAX_TIMEOUT_MILLIS = 60L * 60L * 1000L
        const val CONNECT_TIMEOUT_MILLIS = 30L * 1000L
        const val MAX_RESULT_BYTES = 512L * 1024L * 1024L
    }
}
