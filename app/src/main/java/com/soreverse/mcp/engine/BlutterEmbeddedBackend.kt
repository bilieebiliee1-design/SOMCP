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

internal class BlutterEmbeddedBackend(
    private val context: Context,
    private val store: BlutterResultStore,
) {
    private val active = ConcurrentHashMap<String, ActiveJob>()

    fun start(jobId: String, runner: BlutterRunnerDescriptor, libraries: FlutterLibraries, options: JSONObject) {
        val jobDir = File(context.noBackupFilesDir, "blutter/v1/jobs/$jobId/input").apply { mkdirs() }
        val libapp = File(jobDir, "libapp.so").apply { writeBytes(libraries.libapp) }
        val libflutter = File(jobDir, "libflutter.so").apply { writeBytes(libraries.libflutter) }
        val output = File(jobDir.parentFile, "runner-result.json").apply { if (exists()) delete() }
        val connection = RunnerConnection(jobId, runner, libraries, libapp, libflutter, output, options)
        active[jobId] = ActiveJob(connection)
        store.update(jobId, "running", "binding_runner")
        val intent = Intent(context, BlutterRunnerService::class.java)
        if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            active.remove(jobId)
            fail(jobId, "RUNNER_BIND_FAILED", "Cannot bind the isolated Blutter runner process", "binding_runner", true)
        }
    }

    fun cancel(jobId: String): Boolean {
        val job = active.remove(jobId) ?: return false
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
    ) : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val runner = IBlutterRunner.Stub.asInterface(binder)
            val job = active[jobId] ?: return
            job.runner = runner
            store.update(jobId, "running", "runner_execution")
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
                if (callbackJobId == jobId && active.containsKey(jobId)) store.update(jobId, "running", stage)
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
            store.update(jobId, "running", "committing")
            store.commit(jobId, result, key)
            finish()
        }

        private fun finishFailure(code: String, message: String, recoverable: Boolean, status: String = "failed") {
            fail(jobId, code, message, "runner_execution", recoverable, status)
            finish()
        }

        private fun finish() {
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

    private data class ActiveJob(val connection: ServiceConnection, var runner: IBlutterRunner? = null)

    private companion object {
        const val MAX_RESULT_BYTES = 512L * 1024L * 1024L
    }
}
