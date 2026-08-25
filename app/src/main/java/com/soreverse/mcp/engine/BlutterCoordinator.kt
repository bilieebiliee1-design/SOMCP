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
package com.soreverse.mcp.engine

import android.content.Context
import com.soreverse.mcp.core.InsufficientMemoryException
import com.soreverse.mcp.core.MemoryGuard
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

internal class BlutterCoordinator(
    private val context: Context,
    private val store: BlutterResultStore = BlutterResultStore(context),
    private val registry: BlutterRunnerRegistry = BlutterRunnerRegistry(context)
) {
    private val embedded = BlutterEmbeddedBackend(context, store)
    fun handle(args: JSONObject, workDirectory: WorkDirectory? = null): JSONObject = when (args.str("action", "inspect")) {
        "inspect" -> inspect(args, workDirectory)

        "analyze" -> analyze(args, workDirectory)

        "status" -> status(args.str("jobId"))

        "result" -> result(
            args.str("jobId"),
            args.optString("kind").takeIf {
                it.isNotBlank()
            },
            args.optString("cursor").takeIf { it.isNotBlank() },
            args.optInt("limit", 1000)
        )

        "cancel" -> cancel(args.str("jobId"))

        "packages" -> ok(registry.capabilities())

        "prune" -> ok(store.prune(args.optLong("olderThanMillis", 7L * 24 * 60 * 60 * 1000)))

        else -> err(
            "UNKNOWN_ACTION",
            "Unsupported flutter_blutter action",
            "action",
            args.str("action")
        )
    }

    private fun inspect(args: JSONObject, workDirectory: WorkDirectory?): JSONObject {
        val path = args.str("path")
        if (path.isBlank()) {
            return err(
                "INPUT_REQUIRED",
                "path is required for inspect",
                "path",
                path
            )
        }
        val file = File(path)
        return try {
            if (file.isDirectory) {
                inspectDirectory(file, path, args.str("abi", "auto"))
            } else if (file.isFile) {
                MemoryGuard.ensureAnalysisMemory(
                    file.length(),
                    "Inspecting Flutter APK ${file.name}"
                )
                val bytes = file.readBytes()
                if (!file.extension.equals(
                        "apk",
                        true
                    )
                ) {
                    return err(
                        "UNSUPPORTED_INPUT",
                        "inspect currently accepts an APK or a libapp/libflutter directory",
                        "path",
                        path
                    )
                }
                val inventory = FlutterArtifactInspector.inspectApk(
                    bytes,
                    path,
                    args.str("abi", "auto")
                )
                val selected = inventory.optJSONObject("selected")
                if (selected == null) {
                    ok(inventory)
                } else {
                    val detailed = FlutterArtifactInspector.inspectLibraries(
                        FlutterArtifactInspector.extractLibraries(
                            bytes,
                            path,
                            args.str("abi", "auto")
                        )
                    )
                    ok(inventory.put("selectedAnalysis", detailed))
                }
            } else if (workDirectory != null) {
                MemoryGuard.ensureAnalysisMemory(
                    workDirectory.fileSize(path) ?: ApkAnalyzer.MAX_INPUT_BYTES,
                    "Inspecting Flutter APK $path"
                )
                val bytes = workDirectory.readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
                val inventory = FlutterArtifactInspector.inspectApk(
                    bytes,
                    path,
                    args.str("abi", "auto")
                )
                val selected = inventory.optJSONObject("selected")
                if (selected ==
                    null
                ) {
                    ok(inventory)
                } else {
                    ok(
                        inventory.put(
                            "selectedAnalysis",
                            FlutterArtifactInspector.inspectLibraries(
                                FlutterArtifactInspector.extractLibraries(
                                    bytes,
                                    path,
                                    args.str("abi", "auto")
                                )
                            )
                        )
                    )
                }
            } else {
                err(
                    "INPUT_NOT_FOUND",
                    "Input path does not exist and no work directory is selected",
                    "path",
                    path
                )
            }
        } catch (error: InsufficientMemoryException) {
            err(
                "INSUFFICIENT_MEMORY",
                error.message ?: "Insufficient memory to inspect Flutter artifacts",
                "path",
                path
            )
        } catch (error: Exception) {
            err(
                error.message?.substringBefore(':')?.takeIf {
                    it in
                        setOf("INPUT_LIMIT_EXCEEDED", "APK_INVALID", "UNSUPPORTED_ELF")
                }
                    ?: "FLUTTER_INSPECT_FAILED",
                error.message ?: "Flutter inspection failed",
                "path",
                path
            )
        }
    }

    private fun analyze(args: JSONObject, workDirectory: WorkDirectory?): JSONObject {
        val jobId = store.create(args)
        val resolved = runCatching {
            val libs = resolveLibraries(args, workDirectory)
            libs to FlutterArtifactInspector.inspectLibraries(libs)
        }
        if (resolved.isFailure) {
            val failure = resolved.exceptionOrNull()
            val problem = JSONObject()
                .put(
                    "code",
                    if (failure is InsufficientMemoryException) {
                        "INSUFFICIENT_MEMORY"
                    } else {
                        "INPUT_RESOLUTION_FAILED"
                    }
                )
                .put(
                    "message",
                    failure?.message ?: "Cannot resolve Flutter libraries"
                )
                .put("recoverable", false)
                .put("stage", "resolving_input")
            store.update(jobId, "failed", "resolving_input", problem)
            return ok(JSONObject().put("jobId", jobId).put("status", "failed").put("error", problem))
        }
        val (libraries, analysis) = resolved.getOrThrow()
        val flutter = analysis.optJSONObject("flutter") ?: JSONObject()
        val requirement = BlutterRunnerRequirement(
            engineRevision = flutter.optJSONArray("engineIds")?.optString(0)?.takeIf {
                it.isNotBlank()
            },
            dartVersion = flutter.optString("dartVersion").takeIf { it.isNotBlank() },
            abi = analysis.optString("abi", args.str("abi", "arm64-v8a")),
            compressedPointers = flutter.optBoolean("compressedPointers", false),
            analysis = !args.optBoolean("noAnalysis", false)
        )
        val runner = registry.select(requirement)
        if (runner == null) {
            val required = JSONObject().put(
                "engineRevision",
                requirement.engineRevision ?: JSONObject.NULL
            ).put(
                "dartVersion",
                requirement.dartVersion ?: JSONObject.NULL
            ).put(
                "abi",
                requirement.abi
            ).put(
                "compressedPointers",
                requirement.compressedPointers
            ).put("analysis", requirement.analysis)
            val error = JSONObject().put(
                "code",
                "FLUTTER_VERSION_NOT_SUPPORTED"
            ).put(
                "message",
                "This release embeds only the Flutter 3.44.x / Dart 3.12.2 arm64-v8a Blutter runner. The target APK does not match that exact snapshot compatibility key."
            ).put(
                "recoverable",
                false
            ).put(
                "stage",
                "runner_selection"
            ).put("supportedFlutter", "3.44.x").put("supportedDart", "3.12.2").put("required", required)
            store.update(jobId, "failed", "runner_selection", error)
            return ok(
                JSONObject().put(
                    "jobId",
                    jobId
                ).put(
                    "status",
                    "failed"
                ).put(
                    "inspection",
                    analysis
                ).put(
                    "requiredRunner",
                    required
                ).put(
                    "error",
                    error
                ).put(
                    "nextActions",
                    JSONArray().put(
                        "use a Flutter 3.44.x APK built with Dart 3.12.2"
                    ).put("inspect the APK fingerprint without running analysis")
                )
            )
        }
        val key = embedded.cacheKey(libraries.libapp, libraries.libflutter, runner.sha256, args.toString())
        store.lookup(key)?.let { cached ->
            store.update(jobId, "running", "cache_lookup")
            store.commit(jobId, cached, key)
            return ok(
                JSONObject().put("jobId", jobId).put("status", "succeeded").put("backend", "cache")
                    .put("cacheHit", true).put("runner", runner.toJson())
                    .put("message", "Reused identical previous analysis result (cache hit)")
            )
        }
        val startResult = runCatching { embedded.start(jobId, runner, libraries, args) }
        if (startResult.isFailure) {
            val problem = JSONObject().put("code", "RUNNER_START_FAILED").put(
                "message",
                startResult.exceptionOrNull()?.message ?: "Cannot start Blutter runner"
            ).put("recoverable", false).put("stage", "runner_execution")
            store.update(jobId, "failed", "runner_execution", problem)
            return ok(JSONObject().put("jobId", jobId).put("status", "failed").put("error", problem))
        }
        return ok(
            JSONObject().put(
                "jobId",
                jobId
            ).put(
                "status",
                "running"
            ).put("backend", "embedded").put("runner", runner.toJson())
        )
    }

    private fun status(jobId: String): JSONObject = store.get(jobId)?.let { ok(it) }
        ?: err("JOB_NOT_FOUND", "Blutter job was not found", "jobId", jobId)
    private fun result(jobId: String, kind: String?, cursor: String?, limit: Int): JSONObject = runCatching {
        store.result(jobId, kind, cursor, limit)?.let { ok(it) }
            ?: err("RESULT_NOT_FOUND", "Blutter result is not available", "jobId", jobId)
    }.getOrElse {
        err(
            "INVALID_RESULT_REQUEST",
            it.message ?: "Invalid result request",
            "jobId",
            jobId
        )
    }
    private fun cancel(jobId: String): JSONObject {
        embedded.cancel(jobId)
        return if (store.cancel(
                jobId
            )
        ) {
            ok(
                JSONObject().put("jobId", jobId).put("status", "cancelled")
            )
        } else {
            err(
                "JOB_NOT_CANCELLABLE",
                "Job was not found or already finished",
                "jobId",
                jobId
            )
        }
    }

    private fun resolveLibraries(args: JSONObject, workDirectory: WorkDirectory?): FlutterLibraries {
        val path = args.str("path")
        val file = File(path)
        if (file.isDirectory) {
            val app =
                file.resolve("libapp.so").takeIf { it.isFile }
                    ?: file.resolve("App").takeIf { it.isFile }
                    ?: error("FLUTTER_LIBS_NOT_FOUND")
            val flutter =
                file.resolve("libflutter.so").takeIf { it.isFile }
                    ?: file.resolve("Flutter").takeIf { it.isFile }
                    ?: error("FLUTTER_LIBS_NOT_FOUND")
            MemoryGuard.ensureAnalysisMemory(
                app.length() + flutter.length(),
                "Analyzing Flutter libraries in ${file.name}"
            )
            return FlutterLibraries(
                file.name,
                "arm64-v8a",
                app.readBytes(),
                flutter.readBytes(),
                app.name,
                flutter.name
            )
        }
        val bytes = if (file.isFile) {
            MemoryGuard.ensureAnalysisMemory(
                file.length(),
                "Analyzing Flutter APK ${file.name}"
            )
            file.readBytes()
        } else {
            val dir = workDirectory ?: error("INPUT_NOT_FOUND")
            MemoryGuard.ensureAnalysisMemory(
                dir.fileSize(path) ?: ApkAnalyzer.MAX_INPUT_BYTES,
                "Analyzing Flutter APK $path"
            )
            dir.readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
        }
        return FlutterArtifactInspector.extractLibraries(bytes, path, args.str("abi", "arm64-v8a"))
    }

    private fun inspectDirectory(dir: File, path: String, requestedAbi: String): JSONObject {
        val app =
            dir.resolve("libapp.so").takeIf { it.isFile } ?: dir.resolve("App").takeIf { it.isFile }
        val flutter =
            dir.resolve("libflutter.so").takeIf { it.isFile }
                ?: dir.resolve("Flutter").takeIf { it.isFile }
        if (app == null ||
            flutter == null
        ) {
            return err(
                "FLUTTER_LIBS_NOT_FOUND",
                "Directory must contain libapp.so and libflutter.so",
                "path",
                path
            )
        }
        val abi = if (requestedAbi == "auto") "arm64-v8a" else requestedAbi
        MemoryGuard.ensureAnalysisMemory(
            app.length() + flutter.length(),
            "Inspecting Flutter libraries in ${dir.name}"
        )
        return ok(
            FlutterArtifactInspector.inspectLibraries(
                FlutterLibraries(
                    dir.name,
                    abi,
                    app.readBytes(),
                    flutter.readBytes(),
                    app.name,
                    flutter.name
                )
            )
        )
    }
}
