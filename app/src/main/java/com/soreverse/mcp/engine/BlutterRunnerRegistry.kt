package com.soreverse.mcp.engine

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

internal data class BlutterRunnerRequirement(
    val engineRevision: String?,
    val dartVersion: String?,
    val abi: String,
    val compressedPointers: Boolean,
    val analysis: Boolean,
    val engineRevisions: List<String> = emptyList(),
    val snapshotHash: String? = null,
)

/**
 * How confidently a [BlutterRunnerDescriptor] satisfies a [BlutterRunnerRequirement].
 * - EXACT: engine revision or Dart version matches (or an alias in the runner's engine revision list).
 * - SNAPSHOT_ALIAS: the target snapshot hash matches the runner's snapshot format, but the exact
 *   engine/dart version string did not (a safe multi-version fallback within the same snapshot format).
 * - APPROXIMATE: no fingerprint matched; the runner shares the ABI/pointer profile only. Results from
 *   an APPROXIMATE match may be incomplete or inaccurate and must be flagged to the caller.
 */
internal enum class RunnerCompatibility { EXACT, SNAPSHOT_ALIAS, APPROXIMATE }

internal data class RunnerMatch(val descriptor: BlutterRunnerDescriptor, val compatibility: RunnerCompatibility, val score: Int)

internal data class BlutterRunnerDescriptor(
    val runnerId: String,
    val dartVersion: String?,
    val engineRevision: String?,
    val abi: String,
    val compressedPointers: Boolean,
    val analysis: Boolean,
    val sha256: String,
    val source: String,
    val libraryName: String,
    val upstreamCommit: String = "",
    val dartRevision: String? = null,
    val snapshotAliases: List<String> = emptyList(),
    val engineRevisions: List<String> = emptyList(),
    val snapshotHash: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("runnerId", runnerId)
        .put("dartVersion", dartVersion ?: JSONObject.NULL)
        .put("engineRevision", engineRevision ?: JSONObject.NULL)
        .put("engineRevisions", JSONArray(engineRevisions))
        .put("snapshotHash", snapshotHash ?: JSONObject.NULL)
        .put("abi", abi)
        .put("compressedPointers", compressedPointers)
        .put("analysis", analysis)
        .put("sha256", sha256)
        .put("source", source)
        .put("libraryName", libraryName)
        .put("upstreamCommit", upstreamCommit)
        .put("dartRevision", dartRevision ?: JSONObject.NULL)
        .put("snapshotAliases", JSONArray(snapshotAliases))
}

internal object BlutterRunnerMatcher {
    /**
     * Selects the best runner for [requirement].
     *
     * Matching is layered so a single embedded runner can serve many Dart/Flutter releases:
     *   1. exact engine revision (single field)        -> score 4 (EXACT)
     *   2. any engine revision in the runner's list     -> score 3 (EXACT)
     *   3. exact Dart version                           -> score 2 (EXACT)
     *   4. snapshot hash / alias match                  -> score 1 (SNAPSHOT_ALIAS)
     *
     * When [allowApproximate] is true and no layered match exists, the first runner with the same
     * ABI/pointer/analysis profile is returned as [RunnerCompatibility.APPROXIMATE].
     */
    fun match(requirement: BlutterRunnerRequirement, runners: List<BlutterRunnerDescriptor>, allowApproximate: Boolean = false): RunnerMatch? {
        val strict = runners.asSequence()
            .filter { it.abi == requirement.abi && it.compressedPointers == requirement.compressedPointers && (!requirement.analysis || it.analysis) }
            .mapNotNull { runner ->
                val score = when {
                    requirement.engineRevision != null && runner.engineRevision == requirement.engineRevision -> 4
                    (requirement.engineRevisions.isNotEmpty() && runner.engineRevisions.any { it in requirement.engineRevisions }) ||
                        (requirement.engineRevision != null && runner.engineRevisions.contains(requirement.engineRevision)) -> 3
                    requirement.dartVersion != null && runner.dartVersion == requirement.dartVersion -> 2
                    requirement.snapshotHash != null && (runner.snapshotHash == requirement.snapshotHash || runner.snapshotAliases.contains(requirement.snapshotHash)) -> 1
                    else -> 0
                }
                if (score == 0) null else RunnerMatch(runner, if (score == 1) RunnerCompatibility.SNAPSHOT_ALIAS else RunnerCompatibility.EXACT, score)
            }
            .sortedWith(compareByDescending<RunnerMatch> { it.score }.thenBy { it.descriptor.runnerId })
            .firstOrNull()
        if (strict != null) return strict
        if (!allowApproximate) return null
        return runners.firstOrNull { it.abi == requirement.abi && it.compressedPointers == requirement.compressedPointers && (!requirement.analysis || it.analysis) }
            ?.let { RunnerMatch(it, RunnerCompatibility.APPROXIMATE, 0) }
    }

    fun select(requirement: BlutterRunnerRequirement, runners: List<BlutterRunnerDescriptor>): BlutterRunnerDescriptor? = match(requirement, runners)?.descriptor
}

internal class BlutterRunnerRegistry(private val context: Context) {
    private val manifest by lazy { loadManifest() }
    val upstreamCommit: String get() = manifest.optString("upstreamCommit")
    val runners: List<BlutterRunnerDescriptor> by lazy { parseRunners(manifest.optJSONArray("runners"), "embedded") }

    fun select(requirement: BlutterRunnerRequirement): BlutterRunnerDescriptor? = BlutterRunnerMatcher.match(requirement, runners)?.descriptor
    fun match(requirement: BlutterRunnerRequirement, allowApproximate: Boolean = false): RunnerMatch? = BlutterRunnerMatcher.match(requirement, runners, allowApproximate)

    fun capabilities(): JSONObject = JSONObject()
        .put("schemaVersion", manifest.optInt("schemaVersion", 2))
        .put("matrixVersion", manifest.optString("matrixVersion"))
        .put("protocolVersion", manifest.optInt("protocolVersion", 1))
        .put("upstreamCommit", upstreamCommit)
        .put("embedded", JSONArray(runners.map { it.toJson() }))
        .put("coverage", manifest.optJSONArray("coverage") ?: JSONArray())
        .put("execution", "all_in_one_apk")
        .put("fullyOffline", true)
        .put("runnerCount", runners.size)

    private fun loadManifest(): JSONObject = context.assets.open("blutter/runners.json").bufferedReader().use { JSONObject(it.readText()) }

    private fun parseRunners(array: JSONArray?, source: String): List<BlutterRunnerDescriptor> {
        if (array == null) return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val id = item.optString("runnerId")
            val abi = item.optString("abi")
            val sha256 = item.optString("sha256")
            if (id.isBlank() || abi.isBlank() || !sha256.matches(Regex("[a-f0-9]{64}"))) return@mapNotNull null
            val libraryName = item.optString("libraryName")
            if (!libraryName.matches(Regex("^blutter_[A-Za-z0-9_]+$"))) return@mapNotNull null
            val aliases = item.optJSONArray("snapshotAliases")?.let { array -> (0 until array.length()).mapNotNull(array::optString) } ?: emptyList()
            val engineRevisions = item.optJSONArray("engineRevisions")?.let { array -> (0 until array.length()).mapNotNull(array::optString).filter { it.isNotBlank() } } ?: emptyList()
            val snapshotHash = item.optString("snapshotHash").takeIf { it.isNotBlank() }
            BlutterRunnerDescriptor(
                runnerId = id,
                dartVersion = item.optString("dartVersion").takeIf { it.isNotBlank() },
                engineRevision = item.optString("engineRevision").takeIf { it.isNotBlank() },
                abi = abi,
                compressedPointers = item.optBoolean("compressedPointers"),
                analysis = item.optBoolean("analysis", true),
                sha256 = sha256,
                source = source,
                libraryName = libraryName,
                upstreamCommit = manifest.optString("upstreamCommit"),
                dartRevision = item.optString("dartRevision").takeIf { it.isNotBlank() },
                snapshotAliases = aliases,
                engineRevisions = engineRevisions,
                snapshotHash = snapshotHash,
            )
        }
    }
}
