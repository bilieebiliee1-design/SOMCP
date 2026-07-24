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
)

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
) {
    fun toJson(): JSONObject = JSONObject()
        .put("runnerId", runnerId)
        .put("dartVersion", dartVersion ?: JSONObject.NULL)
        .put("engineRevision", engineRevision ?: JSONObject.NULL)
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
    fun select(requirement: BlutterRunnerRequirement, runners: List<BlutterRunnerDescriptor>): BlutterRunnerDescriptor? = runners
        .asSequence()
        .filter { it.abi == requirement.abi && it.compressedPointers == requirement.compressedPointers && (!requirement.analysis || it.analysis) }
        .mapNotNull { runner ->
            val score = when {
                requirement.engineRevision != null && runner.engineRevision == requirement.engineRevision -> 2
                requirement.dartVersion != null && runner.dartVersion == requirement.dartVersion -> 1
                else -> 0
            }
            runner.takeIf { score > 0 }?.let { score to it }
        }
        .sortedWith(compareByDescending<Pair<Int, BlutterRunnerDescriptor>> { it.first }.thenBy { it.second.runnerId })
        .map { it.second }
        .firstOrNull()
}

internal class BlutterRunnerRegistry(private val context: Context) {
    private val manifest by lazy { loadManifest() }
    val upstreamCommit: String get() = manifest.optString("upstreamCommit")
    val runners: List<BlutterRunnerDescriptor> by lazy { parseRunners(manifest.optJSONArray("runners"), "embedded") }

    fun select(requirement: BlutterRunnerRequirement): BlutterRunnerDescriptor? = BlutterRunnerMatcher.select(requirement, runners)

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
            BlutterRunnerDescriptor(id, item.optString("dartVersion").takeIf { it.isNotBlank() }, item.optString("engineRevision").takeIf { it.isNotBlank() }, abi, item.optBoolean("compressedPointers"), item.optBoolean("analysis", true), sha256, source, libraryName, manifest.optString("upstreamCommit"), item.optString("dartRevision").takeIf { it.isNotBlank() }, aliases)
        }
    }
}
