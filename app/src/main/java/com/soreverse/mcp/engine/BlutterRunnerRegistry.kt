package com.soreverse.mcp.engine

import android.content.Context
import com.soreverse.mcp.core.ShellAssets
import org.json.JSONArray
import org.json.JSONObject

internal data class BlutterRunnerRequirement(
    val engineRevision: String?,
    val dartVersion: String?,
    val abi: String,
    val compressedPointers: Boolean,
    val analysis: Boolean,
    val snapshotHash: String? = null
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
    val engineRevisions: List<String> = emptyList(),
    val flutterVersions: List<String> = emptyList(),
    val snapshotHashes: Set<String> = emptySet()
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
        .put("engineRevisions", JSONArray(engineRevisions))
        .put("flutterVersions", JSONArray(flutterVersions))
        .put("snapshotHashes", JSONArray(snapshotHashes.toList().sorted()))
}

internal object BlutterRunnerMatcher {
    /**
     * Ranks candidates by how strong the compatibility evidence is:
     *
     *  4. snapshot hash — the key the Dart snapshot format is actually bound to.
     *     One snapshot hash is shared by several engine revisions (Flutter
     *     3.44.1–3.44.7 all hash to `ace65428…`), so this is the only key that
     *     survives an engine revision the manifest does not enumerate.
     *  3. engine revision, either the primary one or any entry of
     *     `engineRevisions` (the manifest lists five for the 3.44.x runner).
     *  1. Dart version, the loosest usable signal.
     *
     * A requirement that matches nothing returns null: the caller reports the
     * unsupported version rather than guessing a runner whose VM cannot
     * deserialize the snapshot.
     */
    fun select(requirement: BlutterRunnerRequirement, runners: List<BlutterRunnerDescriptor>): BlutterRunnerDescriptor? = runners
        .asSequence()
        .filter {
            it.abi == requirement.abi &&
                it.compressedPointers == requirement.compressedPointers &&
                (!requirement.analysis || it.analysis)
        }
        .mapNotNull { runner ->
            val score = score(requirement, runner)
            if (score == 0) null else score to runner
        }
        .sortedWith(
            compareByDescending<Pair<Int, BlutterRunnerDescriptor>> {
                it.first
            }.thenBy { it.second.runnerId }
        )
        .map { it.second }
        .firstOrNull()

    private fun score(requirement: BlutterRunnerRequirement, runner: BlutterRunnerDescriptor): Int = when {
        requirement.snapshotHash != null && requirement.snapshotHash in runner.snapshotHashes -> 4

        requirement.engineRevision != null &&
            (requirement.engineRevision == runner.engineRevision || requirement.engineRevision in runner.engineRevisions) -> 3

        requirement.dartVersion != null && runner.dartVersion == requirement.dartVersion -> 1

        else -> 0
    }
}

/**
 * Pure projection of `assets/blutter/runners.json` into descriptors.
 *
 * Split out of [BlutterRunnerRegistry] so the compatibility-key derivation can be
 * tested against a synthetic manifest without an Android `Context`.
 */
internal object BlutterRunnerManifest {
    /** Numeric-aware ordering so 3.44.10 sorts after 3.44.7. */
    val VERSION_ORDER: Comparator<String> = Comparator { left, right ->
        val leftParts = left.split('.', '-', '+')
        val rightParts = right.split('.', '-', '+')
        val size = maxOf(leftParts.size, rightParts.size)
        for (index in 0 until size) {
            val a = leftParts.getOrNull(index)?.toIntOrNull()
            val b = rightParts.getOrNull(index)?.toIntOrNull()
            if (a != null && b != null) {
                if (a != b) return@Comparator a.compareTo(b)
            } else {
                val result = leftParts.getOrNull(index).orEmpty().compareTo(rightParts.getOrNull(index).orEmpty())
                if (result != 0) return@Comparator result
            }
        }
        0
    }

    fun runners(manifest: JSONObject, source: String): List<BlutterRunnerDescriptor> {
        val array = manifest.optJSONArray("runners") ?: return emptyList()
        val coverageHashes = coverageSnapshotHashes(manifest)
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val id = item.optString("runnerId")
            val abi = item.optString("abi")
            val sha256 = item.optString("sha256")
            if (id.isBlank() ||
                abi.isBlank() ||
                !sha256.matches(Regex("[a-f0-9]{64}"))
            ) {
                return@mapNotNull null
            }
            val libraryName = item.optString("libraryName")
            if (!libraryName.matches(Regex("^blutter_[A-Za-z0-9_]+$"))) return@mapNotNull null
            val aliases = stringList(item.optJSONArray("snapshotAliases"))
            val engineRevisions = (
                stringList(item.optJSONArray("engineRevisions")) +
                    listOfNotNull(item.optString("engineRevision").takeIf { it.isNotBlank() })
                ).distinct()
            BlutterRunnerDescriptor(
                id,
                item.optString("dartVersion").takeIf {
                    it.isNotBlank()
                },
                item.optString("engineRevision").takeIf {
                    it.isNotBlank()
                },
                abi,
                item.optBoolean(
                    "compressedPointers"
                ),
                item.optBoolean(
                    "analysis",
                    true
                ),
                sha256, source, libraryName, manifest.optString("upstreamCommit"),
                item.optString("dartRevision").takeIf {
                    it.isNotBlank()
                },
                aliases,
                engineRevisions,
                stringList(item.optJSONArray("flutterVersions")),
                (aliases + engineRevisions.mapNotNull { coverageHashes[it] }).toSet()
            )
        }
    }

    /**
     * Engine revision -> snapshot hash, taken from the coverage table.
     *
     * The coverage table is the only place that records which snapshot hash a
     * given engine revision ships, and the runner entry itself only carries the
     * aliases its builder curated. Unioning both means a snapshot-compatible
     * engine revision is recognised even when nobody added it to the alias list.
     */
    fun coverageSnapshotHashes(manifest: JSONObject): Map<String, String> {
        val coverage = manifest.optJSONArray("coverage") ?: return emptyMap()
        val map = mutableMapOf<String, String>()
        for (index in 0 until coverage.length()) {
            val item = coverage.optJSONObject(index) ?: continue
            val engineRevision = item.optString("engineRevision").takeIf { it.isNotBlank() } ?: continue
            val snapshotHash = item.optString("snapshotHash").takeIf { it.isNotBlank() } ?: continue
            map.putIfAbsent(engineRevision, snapshotHash)
        }
        return map
    }

    /** Versions the given runners actually claim, for error messages. */
    fun supportedSummary(runners: List<BlutterRunnerDescriptor>): JSONObject = JSONObject()
        .put("flutterVersions", JSONArray(runners.flatMap { it.flutterVersions }.distinct().sortedWith(VERSION_ORDER)))
        .put("dartVersions", JSONArray(runners.mapNotNull { it.dartVersion }.distinct().sortedWith(VERSION_ORDER)))
        .put("abis", JSONArray(runners.map { it.abi }.distinct().sorted()))

    /**
     * Coverage rows that explain a rejected fingerprint, so the caller can say
     * *which* Flutter build to rebuild with instead of only "unsupported".
     */
    fun coverageHints(manifest: JSONObject, requirement: BlutterRunnerRequirement, limit: Int = 3): JSONArray {
        val coverage = manifest.optJSONArray("coverage") ?: return JSONArray()
        val hints = JSONArray()
        for (index in 0 until coverage.length()) {
            if (hints.length() >= limit) break
            val item = coverage.optJSONObject(index) ?: continue
            val engineRevision = item.optString("engineRevision")
            val snapshotHash = item.optString("snapshotHash")
            val dartVersion = item.optString("dartVersion")
            val matched = (requirement.engineRevision != null && engineRevision == requirement.engineRevision) ||
                (requirement.snapshotHash != null && snapshotHash == requirement.snapshotHash) ||
                (requirement.dartVersion != null && dartVersion == requirement.dartVersion)
            if (!matched) continue
            hints.put(
                JSONObject()
                    .put("flutterVersion", item.optString("flutterVersion"))
                    .put("dartVersion", dartVersion.ifBlank { null } ?: JSONObject.NULL)
                    .put("engineRevision", engineRevision.ifBlank { null } ?: JSONObject.NULL)
                    .put("snapshotHash", snapshotHash.ifBlank { null } ?: JSONObject.NULL)
                    .put("status", item.optString("status"))
                    .put("supported", item.optBoolean("supported", false))
                    .put("reason", item.optString("reason").ifBlank { null } ?: JSONObject.NULL)
            )
        }
        return hints
    }

    private fun stringList(array: JSONArray?): List<String> {
        if (array == null) return emptyList()
        return (0 until array.length()).mapNotNull { array.optString(it).takeIf { value -> value.isNotBlank() } }
    }
}

internal class BlutterRunnerRegistry(private val context: Context) {
    private val manifest by lazy { loadManifest() }
    val upstreamCommit: String get() = manifest.optString("upstreamCommit")
    val runners: List<BlutterRunnerDescriptor> by lazy {
        BlutterRunnerManifest.runners(manifest, "embedded")
    }

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
        .put("supportedVersions", supportedSummary())

    fun supportedSummary(): JSONObject = BlutterRunnerManifest.supportedSummary(runners)

    fun coverageHints(requirement: BlutterRunnerRequirement, limit: Int = 3): JSONArray = BlutterRunnerManifest.coverageHints(manifest, requirement, limit)

    private fun loadManifest(): JSONObject = JSONObject(ShellAssets.readText(context, "blutter/runners.json"))
}
