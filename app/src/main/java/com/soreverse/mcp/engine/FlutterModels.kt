package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal data class FlutterFingerprint(
    val dartVersion: String?,
    val snapshotHash: String?,
    val flags: List<String>,
    val engineIds: List<String>,
    val architecture: String?,
    val os: String?,
    val compressedPointers: Boolean?,
    val confidence: Double,
    val evidence: List<String>,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("dartVersion", dartVersion ?: JSONObject.NULL)
        .put("snapshotHash", snapshotHash ?: JSONObject.NULL)
        .put("flags", JSONArray(flags))
        .put("engineIds", JSONArray(engineIds))
        .put("architecture", architecture ?: JSONObject.NULL)
        .put("os", os ?: JSONObject.NULL)
        .put("compressedPointers", compressedPointers ?: JSONObject.NULL)
        .put("confidence", confidence)
        .put("evidence", JSONArray(evidence))

    companion object {
        fun unknown(): FlutterFingerprint = FlutterFingerprint(null, null, emptyList(), emptyList(), null, null, null, 0.0, emptyList())
    }
}

internal data class FlutterLibraries(
    val displayName: String,
    val abi: String,
    val libapp: ByteArray,
    val libflutter: ByteArray,
    val libappEntry: String,
    val libflutterEntry: String,
)
