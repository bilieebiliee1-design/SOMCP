package com.soreverse.mcp.mcp

import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.intValue
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import com.soreverse.mcp.engine.NativeSoEngine
import org.json.JSONArray
import org.json.JSONObject

internal object UnidbgBatchRunner {
    private val unidbgBatchKeyPattern = Regex("\\$\\{([a-zA-Z0-9_]+)([^}]*)\\}")
    private val unidbgBatchResultKeyPattern = Regex("^[a-zA-Z0-9_]+$")
    private val unidbgBatchIndexPattern = Regex("\\[(\\d+)\\]")

    fun run(engine: NativeSoEngine, args: JSONObject): JSONObject {
        val steps = args.optJSONArray("steps") ?: return err("BAD_REQUEST", "steps[] is required", "steps", JSONArray())
        val stopOnError = if (args.has("stopOnError")) args.bool("stopOnError", true) else true
        val maxSteps = args.intValue("maxSteps", 30).coerceIn(1, 100)
        if (steps.length() > maxSteps) return err("TOO_MANY_STEPS", "Too many Unidbg batch steps", "maxSteps", maxSteps)
        val keyed = HashMap<String, JSONObject>()
        val out = JSONArray()
        for (i in 0 until steps.length()) {
            val step = steps.optJSONObject(i) ?: JSONObject()
            val op = step.optString("op", "status")
            val method = substituteUnidbgBatchString(step.optString("method"), keyed)
            val stepWorkspaceId = substituteUnidbgBatchString(step.optString("workspaceId", args.str("workspaceId")), keyed)
            val stepEditSessionId = substituteUnidbgBatchString(step.optString("editSessionId", args.str("editSessionId")), keyed)
            val dispatchArgs = substituteUnidbgBatchValue(step.optJSONArray("args") ?: JSONArray(), keyed) as JSONArray
            val result = try {
                engine.unidbgDispatch(stepWorkspaceId, stepEditSessionId, op, method, dispatchArgs)
            } catch (ex: Exception) {
                JSONObject().put("ok", false).put("error", JSONObject().put("code", "STEP_EXCEPTION").put("message", ex.message ?: ex.javaClass.simpleName))
            }
            val okStep = result.optBoolean("ok", true)
            val resultKey = step.optString("resultKey").trim()
            val envelope = JSONObject()
                .put("step", i)
                .put("op", op)
                .put("method", method)
                .put("args", dispatchArgs)
                .put("resultKey", resultKey)
                .put("ok", okStep)
                .put("result", result)
            out.put(envelope)
            if (resultKey.matches(unidbgBatchResultKeyPattern)) keyed[resultKey] = result
            if (!okStep && stopOnError) return ok(JSONObject().put("steps", out).put("executedCount", i + 1).put("aborted", true))
        }
        return ok(JSONObject().put("steps", out).put("executedCount", out.length()).put("aborted", false))
    }

    private fun substituteUnidbgBatchValue(value: Any?, keyed: Map<String, JSONObject>): Any = when (value) {
        is JSONObject -> JSONObject().also { copy -> value.keys().forEach { key -> copy.put(key, substituteUnidbgBatchValue(value.opt(key), keyed)) } }
        is JSONArray -> JSONArray().also { copy -> for (i in 0 until value.length()) copy.put(substituteUnidbgBatchValue(value.opt(i), keyed)) }
        is String -> substituteUnidbgBatchString(value, keyed)
        null -> JSONObject.NULL
        else -> value
    }

    private fun substituteUnidbgBatchString(raw: String, keyed: Map<String, JSONObject>): String {
        if (raw.isEmpty()) return raw
        return unidbgBatchKeyPattern.replace(raw) { match ->
            val root = keyed[match.groupValues[1]] ?: return@replace match.value
            val path = match.groupValues[2].trimStart('.')
            val value = resolveUnidbgBatchPath(root, path)
            when (value) {
                null, JSONObject.NULL -> ""
                is JSONObject, is JSONArray -> value.toString()
                else -> value.toString()
            }
        }
    }

    private fun resolveUnidbgBatchPath(root: Any, path: String): Any? {
        if (path.isBlank()) return root
        var cur: Any? = root
        for (part in path.split('.').filter { it.isNotBlank() }) {
            val name = part.substringBefore('[')
            if (name.isNotBlank()) cur = (cur as? JSONObject)?.opt(name) ?: return null
            val indexes = unidbgBatchIndexPattern.findAll(part).mapNotNull { it.groupValues[1].toIntOrNull() }
            for (idx in indexes) cur = (cur as? JSONArray)?.opt(idx) ?: return null
        }
        return cur
    }
}
