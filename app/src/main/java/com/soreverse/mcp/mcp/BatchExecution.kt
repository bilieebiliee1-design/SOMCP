package com.soreverse.mcp.mcp

import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.intValue
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject
import java.util.regex.Matcher
import java.util.regex.Pattern

internal object BatchTemplateResolver {
    private val keyPattern = Pattern.compile("\\$\\{([a-zA-Z0-9_]+)((?:\\.[^\\s\"\\}]+)*?)\\}")

    fun substitute(node: JSONObject, keyed: Map<String, JSONObject>): JSONObject {
        val out = JSONObject()
        for (key in node.keys()) out.put(key, substituteValue(node.get(key), keyed))
        return out
    }

    fun resolvePath(root: Any?, path: String): Any? {
        var current = root
        for (raw in path.split('.').filter { it.isNotEmpty() }) {
            if (current == null) return null
            current = when (current) {
                is JSONObject -> {
                    val bracket = raw.indexOf('[')
                    if (bracket < 0) {
                        val key = raw.replace("]", "")
                        if (current.has(key)) current.get(key) else null
                    } else {
                        val field = raw.substring(0, bracket)
                        val access = raw.substring(bracket)
                        val stepped = if (field.isBlank() || field == "]") current else if (current.has(field)) current.get(field) else null
                        stepArrayAccess(stepped, access)
                    }
                }
                is JSONArray -> stepArrayAccess(current, raw)
                else -> null
            }
        }
        return current
    }

    private fun substituteValue(value: Any?, keyed: Map<String, JSONObject>): Any? = when (value) {
        is String -> substituteString(value, keyed)
        is JSONObject -> substitute(value, keyed)
        is JSONArray -> JSONArray().also { out -> for (i in 0 until value.length()) out.put(substituteValue(value.get(i), keyed)) }
        else -> value
    }

    private fun substituteString(value: String, keyed: Map<String, JSONObject>): Any {
        if (!value.contains("\${")) return value
        var complex = false
        val output = StringBuffer(value.length + 16)
        val matcher = keyPattern.matcher(value)
        while (matcher.find()) {
            val key = matcher.group(1).orEmpty()
            val path = matcher.group(2).orEmpty()
            val resolved = keyed[key]?.let { resolvePath(it, path) }
            if (resolved == null) {
                matcher.appendReplacement(output, Matcher.quoteReplacement(matcher.group()))
                continue
            }
            if (resolved is JSONObject || resolved is JSONArray) complex = true
            matcher.appendReplacement(output, Matcher.quoteReplacement(resolved.toString()))
        }
        matcher.appendTail(output)
        return if (complex) parseJson(output.toString()) else output.toString()
    }

    private fun parseJson(value: String): Any = try {
        when {
            value.trim().startsWith("{") -> JSONObject(value.trim())
            value.trim().startsWith("[") -> JSONArray(value.trim())
            else -> value
        }
    } catch (_: Exception) {
        value
    }

    private fun stepArrayAccess(node: Any?, raw: String): Any? {
        var current = node
        var offset = 0
        while (offset < raw.length && current != null) {
            if (raw[offset] != '[') {
                offset++
                continue
            }
            val end = raw.indexOf(']', offset)
            if (end < 0) return null
            val indexText = raw.substring(offset + 1, end).trim()
            val index = indexText.toIntOrNull() ?: return null
            current = when (current) {
                is JSONArray -> if (index in 0 until current.length()) current.get(index) else null
                is JSONObject -> if (current.has(indexText)) current.get(indexText) else null
                else -> null
            }
            offset = end + 1
        }
        return current
    }
}

internal class BatchExecutor(
    private val executeTool: (String, JSONObject) -> JSONObject,
    private val ensureSnapshot: (JSONObject, MutableSet<String>) -> Unit,
    private val rollbackSnapshots: (Set<String>) -> JSONArray,
) {
    fun execute(args: JSONObject): JSONObject {
        val steps = args.optJSONArray("steps") ?: JSONArray()
        val stopOnError = if (args.has("stopOnError")) args.bool("stopOnError", true) else true
        val transactional = args.bool("transactional", false)
        val cap = args.intValue("maxSteps", 20).coerceIn(1, 50)
        if (steps.length() == 0) return err("BAD_REQUEST", "steps[] is required and must not be empty", "steps", JSONArray())
        if (steps.length() > cap) return err("TOO_MANY_STEPS", "Too many steps (got ${steps.length()}, max $cap). Split the pipeline or pass maxSteps (<=50).", "steps", steps.length())

        val results = JSONArray()
        val keyed = HashMap<String, JSONObject>()
        val snapshots = LinkedHashSet<String>()
        for (index in 0 until steps.length()) {
            val step = steps.optJSONObject(index) ?: continue
            val toolName = step.optString("tool")
            if (toolName.isBlank()) {
                results.put(JSONObject().put("step", index).put("ok", false).put("error", JSONObject().put("code", "BAD_REQUEST").put("message", "step.tool is required")))
                if (stopOnError) return ok(JSONObject().put("steps", results).put("executedCount", index).put("aborted", true))
                continue
            }
            val resolvedArgs = BatchTemplateResolver.substitute(step.optJSONObject("arguments") ?: JSONObject(), keyed)
            if (transactional) ensureSnapshot(resolvedArgs, snapshots)
            val resultKey = step.optString("resultKey", "").trim()
            val payload = try {
                executeTool(toolName, resolvedArgs)
            } catch (error: Exception) {
                JSONObject().put("ok", false).put("error", JSONObject().put("code", "STEP_EXCEPTION").put("message", error.message ?: error.javaClass.simpleName))
            }
            val succeeded = payload.optBoolean("ok", true)
            results.put(JSONObject().put("step", index).put("tool", toolName).put("resultKey", resultKey).put("arguments", resolvedArgs).put("ok", succeeded).put("result", payload))
            if (resultKey.matches(Regex("^[a-zA-Z0-9_]+$"))) keyed[resultKey] = payload
            if (!succeeded && stopOnError) {
                return ok(JSONObject()
                    .put("steps", results)
                    .put("executedCount", index + 1)
                    .put("aborted", true)
                    .put("transactional", transactional)
                    .put("rollback", if (transactional) rollbackSnapshots(snapshots) else JSONArray())
                    .put("hint", "stopOnError=true aborted the pipeline at the first failing step. Pass stopOnError=false to execute every step regardless."))
            }
        }
        return ok(JSONObject().put("steps", results).put("executedCount", results.length()).put("transactional", transactional).put("aborted", false))
    }
}
