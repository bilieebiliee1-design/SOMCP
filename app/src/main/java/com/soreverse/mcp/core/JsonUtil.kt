package com.soreverse.mcp.core

import org.json.JSONArray
import org.json.JSONObject

fun JSONObject.obj(name: String): JSONObject = optJSONObject(name) ?: JSONObject()
fun JSONObject.str(name: String, default: String = ""): String = optString(name, default)
fun JSONObject.intValue(name: String, default: Int = 0): Int = if (has(name)) optInt(name, default) else default
fun JSONObject.doubleValue(name: String, default: Double = 0.0): Double = if (has(name)) optDouble(name, default) else default
fun JSONObject.bool(name: String, default: Boolean = false): Boolean = if (has(name)) optBoolean(name, default) else default

fun Iterable<Any?>.toJsonArray(): JSONArray {
    val arr = JSONArray()
    forEach { arr.put(it) }
    return arr
}

fun ok(payload: JSONObject = JSONObject()): JSONObject {
    payload.put("ok", true)
    if (!payload.has("nextActions")) payload.put("nextActions", JSONArray())
    return payload
}

fun err(code: String, message: String, argument: String? = null, badValue: Any? = null): JSONObject {
    val error = JSONObject()
        .put("code", code)
        .put("message", message)
        .put("severity", "error")
        .put("recoverable", true)
        .put("retrySameArguments", false)
        .put("diagnostics", JSONObject())
    if (argument != null) error.put("argument", argument)
    if (badValue != null) error.put("badValue", badValue)
    return JSONObject().put("ok", false).put("error", error).put("nextActions", JSONArray())
}

fun err(code: String, message: String, argument: String?, badValue: Any?, vararg extra: Pair<String, Any?>): JSONObject {
    val result = err(code, message, argument, badValue)
    val diag = result.getJSONObject("error").getJSONObject("diagnostics")
    extra.forEach { (k, v) -> if (v != null) diag.put(k, v) }
    return result
}
