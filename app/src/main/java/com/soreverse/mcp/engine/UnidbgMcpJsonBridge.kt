/*
SPDX-License-Identifier: AGPL-3.0-or-later

Copyright (C) 2026 bilieebiliee1-design

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
package com.soreverse.mcp.engine

import java.lang.reflect.Proxy

/**
 * Adapts the `org.json` values we already use to the `com.alibaba.fastjson`
 * types that `com.github.unidbg.mcp.McpTools#dispatchTool(String, JSONObject)`
 * insists on in its bytecode.
 *
 * Why a proxy instead of the fastjson artifact. unidbg 0.9.9's patched jar names
 * fastjson's classes, but the surface it actually uses is small and verified
 * against the class files:
 *   - `McpTools#dispatchTool(String, JSONObject)` calls `getString`, `getIntValue`,
 *     `getLongValue`, `getBooleanValue`, `getBoolean`, `containsKey`, `getJSONObject`,
 *     `getJSONArray` and `remove` on its argument; `parseCallArg` also tolerates a
 *     null argument.
 *   - `McpTools#textResult/errorResult` build their result with `new JSONObject()`
 *     and `put`, and `pollEvents` / the custom-tool path call `toJSONString()` and
 *     `toString()` on values it either owns or gets back from a tool.
 * Because `com.alibaba.fastjson.JSONObject` is a `java.util.Map`, a Map proxy is
 * assignable to the parameter, so `dispatchTool` never needs the real class.
 *
 * Two things the artifact cannot simply do instead:
 *   - upgrading to 1.2.84 is not viable: that release drops
 *     `JSONObject#toJSONString()` while unidbg calls it (see `pollEvents`);
 *   - fastjson2 only ships `com.alibaba.fastjson2.*`, so it would not resolve
 *     unidbg's `com/alibaba/fastjson` references either.
 *
 * Keeping fastjson off the classpath removes the whole autoType / deserialization
 * surface (CVE-2026-16723, CWE-502) while leaving `dispatchTool`'s contract intact.
 */
internal object UnidbgMcpJsonBridge {

    /** Renders `textResult(...)` / `errorResult(...)` payloads as fastjson-compatible JSON text. */
    fun toFastJsonText(payload: Any?): String = when (payload) {
        null -> "null"
        is Map<*, *> -> toJson(payload)
        is Collection<*> -> toJson(payload)
        is Array<*> -> toJson(payload.toList())
        is Number, is Boolean -> payload.toString()
        else -> payload.toString()
    }

    /**
     * A value that answers the `JSONObject` messages unidbg sends to a tool result:
     * `toJSONString()`, `toString()`, and the accessors used by the event and
     * custom-tool paths. Unknown messages return their type's default rather than
     * throwing, so a future unidbg build cannot turn a read into a crash.
     */
    fun resultView(payload: Any?): Any {
        val text = toFastJsonText(payload)
        return Proxy.newProxyInstance(
            UnidbgMcpJsonBridge::class.java.classLoader,
            arrayOf(McpJsonShim::class.java,
                Class.forName("com.alibaba.fastjson.JSONObject"))
        ) { _, method, args ->
            when (method.name) {
                "toJSONString", "toString", "toJsonString" -> text
                "getString" -> lookup(payload, args?.firstOrNull() as? String)?.toString()
                "getJSONObject", "getJsonObject" -> lookup(payload, args?.firstOrNull() as? String)
                    ?.let { if (it is Map<*, *>) resultView(it) else null }
                "getJSONArray", "getJsonArray" -> lookup(payload, args?.firstOrNull() as? String)
                    ?.let { if (it is Collection<*>) it.toList() else null }
                "get" -> lookup(payload, args?.firstOrNull())
                "isEmpty" -> (payload as? Map<*, *>)?.isEmpty() ?: (payload as? Collection<*>)?.isEmpty() ?: true
                "size" -> (payload as? Map<*, *>)?.size ?: (payload as? Collection<*>)?.size ?: 0
                "hashCode" -> text.hashCode()
                "equals" -> args?.firstOrNull()?.toString() == text
                "isError" -> payload is Map<*, *> && payload.containsKey("error")
                else -> defaultValue(method.returnType)
            }
        }
    }

    /**
     * The value handed to `dispatchTool`. `McpTools` calls `getString` / `getIntValue` /
     * `getLongValue` / `getBooleanValue` / `containsKey` / `getJSONArray` on it, so a bare
     * `Map` is not enough; this proxy answers both those and the `Map` messages.
     */
    fun argView(json: org.json.JSONObject): Any {
        val map = toArgMap(json)
        return java.lang.reflect.Proxy.newProxyInstance(
            UnidbgMcpJsonBridge::class.java.classLoader,
            arrayOf(Map::class.java),
            { _, method, args ->
                val key = args?.firstOrNull()
                when (method.name) {
                    "getString" -> map[key]?.toString()
                    "getJSONObject", "getJSONArray" -> map[key]
                    "getIntValue" -> (map[key] as? Number)?.toInt() ?: 0
                    "getLongValue" -> (map[key] as? Number)?.toLong() ?: 0L
                    "getBooleanValue" -> map[key] as? Boolean ?: false
                    "getBoolean" -> map[key] as? Boolean
                    "containsKey" -> map.containsKey(key)
                    "toJSONString", "toString" -> toFastJsonText(map)
                    "equals" -> map == args?.firstOrNull()
                    "isEmpty" -> map.isEmpty()
                    "size" -> map.size
                    "hashCode" -> map.hashCode()
                    else -> defaultValue(method.returnType)
                }
            }
        )
    }

    /**
     * Builds the plain map behind [argView]: fastjson's `JSONObject(Map)` semantics
     * (nulls kept, nested maps/lists unwrapped), no type resolution, so nothing in it
     * can ever be deserialized into an attacker-chosen class.
     */
    fun toArgMap(json: org.json.JSONObject): Map<String, Any?> {
        val result = LinkedHashMap<String, Any?>()
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            result[key] = toPlain(json.opt(key))
        }
        return result
    }

    private fun toPlain(value: Any?): Any? = when (value) {
        null, org.json.JSONObject.NULL -> null
        is org.json.JSONObject -> toArgMap(value)
        is org.json.JSONArray -> (0 until value.length()).map { toPlain(value.opt(it)) }
        else -> value
    }

    private fun lookup(container: Any?, key: Any?): Any? = when (container) {
        is Map<*, *> -> container[key]
        is List<*> -> (key as? Number)?.toInt()?.let { container.getOrNull(it) }
        is Array<*> -> (key as? Number)?.toInt()?.let { container.getOrNull(it) }
        else -> null
    }

    private fun defaultValue(type: Class<*>): Any? = when (type) {
        java.lang.Boolean.TYPE -> false
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Float.TYPE -> 0f
        java.lang.Double.TYPE -> 0.0
        java.lang.Character.TYPE -> '\u0000'
        else -> null
    }

    private fun toJson(value: Any?): String = buildString { write(value) }

    private fun StringBuilder.write(value: Any?) {
        when (value) {
            null -> append("null")
            is String, is Char -> append(quote(value.toString()))
            is Number, is Boolean -> append(value.toString())
            is Map<*, *> -> {
                append('{')
                var first = true
                value.forEach { (k, v) ->
                    if (!first) append(',')
                    first = false
                    append(quote(k?.toString() ?: "null"))
                    append(':')
                    write(v)
                }
                append('}')
            }
            is Iterable<*> -> {
                append('[')
                var first = true
                value.forEach {
                    if (!first) append(',')
                    first = false
                    write(it)
                }
                append(']')
            }
            is Array<*> -> write(value.toList())
            else -> append(quote(value.toString()))
        }
    }

    private fun quote(text: String): String {
        val sb = StringBuilder(text.length + 2)
        sb.append('"')
        text.forEach { c ->
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c < ' ' -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }
}

/**
 * The `JSONObject` messages unidbg's MCP tools send to a tool result. Declaring them
 * here keeps the proxy's interface list explicit and self-documenting; the proxy itself
 * returns `null` for anything it does not handle.
 */
internal interface McpJsonShim {
    fun toJSONString(): String
    fun getString(key: String?): String?
    fun getJSONObject(key: String?): Any?
    fun getJSONArray(key: String?): List<Any?>?
    fun get(key: Any?): Any?
    fun getIntValue(key: String?): Int
    fun getLongValue(key: String?): Long
    fun getBooleanValue(key: String?): Boolean
    fun getBoolean(key: String?): Boolean?
    fun containsKey(key: Any?): Boolean
    fun isEmpty(): Boolean
    fun size(): Int
}
