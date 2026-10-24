// SPDX-License-Identifier: AGPL-3.0-or-later
//
// JNI symbol mangling codec: Java_com_example_Foo_bar__sig <-> components.
// Encoding follows the JNI spec escaping ('_' -> _1, ';' -> _2, '[' -> _3,
// unicode -> _0xxxx). Because '_' is escaped inside names, a bare '_' is an
// unambiguous token separator, which is what makes decoding deterministic.
package com.soreverse.mcp.engine

import org.json.JSONObject

internal object JniMangle {
    private const val PREFIX = "Java_"

    private fun escape(component: String): String = buildString {
        component.forEach { c ->
            when {
                c == '_' -> append("_1")
                c == ';' -> append("_2")
                c == '[' -> append("_3")
                c.code in 0x20..0x7e -> append(c)
                else -> append("_0").append(String.format("%04x", c.code))
            }
        }
    }

    private fun mangleClass(clazz: String): String = clazz.split('.').joinToString("_") { escape(it) }

    private fun mangleSignature(sig: String): String = buildString {
        sig.forEach { c ->
            when {
                c == '/' -> append("_")
                c == '_' -> append("_1")
                c == ';' -> append("_2")
                c == '[' -> append("_3")
                c == '(' || c == ')' -> {}
                c.code in 0x20..0x7e -> append(c)
                else -> append("_0").append(String.format("%04x", c.code))
            }
        }
    }

    fun encode(clazz: String, method: String, signature: String?): String {
        val base = PREFIX + mangleClass(clazz.trim()) + "_" + escape(method.trim())
        val sig = signature?.trim().orEmpty()
        if (sig.isBlank() || sig == "()") return base
        // The long name encodes the argument descriptor only; the return type is dropped.
        val args = sig.substringAfter('(').substringBeforeLast(')')
        return "$base" + "__" + mangleSignature(args)
    }

    /** Splits [raw] on bare '_' and decodes _1/_2/_3/_0xxxx escapes in place. */
    private fun unescape(raw: String, signatureMode: Boolean): List<String> {
        val tokens = mutableListOf(StringBuilder())
        var current = tokens[0]
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c == '_' && i + 1 < raw.length) {
                when (raw[i + 1]) {
                    '1' -> {
                        current.append('_')
                        i += 2
                        continue
                    }
                    '2' -> {
                        current.append(';')
                        i += 2
                        continue
                    }
                    '3' -> {
                        current.append('[')
                        i += 2
                        continue
                    }
                    '0' -> {
                        if (i + 5 < raw.length) {
                            val code = raw.substring(i + 2, i + 6).toIntOrNull(16)
                            if (code != null) {
                                current.append(code.toChar())
                                i += 6
                                continue
                            }
                        }
                    }
                }
                if (signatureMode) {
                    current.append('/')
                } else {
                    tokens += StringBuilder()
                    current = tokens.last()
                }
                i++
                continue
            }
            current.append(c)
            i++
        }
        return tokens.map { it.toString() }
    }

    fun decode(symbol: String): JSONObject {
        val result = JSONObject()
        if (!symbol.startsWith(PREFIX)) {
            return result.put("valid", false).put("reason", "not a JNI symbol: missing Java_ prefix")
        }
        val body = symbol.removePrefix(PREFIX)
        val longSplit = body.indexOf("__")
        val prefix: String
        var signature: String? = null
        if (longSplit >= 0) {
            prefix = body.substring(0, longSplit)
            val sigTokens = unescape(body.substring(longSplit + 2), signatureMode = true)
            signature = "(${sigTokens.joinToString("")})"
        } else {
            prefix = body
        }
        val tokens = unescape(prefix, signatureMode = false)
        if (tokens.size < 2) {
            return result
                .put("valid", false)
                .put("reason", "symbol has no class/method split after Java_")
                .put("tokens", tokens.joinToString(","))
        }
        val className = tokens.dropLast(1).joinToString(".")
        val methodName = tokens.last()
        val dot = className.lastIndexOf('.')
        return result
            .put("valid", true)
            .put("className", className)
            .put("packageName", if (dot >= 0) className.substring(0, dot) else "")
            .put("simpleClassName", if (dot >= 0) className.substring(dot + 1) else className)
            .put("methodName", methodName)
            .put("signature", signature)
            .put("shortName", PREFIX + prefix)
            .put("longName", if (signature != null) symbol else JSONObject.NULL)
    }
}
