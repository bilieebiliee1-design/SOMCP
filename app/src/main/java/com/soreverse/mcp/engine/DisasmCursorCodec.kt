package com.soreverse.mcp.engine

import java.util.Base64

internal object DisasmCursorCodec {
    fun encode(workspaceId: String, editSessionId: String, locator: String, byteOffset: Int, limit: Int, maxBytes: Int): String =
        listOf(
            encodePart(workspaceId),
            encodePart(editSessionId),
            encodePart(locator),
            byteOffset.toString(),
            limit.coerceIn(1, 5000).toString(),
            maxBytes.coerceIn(256, 65536).toString(),
        ).joinToString(":", prefix = "disasm:")

    fun decode(cursor: String): DisasmCursorState? {
        if (!cursor.startsWith("disasm:")) return null
        val parts = cursor.removePrefix("disasm:").split(':')
        if (parts.size != 6) return null
        return runCatching {
            DisasmCursorState(
                workspaceId = decodePart(parts[0]),
                editSessionId = decodePart(parts[1]),
                locator = decodePart(parts[2]),
                byteOffset = parts[3].toInt().coerceAtLeast(0),
                limit = parts[4].toInt().coerceIn(1, 5000),
                maxBytes = parts[5].toInt().coerceIn(256, 65536),
            )
        }.getOrNull()
    }

    private fun encodePart(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))
    private fun decodePart(value: String): String = String(Base64.getUrlDecoder().decode(value), Charsets.UTF_8)
}
