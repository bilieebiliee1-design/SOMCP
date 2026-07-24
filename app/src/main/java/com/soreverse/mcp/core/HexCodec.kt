package com.soreverse.mcp.core

object HexCodec {
    fun long(value: String): Long? = value.trim()
        .removePrefix("0x")
        .removePrefix("0X")
        .takeIf(String::isNotBlank)
        ?.toLongOrNull(16)

    fun bytes(value: String): ByteArray? {
        val clean = value.filterNot { it == ' ' || it == '\n' || it == '\r' || it == '\t' || it == ',' }
        if (clean.isBlank() || clean.length % 2 != 0) return null
        return ByteArray(clean.length / 2) { index ->
            val high = Character.digit(clean[index * 2], 16)
            val low = Character.digit(clean[index * 2 + 1], 16)
            if (high < 0 || low < 0) return null
            ((high shl 4) or low).toByte()
        }
    }
}
