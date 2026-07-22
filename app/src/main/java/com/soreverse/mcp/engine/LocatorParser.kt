package com.soreverse.mcp.engine

import com.soreverse.mcp.core.HexCodec

internal object LocatorParser {
    fun target(locator: String, prefix: String = ""): String {
        val trimmed = locator.trim()
        val withoutPrefix = if (prefix.isNotBlank() && trimmed.startsWith("$prefix:")) trimmed.substringAfter(':') else trimmed
        return withoutPrefix.substringAfterLast('!').substringBeforeLast('@').trim()
    }

    fun address(locator: String): Long? {
        val trimmed = locator.trim()
        val at = trimmed.substringAfterLast('@', "")
        return at.takeIf { it.isNotBlank() && it != trimmed }?.let(::hex)
    }

    fun hex(value: String): Long? = HexCodec.long(value)

    fun normalizeSymbol(raw: String): String {
        val base = raw.substringBefore('@').trim()
        return base
            .removePrefix("so_function:")
            .removePrefix("so_symbol:")
            .substringAfterLast('!')
            .removePrefix("sym.imp.")
            .removePrefix("sym.")
            .removePrefix("fcn.")
            .ifBlank { raw.substringBefore('@').trim() }
    }
}
