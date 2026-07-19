package com.soreverse.mcp.core

import okhttp3.Request

internal fun sanitizeCredential(value: String): String =
    value.filterNot { it == '\r' || it == '\n' || it.code == 0x7f }.trim()

internal fun Request.Builder.safeHeader(name: String, value: String): Request.Builder {
    val normalizedName = name.trim()
    require(normalizedName.matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) {
        "Invalid HTTP header name"
    }
    val normalizedValue = value.replace('\r', ' ').replace('\n', ' ').trim()
    require(normalizedValue.none { it.code < 0x20 && it != '\t' || it.code == 0x7f }) {
        "Invalid value for HTTP header $normalizedName"
    }
    return header(normalizedName, normalizedValue)
}
