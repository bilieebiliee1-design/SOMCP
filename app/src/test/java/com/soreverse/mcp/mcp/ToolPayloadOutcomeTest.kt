/*
 * SOMCP - Android native SO reverse-engineering MCP server
 * Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
 *
 * This file is part of SOMCP and is licensed under the GNU General Public
 * License v3.0 only (GPL-3.0-only). See the LICENSE file.
 */
package com.soreverse.mcp.mcp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Built-in tool payloads use `{ok: Boolean}`; payloads forwarded from a bridged
 * APK MCP server use the MCP wire shape `{isError, content[]}` and have no `ok`
 * key. Both shapes must map onto the same success/failure decision.
 */
class ToolPayloadOutcomeTest {

    @Test
    fun builtInSuccessIsNotFailure() {
        assertFalse(toolPayloadFailed(JSONObject().put("ok", true)))
    }

    @Test
    fun builtInFailureIsFailure() {
        val payload = JSONObject()
            .put("ok", false)
            .put("error", JSONObject().put("code", "SO_NOT_FOUND").put("message", "no such SO"))
        assertTrue(toolPayloadFailed(payload))
        assertEquals("no such SO", toolPayloadErrorMessage(payload))
    }

    @Test
    fun bridgedErrorIsFailureEvenWithoutOkKey() {
        // This is the regression: no "ok" key at all, so a default of true
        // previously scored a failed bridge forward as a successful call.
        val payload = JSONObject()
            .put("isError", true)
            .put("source", "apk-mcp-bridge")
            .put(
                "content",
                JSONArray().put(
                    JSONObject().put("type", "text").put("text", "APK MCP error [mt_apk_open]: forward failed: timeout"),
                ),
            )
        assertTrue(toolPayloadFailed(payload))
        assertEquals("APK MCP error [mt_apk_open]: forward failed: timeout", toolPayloadErrorMessage(payload))
    }

    @Test
    fun bridgedSuccessIsNotFailure() {
        val payload = JSONObject()
            .put("isError", false)
            .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", "{}")))
        assertFalse(toolPayloadFailed(payload))
        assertEquals("", toolPayloadErrorMessage(payload))
    }

    @Test
    fun bridgedResultWithoutIsErrorIsTreatedAsSuccess() {
        // A well-behaved remote that simply omits isError on success.
        val payload = JSONObject().put("content", JSONArray())
        assertFalse(toolPayloadFailed(payload))
    }

    @Test
    fun okKeyWinsOverIsErrorWhenBothPresent() {
        // Local shape is authoritative for local handlers.
        assertTrue(toolPayloadFailed(JSONObject().put("ok", false).put("isError", false)))
        assertFalse(toolPayloadFailed(JSONObject().put("ok", true).put("isError", true)))
    }

    @Test
    fun emptyPayloadIsNotFailure() {
        assertFalse(toolPayloadFailed(JSONObject()))
        assertEquals("", toolPayloadErrorMessage(JSONObject()))
    }

    @Test
    fun blankErrorMessageFallsBackToContentText() {
        val payload = JSONObject()
            .put("isError", true)
            .put("error", JSONObject().put("code", "X").put("message", ""))
            .put("content", JSONArray().put(JSONObject().put("type", "text").put("text", "bridge said no")))
        assertEquals("bridge said no", toolPayloadErrorMessage(payload))
    }
}