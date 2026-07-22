package com.soreverse.mcp.mcp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatchExecutionTest {
    @Test
    fun resolvesNestedObjectAndArrayPaths() {
        val prior = JSONObject().put("result", JSONObject().put("items", JSONArray().put(JSONObject().put("workspaceId", "ws-1"))))
        val input = JSONObject()
            .put("workspaceId", "${'$'}{open.result.items[0].workspaceId}")
            .put("nested", JSONArray().put(JSONObject().put("copy", "prefix-${'$'}{open.result.items[0].workspaceId}")))

        val resolved = BatchTemplateResolver.substitute(input, mapOf("open" to prior))

        assertEquals("ws-1", resolved.getString("workspaceId"))
        assertEquals("prefix-ws-1", resolved.getJSONArray("nested").getJSONObject(0).getString("copy"))
        assertEquals("ws-1", BatchTemplateResolver.resolvePath(prior, ".result.items[0].workspaceId"))
    }

    @Test
    fun preservesMissingPlaceholders() {
        val resolved = BatchTemplateResolver.substitute(JSONObject().put("value", "${'$'}{missing.path}"), emptyMap())

        assertEquals("${'$'}{missing.path}", resolved.getString("value"))
    }

    @Test
    fun abortsAndRollsBackTransactionalPipeline() {
        val calls = mutableListOf<String>()
        val snapshots = mutableListOf<String>()
        var rolledBack = emptySet<String>()
        val executor = BatchExecutor(
            executeTool = { name, _ -> calls += name; JSONObject().put("ok", name != "fail").put("workspaceId", "ws-1") },
            ensureSnapshot = { args, keys -> args.optString("editSessionId").takeIf { it.isNotBlank() }?.let { keys += it; snapshots += it } },
            rollbackSnapshots = { keys -> rolledBack = keys; JSONArray(keys.toList()) },
        )
        val steps = JSONArray()
            .put(JSONObject().put("tool", "open").put("resultKey", "opened"))
            .put(JSONObject().put("tool", "fail").put("arguments", JSONObject().put("workspaceId", "${'$'}{opened.workspaceId}").put("editSessionId", "edit-1")))
            .put(JSONObject().put("tool", "never"))

        val result = executor.execute(JSONObject().put("steps", steps).put("transactional", true))

        assertTrue(result.getBoolean("ok"))
        assertTrue(result.getBoolean("aborted"))
        assertEquals(listOf("open", "fail"), calls)
        assertEquals(listOf("edit-1"), snapshots)
        assertEquals(setOf("edit-1"), rolledBack)
    }

    @Test
    fun continuesWhenStopOnErrorIsDisabled() {
        val executor = BatchExecutor(
            executeTool = { name, _ -> JSONObject().put("ok", name != "fail") },
            ensureSnapshot = { _, _ -> },
            rollbackSnapshots = { JSONArray() },
        )
        val steps = JSONArray().put(JSONObject().put("tool", "fail")).put(JSONObject().put("tool", "next"))

        val result = executor.execute(JSONObject().put("steps", steps).put("stopOnError", false))

        assertFalse(result.getBoolean("aborted"))
        assertEquals(2, result.getInt("executedCount"))
    }
}
