package com.soreverse.mcp.engine

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PageStoreTest {
    @Test
    fun coversFirstAndLastPages() {
        val store = PageStore()
        val first = store.first("items", items(5), 2)
        val second = store.consume(first.nextCursor!!)!!
        val last = store.consume(second.nextCursor!!)!!

        assertEquals(2, first.returnedCount)
        assertTrue(first.hasMore)
        assertEquals(1, last.returnedCount)
        assertFalse(last.hasMore)
        assertNull(last.nextCursor)
    }

    @Test
    fun clampsLimit() {
        val store = PageStore()

        assertEquals(1, store.first("items", items(2), 0).limit)
        assertEquals(5000, store.first("items", items(2), 5001).limit)
    }

    @Test
    fun reusesFieldAndLimit() {
        val store = PageStore()
        val first = store.first("results", items(3), 2)
        val next = store.consume(first.nextCursor!!)!!

        assertEquals("results", next.field)
        assertEquals(2, next.limit)
    }

    @Test
    fun consumesCursorOnce() {
        val store = PageStore()
        val cursor = store.first("items", items(2), 1).nextCursor!!

        assertTrue(store.consume(cursor) != null)
        assertNull(store.consume(cursor))
    }

    @Test
    fun clearInvalidatesCursor() {
        val store = PageStore()
        val cursor = store.first("items", items(2), 1).nextCursor!!

        store.clear()

        assertNull(store.consume(cursor))
    }

    @Test
    fun supportsEmptyList() {
        val slice = PageStore().first("items", emptyList(), 10)

        assertEquals(0, slice.returnedCount)
        assertEquals(0, slice.totalCount)
        assertFalse(slice.hasMore)
        assertNull(slice.nextCursor)
    }

    private fun items(count: Int): List<JSONObject> = (0 until count).map { JSONObject().put("id", it) }
}
