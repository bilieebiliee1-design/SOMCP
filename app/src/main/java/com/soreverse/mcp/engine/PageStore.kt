package com.soreverse.mcp.engine

import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

internal class PageStore {
    internal data class PageSlice(
        val field: String,
        val items: List<JSONObject>,
        val hasMore: Boolean,
        val nextCursor: String?,
        val returnedCount: Int,
        val limit: Int,
        val totalCount: Int,
    )

    private data class PageState(
        val field: String,
        val items: List<JSONObject>,
        val offset: Int,
        val limit: Int,
    )

    private val pages = ConcurrentHashMap<String, PageState>()

    fun first(field: String, items: List<JSONObject>, limit: Int): PageSlice =
        slice(PageState(field, items, 0, limit.coerceIn(1, 5000)))

    fun consume(cursor: String): PageSlice? = pages.remove(cursor)?.let(::slice)

    fun clear() {
        pages.clear()
    }

    private fun slice(state: PageState): PageSlice {
        val chunk = state.items.drop(state.offset).take(state.limit)
        val nextOffset = state.offset + chunk.size
        val nextCursor = if (nextOffset < state.items.size) {
            "page:${UUID.randomUUID()}".also { pages[it] = state.copy(offset = nextOffset) }
        } else {
            null
        }
        return PageSlice(state.field, chunk, nextCursor != null, nextCursor, chunk.size, state.limit, state.items.size)
    }
}
