// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
package com.soreverse.mcp.engine

import java.util.LinkedHashMap
import java.util.UUID
import org.json.JSONObject

internal class PageStore {
    internal data class PageSlice(
        val field: String,
        val items: List<JSONObject>,
        val hasMore: Boolean,
        val nextCursor: String?,
        val returnedCount: Int,
        val limit: Int,
        val totalCount: Int
    )

    private data class PageState(val field: String, val items: List<JSONObject>, val offset: Int, val limit: Int)

    /**
     * Bounded, insertion-ordered page cache. Each entry holds a full item list
     * (up to `limit` items), so an unbounded map would leak whenever a client
     * abandons a cursor without continuing or repeatedly requests page one.
     * The eldest entry is evicted once the cache exceeds [maxPages], bounding
     * the retained JSON to a fixed working set.
     */
    private val lock = Any()
    private val maxPages = 64
    private val pages = object : LinkedHashMap<String, PageState>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, PageState>?): Boolean =
            size > maxPages
    }

    fun first(field: String, items: List<JSONObject>, limit: Int): PageSlice = synchronized(lock) {
        slice(PageState(field, items, 0, limit.coerceIn(1, 5000)))
    }

    fun consume(cursor: String): PageSlice? = synchronized(lock) {
        pages.remove(cursor)?.let(::slice)
    }

    fun clear() {
        synchronized(lock) { pages.clear() }
    }

    private fun slice(state: PageState): PageSlice {
        val chunk = state.items.drop(state.offset).take(state.limit)
        val nextOffset = state.offset + chunk.size
        val nextCursor = if (nextOffset < state.items.size) {
            "page:${UUID.randomUUID()}".also { pages[it] = state.copy(offset = nextOffset) }
        } else {
            null
        }
        return PageSlice(
            state.field,
            chunk,
            nextCursor != null,
            nextCursor,
            chunk.size,
            state.limit,
            state.items.size
        )
    }
}
