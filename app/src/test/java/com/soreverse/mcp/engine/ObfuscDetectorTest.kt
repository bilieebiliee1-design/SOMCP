// SPDX-License-Identifier: AGPL-3.0-only
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
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ObfuscDetectorTest {

    private val noTarget = -1L

    /** addr, ninstr, jump, fail */
    private fun block(addr: Long, ninstr: Int, jump: Long, fail: Long): JSONObject = JSONObject()
        .put("addr", addr)
        .put("size", 4)
        .put("ninstr", ninstr)
        .put("jump", if (jump == noTarget) JSONObject.NULL else jump)
        .put("fail", if (fail == noTarget) JSONObject.NULL else fail)

    private fun cfg(vararg blocks: JSONObject): JSONObject = JSONObject()
        .put("function", "sub_test")
        .put("addr", blocks.first().getLong("addr"))
        .put("blocks", JSONArray(blocks.toList()))
        .put("edges", JSONArray())

    /**
     * A control-flow-flattened function: every real block jumps back into one
     * thin dispatcher, and several of those blocks are themselves thin bogus
     * blocks that do no work.
     */
    private fun flattenedCfg() = cfg(
        block(0x10, 2, 0x50, noTarget),
        block(0x11, 2, 0x50, noTarget),
        block(0x20, 4, 0x50, noTarget),
        block(0x30, 2, 0x50, noTarget),
        block(0x31, 2, 0x50, noTarget),
        block(0x40, 4, 0x50, noTarget),
        block(0x50, 3, 0x20, 0x60),
        block(0x60, 4, 0x50, noTarget),
        block(0x61, 2, 0x50, noTarget),
        block(0x70, 3, 0x50, noTarget)
    )

    /** An ordinary diamond plus straight-line blocks: no central dispatcher. */
    private fun plainCfg() = cfg(
        block(0x10, 4, 0x20, 0x30),
        block(0x20, 4, 0x40, noTarget),
        block(0x30, 4, 0x40, noTarget),
        block(0x40, 4, 0x50, noTarget),
        block(0x50, 4, 0x60, noTarget),
        block(0x60, 4, 0x70, noTarget),
        block(0x70, 4, noTarget, noTarget),
        block(0x80, 4, 0x90, noTarget),
        block(0x90, 4, 0xA0, noTarget),
        block(0xA0, 4, noTarget, noTarget)
    )

    @Test
    fun detectsFlattenedControlFlow() {
        val r = ObfuscDetector.analyzeFunction(flattenedCfg())
        assertEquals("flattened", r.getString("verdict"))
        assertEquals("high", r.getString("confidence"))
        assertTrue("dispatcher should be found", r.getInt("dispatcherBlocks") >= 1)
        assertTrue("factor should be high", r.getDouble("flatteningFactor") >= 8.0)
    }

    @Test
    fun doesNotFlagOrdinaryControlFlow() {
        val r = ObfuscDetector.analyzeFunction(plainCfg())
        assertEquals("clean", r.getString("verdict"))
        assertEquals(0, r.getInt("dispatcherBlocks"))
    }

    @Test
    fun emptyCfgIsReportedNotCrashed() {
        val r = ObfuscDetector.analyzeFunction(JSONObject().put("function", "sub_x").put("blocks", JSONArray()))
        assertEquals("no_cfg", r.getString("verdict"))
        assertEquals(0, r.getInt("blockCount"))
    }

    @Test
    fun tinyFunctionIsNotAnalysedForDispatchers() {
        // Fewer than 6 blocks cannot host a dispatcher; must not be judged.
        val r = ObfuscDetector.analyzeFunction(
            cfg(
                block(0x10, 2, 0x20, 0x20),
                block(0x20, 2, noTarget, noTarget)
            )
        )
        assertEquals(0, r.getInt("dispatcherBlocks"))
        assertEquals("clean", r.getString("verdict"))
    }
}
