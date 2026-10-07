// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * De-flattening must never claim more than the CFG supports.
 *
 * The load-bearing tests here are the negative ones: a function that is not
 * flattened has to be reported as such, and a flattened one has to be reported
 * as *candidates only*. A pass that quietly promoted a guess to a recovered CFG
 * would be worse than having no deflattening at all.
 */
class OllvmDeflattenerTest {

    private val noTarget = -1L

    private fun block(addr: Long, ninstr: Int, jump: Long, fail: Long): CfgBlock = CfgBlock(addr = addr, size = 4, ninstr = ninstr, jump = jump, fail = fail)

    /**
     * A flattened function: real blocks 0x20/0x40/0x70 all hand control back to
     * the dispatcher at 0x50, and the dispatcher dispatches onward to them.
     */
    private val flattened = listOf(
        block(0x10, 2, 0x50, noTarget),
        block(0x20, 4, 0x50, noTarget),
        block(0x40, 4, 0x50, noTarget),
        block(0x70, 4, 0x50, noTarget),
        block(0x50, 3, 0x20, 0x40)
    )

    /** An ordinary diamond: no block funnels everything back into one place. */
    private val plain = listOf(
        block(0x10, 4, 0x20, 0x30),
        block(0x20, 4, 0x40, noTarget),
        block(0x30, 4, 0x40, noTarget),
        block(0x40, 4, 0x50, noTarget),
        block(0x50, 4, 0x60, noTarget),
        block(0x60, 4, noTarget, noTarget)
    )

    @Test
    fun reportsNotFlattenedWhenThereIsNoDispatcher() {
        val r = OllvmDeflattener.rebuild("sub_plain", plain)
        assertEquals("not_flattened", r.getString("verdict"))
        assertEquals(0, r.getInt("dispatcherBlocks"))
        assertEquals(0, r.getJSONArray("edges").length())
    }

    @Test
    fun findsTheDispatcherThatTheDetectorAlsoFinds() {
        // The whole point of sharing the rule: two passes must not disagree
        // about which block is the dispatcher for the same function.
        val payload = JSONObject()
            .put("function", "sub_flat")
            .put(
                "blocks",
                JSONArray(
                    flattened.map {
                        JSONObject()
                            .put("addr", it.addr)
                            .put("size", it.size)
                            .put("ninstr", it.ninstr)
                            .put("jump", if (it.jump == noTarget) JSONObject.NULL else it.jump)
                            .put("fail", if (it.fail == noTarget) JSONObject.NULL else it.fail)
                    }
                )
            )
        val detected = ObfuscDetector.analyzeFunction(payload)
            .getJSONArray("dispatcherAddrs")
            .toString()
        val rebuilt = OllvmDeflattener.rebuild("sub_flat", flattened)
            .getJSONArray("dispatcherAddrs")
            .toString()
        assertEquals(detected, rebuilt)
    }

    @Test
    fun neverClaimsRecoveredControlFlow() {
        // rzCfg exposes no state variable, so the honest verdict is fixed. If a
        // future change starts asserting a recovered CFG, this is the test that
        // must be revisited deliberately rather than silently.
        val r = OllvmDeflattener.rebuild("sub_flat", flattened)
        assertEquals("candidates_only", r.getString("verdict"))
        assertEquals("low", r.getString("confidence"))
        assertFalse(
            "must not be presented as a recovered CFG",
            r.has("recoveredEdges")
        )
    }

    @Test
    fun statesTheLimitationThatMakesItCandidatesOnly() {
        val r = OllvmDeflattener.rebuild("sub_flat", flattened)
        val limitations = r.getString("limitations")
        assertTrue(
            "should name the missing state variable",
            limitations.contains("state variable", ignoreCase = true)
        )
        assertTrue(
            "should point at the tool that closes the gap",
            limitations.contains("read_disasm")
        )
    }

    @Test
    fun candidateTargetsExcludeDispatchersAndTrampolines() {
        // 0x10 is thin (2 instructions) and every successor is a dispatcher, so
        // it is a trampoline; 0x50 is the dispatcher. Neither may be offered as
        // a post-flattening landing spot.
        val r = OllvmDeflattener.rebuild("sub_flat", flattened)
        val targets = r.getJSONArray("dispatchTargets").toString()
        assertTrue("real blocks should be candidates", targets.contains("0x20"))
        assertFalse("dispatcher is not a real successor", targets.contains("0x50"))
        assertFalse("trampoline is not a real successor", targets.contains("0x10"))
    }

    @Test
    fun everyEdgeSourceReachesADispatcher() {
        val r = OllvmDeflattener.rebuild("sub_flat", flattened)
        val dispatcherAddrs = r.getJSONArray("dispatcherAddrs").toString()
        val edges = r.getJSONArray("edges")
        assertTrue("there should be candidate edges", edges.length() > 0)
        for (i in 0 until edges.length()) {
            val from = edges.getJSONObject(i).getString("from")
            val asLong = from.removePrefix("0x").toLong(16)
            val source = flattened.first { it.addr == asLong }
            val reaches = listOf(source.jump, source.fail)
                .any { it != noTarget && dispatcherAddrs.contains("0x${it.toString(16)}") }
            assertTrue("$from does not reach a dispatcher", reaches)
        }
    }

    @Test
    fun tinyFunctionIsNotJudged() {
        // Fewer than 6 blocks cannot host a dispatcher; reporting "not
        // flattened" is correct and reporting a dispatcher would not be.
        val tiny = listOf(
            block(0x10, 2, 0x20, noTarget),
            block(0x20, 2, noTarget, noTarget)
        )
        assertEquals("not_flattened", OllvmDeflattener.rebuild("sub_tiny", tiny).getString("verdict"))
    }

    @Test
    fun entryBlockIsNotTreatedAsADispatcher() {
        // Every loop back-edge points at the entry, so it is legitimately
        // high-fan-in without being a dispatcher.
        val entryHeavy = listOf(
            block(0x10, 2, 0x20, 0x30),
            block(0x20, 4, 0x10, noTarget),
            block(0x30, 4, 0x10, noTarget),
            block(0x40, 4, 0x10, noTarget),
            block(0x50, 4, 0x10, noTarget),
            block(0x60, 4, noTarget, noTarget)
        )
        val r = OllvmDeflattener.rebuild("sub_entry", entryHeavy)
        assertEquals("not_flattened", r.getString("verdict"))
    }
}
