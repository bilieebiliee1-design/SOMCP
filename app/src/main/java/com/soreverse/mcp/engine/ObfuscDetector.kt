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

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject

/**
 * A CFF dispatcher is the block every real block funnels back into, so it must
 * have several predecessors. Kept at file scope because both the detector and
 * the runtime entry point quote these thresholds in their output.
 */
internal const val DISPATCHER_MIN_FANIN = 3

/** A block this thin is a jump thunk or a state compare, not real work. */
internal const val THIN_BLOCK_INSTR = 2

/** A basic block as reported by Rizin's `rzCfg`. */
internal data class CfgBlock(val addr: Long, val size: Long, val ninstr: Int, val jump: Long, val fail: Long) {
    /** Rizin uses UT64_MAX for "no target". */
    val hasJump: Boolean get() = jump != Long.MAX_VALUE && jump != -1L
    val hasFail: Boolean get() = fail != Long.MAX_VALUE && fail != -1L
}

/** One function's CFG plus the derived obfuscation metrics. */
internal data class ObfuscVerdict(
    val function: String,
    val addr: Long,
    val blockCount: Int,
    val edgeCount: Int,
    val dispatcherBlocks: Int,
    val flatteningFactor: Double,
    val bogusEdgeRatio: Double,
    val verdict: String,
    val confidence: String,
    val notes: List<String>
)

/**
 * Control-flow-obfuscation detection driven by the actual basic-block graph.
 *
 * The existing `hasOllvm` flag in `ElfOverviewBuilder` keys off symbol-name
 * substrings such as `.cold.` and `__clang_call_terminate`. Those are ordinary
 * clang release artefacts, not obfuscation markers, so that heuristic fires on
 * virtually every NDK build; it is a risk label, not a detector. This engine
 * replaces the guess with structural evidence, matching what OLLVM's
 * control-flow-flattening pass actually produces.
 *
 * The flattened form routes every basic block through a central dispatcher
 * holding a state variable, so its CFG has a characteristic shape:
 *
 *  - a **dispatcher block** with high fan-in (many predecessors) and a thin
 *    body — the `switch` that picks the next real block;
 *  - a raised **flattening factor** — basic blocks per dispatcher is far above
 *    what unflattened code produces;
 *  - **bogus edges** — dispatch targets that immediately jump onward without
 *    doing useful work, the signature of bogus-control-flow splitting.
 *
 * Every threshold is reported alongside the measurement, and a function is
 * only called `flattened` when the dispatcher evidence is unambiguous, because
 * a false "this is obfuscated" is worse than an admission of not knowing.
 */
internal object ObfuscDetector {

    private fun parseCfg(payload: JSONObject): Pair<String, List<CfgBlock>> {
        val blocks = ArrayList<CfgBlock>()
        val arr = payload.optJSONArray("blocks") ?: JSONArray()
        for (i in 0 until arr.length()) {
            val b = arr.optJSONObject(i) ?: continue
            blocks.add(
                CfgBlock(
                    addr = b.optLong("addr"),
                    size = b.optLong("size"),
                    ninstr = b.optInt("ninstr"),
                    jump = if (b.isNull("jump")) -1L else b.optLong("jump"),
                    fail = if (b.isNull("fail")) -1L else b.optLong("fail")
                )
            )
        }
        return payload.optString("function", "fcn") to blocks
    }

    private fun successors(b: CfgBlock): List<Long> = buildList {
        if (b.hasJump) add(b.jump)
        if (b.hasFail) add(b.fail)
    }

    /**
     * A CFF dispatcher is the block every real block funnels back into: high
     * fan-in plus a thin body, because all it does is compare a state variable
     * and branch. Fan-out is deliberately *not* constrained — the dispatcher is
     * a `switch`, so having many successors is the point, not an anomaly.
     *
     * The function's entry block is excluded: every loop back-edge points at
     * it, so it is the one address that is legitimately high-fan-in without
     * being a dispatcher.
     */
    private fun findDispatchers(blocks: List<CfgBlock>): Set<Long> {
        if (blocks.size < 6) return emptySet()
        val inDegree = HashMap<Long, Int>()
        blocks.forEach { b ->
            successors(b).forEach { s ->
                inDegree[s] = (inDegree[s] ?: 0) + 1
            }
        }
        val entry = blocks.minByOrNull { it.addr }?.addr
        return blocks
            .filter { b ->
                (inDegree[b.addr] ?: 0) >= DISPATCHER_MIN_FANIN &&
                    b.ninstr <= THIN_BLOCK_INSTR + 2 &&
                    b.addr != entry
            }
            .map { it.addr }
            .toSet()
    }

    /**
     * Bogus control flow inserts edges that are never taken at runtime. A
     * static tell is a very short block that only branches onward, so it
     * contributes a decision without contributing semantics.
     */
    private fun bogusEdgeRatio(blocks: List<CfgBlock>, dispatchers: Set<Long>): Double {
        if (blocks.isEmpty()) return 0.0
        val thin = blocks.count { it.ninstr in 1..THIN_BLOCK_INSTR && it.addr !in dispatchers }
        return thin.toDouble() / blocks.size
    }

    fun analyzeFunction(payload: JSONObject): JSONObject {
        val (name, blocks) = parseCfg(payload)
        if (blocks.isEmpty()) {
            return JSONObject()
                .put("function", name)
                .put("blockCount", 0)
                .put("verdict", "no_cfg")
                .put("note", "Rizin returned no basic blocks for this function")
        }
        val dispatchers = findDispatchers(blocks)
        val factor = if (dispatchers.isEmpty()) 0.0 else blocks.size.toDouble() / dispatchers.size
        val bogus = bogusEdgeRatio(blocks, dispatchers)
        val edges = blocks.sumOf { successors(it).size }

        // Both signals must agree before calling it flattened: a dispatcher with
        // a low flattening factor is an ordinary shared jump target, and a high
        // factor without a dispatcher is just a big function.
        val verdict = when {
            dispatchers.isEmpty() -> "clean"
            factor >= 8.0 && bogus >= 0.25 -> "flattened"
            factor >= 8.0 || bogus >= 0.35 -> "suspected"
            else -> "clean"
        }
        val confidence = when (verdict) {
            "flattened" -> "high"
            "suspected" -> "medium"
            else -> "low"
        }
        val notes = mutableListOf<String>()
        if (dispatchers.isNotEmpty()) {
            notes.add("${dispatchers.size} dispatcher-like block(s): fan-in >= $DISPATCHER_MIN_FANIN with a thin body")
        }
        if (factor >= 8.0) notes.add("flattening factor ${"%.1f".format(factor)} blocks per dispatcher")
        if (bogus >= 0.25) notes.add("${"%.0f".format(bogus * 100)}% of blocks are <= $THIN_BLOCK_INSTR instructions (bogus-edge candidates)")

        return JSONObject()
            .put("function", name)
            .put("addr", blocks.first().addr)
            .put("blockCount", blocks.size)
            .put("edgeCount", edges)
            .put("dispatcherBlocks", dispatchers.size)
            .put("dispatcherAddrs", JSONArray(dispatchers.map { "0x${it.toString(16)}" }))
            .put("flatteningFactor", factor)
            .put("bogusEdgeRatio", bogus)
            .put("verdict", verdict)
            .put("confidence", confidence)
            .put("notes", JSONArray(notes))
    }
}

internal fun EngineRuntime.obfuscScan(workspaceId: String, editSessionId: String = "", limit: Int = 40): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) {
        return@guarded err(
            "RIZIN_UNAVAILABLE",
            "Rizin native backend is not loaded; obfuscation metrics need its CFG analysis."
        )
    }
    val bytes = dataFor(workspaceId, editSessionId)
    val candidates = (elf.dynSymbols + elf.symbols)
        .filter { it.type == "FUNC" && it.value != 0L && it.size > 0 }
        .distinctBy { it.value }
        // Largest functions first: flattening shows up where there is enough
        // control flow to flatten, and it keeps the budget meaningful.
        .sortedByDescending { it.size }
        .take(limit.coerceIn(1, 200))

    val results = JSONArray()
    var flattened = 0
    var suspected = 0
    var analyzed = 0
    candidates.forEach { sym ->
        val raw = runCatching {
            NativeEngine.active().cfg(bytes, elf.architecture, sym.value)
        }.getOrNull() ?: return@forEach
        val payload = JSONObject(raw)
        if (payload.has("error")) return@forEach
        val item = ObfuscDetector.analyzeFunction(payload)
            .put("symbol", sym.name)
            .put("va", "0x${sym.value.toString(16)}")
        analyzed++
        when (item.optString("verdict")) {
            "flattened" -> flattened++
            "suspected" -> suspected++
        }
        results.put(item)
    }

    val overall = when {
        flattened > 0 -> "flattened"
        suspected > 0 -> "suspected"
        else -> "clean"
    }
    ok(
        JSONObject()
            .put("overall", overall)
            .put("analyzed", analyzed)
            .put("flattenedFunctions", flattened)
            .put("suspectedFunctions", suspected)
            .put("functions", results)
            .put(
                "method",
                "Structural CFG analysis: dispatcher blocks (fan-in >= $DISPATCHER_MIN_FANIN with a thin body, excluding the entry block) plus flattening factor and thin-block ratio. No symbol-name heuristics are used."
            )
            .put(
                "limits",
                "Only functions with a non-zero symbol size are analysed, and the scan is capped at the requested limit. Compiler-generated shared jump targets can resemble a dispatcher; 'suspected' is the deliberate ceiling for anything short of unambiguous evidence."
            )
    )
}

internal fun EngineRuntime.obfuscCapabilities(): JSONObject = JSONObject()
    .put("coverageClass", "cfg_structural_analysis")
    .put(
        "supported",
        JSONArray(
            listOf(
                "dispatcher block identification (fan-in / single-successor shape)",
                "flattening factor per function",
                "bogus-edge candidate ratio (thin non-dispatcher blocks)",
                "per-function verdict with confidence and explicit notes"
            )
        )
    )
    .put(
        "notCovered",
        JSONArray(
            listOf(
                "instruction substitution and opaque-predicate solving are not implemented",
                "deobfuscation / automatic CFG reconstruction is not implemented",
                "SMT-based opaque predicate evaluation is not implemented"
            )
        )
    )
    .put(
        "replaces",
        "Structural evidence supersedes the hasOllvm symbol-name heuristic in ElfOverviewBuilder, which matches standard clang artefacts such as .cold. and fires on ordinary NDK builds."
    )
