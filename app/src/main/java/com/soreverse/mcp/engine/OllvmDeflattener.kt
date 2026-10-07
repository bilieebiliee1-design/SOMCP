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
 * OLLVM control-flow de-flattening.
 *
 * [ObfuscDetector] answers "is this function flattened?" from the block graph.
 * This file answers the next question: "what did the function look like before
 * the dispatcher was inserted?" De-flattening is a graph rewrite, and the whole
 * job is recovering the real successor of a block that currently appears to jump
 * into the dispatcher.
 *
 * A flattened block does not branch to its real successor — it stores a state
 * number and jumps to the dispatcher, which then dispatches on that state. So
 * the edge `B -> dispatcher` in the CFG carries no information about where `B`
 * really goes; that information lives in the state value `B` assigns.
 *
 * Recovering it needs the state variable, which Rizin's `rzCfg` does not report:
 * a CFG block is only `addr / size / ninstr / jump / fail`. There is no state
 * variable, no case table, and no instruction text. Rather than invent a
 * plausible-looking answer, this pass works from what is actually observable:
 *
 *  - the **dispatcher set**, from the same fan-in/thin-body rule the detector
 *    uses, so detection and de-flattening never disagree about what a
 *    dispatcher is;
 *  - the **predecessor lists**, which the detector throws away (it keeps only
 *    in-degree counts) and which are what let a real edge be recognised;
 *  - the **dispatcher's own successors**, which are the real blocks the
 *    dispatcher can reach.
 *
 * What that yields is a *candidate* real-edge set: for each block that flows
 * into a dispatcher, the set of dispatcher successors that are plausible
 * continuations. It deliberately does **not** claim to have recovered the true
 * CFG, because the state variable is not in the input. Emitting a single
 * "recovered" successor per block would be a guess, and a wrong guess is worse
 * than an admission of not knowing — the same standard
 * [ObfuscDetector.analyzeFunction] holds itself to. A `confidence` field and
 * the `limitations` block say so explicitly, and the caller is told which tool
 * closes the gap (`read_disasm` for the state variable, or `emulate_call`).
 */
internal object OllvmDeflattener {

    /**
     * Predecessor lists, keyed by target block address.
     *
     * [ObfuscDetector] computes in-degree but discards the addresses, and the
     * addresses are exactly what de-flattening needs: recognising "this block
     * exists only to reach the dispatcher" is a statement about predecessors.
     */
    private fun predecessors(blocks: List<CfgBlock>): Map<Long, List<Long>> {
        val preds = HashMap<Long, MutableList<Long>>()
        blocks.forEach { b ->
            listOfNotNull(
                b.jump.takeIf { b.hasJump },
                b.fail.takeIf { b.hasFail }
            ).forEach { target ->
                preds.getOrPut(target) { mutableListOf() }.add(b.addr)
            }
        }
        return preds
    }

    /**
     * Dispatcher blocks, using the detector's own rule and thresholds.
     *
     * Duplicating the constants here would let the two passes drift apart and
     * report different dispatchers for the same function, so both the rule and
     * its numbers are imported rather than restated. The entry block is
     * excluded for the same reason the detector excludes it: every loop
     * back-edge points there.
     */
    private fun dispatchers(blocks: List<CfgBlock>): Set<Long> {
        if (blocks.size < 6) return emptySet()
        val preds = predecessors(blocks)
        val entry = blocks.minByOrNull { it.addr }?.addr
        return blocks
            .filter { b ->
                (preds[b.addr]?.size ?: 0) >= DISPATCHER_MIN_FANIN &&
                    b.ninstr <= THIN_BLOCK_INSTR + 2 &&
                    b.addr != entry
            }
            .map { it.addr }
            .toSet()
    }

    /**
     * Blocks that exist only to hand control to a dispatcher.
     *
     * A real block ends by choosing a state and jumping to the dispatcher; a
     * dispatch trampoline is distinguishable because it is *thin* (it only
     * stores the state and branches, per [THIN_BLOCK_INSTR]) and every one of
     * its successors is a dispatcher. Anything thicker is doing real work and
     * must keep its own identity.
     */
    private fun isTrampoline(block: CfgBlock, dispatcherSet: Set<Long>): Boolean {
        if (block.addr in dispatcherSet) return false
        val targets = listOfNotNull(
            block.jump.takeIf { block.hasJump },
            block.fail.takeIf { block.hasFail }
        )
        if (targets.isEmpty()) return false
        if (block.ninstr > THIN_BLOCK_INSTR) return false
        return targets.all { it in dispatcherSet }
    }

    /**
     * Rebuild the pre-flattening edge set.
     *
     * For every block that reaches a dispatcher, the real continuation is one
     * of the blocks the dispatcher itself dispatches to. Candidates are
     * restricted to blocks that are *not* dispatchers and *not* trampolines:
     * a dispatcher chaining into another dispatcher is the flattening itself,
     * not the original control flow.
     */
    fun rebuild(name: String, blocks: List<CfgBlock>): JSONObject {
        val dispatcherSet = dispatchers(blocks)
        if (dispatcherSet.isEmpty()) {
            return JSONObject()
                .put("function", name)
                .put("verdict", "not_flattened")
                .put("dispatcherBlocks", 0)
                .put(
                    "reason",
                    "No dispatcher block met the detection rule (fan-in >= $DISPATCHER_MIN_FANIN with a thin body). There is nothing to de-flatten."
                )
                .put("edges", JSONArray())
        }

        val blockByAddr = blocks.associateBy { it.addr }
        val trampolines = blocks.filter { isTrampoline(it, dispatcherSet) }.map { it.addr }.toSet()

        // Everything the dispatcher can hand control to. These are the only
        // legal landing spots once the dispatcher hop is removed.
        val dispatchTargets = dispatcherSet
            .mapNotNull { blockByAddr[it] }
            .flatMap { b ->
                listOfNotNull(
                    b.jump.takeIf { b.hasJump },
                    b.fail.takeIf { b.hasFail }
                )
            }
            .filter { it in blockByAddr && it !in dispatcherSet && it !in trampolines }
            .distinct()
            .sorted()

        val edges = LinkedHashSet<Pair<Long, Long>>()
        blocks.forEach { b ->
            if (b.addr in dispatcherSet) return@forEach
            val reachesDispatcher = listOfNotNull(
                b.jump.takeIf { b.hasJump },
                b.fail.takeIf { b.hasFail }
            ).any { it in dispatcherSet }
            if (!reachesDispatcher) return@forEach
            dispatchTargets.forEach { target -> edges.add(b.addr to target) }
        }

        val recovered = edges.map { (from, to) ->
            JSONObject()
                .put("from", hex(from))
                .put("to", hex(to))
                // Repeated per edge so a caller reading a single edge does not
                // have to join it back against dispatchTargets to know how
                // ambiguous it is.
                .put("alternativesFrom", dispatchTargets.size)
        }

        return JSONObject()
            .put("function", name)
            .put("blockCount", blocks.size)
            .put("dispatcherBlocks", dispatcherSet.size)
            .put("dispatcherAddrs", JSONArray(dispatcherSet.map { hex(it) }))
            .put("trampolineAddrs", JSONArray(trampolines.map { hex(it) }))
            .put("dispatchTargets", JSONArray(dispatchTargets.map { hex(it) }))
            .put(
                "sources",
                JSONArray(
                    blocks
                        .filter { it.addr !in dispatcherSet }
                        .filter { b ->
                            listOfNotNull(
                                b.jump.takeIf { b.hasJump },
                                b.fail.takeIf { b.hasFail }
                            ).any { it in dispatcherSet }
                        }
                        .map { hex(it.addr) }
                )
            )
            .put("edges", JSONArray(recovered))
            .put("candidateEdgeCount", recovered.size)
            .put("verdict", "candidates_only")
            .put("confidence", "low")
            .put(
                "method",
                "Dispatcher set reused from ObfuscDetector (fan-in >= $DISPATCHER_MIN_FANIN, thin body, entry block excluded). Edges are the cross product of {blocks reaching a dispatcher} x {non-dispatcher, non-trampoline dispatcher successors}. No state variable is solved."
            )
            .put(
                "limitations",
                "These are CANDIDATE continuations, not a recovered CFG. Rizin reports only addr/size/ninstr/jump/fail per block, so the state variable and case table that encode the true successor are not in the input. Resolve the state assignment per block with read_disasm, or observe it with emulate_call, before treating any single edge as the original control flow."
            )
    }

    private fun hex(v: Long) = "0x${v.toString(16)}"
}

internal fun EngineRuntime.obfuscDeflatten(
    workspaceId: String,
    editSessionId: String = "",
    locator: String = "",
    symbol: String = "",
    limit: Int = 40
): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) {
        return@guarded err(
            "RIZIN_UNAVAILABLE",
            "Rizin native backend is not loaded; de-flattening needs its CFG analysis."
        )
    }
    val bytes = dataFor(workspaceId, editSessionId)

    // A single-function request is addressed by locator or symbol; with neither,
    // fall back to a scan of the largest functions so the tool still answers
    // "which functions in this library are flattened, and what would each look
    // like de-flattened".
    if (locator.isNotBlank() || symbol.isNotBlank()) {
        val requested = locator.ifBlank { symbol }
        val funcVa = resolveCodeAddress(bytes, elf, requested)
            ?: return@guarded err(
                "FUNCTION_NOT_FOUND",
                "Function or address could not be resolved",
                "locator",
                requested
            )
        val raw = runCatching {
            NativeEngine.active().cfg(bytes, elf.architecture, funcVa)
        }.getOrNull() ?: return@guarded err("RIZIN_CFG_FAILED", "Rizin returned no CFG payload")
        val payload = JSONObject(raw)
        if (payload.has("error")) {
            return@guarded err("RIZIN_CFG_FAILED", "Rizin could not analyse this function", "locator", requested)
        }
        val name = LocatorParser.normalizeSymbol(
            (elf.symbols + elf.dynSymbols).firstOrNull { it.value == (funcVa and -2L) }?.name
                ?: payload.optString("function", "fcn")
        )
        val verdict = ObfuscDetector.analyzeFunction(payload)
        val rebuilt = OllvmDeflattener.rebuild(name, ObfuscDetector.blocksOf(payload))
        return@guarded ok(
            rebuilt
                .put("workspaceId", workspaceId)
                .put("functionVa", "0x${funcVa.toString(16)}")
                .put("detectionVerdict", verdict.optString("verdict"))
                .put("detectionConfidence", verdict.optString("confidence"))
                .put("flatteningFactor", verdict.optDouble("flatteningFactor"))
                .put("bogusEdgeRatio", verdict.optDouble("bogusEdgeRatio"))
        )
    }

    val candidates = (elf.dynSymbols + elf.symbols)
        .filter { it.type == "FUNC" && it.value != 0L && it.size > 0 }
        .distinctBy { it.value }
        .sortedByDescending { it.size }
        .take(limit.coerceIn(1, 200))

    val results = JSONArray()
    var flattened = 0
    candidates.forEach { sym ->
        val raw = runCatching {
            NativeEngine.active().cfg(bytes, elf.architecture, sym.value)
        }.getOrNull() ?: return@forEach
        val payload = JSONObject(raw)
        if (payload.has("error")) return@forEach
        val blocks = ObfuscDetector.blocksOf(payload)
        val verdict = ObfuscDetector.analyzeFunction(payload)
        if (verdict.optString("verdict") == "clean") return@forEach
        flattened++
        results.put(
            OllvmDeflattener
                .rebuild(sym.name, blocks)
                .put("va", "0x${sym.value.toString(16)}")
                .put("detectionVerdict", verdict.optString("verdict"))
                .put("flatteningFactor", verdict.optDouble("flatteningFactor"))
        )
    }

    ok(
        JSONObject()
            .put("mode", "scan")
            .put("functions", results)
            .put("flattenedFunctions", flattened)
            .put("scannedFunctions", candidates.size)
            .put(
                "method",
                "Per function: dispatcher set from ObfuscDetector's rule, then candidate edges rebuilt as {blocks reaching a dispatcher} x {non-dispatcher, non-trampoline dispatcher successors}."
            )
            .put(
                "limitations",
                "Candidate edges only. The state variable and case table that encode each true successor are not present in Rizin's CFG output, so no single edge is claimed as the original control flow. Use read_disasm or emulate_call per block to resolve them."
            )
    )
}

internal fun EngineRuntime.obfuscDeflattenCapabilities(): JSONObject = JSONObject()
    .put("coverageClass", "cfg_structural_reconstruction")
    .put(
        "supported",
        JSONArray(
            listOf(
                "dispatcher set shared with ObfuscDetector, so detection and de-flattening cannot disagree",
                "predecessor lists, which the detector discards",
                "trampoline classification (thin blocks whose every successor is a dispatcher)",
                "candidate real-edge set per block that reaches a dispatcher",
                "dispatch targets, i.e. the legal landing spots once the dispatcher hop is cut"
            )
        )
    )
    .put(
        "notCovered",
        JSONArray(
            listOf(
                "state-variable recovery: rzCfg reports only addr/size/ninstr/jump/fail per block",
                "case-table reconstruction, and therefore a single true successor per block",
                "jump-table (TBB/TBH) dispatchers, which carry no compare chain to read",
                "emitting a patched binary; this pass is analysis-only and writes nothing"
            )
        )
    )
    .put(
        "nextStep",
        "Recover the state assignment per source block with read_disasm, or observe the real path with emulate_call, then pick the matching candidate edge."
    )
