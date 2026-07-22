package com.soreverse.mcp.engine

import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

internal fun EngineRuntime.rzAnalyze(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val result = NativeEngine.active().analyze(bytes, elf.architecture)
    ok(JSONObject(result).put("workspaceId", workspaceId).put("architecture", elf.architecture))
}

internal fun EngineRuntime.rzFunctions(workspaceId: String, editSessionId: String = "", limit: Int = SettingsStore(context).defaultLimit, cursor: String = ""): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val result = NativeEngine.active().functions(bytes, elf.architecture)
    val arr = runCatching { JSONArray(result) }.getOrNull()
    if (arr != null && arr.length() > 0) {
        val wsName = workspaces[workspaceId]?.source?.name ?: "lib.so"
        val list = (0 until arr.length()).map {
            val item = arr.getJSONObject(it)
            val name = item.optString("name")
            val start = item.optLong("addr") and -2L
            item.put("locator", "so_function:$wsName!$name@${hex(start)}")
                .put("startAddr", hex(start))
                .put("endAddr", hex(start + item.optLong("size")))
                .put("kind", rizinFunctionKind(elf, item))
        }
        return@guarded page("functions", list, limit, cursor).put("workspaceId", workspaceId).put("architecture", elf.architecture).put("source", "rizin")
    }
    val wsName = workspaces[workspaceId]?.source?.name ?: "lib.so"
    val fallback = (elf.symbols + elf.dynSymbols)
        .filter { it.type == "FUNC" && !it.imported }
        .map { JSONObject().put("locator", "so_function:$wsName!${it.name}@${hex(it.value and -2L)}").put("name", it.name).put("offset", it.value and -2L).put("addr", it.value and -2L).put("startAddr", hex(it.value and -2L)).put("endAddr", hex((it.value and -2L) + it.size)).put("size", it.size).put("calls", 0).put("kind", functionKind(elf, it)).put("source", "lief-dynsym-fallback") }
    val warning = if (arr == null) "Rizin function JSON could not be parsed; using LIEF exported FUNC symbols as fallback." else "Rizin returned no functions; using LIEF exported FUNC symbols as fallback."
    page("functions", fallback, limit, cursor).put("workspaceId", workspaceId).put("architecture", elf.architecture).put("source", "lief-dynsym-fallback").put("warning", warning)
}

internal fun EngineRuntime.rzCfg(workspaceId: String, editSessionId: String, locator: String): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val name = LocatorParser.target(locator, "so_function")
    val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
    val funcVa = resolveCodeAddress(bytes, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address could not be resolved", "locator", locator)
    validateCodeAddress(elf, funcVa, false)?.let { return@guarded it }
    val result = NativeEngine.active().cfg(bytes, elf.architecture, funcVa)
    val payload = JSONObject(result).put("workspaceId", workspaceId).put("functionName", name).put("functionVa", hex(funcVa))
    normalizeCfgPayload(payload, elf)
    if (payload.has("error")) return@guarded err("RIZIN_CFG_FAILED", payload.optString("error", "Rizin CFG failed"), "locator", locator, "payload" to payload)
    ok(payload)
}

internal fun EngineRuntime.rzXrefs(workspaceId: String, editSessionId: String, locator: String, direction: String = "to"): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val name = LocatorParser.normalizeSymbol(LocatorParser.target(locator, if (locator.startsWith("so_function:")) "so_function" else "so_symbol"))
    val bareName = name.removePrefix("sym.imp.").removePrefix("sym.")
    val sym = (elf.symbols + elf.dynSymbols).firstOrNull {
        it.name == name || it.name == bareName || it.name == "sym.imp.$bareName" || it.name == "sym.$bareName"
    }
    val importHints = rizinImportStubHints(workspaceId, editSessionId, elf)
    val pltStubVa = importHints.entries.firstOrNull {
        it.value == bareName || it.value == name || "sym.imp.${it.value}" == name
    }?.key
    val atVa = LocatorParser.address(locator)
        ?: LocatorParser.hex(locator)
        ?: resolveCodeAddress(bytes, elf, locator)
        ?: sym?.value?.and(-2L)?.takeIf { it > 0 }
        ?: pltStubVa
        ?: return@guarded err("SYMBOL_NOT_FOUND", "Symbol not found and locator has no address or PLT fallback", "locator", locator)
    val result = NativeEngine.active().xrefs(bytes, elf.architecture, atVa, direction)
    val payload = JSONObject(result)
    val xrefs = payload.optJSONArray("xrefs") ?: JSONArray().also { payload.put("xrefs", it) }
    val seen = HashSet<String>()
    for (i in 0 until xrefs.length()) {
        val item = xrefs.getJSONObject(i)
        if (!item.has("sourceType")) item.put("sourceType", "direct")
        if (!item.has("type") || item.optString("type").isBlank()) item.put("type", "code")
        seen += "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType", item.optString("type"))}:${item.optString("direction")}"
    }
    val relocations = elf.relocations.filter {
        it.symbol == bareName || it.symbol == name || it.symbol == "sym.imp.$bareName" ||
            (LocatorParser.hex(locator) != null && it.offset == atVa) || it.offset == atVa
    }
    val gotSlots = relocations.map { it.offset }.toMutableSet()
    if (direction == "to" || direction == "both") {
        relocations.forEach { relocation ->
            val key = "${relocation.offset}:$atVa:relocation:incoming"
            if (seen.add(key)) {
                xrefs.put(
                    JSONObject()
                        .put("from", relocation.offset)
                        .put("to", atVa)
                        .put("type", "relocation")
                        .put("sourceType", "relocation")
                        .put("direction", "incoming")
                        .put("section", relocation.section)
                        .put("symbol", relocation.symbol)
                        .put("evidence", "${relocation.section} relocation maps ${hex(relocation.offset)} to $bareName"),
                )
            }
        }
        if (elf.architecture == "arm64") {
            val targets = (gotSlots + atVa + listOfNotNull(pltStubVa)).toSet()
            aarch64ComputedXrefs(bytes, elf, targets).forEach { item ->
                val key = "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType")}:incoming"
                if (seen.add(key)) xrefs.put(item)
                if (item.optString("sourceType") == "got") gotSlots += item.optLong("to")
            }
            // Direct BL/B to function body. BL to PLT stub is classified as plt_call.
            if (pltStubVa != null) {
                aarch64BranchXrefs(bytes, elf, setOf(pltStubVa)).forEach { item ->
                    item.put("to", atVa)
                    item.put("pltStub", hex(pltStubVa))
                    item.put("sourceType", "plt_call")
                    item.put("type", "plt_call")
                    item.put("evidence", "AArch64 BL to PLT stub ${hex(pltStubVa)} for $bareName")
                    val key = "${item.optLong("from")}:$atVa:plt_call:incoming"
                    if (seen.add(key)) xrefs.put(item)
                }
            }
            // Direct BL/B to the resolved target itself (non-PLT body / local function).
            aarch64BranchXrefs(bytes, elf, setOf(atVa)).forEach { item ->
                if (pltStubVa != null && item.optLong("to") == pltStubVa) return@forEach
                val key = "${item.optLong("from")}:${item.optLong("to")}:direct_call:incoming"
                if (seen.add(key)) xrefs.put(item)
            }
            // LDR from GOT then BLR Xn (indirect call through GOT).
            aarch64GotBlrXrefs(bytes, elf, gotSlots, atVa, bareName).forEach { item ->
                val key = "${item.optLong("from")}:${item.optLong("to")}:${item.optString("sourceType")}:incoming"
                if (seen.add(key)) xrefs.put(item)
            }
        }
    }
    val bySource = JSONObject()
    for (i in 0 until xrefs.length()) {
        val st = xrefs.getJSONObject(i).optString("sourceType", "direct")
        bySource.put(st, bySource.optInt(st, 0) + 1)
    }
    ok(
        payload
            .put("workspaceId", workspaceId)
            .put("symbolName", bareName)
            .put("direction", direction)
            .put("atVa", hex(atVa))
            .put("pltStubVa", pltStubVa?.let(::hex) ?: JSONObject.NULL)
            .put("resolvedVia", when {
                sym?.imported == true && sym.value == 0L -> "plt_stub"
                pltStubVa != null && atVa == pltStubVa -> "plt_stub"
                else -> "locator"
            })
            .put("relocationSlots", JSONArray(relocations.map { hex(it.offset) }))
            .put("sourceTypeCounts", bySource)
            .put("xrefCount", xrefs.length())
            .put("sourceTypeLegend", JSONObject()
                .put("direct", "Rizin analysis graph edge")
                .put("relocation", "ELF relocation slot")
                .put("got", "ADRP+LDR GOT load")
                .put("computed", "ADRP+ADD computed address")
                .put("direct_call", "direct BL/B to target")
                .put("plt_call", "BL to PLT stub of target")
                .put("got_call", "BLR through GOT slot of target")),
    )
}

private fun EngineRuntime.setOfNotNull(vararg values: Long?): Set<Long> = values.filterNotNull().toSet()

private fun EngineRuntime.aarch64ComputedXrefs(bytes: ByteArray, elf: ElfFile, targets: Set<Long>): List<JSONObject> {
    if (targets.isEmpty()) return emptyList()
    val found = ArrayList<JSONObject>()
    elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 8 }.forEach { section ->
        val start = section.offset.toInt().coerceAtLeast(0)
        val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt()
        var offset = start
        while (offset + 8 <= end) {
            val adrp = littleEndianInt(bytes, offset)
            if (adrp and 0x9f000000.toInt() == 0x90000000.toInt()) {
                val register = adrp and 0x1f
                val imm21 = (((adrp ushr 5) and 0x7ffff) shl 2) or ((adrp ushr 29) and 0x3)
                val signed = if (imm21 and 0x100000 != 0) imm21 or -0x200000 else imm21
                val instructionVa = section.addr + (offset - start)
                val page = (instructionVa and -0x1000L) + (signed.toLong() shl 12)
                for (lookAhead in 1..4) {
                    val nextOffset = offset + lookAhead * 4
                    if (nextOffset + 4 > end) break
                    val next = littleEndianInt(bytes, nextOffset)
                    val baseRegister = (next ushr 5) and 0x1f
                    if (baseRegister != register) continue
                    val addImmediate = next and 0x7f000000 == 0x11000000
                    val loadUnsigned = next and 0x3b000000 == 0x39000000 && next and 0x00400000 != 0
                    if (!addImmediate && !loadUnsigned) continue
                    val immediate = (next ushr 10) and 0xfff
                    val scale = if (addImmediate) if (next and 0x00400000 != 0) 4096L else 1L else 1L shl ((next ushr 30) and 0x3)
                    val target = page + immediate * scale
                    if (target !in targets) continue
                    val sourceType = if (loadUnsigned) "got" else "computed"
                    found += JSONObject()
                        .put("from", instructionVa)
                        .put("to", target)
                        .put("type", sourceType)
                        .put("sourceType", sourceType)
                        .put("direction", "incoming")
                        .put("pairAddress", hex(section.addr + (nextOffset - start)))
                        .put("evidence", "AArch64 ADRP + ${if (loadUnsigned) "LDR" else "ADD"} resolves to ${hex(target)}")
                }
            }
            offset += 4
        }
    }
    return found
}

/** Direct AArch64 BL/B (imm26) call/jump edges to exact targets (function body or PLT stub). */
private fun EngineRuntime.aarch64BranchXrefs(bytes: ByteArray, elf: ElfFile, targets: Set<Long>): List<JSONObject> {
    if (targets.isEmpty()) return emptyList()
    val found = ArrayList<JSONObject>()
    elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 4 }.forEach { section ->
        val start = section.offset.toInt().coerceAtLeast(0)
        val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt() and -4
        var offset = start and -4
        while (offset + 4 <= end) {
            val insn = littleEndianInt(bytes, offset)
            val isBl = insn and 0xFC000000.toInt() == 0x94000000.toInt()
            val isB = insn and 0xFC000000.toInt() == 0x14000000.toInt()
            if (isBl || isB) {
                var imm = insn and 0x03FFFFFF
                if (imm and 0x02000000 != 0) imm = imm or -0x04000000
                val instructionVa = section.addr + (offset - start)
                val target = instructionVa + (imm.toLong() shl 2)
                if (target in targets) {
                    found += JSONObject()
                        .put("from", instructionVa)
                        .put("to", target)
                        .put("type", if (isBl) "call" else "branch")
                        .put("sourceType", "direct_call")
                        .put("direction", "incoming")
                        .put("evidence", "AArch64 ${if (isBl) "BL" else "B"} ${hex(instructionVa)} -> ${hex(target)}")
                }
            }
            offset += 4
        }
    }
    return found
}

/**
 * Recover call sites that load a GOT slot then BLR:
 * ADRP+LDR Xt, [Xn, #off] ... BLR Xt  where the GOT slot belongs to [gotSlots].
 */
private fun EngineRuntime.aarch64GotBlrXrefs(bytes: ByteArray, elf: ElfFile, gotSlots: Set<Long>, symbolVa: Long, symbolName: String): List<JSONObject> {
    if (gotSlots.isEmpty()) return emptyList()
    val found = ArrayList<JSONObject>()
    elf.sections.filter { it.flags and 0x4L != 0L && it.size >= 8 }.forEach { section ->
        val start = section.offset.toInt().coerceAtLeast(0)
        val end = (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt()
        // Map: register -> (gotSlot, loadVa) recently materialised in a local window.
        val live = HashMap<Int, Pair<Long, Long>>()
        var offset = start and -4
        while (offset + 4 <= end) {
            val insn = littleEndianInt(bytes, offset)
            val instructionVa = section.addr + (offset - start)
            // Expire stale register tags after ~24 instructions.
            live.entries.removeAll { instructionVa - it.value.second > 0x60 }
            if (insn and 0x9f000000.toInt() == 0x90000000.toInt()) {
                val register = insn and 0x1f
                val imm21 = (((insn ushr 5) and 0x7ffff) shl 2) or ((insn ushr 29) and 0x3)
                val signed = if (imm21 and 0x100000 != 0) imm21 or -0x200000 else imm21
                val page = (instructionVa and -0x1000L) + (signed.toLong() shl 12)
                for (lookAhead in 1..4) {
                    val nextOffset = offset + lookAhead * 4
                    if (nextOffset + 4 > end) break
                    val next = littleEndianInt(bytes, nextOffset)
                    val baseRegister = (next ushr 5) and 0x1f
                    if (baseRegister != register) continue
                    val loadUnsigned = next and 0x3b000000 == 0x39000000 && next and 0x00400000 != 0
                    if (!loadUnsigned) continue
                    val dest = next and 0x1f
                    val immediate = (next ushr 10) and 0xfff
                    val scale = 1L shl ((next ushr 30) and 0x3)
                    val target = page + immediate * scale
                    if (target in gotSlots) {
                        live[dest] = target to (section.addr + (nextOffset - start))
                    }
                }
            }
            // BLR Xn
            if (insn and 0xFFFFFC1F.toInt() == 0xD63F0000.toInt()) {
                val rn = (insn ushr 5) and 0x1f
                val hit = live[rn]
                if (hit != null) {
                    found += JSONObject()
                        .put("from", instructionVa)
                        .put("to", symbolVa)
                        .put("type", "got_call")
                        .put("sourceType", "got_call")
                        .put("direction", "incoming")
                        .put("gotSlot", hex(hit.first))
                        .put("pairAddress", hex(hit.second))
                        .put("evidence", "AArch64 LDR GOT ${hex(hit.first)} + BLR X$rn for $symbolName")
                }
            }
            // MOV Xd, Xm keeps tag if source tagged
            if (insn and 0xFFE0FFE0.toInt() == 0xAA0003E0.toInt()) {
                val rm = (insn ushr 16) and 0x1f
                val rd = insn and 0x1f
                live[rm]?.let { live[rd] = it }
            }
            offset += 4
        }
    }
    return found
}

internal fun EngineRuntime.rzSearchBytes(workspaceId: String, editSessionId: String, pattern: String, fromVa: Long = 0, toVa: Long = 0): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val result = NativeEngine.active().searchBytes(bytes, elf.architecture, pattern, fromVa, toVa)
    val payload = JSONObject(result).put("workspaceId", workspaceId).put("pattern", pattern).put("architecture", elf.architecture)
    val nativeHits = payload.optJSONArray("hits") ?: JSONArray()
    enrichRizinSearchHits(elf, nativeHits)
    if (nativeHits.length() > 0) return@guarded ok(payload.put("backend", "rizin"))
    if (!payload.has("error")) return@guarded ok(payload.put("backend", "rizin"))
    val fallbackHits = fallbackByteSearch(bytes, elf, pattern, fromVa, toVa)
    if (payload.has("error") && fallbackHits.length() == 0) return@guarded err("RIZIN_SEARCH_FAILED", payload.optString("error", "Rizin byte search failed"), "pattern", pattern, "payload" to payload)
    ok(JSONObject()
        .put("hits", fallbackHits)
        .put("workspaceId", workspaceId)
        .put("pattern", pattern)
        .put("architecture", elf.architecture)
        .put("backend", "file-fallback")
        .put("nativeHitCount", 0)
        .put("nativeError", payload.optString("error", "")))
}

internal fun EngineRuntime.rzScanCrypto(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val result = NativeEngine.active().scanCrypto(bytes, elf.architecture)
    ok(JSONObject(result).put("workspaceId", workspaceId).put("architecture", elf.architecture))
}

internal fun EngineRuntime.rzEsilStep(workspaceId: String, editSessionId: String, locator: String, stepCount: Int = 1): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val name = LocatorParser.target(locator, "so_function")
    val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
    val startVa = resolveCodeAddress(bytes, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address could not be resolved", "locator", locator)
    val result = NativeEngine.active().esilStep(bytes, elf.architecture, startVa, stepCount.coerceIn(1, 1000))
    ok(JSONObject(result).put("workspaceId", workspaceId).put("functionName", name).put("startVa", hex(startVa)).put("stepCount", stepCount))
}

internal fun EngineRuntime.rzDiff(workspaceIdA: String, editSessionIdA: String, workspaceIdB: String, editSessionIdB: String): JSONObject = guarded {
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val bytesA = dataFor(workspaceIdA, editSessionIdA)
    val bytesB = dataFor(workspaceIdB, editSessionIdB)
    if (maxOf(bytesA.size, bytesB.size) <= 1024 * 1024) {
        val ranges = PatchByteUtils.byteDiffRanges(bytesA, bytesB)
        return@guarded ok(JSONObject()
            .put("workspaceIdA", workspaceIdA)
            .put("workspaceIdB", workspaceIdB)
            .put("diffBackend", "fast-byte-diff")
            .put("diffRangeCount", ranges.length())
            .put("diffRanges", ranges)
            .put("sha256A", sha256(bytesA))
            .put("sha256B", sha256(bytesB)))
    }
    val result = NativeEngine.active().diff(bytesA, bytesB)
    ok(JSONObject(result).put("workspaceIdA", workspaceIdA).put("workspaceIdB", workspaceIdB).put("diffBackend", "rizin"))
}

internal fun EngineRuntime.rzCommand(workspaceId: String, editSessionId: String = "", command: String, unsafe: Boolean = false): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    if (command.isBlank()) return@guarded err("INVALID_ARGUMENT", "command must not be blank", "command", command)
    // Align low-level axt/axtj with high-level analyze_xrefs / rizin_api xrefs enrichment.
    parseAxtCommand(command)?.let { (va, asJson) ->
        val enriched = rzXrefs(workspaceId, editSessionId, hex(va), "to")
        if (enriched.optBoolean("ok", false) || enriched.has("xrefs") || enriched.optJSONObject("data") != null) {
            val data = enriched.optJSONObject("data") ?: enriched
            val xrefs = data.optJSONArray("xrefs") ?: JSONArray()
            val text = if (asJson) {
                xrefs.toString()
            } else {
                buildString {
                    for (i in 0 until xrefs.length()) {
                        val x = xrefs.getJSONObject(i)
                        append(hex(x.optLong("from")))
                        append(' ')
                        append(x.optString("sourceType", x.optString("type", "ref")))
                        append(" -> ")
                        append(hex(x.optLong("to")))
                        val ev = x.optString("evidence")
                        if (ev.isNotBlank()) {
                            append("  ; ")
                            append(ev)
                        }
                        append('\n')
                    }
                    if (isEmpty()) append("[]\n")
                }
            }
            return@guarded ok(
                JSONObject()
                    .put("command", command)
                    .put("text", text)
                    .put("xrefs", xrefs)
                    .put("xrefCount", xrefs.length())
                    .put("atVa", hex(va))
                    .put("sourceTypeCounts", data.optJSONObject("sourceTypeCounts") ?: JSONObject())
                    .put("alignedWith", "rizin_api.xrefs / analyze_xrefs")
                    .put("workspaceId", workspaceId)
                    .put("editSessionId", editSessionId)
                    .put("architecture", elf.architecture)
                    .put("unsafe", unsafe)
                    .put("mode", "axt_enriched"),
            )
        }
    }
    val result = NativeEngine.active().command(bytes, elf.architecture, command, unsafe)
    val payload = JSONObject(result).put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("architecture", elf.architecture).put("unsafe", unsafe).put("mode", if (unsafe) "rizin_raw_full" else "rizin_raw_readonly")
    if (payload.has("error")) return@guarded err("RIZIN_COMMAND_FAILED", payload.optString("error", "Rizin command failed"), "command", command, "payload" to payload)
    if (unsafe && payload.optBoolean("mutated", false)) {
        val patched = bytes.copyOf()
        val patches = payload.optJSONArray("patches") ?: JSONArray()
        for (i in 0 until patches.length()) {
            val patch = patches.getJSONObject(i)
            val offset = patch.getInt("offset")
            val patchBytes = hexToBytes(patch.getString("hex")) ?: return@guarded err("RIZIN_COMMAND_FAILED", "Native Rizin returned invalid patch bytes")
            if (offset < 0 || offset + patchBytes.size > patched.size) return@guarded err("RIZIN_COMMAND_FAILED", "Native Rizin patch range exceeds workspace bytes")
            System.arraycopy(patchBytes, 0, patched, offset, patchBytes.size)
        }
        val sessionId = "rizin-${UUID.randomUUID()}"
        workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
        payload.put("editSessionId", sessionId).put("sha256Before", sha256(bytes)).put("sha256After", sha256(patched)).put("patchCount", patches.length())
    }
    ok(payload)
}

/** Parse `axtj @ 0xVA`, `axt @VA`, `s 0xVA; axtj` style commands. */
private fun EngineRuntime.parseAxtCommand(command: String): Pair<Long, Boolean>? {
    val cmd = command.trim()
    val asJson = cmd.contains("axtj", ignoreCase = true)
    if (!cmd.contains("axt", ignoreCase = true)) return null
    // axtj @ 0x1c6f0  /  axt @1c6f0
    Regex("""(?i)axtj?\s*@\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)""").find(cmd)?.groupValues?.getOrNull(1)?.let { LocatorParser.hex(it) }?.let {
        return it to asJson
    }
    // s 0x1c6f0; axtj  or  s 0x1c6f0\naxt
    Regex("""(?i)s\s+(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\s*[;\n\r]+\s*axtj?""").find(cmd)?.groupValues?.getOrNull(1)?.let { LocatorParser.hex(it) }?.let {
        return it to asJson
    }
    return null
}

internal fun EngineRuntime.rzDecompile(workspaceId: String, editSessionId: String = "", locator: String = "", strict: Boolean = true): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded for this ABI")
    val target = locator.ifBlank { hex(elf.entry) }
    val name = LocatorParser.target(target, "so_function")
    val va = resolveCodeAddress(bytes, elf, target) ?: return@guarded err("INVALID_ARGUMENT", "locator must resolve to a function or hex VA", "locator", locator)
    val payload = JSONObject(NativeEngine.active().decompile(bytes, elf.architecture, va))
        .put("workspaceId", workspaceId)
        .put("addr", hex(va))
        .put("requestedBackend", "rizin-ghidra")
        .put("usesBuiltinPseudo", false)
    val decompErr = payload.optString("error")
    if ((decompErr == "DECOMPILER_UNAVAILABLE" || decompErr == "DECOMPILER_FAILED") && strict) {
        return@guarded err(decompErr, payload.optString("message"), "backend", "rizin-ghidra", "payload" to payload)
    }
    if (payload.has("error")) return@guarded ok(payload)
    ok(enrichDecompilePayload(payload, bytes, elf, va, name, target))
}

private fun EngineRuntime.rizinFunctionKind(elf: ElfFile, item: JSONObject): String {
    val name = item.optString("name")
    val addr = item.optLong("addr", -1L)
    val section = if (addr >= 0) sectionFor(elf, addr) else null
    return when {
        section?.name == ".plt" || name.startsWith("sym.imp.") -> "plt_stub"
        item.optLong("size", 0L) in 1..4 && elf.architecture == "arm64" -> "export_thunk"
        else -> "real_function"
    }
}


private fun EngineRuntime.fallbackByteSearch(bytes: ByteArray, elf: ElfFile, pattern: String, fromVa: Long, toVa: Long): JSONArray {
    val parsed = parseHexPattern(pattern) ?: return JSONArray()
    val start = if (fromVa > 0) vaToOffset(elf, fromVa)?.toInt() ?: fromVa.toInt().coerceIn(0, bytes.size) else 0
    val end = if (toVa > 0) vaToOffset(elf, toVa)?.toInt() ?: toVa.toInt().coerceIn(0, bytes.size) else bytes.size
    val boundedStart = start.coerceIn(0, bytes.size)
    val boundedEnd = end.coerceIn(boundedStart, bytes.size)
    val hits = JSONArray()
    var pos = boundedStart
    val maxHits = 5000
    while (pos <= boundedEnd - parsed.size && hits.length() < maxHits) {
        if (parsed.indices.all { parsed[it] == null || bytes[pos + it] == parsed[it] }) {
            val va = offsetToVa(elf, pos.toLong())
            hits.put(JSONObject().put("fileOffset", hex(pos.toLong())).put("va", va?.let(::hex) ?: JSONObject.NULL).put("section", sectionForOffset(elf, pos.toLong())?.name ?: "").put("length", parsed.size))
            pos += parsed.size.coerceAtLeast(1)
        } else {
            pos++
        }
    }
    return hits
}
private fun EngineRuntime.parseHexPattern(pattern: String): List<Byte?>? {
    val tokens = pattern.trim().split(Regex("[\\s,]+"), 0).filter { it.isNotBlank() }
    if (tokens.isEmpty()) return null
    if (tokens.size == 1 && !tokens[0].contains('?')) {
        val compact = tokens[0]
        if (compact.length % 2 != 0 || !compact.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) return null
        return compact.chunked(2).map { it.toInt(16).toByte() }
    }
    return tokens.map { token ->
        if (token == "??" || token == "?") null else token.toIntOrNull(16)?.takeIf { it in 0..255 }?.toByte() ?: return null
    }
}
private fun EngineRuntime.enrichRizinSearchHits(elf: ElfFile, hits: JSONArray) {
    for (i in 0 until hits.length()) {
        val hit = hits.optJSONObject(i) ?: continue
        val addr = hit.optLong("addr", -1L)
        if (addr < 0) continue
        hit.put("hexAddr", hex(addr))
        val fileOffset = vaToOffset(elf, addr)
        if (fileOffset != null) {
            hit.put("fileOffset", hex(fileOffset))
            sectionForOffset(elf, fileOffset)?.let { section ->
                hit.put("section", section.name)
                hit.put("sectionOffset", hex(fileOffset - section.offset))
            }
        }
    }
}
private fun EngineRuntime.normalizeCfgPayload(payload: JSONObject, elf: ElfFile) {
    val blocks = payload.optJSONArray("basicBlocks") ?: payload.optJSONArray("blocks") ?: return
    for (i in 0 until blocks.length()) {
        val block = blocks.optJSONObject(i) ?: continue
        normalizeCfgAddressField(block, "jump", elf)
        normalizeCfgAddressField(block, "fail", elf)
        normalizeCfgAddressField(block, "addr", elf)
        normalizeCfgAddressField(block, "startAddr", elf)
        normalizeCfgAddressField(block, "endAddr", elf)
    }
    val edges = payload.optJSONArray("edges") ?: return
    for (i in 0 until edges.length()) {
        val edge = edges.optJSONObject(i) ?: continue
        normalizeCfgAddressField(edge, "from", elf)
        normalizeCfgAddressField(edge, "to", elf)
    }
    val signalNames = signalImports(elf)
    if (signalNames.isNotEmpty()) {
        payload.put("signalHandling", JSONObject()
            .put("importedSignals", JSONArray(signalNames))
            .put("staticCfgLimitation", "Signal handlers and asynchronous signal delivery are semantic/runtime edges; Rizin basic-block CFG does not automatically add those edges without concrete handler recovery."))
    }
}

private fun EngineRuntime.normalizeCfgAddressField(obj: JSONObject, field: String, elf: ElfFile) {
    if (!obj.has(field) || obj.isNull(field)) return
    val value = obj.opt(field)
    val longValue = when (value) {
        null -> null
        is Number -> value.toLong()
        is String -> LocatorParser.hex(value) ?: value.toLongOrNull()
        else -> null
    }
    if (longValue == null || longValue < 0 || vaToOffset(elf, longValue) == null) {
        obj.put(field, JSONObject.NULL)
        obj.put("${field}Valid", false)
    } else {
        obj.put(field, hex(longValue))
        obj.put("${field}Valid", true)
    }
}
private fun EngineRuntime.enrichDecompilePayload(payload: JSONObject, bytes: ByteArray, elf: ElfFile, va: Long, name: String, locator: String): JSONObject {
    // Keep pseudocode exactly as emitted by the decompiler. Boundary repair happens in native analysis before pdg.
    // Post-pass only DETECTS real content crossing; never hard-clips text.
    val rawPseudo = payload.optString("pseudocode")
    val analyzedSize = payload.optLong("functionSize", 0L).takeIf { it > 0 }
        ?: rizinFunctionSize(bytes, elf, va)?.toLong()
        ?: (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name || (it.value and -2L) == va }?.size?.takeIf { it > 0 }
        ?: 0L
    val end = payload.optLong("functionEnd", 0L).takeIf { it > va }
        ?: if (analyzedSize > 0) va + analyzedSize else 0L
    val nextBoundary = payload.optLong("nextBoundary", 0L).takeIf { it > va }
        ?: (elf.symbols + elf.dynSymbols)
            .asSequence()
            .filter { it.type == "FUNC" && !it.imported }
            .map { (it.value and -2L) to it.name }
            .filter { it.first > va }
            .minByOrNull { it.first }
            ?.first
        ?: 0L
    val nextName = (elf.symbols + elf.dynSymbols)
        .firstOrNull { it.type == "FUNC" && !it.imported && (it.value and -2L) == nextBoundary }
        ?.name
    val resized = payload.optBoolean("resizedToBoundary", false)
    val returnInference = inferReturnType(bytes, elf, va, if (analyzedSize > 0) analyzedSize.toInt() else 0)
    val contentAudit = auditPseudocodeBoundary(rawPseudo, elf, va, end, nextBoundary, name, nextName)
    val contentCrossing = contentAudit.optBoolean("contentCrossing", false)
    val boundaryCrossing = contentCrossing
    val warnings = ArrayList<String>()
    if (resized && nextBoundary > 0) {
        warnings += if (!nextName.isNullOrBlank()) {
            "Analysis function object was resized to next boundary $nextName @ ${hex(nextBoundary)} before decompilation; pseudocode is uncut decompiler output"
        } else {
            "Analysis function object was resized to next boundary @ ${hex(nextBoundary)} before decompilation; pseudocode is uncut decompiler output"
        }
    }
    contentAudit.optJSONArray("warnings")?.let { arr ->
        for (i in 0 until arr.length()) arr.optString(i).takeIf { it.isNotBlank() }?.let(warnings::add)
    }
    return payload
        .put("locator", locator)
        .put("requestedFunction", name)
        .put("pseudocode", rawPseudo)
        .put("functionBounds", JSONObject()
            .put("startAddr", hex(va))
            .put("endAddr", if (end > 0) hex(end) else JSONObject.NULL)
            .put("size", payload.optLong("functionSize", analyzedSize))
            .put("rawSize", payload.optLong("rawFunctionSize", analyzedSize))
            .put("nextBoundary", if (nextBoundary > 0) hex(nextBoundary) else JSONObject.NULL)
            .put("resizedToBoundary", resized)
            .put("anchorCount", payload.optLong("anchorCount", 0L))
            .put("seededNeighbors", payload.optLong("seededNeighbors", 0L))
            .put("source", payload.optString("boundaryStrategy", if (payload.optLong("functionSize", 0L) > 0) "rizin" else "symbol-or-heuristic")))
        .put("boundaryCrossing", boundaryCrossing)
        .put("boundaryCrossingReasons", contentAudit.optJSONArray("reasons") ?: JSONArray())
        .put("pseudocodeCoverage", contentAudit.optJSONObject("coverage") ?: JSONObject()
            .put("declaredStart", hex(va))
            .put("declaredEnd", if (end > 0) hex(end) else JSONObject.NULL)
            .put("contentMinAddr", JSONObject.NULL)
            .put("contentMaxAddr", JSONObject.NULL)
            .put("outOfBoundsAddrs", JSONArray()))
        .put("boundaryWarning", when {
            warnings.isEmpty() -> JSONObject.NULL
            warnings.size == 1 -> warnings[0]
            else -> warnings.joinToString(" | ")
        })
        .put("typeInference", returnInference)
        .put("typeConfidenceNote", "Type fields are inferred heuristics, not proven ABI facts")
        .put("pseudocodePolicy", "never-hard-clip; root-cause analysis-boundary repair + post content-crossing detection only")
}

/**
 * Detect whether decompiler text references code after the declared function end.
 * Never rewrites/clips [pseudocode]. Function-pointer assignments to neighbor names
 * (e.g. `pcStack_x = n0g1a2`) are noted separately from true address overreach.
 */
private fun EngineRuntime.auditPseudocodeBoundary(
    pseudocode: String,
    elf: ElfFile,
    startVa: Long,
    endVa: Long,
    nextBoundary: Long,
    functionName: String,
    nextName: String?,
): JSONObject {
    if (pseudocode.isBlank()) {
        return JSONObject()
            .put("contentCrossing", false)
            .put("reasons", JSONArray())
            .put("warnings", JSONArray())
            .put("coverage", JSONObject()
                .put("declaredStart", hex(startVa))
                .put("declaredEnd", if (endVa > 0) hex(endVa) else JSONObject.NULL)
                .put("contentMinAddr", JSONObject.NULL)
                .put("contentMaxAddr", JSONObject.NULL)
                .put("outOfBoundsAddrs", JSONArray()))
    }
    val hardEnd = when {
        nextBoundary > startVa -> nextBoundary
        endVa > startVa -> endVa
        else -> 0L
    }
    val codeSites = LinkedHashSet<Long>()
    Regex("""(?i)\bcode_r0x([0-9a-f]{3,})\b""").findAll(pseudocode).forEach { m ->
        m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
    }
    Regex("""(?i)\bgoto\s+(?:code_r)?0x([0-9a-f]{3,})\b""").findAll(pseudocode).forEach { m ->
        m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
    }
    Regex("""(?i)WARNING:.*?at\s+0x([0-9a-f]+)""").findAll(pseudocode).forEach { m ->
        m.groupValues[1].toLongOrNull(16)?.let(codeSites::add)
    }
    val allExplicitAddrs = LinkedHashSet<Long>()
    Regex("""(?i)0x([0-9a-f]{3,})""").findAll(pseudocode).forEach { m ->
        m.groupValues[1].toLongOrNull(16)?.let(allExplicitAddrs::add)
    }
    val inRange = ArrayList<Long>()
    val outOfBounds = ArrayList<Long>()
    for (addr in codeSites) {
        // Ignore tiny immediates / stack slots misparsed as bare hex.
        if (addr < 0x1000) continue
        // Keep only addresses that land in executable image space.
        val inImage = sectionFor(elf, addr) != null || elf.programHeaders.any { it.type == 1L && addr >= it.vaddr && addr < it.vaddr + maxOf(it.memsz, it.filesz) }
        if (!inImage) continue
        if (hardEnd > startVa && addr >= hardEnd) {
            outOfBounds += addr
        } else if (endVa > startVa && addr >= endVa && (nextBoundary == 0L || addr < nextBoundary)) {
            outOfBounds += addr
        } else if (addr >= startVa && (hardEnd == 0L || addr < hardEnd)) {
            inRange += addr
        } else if (addr < startVa && sectionFor(elf, addr)?.let { it.flags and 0x4L != 0L } == true) {
            // references to earlier code (helpers/PLT) are normal; track coverage only for later/overrun.
        }
    }
    val reasons = JSONArray()
    val warnings = JSONArray()
    var contentCrossing = false
    if (outOfBounds.isNotEmpty()) {
        contentCrossing = true
        reasons.put("pseudocode_refs_after_boundary")
        warnings.put(
            "Pseudocode references ${outOfBounds.size} address(es) at/after declared boundary " +
                "(first=${hex(outOfBounds.first())}" +
                (if (hardEnd > 0) ", boundary=${hex(hardEnd)}" else "") +
                "); output was NOT clipped",
        )
    }
    val picOutside = codeSites.filter { hardEnd > startVa && it >= hardEnd }
    if (picOutside.isNotEmpty()) {
        contentCrossing = true
        reasons.put("pic_or_warning_after_boundary")
        warnings.put("Decompiler PIC/WARNING sites after boundary: ${picOutside.take(4).joinToString { hex(it) }}")
    }
    val externalCodeRefs = allExplicitAddrs.filter { addr ->
        addr !in codeSites && addr >= 0x1000 &&
            (sectionFor(elf, addr)?.let { it.flags and 0x4L != 0L } == true) &&
            (addr < startVa || (hardEnd > startVa && addr >= hardEnd))
    }.distinct().sorted()
    val allCoverage = (inRange + outOfBounds)
    val coverage = JSONObject()
        .put("declaredStart", hex(startVa))
        .put("declaredEnd", if (endVa > 0) hex(endVa) else JSONObject.NULL)
        .put("hardBoundary", if (hardEnd > 0) hex(hardEnd) else JSONObject.NULL)
        .put("contentMinAddr", allCoverage.minOrNull()?.let(::hex) ?: JSONObject.NULL)
        .put("contentMaxAddr", allCoverage.maxOrNull()?.let(::hex) ?: JSONObject.NULL)
        .put("inBoundsAddrCount", inRange.size)
        .put("outOfBoundsAddrs", JSONArray(outOfBounds.distinct().sorted().take(32).map(::hex)))
        .put("externalCodeRefs", JSONArray(externalCodeRefs.take(64).map(::hex)))
    return JSONObject()
        .put("contentCrossing", contentCrossing)
        .put("reasons", reasons)
        .put("warnings", warnings)
        .put("coverage", coverage)
}
internal fun EngineRuntime.resolveRizinFunctionAddress(bytes: ByteArray, elf: ElfFile, name: String): Long? = rizinFunctions(bytes, elf)
        .firstOrNull { it.optString("name") == name }
        ?.optLong("addr", -1L)
        ?.takeIf { it >= 0 }
        ?.and(-2L)

internal fun EngineRuntime.rizinFunctionSize(bytes: ByteArray, elf: ElfFile, start: Long): Int? = rizinFunctions(bytes, elf)
        .firstOrNull { (it.optLong("addr", -1L) and -2L) == start }
        ?.optLong("size", 0L)
        ?.toInt()
        ?.takeIf { it > 0 }

internal fun EngineRuntime.rizinFunctions(bytes: ByteArray, elf: ElfFile): List<JSONObject> {
        if (!NativeEngine.active().available()) return emptyList()
        val arr = runCatching { JSONArray(NativeEngine.active().functions(bytes, elf.architecture)) }.getOrNull() ?: return emptyList()
        return (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
    }
internal fun EngineRuntime.decompileWithContext(workspaceId: String, editSessionId: String, elf: ElfFile, va: Long, lines: List<String> = emptyList()): JSONObject {
        val thunk = thunkInfoFromLines(lines, va)
        val payload = rzDecompile(workspaceId, editSessionId, hex(va), false)
        val decompileVa = payload.optString("addr", hex(va))
        return payload
            .put("entryVa", hex(va))
            .put("decompiledVa", decompileVa)
            .put("sameAsEntry", decompileVa == hex(va))
            .put("thunk", thunk)
            .put("sourceSection", sectionFor(elf, va)?.name ?: JSONObject.NULL)
    }

internal fun EngineRuntime.rizinImportStubHints(workspaceId: String, editSessionId: String, elf: ElfFile): Map<Long, String> {
        if (!NativeEngine.active().available()) return emptyMap()
        val bytes = runCatching { dataFor(workspaceId, editSessionId) }.getOrNull() ?: return emptyMap()
        val functions = runCatching { JSONArray(NativeEngine.active().functions(bytes, elf.architecture)) }.getOrNull() ?: return emptyMap()
        val hints = linkedMapOf<Long, String>()
        for (i in 0 until functions.length()) {
            val function = functions.optJSONObject(i) ?: continue
            val name = function.optString("name")
            if (!name.startsWith("sym.imp.")) continue
            val address = function.optLong("addr", -1L)
            if (address >= 0) hints[address] = name.removePrefix("sym.imp.")
        }
        return hints
    }
