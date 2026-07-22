package com.soreverse.mcp.engine

import com.soreverse.mcp.core.HexCodec
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.toJsonArray
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.min

internal fun EngineRuntime.list(workspaceId: String, editSessionId: String, view: String, prefix: String, limit: Int, pathHint: String = "", cursor: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val all = when (view) {
            "sections" -> elf.sections.asSequence().withIndex().filter { it.value.name.startsWith(prefix) }.map { (index, section) ->
                EngineJson.sectionJson(name, section, index).put("virtualAddr", hex(section.addr)).put("fileOffset", hex(section.offset)).put("alignment", section.addralign)
            }
            "symbols", "dynsyms" -> (if (view == "dynsyms") elf.dynSymbols else elf.symbols).asSequence().filter { it.name.startsWith(prefix) }.map {
                EngineJson.symbolJson(name, it)
            }
            "functions" -> (elf.symbols + elf.dynSymbols).asSequence().filter { it.type == "FUNC" && !it.imported && it.name.startsWith(prefix) }.map {
                JSONObject().put("locator", "so_function:$name!${it.name}").put("name", it.name).put("demangled", JSONObject.NULL).put("startAddr", hex(it.value and -2L)).put("endAddr", hex((it.value and -2L) + it.size)).put("size", it.size).put("section", sectionFor(elf, it.value)?.name ?: "").put("isExported", it.exported)
            }
            "relocations" -> elf.relocations.asSequence().filter { it.symbol.startsWith(prefix) }.map {
                EngineJson.relocationJson(name, elf, it)
            }
            "strings" -> elf.strings.asSequence().filter { prefix.isBlank() || it.value.contains(prefix, ignoreCase = true) }.map {
                EngineJson.stringJson(name, it)
            }
            "imports" -> elf.dynSymbols.asSequence().filter { it.imported && it.name.startsWith(prefix) }.map {
                JSONObject().put("locator", "so_import:$name!UNRESOLVED!${it.name}").put("soname", JSONObject.NULL).put("resolution", "unresolved_without_symbol_version_mapping").put("neededLibraries", JSONArray(neededLibraries(elf, dataFor(workspaceId, editSessionId)))).put("symbol", it.name).put("symbolLocator", "so_symbol:$name!${it.name}").put("isWeak", it.bind == "WEAK")
            }
            "plt_stubs" -> emptySequence()
            else -> return@guarded err("INVALID_LOCATOR", "Unsupported list view", "view", view)
        }.toList()
        page("items", all, limit, cursor)
    }

internal fun EngineRuntime.readElf(workspaceId: String, editSessionId: String, pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        ok(JSONObject()
            .put("workspaceId", resolvedWorkspaceId)
            .put("ident", JSONObject().put("magic", "7F 45 4C 46").put("class", if (elf.bits == 64) "ELF64" else "ELF32").put("data", elf.endian))
            .put("type", elf.type)
            .put("machine", elf.machineName)
            .put("entryPoint", hex(elf.entry))
            .put("programHeaders", JSONArray(elf.programHeaders.map { EngineJson.phJson(it) }))
            .put("sectionHeaders", elf.sections.map { JSONObject().put("name", it.name).put("type", it.type).put("flags", flags(it.flags)).put("addr", hex(it.addr)).put("offset", hex(it.offset)).put("size", it.size) }.toJsonArray())
            .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { EngineJson.dynJson(it) })))
    }

internal fun EngineRuntime.hexdump(workspaceId: String, editSessionId: String, locator: String, byteOffset: Int, maxBytes: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val bytes = dataFor(workspaceId, editSessionId)
        val sec = ElfSectionResolver.resolve(elf, locator) ?: return@guarded err("SECTION_NOT_FOUND", "Section '${LocatorParser.target(locator, "so_section")}' not found. Call analyze_elf (view=list, subView=sections) to see available sections. If names are duplicated, pass the full locator returned by analyze_elf.", "locator", locator, "availableSections" to elf.sections.mapIndexed { index, section -> EngineJson.sectionKey(section, index) })
        val start = (sec.offset + byteOffset).toInt().coerceIn(0, bytes.size)
        val count = min(maxBytes.coerceIn(1, 4096), bytes.size - start)
        val slice = bytes.copyOfRange(start, start + count)
        ok(JSONObject()
            .put("locator", locator)
            .put("targetName", sec.name)
            .put("targetLocator", EngineJson.sectionLocator(workspaces[workspaceId]?.source?.name ?: "lib.so", sec, elf.sections.indexOf(sec)))
            .put("entrySize", sec.size)
            .put("byteWindow", JSONObject().put("hex", slice.joinToString(" ") { "%02X".format(it) }).put("ascii", slice.map { val c = it.toInt() and 0xff; if (c in 32..126) c.toChar() else '.' }.joinToString("")).put("byteOffset", byteOffset).put("bytesReturned", count))
            .put("targetVersion", sha256(slice)))
    }

internal fun EngineRuntime.strings(workspaceId: String, editSessionId: String, locator: String, prefix: String, limit: Int, pathHint: String = "", cursor: String = "", regex: Boolean = false, ignoreCase: Boolean = true, encoding: String = "", minConfidence: Double = 0.0): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val section = LocatorParser.target(locator, "so_section")
        val encodingFilter = encoding.trim().uppercase()
        val compiledRegex = if (regex && prefix.isNotBlank()) {
            runCatching { Regex(prefix, if (ignoreCase) setOf(RegexOption.IGNORE_CASE) else emptySet()) }
                .getOrElse { return@guarded err("INVALID_REGEX", it.message ?: "Invalid regex", "prefix", prefix) }
        } else null
        val all = elf.strings.asSequence()
            .filter { locator.isBlank() || it.section == section }
            .filter { encodingFilter.isBlank() || it.encoding.equals(encodingFilter, ignoreCase = true) || (encodingFilter == "UTF16" && it.encoding.startsWith("UTF-16", ignoreCase = true)) }
            .filter { it.confidence >= minConfidence }
            .filter { prefix.isBlank() || compiledRegex?.containsMatchIn(it.value) ?: it.value.contains(prefix, ignoreCase = ignoreCase) }
            .map { EngineJson.stringJson(name, it) }
            .toList()
        page("items", all, limit, cursor)
            .put("workspaceId", resolvedWorkspaceId)
            .put("matchMode", if (regex) "regex" else "contains")
            .put("ignoreCase", ignoreCase)
            .put("encoding", if (encodingFilter.isBlank()) "any" else encodingFilter)
            .put("minConfidence", minConfidence)
    }

internal fun EngineRuntime.disasm(workspaceId: String, editSessionId: String, locator: String, limit: Int, cursor: String = "", instructionOffset: Int = 0, byteOffset: Int = 0, maxBytes: Int = 4096, addr: String = "", thumb: Boolean? = null, mode: String = "auto"): JSONObject = guarded {
        val cursorArgs = DisasmCursorCodec.decode(cursor)
        if (cursor.startsWith("disasm:") && cursorArgs == null) return@guarded err("INVALID_CURSOR", "Invalid disassembly cursor", "cursor", cursor)
        val effectiveWorkspaceId = cursorArgs?.workspaceId ?: workspaceId
        val effectiveEditSessionId = cursorArgs?.editSessionId ?: editSessionId
        val effectiveLocator = cursorArgs?.locator ?: locator
        val effectiveLimit = cursorArgs?.limit ?: limit
        val effectiveMaxBytes = cursorArgs?.maxBytes ?: maxBytes
        val elf = elfFor(effectiveWorkspaceId, effectiveEditSessionId)
        val bytes = dataFor(effectiveWorkspaceId, effectiveEditSessionId)
        val directRawVa = LocatorParser.hex(addr.ifBlank { effectiveLocator.takeIf { it.startsWith("0x", ignoreCase = true) } ?: "" })
        val directVa = directRawVa?.let { if (elf.architecture == "arm32") it and -2L else it }
        if (directVa != null) {
            val directThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (directRawVa and 1L) == 1L)
            val addressIssue = validateCodeAddress(elf, directVa, directThumb)
            if (addressIssue != null) return@guarded addressIssue
            val off = vaToOffset(elf, directVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(directVa)} cannot be mapped to a file offset", "addr", hex(directVa))
            val requestedMaxBytes = effectiveMaxBytes.coerceIn(1, 65536)
            val windowBytes = requestedMaxBytes.coerceAtMost(bytes.size - off)
            val slice = bytes.copyOfRange(off, off + windowBytes)
            val rizinText = runCatching { NativeEngine.active().disassemble(slice, elf.architecture, directVa, directThumb, effectiveLimit.coerceIn(1, 5000)) }.getOrDefault("")
            val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
            val symbolHints = disasmSymbolHints(referenceHints, elf, directVa, windowBytes.toLong())
            val lines = annotateDisasmLines(referenceHints, cleanDisasmLines(rizinText, effectiveLimit.coerceIn(1, 5000)))
            val containingFunction = functionContaining(elf, directVa)
            val section = executableSectionFor(elf, directVa)
            return@guarded ok(JSONObject()
                .put("locator", if (effectiveLocator.isBlank()) hex(directVa) else effectiveLocator)
                .put("addr", hex(directVa))
                .put("architecture", elf.architecture)
                .put("disasmMode", if (directThumb) "thumb" else elf.architecture)
                .put("thumb", directThumb)
                .put("disasmBackend", "rizin-address")
                .put("resolvedSection", section?.let { EngineJson.sectionJson(workspaces[effectiveWorkspaceId]?.source?.name ?: "lib.so", it, elf.sections.indexOf(it)) } ?: JSONObject.NULL)
                .put("resolvedFunction", containingFunction?.let { functionIdentityJson(elf, it) } ?: JSONObject.NULL)
                .put("instructionCount", lines.size)
                .put("bytesReturned", windowBytes)
                .put("symbolHints", symbolHints)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, directVa))
                .put("textWindow", JSONObject().put("text", lines.joinToString("\n")).put("startByteOffset", 0).put("endByteOffset", windowBytes).put("startAddress", hex(directVa)).put("requestedMaxBytes", requestedMaxBytes).put("effectiveMaxBytes", windowBytes))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(slice))
                .put("workspaceHash", sha256(bytes))
                .put("pagination", disasmPagination(false, null, lines.size, effectiveLimit, windowBytes, windowBytes)))
        }
        val locatorVa = LocatorParser.address(effectiveLocator) ?: resolveRizinFunctionAddress(bytes, elf, LocatorParser.target(effectiveLocator, "so_function"))
        val name = LocatorParser.target(effectiveLocator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        if (sym == null && locatorVa != null) {
            val addressIssue = validateCodeAddress(elf, locatorVa, false)
            if (addressIssue != null) return@guarded addressIssue
            val off = vaToOffset(elf, locatorVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(locatorVa)} cannot be mapped to a file offset", "locator", effectiveLocator)
            val windowLimit = rizinFunctionSize(bytes, elf, locatorVa) ?: functionByteSizeFromAddress(elf, locatorVa, off, bytes.size)
            val requestedMaxBytes = effectiveMaxBytes.coerceIn(1, 65536)
            val windowBytes = requestedMaxBytes.coerceAtMost(windowLimit)
            val slice = bytes.copyOfRange(off, off + windowBytes)
            val rizinText = runCatching { NativeEngine.active().disassemble(slice, elf.architecture, locatorVa, false, effectiveLimit.coerceIn(1, 5000)) }.getOrDefault("")
            val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
            val symbolHints = disasmSymbolHints(referenceHints, elf, locatorVa, windowBytes.toLong())
            val lines = annotateDisasmLines(referenceHints, cleanDisasmLines(rizinText, effectiveLimit.coerceIn(1, 5000)))
            return@guarded ok(JSONObject()
                .put("locator", effectiveLocator)
                .put("functionName", name)
                .put("addr", hex(locatorVa))
                .put("architecture", elf.architecture)
                .put("disasmMode", elf.architecture)
                .put("thumb", false)
                .put("disasmBackend", "rizin-address")
                .put("instructionCount", lines.size)
                .put("bytesReturned", windowBytes)
                .put("symbolHints", symbolHints)
                .put("resolvedSection", executableSectionFor(elf, locatorVa)?.let { EngineJson.sectionJson(workspaces[effectiveWorkspaceId]?.source?.name ?: "lib.so", it, elf.sections.indexOf(it)) } ?: JSONObject.NULL)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, locatorVa))
                .put("functionBounds", JSONObject().put("startAddr", hex(locatorVa)).put("endAddr", hex(locatorVa + windowLimit)).put("size", windowLimit).put("source", "rizin-locator-address"))
                .put("textWindow", JSONObject().put("text", lines.joinToString("\n")).put("startByteOffset", 0).put("endByteOffset", windowBytes).put("startAddress", hex(locatorVa)).put("requestedMaxBytes", requestedMaxBytes).put("effectiveMaxBytes", windowBytes))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(slice))
                .put("workspaceHash", sha256(bytes))
                .put("pagination", disasmPagination(false, null, lines.size, effectiveLimit, windowBytes, windowBytes)))
        }
        if (sym == null) return@guarded err("FUNCTION_NOT_FOUND", "Function not found", "locator", locator)
        val startAddress = sym.value and -2L
        val symThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L)
        val addressIssue = validateCodeAddress(elf, startAddress, symThumb)
        if (addressIssue != null) return@guarded addressIssue
        val off = vaToOffset(elf, startAddress)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address cannot be mapped")
        val size = (rizinFunctionSize(bytes, elf, startAddress) ?: functionByteSize(elf, sym, off, bytes.size)).coerceIn(0, bytes.size - off)
        val derivedByteOffset = cursorArgs?.byteOffset ?: if (byteOffset > 0) byteOffset else instructionOffsetToByteOffset(elf, sym, instructionOffset)
        val windowOffset = derivedByteOffset.coerceIn(0, size)
        val windowBytes = effectiveMaxBytes.coerceIn(256, 65536).coerceAtMost(size - windowOffset)
        if (windowBytes <= 0) {
            return@guarded ok(JSONObject()
                .put("locator", effectiveLocator)
                .put("functionName", name)
                .put("architecture", elf.architecture)
                .put("disasmMode", elf.architecture)
                .put("instructionCount", 0)
                .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, startAddress))
                .put("textWindow", JSONObject().put("text", "").put("startByteOffset", windowOffset).put("endByteOffset", windowOffset).put("startAddress", hex(startAddress + windowOffset)).put("maxBytes", 0))
                .put("basicBlocks", JSONArray())
                .put("windowHash", sha256(ByteArray(0)))
                .put("workspaceHash", sha256(bytes))
                .put("bytesReturned", 0)
                .put("pagination", disasmPagination(false, null, 0, effectiveLimit, 0, size)))
        }
        val functionBytes = bytes.copyOfRange(off + windowOffset, off + windowOffset + windowBytes)
        val windowAddress = startAddress + windowOffset
        val rizinText = runCatching {
            NativeEngine.active().disassemble(functionBytes, elf.architecture, windowAddress, symThumb, effectiveLimit.coerceIn(1, 5000))
        }.getOrDefault("")
        val usedPseudo = rizinText.isBlank()
        val text = rizinText.ifBlank {
            if (SettingsStore(context).disasmPseudoFallback) pseudoDisasm(elf, sym, functionBytes, effectiveLimit.coerceIn(1, 5000), windowAddress) else ""
        }
        val referenceHints = disasmReferenceHints(effectiveWorkspaceId, effectiveEditSessionId, elf)
        val symbolHints = disasmSymbolHints(referenceHints, elf, windowAddress, windowBytes.toLong())
        val lines = if (usedPseudo) text.lineSequence().take(effectiveLimit.coerceIn(1, 5000)).toList() else annotateDisasmLines(referenceHints, cleanDisasmLines(text, effectiveLimit.coerceIn(1, 5000)))
        val nextByteOffset = windowOffset + windowBytes
        val nextCursor = if (nextByteOffset < size) DisasmCursorCodec.encode(effectiveWorkspaceId, effectiveEditSessionId, effectiveLocator, nextByteOffset, effectiveLimit, effectiveMaxBytes) else null
        ok(JSONObject()
            .put("locator", effectiveLocator)
            .put("functionName", name)
            .put("architecture", elf.architecture)
            .put("disasmMode", if ((thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L))) "thumb" else elf.architecture)
            .put("thumb", thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (sym.value and 1L) == 1L))
            .put("disasmBackend", if (usedPseudo) "pseudo-fallback" else "rizin")
            .put("functionKind", functionKind(elf, sym))
            .put("thunk", thunkInfoFromLines(lines, startAddress))
            .put("instructionCount", lines.size)
            .put("bytesReturned", windowBytes)
            .put("symbolHints", symbolHints)
            .put("pseudocode", decompileWithContext(effectiveWorkspaceId, effectiveEditSessionId, elf, startAddress, lines))
            .put("functionBounds", JSONObject().put("startAddr", hex(startAddress)).put("endAddr", hex(startAddress + size)).put("size", size).put("source", "symbol"))
            .put("textWindow", JSONObject()
                .put("text", lines.joinToString("\n"))
                .put("startByteOffset", windowOffset)
                .put("endByteOffset", nextByteOffset)
                .put("startAddress", hex(windowAddress))
                .put("requestedMaxBytes", effectiveMaxBytes.coerceIn(1, 65536))
                .put("effectiveMaxBytes", windowBytes))
            .put("basicBlocks", JSONArray())
            .put("windowHash", sha256(functionBytes))
            .put("workspaceHash", sha256(bytes))
            .put("pagination", disasmPagination(nextCursor != null, nextCursor, lines.size, effectiveLimit, windowBytes, size)))
    }

internal fun EngineRuntime.outline(workspaceId: String, editSessionId: String, locator: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val name = LocatorParser.target(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name } ?: return@guarded err("FUNCTION_NOT_FOUND", "Function not found", "locator", locator)
        val start = sym.value and -2L
        ok(JSONObject()
            .put("locator", locator)
            .put("name", name)
            .put("demangled", JSONObject.NULL)
            .put("startAddr", hex(start))
            .put("endAddr", hex(start + sym.size))
            .put("size", sym.size)
            .put("instructionCount", if (elf.architecture in setOf("arm32", "arm64", "mips")) (sym.size / 4).toInt() else sym.size.toInt())
            .put("basicBlocks", JSONArray().put(JSONObject().put("index", 0).put("startAddr", hex(start)).put("endAddr", hex(start + sym.size)).put("instructionCount", 0).put("isEntry", true).put("isExit", true).put("successors", JSONArray()).put("predecessors", JSONArray())))
            .put("calledFunctions", JSONArray())
            .put("callers", JSONArray())
            .put("stringReferences", JSONArray())
            .put("dataReferences", JSONArray())
            .put("loops", JSONArray()))
    }

internal fun EngineRuntime.xrefSymbol(workspaceId: String, editSessionId: String, locator: String, refDirection: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val symbol = LocatorParser.target(locator, "so_symbol")
        val incoming = JSONArray()
        elf.relocations.asSequence().filter { it.symbol == symbol }.take(limit).forEach {
            incoming.put(JSONObject().put("type", "relocation").put("from", "so_reloc:${workspaces[workspaceId]?.source?.name}!${it.section}!${it.offset.toString(16)}").put("to", locator).put("address", hex(it.offset)).put("confidence", "high"))
        }
        ok(JSONObject()
            .put("locator", locator)
            .put("refDirection", refDirection)
            .put("incoming", if (refDirection != "outgoing") incoming else JSONArray())
            .put("outgoing", JSONArray())
            .put("pagination", pagination(false, null, incoming.length(), limit, incoming.length())))
    }

internal fun EngineRuntime.xrefString(workspaceId: String, editSessionId: String, locator: String, limit: Int): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        val targetOffset = locator.substringAfterLast('!').toLongOrNull(16) ?: return@guarded err("INVALID_LOCATOR", "Invalid string locator")
        val targetVa = elf.sections.firstOrNull { targetOffset >= it.offset && targetOffset < it.offset + it.size }?.let { it.addr + (targetOffset - it.offset) }
        val refs = JSONArray()
        if (targetVa != null) {
            val bytes = dataFor(workspaceId, editSessionId)
            val pattern = byteArrayOf((targetVa and 0xff).toByte(), ((targetVa shr 8) and 0xff).toByte(), ((targetVa shr 16) and 0xff).toByte(), ((targetVa shr 24) and 0xff).toByte())
            var i = 0
            while (i <= bytes.size - pattern.size && refs.length() < limit) {
                if (pattern.indices.all { bytes[i + it] == pattern[it] }) refs.put(JSONObject().put("type", "literal_address").put("address", hex(i.toLong())).put("locator", locator).put("confidence", "medium"))
                i++
            }
        }
        ok(JSONObject().put("locator", locator).put("references", refs).put("pagination", pagination(false, null, refs.length(), limit, refs.length())))
    }

internal fun EngineRuntime.search(workspaceId: String, editSessionId: String, target: String, query: String, limit: Int, pathHint: String = "", cursor: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint.ifBlank { query })
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val name = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so"
        val key = searchKey(resolvedWorkspaceId, editSessionId, target, query, limit)
        if (searchCache.size > 64) searchCache.clear()
        val hits = searchCache.getOrPut(key) {
            val next = mutableListOf<JSONObject>()
            val needle = query.lowercase()
            if (target in setOf("symbols", "overview")) {
                (elf.symbols + elf.dynSymbols).asSequence()
                    .filter { it.name.lowercase().contains(needle) }
                    .forEach { next += JSONObject().put("target", "symbols").put("locator", "so_symbol:$name!${it.name}").put("snippet", it.name) }
            }
            if (target in setOf("strings", "overview")) {
                elf.strings.asSequence()
                    .filter { it.value.lowercase().contains(needle) }
                    .forEach { next += JSONObject().put("target", "strings").put("locator", "so_string:$name!${it.offset.toString(16)}").put("snippet", it.value.take(160)) }
                rawUtf8Hits(dataFor(resolvedWorkspaceId, editSessionId), query, limit).forEach { (offset, snippet) ->
                    next += JSONObject().put("target", "raw_utf8").put("locator", "so_raw_string:$name!${offset.toString(16)}").put("snippet", snippet)
                }
            }
            next
        }
        page("hits", hits, limit, cursor).put("workspaceId", resolvedWorkspaceId)
    }

internal fun EngineRuntime.readStats(workspaceId: String, editSessionId: String = "", pathHint: String = ""): JSONObject = guarded {
        val resolvedId = resolveWorkspaceId(workspaceId, pathHint)
        val data = if (editSessionId.isNotBlank()) {
            workspaces[resolvedId]?.edits?.get(editSessionId)?.data ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        } else {
            workspaces[resolvedId]?.data ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
        }
        val elf = runCatching { lief.parse(data) }.getOrElse { return@guarded err("ELF_PARSE_FAILED", it.message ?: "ELF parse failed") }
        val sections = elf.sections.size
        val symbols = elf.symbols.size
        val dynSymbols = elf.dynSymbols.size
        val symbolFunctions = (elf.symbols + elf.dynSymbols).count { it.type == "FUNC" && !it.imported }
        val exportedFunctions = elf.dynSymbols.count { it.type == "FUNC" && !it.imported && it.value > 0 }
        val analyzedFunctions = rizinFunctions(data, elf).size
        val pltStubs = elf.relocations.count { it.section.contains("plt", true) }
        val strings = elf.strings.size
        val relocations = elf.relocations.size
        val imports = elf.dynSymbols.count { it.imported }
        val jniExports = (elf.symbols + elf.dynSymbols).count { it.name == "JNI_OnLoad" || it.name.startsWith("Java_") }
        val res = JSONObject()
            .put("workspaceId", resolvedId)
            .put("size", data.size)
            .put("sha256", sha256(data))
            .put("arch", elf.architecture)
            .put("bits", elf.bits)
            .put("endian", elf.endian)
            .put("stripped", elf.symbols.isEmpty())
            .put("counts", JSONObject()
                .put("sections", sections)
                .put("symbols", symbols)
                .put("dynSymbols", dynSymbols)
                .put("functions", analyzedFunctions)
                .put("functionsMeaning", "analyzedFunctions")
                .put("functionsFieldMeaning", "functions==analyzedFunctions (Rizin recovered routines including anonymous/local); symbolFunctions are ELF FUNC symbols; exportedFunctions are dynamic exports; pltStubs are import stubs")
                .put("symbolFunctions", symbolFunctions)
                .put("exportedFunctions", exportedFunctions)
                .put("analyzedFunctions", analyzedFunctions)
                .put("pltStubs", pltStubs)
                .put("strings", strings)
                .put("relocations", relocations)
                .put("imports", imports)
                .put("jniExports", jniExports))
            .put("hint", "Use analyze_elf (view=list, subView=<count-name>) for details. analyze_crypto for security-tinged hints. functionsMeaning explains which function count is default.")
        if (editSessionId.isNotBlank()) res.put("editSessionId", editSessionId)
        ok(res)
    }

internal fun EngineRuntime.assembleRaw(workspaceId: String, editSessionId: String = "", asm: String, addr: Long = 0L, thumb: Boolean? = null, mode: String = "auto"): JSONObject = guarded {
        val elf = elfFor(workspaceId, editSessionId)
        if (asm.isBlank()) return@guarded err("INVALID_ARGUMENT", "asm must not be blank", "asm", asm)
        val rawAddr = addr
        val normalizedAddr = if (elf.architecture == "arm32") rawAddr and -2L else rawAddr
        val useThumb = thumb ?: (mode == "thumb") || (mode == "auto" && elf.architecture == "arm32" && (rawAddr and 1L) == 1L)
        val encoded = NativeEngine.active().assemble(asm, elf.architecture, normalizedAddr, useThumb)
        ok(JSONObject()
            .put("architecture", elf.architecture)
            .put("addr", hex(normalizedAddr))
            .put("thumb", useThumb)
            .put("mode", if (useThumb) "thumb" else elf.architecture)
            .put("asm", asm)
            .put("size", encoded.size)
            .put("hex", encoded.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }))
    }

internal fun EngineRuntime.analyze(workspaceId: String, editSessionId: String, pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val bytes = dataFor(resolvedWorkspaceId, editSessionId)
        val allSymbols = elf.symbols + elf.dynSymbols
        val names = allSymbols.map { it.name }
        val imports = elf.dynSymbols.filter { it.imported }.map { it.name }
        val strings = elf.strings.map { it.value }
        val jniExports = names.filter { it == "JNI_OnLoad" || it.startsWith("Java_") }.take(200)
        val registerNativesHints = (names + strings).filter { it.contains("RegisterNatives", ignoreCase = true) }.distinct().take(50)
        val urlStrings = strings.filter { it.contains("http://") || it.contains("https://") }.take(80)
        val pathStrings = strings.filter { it.startsWith("/") || it.contains("/data/") || it.contains("/sdcard/") }.take(80)
        val commandStrings = strings.filter { value ->
            listOf("su", "sh ", "chmod", "mount", "getprop", "setprop").any { value.contains(it, ignoreCase = true) }
        }.take(80)
        val cryptoImports = imports.filter { it.contains("ssl", true) || it.contains("crypto", true) || it.contains("AES", true) || it.contains("RSA", true) }.distinct()
        val dynamicImports = imports.filter { it in setOf("dlopen", "dlsym", "dlclose", "android_dlopen_ext") }.distinct()
        val symbolFunctions = allSymbols.filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
        val overview = ElfOverviewBuilder.build(
            elf = elf,
            bytes = bytes,
            fileName = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so",
            sha256 = sha256(bytes),
            size = bytes.size.toLong(),
            functionCountHint = symbolFunctions.size,
        )
        ok(JSONObject()
            .put("workspaceId", resolvedWorkspaceId)
            .put("architecture", elf.architecture)
            .put("bits", elf.bits)
            .put("entryPoint", hex(elf.entry))
            .put("stripped", elf.symbols.isEmpty())
            .put("hasDebugInfo", elf.sections.any { it.name.startsWith(".debug") })
            .put("hasJniOnLoad", names.any { it == "JNI_OnLoad" })
            .put("jniExports", jniExports.toJsonArray())
            .put("registerNativesHints", registerNativesHints.toJsonArray())
            .put("dynamicLoaderImports", dynamicImports.toJsonArray())
            .put("cryptoImports", cryptoImports.toJsonArray())
            .put("interestingStrings", JSONObject()
                .put("urls", urlStrings.toJsonArray())
                .put("paths", pathStrings.toJsonArray())
                .put("commands", commandStrings.toJsonArray()))
            .put("counts", JSONObject()
                .put("sections", elf.sections.size)
                .put("symbols", elf.symbols.size)
                .put("dynsyms", elf.dynSymbols.size)
                .put("imports", imports.size)
                .put("relocations", elf.relocations.size)
                .put("strings", elf.strings.size)
                .put("segments", elf.programHeaders.size)
                .put("needed", overview.optJSONArray("neededLibraries")?.length() ?: 0)
                .put("exports", overview.optInt("exportCount"))
                .put("functions", overview.optInt("functionCount")))
            .put("overview", overview))
    }

internal fun EngineRuntime.overview(workspaceId: String, editSessionId: String = "", pathHint: String = ""): JSONObject = guarded {
        val resolvedWorkspaceId = resolveWorkspaceId(workspaceId, pathHint)
        val elf = elfFor(resolvedWorkspaceId, editSessionId)
        val bytes = dataFor(resolvedWorkspaceId, editSessionId)
        val symbolFunctions = (elf.symbols + elf.dynSymbols).filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
        ok(
            ElfOverviewBuilder.build(
                elf = elf,
                bytes = bytes,
                fileName = workspaces[resolvedWorkspaceId]?.source?.name ?: "lib.so",
                sha256 = sha256(bytes),
                size = bytes.size.toLong(),
                functionCountHint = symbolFunctions.size,
            ).put("workspaceId", resolvedWorkspaceId),
        )
    }

internal fun EngineRuntime.continuePage(cursor: String): JSONObject = guarded {
        if (cursor.startsWith("source:")) {
            return@guarded listAvailableSos(cursor = cursor)
        }
        if (cursor.startsWith("disasm:")) {
            return@guarded disasm("", "", "", 0, cursor)
        }
        val slice = pageStore.consume(cursor) ?: return@guarded err("INVALID_CURSOR", "Cursor expired or not found", "cursor", cursor)
        pageJson(slice)
    }

internal fun EngineRuntime.resolveWorkspaceId(workspaceId: String, pathHint: String = ""): String {
        if (workspaceId.isNotBlank() && workspaces.containsKey(workspaceId)) return workspaceId
        if (pathHint.isNotBlank()) return openWorkspace(pathHint, temporary = true).id
        if (workspaceId.isNotBlank()) {
            findSource(workspaceId)?.let { return openWorkspace(it.path, temporary = true).id }
        }
        if (workspaceId.isBlank() && workspaces.size == 1) return workspaces.keys.first()
        error("Workspace not found: $workspaceId")
    }

internal fun EngineRuntime.workspace(id: String): Workspace = workspaces[id] ?: error("Workspace not found: $id")

internal fun EngineRuntime.dataFor(workspaceId: String, editSessionId: String): ByteArray = if (editSessionId.isBlank()) workspace(workspaceId).data else workspace(workspaceId).edits[editSessionId]?.data ?: error("Edit session not found")

internal fun EngineRuntime.elfFor(workspaceId: String, editSessionId: String): ElfFile = if (editSessionId.isBlank()) workspace(workspaceId).elf else lief.parse(dataFor(workspaceId, editSessionId))

internal fun EngineRuntime.acceptedLocatorForms(): JSONArray = JSONArray(
        listOf(
            "0xVA",
            "VA",
            "symbolName",
            "fcn.NAME",
            "fcn.0xVA",
            "fcn.0000VA",
            "fcn.NAME@0xVA",
            "sym.NAME",
            "sym.imp.NAME",
            "so_function:name@0xVA",
            "so_symbol:name@0xVA",
        ),
    )

internal fun EngineRuntime.resolveCodeAddress(bytes: ByteArray, elf: ElfFile, locator: String, explicitAddress: String = ""): Long? {
        val target = locator.ifBlank { explicitAddress }.trim()
        if (target.isEmpty() && explicitAddress.isBlank()) return null
        // Explicit address fields and @addr tails win first (fcn.0000b208@0xb208).
        LocatorParser.hex(explicitAddress)?.let { return it }
        LocatorParser.address(target)?.let { return it }
        LocatorParser.hex(target)?.let { return it }

        val name = LocatorParser.target(target, if (target.startsWith("so_symbol:")) "so_symbol" else "so_function")
        val bare = LocatorParser.normalizeSymbol(name)

        // fcn.0000b208 / fcn.b208 — zero-padded hex function name without 0x
        if (bare.isNotEmpty() && bare.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } && bare.length >= 3) {
            bare.toLongOrNull(16)?.takeIf { it > 0 }?.let { return it }
        }

        (elf.symbols + elf.dynSymbols).firstOrNull {
            it.name == name || it.name == bare || it.name == "sym.$bare" || it.name == "sym.imp.$bare" || it.name == "fcn.$bare"
        }?.value?.and(-2L)?.takeIf { it > 0 }?.let { return it }

        resolveRizinFunctionAddress(bytes, elf, name)?.let { return it }
        if (bare != name) resolveRizinFunctionAddress(bytes, elf, bare)?.let { return it }
        resolveRizinFunctionAddress(bytes, elf, "fcn.$bare")?.let { return it }
        return null
    }

internal fun EngineRuntime.hexToBytes(value: String): ByteArray? = HexCodec.bytes(value)

internal fun EngineRuntime.littleEndianInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8) or ((bytes[offset + 2].toInt() and 0xff) shl 16) or ((bytes[offset + 3].toInt() and 0xff) shl 24)

internal fun EngineRuntime.searchKey(workspaceId: String, editSessionId: String, target: String, query: String, limit: Int): String {
        val revision = if (editSessionId.isBlank()) 0 else workspaces[workspaceId]?.edits?.get(editSessionId)?.revision ?: 0
        return "$workspaceId|$editSessionId|$revision|$target|${query.lowercase()}|${limit.coerceIn(1, 5000)}"
    }

internal fun EngineRuntime.page(field: String, all: List<JSONObject>, limit: Int, cursor: String = ""): JSONObject {
        val slice = cursor.takeIf { it.isNotBlank() }?.let(pageStore::consume) ?: pageStore.first(field, all, limit)
        return pageJson(slice)
    }

internal fun EngineRuntime.pageJson(slice: PageStore.PageSlice): JSONObject {
        return ok(JSONObject()
            .put(slice.field, slice.items.toJsonArray())
            .put("pagination", pagination(slice.hasMore, slice.nextCursor, slice.returnedCount, slice.limit, slice.totalCount)))
    }

internal fun EngineRuntime.functionByteSize(elf: ElfFile, sym: SymbolInfo, fileOffset: Int, fileSize: Int): Int {
        val declared = sym.size.toInt().takeIf { it > 0 }
        if (declared != null) return declared
        val start = sym.value and -2L
        val nextFunction = (elf.symbols + elf.dynSymbols)
            .asSequence()
            .filter { it.type == "FUNC" && !it.imported }
            .map { it.value and -2L }
            .filter { it > start }
            .minOrNull()
        val byNext = nextFunction?.let { (it - start).toInt().takeIf { size -> size > 0 } }
        if (byNext != null) return byNext.coerceAtMost(fileSize - fileOffset)
        val bySection = sectionFor(elf, start)?.let { (it.offset + it.size - fileOffset).toInt().takeIf { size -> size > 0 } }
        return (bySection ?: (fileSize - fileOffset)).coerceAtMost(64 * 1024)
    }

internal fun EngineRuntime.functionByteSizeFromAddress(elf: ElfFile, start: Long, fileOffset: Int, fileSize: Int): Int {
        val nextFunction = (elf.symbols + elf.dynSymbols)
            .asSequence()
            .filter { it.type == "FUNC" && !it.imported }
            .map { it.value and -2L }
            .filter { it > start }
            .minOrNull()
        val byNext = nextFunction?.let { (it - start).toInt().takeIf { size -> size > 0 } }
        if (byNext != null) return byNext.coerceAtMost(fileSize - fileOffset)
        val bySection = sectionFor(elf, start)?.let { (it.offset + it.size - fileOffset).toInt().takeIf { size -> size > 0 } }
        return (bySection ?: (fileSize - fileOffset)).coerceAtMost(64 * 1024)
    }

internal fun EngineRuntime.neededLibraries(elf: ElfFile, bytes: ByteArray): List<String> {
        val dynstr = elf.sections.firstOrNull { it.name == ".dynstr" } ?: return emptyList()
        return elf.dynamicEntries.asSequence()
            .filter { it.tag == 1L }
            .mapNotNull { entry ->
                val start = (dynstr.offset + entry.value).toInt()
                if (start !in bytes.indices) return@mapNotNull null
                var end = start
                while (end < bytes.size && bytes[end].toInt() != 0) end++
                bytes.copyOfRange(start, end).toString(Charsets.UTF_8).takeIf { it.isNotBlank() }
            }
            .distinct()
            .toList()
    }

internal fun EngineRuntime.validateCodeAddress(elf: ElfFile, va: Long, thumb: Boolean): JSONObject? {
        val alignment = if (elf.architecture == "arm32" && thumb) 2L else if (elf.architecture in setOf("arm32", "arm64", "mips")) 4L else 1L
        if (alignment > 1 && va % alignment != 0L) return err("INVALID_ADDRESS_ALIGNMENT", "Address ${hex(va)} is not aligned for ${elf.architecture}${if (thumb) " thumb" else ""}", "addr", hex(va), "alignment" to alignment)
        val section = sectionFor(elf, va) ?: return err("OFFSET_OUT_OF_RANGE", "Address ${hex(va)} does not belong to any section", "addr", hex(va))
        if (!sectionExecutable(section)) return err("NON_EXECUTABLE_ADDRESS", "Address ${hex(va)} is in non-executable section '${section.name}'", "addr", hex(va), "section" to section.name, "sectionFlags" to flags(section.flags))
        return null
    }

internal fun EngineRuntime.sectionExecutable(section: SectionInfo): Boolean = section.flags and 4L != 0L

internal fun EngineRuntime.executableSectionFor(elf: ElfFile, va: Long): SectionInfo? = sectionFor(elf, va)?.takeIf(::sectionExecutable)

internal fun EngineRuntime.functionContaining(elf: ElfFile, va: Long): SymbolInfo? = (elf.symbols + elf.dynSymbols)
        .asSequence()
        .filter { it.type == "FUNC" && !it.imported && it.size > 0 }
        .firstOrNull { va >= (it.value and -2L) && va < (it.value and -2L) + it.size }

internal fun EngineRuntime.functionIdentityJson(elf: ElfFile, sym: SymbolInfo): JSONObject {
        val start = sym.value and -2L
        return JSONObject()
            .put("name", sym.name)
            .put("startAddr", hex(start))
            .put("endAddr", hex(start + sym.size))
            .put("size", sym.size)
            .put("kind", functionKind(elf, sym))
    }

internal fun EngineRuntime.functionKind(elf: ElfFile, sym: SymbolInfo): String {
        val start = sym.value and -2L
        val section = sectionFor(elf, start)
        return when {
            sym.imported -> "import_symbol"
            section?.name == ".plt" || sym.name.startsWith("sym.imp.") -> "plt_stub"
            sym.size in 1..4 && elf.architecture == "arm64" -> "export_thunk"
            else -> "real_function"
        }
    }

internal fun EngineRuntime.thunkInfoFromLines(lines: List<String>, entry: Long): JSONObject {
        val first = lines.firstOrNull().orEmpty()
        val branch = Regex("""^0x[0-9a-fA-F]+:\s+b\s+(0x[0-9a-fA-F]+)""").find(first)
        return if (branch != null) JSONObject()
            .put("isThunk", true)
            .put("entry", hex(entry))
            .put("target", branch.groupValues[1])
        else JSONObject().put("isThunk", false)
    }

internal fun EngineRuntime.instructionOffsetToByteOffset(elf: ElfFile, sym: SymbolInfo, instructionOffset: Int): Int {
        if (instructionOffset <= 0) return 0
        val step = if (elf.architecture == "arm32" && (sym.value and 1L) == 1L) {
            2
        } else if (elf.architecture in setOf("arm32", "arm64", "mips")) {
            4
        } else {
            0
        }
        return if (step > 0) instructionOffset * step else 0
    }

internal fun EngineRuntime.sectionFor(elf: ElfFile, va: Long): SectionInfo? = elf.sections.firstOrNull { it.size > 0 && it.addr != 0L && va >= it.addr && va < it.addr + it.size }

internal fun EngineRuntime.sectionForOffset(elf: ElfFile, offset: Long): SectionInfo? = elf.sections.firstOrNull { offset >= it.offset && offset < it.offset + it.size }

internal fun EngineRuntime.offsetToVa(elf: ElfFile, offset: Long): Long? {
        sectionForOffset(elf, offset)?.let { return it.addr + (offset - it.offset) }
        val ph = elf.programHeaders.firstOrNull { it.type == 1L && offset >= it.offset && offset < it.offset + it.filesz }
        return ph?.let { it.vaddr + (offset - it.offset) }
    }

internal fun EngineRuntime.vaToOffset(elf: ElfFile, va: Long): Long? {
        val ph = elf.programHeaders.firstOrNull { it.type == 1L && va >= it.vaddr && va < it.vaddr + it.filesz }
        if (ph != null) return ph.offset + (va - ph.vaddr)
        sectionFor(elf, va)?.let { return it.offset + (va - it.addr) }
        return null
    }

internal fun EngineRuntime.pseudoDisasm(elf: ElfFile, sym: SymbolInfo, bytes: ByteArray, limit: Int, startAddress: Long = sym.value and -2L): String {
        val step = if (elf.architecture == "arm32" && (sym.value and 1L) == 1L) 2 else if (elf.architecture in setOf("arm32", "arm64", "mips")) 4 else 1
        val lines = mutableListOf<String>()
        var p = 0
        while (p < bytes.size && lines.size < limit) {
            val chunk = bytes.copyOfRange(p, min(p + step, bytes.size))
            lines += "0x${(startAddress + p).toString(16)}: ${chunk.joinToString(" ") { "%02X".format(it) }}    .byte ${chunk.joinToString(", ") { "0x%02x".format(it) }}"
            p += step
        }
        return lines.joinToString("\n")
    }

internal fun EngineRuntime.cleanDisasmLines(text: String, limit: Int): List<String> = text.lineSequence()
        .map { it.trimEnd() }
        .filter { it.isNotBlank() }
        .map { line ->
            val mixed = Regex("""^(0x[0-9a-fA-F]+:)\s+(?:[0-9a-fA-F]{2}\s+){4,}(.+)$""").find(line.trim())
            if (mixed != null) "${mixed.groupValues[1]} ${mixed.groupValues[2].trim()}" else line.trim()
        }
        .filterNot { it.matches(Regex("""^[0-9a-fA-F]{4,}\s+[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){3,}.*""")) }
        .take(limit)
        .toList()

internal fun EngineRuntime.annotateDisasmLines(hints: Map<Long, String>, lines: List<String>): List<String> {
        if (lines.isEmpty()) return lines
        if (hints.isEmpty()) return lines
        val addressPattern = Regex("""\b0x[0-9a-fA-F]+\b""")
        return lines.map { line ->
            if (line.contains("sym.imp.") || line.contains("; import:")) return@map line
            val importNames = addressPattern.findAll(line)
                .mapNotNull { match -> LocatorParser.hex(match.value)?.let(hints::get) }
                .distinct()
                .toList()
            if (importNames.isEmpty()) line else "$line ; import: ${importNames.joinToString(", ") { "sym.imp.$it" }}"
        }
    }

internal fun EngineRuntime.disasmReferenceHints(workspaceId: String, editSessionId: String, elf: ElfFile): Map<Long, String> {
        val hints = importAddressHints(elf).toMutableMap()
        hints.putAll(rizinImportStubHints(workspaceId, editSessionId, elf))
        return hints
    }

internal fun EngineRuntime.disasmSymbolHints(hints: Map<Long, String>, elf: ElfFile, startVa: Long, size: Long): JSONArray {
        val endVa = startVa + size.coerceAtLeast(0)
        val result = JSONArray()
        hints.entries
            .filter { it.key in startVa until endVa }
            .sortedBy { it.key }
            .forEach { (address, name) ->
                result.put(JSONObject()
                    .put("addr", hex(address))
                    .put("symbol", name)
                    .put("kind", "import")
                    .put("display", "sym.imp.$name"))
            }
        signalImports(elf).forEach { signalName ->
            result.put(JSONObject()
                .put("symbol", signalName)
                .put("kind", "signal-import")
                .put("display", "sym.imp.$signalName"))
        }
        return result
    }

internal fun EngineRuntime.importAddressHints(symbolHints: JSONArray): Map<Long, String> {
        val hints = linkedMapOf<Long, String>()
        for (i in 0 until symbolHints.length()) {
            val hint = symbolHints.optJSONObject(i) ?: continue
            val address = LocatorParser.hex(hint.optString("addr")) ?: continue
            val symbol = hint.optString("symbol").takeIf { it.isNotBlank() } ?: continue
            if (hint.optString("kind") == "import") hints[address] = symbol
        }
        return hints
    }

internal fun EngineRuntime.importAddressHints(elf: ElfFile): Map<Long, String> {
        val importedSymbols = elf.dynSymbols.filter { it.imported && it.name.isNotBlank() }.associateBy { it.name }
        val hints = linkedMapOf<Long, String>()
        elf.relocations
            .filter { it.symbol.isNotBlank() && importedSymbols.containsKey(it.symbol) }
            .forEach { relocation -> hints[relocation.offset] = relocation.symbol }
        importedSymbols.values
            .filter { it.value > 0 }
            .forEach { symbol -> hints.putIfAbsent(symbol.value and -2L, symbol.name) }
        return hints
    }

internal fun EngineRuntime.signalImports(elf: ElfFile): List<String> {
        val signalNames = setOf("signal", "sigaction", "sigprocmask", "sigfillset", "sigemptyset", "sigaddset", "pthread_sigmask", "kill", "raise")
        return elf.dynSymbols.asSequence()
            .filter { it.imported && it.name in signalNames }
            .map { it.name }
            .distinct()
            .sorted()
            .toList()
    }

internal fun EngineRuntime.flags(flags: Long) = buildString { if (flags and 1L != 0L) append('W'); if (flags and 2L != 0L) append('A'); if (flags and 4L != 0L) append('X') }

internal fun EngineRuntime.indexOf(data: ByteArray, pattern: ByteArray): Int {
        if (pattern.isEmpty() || data.size < pattern.size) return -1
        for (i in 0..data.size - pattern.size) if (pattern.indices.all { data[i + it] == pattern[it] }) return i
        return -1
    }

internal fun EngineRuntime.allIndexesOf(data: ByteArray, pattern: ByteArray): List<Int> {
        if (pattern.isEmpty() || data.size < pattern.size) return emptyList()
        val out = mutableListOf<Int>()
        var start = 0
        while (start <= data.size - pattern.size) {
            val pos = indexOf(data, pattern, start)
            if (pos < 0) break
            out += pos
            start = pos + pattern.size
        }
        return out
    }

internal fun EngineRuntime.rawUtf8Hits(data: ByteArray, query: String, remaining: Int): List<Pair<Int, String>> {
        if (query.isBlank() || remaining <= 0) return emptyList()
        val pattern = query.toByteArray(Charsets.UTF_8)
        val hits = mutableListOf<Pair<Int, String>>()
        var start = 0
        while (start <= data.size - pattern.size && hits.size < remaining) {
            val pos = indexOf(data, pattern, start)
            if (pos < 0) break
            val from = (pos - 80).coerceAtLeast(0)
            val to = (pos + pattern.size + 80).coerceAtMost(data.size)
            val snippet = data.copyOfRange(from, to).toString(Charsets.UTF_8)
                .filter { it == '\t' || it == '\n' || it == '\r' || !it.isISOControl() }
                .take(160)
            hits += pos to snippet
            start = pos + pattern.size
        }
        return hits
    }

internal fun EngineRuntime.indexOf(data: ByteArray, pattern: ByteArray, startAt: Int): Int {
        if (pattern.isEmpty() || data.size < pattern.size) return -1
        for (i in startAt.coerceAtLeast(0)..data.size - pattern.size) if (pattern.indices.all { data[i + it] == pattern[it] }) return i
        return -1
    }

internal fun EngineRuntime.pagination(hasMore: Boolean, cursor: String?, returned: Int, limit: Int, total: Int) = JSONObject().put("hasMore", hasMore).put("nextCursor", cursor ?: JSONObject.NULL).put("returnedCount", returned).put("limitMax", limit).put("totalAvailableCount", total)

internal fun EngineRuntime.disasmPagination(hasMore: Boolean, cursor: String?, instructionCount: Int, limit: Int, bytesReturned: Int, totalBytes: Int) = JSONObject()
        .put("hasMore", hasMore)
        .put("nextCursor", cursor ?: JSONObject.NULL)
        .put("instructionCount", instructionCount)
        .put("bytesReturned", bytesReturned)
        .put("hasMoreInstructions", hasMore)
        .put("returnedCount", instructionCount)
        .put("limitMax", limit)
        .put("totalAvailableCount", totalBytes)
        .put("totalAvailableBytes", totalBytes)
        .put("units", JSONObject().put("returnedCount", "instructions").put("totalAvailableCount", "bytes"))

internal fun EngineRuntime.inferReturnType(bytes: ByteArray, elf: ElfFile, startVa: Long, size: Int): JSONObject {
        if (elf.architecture != "arm64" || size < 8) return JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        val off = vaToOffset(elf, startVa)?.toInt() ?: return JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        val end = (off + size).coerceAtMost(bytes.size)
        var sawZero = false
        var sawOne = false
        var sawBoolBranch = false
        var i = off
        while (i + 4 <= end) {
            val insn = littleEndianInt(bytes, i)
            // MOV W0, #0 / MOVZ W0, #0
            if (insn == 0x52800000 || insn == 0x2a1f03e0) sawZero = true
            // MOV W0, #1 / MOVZ W0, #1
            if (insn == 0x52800020) sawOne = true
            // TBZ/TBNZ W0, #0, ...
            if ((insn and 0xff00001f.toInt()) == 0x36000000 || (insn and 0xff00001f.toInt()) == 0x37000000) {
                if (((insn ushr 19) and 0x1f) == 0) sawBoolBranch = true
            }
            i += 4
        }
        return when {
            sawZero && sawOne -> JSONObject().put("returnType", "bool|int").put("confidence", if (sawBoolBranch) 0.86 else 0.72).put("evidence", JSONArray(listOfNotNull("mov w0,#0", "mov w0,#1", if (sawBoolBranch) "tbz/tbnz w0,#0" else null)))
            sawBoolBranch -> JSONObject().put("returnType", "bool|int").put("confidence", 0.6).put("evidence", JSONArray(listOf("tbz/tbnz w0,#0")))
            else -> JSONObject().put("returnType", "unknown").put("confidence", 0.0)
        }
    }
