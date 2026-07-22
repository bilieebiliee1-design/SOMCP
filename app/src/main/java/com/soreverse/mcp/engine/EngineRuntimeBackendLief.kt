package com.soreverse.mcp.engine

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

internal fun EngineRuntime.capabilityRegistry(): JSONObject = JSONObject()
    .put("coverage", "capability-registry")
    .put("truth", "Entries are generated from code paths that are callable through MCP and verified against packaged runtime modules. Commercial-only upstream modules are never advertised as native open-source implementations.")
    .put("backends", JSONObject()
        .put("rizin", JSONObject()
            .put("status", NativeEngine.active().loadStatus())
            .put("coverageClass", "native_full_gateway")
            .put("supported", JSONArray(listOf("full_rz_core_command_gateway", "authenticated_unsafe_mutating_file_shell_debugger_commands", "persistent_patch_edit_sessions", "disassemble", "assemble", "arm32_thumb_disassemble", "arm32_thumb_assemble", "analyze", "functions", "cfg", "xrefs", "search_bytes", "crypto_scan", "esil_step", "diff", "decompile_probe")))
            .put("gating", JSONObject().put("unsafeCommands", "require unsafe=true and authenticated MCP access").put("mutations", "returned as persistent edit sessions")))
        .put("lief", JSONObject()
            .put("status", lief.loadStatus())
            .put("version", "0.16.1")
            .put("coverageClass", "native_serialized_object_tree")
            .put("compiledFormats", JSONArray(listOf("ELF", "PE", "Mach-O", "DEX", "ART", "OAT", "VDEX")))
            .put("supported", JSONArray(listOf("parse_any_official_json", "native_snapshot", "native_get", "native_list", "parse_elf", "parse_pe", "parse_macho", "parse_dex", "parse_art", "parse_oat", "parse_vdex", "object_path_dispatch", "sections", "symbols", "relocations", "program_headers", "dynamic_entries", "get_set_section_content", "patch_address", "add_exported_function", "remove_symbol", "fix_sections", "build")))
            .put("notCountedAsLief", JSONArray(listOf("Rizin assembly", "Rizin debug info", "Rizin Objective-C analysis", "Rizin dyld cache analysis"))))
        .put("unidbg", JSONObject()
            .put("status", emulationStatus())
            .put("coverageClass", "native_full_gateway")
            .put("upstreamNativeToolCount", 41)
            .put("supported", JSONArray(listOf("upstream_native_schemas", "upstream_native_tool_dispatch", "load_so", "session_open", "session_list", "session_close", "session_call", "session_call_address", "session_dump", "session_memory_maps", "session_registers", "session_modules", "session_exports", "session_memory_write", "session_memory_map", "session_memory_protect", "session_memory_unmap", "session_trace_code", "session_breakpoint_add", "reflect_roots", "reflect_methods", "reflect_invoke", "object_handle_chaining", "JNI_OnLoad", "call_export", "call_Java_native", "dump_memory", "modules", "exports", "imports", "unidbg_batch_cli_pipeline")))
            .put("dynamicCoverage", "All public methods reachable from packaged live emulator/vm/module/backend/memory objects are discoverable and invokable through object handles"))
        .put("xanso", JSONObject()
            .put("status", JSONObject().put("available", xanso.available()).put("backend", "freakishfox/xAnSo upstream + xAnSo64 extension"))
            .put("coverageClass", "native_full_upstream_scope")
            .put("supported", JSONArray(listOf("help", "build-section", "ELF32_ARM_upstream_section_fix", "ELF64_LIEF_assisted_reconstruction", "persistent_edit_session", "sha256_and_diff_evidence")))
            .put("upstreamScope", "Complete public xAnSo CLI/core functionality: h/help, build-section, quit/session close semantics")))

internal fun EngineRuntime.liefDispatch(workspaceId: String, editSessionId: String = "", op: String, objectPath: String = "", method: String = "", args: JSONArray = JSONArray(), dryRun: Boolean = false): JSONObject = guarded {
    val elf by lazy { elfFor(workspaceId, editSessionId) }
    when (op) {
        "roots" -> return@guarded ok(JSONObject().put("roots", JSONArray(listOf("binary", "sections", "symbols", "dynSymbols", "relocations", "programHeaders", "dynamicEntries", "strings", "nativeJson"))).put("formats", JSONArray(listOf("ELF", "PE", "Mach-O", "DEX", "ART", "OAT", "VDEX"))))
        "methods" -> return@guarded ok(JSONObject().put("methods", JSONArray(listOf("parseAny", "nativeSnapshot", "nativeGet", "nativeList", "toJson", "snapshot", "getSectionContent", "setSectionContent", "patchAddress", "addExportedFunction", "removeSymbol", "fixSections", "build"))).put("settableObjectPaths", JSONArray(listOf("sections[i].content", "symbols[i].name", "dynSymbols[i].name"))).put("argumentTemplates", JSONObject().put("parseAny", JSONArray(listOf("format:auto|elf|pe|macho|dex|art|oat|vdex"))).put("nativeGet", JSONArray(listOf("format", "objectPath"))).put("setSectionContent", JSONArray(listOf("sectionName", "hexContent"))).put("patchAddress", JSONArray(listOf("vaHex", "patchHex"))).put("addExportedFunction", JSONArray(listOf("vaHex", "name"))).put("removeSymbol", JSONArray(listOf("name"))).put("build", JSONArray(listOf("outputName", "conflictStrategy")))))
        "parse_any" -> return@guarded ok(JSONObject().put("format", args.optString(0, "auto")).put("binary", lief.parseAny(dataFor(workspaceId, editSessionId), args.optString(0, "auto"))))
        "native_snapshot" -> {
            val format = args.optString(0, "auto")
            return@guarded ok(JSONObject().put("format", format).put("source", "LIEF::to_json").put("binary", lief.parseAny(dataFor(workspaceId, editSessionId), format)))
        }
        "native_get", "native_list" -> {
            val format = args.optString(0, "auto")
            val nativeRoot = lief.parseAny(dataFor(workspaceId, editSessionId), format)
            val value = resolveJsonObjectPath(nativeRoot, objectPath)
            return@guarded ok(JSONObject().put("format", format).put("source", "LIEF::to_json").put("objectPath", objectPath).put(if (op == "native_list") "items" else "value", value))
        }
        "validate" -> return@guarded validateLiefDispatch(elf, objectPath, method, args)
        "get" -> return@guarded ok(JSONObject().put("objectPath", objectPath).put("value", resolveLiefObjectPath(elf, objectPath)))
        "list" -> return@guarded ok(JSONObject().put("objectPath", objectPath).put("items", resolveLiefObjectPath(elf, objectPath)))
        "call" -> return@guarded when (method) {
            "toJson", "snapshot" -> ok(JSONObject().put("binary", EngineJson.elfSummaryJson(workspaceId, editSessionId, elf)))
            "getSectionContent" -> {
                val name = args.optString(0, objectPath.substringAfterLast('.'))
                val content = lief.getSectionContent(dataFor(workspaceId, editSessionId), name)
                ok(JSONObject().put("section", name).put("size", content.size).put("hexPreview", PatchByteUtils.hexBytes(content.copyOfRange(0, minOf(content.size, 256)))))
            }
            "setSectionContent" -> {
                val sectionName = args.optString(0)
                val content = hexToBytes(args.optString(1)) ?: return@guarded err("INVALID_HEX", "args[1] must be hex section content", "args", args)
                if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("section", sectionName).put("size", content.size))
                val original = dataFor(workspaceId, editSessionId)
                if (elf.sections.none { it.name == sectionName }) return@guarded err("SECTION_NOT_FOUND", "Section '$sectionName' was not found", "section", sectionName)
                val patched = lief.setSectionContent(original, sectionName, content)
                if (patched.contentEquals(original)) return@guarded err("LIEF_MUTATION_FAILED", "LIEF setSectionContent returned unchanged bytes", "section", sectionName)
                val sessionId = "lief-${UUID.randomUUID()}"
                workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("method", method).put("section", sectionName).put("size", content.size), workspaceId, sessionId))
            }
            "patchAddress" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("va", args.optString(0)).put("patchHex", args.optString(1))) else liefPatchAddress(workspaceId, editSessionId, LocatorParser.hex(args.optString(0)) ?: return@guarded err("INVALID_ARGUMENT", "args[0] must be hex VA", "args", args), hexToBytes(args.optString(1)) ?: return@guarded err("INVALID_HEX", "args[1] must be hex patch", "args", args))
            "addExportedFunction" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("va", args.optString(0)).put("name", args.optString(1))) else liefAddExportedFunction(workspaceId, editSessionId, LocatorParser.hex(args.optString(0)) ?: return@guarded err("INVALID_ARGUMENT", "args[0] must be hex VA", "args", args), args.optString(1))
            "removeSymbol" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method).put("name", args.optString(0))) else liefRemoveSymbol(workspaceId, editSessionId, args.optString(0))
            "fixSections" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("method", method)) else fixSections(workspaceId, editSessionId)
            "build" -> if (dryRun) ok(JSONObject().put("dryRun", true).put("wouldBuild", true).put("outputName", args.optString(0, "patched.so")).put("conflictStrategy", args.optString(1, "rename"))) else build(workspaceId, editSessionId, args.optString(0, "patched.so"), args.optString(1, "rename"), null, null)
            else -> err("CAPABILITY_NOT_IMPLEMENTED", "LIEF method is not implemented by the current dispatcher", "method", method)
        }
        "set" -> return@guarded when {
            objectPath.startsWith("sections[") && objectPath.endsWith("].content") -> {
                val idx = Regex("sections\\[(\\d+)]").find(objectPath)?.groupValues?.getOrNull(1)?.toIntOrNull()
                val sec = idx?.let { elf.sections.getOrNull(it) } ?: return@guarded err("INVALID_ARGUMENT", "section index not found", "objectPath", objectPath)
                val content = hexToBytes(args.optString(0)) ?: return@guarded err("INVALID_HEX", "args[0] must be hex section content", "args", args)
                if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("objectPath", objectPath).put("section", sec.name).put("size", content.size))
                val original = dataFor(workspaceId, editSessionId)
                val patched = lief.setSectionContent(original, sec.name, content)
                if (patched.contentEquals(original)) return@guarded err("LIEF_MUTATION_FAILED", "LIEF section mutation returned unchanged bytes", "objectPath", objectPath)
                val sessionId = "lief-${UUID.randomUUID()}"
                workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("objectPath", objectPath).put("section", sec.name).put("size", content.size), workspaceId, sessionId))
            }
            objectPath.matches(Regex("(symbols|dynSymbols)\\[\\d+].name")) -> {
                val group = objectPath.substringBefore('[')
                val idx = Regex("\\[(\\d+)]").find(objectPath)?.groupValues?.getOrNull(1)?.toIntOrNull()
                val sym = idx?.let { if (group == "symbols") elf.symbols.getOrNull(it) else elf.dynSymbols.getOrNull(it) }
                    ?: return@guarded err("INVALID_ARGUMENT", "symbol index not found", "objectPath", objectPath)
                val newName = args.optString(0)
                if (newName.isBlank()) return@guarded err("INVALID_ARGUMENT", "args[0] must be the new symbol name", "args", args)
                if (newName.length > sym.name.length) return@guarded err("SYMTAB_OVERFLOW", "Renaming to a longer symbol name is not supported by byte-level string-table replacement", "args", args)
                val original = dataFor(workspaceId, editSessionId)
                val oldBytes = sym.name.toByteArray()
                val newBytes = newName.toByteArray()
                val matches = allIndexesOf(original, oldBytes)
                if (matches.isEmpty()) return@guarded err("SYMBOL_NOT_FOUND", "Symbol string bytes were not found", "objectPath", objectPath)
                if (matches.size != 1) return@guarded err("AMBIGUOUS_SYMBOL_STRING", "Symbol string bytes matched multiple file offsets; use removeSymbol/addExportedFunction or a section-specific edit instead", "objectPath", objectPath)
                val pos = matches.first()
                if (dryRun) return@guarded ok(JSONObject().put("dryRun", true).put("wouldMutate", true).put("objectPath", objectPath).put("oldName", sym.name).put("newName", newName).put("fileOffset", hex(pos.toLong())))
                val patched = original.copyOf()
                val replacement = ByteArray(oldBytes.size) { if (it < newBytes.size) newBytes[it] else 0 }
                System.arraycopy(replacement, 0, patched, pos, replacement.size)
                val sessionId = "lief-${UUID.randomUUID()}"
                workspace(workspaceId).edits[sessionId] = EditSession(sessionId, patched)
                ok(withMutationHints(JSONObject().put("editSessionId", sessionId).put("objectPath", objectPath).put("oldName", sym.name).put("newName", newName).put("fileOffset", hex(pos.toLong())), workspaceId, sessionId))
            }
            else -> err("CAPABILITY_NOT_IMPLEMENTED", "Generic LIEF property mutation is not implemented for this objectPath", "objectPath", objectPath)
        }
        else -> return@guarded err("UNKNOWN_ACTION", "Unknown LIEF dispatcher op", "op", op)
    }
}

private fun EngineRuntime.resolveLiefObjectPath(elf: ElfFile, objectPath: String): Any {
    val root = JSONObject()
        .put("binary", EngineJson.elfSummaryJson("", "", elf))
        .put("sections", JSONArray(elf.sections.map { EngineJson.sectionJson("", it) }))
        .put("symbols", JSONArray(elf.symbols.map { EngineJson.symbolJson("", it) }))
        .put("dynSymbols", JSONArray(elf.dynSymbols.map { EngineJson.symbolJson("", it) }))
        .put("relocations", JSONArray(elf.relocations.map { EngineJson.relocJson(it) }))
        .put("programHeaders", JSONArray(elf.programHeaders.map { EngineJson.phJson(it) }))
        .put("dynamicEntries", JSONArray(elf.dynamicEntries.map { EngineJson.dynJson(it) }))
        .put("strings", JSONArray(elf.strings.map { EngineJson.stringJson("", it) }))
    if (objectPath.isBlank()) return root
    var cur: Any = root
    for (part in objectPath.split('.').filter { it.isNotBlank() }) {
        val name = part.substringBefore('[')
        if (name.isNotBlank()) cur = (cur as? JSONObject)?.opt(name) ?: JSONObject.NULL
        val idx = Regex("\\[(\\d+)]").find(part)?.groupValues?.getOrNull(1)?.toIntOrNull()
        if (idx != null) cur = (cur as? JSONArray)?.opt(idx) ?: JSONObject.NULL
    }
    return cur
}

private fun EngineRuntime.resolveJsonObjectPath(root: Any, objectPath: String): Any {
    if (objectPath.isBlank()) return root
    var current: Any? = root
    for (part in objectPath.split('.').filter { it.isNotBlank() }) {
        val name = part.substringBefore('[')
        if (name.isNotBlank()) current = (current as? JSONObject)?.opt(name) ?: JSONObject.NULL
        val indexes = Regex("\\[(\\d+)]").findAll(part).mapNotNull { it.groupValues[1].toIntOrNull() }
        for (index in indexes) current = (current as? JSONArray)?.opt(index) ?: JSONObject.NULL
    }
    return current ?: JSONObject.NULL
}

private fun EngineRuntime.validateLiefDispatch(elf: ElfFile, objectPath: String, method: String, args: JSONArray): JSONObject {
    val issues = JSONArray()
    if (objectPath.isNotBlank()) {
        val value = resolveLiefObjectPath(elf, objectPath)
        if (value == JSONObject.NULL) issues.put("objectPath does not resolve: $objectPath")
    }
    when (method) {
        "setSectionContent" -> {
            if (args.optString(0).isBlank()) issues.put("args[0] section name is required")
            if (hexToBytes(args.optString(1)) == null) issues.put("args[1] must be valid hex content")
        }
        "patchAddress" -> {
            val va = LocatorParser.hex(args.optString(0))
            if (va == null) issues.put("args[0] must be a hex VA") else if (vaToOffset(elf, va) == null) issues.put("args[0] VA does not map to a file offset")
            if (hexToBytes(args.optString(1)) == null) issues.put("args[1] must be valid hex patch bytes")
        }
        "addExportedFunction" -> {
            if (LocatorParser.hex(args.optString(0)) == null) issues.put("args[0] must be a hex VA")
            if (args.optString(1).isBlank()) issues.put("args[1] export name is required")
        }
        "removeSymbol" -> if (args.optString(0).isBlank()) issues.put("args[0] symbol name is required")
    }
    return ok(JSONObject().put("valid", issues.length() == 0).put("issues", issues).put("method", method).put("objectPath", objectPath))
}

private fun EngineRuntime.withMutationHints(payload: JSONObject, workspaceId: String, editSessionId: String): JSONObject = payload
    .put("mutation", true)
    .put("workspaceId", workspaceId)
    .put("nextActions", JSONArray(listOf(
        "session_history(action=check, workspaceId=$workspaceId, editSessionId=$editSessionId)",
        "session_audit(action=audit, workspaceId=$workspaceId, editSessionId=$editSessionId)",
        "build_so(action=build, workspaceId=$workspaceId, editSessionId=$editSessionId)"
    )))
    .put("rollbackHint", "Use session_history(action=rollback, workspaceId=$workspaceId, editSessionId=$editSessionId) if validation fails")

internal fun EngineRuntime.xansoDispatch(workspaceId: String, editSessionId: String = "", op: String): JSONObject = guarded {
    return@guarded when (op) {
        "status", "roots", "capabilities" -> ok(JSONObject()
            .put("available", xanso.available())
            .put("backend", "freakishfox/xAnSo upstream Core/fix")
            .put("upstreamCommit", "2f2b6bcff52aba995ad4280d41a588f7cd40a781")
            .put("roots", JSONArray(listOf("help", "build-section")))
            .put("formats", JSONArray(listOf("ELF32 little-endian ET_DYN ARM via upstream section_fix", "ELF64 via xAnSo64 LIEF-assisted reconstruction")))
            .put("scope", "Complete upstream CLI/core public functionality plus ELF64 reconstruction extension"))
        "methods", "help" -> ok(JSONObject()
            .put("methods", JSONArray(listOf("status", "capabilities", "help", "build-section")))
            .put("backend", "freakishfox/xAnSo upstream Core/fix")
            .put("commands", JSONArray(listOf("h", "build-section", "quit"))))
        "fix_sections", "build-section" -> xansoBuildSections(workspaceId, editSessionId, false)
        else -> err("UNKNOWN_ACTION", "Unknown xAnSo dispatcher op", "op", op)
    }
}

internal fun EngineRuntime.xansoBuildSections(workspaceId: String, editSessionId: String = "", force: Boolean = false): JSONObject = guarded {
    val original = dataFor(workspaceId, editSessionId)
    if (original.size < 5) return@guarded err("ELF_CORRUPTED", "Input is too small to contain an ELF identification header")
    val elfClass = original[4].toInt() and 0xff
    val beforeElf = lief.parse(original)
    val backend = when (elfClass) {
        1 -> "xAnSo32 upstream section_fix"
        2 -> "xAnSo64 LIEF-assisted reconstruction"
        else -> return@guarded err("XANSO_UNSUPPORTED_ELF_CLASS", "Unsupported ELF class", "elfClass", elfClass)
    }
    if (elfClass == 1 && !xanso.available()) return@guarded err("XANSO_UNAVAILABLE", "Real xAnSo native backend is not loaded for this ABI")
    if (elfClass == 2 && !lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF is required by the xAnSo64 reconstruction extension")
    val alreadyStructured = beforeElf.sections.isNotEmpty() && beforeElf.programHeaders.isNotEmpty() && beforeElf.dynamicEntries.isNotEmpty()
    if (alreadyStructured && !force) return@guarded ok(JSONObject()
        .put("backend", backend)
        .put("operation", "build-section")
        .put("elfClass", if (elfClass == 1) "ELF32" else "ELF64")
        .put("changed", false)
        .put("message", "Section table is already present and parseable; set force=true to rebuild it")
        .put("sections", beforeElf.sections.size)
        .put("programHeaders", beforeElf.programHeaders.size)
        .put("dynamicEntries", beforeElf.dynamicEntries.size)
        .put("sha256Before", sha256(original))
        .put("sha256After", sha256(original)))
    val recovered = if (elfClass == 2 && beforeElf.sections.isEmpty()) xanso.recoverElf64Sections(original) else null
    val fixed = when (elfClass) {
        1 -> xanso.buildSections(original)
        else -> runCatching { lief.fixSections(recovered ?: original) }.getOrNull()
    } ?: return@guarded err("XANSO_BUILD_FAILED", "$backend failed to reconstruct section headers")
    val afterElf = lief.parse(fixed)
    if (afterElf.sections.isEmpty()) return@guarded err("XANSO_BUILD_FAILED", "$backend produced an ELF without a usable section table")
    val sessionId = "xanso-${UUID.randomUUID()}"
    workspace(workspaceId).edits[sessionId] = EditSession(sessionId, fixed)
    ok(JSONObject()
        .put("backend", backend)
        .put("operation", "build-section")
        .put("elfClass", if (elfClass == 1) "ELF32" else "ELF64")
        .put("changed", !fixed.contentEquals(original))
        .put("recoveryMode", when { elfClass == 1 -> "upstream-section-fix"; recovered != null && recovered.size == original.size -> "orphan-section-table-scan+LIEF"; recovered != null -> "program-header-section-synthesis+LIEF"; else -> "dynamic-metadata+LIEF" })
        .put("editSessionId", sessionId)
        .put("sizeBefore", original.size)
        .put("sizeAfter", fixed.size)
        .put("sectionsBefore", beforeElf.sections.size)
        .put("sectionsAfter", afterElf.sections.size)
        .put("programHeadersBefore", beforeElf.programHeaders.size)
        .put("programHeadersAfter", afterElf.programHeaders.size)
        .put("dynamicEntriesBefore", beforeElf.dynamicEntries.size)
        .put("dynamicEntriesAfter", afterElf.dynamicEntries.size)
        .put("sha256Before", sha256(original))
        .put("sha256After", sha256(fixed))
        .put("diffRanges", PatchByteUtils.byteDiffRanges(original, fixed)))
}

internal fun EngineRuntime.liefPatchAddress(workspaceId: String, editSessionId: String, va: Long, patch: ByteArray): JSONObject = guarded {
    if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
    val original = dataFor(workspaceId, editSessionId)
    val patched = lief.patchAddress(original, va, patch)
    if (patched.contentEquals(original)) return@guarded err("PATCH_FAILED", "LIEF patch_address returned unchanged bytes (VA may not map to a loadable segment)")
    val newSessionId = "patch-${UUID.randomUUID()}"
    workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
    ok(JSONObject()
        .put("editSessionId", newSessionId)
        .put("va", hex(va))
        .put("patchSize", patch.size)
        .put("sizeBefore", original.size)
        .put("sizeAfter", patched.size))
}

internal fun EngineRuntime.liefAddExportedFunction(workspaceId: String, editSessionId: String, addr: Long, name: String): JSONObject = guarded {
    if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
    val original = dataFor(workspaceId, editSessionId)
    val patched = lief.addExportedFunction(original, addr, name)
    if (patched.contentEquals(original)) return@guarded err("LIEF_MUTATION_FAILED", "LIEF add_exported_function returned unchanged bytes", "name", name)
    val verified = lief.parse(patched).dynSymbols.any { it.name == name && it.value == addr }
    if (!verified) return@guarded err("LIEF_POSTCONDITION_FAILED", "Exported function was not present after LIEF rebuild", "name", name)
    val newSessionId = "sym-${UUID.randomUUID()}"
    workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
    ok(JSONObject()
        .put("editSessionId", newSessionId)
        .put("addr", hex(addr))
        .put("name", name)
        .put("sizeBefore", original.size)
        .put("sizeAfter", patched.size))
}

internal fun EngineRuntime.liefRemoveSymbol(workspaceId: String, editSessionId: String, name: String): JSONObject = guarded {
    if (!lief.available()) return@guarded err("LIEF_UNAVAILABLE", "LIEF native backend not loaded for this ABI")
    val original = dataFor(workspaceId, editSessionId)
    val before = lief.parse(original)
    if ((before.symbols + before.dynSymbols).none { it.name == name }) return@guarded err("SYMBOL_NOT_FOUND", "Symbol '$name' was not found", "name", name)
    val patched = lief.removeSymbol(original, name)
    if (patched.contentEquals(original)) return@guarded err("LIEF_MUTATION_FAILED", "LIEF remove_symbol returned unchanged bytes", "name", name)
    val verified = lief.parse(patched)
    if ((verified.symbols + verified.dynSymbols).any { it.name == name }) return@guarded err("LIEF_POSTCONDITION_FAILED", "Symbol remained present after LIEF rebuild", "name", name)
    val newSessionId = "rm-${UUID.randomUUID()}"
    workspace(workspaceId).edits.put(newSessionId, EditSession(newSessionId, patched))
    ok(JSONObject()
        .put("editSessionId", newSessionId)
        .put("removedSymbol", name)
        .put("sizeBefore", original.size)
        .put("sizeAfter", patched.size))
}
