package com.soreverse.mcp.engine

import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject


internal fun EngineRuntime.editHex(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        val strict = settings.editStrictValidation
        val maxPatch = settings.maxPatchBytes
        val elf = lief.parse(session.data)
        val sec = ElfSectionResolver.resolve(elf, locator) ?: return@guarded err("SECTION_NOT_FOUND", "Section '${LocatorParser.target(locator, "so_section")}' not found. Call analyze_elf (view=list, subView=sections) to see available sections. If names are duplicated, pass the full locator returned by analyze_elf.", "locator", locator, "availableSections" to elf.sections.mapIndexed { index, section -> EngineJson.sectionKey(section, index) })
        val sectionName = sec.name
        val previews = JSONArray()
        val pending = mutableListOf<Pair<Int, ByteArray>>()
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            val aliases = listOf("newHex", "hex", "bytes", "data", "rawHex")
                .mapNotNull { key -> edit.optString(key).trim().takeIf { it.isNotBlank() }?.let { key to it } }
                .toMutableList()
            val rawValue = edit.opt("rawValue")
            when (rawValue) {
                is String -> rawValue.trim().takeIf { it.isNotBlank() }?.let { aliases += "rawValue" to it }
                is JSONArray -> aliases += "rawValue" to (0 until rawValue.length()).joinToString("") { index -> "%02x".format(rawValue.optInt(index).coerceIn(0, 255)) }
            }
            val normalizedValues = aliases.map { it.second.replace(Regex("[\\s,]"), "").lowercase() }.distinct()
            if (normalizedValues.size > 1) return@guarded err("CONFLICTING_ARGUMENTS", "Hex aliases contain different values at edit index $i", "edits[$i]", JSONObject(aliases.toMap()))
            val rawHex = aliases.firstOrNull()?.second.orEmpty()
            if (rawHex.isBlank()) {
                return@guarded err("INVALID_ARGUMENT", "Missing newHex (aliases: hex/bytes/data/rawHex/rawValue) for hex edit at index $i", "edits[$i].newHex", null)
            }
            val cleaned = rawHex.replace(" ", "").replace("\t", "").replace("\n", "").replace(",", "")
            if (cleaned.isEmpty() || cleaned.length % 2 != 0 || !cleaned.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                return@guarded err("INVALID_HEX", "newHex must be even-length hex digits, got: $rawHex", "edits[$i].newHex", rawHex)
            }
            val patch = cleaned.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            if (patch.isEmpty()) {
                return@guarded err("INVALID_ARGUMENT", "Decoded patch is empty for hex edit at index $i", "edits[$i].newHex", rawHex)
            }
            if (patch.size > maxPatch) {
                return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes $maxPatch", "edits[$i].newHex", patch.size)
            }
            val relOff = edit.optInt("byteOffset", edit.optInt("offset", Int.MIN_VALUE))
            if (relOff == Int.MIN_VALUE) {
                return@guarded err("INVALID_ARGUMENT", "Missing byteOffset (alias: offset) for hex edit at index $i", "edits[$i].byteOffset", null)
            }
            if (strict && relOff < 0) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "byteOffset must be >= 0, got $relOff", "edits[$i].byteOffset", relOff)
            }
            val off = sec.offset.toInt() + relOff
            if (off < 0 || off + patch.size > session.data.size) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "Hex edit range [${hex(off.toLong())}, +${patch.size}) exceeds file bytes (${session.data.size})", "edits[$i].byteOffset", relOff)
            }
            if (off < sec.offset.toInt() || off + patch.size > sec.offset.toInt() + sec.size.toInt()) {
                return@guarded err("OFFSET_OUT_OF_RANGE", "Hex edit range falls outside section '$sectionName'", "edits[$i].byteOffset", relOff)
            }
            val old = session.data.copyOfRange(off, off + patch.size)
            val preview = JSONObject()
                .put("index", i)
                .put("fileOffset", hex(off.toLong()))
                .put("sectionOffset", hex(relOff.toLong()))
                .put("oldHex", PatchByteUtils.hexBytes(old))
                .put("newHex", PatchByteUtils.hexBytes(patch))
                .put("length", patch.size)
            if (dryRun) {
                previews.put(preview)
            }
            pending += off to patch
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        val nextData = session.data.copyOf()
        val nextPatches = pending.map { (off, patch) ->
            val old = nextData.copyOfRange(off, off + patch.size)
            val record = PatchRecord(System.currentTimeMillis(), "hex", locator, off, PatchByteUtils.hexBytes(old), PatchByteUtils.hexBytes(patch))
            System.arraycopy(patch, 0, nextData, off, patch.size)
            record
        }
        if (nextPatches.isNotEmpty()) maybeAutoSnapshot(session, "hex", settings)
        System.arraycopy(nextData, 0, session.data, 0, session.data.size)
        if (nextPatches.isNotEmpty()) session.undone.clear()
        session.patches += nextPatches
        if (nextPatches.isNotEmpty()) {
            session.revision++
            pageStore.clear()
            searchCache.clear()
        }
        val res = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", pending.size)
        maybeAutoPersist(workspaceId, session, settings)?.let { res.put("autoPersist", it) }
        ok(res)
    }

internal fun EngineRuntime.editHexVa(workspaceId: String, editSessionId: String, va: Long, patch: ByteArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        if (patch.isEmpty()) return@guarded err("INVALID_ARGUMENT", "patchHex decoded to empty bytes", "patchHex", "")
        val settings = SettingsStore(context)
        if (patch.size > settings.maxPatchBytes) return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes ${settings.maxPatchBytes}", "patchHex", patch.size)
        val elf = lief.parse(session.data)
        val off = vaToOffset(elf, va)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Address ${hex(va)} cannot be mapped to a file offset", "va", hex(va))
        if (off < 0 || off + patch.size > session.data.size) return@guarded err("OFFSET_OUT_OF_RANGE", "Patch range [${hex(off.toLong())}, +${patch.size}) exceeds file bytes (${session.data.size})", "va", hex(va))
        val old = session.data.copyOfRange(off, off + patch.size)
        val section = sectionForOffset(elf, off.toLong())
        val preview = JSONObject()
            .put("fileOffset", hex(off.toLong()))
            .put("virtualAddress", hex(va))
            .put("section", section?.name ?: JSONObject.NULL)
            .put("sectionOffset", section?.let { hex(off.toLong() - it.offset) } ?: JSONObject.NULL)
            .put("oldHex", PatchByteUtils.hexBytes(old))
            .put("newHex", PatchByteUtils.hexBytes(patch))
            .put("length", patch.size)
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", JSONArray().put(preview))
                .put("previewCount", 1)
                .put("targetVersion", sha256(session.data)))
        }
        maybeAutoSnapshot(session, "hex-va", settings)
        session.undone.clear()
        session.patches += PatchRecord(System.currentTimeMillis(), "hex-va", "va:${hex(va)}", off, PatchByteUtils.hexBytes(old), PatchByteUtils.hexBytes(patch))
        System.arraycopy(patch, 0, session.data, off, patch.size)
        session.revision++
        pageStore.clear()
        searchCache.clear()
        val res = JSONObject()
            .put("workspaceId", workspaceId)
            .put("editSessionId", editSessionId)
            .put("newTargetVersion", sha256(session.data))
            .put("editCount", session.revision)
            .put("patchCount", session.patches.size)
            .put("applied", 1)
            .put("patch", preview)
        maybeAutoPersist(workspaceId, session, settings)?.let { res.put("autoPersist", it) }
        ok(res)
    }

internal fun EngineRuntime.editAsm(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        val maxPatch = settings.maxPatchBytes
        val elf = lief.parse(session.data)
        val name = LocatorParser.target(locator, "so_function")
        val sym = (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name }
        val startVa = resolveCodeAddress(session.data, elf, locator) ?: return@guarded err("FUNCTION_NOT_FOUND", "Function or address '$name' could not be resolved", "locator", locator, "acceptedForms" to acceptedLocatorForms())
        val base = vaToOffset(elf, startVa)?.toInt() ?: return@guarded err("OFFSET_OUT_OF_RANGE", "Function address ${hex(startVa)} cannot be mapped", "locator", locator)
        val thumb = elf.architecture == "arm32" && ((sym?.value ?: startVa) and 1L) == 1L
        val functionSize = rizinFunctionSize(session.data, elf, startVa) ?: sym?.let { functionByteSize(elf, it, base, session.data.size) } ?: functionByteSizeFromAddress(elf, startVa, base, session.data.size)
        val assembledNop = runCatching { NativeEngine.active().assemble("nop", elf.architecture, startVa, thumb) }
            .getOrElse { PatchByteUtils.architectureNop(elf.architecture, thumb) }
        val nop = if (assembledNop.isEmpty()) PatchByteUtils.architectureNop(elf.architecture, thumb) else assembledNop
        val previews = JSONArray()
        val nextData = session.data.copyOf()
        val nextPatches = mutableListOf<PatchRecord>()
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            val mode = edit.optString("mode", "replace_instructions")
            if (mode in setOf("insert_before", "insert_after", "prepend_function", "append_function", "write_function") && !edit.has("byteLength") && !edit.has("instructionCount")) {
                return@guarded err("UNSUPPORTED_OPERATION", "Insertion-style asm edits require an explicit byteLength or instructionCount because Android native build does not relocate downstream function bytes")
            }
            var range = asmEditRange(edit, startVa, thumb, elf.architecture, nop.size, functionSize)
            val patch = if (mode == "nop_out" || mode == "delete_instructions") {
                PatchByteUtils.repeatBytes(nop, range.second)
            } else {
                val asm = edit.optString("writeAsm", edit.optString("newAsm", edit.optString("asm", edit.optString("assembly", "")))).trim()
                if (asm.isBlank()) return@guarded err("ASM_SYNTAX_ERROR", "Missing writeAsm/newAsm/asm (alias: assembly) for asm edit at index $i")
                val encoded = runCatching { NativeEngine.active().assemble(asm, elf.architecture, startVa + range.first, thumb) }
                    .getOrElse { return@guarded err("ASM_SYNTAX_ERROR", it.message ?: "Assembler failed to encode: $asm") }
                if (encoded.isEmpty()) return@guarded err("ASM_SYNTAX_ERROR", "Assembler produced no bytes for: $asm")
                if (encoded.size > range.second && !edit.has("instructionCount") && !edit.has("byteLength")) {
                    val step = if (thumb) 2 else if (elf.architecture in setOf("arm32", "arm64")) 4 else nop.size.coerceAtLeast(1)
                    val needed = ((encoded.size + step - 1) / step) * step
                    if (range.first + needed <= functionSize) range = range.first to needed
                }
                if (encoded.size > range.second) return@guarded err("SIZE_MISMATCH", "Assembled code (${encoded.size}B) is larger than selected instruction range (${range.second}B). Set instructionCount/byteLength to cover multiple instructions, or split into single-instruction edits.", "edits[$i]", JSONObject().put("assembled", encoded.size).put("range", range.second))
                encoded + PatchByteUtils.repeatBytes(nop, range.second - encoded.size)
            }
            if (patch.size > maxPatch) {
                return@guarded err("PATCH_TOO_LARGE", "Patch size ${patch.size} exceeds maxPatchBytes $maxPatch", "edits[$i]", patch.size)
            }
            val writeOffset = base + range.first
            val old = nextData.copyOfRange(writeOffset, writeOffset + patch.size)
            val asmText = edit.optString("writeAsm", edit.optString("newAsm", edit.optString("asm", edit.optString("assembly", mode))))
            val preview = JSONObject()
                .put("index", i)
                .put("fileOffset", hex(writeOffset.toLong()))
                .put("virtualAddress", hex(startVa + range.first))
                .put("oldHex", PatchByteUtils.hexBytes(old))
                .put("newHex", PatchByteUtils.hexBytes(patch))
                .put("asm", asmText)
                .put("mode", mode)
                .put("length", patch.size)
            if (dryRun) {
                previews.put(preview)
                continue
            }
            nextPatches += PatchRecord(System.currentTimeMillis(), "asm", locator, writeOffset, PatchByteUtils.hexBytes(old), PatchByteUtils.hexBytes(patch), asmText)
            System.arraycopy(patch, 0, nextData, writeOffset, patch.size)
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        if (nextPatches.isNotEmpty()) {
            maybeAutoSnapshot(session, "asm", settings)
            session.undone.clear()
            System.arraycopy(nextData, 0, session.data, 0, session.data.size)
            session.patches += nextPatches
            session.revision++
            pageStore.clear()
            searchCache.clear()
        }
        val resAsm = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", nextPatches.size)
        if (nextPatches.isNotEmpty()) maybeAutoPersist(workspaceId, session, settings)?.let { resAsm.put("autoPersist", it) }
        ok(resAsm)
    }

internal fun EngineRuntime.editSymbol(workspaceId: String, editSessionId: String, locator: String, edits: JSONArray, dryRun: Boolean = false): JSONObject = guarded {
        val session = workspaces[workspaceId]?.edits?.get(editSessionId) ?: return@guarded err("EDIT_SESSION_NOT_FOUND", "Edit session not found")
        val settings = SettingsStore(context)
        val name = LocatorParser.target(locator, "so_symbol")
        val previews = JSONArray()
        val nextData = session.data.copyOf()
        val nextPatches = mutableListOf<PatchRecord>()
        for (i in 0 until edits.length()) {
            val edit = edits.getJSONObject(i)
            if (edit.optString("op", "rename") == "rename") {
                val newName = edit.optString("newName", name)
                if (newName.length > name.length) return@guarded err("SYMTAB_OVERFLOW", "Rename to longer symbol is not supported in native Android build")
                val oldBytes = name.toByteArray()
                val newBytes = newName.toByteArray()
                val pos = indexOf(nextData, oldBytes)
                if (pos < 0) return@guarded err("SYMBOL_NOT_FOUND", "Symbol string not found in SO bytes")
                val replacement = ByteArray(oldBytes.size) { if (it < newBytes.size) newBytes[it] else 0 }
                val preview = JSONObject()
                    .put("index", i)
                    .put("fileOffset", hex(pos.toLong()))
                    .put("oldHex", PatchByteUtils.hexBytes(oldBytes))
                    .put("newHex", PatchByteUtils.hexBytes(replacement))
                    .put("asm", "rename $name -> $newName")
                    .put("length", oldBytes.size)
                if (dryRun) {
                    previews.put(preview)
                    continue
                }
                nextPatches += PatchRecord(System.currentTimeMillis(), "symbol", locator, pos, PatchByteUtils.hexBytes(oldBytes), PatchByteUtils.hexBytes(replacement), "rename $name -> $newName")
                for (j in oldBytes.indices) nextData[pos + j] = if (j < newBytes.size) newBytes[j] else 0
            } else {
                return@guarded err("UNSUPPORTED_OPERATION", "Only same-or-shorter rename is supported")
            }
        }
        if (dryRun) {
            return@guarded ok(JSONObject()
                .put("dryRun", true)
                .put("preview", previews)
                .put("previewCount", previews.length())
                .put("targetVersion", sha256(session.data)))
        }
        if (nextPatches.isNotEmpty()) {
            maybeAutoSnapshot(session, "symbol", settings)
            session.undone.clear()
            System.arraycopy(nextData, 0, session.data, 0, session.data.size)
            session.patches += nextPatches
            session.revision++
            pageStore.clear()
            searchCache.clear()
        }
        val resSym = JSONObject().put("newTargetVersion", sha256(session.data)).put("editCount", session.revision).put("patchCount", session.patches.size).put("applied", nextPatches.size)
        if (nextPatches.isNotEmpty()) maybeAutoPersist(workspaceId, session, settings)?.let { resSym.put("autoPersist", it) }
        ok(resSym)
    }

private fun EngineRuntime.asmEditRange(edit: JSONObject, startVa: Long, thumb: Boolean, architecture: String, fallbackInsnSize: Int, maxBytes: Int): Pair<Int, Int> {
        val step = if (architecture == "arm32" && thumb) 2 else fallbackInsnSize.coerceAtLeast(1)
        if (edit.has("address") && edit.optString("address").isNotBlank()) {
            val addrStr = edit.optString("address").trim().removePrefix("0x").removePrefix("0X")
            val addr = addrStr.toLongOrNull(16)
                ?: throw IllegalArgumentException("address must be a hex VA like 0x978, got ${edit.optString("address")}")
            val off = (addr - startVa).toInt()
            val length = when {
                edit.optInt("byteLength", 0) > 0 -> edit.optInt("byteLength", 0)
                edit.optInt("length", 0) > 0 -> edit.optInt("length", 0)
                edit.has("instructionCount") -> edit.optInt("instructionCount", 1).coerceAtLeast(1) * step
                edit.has("count") -> edit.optInt("count", 1).coerceAtLeast(1) * step
                else -> step
            }
            require(off >= 0 && length > 0 && off + length <= maxBytes) { "Assembly edit address range [${hex(off.toLong())}, +$length) exceeds function bytes ($maxBytes)" }
            return off to length
        }
        if (edit.has("instructionIndex")) {
            val idx = edit.optInt("instructionIndex", 0)
            val count = edit.optInt("instructionCount", edit.optInt("count", 1)).coerceAtLeast(1)
            val off = idx * step
            val length = when {
                edit.optInt("byteLength", 0) > 0 -> edit.optInt("byteLength", 0)
                edit.optInt("length", 0) > 0 -> edit.optInt("length", 0)
                else -> count * step
            }
            require(idx >= 0 && length > 0 && off + length <= maxBytes) { "Assembly edit instruction range exceeds function bytes" }
            return off to length
        }
        val explicitByteOffset = when {
            edit.has("byteOffset") && edit.optInt("byteOffset", 0) != 0 -> edit.optInt("byteOffset", 0)
            edit.has("offset") && edit.optInt("offset", 0) != 0 -> edit.optInt("offset", 0)
            edit.has("byteOffset") && !edit.has("instructionIndex") -> edit.optInt("byteOffset", 0)
            edit.has("offset") && !edit.has("instructionIndex") -> edit.optInt("offset", 0)
            else -> 0
        }
        val length = edit.optInt("byteLength", edit.optInt("length", 0)).takeIf { it > 0 } ?: edit.optInt("instructionCount", edit.optInt("count", 1)).coerceAtLeast(1) * step
        require(explicitByteOffset >= 0 && length > 0 && explicitByteOffset + length <= maxBytes) { "Assembly edit byte range exceeds function bytes" }
        return explicitByteOffset to length
    }
