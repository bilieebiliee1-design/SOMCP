// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Read-only patch verification behind patch_length_guard and patch_apply_verify.
// Nothing here writes: length guard is arithmetic over a proposed patch, and
// apply-verify structurally compares an edited byte image against its original.
package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal object PatchAudit {
    /** Verdict for fitting [patchBytes] into a [byteLength] instruction slot. */
    fun lengthGuard(patchBytes: ByteArray, byteLength: Int, architecture: String, thumb: Boolean): JSONObject {
        val nop = PatchByteUtils.architectureNop(architecture, thumb)
        val patchLen = patchBytes.size
        val verdict = when {
            patchLen == byteLength -> "fits"
            patchLen < byteLength -> "fits_with_fill"
            else -> "too_long"
        }
        val remainder = (byteLength - patchLen).coerceAtLeast(0)
        val fill = if (verdict == "fits_with_fill") PatchByteUtils.repeatBytes(nop, remainder) else ByteArray(0)
        val result = JSONObject()
            .put("verdict", verdict)
            .put("patchBytes", patchLen)
            .put("targetBytes", byteLength)
            .put("remainder", remainder)
            .put("architecture", architecture)
            .put("thumb", thumb)
            .put("nopBytes", PatchByteUtils.hexBytes(nop))
        if (fill.isNotEmpty()) result.put("suggestedFill", PatchByteUtils.hexBytes(fill))
        if (verdict == "too_long") {
            result.put("detail", "Patch is ${patchLen - byteLength} byte(s) longer than the target slot; shorten the patch or enlarge the slot.")
        }
        if (patchLen == 0) result.put("detail", "Patch is empty; nothing would be written.")
        return result
    }

    /**
     * Structural comparison of an edited image against the original it came
     * from. Byte differences are expected; what must not change silently is the
     * ELF skeleton the runtime relies on (entry, header tables, reloc targets)
     * plus any new W+X section.
     */
    fun applyVerify(original: ByteArray, edited: ByteArray, originalElf: ElfFile, editedElf: ElfFile): JSONObject {
        val checks = JSONArray()
        var minSize = minOf(original.size, edited.size)
        var diffCount = 0L
        val diffs = JSONArray()
        var i = 0
        while (i < minSize) {
            if (original[i] != edited[i]) {
                diffCount++
                if (diffs.length() < 32) {
                    diffs.put(JSONObject().put("offset", "0x${i.toString(16)}").put("from", original[i].toInt() and 0xff).put("to", edited[i].toInt() and 0xff))
                }
            }
            i++
        }
        checks.put(
            JSONObject()
                .put("check", "byte_differences")
                .put("status", if (diffCount == 0L) "unchanged" else "changed")
                .put("changedBytes", diffCount)
                .put("sizeDelta", edited.size - original.size)
                .put("samples", diffs)
        )
        var skeletonChanged = false

        fun check(name: String, changed: Boolean, detail: String) {
            if (changed) skeletonChanged = true
            checks.put(JSONObject().put("check", name).put("status", if (changed) "changed" else "preserved").put("detail", detail))
        }
        check("entry_point", originalElf.entry != editedElf.entry, "entry 0x${originalElf.entry.toString(16)} -> 0x${editedElf.entry.toString(16)}")
        check("section_count", originalElf.sections.size != editedElf.sections.size, "${originalElf.sections.size} -> ${editedElf.sections.size}")
        check(
            "program_header_count",
            originalElf.programHeaders.size != editedElf.programHeaders.size,
            "${originalElf.programHeaders.size} -> ${editedElf.programHeaders.size}"
        )
        val origRelocs = originalElf.relocations.map { it.offset to it.type }.toSet()
        val editedRelocs = editedElf.relocations.map { it.offset to it.type }.toSet()
        check("relocation_targets", origRelocs != editedRelocs, "reloc (offset,type) sets differ")
        val origWx = originalElf.sections.count { it.flags and 0x1L != 0L && it.flags and 0x4L != 0L }
        val editedWx = editedElf.sections.count { it.flags and 0x1L != 0L && it.flags and 0x4L != 0L }
        check("wx_section_delta", editedWx > origWx, "W+X sections $origWx -> $editedWx")
        val hardFails = mutableListOf<String>()
        if (edited.size < 16 || edited[0] != 0x7f.toByte() || edited[1] != 'E'.code.toByte()) hardFails += "edited image lost the ELF magic"
        if (editedElf.sections.isNotEmpty() &&
            originalElf.sections.isNotEmpty() &&
            editedElf.sections.size < originalElf.sections.size
        ) {
            hardFails += "section table shrank (${originalElf.sections.size} -> ${editedElf.sections.size})"
        }
        val verdict = when {
            hardFails.isNotEmpty() -> "fail"
            skeletonChanged -> "warn"
            else -> "pass"
        }
        return JSONObject()
            .put("verdict", verdict)
            .put("checks", checks)
            .put("hardFails", JSONArray(hardFails))
            .put(
                "method",
                "Compares the edited image with its original: byte diffs are reported as information; " +
                    "skeleton changes (entry, header tables, reloc target set, W+X growth) drive the verdict."
            )
    }
}
