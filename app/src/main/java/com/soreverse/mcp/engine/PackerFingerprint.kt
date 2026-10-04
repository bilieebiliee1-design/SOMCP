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

import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject

/** One packer/protector verdict with the evidence that produced it. */
internal data class PackerVerdict(val id: String, val name: String, val vendor: String, val confidence: String, val score: Int, val evidence: List<String>)

/**
 * Static packer / commercial-protector fingerprinting.
 *
 * A protected `.so` behaves differently from a clean one in ways that are
 * cheap to measure and hard to unsee: the real entry point is not `.text`'s
 * start, one section dominates the file with near-maximal entropy, section
 * names are non-standard or deliberately empty, or a known vendor marker sits
 * in the data. This detector turns those signals into a ranked verdict.
 *
 * Every signal here is a *hint*, not proof, so the output carries the evidence
 * alongside the score: a false positive on a stripped-but-unprotected library
 * must be visible to the caller rather than silently asserted. Nothing is
 * executed and no network lookup is performed, so it is safe on untrusted
 * input.
 */
internal object PackerFingerprint {

    private const val ENTROPY_WINDOW = 4096
    private const val HIGH_ENTROPY = 7.2

    private val KNOWN_SECTION_NAMES = setOf(
        ".text", ".rodata", ".data", ".bss", ".init", ".fini", ".plt", ".got",
        ".got.plt", ".dynamic", ".dynsym", ".dynstr", ".symtab", ".strtab",
        ".shstrtab", ".note", ".note.android.ident", ".note.gnu.build-id",
        ".gnu.hash", ".hash", ".rel.dyn", ".rel.plt", ".rela.dyn", ".rela.plt",
        ".init_array", ".fini_array", ".eh_frame", ".eh_frame_hdr",
        ".ARM.exidx", ".ARM.extab", ".ARM.attributes", ".gnu.version",
        ".gnu.version_r", ".interp", ".tbss", ".tdata", ".preinit_array",
        ".data.rel.ro", ".gnu.linkonce.b", ".sdata", ".sbss", ".stab", ".stabstr",
        ".MIPS.abiflags", ".reginfo", ".pdr", ".got2", ".ctors", ".dtors",
        ".jcr", ".vfp11_veneer", ".v4_bx", ".iplt", ".rel.iplt", ".ARM.v6k"
    )

    private fun hex(v: Long) = "0x${v.toString(16)}"

    /** Shannon entropy in bits/byte over [bytes]; 0.0 for an empty input. */
    fun shannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val counts = IntArray(256)
        bytes.forEach { counts[it.toInt() and 0xff]++ }
        val n = bytes.size.toDouble()
        var sum = 0.0
        for (c in counts) {
            if (c == 0) continue
            val p = c / n
            sum -= p * (Math.log(p) / Math.log(2.0))
        }
        return sum
    }

    private fun sectionBytes(data: ByteArray, sec: SectionInfo): ByteArray {
        if (sec.type == 8L || sec.size <= 0) return ByteArray(0)
        val start = sec.offset.toInt()
        if (start < 0 || start >= data.size) return ByteArray(0)
        val len = minOf(data.size - start, sec.size.toInt())
        return data.copyOfRange(start, start + len)
    }

    /**
     * Vendor markers are plain ASCII tags that these vendors embed in their
     * stub. Kept as readable strings so a hit is self-explanatory in the
     * evidence output.
     */
    private val VENDOR_MARKERS = listOf(
        Triple("360", "Qihoo 360", "libjiagu"),
        Triple("bangcle", "Bangcle / SecNeo", "SecNeo"),
        Triple("ijiami", "Ijiami", "ijiami"),
        Triple("ali", "Ali (Alibaba)", "libmobisec"),
        Triple("secneo", "SecNeo", "SecNeo"),
        Triple("tencent", "Tencent Legu", "libshella"),
        Triple("legu", "Tencent Legu", "libshella"),
        Triple("upx", "UPX", "UPX!"),
        Triple("bangcle_self", "Bangcle / SecNeo", "bangcle_self")
    )

    fun analyze(elf: ElfFile): JSONObject {
        val data = elf.data
        val evidence = mutableListOf<String>()
        val verdicts = linkedMapOf<String, PackerVerdict>()

        fun add(id: String, name: String, vendor: String, points: Int, reason: String, confidence: String) {
            evidence.add(reason)
            val existing = verdicts[id]
            val score = (existing?.score ?: 0) + points
            // Confidence only ever ratchets upward as more signals pile up.
            val order = mapOf("low" to 0, "medium" to 1, "high" to 2)
            val best = existing?.confidence?.let { order[it] ?: 0 } ?: -1
            verdicts[id] = PackerVerdict(
                id = id,
                name = name,
                vendor = vendor,
                confidence = if ((order[confidence] ?: 0) >= best) confidence else existing?.confidence ?: confidence,
                score = score,
                evidence = (existing?.evidence ?: emptyList()) + reason
            )
        }

        // ── Vendor marker scan ──
        val asciiView = buildString {
            data.forEach { b ->
                val v = b.toInt() and 0xff
                append(if (v in 0x20..0x7e) v.toChar() else ' ')
            }
        }
        for ((id, name, marker) in VENDOR_MARKERS) {
            val present = asciiView.contains(marker)
            if (present) {
                add(
                    id,
                    name,
                    name,
                    60,
                    "Marker string '$marker' present in binary",
                    if (id == "upx") "high" else "medium"
                )
            }
        }

        // ── Section-name analysis ──
        val named = elf.sections.map { it.name }.filter { it.isNotBlank() }
        val unknownNames = named.filterNot { it in KNOWN_SECTION_NAMES }
        if (unknownNames.isNotEmpty()) {
            add(
                "nonstandard_sections",
                "Non-standard section layout",
                "unknown",
                20,
                "Unrecognised section names: ${unknownNames.take(6).joinToString(", ")}",
                "low"
            )
        }
        val blankNamed = elf.sections.count { it.name.isBlank() && it.size > 0 }
        if (blankNamed >= 2) {
            add(
                "stripped_section_names",
                "Stripped / anonymised section names",
                "unknown",
                15,
                "$blankNamed non-empty sections have blank names",
                "low"
            )
        }

        // ── Entropy analysis per section ──
        val highEntropySections = mutableListOf<String>()
        for (sec in elf.sections) {
            val bytes = sectionBytes(data, sec)
            if (bytes.size < ENTROPY_WINDOW) continue
            val entropy = shannonEntropy(bytes.copyOfRange(0, minOf(bytes.size, ENTROPY_WINDOW)))
            if (entropy >= HIGH_ENTROPY) {
                highEntropySections.add("${sec.name.ifBlank { "<blank>" }}@${hex(sec.addr)}(${"%.2f".format(entropy)})")
            }
        }
        if (highEntropySections.isNotEmpty()) {
            add(
                "high_entropy_sections",
                "High-entropy (likely encrypted/compressed) sections",
                "unknown",
                25,
                "${highEntropySections.size} section(s) above $HIGH_ENTROPY bits/byte: ${highEntropySections.take(4).joinToString(", ")}",
                "medium"
            )
        }

        // ── Entry point sanity ──
        val textSec = elf.sections.firstOrNull { it.name == ".text" && it.addr != 0L }
        if (textSec != null && elf.entry != 0L) {
            if (elf.entry < textSec.addr || elf.entry >= textSec.addr + textSec.size) {
                add(
                    "entry_outside_text",
                    "Entry point outside .text",
                    "unknown",
                    45,
                    "e_entry=${hex(elf.entry)} is outside .text [${hex(textSec.addr)}, ${hex(textSec.addr + textSec.size)}) — typical of a packer stub",
                    "high"
                )
            }
        }

        // ── Missing section table (fully stripped) ──
        if (elf.sections.isEmpty()) {
            add(
                "no_section_table",
                "No section table",
                "unknown",
                30,
                "Section table is absent; file may be fully stripped or intentionally malformed",
                "medium"
            )
        }

        // ── Self-integrity / anti-debug string hints ── */
        val tamperHints = listOf(
            "/proc/self/status", "/proc/self/maps", "/proc/self/exe",
            "frida", "TracerPid", "gdb", "ptrace", "substrate", "xposed"
        )
        val foundHints = tamperHints.filter { asciiView.contains(it) }
        if (foundHints.size >= 2) {
            add(
                "anti_analysis_strings",
                "Anti-analysis / anti-tamper strings",
                "unknown",
                10,
                "References to ${foundHints.take(5).joinToString(", ")}",
                "low"
            )
        }

        val ranked = verdicts.values.sortedByDescending { it.score }
        val top = ranked.firstOrNull()
        val overall = when {
            top == null || top.score < 30 -> "clean"
            top.score < 60 -> "suspected"
            else -> "protected"
        }

        val items = JSONArray()
        ranked.forEach { v ->
            items.put(
                JSONObject()
                    .put("id", v.id)
                    .put("name", v.name)
                    .put("vendor", v.vendor)
                    .put("score", v.score)
                    .put("confidence", v.confidence)
                    .put("evidence", JSONArray(v.evidence))
            )
        }

        return JSONObject()
            .put("overall", overall)
            .put("architecture", elf.architecture)
            .put("endian", elf.endian)
            .put("entry", hex(elf.entry))
            .put("sectionCount", elf.sections.size)
            .put("packers", items)
            .put("evidence", JSONArray(evidence))
            .put(
                "guidance",
                "Verdicts are static heuristics, not proof. A high score on 'nonstandard_sections' or 'high_entropy_sections' alone usually means an obfuscated build, not a commercial protector. Confirm with a runtime dump before assuming packing."
            )
    }

    fun capabilities(): JSONObject = JSONObject()
        .put("coverageClass", "static_fingerprint")
        .put(
            "supported",
            JSONArray(
                listOf(
                    "vendor marker string scan (360 / Bangcle / Ijiami / Ali / Tencent Legu / UPX)",
                    "Shannon entropy per section (encrypted / compressed region detection)",
                    "entry point vs .text range check (packer stub indicator)",
                    "non-standard and blank section name detection",
                    "anti-analysis / anti-tamper string hints"
                )
            )
        )
        .put(
            "limits",
            JSONArray(
                listOf(
                    "Heuristic only; no code executed and no runtime unpack performed",
                    "Encrypted markers are invisible until the stub decrypts them",
                    "Customised or rebranded protectors may evade all markers"
                )
            )
        )
}

internal fun EngineRuntime.packerScan(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(PackerFingerprint.analyze(elf))
}
