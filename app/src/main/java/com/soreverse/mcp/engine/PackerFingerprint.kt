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
     * One protector's static signature.
     *
     * [filePatterns] are matched against the analysed file's own name; `*` is
     * the only wildcard. These are the strongest signal available: a stub
     * literally named `libjiagu.so` is the 360 protector, no heuristics needed.
     *
     * [stringMarkers] are ASCII tags found inside the binary, which is weaker —
     * a marker only survives in the binary if the vendor did not encrypt it.
     * Markers must be specific enough to be unlikely by accident; short generic
     * fragments are deliberately excluded (see [VENDOR_SIGNATURES]).
     */
    private class VendorSignature(
        val id: String,
        val name: String,
        val vendor: String,
        val filePatterns: List<String>,
        val stringMarkers: List<String> = emptyList()
    )

    /**
     * True when [candidate] matches [pattern], where `*` is the only wildcard
     * and matches any run of characters (including none).
     *
     * Done without [Regex] so that vendor names containing regex metacharacters
     * — `.so` extensions above all — are matched literally.
     */
    private fun matchesFileName(pattern: String, candidate: String): Boolean {
        if (pattern.equals(candidate, ignoreCase = true)) return true
        if ('*' !in pattern) return false
        val parts = pattern.split("*")
        val haystack = candidate.lowercase()
        var cursor = 0
        parts.forEachIndexed { index, raw ->
            val part = raw.lowercase()
            val last = index == parts.lastIndex
            val found = when {
                // Leading part must anchor at the start.
                index == 0 -> if (haystack.startsWith(part)) 0 else -1
                // Trailing part must anchor at the end, so "libshella-*.so"
                // does not match "libshella-1.2.3.so.bak".
                last -> if (part.isEmpty() || haystack.endsWith(part)) haystack.length - part.length else -1
                // Interior parts may appear anywhere after the cursor.
                else -> haystack.indexOf(part, cursor)
            }
            if (found < 0) return false
            cursor = found + part.length
        }
        return true
    }

    /**
     * Vendor signatures, keyed by the file/entry names each protector ships.
     *
     * Sourced from published packer-signature lists. Two classes of entry in
     * those lists are intentionally **not** included here:
     *
     *  - Ordinary third-party dependencies that co-occur with protection
     *    (`okhttp3`, `com.google.gson`, `kotlinx.coroutines`, `androidx.*`,
     *    `com.alibaba.android.arouter`, `com.tencent.bugly`, …). They describe
     *    the app, not the protector, and would flag a large share of clean APKs.
     *  - Obfuscated class names (`a.a`, `a.b.a`, `a.f.a`) and very short
     *    fragments (`_se_`, `_me_`), which match almost anything.
     *
     * Both classes are DEX-level rather than SO-level, so they are out of reach
     * of this SO scanner anyway; see `capabilities.limits`.
     */
    private val VENDOR_SIGNATURES = listOf(
        VendorSignature(
            "360",
            "Qihoo 360",
            "Qihoo",
            listOf("libjiagu.so", "libjiagu_a64.so", "libjiagu_x86.so", "libjiagu_x64.so", "libprotectClass.so"),
            listOf("libjiagu")
        ),
        VendorSignature(
            "360_enterprise",
            "Qihoo 360 Enterprise",
            "Qihoo",
            listOf("libjiagu_vip.so", "libjiagu_vip_a64.so", "libjiagu_vip_x86.so", "libjiagu_vip_x64.so", "libjg_mc.so")
        ),
        VendorSignature("bangcle", "Bangcle / SecNeo", "Bangcle", listOf("libsecexe.so", "libsecmain.so", "libSecShell.so"), listOf("bangcle", "secneo")),
        VendorSignature(
            "bangcle_enterprise",
            "Bangcle Enterprise",
            "Bangcle",
            listOf("libDexHelper.so", "libDexHelper-x86.so", "libAppGuard.so", "libAppGuard-x86.so"),
            listOf("libDexHelper")
        ),
        VendorSignature(
            "ijiami",
            "Ijiami",
            "Ijiami",
            listOf("ijiami.ajm", "ijiami.dat", "IJMDal.Data", "libijmDataEncryption.so", "libijm-emulator.so"),
            listOf("ijiami")
        ),
        VendorSignature("ijiami_enterprise", "Ijiami Enterprise", "Ijiami", listOf("libijm-emulator.so", "libijmDataEncryption.so")),
        VendorSignature(
            "tencent_legu",
            "Tencent Legu",
            "Tencent",
            listOf("libshell.so", "libtup.so", "mix.dex", "mixz.dex", "libshella-*.so", "libshellx-*.so"),
            listOf("libshella", "legu")
        ),
        VendorSignature(
            "tencent_yu",
            "Tencent Yuas",
            "Tencent",
            listOf(
                "libshell-super.2019.so",
                "libshell-superbasic.2019.so",
                "libtosprotection.armeabi.so",
                "libtosprotection.armeabi-v7a.so",
                "libtosprotection.x86.so",
                "tosversion"
            )
        ),
        VendorSignature(
            "tencent_yu_enterprise",
            "Tencent Yuas Enterprise",
            "Tencent",
            listOf("libshell-superv.2019.so", "libshell-supervbasic.2019.so", "dexMethod_00oo1l1l.dat")
        ),
        VendorSignature("ali", "Ali (Alibaba)", "Alibaba", listOf("libfakejni.so", "libzuma.so")),
        VendorSignature("ali_ju", "Ali Ju Security", "Alibaba", listOf("aliprotect.dat", "libmobisec.so"), listOf("libmobisec")),
        VendorSignature("alipay", "Alipay", "Alibaba", listOf("libashield.so")),
        VendorSignature(
            "nagain",
            "Nagain",
            "Nagain",
            listOf("libddog.so", "libedog.so", "libchaosvmp.so", "libddog.solibfdog.so", "libvdog", "libvdog64", "libvdog-x86")
        ),
        VendorSignature("tongfu", "Tongfu Shield", "Tongfu", listOf("libNSaferOnly.so", "libegis.so")),
        VendorSignature("baidu", "Baidu", "Baidu", listOf("libbaiduprotect.so", "libbuGvmSolxMV.so")),
        VendorSignature("baidu_sagittarius", "Baidu Sagittarius", "Baidu", listOf("libsagittarius6.so", "libsagittarius6_x86", "sagittarius6-sec.dex")),
        VendorSignature("netqin", "NetQin", "NetQin", listOf("libnqshield.so")),
        VendorSignature(
            "netease",
            "NetEase Yidun",
            "NetEase",
            listOf("libnesec", "libnesec64", "libnesec.so", "libunisec.so", "libunisec_x86.so", "libunisec2.so", "libunisec2_x86.so", "nedata.db")
        ),
        VendorSignature(
            "kiwi",
            "Kiwi Security",
            "Kiwi",
            listOf(
                "libkwscmm.so",
                "libkwscr.so",
                "libkwslinker.so",
                "libKwProtectSDK.so",
                "libKwAppGuardSDK.so",
                "kwmkadp_arm64-v8a",
                "kwmkadp_armeabi-v7a",
                "kiwiguard.lic"
            )
        ),
        VendorSignature(
            "dingxiang",
            "Dingxiang",
            "Dingxiang",
            listOf(
                "libx3g.so", "libdx-ld.so", "libcsn.so", "libstub000.so",
                "libDXWhiteBoxComm-*.so", "output-armeabi-v7a.zip", "output-arm64-v8a.zip", "output-x86.zip", "output-x86_64.zip"
            )
        ),
        VendorSignature("manxi", "Manxi", "Manxi", listOf("mxsafe.data", "mxsafe.jar", "libmanxi.so", "libmxldd.so", "libmxacc.so")),
        VendorSignature("shensi", "Shensi Shield", "Shensi", listOf("kqkticwjgzy_a32.so", "kqkticwjgzy_a64.so", "kqkticwjgzy_x86.so", "kqkticwjgzy_x64.so")),
        VendorSignature("cmcc_mogo", "China Mobile Mogo", "China Mobile", listOf("mogosec_classes", "libcmvmp.so", "libmogosecurity.so")),
        VendorSignature("shanhulingyu", "Shanhulingyu", "Shanhulingyu", listOf("libreincp.so", "libreincp_x86.so")),
        VendorSignature("epic", "Epic", "Epic", listOf("Epic.vmp", "libEP_arm.so", "libEP_arm64.so", "libEP_x86.so", "libEP_x86_64.so")),
        VendorSignature("epic_v3", "Epic V3", "Epic", listOf("libEpicVm.so")),
        VendorSignature("arm", "Arm Protect", "Arm", listOf("libArmEpicVm.so", "libarm_protect.so")),
        VendorSignature("oppo", "OPPO", "OPPO", listOf("libomas.so")),
        VendorSignature("google_pairip", "Google Play Protect", "Google", listOf("libpairipcore.so")),
        VendorSignature("venustech", "Venustech", "Venustech", listOf("libvenustech.so", "libvenSec.so")),
        VendorSignature("appshield", "AppShield", "AppShield", listOf("libahope.so")),
        VendorSignature("appsealin", "AppSealin", "AppSealin", listOf("libcovault-appsec.so", "libcovault.so")),
        VendorSignature("nesun", "Nesun", "Nesun", listOf("libzprotect.so")),
        VendorSignature("shadowsafety", "ShadowSafety", "ShadowSafety", listOf("libShadowSafetyProtect.so", "libShadowSafetyProtect_a64.so")),
        VendorSignature("yingan", "Yingan", "Yingan", listOf("libabcdProtect.so", "libabcdProtect_a64.so")),
        VendorSignature("yinglian", "Yinglian", "Yinglian", listOf("libylshell.so")),
        VendorSignature("yangfan", "Yangfan Security", "Yangfan", listOf("libyfboot.so")),
        VendorSignature("shanda", "Shanda", "Shanda", listOf("libapssec.so")),
        VendorSignature("rising", "Rising", "Rising", listOf("librsprotect.so")),
        VendorSignature("uu", "UU Security", "UU", listOf("libuusafe.jar.so", "libuusafe.so", "libuusafeempty.so")),
        VendorSignature("haiyunan", "HaiyunAn", "HaiyunAn", listOf("libitsec.so")),
        VendorSignature("dexprotect", "DexProtect", "DexProtect", listOf("dp.arm-v7.so.dat", "dp.arm.so.dat", "libdexprotector.so")),
        VendorSignature("apkprotect", "APKProtect", "APKProtect", listOf("libAPKProtect.so")),
        VendorSignature("upx", "UPX", "UPX", emptyList(), listOf("UPX!"))
    )

    fun analyze(elf: ElfFile, sourceName: String = ""): JSONObject {
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

        // ── Vendor signature scan ──
        val asciiView = buildString {
            data.forEach { b ->
                val v = b.toInt() and 0xff
                append(if (v in 0x20..0x7e) v.toChar() else ' ')
            }
        }
        // A stub is normally named after its vendor, so the file name is the
        // cheapest and strongest evidence there is. Score it above any string
        // hit, because a name collision on a marker is far likelier than a
        // third-party library shipping the exact protector stub name.
        val fileName = sourceName.substringAfterLast('/').substringAfterLast('\\')
        for (sig in VENDOR_SIGNATURES) {
            if (fileName.isNotBlank()) {
                val hit = sig.filePatterns.firstOrNull { matchesFileName(it, fileName) }
                if (hit != null) {
                    add(
                        sig.id,
                        sig.name,
                        sig.vendor,
                        90,
                        "File name '$fileName' matches known $sig.vendor artefact '$hit'",
                        "high"
                    )
                }
            }
            sig.stringMarkers.forEach { marker ->
                if (asciiView.contains(marker)) {
                    add(
                        sig.id,
                        sig.name,
                        sig.vendor,
                        60,
                        "Marker string '$marker' present in binary",
                        if (sig.id == "upx") "high" else "medium"
                    )
                }
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
            .put("fileName", fileName)
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
                    "vendor artefact file-name match (${VENDOR_SIGNATURES.count {
                        it.filePatterns.isNotEmpty()
                    }} protectors: 360 / Bangcle / Ijiami / Tencent Legu+Yuas / Ali / Baidu / Netease / Kiwi / Dingxiang / Epic / …)",
                    "vendor marker string scan inside the binary (360 / Bangcle / Ijiami / Tencent Legu / Ali / UPX)",
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
                    "Customised or rebranded protectors may evade all markers",
                    "DEX-level signatures (wrapper Application classes, injected packages) are out of scope: this scanner only sees one SO, not the APK or its DEX files"
                )
            )
        )
}

internal fun EngineRuntime.packerScan(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(PackerFingerprint.analyze(elf, workspace(workspaceId).source.name))
}
