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
import org.json.JSONArray
import org.json.JSONObject

/** One anti-analysis finding with the evidence class that produced it. */
internal data class AntiDebugFinding(val category: String, val technique: String, val evidenceClass: String, val evidence: String)

/**
 * Structured anti-analysis / anti-tamper detection for the *analysed* SO.
 *
 * This is deliberately stronger than a substring sweep. Evidence is graded:
 *
 *  - `import` — the binary actually imports the API. A relocation-backed
 *    `ptrace` or `inotify_add_watch` import is a call the loader must resolve,
 *    so it is close to proof the code intends to use it.
 *  - `string` — a `"/proc/self/maps"` literal exists, but so does any log
 *    message or error text, so on its own it proves nothing.
 *  - `code_pattern` — a byte pattern typical of inline-hook or integrity
 *    trampolines.
 *
 * Nothing here executes the target, and every finding keeps its class so a
 * caller can weigh a loader-backed import differently from a bare string.
 *
 * Scope note: this analyses the file the user points at. It is unrelated to
 * `SelfArtifactGuard` / `IntegrityGuard`, which protect SOMCP itself.
 */
internal object AntiDebugScanner {

    private data class Rule(val category: String, val technique: String, val patterns: List<String>, val explain: String)

    private val IMPORT_RULES = listOf(
        Rule(
            "anti_debug",
            "ptrace self-attach",
            listOf("ptrace"),
            "Imports ptrace; PTRACE_TRACEME self-attach is the classic debugger detector"
        ),
        Rule(
            "anti_debug",
            "inotify watch on /proc/self",
            listOf("inotify_add_watch", "inotify_init"),
            "Imports inotify; watching /proc/self/* blocks debugger and frida-server file events"
        ),
        Rule(
            "anti_debug",
            "fork-based ptrace probe",
            listOf("fork", "vfork", "clone"),
            "Imports fork/clone; a child ptrace-parent probe is a common debugger check"
        ),
        Rule(
            "anti_debug",
            "kill / signal probing",
            listOf("kill", "tgkill", "raise"),
            "Imports signalling APIs; used to probe for tracer or to terminate on detection"
        ),
        Rule(
            "anti_debug",
            "timing / clock check",
            listOf("clock_gettime", "gettimeofday", "clock_gettime64"),
            "Imports a clock API; delta-time checks are the standard timing-based detector"
        ),
        Rule(
            "anti_hook",
            "process memory inspection",
            listOf("dl_iterate_phdr", "dlopen", "dlsym"),
            "Imports dynamic-loader APIs; enumerating loaded objects exposes injected libraries"
        ),
        Rule(
            "anti_hook",
            "signal handler self-check",
            listOf("sigaction", "signal", "sigtrap", "sigsetjmp"),
            "Imports signal APIs; a SIGTRAP/SIGBUS handler comparing its own code detects hooks"
        )
    )

    private val STRING_RULES = listOf(
        Rule(
            "anti_debug",
            "TracerPid read",
            listOf("/proc/self/status", "TracerPid"),
            "Reads /proc/self/status, the canonical way to see whether a tracer is attached"
        ),
        Rule(
            "anti_debug",
            "thread/wchan inspection",
            listOf("/proc/self/task", "/proc/self/wchan", "/proc/%d/wchan"),
            "Per-thread state paths are used to spot an attached debugger or injected thread"
        ),
        Rule(
            "anti_hook",
            "maps scanning for injected modules",
            listOf("/proc/self/maps", "/proc/self/pagemap"),
            "Scans its own address space, typically to grep for frida/xposed/substrate"
        ),
        Rule(
            "anti_hook",
            "executable self-reference",
            listOf("/proc/self/exe", "/proc/self/cmdline"),
            "Reads its own executable path, a precursor to file-integrity checks"
        )
    )

    private val INJECTOR_TOKENS = listOf(
        "frida", "libfrida", "frida-agent", "frida-gadget", "frida-server",
        "xposed", "libxposed", "substrate", "libsubstrate",
        "libriru", "magisk", "libzygisk", "sandhook", "whale",
        "/dev/ptrace", "TracerPid", "linjector"
    )

    private fun hex(v: Long) = "0x${v.toString(16)}"

    /** Imported dynamic symbols, i.e. names the loader must resolve. */
    private fun importedNames(elf: ElfFile): Set<String> = elf.dynSymbols.filter { it.imported }.map { it.name }.toSet() +
        elf.symbols.filter { it.imported }.map { it.name }.toSet()

    /**
     * Inline-hook trampolines. A `mov rax, imm64 ; jmp rax` pair at a function
     * entry is what a userspace detour looks like on x86-64; the AArch64
     * equivalent loads a 64-bit pointer then branches. These patterns only mean
     * "suspicious" in context, so they are reported separately from imports.
     */
    private fun hookTrampolines(elf: ElfFile): List<AntiDebugFinding> {
        val out = mutableListOf<AntiDebugFinding>()
        elf.sections.forEach { sec ->
            if (sec.type == 8L || sec.size <= 0) return@forEach
            if (sec.flags and 0x4L == 0L) return@forEach // executable sections only
            val start = sec.offset.toInt()
            if (start < 0 || start >= elf.data.size) return@forEach
            val len = minOf(elf.data.size - start, sec.size.toInt())
            val body = elf.data.copyOfRange(start, start + len)
            if (body.size < 12) return@forEach
            // x86-64: 48 B8 <imm64> FF E0  == mov rax, imm64 ; jmp rax
            var i = 0
            while (i + 12 <= body.size) {
                if (body[i] == 0x48.toByte() &&
                    body[i + 1] == 0xB8.toByte() &&
                    body[i + 10] == 0xFF.toByte() &&
                    body[i + 11] == 0xE0.toByte()
                ) {
                    out.add(
                        AntiDebugFinding(
                            "inline_hook",
                            "x86-64 mov rax,imm64 ; jmp rax trampoline",
                            "code_pattern",
                            "detour-shaped 12-byte sequence at ${hex(sec.addr + i)} in ${sec.name}"
                        )
                    )
                }
                i++
            }
        }
        return out
    }

    fun analyze(elf: ElfFile, maxStrings: Int = 400): JSONObject {
        val imports = importedNames(elf)
        val findings = mutableListOf<AntiDebugFinding>()

        IMPORT_RULES.forEach { rule ->
            val hit = imports.firstOrNull { name -> rule.patterns.any { name.contains(it, ignoreCase = true) } }
            if (hit != null) {
                findings.add(
                    AntiDebugFinding(rule.category, rule.technique, "import", "${rule.explain} (imports '$hit')")
                )
            }
        }

        // Strings are weak evidence, so scan the parsed string table (bounded)
        // rather than sweeping arbitrary bytes.
        val strings = elf.strings.take(maxStrings).map { it.value }
        STRING_RULES.forEach { rule ->
            val hit = strings.firstOrNull { s -> rule.patterns.any { s.contains(it, ignoreCase = true) } }
            if (hit != null) {
                findings.add(
                    AntiDebugFinding(
                        rule.category,
                        rule.technique,
                        "string",
                        "${rule.explain} (string literal present: \"${hit.take(60)}\")"
                    )
                )
            }
        }

        // Injector token cluster: seeing two or more is meaningful because these
        // tokens rarely co-occur in ordinary library text.
        val tokenHits = INJECTOR_TOKENS.filter { token -> strings.any { it.contains(token, ignoreCase = true) } }
        if (tokenHits.size >= 2) {
            findings.add(
                AntiDebugFinding(
                    "anti_hook",
                    "injection-framework token cluster",
                    "string",
                    "${tokenHits.size} injector-related tokens co-occur: ${tokenHits.take(8).joinToString(", ")}"
                )
            )
        }

        findings.addAll(hookTrampolines(elf))

        val byCategory = findings.groupBy { it.category }
        val items = JSONArray()
        findings.forEach { f ->
            items.put(
                JSONObject()
                    .put("category", f.category)
                    .put("technique", f.technique)
                    .put("evidenceClass", f.evidenceClass)
                    .put("evidence", f.evidence)
            )
        }

        val importCount = findings.count { it.evidenceClass == "import" }
        val risk = when {
            importCount >= 3 -> "high"
            importCount >= 1 || findings.any { it.evidenceClass == "code_pattern" } -> "medium"
            findings.isNotEmpty() -> "low"
            else -> "none"
        }

        return JSONObject()
            .put("risk", risk)
            .put("importHits", importCount)
            .put("stringHits", findings.count { it.evidenceClass == "string" })
            .put("codePatternHits", findings.count { it.evidenceClass == "code_pattern" })
            .put("categories", JSONArray(byCategory.keys.sorted()))
            .put("findings", items)
            .put("injectorTokens", JSONArray(tokenHits))
            .put(
                "evidenceModel",
                "import = the loader must resolve this symbol (close to proof of intent); " +
                    "string = a literal exists but may be log text (weak); " +
                    "code_pattern = a byte sequence typical of a detour (needs context)."
            )
            .put(
                "limits",
                "Static only. Findings do not prove a technique is reachable or enabled, and a packer may hide the imports. A 'none' verdict is not a clean bill of health — it only means nothing recognisable was found statically."
            )
    }

    fun capabilities(): JSONObject = JSONObject()
        .put("coverageClass", "structured_static_triage")
        .put(
            "supported",
            JSONArray(
                listOf(
                    "import-backed detection (ptrace / inotify / fork / clock / dl_iterate_phdr / signal APIs)",
                    "/proc/self inspection string detection with technique mapping",
                    "injector token co-occurrence clustering (frida / xposed / substrate / magisk / riru)",
                    "x86-64 inline detour trampoline pattern recognition"
                )
            )
        )
        .put(
            "evidenceClasses",
            JSONArray(listOf("import", "string", "code_pattern"))
        )
        .put(
            "notCovered",
            JSONArray(
                listOf(
                    "ARM64 detour pattern recognition is not implemented (only x86-64 is scanned)",
                    "runtime checks cannot be observed statically",
                    "packed binaries hide these imports until unpacked"
                )
            )
        )
        .put(
            "scope",
            "Analyses the file under analysis. Unrelated to SelfArtifactGuard / IntegrityGuard, which protect SOMCP itself."
        )
}

internal fun EngineRuntime.antiDebugScan(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    if (elf.sections.isEmpty()) {
        return@guarded err(
            "NO_SECTIONS",
            "Section table is empty; run edit_fix_sections (or xanso_api fix_sections) first."
        )
    }
    ok(AntiDebugScanner.analyze(elf))
}

internal fun EngineRuntime.antiDebugCapabilities(): JSONObject = AntiDebugScanner.capabilities()
