package com.soreverse.mcp.mcp

import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.doubleValue
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.intValue
import com.soreverse.mcp.core.obj
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import org.json.JSONArray
import org.json.JSONObject

enum class ToolClass { CORE, META, EXTRA }

@DslMarker
annotation class SchemaDsl

@SchemaDsl
object SchemaBuilder {
    fun emptyObject(): JSONObject = JSONObject().put("type", "object").put("properties", JSONObject())

    fun objectSchema(properties: JSONObject): JSONObject = JSONObject()
        .put("type", "object").put("properties", properties)

    private fun strProp(d: String): JSONObject = JSONObject().put("type", "string").put("description", d)
    private fun enumProp(d: String, vararg values: String): JSONObject = strProp(d).put("enum", JSONArray(values.toList()))
    private fun intProp(d: String): JSONObject = JSONObject().put("type", "integer").put("description", d)
    private fun numProp(d: String): JSONObject = JSONObject().put("type", "number").put("description", d)
    private fun boolProp(d: String): JSONObject = JSONObject().put("type", "boolean").put("description", d)
    private fun arrProp(d: String, items: JSONObject?): JSONObject =
        JSONObject().put("type", "array").put("description", d).apply { if (items != null) put("items", items) }

    fun props(block: PropList.() -> Unit): JSONObject = PropList().apply(block).build()

    class PropList {
        private val properties = JSONObject()
        infix fun String.str(d: String) { properties.put(this, strProp(d)) }
        fun String.oneOf(d: String, vararg values: String) { properties.put(this, enumProp(d, *values)) }
        infix fun String.int(d: String) { properties.put(this, intProp(d)) }
        infix fun String.num(d: String) { properties.put(this, numProp(d)) }
        infix fun String.bool(d: String) { properties.put(this, boolProp(d)) }
        infix fun String.arr(d: String) { properties.put(this, arrProp(d, null)) }
        infix fun String.arr(d: Pair<String, JSONObject>) { properties.put(this, arrProp(d.first, d.second)) }
        fun build(): JSONObject = properties
    }

    fun editsAsmSchema(): JSONObject {
        val items = JSONObject().put("type", "object")
            .put("description", "One assembly edit. Defaults to replacing one instruction at instructionIndex=0; set instructionCount/byteLength to cover multiple instruction slots.")
            .put("properties", JSONObject()
                .put("writeAsm", strProp("New assembly text (assembler syntax). Alias: newAsm / asm / assembly."))
                .put("newAsm", strProp("Alias for writeAsm."))
                .put("asm", strProp("Alias for writeAsm."))
                .put("address", strProp("Hex virtual address inside the function, e.g. 0x978. Overrides instructionIndex/byteOffset."))
                .put("instructionIndex", intProp("Index of the instruction to replace (default 0)."))
                .put("instructionCount", intProp("Number of instruction slots to cover (default 1). Use >1 to fit multi-instruction payloads."))
                .put("byteOffset", intProp("Byte offset inside the function (alternative to instructionIndex)."))
                .put("byteLength", intProp("Byte length to overwrite (alternative to instructionCount). Required for insert_* and write_function modes."))
                .put("mode", strProp("replace_instructions (default) | nop_out | delete_instructions | insert_before | insert_after | prepend_function | append_function | write_function")))
            .put("required", JSONArray().put("writeAsm"))
        return items
    }

    fun editsHexSchema(): JSONObject {
        val items = JSONObject().put("type", "object")
            .put("description", "One hex edit: write bytes at byteOffset inside the section. Hex aliases are accepted; conflicting alias values are rejected.")
            .put("properties", JSONObject()
                .put("newHex", strProp("Hex bytes to write, e.g. 20 00 80 52. Aliases: hex / bytes / data / rawHex / rawValue."))
                .put("hex", strProp("Alias for newHex."))
                .put("bytes", strProp("Alias for newHex."))
                .put("data", strProp("Alias for newHex."))
                .put("rawHex", strProp("Legacy alias for newHex."))
                .put("rawValue", JSONObject().put("description", "Legacy alias: hex string or array of byte values 0..255."))
                .put("byteOffset", strProp("Byte offset inside the section (not file offset). Alias: offset."))
                .put("offset", strProp("Alias for byteOffset.")))
            .put("required", JSONArray().put("byteOffset"))
        return items
    }

    fun editsSymbolSchema(): JSONObject {
        val items = JSONObject().put("type", "object")
            .put("description", "One symbol edit. rename: same-or-shorter rename. add: add exported function at addr. remove: remove symbol by name.")
            .put("properties", JSONObject()
                .put("op", strProp("rename (default) | add | remove"))
                .put("newName", strProp("New symbol name (for rename: must be <= original length)."))
                .put("addr", strProp("Hex virtual address for the new exported function (add op only)."))
                .put("name", strProp("Symbol name to remove (remove op only).")))
            .put("required", JSONArray().put("op"))
        return items
    }

    fun outputsSchema(): JSONObject {
        val items = JSONObject().put("type", "object")
            .put("description", "One build output variant.")
            .put("properties", JSONObject()
                .put("outputName", strProp("Output file name, e.g. libflass_patched_v1.so."))
                .put("writeToWorkDir", JSONObject().put("type", "boolean").put("description", "Mirror this variant into the work directory."))
                .put("writePatchReport", JSONObject().put("type", "boolean").put("description", "Write a patch-report JSON sidecar for this variant.")))
            .put("required", JSONArray().put("outputName"))
        return items
    }

    fun batchStepsSchema(): JSONObject {
        val itemProps = JSONObject()
            .put("tool", strProp("Tool name to invoke."))
            .put("arguments", JSONObject().put("type", "object").put("description", "Arguments object for this tool. May contain \${resultKey.jsonPath} placeholders substituted from prior steps' results."))
            .put("resultKey", strProp("Optional short key (e.g. a0, b1) used to reference this step's result JSON in later steps."))
        val items = JSONObject().put("type", "object")
            .put("description", "One batch pipeline step. Steps execute serially in array order.")
            .put("properties", itemProps)
            .put("required", JSONArray().put("tool"))
        return items
    }
}

class HookedContext(
    context: android.content.Context,
    settings: com.soreverse.mcp.core.SettingsStore,
    engine: com.soreverse.mcp.engine.NativeSoEngine,
    val healthHook: () -> JSONObject,
    val statsHook: () -> JSONObject,
    val resetStatsHook: () -> Unit,
    val toolsCountHook: () -> JSONObject,
    val helpHook: () -> JSONObject,
    val listToolsHook: (String, String) -> JSONObject,
    val describeToolsHook: (List<String>) -> JSONObject,
    val workflowsHook: () -> JSONObject,
    val suggestHook: (JSONObject) -> JSONObject,
    val errorsHook: () -> JSONObject,
    val reportHook: (JSONObject) -> JSONObject,
    val capabilitiesHook: () -> JSONObject,
    val batchHook: (JSONObject) -> JSONObject,
    val continueHook: (String) -> JSONObject,
    val sysStatusHook: (Boolean) -> JSONObject,
    val tunnelStatusHook: () -> JSONObject,
    val tunnelStatsHook: (Boolean) -> JSONObject,
    val tunnelStartHook: (String, Int, String) -> JSONObject,
    val tunnelStopHook: () -> JSONObject,
    val apkStatusHook: (Boolean) -> JSONObject,
    val apkProbeHook: () -> JSONObject,
    val apkPingHook: () -> JSONObject,
) : ToolContext(context, settings, engine)

object ToolCatalog {

    private val pathArg: JSONObject.() -> String = { str("path").ifBlank { str("filePath").ifBlank { str("inputPath").ifBlank { str("soPath") } } } }

    private fun hexLong(value: String): Long? {
        val trimmed = value.trim()
        if (trimmed.isBlank()) return null
        return trimmed.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
    }

    private fun hexBytes(value: String): ByteArray? {
        val clean = value.replace(" ", "").replace("\n", "").replace("\t", "")
        if (clean.isBlank() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) + lo).toByte()
        }
        return out
    }

    // ── WORKSPACE ──

    private val soOpen = EngineToolHandler(
        ToolMeta("so_open",
            "打开 SO 文件并创建工作区（action=list 列出可用 SO）",
            "Open a SO file and create a workspace. Use action=list to discover available SO files. Use action=open_url to download a http(s) SO into the selected work directory, then open and analyze it.",
            "workspace", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("open (default) | list | open_url", "open", "list", "open_url")
            "path" str "Absolute path or content:// URI (action=open)"
            "filePath" str "Alias of path"
            "url" str "http(s) URL pointing directly to a .so/ELF file (action=open_url). A work directory must be selected first."
            "outputName" str "Optional file name to save the downloaded SO in the work directory"
            "prefix" str "Path or file prefix filter (action=list)"
            "limit" int "Maximum items (action=list)"
            "cursor" str "Pagination cursor (action=list)"
            "temporary" bool "If true, workspace won't persist across restarts"
        }) }
    ) { e, a, s ->
        when (a.str("action", "open")) {
            "list" -> e.listAvailableSos(a.str("prefix"), a.intValue("limit", s.defaultLimit), a.str("cursor"))
            "open_url" -> e.openUrl(a.str("url"), a.str("outputName"), a.bool("temporary", false))
            else -> e.open(a.pathArg(), a.bool("temporary", true))
        }
    }

    private val soClose = EngineToolHandler(
        ToolMeta("so_close",
            "关闭工作区（action=list 列出已打开工作区）",
            "Close an open workspace. Use action=list to see open workspaces.",
            "workspace", ToolClass.CORE,
        ) { objectSchema(props {
            "action".oneOf("close (default) | list", "close", "list")
            "workspaceId" str "Workspace id (action=close)"
        }) }
    ) { e, a, _ ->
        when (a.str("action", "close")) {
            "list" -> e.listWorkspaces()
            else -> e.close(a.str("workspaceId"))
        }
    }

    private val apkAnalyze = EngineToolHandler(
        ToolMeta(
            "apk_analyze",
            "独立解析本地 APK：ZIP 条目、Manifest 格式、DEX 头、ABI/SO、资源与 v1 签名文件；不依赖外部 APK MCP。",
            "Standalone local APK parser for ZIP entries, manifest format, DEX headers, ABI/SO inventory, resources, and v1 signature files; no external APK MCP required.",
            "workspace",
            ToolClass.CORE,
        ) {
            objectSchema(props {
                "path" str "Local APK path or path relative to the selected work directory."
                "entryLimit" int "Maximum ZIP entries returned, 1..5000 (default 500)."
            })
        },
    ) { engine, args, _ -> engine.analyzeApk(args.str("path").ifBlank { args.str("filePath") }, args.intValue("entryLimit", 500)) }

    // ── ANALYZE (Rizin-backed deep analysis) ──

    private val analyzeElf = EngineToolHandler(
        ToolMeta("analyze_elf",
            "ELF 结构与统计（LIEF 解析：节区/符号/重定位/程序头/动态段）",
            "Full ELF structure and triage stats via LIEF: sections, symbols, relocations, program headers, dynamic entries.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional, uses original SO if blank)"
            "view".oneOf("full (default) | stats | list", "full", "stats", "list")
            "subView".oneOf("Sub-view when view=list", "sections", "symbols", "dynsyms", "functions", "relocations", "strings", "imports")
            "prefix" str "Name prefix filter (view=list)"
            "limit" int "Maximum items (view=list)"
        }) }
    ) { e, a, s ->
        val view = a.str("view", "full")
        when (view) {
            "stats" -> e.readStats(a.str("workspaceId"), a.str("editSessionId"))
            "list" -> e.list(a.str("workspaceId"), a.str("editSessionId"), a.str("subView", "sections"), a.str("prefix"), a.intValue("limit", s.defaultLimit))
            else -> e.readElf(a.str("workspaceId"), a.str("editSessionId"))
        }
    }

    private val readStats = EngineToolHandler(
        ToolMeta("read_stats",
            "SO 快速统计（analyze_elf view=stats 的直观别名）",
            "Direct alias for analyze_elf(view=stats). Useful for clients that expect a standalone read_stats tool.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
        }) }
    ) { e, a, _ -> e.readStats(a.str("workspaceId"), a.str("editSessionId")) }

    private val analysisReport = EngineToolHandler(
        ToolMeta("analysis_report",
            "生成综合分析报告（meta_info action=report 的直观别名）",
            "Generate a full analysis report. Direct alias for meta_info(action=report)/lief_api(action=report).",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "writeToFile" bool "Write report JSON to app files"
        }) }
    ) { e, a, _ -> e.analysisReport(a.str("workspaceId"), a.str("editSessionId"), a.optBoolean("writeToFile", true)) }

    private val analyzeFunctions = EngineToolHandler(
        ToolMeta("analyze_functions",
            "列出 Rizin 自动分析发现的所有函数（含地址/大小/调用数）",
            "List all functions discovered by Rizin auto-analysis (address, size, call count).",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "limit" int "Maximum functions to return"
            "cursor" str "Pagination cursor"
        }) }
    ) { e, a, s -> e.rzFunctions(a.str("workspaceId"), a.str("editSessionId"), a.intValue("limit", s.defaultLimit), a.str("cursor")) }

    private val analyzeCfg = EngineToolHandler(
        ToolMeta("analyze_cfg",
            "函数控制流图（Rizin CFG：基本块 + 跳转边）",
            "Control flow graph for a function via Rizin: basic blocks and jump edges.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Function locator. Accepts full locator from analyze_functions (so_function:file!Name) or short function name."
        }) }
    ) { e, a, _ -> e.rzCfg(a.str("workspaceId"), a.str("editSessionId"), a.str("locator")) }

    private val analyzeCrypto = EngineToolHandler(
        ToolMeta("analyze_crypto",
            "密码学特征扫描（AES/RSA/ECC 常量 + 熵分析）",
            "Scan for cryptographic material (AES/RSA/ECC constants) and high-entropy regions via Rizin.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
        }) }
    ) { e, a, _ -> e.rzScanCrypto(a.str("workspaceId"), a.str("editSessionId")) }

    private val analyzeXrefs = EngineToolHandler(
        ToolMeta("analyze_xrefs",
            "交叉引用（Rizin：direction=to 入引用 / from 出引用 / both 双向）",
            "Cross-references via Rizin. direction: to (incoming refs) | from (outgoing refs) | both.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Symbol/function locator. Accepts full locator from analyze_elf/analyze_functions or short symbol name."
            "direction".oneOf("to (default) | from | both", "to", "from", "both")
            "limit" int "Maximum references"
        }) }
    ) { e, a, s -> e.rzXrefs(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.str("direction", "to")) }

    private val analyzeEsil = EngineToolHandler(
        ToolMeta("analyze_esil",
            "ESIL 指令级模拟追踪（Rizin ESIL VM：寄存器快照 + 内存读写）",
            "ESIL instruction-level emulation trace via Rizin: register snapshots and memory reads/writes.",
            "analyze", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Function locator or hex VA. Accepts full locator from analyze_functions, short function name, or 0x... address."
            "addr" str "Hex virtual address fallback when no function symbol is available, e.g. 0x1234."
            "stepCount" int "Number of instructions to emulate (default 1, max 1000)"
        }) }
    ) { e, a, _ -> e.rzEsilStep(a.str("workspaceId"), a.str("editSessionId"), a.str("locator").ifBlank { a.str("addr") }, a.intValue("stepCount", 1)) }

    // ── SEARCH ──

    private val searchBytes = EngineToolHandler(
        ToolMeta("search_bytes",
            "十六进制模式搜索（Rizin byte pattern：紧凑 hex，MCP 会兼容空格和 ??）",
            "Hex pattern search via Rizin byte-pattern syntax. Native syntax is compact hex/nibble wildcard, e.g. 5F2403D5, 5F24..D5, bytes:mask; MCP also normalizes spaced hex like '5F 24 ?? D5'.",
            "search", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "pattern" str "Rizin byte pattern: compact hex such as 5F2403D5, nibble wildcard using . such as 5F24..D5, optional bytes:mask; spaced hex and ?? are normalized for compatibility"
            "fromVa" str "Start VA hex string (blank/0 = from beginning)"
            "toVa" str "End VA hex string (blank/0 = to end)"
        }) }
    ) { e, a, _ -> e.rzSearchBytes(a.str("workspaceId"), a.str("editSessionId"), a.str("pattern"), hexLong(a.str("fromVa")) ?: 0L, hexLong(a.str("toVa")) ?: 0L) }

    private val searchStrings = EngineToolHandler(
        ToolMeta("search_strings",
            "字符串搜索（prefix 过滤，扫描 .rodata/.strtab/.dynstr）",
            "Search extracted UTF-8 and UTF-16LE strings, including Chinese text, with optional prefix/content filter.",
            "search", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "prefix" str "String contains filter or regex pattern, supports Chinese/UTF-8 text"
            "regex" bool "If true, treat prefix as a Kotlin regular expression"
            "ignoreCase" bool "Case-insensitive matching (default true)"
            "encoding" str "Optional encoding filter: UTF-8, UTF-16LE, or empty for any"
            "minConfidence" num "Minimum string confidence score in [0,1]; useful to drop noisy UTF-16 candidates"
            "limit" int "Maximum results"
            "cursor" str "Pagination cursor"
        }) }
    ) { e, a, s -> e.strings(a.str("workspaceId"), a.str("editSessionId"), "", a.str("prefix"), a.intValue("limit", s.defaultLimit), "", a.str("cursor"), a.bool("regex"), a.bool("ignoreCase", true), a.str("encoding"), a.doubleValue("minConfidence", 0.0)) }

    // ── READ ──

    private val readDisasm = EngineToolHandler(
        ToolMeta("read_disasm",
            "反汇编（Rizin：按函数/地址返回汇编和 Ghidra 伪代码）",
            "Disassemble via Rizin and include rizin-ghidra pseudocode when the Android native backend has pdg available.",
            "read", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Function locator. Accepts full locator from analyze_functions or short function name."
            "limit" int "Maximum instructions"
            "cursor" str "Pagination cursor"
            "instructionOffset" int "Skip N instructions"
            "byteOffset" int "Byte offset within function"
            "maxBytes" int "Max bytes to read"
            "addr" str "Hex virtual address fallback; ARM32 Thumb may use odd address or thumb=true"
            "thumb" bool "Force ARM32 Thumb mode"
            "mode".oneOf("Instruction mode", "auto", "arm", "thumb")
        }) }
    ) { e, a, s -> e.disasm(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.intValue("limit", s.defaultLimit), a.str("cursor"), a.intValue("instructionOffset"), a.intValue("byteOffset"), a.intValue("maxBytes", 4096), a.str("addr"), if (a.has("thumb")) a.bool("thumb") else null, a.str("mode", "auto")) }

    private val readHexdump = EngineToolHandler(
        ToolMeta("read_hexdump",
            "十六进制转储（按偏移/地址读取原始字节）",
            "Hex dump: read raw bytes at a given offset or address.",
            "read", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Section locator. Accepts full locator from analyze_elf sections, so_section:.text, or short section name like .text."
            "byteOffset" int "Byte offset within the section"
            "maxBytes" int "Max bytes to dump"
        }) }
    ) { e, a, _ -> e.hexdump(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.intValue("byteOffset"), a.intValue("maxBytes", 4096)) }

    // ── EDIT ──

    private val editHex = EngineToolHandler(
        ToolMeta("edit_hex",
            "字节级补丁（edits[] 写 newHex；或 va+patch 通过 LIEF patch_address）",
            "Patch raw bytes. Use edits[] with byteOffset for offset-based patching, or va+patchHex for VA-based patching via LIEF.",
            "edit", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "locator" str "Section locator for offset-based patching. Accepts full locator from analyze_elf sections, so_section:.text, or short section name like .text."
            "edits" arr ("Array of hex edits" to SchemaBuilder.editsHexSchema())
            "va" str "Virtual address for VA-based patching (hex, e.g. 0x1234)"
            "patchHex" str "Hex bytes to write at va (e.g. '20 00 80 52')"
            "dryRun" bool "If true, return a preview without applying changes"
        }) }
    ) { e, a, _ ->
        val vaStr = a.str("va")
        if (vaStr.isNotEmpty()) {
            val va = vaStr.removePrefix("0x").toLong(16)
            val patchHex = a.str("patchHex").replace(" ", "")
            val patch = ByteArray(patchHex.length / 2) { i ->
                ((Character.digit(patchHex[i * 2], 16) shl 4) + Character.digit(patchHex[i * 2 + 1], 16)).toByte()
            }
            e.editHexVa(a.str("workspaceId"), a.str("editSessionId"), va, patch, a.bool("dryRun"))
        } else {
            e.editHex(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.getJSONArray("edits"), a.bool("dryRun"))
        }
    }

    private val editAsm = EngineToolHandler(
        ToolMeta("edit_asm",
            "汇编级补丁（Rizin assemble：edits[] 替换指令；dryRun 预览）",
            "Patch assembly using Rizin assembler. edits[] each replace one or more instructions; dryRun=true previews.",
            "edit", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "locator" str "Function or address locator. Accepts so_function:file!name@0xVA, function name, or bare 0xVA."
            "dryRun" bool "If true, return a preview without applying changes"
            "edits" arr ("Array of asm edits" to SchemaBuilder.editsAsmSchema())
        }) }
    ) { e, a, _ -> e.editAsm(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.getJSONArray("edits"), a.bool("dryRun")) }

    private val editSymbol = EngineToolHandler(
        ToolMeta("edit_symbol",
            "符号管理（rename 重命名 / add 添加导出函数 / remove 移除符号）",
            "Symbol management: rename (same-or-shorter), add exported function via LIEF, or remove symbol via LIEF.",
            "edit", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "locator" str "Symbol locator for rename. Accepts full locator from analyze_elf symbols or short symbol name."
            "edits" arr ("Array of symbol edits" to SchemaBuilder.editsSymbolSchema())
            "dryRun" bool "If true, return a preview (rename only)"
            "addr" str "Hex VA for new exported function (add op, shortcut)"
            "name" str "Symbol name (add: new function name, remove: symbol to remove, shortcut)"
            "op".oneOf("rename | add | remove (shortcut, bypasses edits[])", "rename", "add", "remove")
        }) }
    ) { e, a, _ ->
        val op = a.str("op")
        if (op.isNotEmpty()) {
            when (op) {
                "add" -> e.liefAddExportedFunction(a.str("workspaceId"), a.str("editSessionId"), a.str("addr").removePrefix("0x").toLong(16), a.str("name"))
                "remove" -> e.liefRemoveSymbol(a.str("workspaceId"), a.str("editSessionId"), a.str("name"))
                else -> e.editSymbol(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.getJSONArray("edits"), a.bool("dryRun"))
            }
        } else {
            e.editSymbol(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.getJSONArray("edits"), a.bool("dryRun"))
        }
    }

    private val editFixSections = EngineToolHandler(
        ToolMeta("edit_fix_sections",
            "xAnSo 节区头重建（LIEF Builder：从 .dynamic 段重建节区头）",
            "Reconstruct ELF section headers from the .dynamic segment via LIEF Builder (xAnSo algorithm). Essential for NDK-compiled SOs with stripped section headers.",
            "edit", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
        }) }
    ) { e, a, _ -> e.fixSections(a.str("workspaceId"), a.str("editSessionId")) }

    // ── EMULATE (Unidbg + DalvikVM) ──

    private val emulateCall = EngineToolHandler(
        ToolMeta("emulate_call",
            "函数模拟执行（Unidbg + DalvikVM：导出函数/JNI_OnLoad/Java_*，返回阶段化诊断）",
            "Emulate an exported function via Unidbg with DalvikVM JNI support. Best for JNI_OnLoad, exported functions, Java_* JNI methods, and patch validation; failures include stage and nextActions diagnostics.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (uses patched bytes if set)"
            "symbolName" str "Exported symbol to call, e.g. JNI_OnLoad or Java_com_example_Class_method. Use analyze_elf dynsyms first."
            "args" arr "Array of integer/string arguments after implicit JNI args for Java_* methods"
            "trace" bool "Enable verbose Unidbg tracing for diagnostics; use only on small functions"
        }) }
    ) { e, a, s -> if (!s.emulationEnabled) err("EMULATION_DISABLED", "Emulation is disabled in settings. Enable emulationEnabled to use this feature.", "emulationEnabled", false) else e.emulate(a.str("workspaceId"), a.str("editSessionId"), a.str("symbolName"), a.optJSONArray("args") ?: JSONArray(), a.bool("trace", false)) }

    private val emulateDump = EngineToolHandler(
        ToolMeta("emulate_dump",
            "内存转储（Unidbg：加载 SO 后读取指定地址的内存）",
            "Dump memory at an Unidbg runtime absolute virtual address after loading the SO. Add the module base to an ELF RVA/VA.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "addr" str "Unidbg runtime absolute virtual address. Add the module base from unidbg_session(action=modules) to an ELF RVA/VA."
            "size" int "Number of bytes to dump (1-65536)"
        }) }
    ) { e, a, s ->
        if (!s.emulationEnabled) err("EMULATION_DISABLED", "Emulation is disabled in settings. Enable emulationEnabled to use this feature.", "emulationEnabled", false)
        else {
            val addr = a.str("addr").trim().removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                ?: return@EngineToolHandler err("INVALID_ARGUMENT", "addr must be a hex Unidbg runtime absolute virtual address", "addr", a.str("addr"))
            e.dumpMemory(a.str("workspaceId"), a.str("editSessionId"), addr, a.intValue("size", 256))
        }
    }

    // ── DIFF ──

    private val diffSo = EngineToolHandler(
        ToolMeta("diff_so",
            "结构化差异对比（Rizin：字节级 + 函数级相似度）",
            "Structural diff between two SO versions via Rizin: byte-level differences and function similarity ratio.",
            "diff", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace A ID"
            "editSessionId" str "Edit session A ID (optional)"
            "workspaceIdB" str "Workspace B ID"
            "editSessionIdB" str "Edit session B ID (optional)"
            "limit" int "Maximum diff hunks (0 = all)"
        }) }
    ) { e, a, s ->
        val wsB = a.str("workspaceIdB")
        if (wsB.isNotEmpty()) {
            e.rzDiff(a.str("workspaceId"), a.str("editSessionId"), wsB, a.str("editSessionIdB"))
        } else {
            e.diff(a.str("workspaceId"), a.str("editSessionId"), a.intValue("limit", s.defaultLimit))
        }
    }

    // ── LOW-LEVEL API GATEWAYS ──

    private val rizinApi = EngineToolHandler(
        ToolMeta("rizin_api",
            "Rizin 底层能力网关（analyze/functions/cfg/xrefs/search_bytes/crypto/esil/diff/asm/disasm）",
            "Low-level Rizin gateway with enum actions for analyze, functions, cfg, xrefs, search_bytes, crypto, esil, diff, asm, and disasm.",
            "lowlevel", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("Rizin operation", "capabilities", "command", "analyze", "functions", "cfg", "xrefs", "search_bytes", "crypto", "esil", "diff", "asm", "disasm", "decompile")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "workspaceIdB" str "Workspace B ID (diff)"
            "editSessionIdB" str "Edit session B ID (diff)"
            "locator" str "Function/symbol locator or hex VA"
            "direction".oneOf("xref direction", "to", "from", "both")
            "pattern" str "Hex pattern for search_bytes"
            "fromVa" str "Start VA hex for search_bytes"
            "toVa" str "End VA hex for search_bytes"
            "asm" str "Assembly text for asm"
            "command" str "Any Rizin core command for action=command. Mutating/file/shell/debugger commands require unsafe=true."
            "unsafe" bool "Allow mutating, file, shell, debugger, and external commands. Requires authenticated MCP access."
            "addr" str "Hex VA for asm/disasm/esil"
            "thumb" bool "Force ARM32 Thumb mode for asm/disasm"
            "mode".oneOf("Instruction mode", "auto", "arm", "thumb")
            "limit" int "Instruction/result limit"
            "stepCount" int "ESIL step count"
            "strict" bool "For decompile: fail if rizin-ghidra is unavailable"
        }) }
    ) { e, a, s ->
        when (a.str("action", "analyze")) {
            "capabilities" -> ok(e.capabilityRegistry().getJSONObject("backends").getJSONObject("rizin"))
            "command" -> e.rzCommand(a.str("workspaceId"), a.str("editSessionId"), a.str("command"), a.bool("unsafe", false))
            "analyze" -> e.rzAnalyze(a.str("workspaceId"), a.str("editSessionId"))
            "functions" -> e.rzFunctions(a.str("workspaceId"), a.str("editSessionId"), a.intValue("limit", s.defaultLimit), a.str("cursor"))
            "cfg" -> e.rzCfg(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"))
            "xrefs" -> e.rzXrefs(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.str("direction", "to"))
            "search_bytes" -> e.rzSearchBytes(a.str("workspaceId"), a.str("editSessionId"), a.str("pattern"), hexLong(a.str("fromVa")) ?: 0L, hexLong(a.str("toVa")) ?: 0L)
            "crypto" -> e.rzScanCrypto(a.str("workspaceId"), a.str("editSessionId"))
            "esil" -> e.rzEsilStep(a.str("workspaceId"), a.str("editSessionId"), a.str("locator").ifBlank { a.str("addr") }, a.intValue("stepCount", 1))
            "diff" -> e.rzDiff(a.str("workspaceId"), a.str("editSessionId"), a.str("workspaceIdB"), a.str("editSessionIdB"))
            "asm" -> e.assembleRaw(a.str("workspaceId"), a.str("editSessionId"), a.str("asm"), hexLong(a.str("addr")) ?: 0L, if (a.has("thumb")) a.bool("thumb") else null, a.str("mode", "auto"))
            "disasm" -> e.disasm(a.str("workspaceId"), a.str("editSessionId"), a.str("locator"), a.intValue("limit", s.defaultLimit), "", 0, 0, 4096, a.str("addr"), if (a.has("thumb")) a.bool("thumb") else null, a.str("mode", "auto"))
            "decompile" -> e.rzDecompile(a.str("workspaceId"), a.str("editSessionId"), a.str("locator").ifBlank { a.str("addr") }, a.bool("strict", true))
            else -> err("UNKNOWN_ACTION", "Unknown Rizin action", "action", a.str("action"))
        }
    }

    private val liefApi = EngineToolHandler(
        ToolMeta("lief_api",
            "LIEF 全格式能力网关（ELF/PE/Mach-O/DEX/ART/OAT/VDEX）",
            "Full-format LIEF gateway for ELF, PE, Mach-O, DEX, ART, OAT, and VDEX parsing plus format-specific mutations.",
            "lowlevel", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("LIEF operation", "capabilities", "dispatch", "parse", "parse_any", "list", "patch_address", "add_export", "remove_symbol", "build", "fix_sections", "report")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "subView".oneOf("list sub-view", "sections", "symbols", "dynsyms", "functions", "relocations", "strings", "imports")
            "query" str "Filter query"
            "limit" int "Maximum list results"
            "va" str "Patch/add-export VA hex"
            "patchHex" str "Hex bytes for patch_address"
            "name" str "Symbol/export name"
            "outputName" str "Build output name"
            "conflictStrategy".oneOf("build conflict strategy", "skip", "overwrite", "rename")
            "writeReport" bool "Write patch report"
            "writeToFile" bool "Write analysis report file"
            "format".oneOf("Input format for parse_any", "auto", "elf", "pe", "macho", "dex", "art", "oat", "vdex")
            "op".oneOf("Dispatcher operation", "roots", "methods", "parse_any", "validate", "get", "list", "set", "call")
            "objectPath" str "Object path, e.g. sections[0].name or binary.entry"
            "method" str "Method name for dispatcher call"
            "args" arr "Dispatcher arguments"
            "dryRun" bool "Preview dispatcher mutation/build without applying it"
        }) }
    ) { e, a, s ->
        when (a.str("action", "parse")) {
            "capabilities" -> ok(e.capabilityRegistry().getJSONObject("backends").getJSONObject("lief"))
            "dispatch" -> e.liefDispatch(a.str("workspaceId"), a.str("editSessionId"), a.str("op", "roots"), a.str("objectPath"), a.str("method"), a.optJSONArray("args") ?: JSONArray(), a.bool("dryRun", false))
            "parse" -> e.readStats(a.str("workspaceId"), a.str("editSessionId"))
            "parse_any" -> e.liefDispatch(a.str("workspaceId"), a.str("editSessionId"), "parse_any", args = JSONArray().put(a.str("format", "auto")))
            "list" -> e.list(a.str("workspaceId"), a.str("editSessionId"), a.str("subView", "sections"), a.str("query"), a.intValue("limit", s.defaultLimit))
            "patch_address" -> e.liefPatchAddress(a.str("workspaceId"), a.str("editSessionId"), hexLong(a.str("va")) ?: return@EngineToolHandler err("INVALID_ARGUMENT", "va must be hex", "va", a.str("va")), hexBytes(a.str("patchHex")) ?: return@EngineToolHandler err("INVALID_HEX", "patchHex must be valid hex", "patchHex", a.str("patchHex")))
            "add_export" -> e.liefAddExportedFunction(a.str("workspaceId"), a.str("editSessionId"), hexLong(a.str("va")) ?: return@EngineToolHandler err("INVALID_ARGUMENT", "va must be hex", "va", a.str("va")), a.str("name"))
            "remove_symbol" -> e.liefRemoveSymbol(a.str("workspaceId"), a.str("editSessionId"), a.str("name"))
            "build" -> e.build(a.str("workspaceId"), a.str("editSessionId"), a.str("outputName"), a.str("conflictStrategy"), a.optBoolean("writeReport", s.writePatchReport), a.optBoolean("writeToWorkDir", s.buildCopyToWorkDir))
            "fix_sections" -> e.fixSections(a.str("workspaceId"), a.str("editSessionId"))
            "report" -> e.analysisReport(a.str("workspaceId"), a.str("editSessionId"), a.optBoolean("writeToFile", true))
            else -> err("UNKNOWN_ACTION", "Unknown LIEF action", "action", a.str("action"))
        }
    }

    private val unidbgApi = EngineToolHandler(
        ToolMeta("unidbg_api",
            "Unidbg 底层能力网关（session/call/memory/registers/trace/breakpoints）",
            "Low-level Unidbg gateway for live sessions, function/address calls, memory map/read/write/protect/unmap, registers, modules, exports, trace, and breakpoints.",
            "lowlevel", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("Unidbg operation", "capabilities", "dispatch", "status", "call", "dump")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "symbolName" str "Exported symbol to call"
            "args" arr "Integer/string arguments"
            "trace" bool "Enable trace"
            "addr" str "Memory dump VA hex"
            "size" int "Dump size"
            "op".oneOf("Dispatcher operation", "status", "roots", "methods", "session_open", "session_list", "session_close", "session_call", "session_call_address", "session_dump", "session_memory_maps", "session_registers", "session_modules", "session_exports", "session_trace_code", "session_breakpoint_add", "session_debugger_status", "session_breakpoint_remove", "session_single_step", "session_emu_stop", "session_memory_write", "session_memory_map", "session_memory_protect", "session_memory_unmap", "reflect_roots", "reflect_methods", "reflect_invoke", "native_schemas", "native_tool", "call", "dump", "modules", "exports", "imports", "debugger_plan", "memory_map_plan", "registers_plan", "breakpoints_plan", "trace_plan", "framework_matrix", "stub_template", "hook_template", "env_template")
            "method" str "Dispatcher method/symbol name. For native_tool, use an upstream Unidbg MCP tool name returned by native_schemas."
            "args" arr "For native_tool: [emulatorSessionId, toolName, toolArgumentsObject]. Other dispatch operations use their documented positional arguments."
            "dispatchArgs" arr "Alias for args when action=dispatch; kept for schema compatibility"
        }) }
    ) { e, a, s ->
        when (a.str("action", "status")) {
            "capabilities" -> ok(e.capabilityRegistry().getJSONObject("backends").getJSONObject("unidbg"))
            "dispatch" -> e.unidbgDispatch(a.str("workspaceId"), a.str("editSessionId"), a.str("op", "status"), a.str("method"), a.optJSONArray("args") ?: a.optJSONArray("dispatchArgs") ?: JSONArray())
            "status" -> ok(e.emulationStatus().put("enabled", s.emulationEnabled))
            "call" -> if (!s.emulationEnabled) err("EMULATION_DISABLED", "Emulation is disabled", "emulationEnabled", false) else e.emulate(a.str("workspaceId"), a.str("editSessionId"), a.str("symbolName"), a.optJSONArray("args") ?: JSONArray(), a.bool("trace", false))
            "dump" -> if (!s.emulationEnabled) err("EMULATION_DISABLED", "Emulation is disabled", "emulationEnabled", false) else e.dumpMemory(a.str("workspaceId"), a.str("editSessionId"), hexLong(a.str("addr")) ?: return@EngineToolHandler err("INVALID_ARGUMENT", "addr must be hex", "addr", a.str("addr")), a.intValue("size", 256))
            else -> err("UNKNOWN_ACTION", "Unknown Unidbg action", "action", a.str("action"))
        }
    }

    private val unidbgSession = EngineToolHandler(
        ToolMeta("unidbg_session",
            "Unidbg 会话工具（open/list/close/call/dump/modules/exports/registers/maps）",
            "Typed Unidbg session tool for shell-friendly live emulator workflows: open/list/close/call/call_address/dump/modules/exports/registers/memory_maps.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("Session action", "open", "list", "close", "call", "call_address", "dump", "modules", "exports", "registers", "memory_maps")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "emulatorSessionId" str "Live Unidbg emulator session ID"
            "symbolName" str "Symbol to call"
            "addr" str "Hex address for call_address or dump"
            "args" arr "Function arguments"
            "trace" bool "Enable trace for call"
            "size" int "Dump size"
            "callJniOnLoad" bool "Call JNI_OnLoad when opening the session"
        }) }
    ) { e, a, _ ->
        val sessionId = a.str("emulatorSessionId")
        val callArgs = a.optJSONArray("args") ?: JSONArray()
        val dispatchArgs = when (a.str("action", "open")) {
            "open" -> JSONArray().put(a.str("editSessionId")).put(a.bool("callJniOnLoad", true))
            "list" -> JSONArray()
            "close" -> JSONArray().put(sessionId)
            "call" -> JSONArray().put(sessionId).put(a.str("symbolName")).put(callArgs).put(a.bool("trace", false))
            "call_address" -> JSONArray().put(sessionId).put(a.str("addr")).put(callArgs)
            "dump" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.intValue("size", 256))
            "modules", "exports", "registers", "memory_maps" -> JSONArray().put(sessionId)
            else -> return@EngineToolHandler err("UNKNOWN_ACTION", "Unknown Unidbg session action", "action", a.str("action"))
        }
        val op = when (a.str("action", "open")) {
            "open" -> "session_open"
            "list" -> "session_list"
            "close" -> "session_close"
            "call" -> "session_call"
            "call_address" -> "session_call_address"
            "dump" -> "session_dump"
            "modules" -> "session_modules"
            "exports" -> "session_exports"
            "registers" -> "session_registers"
            "memory_maps" -> "session_memory_maps"
            else -> a.str("action")
        }
        e.unidbgDispatch(a.str("workspaceId"), a.str("editSessionId"), op, a.str("symbolName"), dispatchArgs)
    }

    private val unidbgMemory = EngineToolHandler(
        ToolMeta("unidbg_memory",
            "Unidbg 内存工具（map/read/write/protect/unmap/maps）",
            "Typed Unidbg memory tool for command-line scripts: map/read/write/protect/unmap/maps on a live emulator session.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("Memory action", "map", "read", "write", "protect", "unmap", "maps")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "emulatorSessionId" str "Live Unidbg emulator session ID"
            "addr" str "Hex virtual address"
            "size" int "Size in bytes"
            "prot" int "Memory protection flags: 1=r, 2=w, 4=x"
            "hex" str "Hex bytes for write"
        }) }
    ) { e, a, _ ->
        val sessionId = a.str("emulatorSessionId")
        val dispatchArgs = when (a.str("action", "maps")) {
            "map" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.intValue("size", 4096)).put(a.intValue("prot", 3))
            "read" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.intValue("size", 256))
            "write" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.str("hex"))
            "protect" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.intValue("size", 4096)).put(a.intValue("prot", 1))
            "unmap" -> JSONArray().put(sessionId).put(a.str("addr")).put(a.intValue("size", 4096))
            "maps" -> JSONArray().put(sessionId)
            else -> return@EngineToolHandler err("UNKNOWN_ACTION", "Unknown Unidbg memory action", "action", a.str("action"))
        }
        val op = when (a.str("action", "maps")) {
            "map" -> "session_memory_map"
            "read" -> "session_dump"
            "write" -> "session_memory_write"
            "protect" -> "session_memory_protect"
            "unmap" -> "session_memory_unmap"
            "maps" -> "session_memory_maps"
            else -> a.str("action")
        }
        e.unidbgDispatch(a.str("workspaceId"), a.str("editSessionId"), op, "", dispatchArgs)
    }

    private val unidbgDebug = EngineToolHandler(
        ToolMeta("unidbg_debug",
            "Unidbg 调试生命周期（trace/breakpoint/step/stop/status）",
            "Typed Unidbg debugger lifecycle for trace, breakpoint add/list/remove, single-step configuration, stop, and status.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("Debug action", "trace_code", "trace_start", "trace_events", "trace_stop", "trace_clear", "hook_start", "hook_list", "hook_stop", "breakpoint_add", "breakpoint_remove", "status", "single_step", "stop", "debugger_plan", "trace_plan", "breakpoints_plan")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "emulatorSessionId" str "Live Unidbg emulator session ID"
            "begin" str "Trace begin address"
            "end" str "Trace end address"
            "addr" str "Breakpoint address"
            "count" int "Single-step instruction count"
            "traceType".oneOf("Trace callback type", "code", "read", "write")
            "traceId" str "Trace hook ID"
            "cursor" int "Trace event cursor"
            "limit" int "Trace event page size, max 1000"
            "hookType".oneOf("Backend hook type", "syscall", "interrupt", "code", "read", "write")
            "hookId" str "Backend hook ID"
        }) }
    ) { e, a, _ ->
        val action = a.str("action", "debugger_plan")
        val op = when (action) {
            "trace_code" -> "session_trace_code"
            "trace_start" -> "session_trace_start"
            "trace_events" -> "session_trace_events"
            "trace_stop" -> "session_trace_stop"
            "trace_clear" -> "session_trace_clear"
            "hook_start" -> "session_hook_start"
            "hook_list" -> "session_hook_list"
            "hook_stop" -> "session_hook_stop"
            "breakpoint_add" -> "session_breakpoint_add"
            "breakpoint_remove" -> "session_breakpoint_remove"
            "status" -> "session_debugger_status"
            "single_step" -> "session_single_step"
            "stop" -> "session_emu_stop"
            "debugger_plan", "trace_plan", "breakpoints_plan" -> action
            else -> return@EngineToolHandler err("UNKNOWN_ACTION", "Unknown Unidbg debug action", "action", action)
        }
        val dispatchArgs = when (action) {
            "trace_code" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("begin")).put(a.str("end"))
            "trace_start" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("traceType", "code")).put(a.str("begin")).put(a.str("end"))
            "trace_events" -> JSONArray().put(a.str("emulatorSessionId")).put(a.intValue("cursor", 0)).put(a.intValue("limit", 100))
            "trace_stop" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("traceId"))
            "trace_clear" -> JSONArray().put(a.str("emulatorSessionId"))
            "hook_start" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("hookType", "syscall")).put(a.str("begin")).put(a.str("end"))
            "hook_list" -> JSONArray().put(a.str("emulatorSessionId"))
            "hook_stop" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("hookId"))
            "breakpoint_add" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("addr"))
            "breakpoint_remove" -> JSONArray().put(a.str("emulatorSessionId")).put(a.str("addr"))
            "status", "stop" -> JSONArray().put(a.str("emulatorSessionId"))
            "single_step" -> JSONArray().put(a.str("emulatorSessionId")).put(a.intValue("count", 1))
            else -> JSONArray()
        }
        e.unidbgDispatch(a.str("workspaceId"), a.str("editSessionId"), op, "", dispatchArgs)
    }

    private val unidbgBatch = EngineToolHandler(
        ToolMeta("unidbg_batch",
            "Unidbg 批处理工具（一条 JSON 顺序执行多个 Unidbg op）",
            "Run a serial Unidbg pipeline in one MCP call. Steps support ${'$'}{key.path} placeholders, ideal for curl/PowerShell batch scripts.",
            "emulate", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Default Workspace ID for steps"
            "editSessionId" str "Default edit session ID for steps"
            "steps" arr "Array of steps: {op, method?, args?, resultKey?}. Placeholders like ${'$'}{open.emulatorSessionId} are supported."
            "stopOnError" bool "Abort on first failed step, default true"
            "maxSteps" int "Maximum steps, default 30, max 100"
        }) }
    ) { e, a, _ -> runUnidbgBatch(e, a) }

    private val xansoApi = EngineToolHandler(
        ToolMeta("xanso_api",
            "真实 xAnSo 上游能力网关（status/help/build-section）",
            "Real freakishfox/xAnSo upstream gateway covering its complete public CLI/core functionality.",
            "lowlevel", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("xAnSo operation", "capabilities", "dispatch", "status", "help", "build-section", "fix_sections")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "op".oneOf("Dispatcher operation", "status", "roots", "methods", "capabilities", "help", "build-section", "fix_sections")
            "force" bool "Rebuild even when a parseable section table is already present"
        }) }
    ) { e, a, _ ->
        when (a.str("action", "status")) {
            "capabilities" -> ok(e.capabilityRegistry().getJSONObject("backends").getJSONObject("xanso"))
            "dispatch" -> e.xansoDispatch(a.str("workspaceId"), a.str("editSessionId"), a.str("op", "status"))
            "status", "help" -> e.xansoDispatch(a.str("workspaceId"), a.str("editSessionId"), a.str("action"))
            "build-section", "fix_sections" -> e.xansoBuildSections(a.str("workspaceId"), a.str("editSessionId"), a.bool("force", false))
            else -> err("UNKNOWN_ACTION", "Unknown xAnSo action", "action", a.str("action"))
        }
    }

    // ── SESSION ──

    private val sessionOpen = EngineToolHandler(
        ToolMeta("session_open",
            "打开编辑会话（基于当前工作区 SO 的副本）",
            "Open an edit session: creates a mutable copy of the workspace SO for patching.",
            "session", ToolClass.CORE,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
        }) }
    ) { e, a, _ -> e.editOpen(a.str("workspaceId")) }

    private val sessionHistory = object : ToolHandler {
        override val meta = ToolMeta("session_history",
            "编辑历史管理（snapshot/rollback/undo/redo/reset/check）",
            "Edit session history: snapshot, rollback, undo, redo, reset, or check integrity.",
            "session", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("snapshot (default) | rollback | undo | redo | reset | check", "snapshot", "rollback", "undo", "redo", "reset", "check")
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID"
            "label" str "Snapshot label (action=snapshot)"
            "snapshotIndex" int "Snapshot index for rollback (-1 = latest, action=rollback)"
            "count" int "Undo/redo count (action=undo|redo)"
        }) }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val e = ctx.engine
            return when (args.str("action", "snapshot")) {
                "snapshot" -> e.editSnapshot(args.str("workspaceId"), args.str("editSessionId"), args.str("label"))
                "rollback" -> e.editRollback(args.str("workspaceId"), args.str("editSessionId"), args.intValue("snapshotIndex", -1))
                "undo" -> e.editUndo(args.str("workspaceId"), args.str("editSessionId"), args.intValue("count", 1))
                "redo" -> e.editRedo(args.str("workspaceId"), args.str("editSessionId"), args.intValue("count", 1))
                "reset" -> e.editReset(args.str("workspaceId"), args.str("editSessionId"))
                "check" -> e.editCheck(args.str("workspaceId"), args.str("editSessionId"))
                else -> err("UNKNOWN_ACTION", "Unknown action: ${args.str("action")}", "action", args.str("action"))
            }
        }
    }

    private val sessionAudit = object : ToolHandler {
        override val meta = ToolMeta("session_audit",
            "审计日志（audit/persist/list/load）",
            "Edit session audit trail: view audit, persist to file, list saved audits, or load a saved audit.",
            "session", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("audit (default) | persist | list | load", "audit", "persist", "list", "load")
            "workspaceId" str "Workspace ID (audit/persist)"
            "editSessionId" str "Edit session ID (audit/persist)"
            "prefix" str "File prefix filter (list)"
            "limit" int "Maximum items (list)"
            "file" str "Audit file path (load)"
        }) }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val e = ctx.engine
            return when (args.str("action", "audit")) {
                "audit" -> e.editAudit(args.str("workspaceId"), args.str("editSessionId"))
                "persist" -> e.persistAudit(args.str("workspaceId"), args.str("editSessionId"))
                "list" -> e.listAudits(args.str("prefix"), args.intValue("limit", 100))
                "load" -> e.loadAudit(args.str("file"))
                else -> err("UNKNOWN_ACTION", "Unknown action: ${args.str("action")}", "action", args.str("action"))
            }
        }
    }

    // ── BUILD ──

    private val buildSo = object : ToolHandler {
        override val meta = ToolMeta("build_so",
            "构建补丁后的 SO（action=build 输出文件 / action=list 列出已构建）",
            "Build patched SO to file, or list built outputs. Supports single and multi-variant build.",
            "build", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "action".oneOf("build (default) | list", "build", "list")
            "workspaceId" str "Workspace ID (build)"
            "editSessionId" str "Edit session ID (build)"
            "outputName" str "Output file name (build)"
            "outputs" arr ("Array of output variants (multi-build)" to SchemaBuilder.outputsSchema())
            "conflictStrategy".oneOf("skip | overwrite | rename (default)", "skip", "overwrite", "rename")
            "writeReport" bool "Write patch-report JSON sidecar"
            "writeToWorkDir" bool "Mirror output into work directory"
            "prefix" str "File prefix filter (list)"
            "limit" int "Maximum items (list)"
        }) }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val e = ctx.engine
            val s = ctx.settings
            return when (args.str("action", "build")) {
                "list" -> e.listBuildOutputs(args.str("prefix"), args.intValue("limit", 200))
                else -> {
                    val outputs = args.optJSONArray("outputs")
                    if (outputs != null && outputs.length() > 0) {
                        e.buildMany(args.str("workspaceId"), args.str("editSessionId"), outputs, args.str("conflictStrategy"), args.optBoolean("writeReport", s.writePatchReport), args.optBoolean("writeToWorkDir", s.buildCopyToWorkDir))
                    } else {
                        e.build(args.str("workspaceId"), args.str("editSessionId"), args.str("outputName"), args.str("conflictStrategy"), args.optBoolean("writeReport", s.writePatchReport), args.optBoolean("writeToWorkDir", s.buildCopyToWorkDir))
                    }
                }
            }
        }
    }

    // ── SYSTEM ──

    private val systemControl = object : ToolHandler {
        override val meta = ToolMeta("system_control",
            "系统控制（tunnel/apk_mcp/status）",
            "System control: tunnel start/stop/status, APK MCP bridge status/probe/ping, overall system status.",
            "system", ToolClass.META,
        ) { objectSchema(props {
            "action".oneOf("status | tunnel_start | tunnel_stop | tunnel_status | tunnel_stats | apk_status | apk_probe | apk_ping", "status", "tunnel_start", "tunnel_stop", "tunnel_status", "tunnel_stats", "apk_status", "apk_probe", "apk_ping")
            "mode".oneOf("Tunnel mode: quick | named (tunnel_start)", "quick", "named")
            "targetPort" int "Tunnel target port (tunnel_start)"
            "probe" bool "Force re-probe (apk_status/status)"
        }) }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val hooked = ctx as? HookedContext ?: return JSONObject().put("error", "System hooks not available")
            return when (args.str("action", "status")) {
                "status" -> hooked.sysStatusHook(args.bool("probe", false))
                "tunnel_start" -> hooked.tunnelStartHook(args.str("mode", "quick"), args.intValue("targetPort", 0), "")
                "tunnel_stop" -> hooked.tunnelStopHook()
                "tunnel_status" -> hooked.tunnelStatusHook()
                "tunnel_stats" -> hooked.tunnelStatsHook(args.bool("probe", false))
                "apk_status" -> hooked.apkStatusHook(args.bool("probe", false))
                "apk_probe" -> hooked.apkProbeHook()
                "apk_ping" -> hooked.apkPingHook()
                else -> err("UNKNOWN_ACTION", "Unknown action: ${args.str("action")}", "action", args.str("action"))
            }
        }
    }

    private val appConfig = object : ToolHandler {
        override val meta = ToolMeta(
            "app_config",
            "读写应用全部配置（外观/服务/引擎/隧道/桥接）",
            "Read and write all app settings: appearance, service, engine limits, tunnel, APK bridge. Designed for AI-driven full configuration of the SOMCP app.",
            "system", ToolClass.META,
        ) {
            objectSchema(props {
                "action".oneOf("get (default) | set | schema | reset_token", "get", "set", "schema", "reset_token")
                "maskSecrets" bool "Mask tokens in get output (default true)"
                "allowSecrets" bool "Allow writing secret fields on set (default true)"
                "config" str "JSON object string or nested object for set (appearance/service/engine/tunnel/apkBridge or flat keys)"
                "themeMode".oneOf("Flat set helper", "system", "light", "dark")
                "accentColor".oneOf("Flat set helper", "blue", "teal", "indigo", "purple", "green", "orange", "red", "mono")
                "uiDensity".oneOf("Flat set helper", "compact", "comfortable", "spacious")
                "cornerStyle".oneOf("Flat set helper", "small", "medium", "large", "xlarge")
                "motionMode".oneOf("Flat set helper", "system", "reduced", "full")
                "textScale".oneOf("Flat set helper", "normal", "large", "xlarge")
                "language".oneOf("Flat set helper", "system", "zh", "en")
                "pureBlackDark" bool "Flat set helper"
                "showAdvancedHome" bool "Flat set helper"
                "highContrast" bool "Flat set helper"
                "port" int "Flat set helper"
                "bindHost" str "Flat set helper: 0.0.0.0 or 127.0.0.1"
                "authEnabled" bool "Flat set helper"
                "accessToken" str "Flat set helper"
                "leanTools" bool "Flat set helper"
                "emulationEnabled" bool "Flat set helper"
                "tunnelMode".oneOf("Flat set helper", "off", "quick", "named")
                "apkMcpUrl" str "Flat set helper"
            })
        }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val settings = ctx.settings
            return when (args.str("action", "get")) {
                "schema" -> ok(settings.schema())
                "reset_token" -> ok(JSONObject().put("accessToken", settings.resetAccessToken()).put("authEnabled", settings.authEnabled))
                "set" -> {
                    val patch = when {
                        args.opt("config") is JSONObject -> args.getJSONObject("config")
                        args.optString("config").isNotBlank() -> runCatching { JSONObject(args.optString("config")) }.getOrElse {
                            return err("INVALID_CONFIG", "config must be a JSON object: ${it.message}")
                        }
                        else -> args
                    }
                    settings.applyPatch(patch, allowSecrets = args.bool("allowSecrets", true))
                }
                else -> ok(settings.snapshot(maskSecrets = args.bool("maskSecrets", true)))
            }
        }
    }

    // ── META ──

    private val metaInfo = object : ToolHandler {
        override val meta = ToolMeta("meta_info",
            "元信息（help/tools/stats/batch/continue/health）",
            "Meta information: help text, tool list/describe, stats, batch pipeline, continue pagination, health check.",
            "meta", ToolClass.META,
        ) { objectSchema(props {
            "action".oneOf("help (default) | tools | describe | stats | batch | continue | health | count | workflows | suggest | errors | report | capabilities", "help", "tools", "describe", "stats", "batch", "continue", "health", "count", "workflows", "suggest", "errors", "report", "capabilities")
            "category" str "Category filter (tools)"
            "query" str "Search query (tools)"
            "tools" arr "Array of tool names (describe)"
            "steps" arr ("Batch pipeline steps (batch)" to SchemaBuilder.batchStepsSchema())
            "cursor" str "Pagination cursor (continue)"
            "transactional" bool "If true, snapshot edit sessions before batch steps and rollback them when a later step fails"
            "workspaceId" str "Workspace ID (suggest/report)"
            "editSessionId" str "Edit session ID (suggest/report)"
            "format".oneOf("Report format", "json")
            "writeToFile" bool "Write report JSON to app files (report)"
            "reset" bool "Reset stats (stats)"
        }) }
        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject {
            val hooked = ctx as? HookedContext ?: return JSONObject().put("error", "Meta hooks not available")
            return when (args.str("action", "help")) {
                "help" -> hooked.helpHook()
                "tools" -> hooked.listToolsHook(args.str("category"), args.str("query"))
                "describe" -> {
                    val names = args.optJSONArray("tools") ?: JSONArray()
                    val list = (0 until names.length()).map { names.optString(it) }
                    hooked.describeToolsHook(list)
                }
                "stats" -> {
                    if (args.bool("reset", false)) hooked.resetStatsHook()
                    hooked.statsHook()
                }
                "workflows" -> hooked.workflowsHook()
                "suggest" -> hooked.suggestHook(args)
                "errors" -> hooked.errorsHook()
                "report" -> hooked.reportHook(args)
                "capabilities" -> hooked.capabilitiesHook()
                "batch" -> hooked.batchHook(args)
                "continue" -> hooked.continueHook(args.str("cursor"))
                "health" -> hooked.healthHook()
                "count" -> hooked.toolsCountHook()
                else -> err("UNKNOWN_ACTION", "Unknown action: ${args.str("action")}", "action", args.str("action"))
            }
        }
    }

    // ── Registry ──

    val ALL: List<ToolHandler> = listOf(
        soOpen, soClose, apkAnalyze,
        analyzeElf, readStats, analysisReport, analyzeFunctions, analyzeCfg, analyzeCrypto, analyzeXrefs, analyzeEsil,
        searchBytes, searchStrings,
        readDisasm, readHexdump,
        editHex, editAsm, editSymbol, editFixSections,
        emulateCall, emulateDump,
        unidbgSession, unidbgMemory, unidbgDebug, unidbgBatch,
        diffSo,
        rizinApi, liefApi, unidbgApi, xansoApi,
        sessionOpen, sessionHistory, sessionAudit,
        buildSo,
        systemControl,
        appConfig,
        metaInfo,
    )

    val byName: Map<String, ToolHandler> = ALL.associateBy { it.meta.name }
    val heavyNames: Set<String> = ALL.filter { it.meta.heavy }.map { it.meta.name }.toSet()
    val names: List<String> = ALL.map { it.meta.name }
    fun leanNames(): List<String> = ALL.filter { it.meta.cls == ToolClass.CORE || it.meta.cls == ToolClass.META || it.meta.category == "lowlevel" }.map { it.meta.name }

    fun leanNames(popularity: Map<String, Long>?): List<String> {
        if (popularity == null || popularity.isEmpty()) return leanNames()
        val base = leanNames().toMutableSet()
        val candidates = ALL.filter { it.meta.cls == ToolClass.EXTRA }
            .mapNotNull { e -> popularity[e.meta.name]?.let { e.meta.name to it } }
            .sortedByDescending { it.second }
            .take(ADAPTIVE_PROMOTION_SLOTS)
            .map { it.first }
        base.addAll(candidates)
        return base.toList()
    }

    fun description(name: String, zh: Boolean): String =
        byName[name]?.let { if (zh) it.meta.zh else it.meta.en } ?: name

    private val ADAPTIVE_PROMOTION_SLOTS = 5

    private val unidbgBatchKeyPattern = Regex("\\$\\{([a-zA-Z0-9_]+)([^}]*)\\}")
    private val unidbgBatchResultKeyPattern = Regex("^[a-zA-Z0-9_]+$")
    private val unidbgBatchIndexPattern = Regex("\\[(\\d+)\\]")

    private fun runUnidbgBatch(e: com.soreverse.mcp.engine.NativeSoEngine, args: JSONObject): JSONObject {
        val steps = args.optJSONArray("steps") ?: return err("BAD_REQUEST", "steps[] is required", "steps", JSONArray())
        val stopOnError = if (args.has("stopOnError")) args.bool("stopOnError", true) else true
        val maxSteps = args.intValue("maxSteps", 30).coerceIn(1, 100)
        if (steps.length() > maxSteps) return err("TOO_MANY_STEPS", "Too many Unidbg batch steps", "maxSteps", maxSteps)
        val keyed = HashMap<String, JSONObject>()
        val out = JSONArray()
        for (i in 0 until steps.length()) {
            val step = steps.optJSONObject(i) ?: JSONObject()
            val op = step.optString("op", "status")
            val method = substituteUnidbgBatchString(step.optString("method"), keyed)
            val stepWorkspaceId = substituteUnidbgBatchString(step.optString("workspaceId", args.str("workspaceId")), keyed)
            val stepEditSessionId = substituteUnidbgBatchString(step.optString("editSessionId", args.str("editSessionId")), keyed)
            val dispatchArgs = substituteUnidbgBatchValue(step.optJSONArray("args") ?: JSONArray(), keyed) as JSONArray
            val result = try {
                e.unidbgDispatch(stepWorkspaceId, stepEditSessionId, op, method, dispatchArgs)
            } catch (ex: Exception) {
                JSONObject().put("ok", false).put("error", JSONObject().put("code", "STEP_EXCEPTION").put("message", ex.message ?: ex.javaClass.simpleName))
            }
            val okStep = result.optBoolean("ok", true)
            val resultKey = step.optString("resultKey").trim()
            val envelope = JSONObject()
                .put("step", i)
                .put("op", op)
                .put("method", method)
                .put("args", dispatchArgs)
                .put("resultKey", resultKey)
                .put("ok", okStep)
                .put("result", result)
            out.put(envelope)
            if (resultKey.matches(unidbgBatchResultKeyPattern)) keyed[resultKey] = result
            if (!okStep && stopOnError) return ok(JSONObject().put("steps", out).put("executedCount", i + 1).put("aborted", true))
        }
        return ok(JSONObject().put("steps", out).put("executedCount", out.length()).put("aborted", false))
    }

    private fun substituteUnidbgBatchValue(value: Any?, keyed: Map<String, JSONObject>): Any = when (value) {
        is JSONObject -> JSONObject().also { copy -> value.keys().forEach { key -> copy.put(key, substituteUnidbgBatchValue(value.opt(key), keyed)) } }
        is JSONArray -> JSONArray().also { copy -> for (i in 0 until value.length()) copy.put(substituteUnidbgBatchValue(value.opt(i), keyed)) }
        is String -> substituteUnidbgBatchString(value, keyed)
        null -> JSONObject.NULL
        else -> value
    }

    private fun substituteUnidbgBatchString(raw: String, keyed: Map<String, JSONObject>): String {
        if (raw.isEmpty()) return raw
        return unidbgBatchKeyPattern.replace(raw) { match ->
            val root = keyed[match.groupValues[1]] ?: return@replace match.value
            val path = match.groupValues[2].trimStart('.')
            val value = resolveUnidbgBatchPath(root, path)
            when (value) {
                null, JSONObject.NULL -> ""
                is JSONObject, is JSONArray -> value.toString()
                else -> value.toString()
            }
        }
    }

    private fun resolveUnidbgBatchPath(root: Any, path: String): Any? {
        if (path.isBlank()) return root
        var cur: Any? = root
        for (part in path.split('.').filter { it.isNotBlank() }) {
            val name = part.substringBefore('[')
            if (name.isNotBlank()) cur = (cur as? JSONObject)?.opt(name) ?: return null
            val indexes = unidbgBatchIndexPattern.findAll(part).mapNotNull { it.groupValues[1].toIntOrNull() }
            for (idx in indexes) cur = (cur as? JSONArray)?.opt(idx) ?: return null
        }
        return cur
    }

    fun categoryDescriptions(zh: Boolean): List<Pair<String, String>> = listOf(
        "workspace" to (if (zh) "工作区生命周期：列出、打开、关闭 SO" else "Workspace lifecycle: list, open, close SO files"),
        "analyze" to (if (zh) "深度分析：ELF 结构、函数列表、CFG、密码学扫描、交叉引用、ESIL 模拟" else "Deep analysis: ELF structure, functions, CFG, crypto scan, xrefs, ESIL emulation"),
        "search" to (if (zh) "搜索：十六进制模式、字符串" else "Search: hex patterns, strings"),
        "read" to (if (zh) "读取：反汇编、十六进制转储" else "Read: disassembly, hex dumps"),
        "edit" to (if (zh) "补丁：字节/汇编/符号 + xAnSo 节区头重建" else "Patch: bytes/asm/symbols + xAnSo section rebuild"),
        "emulate" to (if (zh) "模拟执行：Unidbg + DalvikVM 函数调用、内存转储" else "Emulate: Unidbg + DalvikVM function calls, memory dump"),
        "diff" to (if (zh) "差异对比：结构化 SO 版本差异" else "Diff: structural SO version diff"),
        "lowlevel" to (if (zh) "底层 API 网关：Rizin / LIEF / Unidbg / xAnSo 聚合入口" else "Low-level API gateways: aggregated Rizin / LIEF / Unidbg / xAnSo access"),
        "session" to (if (zh) "编辑会话：打开、历史管理、审计" else "Edit session: open, history, audit"),
        "build" to (if (zh) "构建：输出补丁后的 SO 文件" else "Build: export patched SO file"),
        "system" to (if (zh) "系统控制：隧道、APK MCP 桥" else "System: tunnel, APK MCP bridge"),
        "meta" to (if (zh) "元信息：帮助、工具列表、统计、批量、分页" else "Meta: help, tool list, stats, batch, pagination"),
    )

    fun grouped(zh: Boolean, includeApk: List<String> = emptyList()): List<Pair<String, List<Pair<String, String>>>> {
        val groups = LinkedHashMap<String, MutableList<Pair<String, String>>>()
        val order = categoryDescriptions(zh).map { it.first }
        order.forEach { groups[it] = mutableListOf() }
        ALL.forEach { e -> groups[e.meta.category]?.add(e.meta.name to (if (zh) e.meta.zh else e.meta.en)) }
        if (includeApk.isNotEmpty()) {
            groups["apk-bridge"] = includeApk.map { it to it }.toMutableList()
        }
        return order.map { it to (groups[it] ?: emptyList()) }.filter { it.second.isNotEmpty() }
    }

    fun toolDescriptor(handler: ToolHandler, includeCategory: Boolean): JSONObject {
        val schema = handler.meta.schemaBuilder(SchemaBuilder)
        val obj = JSONObject()
            .put("name", handler.meta.name)
            .put("description", handler.meta.en)
            .put("inputSchema", schema)
        if (includeCategory) obj.put("category", handler.meta.category)
        return obj
    }

    fun categoryOf(name: String): String? = byName[name]?.meta?.category
}
