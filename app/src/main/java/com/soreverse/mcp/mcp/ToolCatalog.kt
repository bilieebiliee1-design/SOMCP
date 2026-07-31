package com.soreverse.mcp.mcp

import com.soreverse.mcp.core.bool
import com.soreverse.mcp.core.doubleValue
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.HexCodec
import com.soreverse.mcp.core.intValue
import com.soreverse.mcp.core.obj
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import org.json.JSONArray
import org.json.JSONObject

object ToolCatalog {

    private val pathArg: JSONObject.() -> String = { str("path").ifBlank { str("filePath").ifBlank { str("inputPath").ifBlank { str("soPath") } } } }

    // ── 扩展工具（低难度功能） ──

    private val decompileFunction = EngineToolHandler(
        ToolMeta("decompile_function",
            "Ghidra 伪代码反编译（直接返回伪 C 代码）",
            "Decompile a function to pseudocode via rizin-ghidra.",
            "analyze", ToolClass.CORE, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "locator" str "Function locator or name"
            "addr" str "Hex VA fallback"
            "strict" bool "Fail if rizin-ghidra unavailable"
        }) }
    ) { e, a, _ -> e.rzDecompile(
        a.str("workspaceId"), a.str("editSessionId"),
        a.str("locator").ifBlank { a.str("addr") },
        a.bool("strict", true)
    )}

    private val exportCallgraph = EngineToolHandler(
        ToolMeta("export_callgraph",
            "调用图可视化导出（DOT / Mermaid 格式）",
            "Export callgraph as DOT or Mermaid for visualization.",
            "analyze", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
            "format".oneOf("dot (default) | mermaid", "dot", "mermaid")
            "functionName" str "Focus on specific function (blank = all)"
        }) }
    ) { e, a, _ -> e.rzCallgraph(
        a.str("workspaceId"), a.str("editSessionId"),
        a.str("format", "dot"), a.str("functionName")
    )}

    private val diffReport = EngineToolHandler(
        ToolMeta("diff_report",
            "结构化 SO diff 报告（新增/删除/修改函数 + 相似度）",
            "Structured diff report: added/removed/modified functions + similarity.",
            "diff", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceIdA" str "Workspace A ID"
            "editSessionIdA" str "Edit session A ID (optional)"
            "workspaceIdB" str "Workspace B ID"
            "editSessionIdB" str "Edit session B ID (optional)"
        }) }
    ) { e, a, _ -> e.diffReport(
        a.str("workspaceIdA"), a.str("editSessionIdA"),
        a.str("workspaceIdB"), a.str("editSessionIdB")
    )}

    private val exportHtmlReport = EngineToolHandler(
        ToolMeta("export_html_report",
            "导出 HTML 格式分析报告（可分享）",
            "Export analysis report as shareable HTML page.",
            "analyze", ToolClass.EXTRA, heavy = true,
        ) { objectSchema(props {
            "workspaceId" str "Workspace ID"
            "editSessionId" str "Edit session ID (optional)"
        }) }
    ) { e, a, _ -> e.exportHtmlReport(a.str("workspaceId"), a.str("editSessionId")) }

    // ── Registry ──

    val ALL: List<ToolHandler> = listOf(
        soOpen, soClose, apkAnalyze, flutterBlutter,
        // ── 新增扩展工具 ──
        decompileFunction, exportCallgraph, diffReport, exportHtmlReport,
        // ── 原有工具 ──
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

    internal val registry = ToolCatalogRegistry(ALL)
    val byName: Map<String, ToolHandler> = registry.byName
    val heavyNames: Set<String> = registry.heavyNames
    val names: List<String> = registry.names
    fun leanNames(): List<String> = registry.leanNames()

    fun leanNames(popularity: Map<String, Long>?): List<String> = registry.leanNames(popularity)

    fun description(name: String, zh: Boolean): String = registry.description(name, zh)

    fun categoryDescriptions(zh: Boolean): List<Pair<String, String>> = ToolCatalogPresentation.categoryDescriptions(zh)

    fun grouped(zh: Boolean, includeApk: List<String> = emptyList()): List<Pair<String, List<Pair<String, String>>>> =
        ToolCatalogPresentation.grouped(zh, includeApk)

    fun toolDescriptor(handler: ToolHandler, includeCategory: Boolean): JSONObject =
        ToolCatalogPresentation.toolDescriptor(handler, includeCategory)

    fun categoryOf(name: String): String? = registry.categoryOf(name)
}