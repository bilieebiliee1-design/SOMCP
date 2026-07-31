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

    // ── WORKSPACE ──

    private val soOpen = EngineToolHandler(
        ToolMeta("so_open",
            "【SO 分析入口】打开 SO 文件并创建工作区（action=list 列出可用 SO）。所有 .so/.ELF 文件操作必须从 so_open 开始，不要使用 mt_apk_*。",
            "【PRIMARY SO ENTRY POINT】Open a SO file and create a workspace. Use action=list to discover available SO files. Use action=open_url to download a http(s) SO into the selected work directory, then open and analyze it. All .so/ELF tasks MUST start from so_open — do NOT use mt_apk_* for SO files.",
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

    private val flutterBlutter = EngineToolHandler(
        ToolMeta(
            "flutter_blutter",
            "Flutter AOT/Blutter 聚合工具：识别 Flutter APK、提取版本指纹，并使用内置 Flutter 3.44.x / Dart 3.12.2 arm64 Runner 完成本地分析。其他版本会明确返回不支持。",
            "Aggregated Flutter AOT and Blutter tool using the embedded Flutter 3.44.x / Dart 3.12.2 arm64 runner. Other versions return an explicit unsupported-version result.",
            "analyze",
            ToolClass.CORE,
            heavy = true,
        ) {
            objectSchema(props {
                "action".oneOf("inspect | analyze | status | result | cancel | packages | prune", "inspect", "analyze", "status", "result", "cancel", "packages", "prune")
                "path" str "APK path or directory containing libapp.so and libflutter.so."
                "jobId" str "Persistent Blutter job id for status, result, or cancel."
                "abi".oneOf("Target ABI", "auto", "arm64-v8a", "x86_64", "armeabi-v7a", "x86")
                "backend".oneOf("Execution backend", "auto", "embedded")
                "limit" int "Maximum result entities, 1..1000."
                "kind".oneOf("Paged result collection", "libraries", "classes", "functions", "objects")
                "cursor" str "Opaque cursor returned by a previous result page."
                "olderThanMillis" int "Prune cached results older than this duration."
            })
        },
    ) { engine, args, _ -> engine.flutterBlutter(args) }

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