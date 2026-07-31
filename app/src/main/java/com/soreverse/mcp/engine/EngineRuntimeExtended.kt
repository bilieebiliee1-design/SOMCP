package com.soreverse.mcp.engine

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject

// ── 1. 调用图可视化导出 ──

internal fun EngineRuntime.rzCallgraph(
    workspaceId: String,
    editSessionId: String = "",
    format: String = "dot",
    functionName: String = ""
): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin native backend not loaded")

    when (format.lowercase()) {
        "dot" -> {
            val cmd = if (functionName.isNotBlank()) "ag @ $functionName; agf" else "agf"
            val result = JSONObject(NativeEngine.active().command(bytes, elf.architecture, cmd, false))
            if (result.has("error")) return@guarded err("RIZIN_COMMAND_FAILED", result.optString("error"))
            ok(JSONObject()
                .put("format", "dot")
                .put("content", result.optString("text", result.optString("output", "")))
                .put("workspaceId", workspaceId)
                .put("functionName", functionName))
        }
        "mermaid" -> {
            val cmd = if (functionName.isNotBlank()) "ag @ $functionName; agf" else "agf"
            val result = JSONObject(NativeEngine.active().command(bytes, elf.architecture, cmd, false))
            if (result.has("error")) return@guarded err("RIZIN_COMMAND_FAILED", result.optString("error"))
            ok(JSONObject()
                .put("format", "mermaid")
                .put("content", tryConvertDotToMermaid(result.optString("text", "")))
                .put("workspaceId", workspaceId)
                .put("functionName", functionName))
        }
        else -> return@guarded err("INVALID_FORMAT", "Use 'dot' or 'mermaid'")
    }
}

private fun tryConvertDotToMermaid(dot: String): String {
    if (dot.isBlank()) return ""
    val sb = StringBuilder().appendLine("graph TD")
    Regex("""(\w+)\s*\[label="([^"]*)"""").findAll(dot).forEach {
        sb.appendLine("    ${it.groupValues[1]}[\"${it.groupValues[2].take(30)}\"]")
    }
    Regex("""(\w+)\s*->\s*(\w+)""").findAll(dot).forEach {
        sb.appendLine("    ${it.groupValues[1]} --> ${it.groupValues[2]}")
    }
    return sb.toString()
}

// ── 2. 结构化 diff 报告 ──

internal fun EngineRuntime.diffReport(
    workspaceIdA: String, editSessionIdA: String,
    workspaceIdB: String, editSessionIdB: String
): JSONObject = guarded {
    if (!NativeEngine.active().available()) return@guarded err("RIZIN_UNAVAILABLE", "Rizin not loaded")

    val bytesA = dataFor(workspaceIdA, editSessionIdA)
    val bytesB = dataFor(workspaceIdB, editSessionIdB)
    val elfA = elfFor(workspaceIdA, editSessionIdA)
    val elfB = elfFor(workspaceIdB, editSessionIdB)

    val funcsA = extractFuncs(bytesA, elfA).associateBy { it.name }
    val funcsB = extractFuncs(bytesB, elfB).associateBy { it.name }

    val added = funcsB.filterKeys { it !in funcsA }
    val removed = funcsA.filterKeys { it !in funcsB }
    val modified = funcsA.filter { (n, f) -> n in funcsB && funcsB[n]!!.size != f.size }
        .map { (n, f) -> JSONObject().put("name", n).put("oldSize", f.size).put("newSize", funcsB[n]!!.size) }

    val similarity = funcsA.keys.intersect(funcsB.keys).size.toDouble() /
        maxOf((funcsA.keys + funcsB.keys).size, 1)

    ok(JSONObject()
        .put("workspaceIdA", workspaceIdA).put("workspaceIdB", workspaceIdB)
        .put("summary", JSONObject()
            .put("totalA", funcsA.size).put("totalB", funcsB.size)
            .put("added", added.size).put("removed", removed.size).put("modified", modified.size)
            .put("similarity", String.format("%.1f%%", similarity * 100)))
        .put("added", JSONArray(added.map { (n, i) -> JSONObject().put("name", n).put("size", i.size) }))
        .put("removed", JSONArray(removed.map { (n, i) -> JSONObject().put("name", n).put("size", i.size) }))
        .put("modified", JSONArray(modified)))
}

private data class FuncInfo(val name: String, val addr: String, val size: Int)

private fun EngineRuntime.extractFuncs(bytes: ByteArray, elf: ElfFile): List<FuncInfo> {
    if (!NativeEngine.active().available()) return emptyList()
    val arr = runCatching { JSONArray(NativeEngine.active().functions(bytes, elf.architecture)) }.getOrNull() ?: return emptyList()
    return (0 until arr.length()).mapNotNull { i ->
        val item = arr.optJSONObject(i) ?: return@mapNotNull null
        FuncInfo(item.optString("name"), hex(item.optLong("addr")), item.optLong("size").toInt())
    }
}

// ── 3. HTML 报告导出 ──

internal fun EngineRuntime.exportHtmlReport(workspaceId: String, editSessionId: String = ""): JSONObject = guarded {
    val resolvedId = resolveWorkspaceId(workspaceId, "")
    val ws = workspaces[resolvedId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found")
    val reportData = analysisReport(resolvedId, editSessionId, false).optJSONObject("report")
        ?: return@guarded err("REPORT_FAILED", "Failed to generate report")

    val html = buildHtmlReport(reportData, ws.source.name)
    val dir = reportDir()
    val safeName = ws.source.name.replace(Regex("[^A-Za-z0-9._-]"), "_")
    val file = File(dir, "${safeName}.${System.currentTimeMillis()}.report.html")
    file.writeText(html)

    ok(JSONObject().put("path", file.absolutePath).put("size", file.length()).put("format", "html"))
}

private fun buildHtmlReport(data: JSONObject, sourceName: String): String {
    val sections = data.optJSONArray("sections") ?: JSONArray()
    val functions = data.optJSONArray("functions") ?: JSONArray()
    val crypto = data.optJSONArray("crypto") ?: JSONArray()
    val recommendations = data.optJSONArray("recommendations") ?: JSONArray()

    return """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>SOMCP 分析报告 - $sourceName</title>
        <style>
            body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
            .container{max-width:1200px;margin:0 auto}
            h1{color:#58a6ff}h2{color:#79c0ff;border-bottom:1px solid #21262d;padding-bottom:5px;margin-top:20px}
            .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:20px 0}
            .stat{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:15px;text-align:center}
            .stat-val{font-size:24px;font-weight:bold;color:#58a6ff}
            table{width:100%;border-collapse:collapse;margin-top:10px}
            th,td{padding:10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
            th{background:#161b22;color:#79c0ff}
            .addr{color:#d2a8ff;font-family:monospace}
            .rec{background:#161b22;border-left:3px solid #58a6ff;padding:10px 15px;margin:5px 0;border-radius:0 4px 4px 0}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 SOMCP 逆向分析报告</h1>
            <p style="color:#8b949e">目标: $sourceName | 架构: ${data.optString("architecture","?")} | ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(java.util.Date())}</p>
            <div class="stats">
                <div class="stat"><div class="stat-val">${functions.length()}</div><div>函数</div></div>
                <div class="stat"><div class="stat-val">${sections.length()}</div><div>节区</div></div>
                <div class="stat"><div class="stat-val">${crypto.length()}</div><div>加密特征</div></div>
            </div>
            <h2>📋 节区列表</h2>
            <table><tr><th>名称</th><th>地址</th><th>大小</th></tr>
                ${(0 until sections.length()).map{val s=sections.optJSONObject(it)?@return@map"";<tr><td class='addr'>${s.optString("name","")}</td><td class='addr'>${s.optString("addr",s.optString("vaddr","0"))}</td><td>${s.optLong("size",0)}</td></tr>"}.joinToString("")}
            </table>
            <h2>🔧 函数列表（前50）</h2>
            <table><tr><th>名称</th><th>地址</th><th>大小</th></tr>
                ${(0 until min(functions.length(),50)).map{val f=functions.optJSONObject(it)?@return@map"";<tr><td class='addr'>${f.optString("name","")}</td><td class='addr'>${f.optString("addr",f.optString("startAddr","0"))}</td><td>${f.optLong("size",0)}</td></tr>"}.joinToString("")}
            </table>
            ${if(recommendations.length()>0){"<h2>💡 建议</h2>"+(0 until recommendations.length()).map{"<div class='rec'>${recommendations.optString(it,"")}</div>"}.joinToString("")}else""}
        </div>
    </body>
    </html>
    """.trimIndent()
}