package com.soreverse.mcp.mcp

import org.json.JSONObject

object ToolCatalogPresentation {
    fun leanNames(): List<String> = ToolCatalog.registry.leanNames()

    fun leanNames(popularity: Map<String, Long>?): List<String> = ToolCatalog.registry.leanNames(popularity)

    fun description(name: String, zh: Boolean): String =
        ToolCatalog.registry.description(name, zh)

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
        val order = categoryDescriptions(zh).map { it.first }.toMutableList()
        order.forEach { groups[it] = mutableListOf() }
        ToolCatalog.ALL.forEach { e -> groups[e.meta.category]?.add(e.meta.name to (if (zh) e.meta.zh else e.meta.en)) }
        if (includeApk.isNotEmpty()) {
            groups["apk-bridge"] = includeApk.map { it to it }.toMutableList()
            order += "apk-bridge"
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

    fun categoryOf(name: String): String? = ToolCatalog.registry.categoryOf(name)
}
