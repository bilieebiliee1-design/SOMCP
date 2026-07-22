package com.soreverse.mcp.mcp

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class ToolCatalogRegistryTest {
    @Test
    fun productionCatalogNamesAndOrderStayStable() {
        assertEquals(
            listOf(
                "so_open", "so_close", "apk_analyze",
                "analyze_elf", "read_stats", "analysis_report", "analyze_functions", "analyze_cfg", "analyze_crypto", "analyze_xrefs", "analyze_esil",
                "search_bytes", "search_strings", "read_disasm", "read_hexdump",
                "edit_hex", "edit_asm", "edit_symbol", "edit_fix_sections",
                "emulate_call", "emulate_dump", "unidbg_session", "unidbg_memory", "unidbg_debug", "unidbg_batch",
                "diff_so", "rizin_api", "lief_api", "unidbg_api", "xanso_api",
                "session_open", "session_history", "session_audit", "build_so", "system_control", "app_config", "meta_info",
            ),
            ToolCatalog.names,
        )
    }

    @Test
    fun preservesHandlerOrderAndBuildsIndexes() {
        val first = handler("first", category = "workspace")
        val second = handler("second", category = "read")
        val registry = ToolCatalogRegistry(listOf(first, second))

        assertEquals(listOf(first, second), registry.handlers)
        assertEquals(listOf("first", "second"), registry.names)
        assertEquals(listOf("first", "second"), registry.byName.keys.toList())
        assertSame(first, registry.byName["first"])
        assertEquals("workspace", registry.categoryOf("first"))
        assertEquals("first zh", registry.description("first", true))
        assertEquals("first en", registry.description("first", false))
        assertEquals("missing", registry.description("missing", false))
    }

    @Test
    fun indexesHeavyToolsInOrder() {
        val registry = ToolCatalogRegistry(
            listOf(
                handler("first", heavy = true),
                handler("second"),
                handler("third", heavy = true),
            ),
        )

        assertEquals(listOf("first", "third"), registry.heavyNames.toList())
    }

    @Test
    fun rejectsDuplicateNames() {
        assertThrows(IllegalArgumentException::class.java) {
            ToolCatalogRegistry(listOf(handler("duplicate"), handler("duplicate")))
        }
    }

    @Test
    fun leanNamesIncludesCoreMetaAndLowLevelInCatalogOrder() {
        val registry = ToolCatalogRegistry(
            listOf(
                handler("extra", cls = ToolClass.EXTRA),
                handler("core", cls = ToolClass.CORE),
                handler("lowlevel", category = "lowlevel", cls = ToolClass.EXTRA),
                handler("meta", cls = ToolClass.META),
                handler("other", cls = ToolClass.EXTRA),
            ),
        )

        assertEquals(listOf("core", "lowlevel", "meta"), registry.leanNames())
    }

    @Test
    fun promotesAtMostFivePopularExtraToolsWithStableOrdering() {
        val registry = ToolCatalogRegistry(
            listOf(
                handler("core", cls = ToolClass.CORE),
                handler("extra-a", cls = ToolClass.EXTRA),
                handler("extra-b", cls = ToolClass.EXTRA),
                handler("extra-c", cls = ToolClass.EXTRA),
                handler("extra-d", cls = ToolClass.EXTRA),
                handler("extra-e", cls = ToolClass.EXTRA),
                handler("extra-f", cls = ToolClass.EXTRA),
            ),
        )
        val popularity = mapOf(
            "extra-a" to 10L,
            "extra-b" to 30L,
            "extra-c" to 30L,
            "extra-d" to 20L,
            "extra-e" to 5L,
            "extra-f" to 1L,
        )

        assertEquals(
            listOf("core", "extra-b", "extra-c", "extra-d", "extra-a", "extra-e"),
            registry.leanNames(popularity),
        )
    }

    private fun handler(
        name: String,
        category: String = "test",
        cls: ToolClass = ToolClass.EXTRA,
        heavy: Boolean = false,
    ): ToolHandler = object : ToolHandler {
        override val meta = ToolMeta(
            name = name,
            zh = "$name zh",
            en = "$name en",
            category = category,
            cls = cls,
            heavy = heavy,
            schemaBuilder = { error("unused") },
        )

        override fun handle(ctx: ToolContext, args: JSONObject): JSONObject = error("unused")
    }
}
