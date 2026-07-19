package com.soreverse.mcp.mcp

import android.content.Context
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.engine.NativeSoEngine
import org.json.JSONObject

/**
 * Command-pattern dispatch core for the MCP tool system.
 *
 * Each tool is a self-contained [ToolHandler] that owns its metadata (name,
 * descriptions, category, class, heavy flag) AND its execution logic in one
 * place — replacing the old split where a separate metadata registry held
 * names and [McpHttpServer] held a giant `when(name)` switch. This is the Open/Closed
 * Principle made concrete: adding a tool means adding a handler object and
 * registering it, never touching a central switch.
 *
 * A [ToolContext] is handed to every handler so handlers never reach for the
 * Android Context, settings, or engine themselves — removing 48x duplicated
 * boilerplate and making handlers trivially testable.
 */
interface ToolHandler {
    val meta: ToolMeta
    fun handle(ctx: ToolContext, args: JSONObject): JSONObject
}

data class ToolMeta(
    val name: String,
    val zh: String,
    val en: String,
    val category: String,
    val cls: ToolClass,
    val heavy: Boolean = false,
    val schemaBuilder: SchemaBuilder.() -> JSONObject = { SchemaBuilder.emptyObject() },
)

// ToolClass is defined in ToolCatalog.kt and reused here to avoid a redeclaration.

open class ToolContext(
    open val context: Context,
    open val settings: SettingsStore,
    open val engine: NativeSoEngine,
)

/**
 * A handler that forwards to a [NativeSoEngine] method via a lambda. Most SO
 * tools are thin adapters over engine methods, so this removes per-tool
 * ceremony while keeping the engine dependency explicit and injectable.
 */
class EngineToolHandler(
    override val meta: ToolMeta,
    private val invoke: (NativeSoEngine, JSONObject, SettingsStore) -> JSONObject,
) : ToolHandler {
    override fun handle(ctx: ToolContext, args: JSONObject): JSONObject = invoke(ctx.engine, args, ctx.settings)
}
