package com.soreverse.mcp.mcp

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

    private fun strProp(description: String): JSONObject = JSONObject().put("type", "string").put("description", description)
    private fun enumProp(description: String, vararg values: String): JSONObject = strProp(description).put("enum", JSONArray(values.toList()))
    private fun intProp(description: String): JSONObject = JSONObject().put("type", "integer").put("description", description)
    private fun numProp(description: String): JSONObject = JSONObject().put("type", "number").put("description", description)
    private fun boolProp(description: String): JSONObject = JSONObject().put("type", "boolean").put("description", description)
    private fun arrProp(description: String, items: JSONObject?): JSONObject =
        JSONObject().put("type", "array").put("description", description).apply { if (items != null) put("items", items) }

    fun props(block: PropList.() -> Unit): JSONObject = PropList().apply(block).build()

    class PropList {
        private val properties = JSONObject()
        infix fun String.str(description: String) { properties.put(this, strProp(description)) }
        fun String.oneOf(description: String, vararg values: String) { properties.put(this, enumProp(description, *values)) }
        infix fun String.int(description: String) { properties.put(this, intProp(description)) }
        infix fun String.num(description: String) { properties.put(this, numProp(description)) }
        infix fun String.bool(description: String) { properties.put(this, boolProp(description)) }
        infix fun String.arr(description: String) { properties.put(this, arrProp(description, null)) }
        infix fun String.arr(description: Pair<String, JSONObject>) { properties.put(this, arrProp(description.first, description.second)) }
        fun build(): JSONObject = properties
    }

    fun editsAsmSchema(): JSONObject = JSONObject().put("type", "object")
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

    fun editsHexSchema(): JSONObject = JSONObject().put("type", "object")
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

    fun editsSymbolSchema(): JSONObject = JSONObject().put("type", "object")
        .put("description", "One symbol edit. rename: same-or-shorter rename. add: add exported function at addr. remove: remove symbol by name.")
        .put("properties", JSONObject()
            .put("op", strProp("rename (default) | add | remove"))
            .put("newName", strProp("New symbol name (for rename: must be <= original length)."))
            .put("addr", strProp("Hex virtual address for the new exported function (add op only)."))
            .put("name", strProp("Symbol name to remove (remove op only).")))
        .put("required", JSONArray().put("op"))

    fun outputsSchema(): JSONObject = JSONObject().put("type", "object")
        .put("description", "One build output variant.")
        .put("properties", JSONObject()
            .put("outputName", strProp("Output file name, e.g. libflass_patched_v1.so."))
            .put("writeToWorkDir", JSONObject().put("type", "boolean").put("description", "Mirror this variant into the work directory."))
            .put("writePatchReport", JSONObject().put("type", "boolean").put("description", "Write a patch-report JSON sidecar for this variant.")))
        .put("required", JSONArray().put("outputName"))

    fun batchStepsSchema(): JSONObject = JSONObject().put("type", "object")
        .put("description", "One batch pipeline step. Steps execute serially in array order.")
        .put("properties", JSONObject()
            .put("tool", strProp("Tool name to invoke."))
            .put("arguments", JSONObject().put("type", "object").put("description", "Arguments object for this tool. May contain \${resultKey.jsonPath} placeholders substituted from prior steps' results."))
            .put("resultKey", strProp("Optional short key (e.g. a0, b1) used to reference this step's result JSON in later steps.")))
        .put("required", JSONArray().put("tool"))
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
