package com.soreverse.mcp.engine

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

internal fun EngineRuntime.unidbgDispatch(workspaceId: String, editSessionId: String = "", op: String, method: String = "", args: JSONArray = JSONArray()): JSONObject = guarded {
    return@guarded when (op) {
        "status", "roots" -> ok(emulationStatus().put("roots", JSONArray(listOf("emulator", "memory", "vm", "module", "symbols", "jni", "framework", "hooks", "environment", "debugger"))))
        "methods" -> ok(JSONObject().put("methods", JSONArray(listOf("session_open", "session_list", "session_close", "session_call", "session_call_address", "session_dump", "session_memory_maps", "session_registers", "session_modules", "session_exports", "session_trace_code", "session_breakpoint_add", "session_memory_write", "session_memory_map", "session_memory_protect", "session_memory_unmap", "native_schemas", "native_tool", "call", "dump", "modules", "exports", "imports", "reflect", "framework_matrix", "stub_template", "hook_template", "env_template"))).put("roots", JSONArray(listOf("emulator", "memory", "vm", "module", "symbols", "jni", "framework", "hooks", "environment", "debugger"))))
        "modules" -> ok(JSONObject().put("modules", JSONArray(listOf(JSONObject().put("name", workspaces[workspaceId]?.source?.name ?: "target.so").put("architecture", elfFor(workspaceId, editSessionId).architecture).put("source", "static-workspace")))).put("runtime", "Call session_open + session_call to load through Unidbg; persistent runtime module listing requires live emulator sessions."))
        "exports" -> list(workspaceId, editSessionId, "dynsyms", "", 500).put("unidbgView", "exports")
        "imports" -> list(workspaceId, editSessionId, "imports", "", 500).put("unidbgView", "imports")
        "debugger_plan", "memory_map_plan", "registers_plan", "breakpoints_plan", "trace_plan" -> ok(unidbgDebuggerPlan(op))
        "framework_matrix" -> ok(unidbgFrameworkMatrix())
        "stub_template" -> ok(unidbgStubTemplate(args.optString(0), args.optString(1)))
        "hook_template" -> ok(unidbgHookTemplate(args.optString(0), args.optString(1)))
        "env_template" -> ok(unidbgEnvironmentTemplate())
        "session_open" -> {
            val elf = elfFor(workspaceId, editSessionId)
            val id = "emu-${UUID.randomUUID()}"
            val open = unidbg.openSession(dataFor(workspaceId, editSessionId), elf.architecture, args.optBoolean(1, true))
            if (!open.optBoolean("ok", false)) return@guarded wrapUnidbgResult(open.put("workspaceId", workspaceId).put("architecture", elf.architecture))
            val live = open.remove("live") as? UnidbgEmulator.LiveSession
                ?: return@guarded err("SESSION_OPEN_ERROR", "Unidbg live session handle was not created")
            emulatorSessions[id] = EmulatorSession(id, workspaceId, editSessionId, elf.architecture, dataFor(workspaceId, editSessionId), live)
            ok(open.put("emulatorSessionId", id).put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("architecture", elf.architecture).put("persistent", true))
        }
        "session_list" -> ok(JSONObject().put("sessions", JSONArray(emulatorSessions.values.map { JSONObject().put("id", it.id).put("workspaceId", it.workspaceId).put("editSessionId", it.editSessionId).put("architecture", it.architecture).put("createdAt", it.createdAt) })))
        "session_close" -> {
            val session = emulatorSessions.remove(args.optString(0))
            if (session?.live != null) unidbg.closeSession(session.live)
            ok(JSONObject().put("closed", session != null).put("emulatorSessionId", args.optString(0)))
        }
        "session_call" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val symbol = method.ifBlank { args.optString(1) }
            val callArgs = args.optJSONArray(2) ?: JSONArray()
            val trace = args.optBoolean(3, false)
            val result = session.live?.let { unidbg.sessionCall(it, symbol, callArgs, trace) }
                ?: unidbg.emulate(session.data, session.architecture, symbol, callArgs, trace)
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("symbolName", symbol).put("architecture", session.architecture))
        }
        "session_call_address" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val callArgs = args.optJSONArray(2) ?: JSONArray()
            val result = session.live?.let { unidbg.sessionCallAddress(it, addr, callArgs) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "address calls require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_dump" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val size = args.optInt(2, 256)
            val result = session.live?.let { unidbg.sessionDump(it, addr, size.coerceIn(1, 65536)) }
                ?: unidbg.dumpMemory(session.data, session.architecture, addr, size.coerceIn(1, 65536))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_memory_maps" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionMemoryMaps(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory maps require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_registers" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionRegisters(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "registers require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_modules" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionModules(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "modules require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_exports" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionExports(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "exports require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_trace_code" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val begin = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex begin address", "args", args)
            val end = parseHexLong(args.optString(2)) ?: return@guarded err("INVALID_ARGUMENT", "args[2] must be a hex end address", "args", args)
            val result = session.live?.let { unidbg.sessionTraceCode(it, begin, end) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "trace requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_trace_start" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val begin = parseHexLong(args.optString(2)) ?: 1L
            val end = parseHexLong(args.optString(3)) ?: 0L
            wrapUnidbgResult((session.live?.let { unidbg.sessionTraceStart(it, args.optString(1, "code"), begin, end) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_trace_events" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionTraceEvents(it, args.optInt(1, 0), args.optInt(2, 100)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_trace_stop" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionTraceStop(it, args.optString(1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_trace_clear" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionTraceClear(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_hook_start" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionHookStart(it, args.optString(1, "syscall"), parseHexLong(args.optString(2)) ?: 1L, parseHexLong(args.optString(3)) ?: 0L) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_hook_list" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionHookList(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_hook_stop" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionHookStop(it, args.optString(1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_breakpoint_add" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val result = session.live?.let { unidbg.sessionBreakpointAdd(it, addr) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "breakpoints require a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_debugger_status" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionDebuggerStatus(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_breakpoint_remove" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            wrapUnidbgResult((session.live?.let { unidbg.sessionBreakpointRemove(it, addr) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_single_step" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionSingleStep(it, args.optInt(1, 1)) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_emu_stop" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            wrapUnidbgResult((session.live?.let { unidbg.sessionEmuStop(it) } ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))).put("emulatorSessionId", session.id))
        }
        "session_memory_write" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val result = session.live?.let { unidbg.sessionMemoryWrite(it, addr, args.optString(2)) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory write requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_memory_map" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
            val result = session.live?.let { unidbg.sessionMemoryMap(it, addr, size, args.optInt(3, 3)) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory map requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_memory_protect" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
            val result = session.live?.let { unidbg.sessionMemoryProtect(it, addr, size, args.optInt(3, 3)) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory protect requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "session_memory_unmap" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val addr = parseHexLong(args.optString(1)) ?: return@guarded err("INVALID_ARGUMENT", "args[1] must be a hex address", "args", args)
            val size = (args.opt(2) as? Number)?.toLong() ?: parseHexLong(args.optString(2)) ?: 0L
            val result = session.live?.let { unidbg.sessionMemoryUnmap(it, addr, size) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "memory unmap requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "reflect_roots" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionReflectRoots(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "reflect_methods" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionReflectMethods(it, args.optString(1)) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "reflect_invoke" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionReflectInvoke(it, args.optString(1), method, args.optJSONArray(2) ?: JSONArray()) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED").put("message", "reflection requires a live emulator session"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId).put("architecture", session.architecture))
        }
        "native_schemas" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val result = session.live?.let { unidbg.sessionNativeToolSchemas(it) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId))
        }
        "native_tool" -> {
            val session = emulatorSessions[args.optString(0)] ?: return@guarded err("EMULATOR_SESSION_NOT_FOUND", "Emulator session not found", "emulatorSessionId", args.optString(0))
            val toolName = method.ifBlank { args.optString(1) }
            if (toolName.isBlank()) return@guarded err("INVALID_ARGUMENT", "native_tool requires a tool name", "method", method)
            val toolArgs = args.optJSONObject(2) ?: JSONObject()
            val result = session.live?.let { unidbg.sessionNativeToolCall(it, toolName, toolArgs) }
                ?: JSONObject().put("ok", false).put("error", JSONObject().put("code", "LIVE_SESSION_REQUIRED"))
            wrapUnidbgResult(result.put("emulatorSessionId", session.id).put("workspaceId", session.workspaceId))
        }
        "call" -> emulate(workspaceId, editSessionId, method.ifBlank { args.optString(0) }, args.optJSONArray(1) ?: JSONArray(), args.optBoolean(2, false))
        "dump" -> dumpMemory(workspaceId, editSessionId, parseHexLong(args.optString(0)) ?: 0L, args.optInt(1, 256))
        "reflect" -> err("INVALID_ARGUMENT", "Use reflect_roots, reflect_methods, or reflect_invoke with a live emulatorSessionId", "op", op)
        else -> err("UNKNOWN_ACTION", "Unknown Unidbg dispatcher op", "op", op)
    }
}

private fun EngineRuntime.unidbgFrameworkMatrix(): JSONObject = JSONObject()
    .put("matrix", JSONArray(listOf(
        JSONObject().put("area", "DalvikVM/JNI").put("status", "implemented").put("items", JSONArray(listOf("createDalvikVM", "JNIEnv", "JNI_OnLoad", "Java_* JNI exported call"))),
        JSONObject().put("area", "Native exports").put("status", "implemented").put("items", JSONArray(listOf("exported symbol call", "argument passing", "return value", "memory dump"))),
        JSONObject().put("area", "Android framework classes").put("status", "targeted-stub-required").put("items", JSONArray(listOf("Context", "Application", "ActivityThread", "PackageManager", "Resources", "ClassLoader"))),
        JSONObject().put("area", "Device/environment APIs").put("status", "targeted-hook-required").put("items", JSONArray(listOf("Build", "Settings.Secure", "TelephonyManager", "system properties", "filesystem", "network"))),
        JSONObject().put("area", "Anti-analysis behavior").put("status", "targeted-hook-required").put("items", JSONArray(listOf("ptrace", "procfs", "thread checks", "timing checks", "emulator checks")))
    )))
    .put("workflow", JSONArray(listOf("Run emulate_call with trace=false", "If it fails, retry trace=true on a small symbol", "Extract missing class/method/syscall from error.stage or trace", "Generate stub_template or hook_template", "Implement targeted hook in UnidbgEmulator", "Retry emulate_call")))

private fun EngineRuntime.unidbgDebuggerPlan(op: String): JSONObject = JSONObject()
    .put("op", op)
    .put("available", false)
    .put("reason", "Persistent live emulator sessions are enabled for session_call/session_dump. This specific debugger operation still needs a typed MCP wrapper and guardrails before being exposed.")
    .put("implementationPlan", JSONArray(listOf(
        "Promote EmulatorSession from bytes-only state to live emulator/vm/module/backend holder",
        "Add serialized single-thread access per emulator session",
        "Expose modules/exports/memory maps/registers as typed read-only operations first",
        "Add explicit breakpoint/trace operations with size/time guards",
        "Keep arbitrary Java reflection blocked unless a sandboxed object-path dispatcher is implemented"
    )))
    .put("safeAlternativesNow", JSONArray(listOf("session_call", "session_dump", "modules", "exports", "imports", "framework_matrix", "hook_template", "stub_template", "env_template")))

private fun EngineRuntime.unidbgStubTemplate(className: String, methodName: String): JSONObject = JSONObject()
    .put("type", "java-class-stub")
    .put("className", className.ifBlank { "android/content/Context" })
    .put("methodName", methodName.ifBlank { "getPackageName" })
    .put("purpose", "Use this template when Unidbg fails on missing Android framework class/method resolution.")
    .put("kotlinSketch", JSONArray(listOf(
        "Detect className/methodName in Unidbg failure trace",
        "Register or intercept the Java class in DalvikVM",
        "Return deterministic app-specific values from Settings/env template",
        "Keep the stub narrow and library-specific to avoid unsafe global behavior"
    )))
    .put("exampleReturnValues", JSONObject()
        .put("getPackageName", "com.example.target")
        .put("getFilesDir", "/data/data/com.example.target/files")
        .put("getCacheDir", "/data/data/com.example.target/cache"))

private fun EngineRuntime.unidbgHookTemplate(hookName: String, symbolOrApi: String): JSONObject = JSONObject()
    .put("type", "native-or-framework-hook")
    .put("hookName", hookName.ifBlank { "anti_emulator_bypass" })
    .put("target", symbolOrApi.ifBlank { "__system_property_get / open / access / ptrace" })
    .put("purpose", "Use this template when a SO performs environment, filesystem, syscall, or anti-analysis checks.")
    .put("strategy", JSONArray(listOf("Identify failing API from trace", "Return realistic device/app data", "Avoid broad hooks that hide real bugs", "Record hook hits in diagnostics")))
    .put("exampleValues", JSONObject()
        .put("ro.product.model", "Pixel 7")
        .put("ro.build.version.sdk", "33")
        .put("/proc/self/status", "TracerPid:\t0"))

private fun EngineRuntime.unidbgEnvironmentTemplate(): JSONObject = JSONObject()
    .put("packageName", "com.example.target")
    .put("apiLevel", 33)
    .put("abi", JSONArray(listOf("arm64-v8a", "armeabi-v7a")))
    .put("files", JSONObject()
        .put("dataDir", "/data/data/com.example.target")
        .put("filesDir", "/data/data/com.example.target/files")
        .put("cacheDir", "/data/data/com.example.target/cache"))
    .put("systemProperties", JSONObject()
        .put("ro.product.manufacturer", "Google")
        .put("ro.product.model", "Pixel 7")
        .put("ro.build.version.sdk", "33"))
    .put("note", "Copy and specialize this environment per target app before adding hooks/stubs.")

internal fun EngineRuntime.emulationStatus(): JSONObject {
    val available = unidbg.available()
    return JSONObject()
        .put("available", available)
        .put("backend", "unidbg+unicorn2")
        .put("scope", "Full Unidbg Android native emulation path backed by Unicorn2 native backend: SO load, DalvikVM/JNIEnv, JNI_OnLoad, exported symbol calls, Java_* JNI calls, and post-load memory dump")
        .put("androidFramework", JSONObject()
            .put("status", "unidbg-runtime")
            .put("implemented", JSONArray(listOf("AndroidEmulatorBuilder", "Unicorn2Factory", "AndroidResolver", "DalvikVM creation", "JNIEnv for Java_* calls", "JNI_OnLoad pre-call", "exported symbol call", "post-load memory dump")))
            .put("requiresHooks", JSONArray(listOf("Context", "Application", "PackageManager", "Resources", "Build fields", "Settings/Secure", "TelephonyManager", "ActivityThread", "ClassLoader", "filesystem paths", "network/system properties", "anti-debug/anti-emulator checks")))
            .put("truth", "This uses the real Unidbg and Unicorn2 execution path. App-specific Android framework behavior is resolved by targeted hooks/stubs when a concrete SO demands it."))
        .put("coverageModel", JSONObject()
            .put("mcpTools", "emulate_call/emulate_dump plus unidbg_api dispatch")
            .put("backendFactory", "com.github.unidbg.arm.backend.Unicorn2Factory")
            .put("nativeLibraries", JSONArray(listOf("libcapstone.so", "libkeystone.so", "libunicorn.so", "libjnidispatch.so")))
            .put("nativeSelfTest", UnidbgEmulator.nativeSelfTest())
            .put("nativeLoadError", UnidbgEmulator.nativeDependencyError()?.toString() ?: JSONObject.NULL)
            .put("availabilityError", UnidbgEmulator.availabilityError()?.toString() ?: JSONObject.NULL))
        .put("limitations", JSONArray()
            .put("Android framework classes, syscalls, filesystem, and anti-analysis behavior are handled by concrete Unidbg hooks/stubs when a target SO requires them")
            .put("Use trace=true for diagnostics, inspect error.stage/error.nextActions, then add the exact missing hook/stub before retrying"))
        .put("nextActions", JSONArray(listOf("Start with symbolName=JNI_OnLoad or an exported Java_* symbol", "If Java/framework lookup fails, identify the exact missing class/method/syscall from error.stage or trace", "Implement the specific Unidbg hook/stub and retry the same symbol")))
}

internal fun EngineRuntime.emulate(workspaceId: String, editSessionId: String, symbolName: String, args: JSONArray, trace: Boolean): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    val result = unidbg.emulate(bytes, elf.architecture, symbolName, args, trace)
    result.put("persistent", false)
        .put("addressSpace", unidbgAddressSpaceHint())
    if (result.optString("returnValue") == "-1") result.put("semanticWarning", "Unidbg completed without backend exception, but returnValue=-1 may be target-specific or indicate an unmodeled signal/syscall/framework path. Validate with trace, mapped arguments, and target-specific hooks.")
    wrapUnidbgResult(result.put("workspaceId", workspaceId).put("symbolName", symbolName).put("architecture", elf.architecture))
}

internal fun EngineRuntime.dumpMemory(workspaceId: String, editSessionId: String, addr: Long, size: Int): JSONObject = guarded {
    val bytes = dataFor(workspaceId, editSessionId)
    val elf = elfFor(workspaceId, editSessionId)
    val result = unidbg.dumpMemory(bytes, elf.architecture, addr, size.coerceIn(1, 65536))
    result.put("persistent", false)
        .put("addressSpace", unidbgAddressSpaceHint())
    wrapUnidbgResult(result.put("workspaceId", workspaceId).put("architecture", elf.architecture))
}

private fun EngineRuntime.unidbgAddressSpaceHint(): JSONObject = JSONObject()
    .put("kind", "runtimeVirtualAddress")
    .put("note", "Unidbg memory APIs use runtime absolute virtual addresses. For ELF RVA/VA, add the module base returned by unidbg_session(action=modules) or session_modules.")

private fun EngineRuntime.parseHexLong(value: String): Long? = LocatorParser.hex(value)

private fun EngineRuntime.wrapUnidbgResult(result: JSONObject): JSONObject {
    if (result.optBoolean("ok", false)) return ok(result)
    if (result.has("content") && !result.optBoolean("isError", false) && !result.has("error")) {
        result.put("ok", true)
        return ok(result)
    }
    val error = result.optJSONObject("error") ?: JSONObject().put("code", "EMULATION_ERROR").put("message", "Unidbg returned an unsuccessful result")
    val code = error.optString("code", "EMULATION_ERROR")
    val message = error.optString("message", "Unidbg returned an unsuccessful result")
    val wrapped = err(code, message, "unidbg", result.optString("stage", "unknown"), "unidbg" to result)
    val next = error.optJSONArray("nextActions")
    if (next != null) wrapped.put("nextActions", next)
    return wrapped
}
