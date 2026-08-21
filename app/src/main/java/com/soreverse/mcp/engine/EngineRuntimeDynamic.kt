// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// EngineRuntimeDynamic: the standalone "dynamic analysis" workflow for SOMCP.
//
// It is deliberately separate from the static deep-analysis loop (Directive:
// unidbg emulation + Frida on-device hooking, piped to an independent AI
// analysis). The user manually selects a backend, a target `.so` (workspace)
// and a target function, loads it into the chosen execution context, runs it,
// and collects runtime evidence (registers / memory / hook / trace).
//
//   Unidbg backend -> "手动加载到内存" == Unidbg session_open (loads the .so
//   into an emulated VM address space), then session_call / session_registers /
//   session_dump / session_trace. Thin re-use of the verified engine path.
//
//   Frida backend   -> "手动加载到内存" == live load of the module into a real
//   device process address space, then Interceptor/Module/Memory agents.
//
// Both produce the same structured `dynamicRun` evidence envelope that can be
// handed to DynamicAnalysisService for an independent AI report.
package com.soreverse.mcp.engine

import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import org.json.JSONArray
import org.json.JSONObject

/** Root frida targets are resolved from the FridaBridge; this is the constant
 *  set of operations EngineRuntimeDynamic can dispatch. */
private val DYNAMIC_METHODS = JSONArray(
    listOf(
        "status",
        "roots",
        "methods",
        "capabilities",
        "analyze",
        "unidbg_session_open",
        "unidbg_session_call",
        "unidbg_session_dump",
        "unidbg_session_registers",
        "unidbg_session_trace",
        "unidbg_session_close",
        "frida_status",
        "frida_sessions",
        "frida_open",
        "frida_close",
        "frida_hook",
        "frida_call",
        "frida_read",
        "frida_backtrace"
    )
)

private val DYNAMIC_ROOTS = JSONArray(listOf("unidbg", "frida", "sessions"))

internal fun EngineRuntime.dynamicDispatch(
    workspaceId: String,
    editSessionId: String = "",
    op: String,
    method: String = "",
    args: JSONArray = JSONArray()
): JSONObject = guarded {
    when (op) {
        "status" -> ok(
            JSONObject()
                .put("roots", DYNAMIC_ROOTS)
                .put("unidbg", emulationStatus())
                .put("frida", frida.connectionStatus(fridaTargetFromArgs(args.opt(0))))
                .put("sessions", fridaSessionsView())
        )

        "roots" -> ok(JSONObject().put("roots", DYNAMIC_ROOTS))

        "methods" -> ok(
            JSONObject().put("methods", DYNAMIC_METHODS).put("roots", DYNAMIC_ROOTS)
        )

        "capabilities" -> ok(
            JSONObject()
                .put(
                    "unidbg",
                    JSONObject()
                        .put("available", unidbg.available())
                        .put(
                            "operations",
                            JSONArray(
                                listOf(
                                    "unidbg_session_open",
                                    "unidbg_session_call",
                                    "unidbg_session_dump",
                                    "unidbg_session_registers",
                                    "unidbg_session_trace",
                                    "unidbg_session_close"
                                )
                            )
                        )
                )
                .put(
                    "frida",
                    JSONObject()
                        .put("available", frida.available(fridaTargetFromArgs(args.opt(0))))
                        .put(
                            "operations",
                            JSONArray(
                                listOf(
                                    "frida_status",
                                    "frida_open",
                                    "frida_hook",
                                    "frida_call",
                                    "frida_read",
                                    "frida_backtrace",
                                    "frida_close"
                                )
                            )
                        )
                )
        )

        "analyze" -> dynamicAnalyze(workspaceId, editSessionId, args)

        // ── Unidbg passthroughs (re-use the verified engine) ──
        "unidbg_session_open" -> unidbgDispatch(
            workspaceId,
            editSessionId,
            "session_open",
            method,
            args
        )

        "unidbg_session_call" -> unidbgDispatch(
            workspaceId,
            editSessionId,
            "session_call",
            method,
            args
        )

        "unidbg_session_dump" -> unidbgDispatch(
            workspaceId,
            editSessionId,
            "session_dump",
            method,
            args
        )

        "unidbg_session_registers" -> unidbgDispatch(
            workspaceId,
            editSessionId,
            "session_registers",
            method,
            args
        )

        "unidbg_session_trace" -> unidbgDispatch(
            workspaceId,
            editSessionId,
            "session_trace_code",
            method,
            args
        )

        "unidbg_session_close" -> {
            val sessionId = args.optString(0)
            val returned = unidbgDispatch(workspaceId, editSessionId, "session_close", method, args)
            returned.put("dynamicSessions", dynamicSessionIds())
        }

        // ── Frida passthroughs (real on-device) ──
        "frida_status" -> ok(frida.connectionStatus(fridaTargetFromArgs(args.opt(0))))

        "frida_sessions" -> ok(fridaSessionsView())

        "frida_open" -> {
            val params = args.opt(0) as? JSONObject ?: JSONObject()
            val target = fridaTargetFromArgs(params)
            val moduleName = params.str("moduleName", "libtarget.so")
            val mode = params.str("mode", "attach")
            val targetIdentifier = params.str("targetIdentifier", "com.example.target")
            val script = params.str("script").ifBlank { frida.defaultAgentHtml(moduleName, params.bool("retaddr", false)) }
            val session = frida.createSession(target, mode, targetIdentifier, script)
            ok(
                JSONObject()
                    .put("fridaSessionId", session.id)
                    .put("target", target.toString())
                    .put("mode", mode)
                    .put("targetIdentifier", targetIdentifier)
            )
        }

        "frida_close" -> {
            val sessionId = args.optString(0)
            frida.closeSession(sessionId)
            ok(JSONObject().put("closed", true).put("fridaSessionId", sessionId))
        }

        "frida_hook" -> {
            val sessionId = args.optString(0)
            val moduleName = args.optString(1)
            val symbolName = method.ifBlank { args.optString(2) }
            val result = frida.invokeRpc(
                sessionId,
                "hookFunction",
                JSONObject().put("functionName", symbolName)
            )
            result.put("fridaSessionId", sessionId).put("moduleName", moduleName)
        }

        "frida_call" -> {
            val sessionId = args.optString(0)
            val symbolName = method.ifBlank { args.optString(1) }
            val callArgs = args.optString(2).ifBlank { "[]" }
            frida.invokeRpc(
                sessionId,
                "callFunction",
                JSONObject()
                    .put("functionName", symbolName)
                    .put("argsJson", callArgs)
            ).put("fridaSessionId", sessionId).put("symbolName", symbolName)
        }

        "frida_read" -> {
            val sessionId = args.optString(0)
            val addr = args.optString(1)
            val size = args.optInt(2, 256)
            frida.invokeRpc(
                sessionId,
                "readMemory",
                JSONObject().put("ptrStr", addr).put("size", size.coerceIn(1, 65536))
            ).put("fridaSessionId", sessionId).put("address", addr)
        }

        "frida_backtrace" -> {
            val sessionId = args.optString(0)
            frida.invokeRpc(sessionId, "registers", JSONObject())
                .put("fridaSessionId", sessionId)
        }

        else -> err("UNKNOWN_ACTION", "Unknown dynamic-analysis op", "op", op)
    }
}

// ── High-level orchestration: "手动加载到内存 → 执行 → 采集证据" ──

private fun EngineRuntime.dynamicAnalyze(workspaceId: String, editSessionId: String, args: JSONArray): JSONObject = guarded {
    val params = args.optJSONObject(0) ?: JSONObject()
    val backend = params.str("backend", "unidbg")
    if (workspaceId.isBlank()) {
        return@guarded err("WORKSPACE_REQUIRED", "dynamic_analyze(target backend=$backend) needs a workspaceId; call so_open first", "workspaceId", "")
    }
    val targetFunction = params.str("targetFunction")
    if (targetFunction.isBlank()) {
        return@guarded err(
            "INVALID_ARGUMENT",
            "dynamic_analyze requires a non-blank targetFunction so the native payload can be manually loaded and invoked",
            "targetFunction",
            ""
        )
    }
    val trace = params.bool("trace", false)
    val retaddr = params.bool("retaddr", false)
    val dumpSize = params.int("dumpSize", 256).coerceIn(1, 65536)
    val functionArgs = params.optJSONArray("args") ?: JSONArray()

    val run = JSONObject()
        .put("workspaceId", workspaceId)
        .put("backend", backend)
        .put("targetFunction", targetFunction)
        .put("manuallyLoadedIntoMemory", true)

    when (backend) {
        "unidbg" -> {
            // 1) Manually load the .so into emulated memory.
            val opened = unidbgDispatch(workspaceId, editSessionId, "session_open", "", JSONArray())
            val emulatorSessionId = opened.optString("emulatorSessionId")
            if (emulatorSessionId.isBlank()) {
                return@guarded err(
                    "UNIDBG_LOAD_FAILED",
                    "Could not manually load the .so into emulated memory: ${opened.optJSONObject(
                        "error"
                    )?.optString("message") ?: opened.optString("message")}",
                    "backend",
                    "unidbg",
                    "openResult" to opened
                )
            }
            run.put("emulatorSessionId", emulatorSessionId)
            // 2) Invoke the target function.
            val call = unidbgDispatch(
                workspaceId,
                editSessionId,
                "session_call",
                targetFunction,
                JSONArray().put(emulatorSessionId).put(targetFunction).put(functionArgs).put(trace)
            )
            run.put("call", call)
            // 3) Collect register / memory / trace evidence.
            run.put(
                "registers",
                unidbgDispatch(
                    workspaceId,
                    editSessionId,
                    "session_registers",
                    "",
                    JSONArray().put(emulatorSessionId)
                )
            )
            val dumpAddr = params.str("dumpAddress")
            if (dumpAddr.isNotBlank()) {
                run.put(
                    "memory",
                    unidbgDispatch(
                        workspaceId,
                        editSessionId,
                        "session_dump",
                        "",
                        JSONArray().put(emulatorSessionId).put(dumpAddr).put(dumpSize)
                    )
                )
            }
            run.put("modules", unidbgDispatch(workspaceId, editSessionId, "modules", "", JSONArray()))
        }

        "frida" -> {
            val target = fridaTargetFromArgs(params)
            if (!frida.available(target)) {
                val reason = "Frida is not reachable at " +
                    "${target.host}:${target.port}. " +
                    "Install and start frida-server / frida-gadget " +
                    "on the device, then retry. ${frida.unavailableReason(target)}"
                return@guarded err(
                    "FRIDA_UNAVAILABLE",
                    reason,
                    "backend",
                    "frida",
                    "target" to target.host + ":" + target.port
                )
            }
            val moduleName = params.str("moduleName", workspaces[workspaceId]?.source?.name ?: "target.so")
            val mode = params.str("fridaMode", "attach")
            val processTarget = params.str("fridaTarget", params.str("processName"))
            if (processTarget.isBlank()) {
                return@guarded err(
                    "INVALID_ARGUMENT",
                    "Frida dynamic analysis requires fridaTarget (pid or process name) to attach to a live process",
                    "fridaTarget",
                    ""
                )
            }
            // 1) Open the session and deploy the agent (loads module host-side).
            val session = frida.createSession(
                target,
                mode,
                processTarget,
                frida.defaultAgentHtml(moduleName, retaddr)
            )
            run.put("fridaSessionId", session.id)
            // 2) Hook the target function and call it live.
            val hook = frida.invokeRpc(
                session.id,
                "hookFunction",
                JSONObject().put("functionName", targetFunction)
            )
            run.put("hook", hook)
            // Retrieve any events captured by the interceptor since hook
            // installation (module-level buffer drained on each poll).
            val hookEvents = frida.invokeRpc(session.id, "getEvents", JSONObject())
            run.put("hookEvents", hookEvents)
            val callResult = frida.invokeRpc(
                session.id,
                "callFunction",
                JSONObject().put("functionName", targetFunction).put("argsJson", functionArgs.toString())
            )
            run.put("call", callResult)
            val bt = frida.invokeRpc(session.id, "registers", JSONObject())
            run.put("backtrace", bt)
            val dumpAddr = params.str("dumpAddress")
            if (dumpAddr.isNotBlank()) {
                run.put(
                    "memory",
                    frida.invokeRpc(
                        session.id,
                        "readMemory",
                        JSONObject().put("ptrStr", dumpAddr).put("size", dumpSize)
                    )
                )
            }
            run.put("moduleName", moduleName)
            run.put(
                "note",
                "Frida hooks ran in a live device process; close the session with frida_close / dynamic_analyze when done so the injected agent detaches."
            )
        }

        else -> return@guarded err("UNKNOWN_ACTION", "Unknown dynamic backend", "backend", backend)
    }

    ok(run)
}

private fun EngineRuntime.fridaSessionsView(): JSONObject {
    val sessions = frida.listSessions()
    return JSONObject().put("fridaSessions", sessions)
}

private fun EngineRuntime.dynamicSessionIds(): JSONArray = fridaSessionsView().optJSONArray("fridaSessions") ?: JSONArray()

private fun EngineRuntime.fridaTargetFromArgs(raw: Any?): FridaTarget {
    val json = raw as? JSONObject ?: JSONObject()
    return FridaTarget(
        host = json.str("host", "127.0.0.1"),
        port = json.int("port", 27042).coerceIn(1, 65535),
        connectTimeoutMillis = json.int("connectTimeoutMillis", 5_000).toLong(),
        readTimeoutMillis = json.int("readTimeoutMillis", 15_000).toLong()
    )
}

private fun JSONObject.int(name: String, default: Int): Int = if (has(name)) optInt(name, default) else default

private fun JSONObject.bool(name: String, default: Boolean): Boolean = if (has(name)) optBoolean(name, default) else default
