// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// Sub-agents: scoped, single-purpose agent runs that an analysis agent (or an
// external MCP client through `agent_api`) can spawn. Each run gets one role's
// tool whitelist, one question to answer, and its own iteration ceiling. They
// share the parent's configured endpoint / API key / model and inherit the
// parent's workspace, so a sub-agent never has to re-open the target .so.
package com.soreverse.mcp.core

import com.soreverse.mcp.mcp.ToolCatalog
import com.soreverse.mcp.mcp.ToolContext
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject

/** One preset sub-agent: what it is for, and the only tools it may touch. */
internal data class SubAgentRole(
    val id: String,
    val nameZh: String,
    val nameEn: String,
    val goalZh: String,
    val goalEn: String,
    val toolNames: List<String>,
    val suggestedIterations: Int
) {
    fun name(zh: Boolean) = if (zh) nameZh else nameEn

    fun goal(zh: Boolean) = if (zh) goalZh else goalEn
}

internal object SubAgentRoles {
    val XREF_TRACER = SubAgentRole(
        id = "xref_tracer",
        nameZh = "调用链与交叉引用追踪",
        nameEn = "Call-chain and xref tracing",
        goalZh = "把指派的函数或地址的调用者/被调用者链读清楚，包括 JNI 动态注册入口。",
        goalEn = "Resolve the caller/callee chain of the assigned function or address, including JNI dynamically registered entries.",
        toolNames = listOf(
            "so_open",
            "analyze_functions",
            "analyze_cfg",
            "analyze_xrefs",
            "read_disasm",
            "jni_api",
            "meta_info"
        ),
        suggestedIterations = 14
    )

    val CRYPTO_LOCATOR = SubAgentRole(
        id = "crypto_locator",
        nameZh = "加密算法与常量定位",
        nameEn = "Crypto and constant location",
        goalZh = "定位加密/哈希/编码相关实现：算法特征常量、S-box、密钥调度、调用点。",
        goalEn = "Locate crypto/hash/encoding implementations: algorithm constants, S-boxes, key schedule, call sites.",
        toolNames = listOf(
            "so_open",
            "analyze_crypto",
            "search_strings",
            "search_bytes",
            "read_hexdump",
            "read_disasm",
            "rizin_api"
        ),
        suggestedIterations = 14
    )

    val PACKER_PROFILER = SubAgentRole(
        id = "packer_profiler",
        nameZh = "壳 / 混淆 / 防护画像",
        nameEn = "Packer, obfuscation and hardening profile",
        goalZh = "判定加固壳、控制流混淆强度、反调试手段与导入来源，并给出证据。",
        goalEn = "Profile packer stubs, control-flow obfuscation, anti-debug measures and import provenance with evidence.",
        toolNames = listOf(
            "so_open",
            "analyze_elf",
            "packer_api",
            "obfusc_api",
            "antidebug_api",
            "import_api",
            "read_stats"
        ),
        suggestedIterations = 10
    )

    val DYN_PROBE = SubAgentRole(
        id = "dyn_probe",
        nameZh = "动态取证",
        nameEn = "Dynamic forensics",
        goalZh = "用 unidbg 模拟或 Frida 真机跑目标函数，采集运行时行为证据。",
        goalEn = "Run the target under unidbg emulation or on-device Frida and collect runtime behaviour evidence.",
        toolNames = listOf(
            "so_open",
            "dynamic_api",
            "unidbg_api",
            "analyze_functions",
            "read_disasm",
            "analysis_report"
        ),
        suggestedIterations = 12
    )

    val GENERALIST = SubAgentRole(
        id = "generalist",
        nameZh = "通用取证",
        nameEn = "General evidence gathering",
        goalZh = "在上述角色都不匹配时，用通用静态取证面回答单个问题。",
        goalEn = "Answer one question through the general static-evidence surface when no focused role fits.",
        toolNames = listOf(
            "so_open",
            "analyze_functions",
            "analyze_cfg",
            "analyze_xrefs",
            "analyze_crypto",
            "analysis_report",
            "search_strings",
            "search_bytes",
            "read_disasm",
            "read_hexdump",
            "meta_info"
        ),
        suggestedIterations = 12
    )

    val ALL: List<SubAgentRole> = listOf(
        XREF_TRACER,
        CRYPTO_LOCATOR,
        PACKER_PROFILER,
        DYN_PROBE,
        GENERALIST
    )

    val IDS: List<String> = ALL.map { it.id }

    fun byId(id: String): SubAgentRole? = ALL.firstOrNull { it.id == id.trim() } ?: ALL.firstOrNull {
        it.id.equals(id.trim(), ignoreCase = true)
    }
}

/** How many spawns one root session may still spend. Pure logic, unit-tested. */
internal class SubAgentBudget(private val maxRuns: Int) {
    private val consumed = AtomicInteger(0)

    fun tryConsume(): Boolean {
        while (true) {
            val current = consumed.get()
            if (current >= maxRuns) return false
            if (consumed.compareAndSet(current, current + 1)) return true
        }
    }

    fun consumedCount(): Int = consumed.get()

    fun remaining(): Int = (maxRuns - consumed.get()).coerceAtLeast(0)
}

internal object SubAgentPolicy {
    /** Root agent runs at depth 0, so a child is [childDepth] = parent + 1. */
    fun spawnAllowed(childDepth: Int, maxDepth: Int): Boolean = childDepth <= maxDepth

    fun iterationsFor(role: SubAgentRole, ceiling: Int): Int = minOf(role.suggestedIterations, ceiling).coerceIn(2, 40)
}

internal data class SubAgentOutcome(
    val role: String,
    val report: String,
    val toolsUsed: List<String>,
    val stepsUsed: Int,
    val workspaceId: String,
    val unresolvedTools: List<String>
) {
    fun toJson(status: String, error: String? = null): JSONObject = JSONObject()
        .put("status", status)
        .put("role", role)
        .apply { if (error != null) put("error", error) }
        .put("report", report)
        .put("tools_used", toolsUsed.toJsonArray())
        .put("steps_used", stepsUsed)
        .put("workspace_id", workspaceId)
        .apply {
            if (unresolvedTools.isNotEmpty()) {
                put(
                    "unresolved_tools",
                    unresolvedTools.toJsonArray()
                )
            }
        }
}

internal class SubAgentRunner(private val ctx: ToolContext) {
    fun runSync(role: SubAgentRole, task: String, zh: Boolean, depth: Int, workspaceId: String = "", onTool: (String) -> Unit = {}): SubAgentOutcome =
        runBlocking(Dispatchers.IO) {
            run(role, task, zh, depth, workspaceId, onTool)
        }

    suspend fun run(role: SubAgentRole, task: String, zh: Boolean, depth: Int, workspaceId: String = "", onTool: (String) -> Unit = {}): SubAgentOutcome =
        withContext(Dispatchers.IO) {
            val settings = ctx.settings
            AgentKernel.requireConfigured(settings)
            val workspace = java.util.concurrent.atomic.AtomicReference(workspaceId)
            val toolsUsed = java.util.concurrent.CopyOnWriteArrayList<String>()
            val gate = concurrencyGate(settings.subAgentMaxConcurrent)
            withTimeout(QUEUE_WAIT_MS) {
                gate.withPermit {
                    val catalog = AgentKernel.catalogTools(
                        ctx,
                        role.toolNames,
                        AgentToolHooks(
                            zh = zh,
                            workspaceId = { workspace.get().orEmpty() },
                            onWorkspaceOpened = { workspace.set(it) },
                            onToolStart = { name ->
                                toolsUsed.add(name)
                                onTool(name)
                            }
                        )
                    )
                    val childDepth = depth + 1
                    val tools = catalog.tools + if (
                        settings.subAgentEnabled &&
                        SubAgentPolicy.spawnAllowed(childDepth, settings.subAgentMaxDepth)
                    ) {
                        listOf(
                            subAgentSpawnTool(
                                ctx = ctx,
                                zh = zh,
                                depth = childDepth,
                                budget = SubAgentBudget(settings.subAgentMaxPerRun),
                                workspaceId = { workspace.get().orEmpty() },
                                onProgress = onTool
                            )
                        )
                    } else {
                        emptyList()
                    }
                    val lastParts = java.util.concurrent.atomic.AtomicReference<List<RikkaPart>>(emptyList())
                    val engine = AgentKernel.engine(settings)
                    val maxSteps = SubAgentPolicy.iterationsFor(role, settings.subAgentMaxIterations)
                    // A sub-agent that hits its step ceiling still owes the parent the
                    // evidence it collected, so the partial text is kept, not discarded.
                    val report = runCatching {
                        engine.run(
                            systemPrompt = buildSystemPrompt(role, zh, tools.map { it.name }),
                            userPrompt = buildUserPrompt(role, task, zh, workspace.get()),
                            tools = tools,
                            maxSteps = maxSteps,
                            onParts = { parts -> lastParts.set(parts) }
                        )
                    }.getOrElse { failure ->
                        if (failure is CancellationException) throw failure
                        val partial = lastParts.get()
                            .filterIsInstance<RikkaPart.Text>()
                            .joinToString("") { it.text }
                            .trim()
                        if (partial.isNotEmpty() && failure.message?.contains("Maximum tool steps exceeded") == true) {
                            partial + if (zh) {
                                "\n\n（已在 $maxSteps 轮上限处停止，以上为截至此刻取到的证据）"
                            } else {
                                "\n\n(Stopped at the $maxSteps-step ceiling; the above is the evidence gathered so far)"
                            }
                        } else {
                            throw failure
                        }
                    }
                    SubAgentOutcome(
                        role = role.id,
                        report = report,
                        toolsUsed = toolsUsed.toList(),
                        stepsUsed = lastParts.get().filterIsInstance<RikkaPart.Tool>().size,
                        workspaceId = workspace.get().orEmpty(),
                        unresolvedTools = catalog.unresolved
                    )
                }
            }
        }

    private fun buildSystemPrompt(role: SubAgentRole, zh: Boolean, toolNames: List<String>): String = if (zh) {
        """你是 SOMCP 的取证子代理，角色：${role.nameZh}。
你只负责主代理派给你的这一个任务，不要写整体分析报告，不要复述任务之外的内容。

职责：${role.goalZh}
可用工具：${toolNames.joinToString(", ")}

硬性要求：
1. 结论必须来自工具结果，逐条附上定位锚点（函数名 / fcn.xxxx / 0x 地址 / 字符串偏移）。没有证据的判断标「未证实」并说明推断依据。
2. 工具报错时，说明失败原因并换用其它工具继续取证，不要把失败写成「不存在」。
3. 阴性结论要写清覆盖范围（查了哪些段/哪些函数/哪些符号集），否则不得写「没有」。
4. 输出不超过 400 词的紧凑证据块：结论 / 证据 / 置信度 / 未解决项。不要输出过程性文字。"""
    } else {
        """You are a SOMCP evidence sub-agent. Role: ${role.nameEn}.
You answer exactly one task handed to you. Do not write a full analysis report.

Responsibility: ${role.goalEn}
Available tools: ${toolNames.joinToString(", ")}

Hard requirements:
1. Every conclusion must come from a tool result and carry a locator (symbol name / fcn.xxxx / 0x address / string offset). Mark a judgement "unverified" and state the inference when evidence is missing.
2. When a tool fails, report the failure and continue with other tools. Never turn a failure into "it does not exist".
3. A negative finding must state its coverage (which sections, functions, or symbol sets were checked).
4. Return a compact evidence block under 400 words: Findings / Evidence / Confidence / Open items. No process prose."""
    }

    private fun buildUserPrompt(role: SubAgentRole, task: String, zh: Boolean, workspaceId: String): String = if (zh) {
        """任务（${role.nameZh}）：
${task.trim()}
${
            workspaceId.takeIf { it.isNotBlank() }?.let {
                "已继承工作区 workspaceId=$it，无需重新 so_open。"
            }.orEmpty()
        }
开始取证，完成后直接返回证据块。"""
    } else {
        """Task (${role.nameEn}):
${task.trim()}
${
            workspaceId.takeIf { it.isNotBlank() }?.let { "Workspace inherited: workspaceId=$it; do not re-open the target." }
                .orEmpty()
        }
Start gathering evidence, then return the evidence block only."""
    }

    private companion object {
        const val QUEUE_WAIT_MS = 5L * 60L * 1000L
    }
}

/**
 * The `spawn_subagent` tool handed to a parent agent. Failures come back as
 * structured payloads rather than exceptions so the parent can proceed alone.
 */
internal fun subAgentSpawnTool(
    ctx: ToolContext,
    zh: Boolean,
    depth: Int,
    budget: SubAgentBudget,
    workspaceId: () -> String,
    onProgress: (String) -> Unit = {}
): RikkaTool {
    val roles = SubAgentRoles.ALL
    val roleDoc = roles.joinToString(if (zh) "；" else "; ") {
        "${it.id}=${it.name(zh)}（${it.goal(zh)}）"
    }
    val schema = JSONObject()
        .put("type", "object")
        .put(
            "properties",
            JSONObject()
                .put(
                    "role",
                    JSONObject()
                        .put("type", "string")
                        .put("enum", JSONArray(roles.map { it.id }))
                        .put("description", roleDoc)
                )
                .put(
                    "task",
                    JSONObject()
                        .put("type", "string")
                        .put(
                            "description",
                            if (zh) {
                                "交给该子代理的单个任务，必须自包含：写清目标函数/地址/ workspaceId 与要回答的具体问题"
                            } else {
                                "The one question this sub-agent must answer, self-contained: include the target function/address and what to prove"
                            }
                        )
                )
        )
        .put("required", JSONArray(listOf("role", "task")))
    return RikkaTool(
        name = "spawn_subagent",
        description = if (zh) {
            "派一个专职取证子代理（独立上下文、同一模型配置、只带该角色的工具白名单）去做一件事并返回证据块。" +
                "剩余配额 ${budget.remaining()}/${budget.consumedCount() + budget.remaining()}，嵌套深度上限 ${ctx.settings.subAgentMaxDepth}。角色：$roleDoc"
        } else {
            "Spawn a focused evidence sub-agent (own context, same model config, role-scoped tool whitelist) to answer one question. " +
                "Remaining quota ${budget.remaining()} of ${budget.consumedCount() + budget.remaining()}; max nesting depth ${ctx.settings.subAgentMaxDepth}. Roles: $roleDoc"
        },
        schema = schema
    ) { args ->
        val settings = ctx.settings
        if (!settings.subAgentEnabled) {
            JSONObject().put("status", "error").put("error", "sub_agents_disabled")
                .put(
                    "hint",
                    if (zh) "设置 → AI → 子代理 已关闭，请自行完成取证" else "Sub-agents are off in Settings; do this evidence pass yourself"
                ).toString()
        } else if (!budget.tryConsume()) {
            JSONObject().put("status", "error").put("error", "sub_agent_budget_exhausted")
                .put("max_per_run", settings.subAgentMaxPerRun)
                .put(
                    "hint",
                    if (zh) "本次会话的子代理配额已用尽，请自己完成剩余取证并给出最终报告" else "Sub-agent quota for this session is spent; finish the analysis yourself"
                ).toString()
        } else {
            val role = SubAgentRoles.byId(args.optString("role"))
            if (role == null) {
                JSONObject().put("status", "error")
                    .put("error", "unknown_role")
                    .put("requested", args.optString("role"))
                    .put("available_roles", JSONArray(SubAgentRoles.IDS)).toString()
            } else {
                val task = args.optString("task").trim()
                if (task.isBlank()) {
                    JSONObject().put("status", "error").put("error", "task_required").toString()
                } else {
                    onProgress(if (zh) "子代理 ${role.id} 启动" else "Sub-agent ${role.id} started")
                    runCatching {
                        SubAgentRunner(ctx).run(
                            role = role,
                            task = task,
                            zh = zh,
                            depth = depth,
                            workspaceId = workspaceId(),
                            onTool = { name -> onProgress("[$role.id] $name") }
                        )
                    }.fold(
                        onSuccess = { outcome ->
                            AppLog.i("Sub-agent ${role.id} done steps=${outcome.toolsUsed.size}")
                            onProgress(if (zh) "子代理 ${role.id} 完成" else "Sub-agent ${role.id} finished")
                            outcome.toJson("ok").toString()
                        },
                        onFailure = { error ->
                            // TimeoutCancellationException is a CancellationException, so it
                            // must be recognised before cancellation is re-thrown.
                            val queueTimeout = error is TimeoutCancellationException
                            // Never absorb a parent cancellation into an error payload:
                            // the UI's stop button relies on it propagating.
                            if (!queueTimeout && error is CancellationException) throw error
                            AppLog.e("Sub-agent ${role.id} failed", error)
                            val message = error.message ?: error.javaClass.simpleName
                            JSONObject().put("status", "error")
                                .put("error", if (queueTimeout) "sub_agent_queue_timeout" else "sub_agent_failed")
                                .put("role", role.id)
                                .put("message", message.take(600))
                                .put(
                                    "hint",
                                    if (queueTimeout) {
                                        if (zh) {
                                            "并发槽被占满，请稍后重试或自己完成该取证"
                                        } else {
                                            "All sub-agent slots are busy; continue this evidence pass yourself"
                                        }
                                    } else {
                                        if (zh) {
                                            "子代理失败，请改用直接工具调用"
                                        } else {
                                            "Sub-agent failed; fall back to direct tool calls"
                                        }
                                    }
                                ).toString()
                        }
                    )
                }
            }
        }
    }
}

/**
 * Permit pools keyed by the configured ceiling. Changing the setting takes
 * effect for the next spawn; runs already in flight keep their original slot.
 */
private val gates = java.util.concurrent.ConcurrentHashMap<Int, Semaphore>()

private fun concurrencyGate(permits: Int): Semaphore {
    val size = permits.coerceIn(1, 6)
    return gates.getOrPut(size) { Semaphore(size) }
}

/**
 * Role catalog for `agent_api(action=roles)`. Declared and resolved tool names
 * are both reported, so a whitelist typo surfaces here instead of silently
 * shrinking a role's evidence surface.
 */
internal fun subAgentRoleCatalog(settings: SettingsStore): JSONArray {
    val known = ToolCatalog.byName.keys
    return JSONArray(
        SubAgentRoles.ALL.map { role ->
            JSONObject()
                .put("id", role.id)
                .put("name", role.nameEn)
                .put("name_zh", role.nameZh)
                .put("description", role.goalEn)
                .put("description_zh", role.goalZh)
                .put("declared_tools", role.toolNames.toJsonArray())
                .put("tools", role.toolNames.filter(known::contains).toJsonArray())
                .put("unresolved_tools", role.toolNames.filterNot(known::contains).toJsonArray())
                .put("max_iterations", SubAgentPolicy.iterationsFor(role, settings.subAgentMaxIterations))
        }
    )
}

internal fun subAgentLimits(settings: SettingsStore): JSONObject = JSONObject()
    .put("enabled", settings.subAgentEnabled)
    .put("max_depth", settings.subAgentMaxDepth)
    .put("max_concurrent", settings.subAgentMaxConcurrent)
    .put("max_iterations", settings.subAgentMaxIterations)
    .put("max_per_run", settings.subAgentMaxPerRun)
    .put("model", settings.aiModel.ifBlank { "(unset)" })
    .put("configured", AgentKernel.isConfigured(settings))

internal fun subAgentCapabilities(settings: SettingsStore): JSONObject = JSONObject()
    .put("roles", SubAgentRoles.IDS.toJsonArray())
    .put("limits", subAgentLimits(settings))
    .put(
        "supported",
        listOf(
            "One scoped question per sub-agent, answered through the role's MCP tool whitelist",
            "Workspace inheritance from the caller so the target .so is not re-opened",
            "Same endpoint / API key / model as the configured AI settings",
            "Structured result: report, tools_used, steps_used, workspace_id"
        ).toJsonArray()
    )
    .put(
        "partial",
        listOf(
            "Nesting is capped by subAgentMaxDepth (default 1, max 2), so grandchildren rarely exist by design",
            "The concurrency ceiling is a process-wide slot pool; changing it applies to the next spawn",
            "Spawns inside one agent turn run sequentially, so parallel fan-out is bounded by steps, not threads"
        ).toJsonArray()
    )
    .put(
        "not_covered",
        listOf(
            "Sub-agents share no conversation history with their parent or with each other",
            "Role whitelists carry no write path: edit_*, build_so and session_* are never exposed to a sub-agent",
            "dyn_probe executes target code on-device (unidbg / Frida) — it is the one role with runtime side effects",
            "No persistent memory across separate runs and no automatic re-verification of a stale report"
        ).toJsonArray()
    )

/**
 * The sub-agent answers in the language of its task; an explicit caller flag
 * wins, and the app language is only the tie-breaker for a Latin-only task.
 */
internal fun resolveSubAgentLanguage(settings: SettingsStore, task: String, explicit: Boolean?): Boolean {
    if (explicit != null) return explicit
    if (task.any { it.code in 0x4E00..0x9FFF }) return true
    return settings.language == "zh"
}

/** Entry point for the external MCP surface: one-shot, depth-1 sub-agent run. */
internal fun runScopedSubAgent(ctx: ToolContext, role: SubAgentRole, task: String, zh: Boolean, workspaceId: String): JSONObject = runCatching {
    SubAgentRunner(ctx).runSync(
        role = role,
        task = task,
        zh = zh,
        depth = 1,
        workspaceId = workspaceId
    )
}.fold(
    onSuccess = { it.toJson(status = "ok") },
    onFailure = { error ->
        AppLog.e("agent_api sub-agent ${role.id} failed", error)
        when {
            error is TimeoutCancellationException -> err(
                "SUBAGENT_QUEUE_TIMEOUT",
                "All sub-agent slots are busy. Retry shortly, or gather this evidence through the regular tools.",
                "role",
                role.id
            )

            error is CancellationException -> throw error

            else -> err("SUBAGENT_FAILED", error.message ?: error.javaClass.simpleName, "role", role.id)
        }
    }
)
