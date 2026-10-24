// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Runtime adapters for the T1 audit tool batch. Each extension resolves the
// workspace/session (except the two pure-codec tools), delegates to the pure
// logic object, and returns through the shared ok()/err() envelope.
package com.soreverse.mcp.engine

import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.core.HexCodec
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import com.soreverse.mcp.core.str
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

private fun auditBase(workspaceId: String, editSessionId: String): JSONObject = JSONObject()
    .put("workspaceId", workspaceId)
    .put("editSessionId", editSessionId)

// ── ELF 结构与链接审计 ──

internal fun EngineRuntime.elfAbiProfile(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("abiProfile", ElfAudit.abiProfile(elf.data, elf)))
}

internal fun EngineRuntime.elfByteLedger(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("ledger", ElfAudit.byteLedger(elf.data, elf)))
}

internal fun EngineRuntime.elfSectionAnomaly(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val anomalies = ElfAudit.sectionAnomalies(elf)
    ok(
        auditBase(workspaceId, editSessionId)
            .put("sectionCount", elf.sections.size)
            .put("anomalyCount", anomalies.length())
            .put("anomalies", anomalies)
    )
}

internal fun EngineRuntime.elfPhdrInvariants(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("invariants", ElfAudit.phdrInvariants(elf)))
}

internal fun EngineRuntime.elfDynamicTags(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("dynamic", ElfAudit.dynamicTags(elf.data, elf)))
}

internal fun EngineRuntime.elfDtFlags(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("flags", ElfAudit.dtFlags(elf)))
}

internal fun EngineRuntime.elfHashTables(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("hashTables", ElfAudit.hashTables(elf.data, elf)))
}

internal fun EngineRuntime.elfRelocCensus(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("census", ElfAudit.relocCensus(elf)))
}

internal fun EngineRuntime.dtNeededResolve(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    val needed = ElfAudit.neededList(data, elf)
    val providers = HashMap<String, Set<String>>()
    workspaces.values.forEach { ws ->
        if (ws.id == workspaceId) return@forEach
        runCatching {
            val needs = ElfAudit.neededList(ws.data, ws.elf).toSet()
            ElfAudit.soname(ws.data, ws.elf)?.let { providers[it] = needs }
            providers[ws.source.name] = needs
        }
    }
    val resolved = LinkedHashSet<String>()
    val missing = LinkedHashSet<String>()
    val providersFound = LinkedHashSet<String>()
    val queue = ArrayDeque(needed)
    var depth = 0
    while (queue.isNotEmpty() && depth < 64) {
        val lib = queue.removeFirst()
        if (!resolved.add(lib)) continue
        val providerNeeds = providers[lib] ?: providers[lib.substringAfterLast('/')]
        if (providerNeeds == null) {
            missing += lib
        } else {
            providersFound += lib
            providerNeeds.filter { it !in resolved }.forEach { queue.addLast(it) }
            depth++
        }
    }
    ok(
        auditBase(workspaceId, editSessionId)
            .put("needed", JSONArray(needed))
            .put("resolvedFromWorkspaces", JSONArray(providersFound))
            .put("missing", JSONArray(missing))
            .put("workspaceProviderCount", workspaces.size - 1)
            .put(
                "scope",
                "Resolution walks DT_NEEDED and matches other opened workspaces by SONAME or file name. " +
                    "missing means: no opened workspace provides it — not proof the library is absent from the device."
            )
    )
}

internal fun EngineRuntime.symbolVisibilityAudit(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("visibility", ElfAudit.visibilityAudit(elf)))
}

// ── 代码空洞（code_padding_caves / patch_cave_finder 共用 ElfAudit.paddingCaves）──

private fun caveJson(elf: ElfFile, cave: ElfAudit.Cave): JSONObject = JSONObject()
    .put("section", cave.section)
    .put("sectionIndex", cave.index)
    .put("fileOffset", "0x${cave.fileOffset.toString(16)}")
    .put("va", "0x${cave.va.toString(16)}")
    .put("size", cave.size)
    .put("fill", cave.fill)

internal fun EngineRuntime.codePaddingCaves(workspaceId: String, editSessionId: String, minSize: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    val caves = ElfAudit.paddingCaves(data, elf, minSize.coerceIn(4, 65536), execOnly = false)
    ok(
        auditBase(workspaceId, editSessionId)
            .put("minSize", minSize.coerceIn(4, 65536))
            .put("caveCount", caves.size)
            .put("caves", JSONArray(caves.take(500).map { caveJson(elf, it) }))
    )
}

internal fun EngineRuntime.patchCaveFinder(workspaceId: String, editSessionId: String, minSize: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    val execLoads = elf.programHeaders.filter { it.type == 1L && it.flags and 0x1L != 0L }
    val relocTargets = elf.relocations.map { it.offset }.toSet()
    val caves = ElfAudit.paddingCaves(data, elf, minSize.coerceIn(4, 65536), execOnly = true)
    val items = JSONArray()
    caves.take(500).forEach { cave ->
        val inExecLoad = execLoads.any { cave.fileOffset >= it.offset && cave.fileOffset + cave.size <= it.offset + it.filesz }
        val relocCovered = relocTargets.any { it >= cave.fileOffset && it < cave.fileOffset + cave.size }
        val holdsEntry = elf.entry >= cave.va && elf.entry < cave.va + cave.size
        items.put(
            caveJson(elf, cave)
                .put("inExecLoad", inExecLoad)
                .put("relocTargetCovered", relocCovered)
                .put("holdsEntryPoint", holdsEntry)
                .put("safeForPatch", inExecLoad && !relocCovered && !holdsEntry)
        )
    }
    ok(
        auditBase(workspaceId, editSessionId)
            .put("minSize", minSize.coerceIn(4, 65536))
            .put("candidateCount", items.length())
            .put("candidates", items)
            .put(
                "safety",
                "safeForPatch requires: inside an executable PT_LOAD, no relocation targets the range, " +
                    "and the entry point is not inside it. Only-read tool: writing still goes through edit_hex/edit_asm."
            )
    )
}

// ── JNI / NDK 画像 ──

internal fun EngineRuntime.jniMangleCodec(args: JSONObject): JSONObject {
    val action = args.str("action", "decode")
    val result = JSONObject()
    if (action == "encode") {
        val clazz = args.str("className")
        val method = args.str("methodName")
        if (clazz.isBlank() || method.isBlank()) {
            return err("INVALID_ARGUMENT", "action=encode requires className and methodName", "className", clazz)
        }
        val symbol = JniMangle.encode(clazz, method, args.str("signature").ifBlank { null })
        result.put("symbol", symbol)
        val decoded = JniMangle.decode(symbol)
        result.put("roundTripValid", decoded.optBoolean("valid") && decoded.optString("methodName") == method.trim())
        result.put("decoded", decoded)
    } else {
        val symbol = args.str("symbol")
        if (symbol.isBlank()) {
            return err("INVALID_ARGUMENT", "action=decode requires symbol", "symbol", symbol)
        }
        result.put("decoded", JniMangle.decode(symbol.trim()))
    }
    return ok(result)
}

internal fun EngineRuntime.androidIdentNote(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("androidIdent", NativeProfile.androidIdent(elf.data, elf)))
}

internal fun EngineRuntime.ndkToolchainFingerprint(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("toolchain", NativeProfile.toolchainFingerprint(elf.data, elf)))
}

internal fun EngineRuntime.libcxxVariant(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("libcxx", NativeProfile.libcxxVariant(elf.data, elf)))
}

// ── 字符串、常量、加密 ──

internal fun EngineRuntime.strEncodingCensus(workspaceId: String, editSessionId: String, limit: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("census", StringCensus.encodingCensus(data, elf, limit.coerceIn(1, 500))))
}

internal fun EngineRuntime.strLiteralClasses(workspaceId: String, editSessionId: String, limit: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("classes", StringCensus.literalClasses(elf, limit.coerceIn(1, 2000))))
}

internal fun EngineRuntime.cryptoConstFingerprint(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("cipherConstants", CryptoFingerprint.scanCipherConstants(data, elf)))
}

internal fun EngineRuntime.cryptoHashConstants(workspaceId: String, editSessionId: String): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val data = dataFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("hashConstants", CryptoFingerprint.scanHashConstants(data, elf)))
}

internal fun EngineRuntime.netEndpointExtract(workspaceId: String, editSessionId: String, limit: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("endpoints", StringCensus.netEndpoints(elf, limit.coerceIn(1, 1000))))
}

internal fun EngineRuntime.filePathRoots(workspaceId: String, editSessionId: String, limit: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("pathRoots", StringCensus.filePathRoots(elf, limit.coerceIn(1, 1000))))
}

internal fun EngineRuntime.envPropertyKeys(workspaceId: String, editSessionId: String, limit: Int): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    ok(auditBase(workspaceId, editSessionId).put("propertyKeys", StringCensus.propertyKeys(elf, limit.coerceIn(1, 1000))))
}

// ── 补丁只读校验 ──

internal fun EngineRuntime.patchLengthGuard(args: JSONObject): JSONObject {
    val newHex = args.str("newHex").ifBlank { args.str("hex").ifBlank { args.str("bytes") } }
    val patch = HexCodec.bytes(newHex)
        ?: return err("INVALID_HEX", "newHex must contain valid hex byte pairs", "newHex", newHex.take(64))
    val byteLength = args.optInt("byteLength", 0)
    if (byteLength <= 0) {
        return err("INVALID_ARGUMENT", "byteLength must be a positive instruction-slot size", "byteLength", byteLength)
    }
    val architecture = args.str("architecture", "arm64").ifBlank { "arm64" }
    return ok(PatchAudit.lengthGuard(patch, byteLength, architecture, args.optBoolean("thumb", false)))
}

internal fun EngineRuntime.patchApplyVerify(workspaceId: String, editSessionId: String): JSONObject = guarded {
    if (editSessionId.isBlank()) {
        return@guarded err(
            "EDIT_SESSION_REQUIRED",
            "patch_apply_verify compares an edit session against the workspace original; pass editSessionId."
        )
    }
    val edited = dataFor(workspaceId, editSessionId)
    val original = dataFor(workspaceId, "")
    val editedElf = runCatching { ElfParser(edited).parse() }.getOrElse {
        return@guarded err("ELF_PARSE_FAILED", it.message ?: "edited image does not parse as ELF")
    }
    val originalElf = runCatching { ElfParser(original).parse() }.getOrElse {
        return@guarded err("ELF_PARSE_FAILED", it.message ?: "original image does not parse as ELF")
    }
    ok(
        auditBase(workspaceId, editSessionId)
            .put("verify", PatchAudit.applyVerify(original, edited, originalElf, editedElf))
    )
}

// ── 证据清单 ──

internal fun EngineRuntime.evidenceManifest(workspaceId: String, claims: JSONArray): JSONObject = guarded {
    val resolvedId = resolveWorkspaceId(workspaceId, "")
    val ws = workspaces[resolvedId] ?: return@guarded err("WORKSPACE_NOT_FOUND", "Workspace not found", "workspaceId", workspaceId)
    val data = ws.data
    val manifest = JSONObject()
        .put(
            "generator",
            JSONObject()
                .put("tool", "SOMCP")
                .put("version", BuildConfig.VERSION_NAME)
                .put("generatedAt", System.currentTimeMillis())
        )
        .put(
            "input",
            JSONObject()
                .put("workspaceId", resolvedId)
                .put("path", ws.source.path)
                .put("source", ws.source.source)
                .put("analysisSource", ws.analysisInputSource)
                .put("sha256", sha256(data))
                .put("size", data.size)
                .put("originalSha256", ws.originalSha256)
        )
        .put(
            "scope",
            JSONObject()
                .put("sections", ws.elf.sections.size)
                .put("dynSymbols", ws.elf.dynSymbols.size)
                .put("relocations", ws.elf.relocations.size)
                .put("architecture", ws.elf.architecture)
        )
        .put("claims", claims)
    val canonical = manifest.toString()
    manifest.put(
        "manifestSha256",
        MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    )
    ok(
        JSONObject()
            .put("manifest", manifest)
            .put(
                "reproduction",
                "so_open path=<input.path>, then re-run each claim's tool with its recorded arguments; " +
                    "compare result digests against the claim entries."
            )
    )
}
