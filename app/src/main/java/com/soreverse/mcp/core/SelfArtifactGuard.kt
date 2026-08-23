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
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
package com.soreverse.mcp.core

import android.content.Context
import com.soreverse.mcp.nativecore.SignatureVerifier
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONArray
import org.json.JSONObject

/**
 * Self-artifact protection for SOMCP.
 *
 * SOMCP must never open, view, or modify its own APK or the native libraries
 * it bundles. An MCP client (or a bridged "merged into tools/list" APK MCP
 * server such as MT Manager) could otherwise be pointed at SOMCP's own
 * artifact and used to read or tamper with the running app's file.
 *
 * Detection is layered and intentionally low false-positive:
 *  - the running APK path (`packageCodePath` / `sourceDir`), which catches the
 *    deployed base.apk wherever it is installed;
 *  - the app's `nativeLibraryDir`, which catches SOMCP's own bundled native
 *    libraries still located in their installation directory;
 *  - a cached v2/v3 signing-block check for copies of the APK placed elsewhere,
 *    matching SOMCP's pinned release signer (signature-based, location-free).
 */
object SelfArtifactGuard {

    // ---------------------------------------------------------------------
    // Running-installation identification
    // ---------------------------------------------------------------------

    /** Canonical paths of the running SOMCP base APK. */
    fun runningApkPaths(context: Context): List<String> {
        val paths = LinkedHashSet<String>()
        runCatching { context.packageCodePath }.getOrNull()?.takeIf { it.isNotBlank() }
            ?.let(paths::add)
        runCatching { context.applicationInfo?.sourceDir }.getOrNull()?.takeIf { it.isNotBlank() }
            ?.let(paths::add)
        return paths.map(::canonical)
    }

    /** Canonical path of the directory holding SOMCP's own unpacked native libs. */
    fun nativeLibraryDir(context: Context): String? =
        runCatching { context.applicationInfo?.nativeLibraryDir }.getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?.let(::canonical)

    /**
     * Basenames of the `.so` files SOMCP actually bundles, taken from the build
     * output / install location (`nativeLibraryDir`). Any later `lib/<abi>/…`
     * APK-entry reference whose last segment matches one of these is SOMCP's
     * own library, no matter where the APK copy is renamed or relocated.
     */
    fun ownLibraryNames(context: Context): Set<String> {
        val root = nativeLibraryDir(context) ?: return emptySet()
        return runCatching {
            File(root).listFiles { f -> f.isFile && f.name.endsWith(".so", ignoreCase = true) }
                ?.map { it.name }
                ?.toSet().orEmpty()
        }.getOrDefault(emptySet())
    }

    /** True when [path] points at the running/base SOMCP APK itself. */
    fun isSelfApkPath(context: Context, path: String): Boolean =
        isSelfApkPathAgainst(runningApkPaths(context), path)

    /** True when [path] is one of SOMCP's own bundled native libraries at its install location. */
    fun isSelfBundledSo(context: Context, path: String): Boolean =
        isSelfBundledSoAgainst(nativeLibraryDir(context), path)

    /** True when [value] is a `lib/<abi>/<name>.so` APK entry naming an own bundled lib. */
    fun isSelfLibEntry(context: Context, value: String): Boolean =
        isSelfLibEntryAgainst(ownLibraryNames(context), value)

    /** Context-free `lib/<abi>/…` entry check against an explicit set of own lib names. */
    fun isSelfLibEntryAgainst(ownLibNames: Set<String>, value: String): Boolean {
        if (ownLibNames.isEmpty() || !libEntryPattern.containsMatchIn(value)) return false
        val name = value.trim().substringAfterLast('/').substringAfterLast('\\')
        return ownLibNames.contains(name)
    }

    /**
     * True when [path] is a copy of SOMCP's own APK whose v2/v3 signing-block
     * certificate matches SOMCP's pinned release signer, no matter where the
     * copy lives or is renamed to.
     */
    fun isSelfSignedApkCopy(context: Context, path: String): Boolean {
        val lower = path.lowercase()
        if (!lower.endsWith(".apk") && !lower.endsWith(".zip")) return false
        val f = runCatching { File(path) }.getOrNull() ?: return false
        if (!f.isFile) return false
        return signatureCache.getOrPut(path) { SignatureVerifier.isSelfSignedApkV234(path) }
    }

    /**
     * Context-free path check against an explicit set of running-APK paths.
     * Used by the [Context] overloads and testable without Android.
     */
    fun isSelfApkPathAgainst(runningApks: List<String>, path: String): Boolean {
        if (runningApks.isEmpty()) return false
        val target = canonical(path)
        return runningApks.map(::canonical).contains(target)
    }

    /**
     * Context-free check that [path] lives inside an explicit native lib dir.
     */
    fun isSelfBundledSoAgainst(nativeLib: String?, path: String): Boolean {
        val root = nativeLib?.let(::canonical) ?: return false
        val target = canonical(path)
        if (target == root) return true
        return target.startsWith("$root/")
    }

    /**
     * Combined check: is [path] SOMCP's own APK or one of its bundled libs?
     */
    fun isSelfArtifact(context: Context, path: String): Boolean =
        isSelfApkPath(context, path) ||
            isSelfBundledSo(context, path) ||
            isSelfSignedApkCopy(context, path) ||
            isSelfLibEntry(context, path)

    // ---------------------------------------------------------------------
    // Argument scanning (for bridge/MCP tool calls)
    // ---------------------------------------------------------------------

    /**
     * Recursively scans a tool-call [args] object for any string argument that
     * references SOMCP's own artifact (using the running install). Returns the
     * offending path on the first hit, or null when the call targets only
     * third-party files.
     */
    fun findSelfArg(context: Context, args: JSONObject): String? =
        findSelfArgAgainst(
            runningApkPaths(context),
            nativeLibraryDir(context),
            args,
            signatureCheck = { path -> isSelfSignedApkCopy(context, path) },
            ownLibNames = ownLibraryNames(context)
        )

    /**
     * Context-free scan overload; lets tests exercise the bridge guard without
     * an Android [Context] or a loaded native verifier by supplying the install
     * paths (and optionally a signature-copy checker) explicitly.
     */
    fun findSelfArgAgainst(
        runningApks: List<String>,
        nativeLib: String?,
        args: JSONObject,
        signatureCheck: ((String) -> Boolean)? = null,
        ownLibNames: Set<String> = emptySet()
    ): String? {
        val holder = PathHolder()
        scanValue(runningApks, nativeLib, signatureCheck, ownLibNames, args, holder)
        return holder.path
    }

    private class PathHolder {
        var path: String? = null
    }

    private fun scanValue(
        runningApks: List<String>,
        nativeLib: String?,
        signatureCheck: ((String) -> Boolean)?,
        ownLibNames: Set<String>,
        value: Any?,
        holder: PathHolder
    ) {
        if (holder.path != null) return
        when (value) {
            is JSONObject -> {
                val keys = value.keys()
                while (keys.hasNext() && holder.path == null) {
                    val k = keys.next()
                    scanValue(runningApks, nativeLib, signatureCheck, ownLibNames, value.opt(k), holder)
                }
            }

            is JSONArray -> {
                for (i in 0 until value.length()) {
                    if (holder.path != null) break
                    scanValue(runningApks, nativeLib, signatureCheck, ownLibNames, value.opt(i), holder)
                }
            }

            is String -> {
                val found = selfReference(runningApks, nativeLib, signatureCheck, ownLibNames, value)
                if (found != null) holder.path = found
            }

            else -> Unit
        }
    }

    private fun selfReference(
        runningApks: List<String>,
        nativeLib: String?,
        signatureCheck: ((String) -> Boolean)?,
        ownLibNames: Set<String>,
        value: String
    ): String? {
        if (value.isBlank() || !isPathLike(value)) return null
        if (isSelfApkPathAgainst(runningApks, value)) return value
        if (isSelfBundledSoAgainst(nativeLib, value)) return value
        // APK-entry reference like `App.apk!lib/<abi>/<own>.so` — matches by the
        // own bundled lib name even when the APK itself is renamed/moved.
        if (isSelfLibEntryAgainst(ownLibNames, value)) return value
        // Signature-based copy detection is only enabled when a live native
        // verifier is available; in JVM unit tests it is omitted entirely.
        if (signatureCheck != null && signatureCheck(value)) return value
        return null
    }

    /** Conservative path heuristic so URLs / bare package names are not scanned. */
    private fun isPathLike(value: String): Boolean {
        if (value.contains('/') || value.contains('\\')) return true
        val lower = value.lowercase()
        return lower.endsWith(".apk") || lower.endsWith(".zip") || lower.endsWith(".so")
    }

    // ---------------------------------------------------------------------
    // Standardized forbidden result
    // ---------------------------------------------------------------------

    /** Standard MCP tool result for a blocked self-artifact operation. */
    fun forbidden(path: String?, detail: String = "SOMCP refuses to open, view, or modify its own APK or bundled native library"):
        JSONObject = err(
        code = "SELF_ANALYSIS_FORBIDDEN",
        message = "$detail (own-artifact protection; no exceptions)",
        argument = "path",
        badValue = path
    )

    private val signatureCache = ConcurrentHashMap<String, Boolean>()

    private val libEntryPattern = Regex("(?:^|[^A-Za-z0-9])lib/[^/]+/[^/]+\\.so$", RegexOption.IGNORE_CASE)

    private fun canonical(path: String): String = try {
        File(path).canonicalPath
    } catch (_: Exception) {
        path
    }
}