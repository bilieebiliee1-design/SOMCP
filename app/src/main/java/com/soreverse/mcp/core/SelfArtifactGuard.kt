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
import com.soreverse.mcp.BuildConfig
import com.soreverse.mcp.nativecore.NativeProbe
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
    fun nativeLibraryDir(context: Context): String? = runCatching { context.applicationInfo?.nativeLibraryDir }.getOrNull()
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
    fun isSelfApkPath(context: Context, path: String): Boolean = isSelfApkPathAgainst(runningApkPaths(context), path)

    /** True when [path] is one of SOMCP's own bundled native libraries at its install location. */
    fun isSelfBundledSo(context: Context, path: String): Boolean = isSelfBundledSoAgainst(nativeLibraryDir(context), path)

    /** True when [value] is a `lib/<abi>/<name>.so` APK entry naming an own bundled lib. */
    fun isSelfLibEntry(context: Context, value: String): Boolean = isSelfLibEntryAgainst(ownLibraryNames(context), value)

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
    fun isOwnApkCopy(context: Context, path: String): Boolean {
        val lower = path.lowercase()
        if (!lower.endsWith(".apk") && !lower.endsWith(".zip")) return false
        val f = runCatching { File(path) }.getOrNull() ?: return false
        if (!f.isFile) return false
        return identityCache.getOrPut(path) { NativeProbe.isOwnApkV234(path) }
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
    fun isSelfArtifact(context: Context, path: String): Boolean = isSelfApkPath(context, path) ||
        isSelfBundledSo(context, path) ||
        isOwnApkCopy(context, path) ||
        isSelfLibEntry(context, path) ||
        isSelfFileByContent(path)

    /**
     * True when the file at [path] identifies SOMCP's own artifact by content,
     * regardless of where it was extracted to or how it was renamed. This closes
     * the gap where a user copies one of SOMCP's own bundled `.so` libraries out
     * into a work directory and then asks MCP to open/view/modify it: the path no
     * longer sits under `nativeLibraryDir`, but its bytes still carry the app id.
     */
    fun isSelfFileByContent(path: String): Boolean {
        val lower = path.trim().lowercase()
        if (!lower.endsWith(".so")) return false
        return readMeOwnMarker(path)
    }

    //
    // Byte-level own-package marker scan (ASCII/UTF-16LE), location-free and
    // robust against renames and light edits. Mirrors the engine-side
    // `containsPackageIdentifier` so `core` stays self-contained/testable.
    //

    private const val MARKER_SCAN_LIMIT = 1 shl 22 // 4 MiB prefix

    fun containsOwnMarker(bytes: ByteArray): Boolean {
        val marker = BuildConfig.APPLICATION_ID
        if (marker.isBlank() || bytes.isEmpty()) return false
        val ascii = marker.toByteArray(Charsets.US_ASCII)
        val utf16le = marker.toByteArray(Charsets.UTF_16LE)
        return containsSubsequence(bytes, ascii) || containsSubsequence(bytes, utf16le)
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        for (i in 0..(haystack.size - needle.size)) {
            var j = 0
            while (j < needle.size && haystack[i + j] == needle[j]) j++
            if (j == needle.size) return true
        }
        return false
    }

    private fun readMeOwnMarker(path: String): Boolean {
        if (path.isBlank()) return false
        return runCatching {
            val f = File(path)
            if (!f.isFile) return false
            f.inputStream().use { ins ->
                val buf = ByteArray(MARKER_SCAN_LIMIT)
                var read = 0
                while (read < buf.size) {
                    val n = ins.read(buf, read, buf.size - read)
                    if (n < 0) break
                    read += n
                }
                read > 0 && containsOwnMarker(buf.copyOf(read))
            }
        }.getOrDefault(false)
    }

    // ---------------------------------------------------------------------
    // Argument scanning (for bridge/MCP tool calls)
    // ---------------------------------------------------------------------

    /**
     * Recursively scans a tool-call [args] object for any string argument that
     * references SOMCP's own artifact (using the running install). Returns the
     * offending path on the first hit, or null when the call targets only
     * third-party files.
     */
    fun findSelfArg(context: Context, args: JSONObject): String? = findSelfArgAgainst(
        runningApkPaths(context),
        nativeLibraryDir(context),
        args,
        identityCheck = { path -> isOwnApkCopy(context, path) },
        ownLibNames = ownLibraryNames(context),
        contentCheck = ::isSelfFileByContent
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
        identityCheck: ((String) -> Boolean)? = null,
        ownLibNames: Set<String> = emptySet(),
        contentCheck: ((String) -> Boolean)? = null
    ): String? {
        val holder = PathHolder()
        scanValue(runningApks, nativeLib, identityCheck, ownLibNames, contentCheck, args, holder)
        return holder.path
    }

    private class PathHolder {
        var path: String? = null
    }

    private fun scanValue(
        runningApks: List<String>,
        nativeLib: String?,
        identityCheck: ((String) -> Boolean)?,
        ownLibNames: Set<String>,
        contentCheck: ((String) -> Boolean)?,
        value: Any?,
        holder: PathHolder
    ) {
        if (holder.path != null) return
        when (value) {
            is JSONObject -> {
                val keys = value.keys()
                while (keys.hasNext() && holder.path == null) {
                    val k = keys.next()
                    scanValue(runningApks, nativeLib, identityCheck, ownLibNames, contentCheck, value.opt(k), holder)
                }
            }

            is JSONArray -> {
                for (i in 0 until value.length()) {
                    if (holder.path != null) break
                    scanValue(runningApks, nativeLib, identityCheck, ownLibNames, contentCheck, value.opt(i), holder)
                }
            }

            is String -> {
                val found = selfReference(runningApks, nativeLib, identityCheck, ownLibNames, contentCheck, value)
                if (found != null) holder.path = found
            }

            else -> Unit
        }
    }

    private fun selfReference(
        runningApks: List<String>,
        nativeLib: String?,
        identityCheck: ((String) -> Boolean)?,
        ownLibNames: Set<String>,
        contentCheck: ((String) -> Boolean)?,
        value: String
    ): String? {
        if (value.isBlank()) return null
        // A workspace id or file name already proven to be SOMCP's own artifact
        // (the open that produced it was refused, but the caller may still hold
        // the id) stays refused from here on.
        if (isQuarantined(value)) return value
        if (!isPathLike(value)) return null
        if (isSelfApkPathAgainst(runningApks, value)) return value
        if (isSelfBundledSoAgainst(nativeLib, value)) return value
        // APK-entry reference like `App.apk!lib/<abi>/<own>.so` — matches by the
        // own bundled lib name even when the APK itself is renamed/moved.
        if (isSelfLibEntryAgainst(ownLibNames, value)) return value
        // An extracted copy of an own `.so` outside its install dir is identified
        // by content (own package marker), defeating the "copy to work dir" trick.
        if (contentCheck != null && contentCheck(value)) return value
        // Signature-based copy detection is only enabled when a live native
        // verifier is available; in JVM unit tests it is omitted entirely.
        if (identityCheck != null && identityCheck(value)) return value
        return null
    }

    /** Conservative path heuristic so URLs / bare package names are not scanned. */
    private fun isPathLike(value: String): Boolean {
        if (value.contains('/') || value.contains('\\')) return true
        val lower = value.lowercase()
        return lower.endsWith(".apk") || lower.endsWith(".zip") || lower.endsWith(".so")
    }

    // ---------------------------------------------------------------------
    // Bridged-result identity and quarantine
    // ---------------------------------------------------------------------

    /**
     * Identifiers proven to belong to SOMCP's own artifact: the workspace ids an
     * already-forwarded bridged call turned out to describe.
     *
     * The argument scan above cannot cover every bridged call. An external APK
     * server (MT Manager) resolves a relative path against a directory of its
     * own — `SOMCP_1.0.21.apk` is not a file in this process, so no path check
     * can classify it — and every follow-up call names only the workspace the
     * open returned, never the archive again. The identity therefore has to be
     * taken from the result: once it names SOMCP's own package, that value is
     * remembered here and every later call mentioning it is refused, so the
     * artifact that was opened cannot be read, xref-ed or rebuilt afterwards.
     */
    private val quarantined = ConcurrentHashMap.newKeySet<String>()

    /** Remembers [values] as own-artifact identifiers. */
    fun quarantine(values: Collection<String>) {
        values.map { it.trim() }.filter { it.isNotEmpty() }.forEach(quarantined::add)
    }

    /** Drops every remembered identifier. */
    fun clearQuarantine() {
        quarantined.clear()
    }

    /** True when [value] names or embeds a remembered own-artifact identifier. */
    fun isQuarantined(value: String): Boolean {
        val v = value.trim()
        if (v.isEmpty() || quarantined.isEmpty()) return false
        if (quarantined.contains(v)) return true
        val base = baseName(v)
        if (base != v && quarantined.contains(base)) return true
        // Embedded forms, e.g. `…/SOMCP_1.0.21.apk!lib/arm64-v8a/liblief_elf.so`.
        return quarantined.any { v.contains(it) }
    }

    /**
     * Own-artifact verdict for an already-forwarded bridged tool result.
     *
     * [value] is the signal that identified SOMCP's own package (the package
     * name, or the signer digest) and is used for the refusal message;
     * [identifiers] are the handles a later call can still name — the workspace
     * ids and digests — and are what gets quarantined.
     */
    class BridgedVerdict(val value: String, val identifiers: List<String>)

    /**
     * Inspects an already-forwarded bridged tool result and returns the verdict
     * when it describes SOMCP's own package, or null for a third-party artifact.
     */
    fun ownArtifactFromBridgedResult(result: JSONObject?): BridgedVerdict? {
        if (result == null) return null
        val scan = BridgedResultScan(
            ownPackage = BuildConfig.APPLICATION_ID,
            pinned = runCatching { normalizeFingerprint(NativeProbe.pinnedFingerprint()) }.getOrDefault("")
        )
        scan.walk(result)
        val offending = scan.offending ?: return null
        // A result that identifies the package but names no handle (no workspace
        // id, no file name) still gets refused; quarantine the signal itself so
        // a repeat of the same call is refused too.
        return BridgedVerdict(
            offending,
            scan.identifiers.filter { it != offending }.ifEmpty { listOf(offending) }
        )
    }

    // ---------------------------------------------------------------------
    // Standardized forbidden result
    // ---------------------------------------------------------------------

    /** Standard MCP tool result for a blocked self-artifact operation. */
    fun forbidden(path: String?, detail: String = "SOMCP refuses to open, view, or modify its own APK or bundled native library"): JSONObject = err(
        code = "SELF_ANALYSIS_FORBIDDEN",
        message = "$detail (own-artifact protection; no exceptions)",
        argument = "path",
        badValue = path
    )

    private val identityCache = ConcurrentHashMap<String, Boolean>()

    private val libEntryPattern = Regex("(?:^|[^A-Za-z0-9])lib/[^/]+/[^/]+\\.so$", RegexOption.IGNORE_CASE)

    /**
     * Recursive walk over a bridged tool result looking for SOMCP's own package
     * identity: the package name the remote server reports, or the pinned
     * release signer digest. Both are exact, so a third-party artifact cannot
     * match by accident. Every workspace id encountered on the way is collected
     * for quarantine. Nested text fields (the remote's `content[].text` carries
     * a JSON document as a string) are parsed and walked as well; an unparsable
     * text still counts when it literally contains the package id.
     */
    private class BridgedResultScan(private val ownPackage: String, private val pinned: String) {
        val identifiers = LinkedHashSet<String>()
        var offending: String? = null

        fun walk(value: Any?) {
            when (value) {
                is JSONObject -> {
                    val keys = value.keys()
                    while (keys.hasNext()) {
                        val key = keys.next()
                        inspect(key, value.opt(key))
                    }
                }

                is JSONArray -> for (i in 0 until value.length()) walk(value.opt(i))

                is String -> walkText(value)

                else -> Unit
            }
        }

        private fun inspect(key: String, value: Any?) {
            if (value !is String) {
                walk(value)
                return
            }
            val v = value.trim()
            when {
                key in ID_KEYS && v.isNotEmpty() -> identifiers.add(v)

                key.equals(PACKAGE_KEY, true) && ownPackage.isNotBlank() && v == ownPackage -> mark(v)

                key in DIGEST_KEYS && pinned.isNotBlank() && normalizeFingerprint(v) == pinned -> mark(v)

                // Any other string may itself be a nested document: the remote
                // carries its payload as a JSON string under `content[].text`
                // (and the bridge parks an unparsable body under `raw`), so a
                // plain string value still has to be looked into.
                else -> walkText(v)
            }
        }

        private fun walkText(text: String) {
            val parsed = if (text.trim().startsWith("{")) {
                runCatching { JSONObject(text.trim()) }.getOrNull()
            } else {
                null
            }
            when {
                parsed != null -> walk(parsed)
                ownPackage.isNotBlank() && text.contains(ownPackage) -> mark(ownPackage)
                else -> Unit
            }
        }

        private fun mark(value: String) {
            if (offending == null) offending = value
            if (value != ownPackage) identifiers.add(value)
        }

        private companion object {
            const val PACKAGE_KEY = "packageName"
            val ID_KEYS = setOf("workspaceId", "workspace_id")
            val DIGEST_KEYS = setOf("sha256", "certSha256", "signerSha256", "certificateSha256", "signerDigest")
        }
    }

    private fun canonical(path: String): String = try {
        File(path).canonicalPath
    } catch (_: Exception) {
        path
    }
}

/** Last path segment of [value], for either separator. */
private fun baseName(value: String): String = value.trim().substringAfterLast('/').substringAfterLast('\\')
