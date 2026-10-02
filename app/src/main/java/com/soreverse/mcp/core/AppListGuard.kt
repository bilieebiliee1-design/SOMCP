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
import android.content.Intent
import android.content.pm.ApplicationInfo
import java.nio.charset.StandardCharsets

/**
 * Refuses to run next to the repack tooling this app is targeted by: a hit on a
 * pinned package name or a pinned install label is reported as a threat to
 * [IntegrityGuard], which terminates the process.
 *
 * Two channels, deliberately not redundant:
 * - [pinnedPackageThreats] is a direct per-package lookup. It is cheap, so it
 *   runs on every [IntegrityGuard] pass (including the 3 s UI poll) and catches
 *   the tools under their published package names before any list scan exists.
 * - The list scan catches a repack that keeps the visible name but changes the
 *   applicationId. Enumerating every installed app and resolving each label is
 *   O(installed apps) binder plus resource reads, so it never runs on the
 *   caller's thread: [threats] hands back the last snapshot and refreshes it in
 *   the background at most once per [REFRESH_INTERVAL_MS].
 *
 * Both channels read through PackageManager, i.e. through the same Binder layer
 * a signature-bypass framework already hooks to fake *this* app's signature, so
 * this is a coexistence gate, not tamper evidence. The filesystem-level checks
 * in NativeProbe stay authoritative for whether the running package is genuine.
 */
object AppListGuard {
    /** An installed app as the matcher sees it. Plain data so matching runs in JVM tests. */
    data class Candidate(val packageName: String, val label: String)

    private const val REFRESH_INTERVAL_MS = 60_000L

    // Hex-encoded UTF-8 of the tool identities, decoded at runtime so none of it
    // sits in the string pool of the compiled artifact. Same convention as
    // IntegrityGuard.marked(), except that one maps bytes to chars, which cannot
    // represent a multi-byte label.
    private const val PIN_PACKAGE_QINGFENG = "636F6D2E71696E6766656E672E617070"
    private const val PIN_PACKAGE_METK_HUB = "6D65746B2E687562"
    private const val PIN_LABEL_QINGFENG = "E6B885E9A38E"
    private const val PIN_LABEL_METK_HUB = "E9A398E99BB6E6B585E98689C2B7487562"

    private val pinnedPackages: List<String> = listOf(decode(PIN_PACKAGE_QINGFENG), decode(PIN_PACKAGE_METK_HUB))

    /**
     * Labels normalized like a fingerprint: separators and case are what
     * separates "飘零浅醉·Hub" from "飘零浅醉 hub" from "飘零浅醉Hub", and they
     * are decoration a repack changes, not identity.
     */
    private val pinnedLabels: List<String> =
        listOf(decode(PIN_LABEL_QINGFENG), decode(PIN_LABEL_METK_HUB)).map { normalizeFingerprint(it) }

    private val refreshLock = Any()

    @Volatile private var lastScanAt = 0L

    @Volatile private var scanning = false

    @Volatile private var snapshot: List<String> = emptyList()

    /** Threat descriptions for [IntegrityGuard.runtimeThreats]. Never blocks. */
    fun threats(context: Context): List<String> {
        val direct = pinnedPackageThreats(context)
        if (direct.isNotEmpty()) return direct
        requestRefresh(context.applicationContext ?: context)
        return snapshot
    }

    /**
     * Direct existence probe per pinned package. QUERY_ALL_PACKAGES makes the
     * exact lookup authoritative. The manifest pins no package name in
     * `<queries>`: that would write the detection criteria into the manifest in
     * plain text, and the generic launcher intent already declared there keeps
     * this probe (and the scan below) working on a ROM whose appops blocks the
     * package list but still resolves launchable intents.
     */
    internal fun pinnedPackageThreats(context: Context): List<String> {
        val pm = context.packageManager
        return pinnedPackages
            .filter { runCatching { pm.getPackageInfo(it, 0) }.isSuccess }
            .map { "signature-bypass tool installed: $it" }
    }

    /** Full installed-app snapshot, read through two independent PM channels. */
    internal fun scan(context: Context): List<Candidate> {
        val pm = context.packageManager
        val apps = linkedMapOf<String, ApplicationInfo>()
        runCatching { pm.getInstalledApplications(0) }
            .getOrDefault(emptyList())
            .forEach { apps.retainFirst(it.packageName, it) }
        // Intent resolution filters the visible set along a different path than
        // getInstalledApplications, so a hook that trims one list still leaves
        // the other populated.
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        runCatching { pm.queryIntentActivities(launcher, 0) }
            .getOrDefault(emptyList())
            .forEach { info ->
                info.activityInfo?.applicationInfo?.let { apps.retainFirst(it.packageName, it) }
            }
        return apps.values.map { info ->
            Candidate(
                packageName = info.packageName,
                label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault("")
            )
        }
    }

    internal fun matchThreats(candidates: List<Candidate>): List<String> {
        val hits = linkedSetOf<String>()
        candidates.forEach { candidate ->
            if (pinnedPackages.any { it.equals(candidate.packageName, ignoreCase = true) }) {
                hits += "signature-bypass tool installed: ${candidate.packageName}"
                return@forEach
            }
            val normalized = normalizeFingerprint(candidate.label)
            if (normalized.isEmpty()) return@forEach
            pinnedLabels.forEach { needle ->
                if (normalized.contains(needle)) {
                    hits += "signature-bypass tool matched by name: ${candidate.packageName} (${candidate.label})"
                }
            }
        }
        return hits.toList()
    }

    /**
     * Hands back the current snapshot and, when it is stale, claims the refresh
     * on a daemon thread. Claiming before scanning (rather than after) keeps a
     * failing scan from being retried by every 3 s poll.
     */
    private fun requestRefresh(context: Context) {
        synchronized(refreshLock) {
            if (scanning) return
            if (System.currentTimeMillis() - lastScanAt < REFRESH_INTERVAL_MS) return
            lastScanAt = System.currentTimeMillis()
            scanning = true
        }
        Thread {
            val threats = runCatching { matchThreats(scan(context)) }
                .onFailure { AppLog.w("AppListGuard scan failed: ${it.javaClass.simpleName}: ${it.message}") }
                .getOrDefault(snapshot)
            snapshot = threats
            synchronized(refreshLock) { scanning = false }
        }.apply {
            isDaemon = true
            name = "soreverse-applist"
            start()
        }
    }

    private fun MutableMap<String, ApplicationInfo>.retainFirst(name: String, info: ApplicationInfo) {
        if (!containsKey(name)) this[name] = info
    }

    private fun decode(hex: String): String = String(
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
        StandardCharsets.UTF_8
    )
}
