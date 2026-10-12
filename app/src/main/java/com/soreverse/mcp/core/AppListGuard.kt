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
import android.content.pm.PackageManager
import java.nio.charset.StandardCharsets

/**
 * Refuses to run next to known derivative builds of this app: a hit on a
 * pinned package name or a pinned install label is reported as a threat to
 * [IntegrityGuard], which terminates the process.
 *
 * The pinned identities are *derivative builds of SOMCP itself* — 清风
 * (`com.qingfeng.app`) and 飘零浅醉·Hub (`metk.hub`) redistribute this
 * project's code and tooling under a different applicationId — not
 * third-party signature-bypass tooling. The distinction is load-bearing in the
 * user-facing text: the gate dialog names the offending package, so calling it
 * a "signature-bypass tool" accuses a third party of shipping an attack tool
 * when what is actually installed is a repack of this project. Naming it a
 * derivative build also states the real consequence, which is the AGPL
 * obligation (see docs/legal/) rather than an attack on this install.
 *
 * Two channels, deliberately not redundant:
 * - [pinnedPackageThreats] is a direct per-package lookup. It is cheap, so it
 *   runs on every [IntegrityGuard] pass (including the 3 s UI poll) and catches
 *   those builds under their published package names before any list scan
 *   exists.
 * - The list scan catches a build that keeps the visible name but changes the
 *   applicationId. Enumerating every installed app and resolving each label is
 *   O(installed apps) binder plus resource reads, so it never runs on the
 *   caller's thread: [threats] hands back the last snapshot and refreshes it in
 *   the background at most once per [REFRESH_INTERVAL_MS].
 *
 * Both channels read through PackageManager, i.e. through the same Binder layer
 * a repack or signature-bypass framework already hooks to fake *this* app's
 * signature, so this is a coexistence gate, not tamper evidence. The
 * filesystem-level checks in NativeProbe stay authoritative for whether the
 * running package is genuine.
 *
 * App-hiding tools (Zygisk app-list hiders and their "reject the app list
 * request" mode) suppress exactly these channels: they trim entries from
 * getInstalledApplications, answer getPackageInfo with a spoofed
 * NameNotFoundException, or reject the whole list call. Reading those answers
 * at face value would let a device that hides the pinned identities pass this
 * gate silently - the coexistence dialog would then never appear even though
 * a derivative build is installed. The gate therefore fails closed on signals
 * that cannot occur on a genuine, unobstructed device: a list call that throws
 * or returns an empty table (impossible outside suppression), and a
 * getPackageInfo failure that is anything other than the honest
 * NameNotFoundException. Those outcomes are reported as threats through the
 * same [threats] entry, so the integrity dialog surfaces the suppression
 * instead of silently passing it.
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
        return pinnedPackages.mapNotNull { pkg ->
            runCatching { pm.getPackageInfo(pkg, 0) }
                .fold(
                    onSuccess = { "derivative build of this app installed: $pkg" },
                    onFailure = { error ->
                        // NameNotFoundException is the system's honest "not
                        // installed". Anything else means the lookup itself was
                        // intercepted or the binder call died - exactly what an
                        // app-hiding tool does to keep a hidden package from
                        // being resolved. Fail closed: report the blocked probe
                        // as a threat instead of reading it as absence, so the
                        // gate dialog still surfaces.
                        if (error is PackageManager.NameNotFoundException) {
                            null
                        } else {
                            "package visibility probe failed for $pkg (${error.javaClass.simpleName})"
                        }
                    }
                )
        }
    }

    /** An app-list read together with whether the primary list channel looked suppressed. */
    data class ScanOutcome(val candidates: List<Candidate>, val installedListSuppressed: Boolean)

    /** Full installed-app snapshot, read through two independent PM channels. */
    internal fun scanOutcome(context: Context): ScanOutcome {
        val pm = context.packageManager
        val apps = linkedMapOf<String, ApplicationInfo>()
        // getInstalledApplications is the primary channel. A thrown or empty
        // answer is not evidence of absence: app-hiding tools suppress exactly
        // this call. Record the anomaly so the caller can fail closed instead
        // of reading the suppressed list as a clean device.
        val installed = runCatching { pm.getInstalledApplications(0) }
        installed.getOrDefault(emptyList()).forEach { apps.retainFirst(it.packageName, it) }
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
        val candidates = apps.values.map { info ->
            Candidate(
                packageName = info.packageName,
                label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault("")
            )
        }
        // A thrown call, or an empty primary table, cannot happen legitimately:
        // every real device ships system apps, with or without QUERY_ALL_PACKAGES.
        // The launcher fallback still contributes candidates, but it does not
        // launder a suppressed primary channel.
        val suppressed = installed.isFailure || installed.getOrDefault(emptyList()).isEmpty()
        return ScanOutcome(candidates, suppressed)
    }

    /** Pure decision, split out so the fail-closed wording is unit-testable off-device. */
    internal fun suppressedListThreat(installedListSuppressed: Boolean, candidateCount: Int): String? = if (installedListSuppressed) {
        "installed-app list is suppressed or rejected (visible entries: $candidateCount)"
    } else {
        null
    }

    internal fun matchThreats(candidates: List<Candidate>): List<String> {
        val hits = linkedSetOf<String>()
        candidates.forEach { candidate ->
            if (pinnedPackages.any { it.equals(candidate.packageName, ignoreCase = true) }) {
                hits += "derivative build of this app installed: ${candidate.packageName}"
                return@forEach
            }
            val normalized = normalizeFingerprint(candidate.label)
            if (normalized.isEmpty()) return@forEach
            pinnedLabels.forEach { needle ->
                if (normalized.contains(needle)) {
                    hits += "derivative build matched by name: ${candidate.packageName} (${candidate.label})"
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
            val outcome = runCatching { scanOutcome(context) }
                .onFailure { AppLog.w("AppListGuard scan failed: ${it.javaClass.simpleName}: ${it.message}") }
                .getOrNull()
            val threats = if (outcome == null) {
                snapshot
            } else {
                matchThreats(outcome.candidates) + listOfNotNull(
                    suppressedListThreat(outcome.installedListSuppressed, outcome.candidates.size)
                )
            }
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
