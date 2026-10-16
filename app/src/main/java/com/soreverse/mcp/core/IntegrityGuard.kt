/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (C) 2026 bilieebiliee1-design
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 */

package com.soreverse.mcp.core

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.os.Process
import com.soreverse.mcp.nativecore.NativeProbe
import java.io.File
import java.security.MessageDigest
import kotlin.random.Random
import kotlin.system.exitProcess

object IntegrityGuard {
    data class Result(val trusted: Boolean, val reason: String, val expected: String, val actual: List<String>, val threats: List<String> = emptyList())

    @Volatile private var cached: Pair<Long, Result>? = null

    private val scheduleLock = Any()

    /**
     * The one component factory a genuine build of this app can declare:
     * `androidx.core:core` (transitive, via `androidx.activity:activity-compose`)
     * puts it in its own manifest and the merger copies it into the shipped
     * APK. Read as a constant rather than a literal at the comparison site so
     * the allowlist has one definition to audit.
     */
    private const val ANDROIDX_COMPONENT_FACTORY = "androidx.core.app.CoreComponentFactory"

    /**
     * ROM-level DEX-dump switch injected into `dalvik.system.DexFile` by the
     * FART-family platform patch (see [fartDumpThreat]). No stock platform
     * declares it.
     */
    private const val FART_DEXFILE_SWITCH = "setFartDumpEnabled"

    /**
     * Method names the same patch injects into `android.app.ActivityThread`.
     * Every entry carries the family's own "Fart" branding, so the stock
     * ActivityThread dump surface - `handleDumpActivity`, `handleDumpProvider`,
     * `handleDumpService`, `handleDumpHeap`, `handleStopBinderTrackingAndDump`,
     * `dumpMemInfoTable`, `nDumpGraphicsInfo`, all real AOSP methods - can
     * never match.
     */
    private val FART_ACTIVITYTHREAD_MARKERS = listOf(
        "runFartDump",
        "startFartDumpThreadIfNeeded",
        "readFartDumpSwitches",
        "getFartProcessDirectory"
    )

    /**
     * The unpacking ROM's own brand. Its build.prop sets both
     * `ro.product.model` and `ro.vendor.product.model` to
     * `Ark脱壳机(菜鸟八哥QQ2380494437)`, so `Build.MODEL` carries this token
     * verbatim. This is the ROM author's fixed branding rather than an
     * attacker-chosen value, so - unlike [foreignFactoryThreat] - substring
     * matching is the correct rule: a version suffix or a changed QQ number
     * must not turn the check off.
     */
    private const val ARK_ROM_MODEL_TOKEN = "Ark脱壳机"

    @Volatile private var recheckStarted = false

    /** Failure recorded by [enforceEarly]; consumed (fail-closed) by [enforce]. */
    @Volatile private var earlyNativeFailure: String? = null

    /**
     * Startup enforcement failure. Surfaced by the UI gate (MainActivity's
     * IntegrityGate dialog shows it with the triggering check or application
     * named) instead of being killed on here: a kill inside
     * Application.onCreate() runs before any UI exists, so the reason died
     * with the in-memory AppLog and the launcher relaunched into the same
     * silent kill - an undiagnosable reboot loop (observed on a HONOR LSA-AN00
     * device where every start SIGKILLed itself ~1.2 s after launch with the
     * native v3 verification passing). Fail-closed semantics are preserved:
     * [inspect] short-circuits on this value, so the service/boot gates and
     * the UI countdown exit all see an untrusted state until it is cleared.
     */
    @Volatile
    var startupFailure: String? = null
        private set

    /**
     * Runs all checks (Java PackageManager + native filesystem-level probe) and
     * records [startupFailure] if any check fails; the UI gate renders the
     * reason and exits after its countdown. Runtime tampering detected by the
     * periodic recheck still terminates immediately.
     *
     * This is the main entry point for startup enforcement.
     * It should be called once during Application.onCreate().
     *
     * The reason for two layers of checking:
     * - Runtime patching tools replace the package metadata returned through
     *   the Java PackageManager Binder interface, so a Java-level check alone
     *   can be defeated.
     * - The native probe reads the package file directly from the filesystem
     *   and extracts the record embedded in the META-INF PKCS7 entry, a path
     *   that a Binder-level replacement cannot reach.
     * - Together they provide defense in depth: an attacker would have to
     *   intervene in BOTH the Java PackageManager AND the native JNI bridge.
     *
     * Those same tools install their hook inside attachBaseContext(), so the
     * native probe additionally runs from [enforceEarly] at that exact
     * lifecycle point, and is repeated periodically at runtime so a one-shot or
     * timing-based bypass does not survive past startup.
     */
    fun enforce(context: Context) {
        // 0. Consume any failure the attachBaseContext-time gate recorded. It
        //    was deliberately non-fatal there (no crash reporter yet), but it
        //    is authoritative by the time onCreate runs: fail closed.
        val earlyFailure = earlyNativeFailure
        earlyNativeFailure = null

        // 1. Java-level check (readable through the Binder interface)
        val javaResult = inspect(context)
        val javaPass = javaResult.trusted

        // 2. Native-level check (reads the package file directly)
        val nativePass = NativeProbe.matches(context)

        // 2b. Native v2/v3 (Signing Block) identity check. Independently reads
        //     the record stored in the v2/v3 block so a scheme-confusion repack
        //     (preserved v1 entries + re-signed v2/v3) cannot pass the
        //     filesystem-level v1 check.
        val v234Pass = NativeProbe.matchesV234(context)

        // 3. Native package-id pin (rejects repackaged builds that changed
        //    applicationId, even if the Java layer reports a spoofed name).
        val packagePass = NativeProbe.matchesId(context)

        // 4. Native archive probe (ZIP structure + critical entries + dex CRC)
        val probeCode = NativeProbe.probeArchive(context)
        val probePass = probeCode == NativeProbe.ProbeCode.OK

        // 5. Native cryptographic verification of the v2/v3 signature record.
        //    Steps 2/2b only prove that the signing block *names* the pinned
        //    signer: the block is a blob, so editing the file content and
        //    leaving the original signature record (and the digests recorded in
        //    it) in place passes both - it installs wherever the installer's own
        //    signature verification is bypassed. This step verifies the
        //    signature with the pinned signer's key and recomputes the signed
        //    content digest, which rejects exactly that repack.
        val blockCode = NativeProbe.verifyBlock(context)
        val blockPass = !NativeProbe.isTamper(blockCode)

        if (earlyFailure != null ||
            !javaPass ||
            !nativePass ||
            !v234Pass ||
            !packagePass ||
            !probePass ||
            !blockPass
        ) {
            val reasons = mutableListOf<String>()
            if (earlyFailure != null) {
                reasons.add("Early gate (attachBaseContext): $earlyFailure")
            }
            if (!javaPass) reasons.add("Java: ${javaResult.reason}")
            if (!nativePass) {
                reasons.add(
                    "Native: build identity differs from the pinned one"
                )
            }
            if (!v234Pass) {
                reasons.add(
                    "Native: v2/v3 identity record missing or mismatched"
                )
            }
            if (!packagePass) {
                reasons.add("Native: package id does not match the pinned value")
            }
            if (!probePass) {
                reasons.add("Native: archive probe failed (code=0x${probeCode.toString(16)})")
            }
            if (!blockPass) {
                reasons.add(
                    "Native: v2/v3 signature or content digest mismatch " +
                        "(code=0x${blockCode.toString(16)})"
                )
            }
            AppLog.e("INTEGRITY ENFORCEMENT FAILED: ${reasons.joinToString("; ")}")
            // Do NOT kill here. MainActivity is about to launch and its
            // IntegrityGate dialog renders this reason (including which
            // installed application tripped the coexistence gate) before the
            // 10 s countdown exit; killing in onCreate() instead produced a
            // silent relaunch loop with no evidence at all. The native
            // crypto-verified tamper codes never reach this branch (they
            // _exit(173) inside librz_native before returning), so the
            // authoritative hard kill remains untouched.
            startupFailure = reasons.joinToString("; ")
            return
        }

        // 6. Keep re-checking at runtime so later tampering is caught.
        schedulePeriodicRecheck(context.applicationContext ?: context)
    }

    /**
     * Lightweight early gate executed from Application.attachBaseContext().
     * Only the native filesystem-level checks run here (identity digest,
     * package-id pin, archive probe): reading the package file directly
     * bypasses the Binder-level replacement that runtime patching tools install
     * at exactly this lifecycle point.
     *
     * NOTE: this gate is NON-FATAL on failure. At attachBaseContext() the app
     * has neither initialized AppLog nor installed CrashReporter, so a hard
     * kill (Process.killProcess) here produced no diagnosable evidence and
     * reboot-looped the app on any transient or false mismatch - the root cause
     * of the startup-crash issue. We therefore only record the mismatch here;
     * the authoritative kill happens in Application.onCreate() via [enforce],
     * which re-runs the same native checks after AppLog has been initialized
     * and logs the exact reason before terminating. The failure is recorded in
     * [earlyNativeFailure] so [enforce] cannot proceed past it even if the
     * state is somehow transient (fail-closed accumulation).
     */
    fun enforceEarly(context: Context) {
        val failures = mutableListOf<String>()
        if (!NativeProbe.matches(context)) failures += "native identity"
        if (!NativeProbe.matchesV234(context)) failures += "native v2/v3 identity"
        if (!NativeProbe.matchesId(context)) failures += "package id pin"
        val probeCode = NativeProbe.probeArchive(context)
        if (probeCode != NativeProbe.ProbeCode.OK) {
            failures += "archive probe (code=0x${probeCode.toString(16)})"
        }
        if (failures.isNotEmpty()) {
            earlyNativeFailure = failures.joinToString("; ")
            AppLog.w(
                "INTEGRITY (early) $earlyNativeFailure mismatch detected; " +
                    "deferring termination to onCreate (attachBaseContext has no crash reporter)"
            )
        }
    }

    /**
     * Schedules a randomized-interval background re-check. Using random delays
     * makes a deterministic "bypass the startup check, then hook later" plan
     * much harder to time accurately.
     */
    private fun schedulePeriodicRecheck(context: Context) {
        synchronized(scheduleLock) {
            if (recheckStarted) return
            recheckStarted = true
        }
        Thread({
            var delay = 8_000L + Random.nextLong(12_000L)
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(delay)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                // The native probe is the trustworthy one; the Java read cannot
                // be faked but can be intercepted, so it is cross-checked too.
                val nativeOk = NativeProbe.matches(context)
                val javaOk = inspect(context).trusted
                val v234Ok = NativeProbe.matchesV234(context)
                val packageOk = NativeProbe.matchesId(context)
                val probeOk =
                    NativeProbe.probeArchive(context) ==
                        NativeProbe.ProbeCode.OK
                // Signature + content-digest verification is the only check that
                // notices content edited under a preserved signature record, so
                // it runs on every re-check as well.
                val blockOk = !NativeProbe.isTamper(NativeProbe.verifyBlock(context))
                if (!nativeOk || !javaOk || !v234Ok || !packageOk || !probeOk || !blockOk) {
                    AppLog.e("INTEGRITY PERIODIC CHECK FAILED: tampering detected at runtime")
                    terminateWithContext(context)
                    return@Thread
                }
                delay = 45_000L + Random.nextLong(90_000L)
            }
        }).apply {
            isDaemon = true
            name = "soreverse-integrity"
            start()
        }
    }

    fun inspect(context: Context): Result {
        // A recorded startup enforcement failure is authoritative and sticky
        // (fail-closed): every consumer of [inspect] - the UI gate, the MCP
        // service gate, the boot receiver gate - must see the untrusted state
        // until the reason is surfaced and the process exits.
        startupFailure?.let { failure ->
            // `expected` is the pinned digest, never null, but `actual` is: the
            // UI renders "expected" against "actual" and an empty `actual` made
            // a pure environment-threat failure read as an identity mismatch.
            // Read the installed fingerprints here so the gate can show both
            // sides and let the user see which one actually failed.
            val actual = runCatching {
                installFingerprints(context).map { it.normalizeDigest() }
            }.getOrDefault(emptyList())
            return Result(
                false,
                failure,
                NativeProbe.pinnedFingerprint().normalizeDigest(),
                actual
            )
        }
        cached?.let { (time, result) ->
            if (System.currentTimeMillis() - time < 2_000L) return result
        }
        val result = runCatching {
            val expected = NativeProbe.pinnedFingerprint().normalizeDigest()
            val threats = runtimeThreats(context)
            if (expected.isBlank()) {
                Result(
                    threats.isEmpty(),
                    if (threats.isEmpty()) "no pinned identity configured" else "runtime instrumentation detected",
                    expected,
                    emptyList(),
                    threats
                )
            } else {
                val actual = installFingerprints(context).map { it.normalizeDigest() }
                val identityTrusted = actual.any { it == expected }
                val allThreats = if (identityTrusted) {
                    threats
                } else {
                    listOf("application identity mismatch") +
                        threats
                }
                Result(
                    trusted = allThreats.isEmpty(),
                    reason = if (allThreats.isEmpty()) {
                        "pinned identity matched"
                    } else {
                        allThreats.joinToString(
                            "; "
                        )
                    },
                    expected = expected,
                    actual = actual,
                    threats = allThreats
                )
            }
        }.getOrElse {
            Result(
                false,
                it.message ?: it.javaClass.simpleName,
                NativeProbe.pinnedFingerprint().normalizeDigest(),
                emptyList()
            )
        }
        cached = System.currentTimeMillis() to result
        return result
    }

    /**
     * Gate used by the service and boot entry points.
     *
     * [inspect] alone reads the package metadata through PackageManager, which a
     * runtime patching framework can substitute; the native identity checks read
     * the package file itself, so they are required here too. The full
     * cryptographic verification (with its content-digest pass over the whole
     * file) is deliberately not part of this path - it runs at startup and on
     * every periodic re-check.
     */
    fun isTrusted(context: Context): Boolean = inspect(context).trusted &&
        runCatching {
            NativeProbe.matches(context) &&
                NativeProbe.matchesV234(context) &&
                NativeProbe.matchesId(context)
        }.getOrDefault(false)

    /**
     * Terminates the current process immediately. This is a hard kill that
     * bypasses any Java-level exception handlers.
     */
    fun terminateWithContext(context: Context) {
        try {
            if (context is Activity) {
                context.finishAffinity()
            }
        } catch (_: Exception) {
        }
        Process.killProcess(Process.myPid())
        exitProcess(173)
    }

    fun terminate(activity: Activity) {
        runCatching { activity.finishAffinity() }
        exitProcess(173)
    }

    private fun installFingerprints(context: Context): List<String> {
        val info = packageInfo(context)
        val certs = if (Build.VERSION.SDK_INT >= 28) {
            val signingInfo = info.signingInfo ?: return emptyList()
            val signers = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners else signingInfo.signingCertificateHistory
            signers.orEmpty().map { it.toByteArray() }
        } else {
            @Suppress("DEPRECATION")
            info.signatures.orEmpty().map { it.toByteArray() }
        }
        return certs.map { bytes ->
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                "%02X".format(it)
            }
        }
    }

    private fun runtimeThreats(context: Context): List<String> {
        val threats = linkedSetOf<String>()
        if (Debug.isDebuggerConnected() ||
            Debug.waitingForDebugger()
        ) {
            threats += "debugger attached"
        }
        val tracer = tracerPid()
        if (tracer > 0) threats += "native tracer attached"
        creatorIntegrityThreat()?.let { threats += it }
        factoryHijackThreat(context)?.let { threats += it }
        applicationClassThreat(context)?.let { threats += it }
        hookStackThreat()?.let { threats += it }
        fartDumpRuntimeThreat(context)?.let { threats += it }
        arkUnpackRomThreat(Build.MODEL, Build.DISPLAY, Build.FINGERPRINT)?.let { threats += it }
        AppListGuard.threats(context).forEach { threats += it }
        val maps = procMapsIndicators()
        if (maps.isNotEmpty()) threats += maps
        return threats.toList()
    }

    /**
     * Detects a Parcel/Creator substitution of the PackageManager result
     * (SoLab "normal"/"original_apk" signature-bypass templates, DPatch's
     * loader, LSPatch's `PackageInfo.CREATOR` proxy): these frameworks install
     * their own Creator class as [PackageInfo.CREATOR] so every
     * getPackageInfo() response is rewritten with the original signatures
     * during unparceling.
     *
     * The criterion is loader *identity*, not "classLoader is null". The
     * genuine creator is the anonymous class `PackageInfo$1`, and a nested
     * class is always defined by the same loader that defined its outer class,
     * so the only invariant that holds on every ROM is
     * `CREATOR.classLoader === PackageInfo.classLoader`. Testing for null
     * instead reports the genuine build as tampered wherever the framework
     * jars are loaded by a named loader rather than the boot loader (ART
     * modules / APEX since Android 14, and OEM framework layouts), because
     * those also return a non-null loader for a class that was never
     * replaced. A repack's own Creator is necessarily defined by a different,
     * app-visible loader, which this still catches.
     */
    private fun creatorIntegrityThreat(): String? = runCatching {
        val creator = PackageInfo::class.java.getField("CREATOR").get(null)
        when {
            creator == null -> "PackageInfo.CREATOR is null"

            creator.javaClass.classLoader !== PackageInfo::class.java.classLoader ->
                "PackageInfo.CREATOR replaced by a foreign classloader"

            else -> null
        }
    }.getOrNull()

    /**
     * DPatch takes over process startup by rewriting the manifest's
     * appComponentFactory (to com.pandora.core.AppFactory) before the app's
     * own code ever runs, so any value outside the allowlist in
     * [foreignFactoryThreat] means the installed manifest was hijacked.
     *
     * The allowlist is load-bearing, not padding. The app's own manifest
     * declares no factory, but `androidx.core:core` - a transitive dependency
     * of `androidx.activity:activity-compose` - ships one in *its* manifest,
     * and the manifest merger copies it into the shipped APK. Treating "any
     * non-empty value" as hostile therefore flagged every genuine build of
     * this app, not just repacks. Matching stays exact (full class name, or
     * the app's own package prefix); no substring heuristics, since the value
     * is attacker-chosen and a loose match would be trivially satisfied.
     *
     * The release pipeline's VMP step also rewrites appComponentFactory, to the
     * de-branded bootstrap class of the shell it embeds
     * (com.soreverse.mcp.rt.shell.BootstrapComponentFactory). That is covered
     * by the existing own-package-prefix rule rather than by a new exemption:
     * the shell was deliberately given a package under this app's own
     * applicationId so the allowlist admits it on the same terms as any other
     * first-party class, and no DPatch/LSPatch-style foreign loader gains an
     * allowance. See tools/vmp/debrand_shell.py, which pins that name.
     */
    private fun factoryHijackThreat(context: Context): String? = runCatching {
        foreignFactoryThreat(context.applicationInfo?.appComponentFactory, context.packageName)
    }.getOrNull()

    /** Pure decision, split out so the allowlist is unit-testable off-device. */
    internal fun foreignFactoryThreat(factory: String?, ownPackage: String): String? {
        val genuine = factory.isNullOrEmpty() ||
            factory == ANDROIDX_COMPONENT_FACTORY ||
            factory.startsWith("$ownPackage.")
        return if (genuine) null else "foreign appComponentFactory declared (value withheld)"
    }

    /**
     * A proxy Application that subclasses ours (so the manifest entry still
     * reaches our code) is caught by exact-class identity: the object passed
     * to attachBaseContext/onCreate must be precisely [android.app.Application]
     * of the declared class, not a repack's subclass installing hooks first.
     * Only applies while [context] is the Application instance itself; an
     * Activity context carries no information about the Application class.
     *
     * The release pipeline's VMP step rewrites android:name to the shell's
     * bootstrap Application, yet this check still holds: the shell does not
     * stay resident as the Application. In attachBaseContext it reflectively
     * invokes LoadedApk.makeApplication to build the *real* declared class and
     * then re-pins LoadedApk.mApplication / ActivityThread.mInitialApplication
     * / mAllApplications onto that instance, so by the time this runs
     * context.javaClass.name is again SoReverseApplication. The shell is a
     * loader in front of the Application, not a replacement for it, so no
     * relaxation of the exact-class rule is needed or wanted here.
     */
    private fun applicationClassThreat(context: Context): String? {
        if (context !is android.app.Application) return null
        val expected = "com.soreverse.mcp.SoReverseApplication"
        return if (context.javaClass.name != expected) {
            "application instance class is not the declared one"
        } else {
            null
        }
    }

    /**
     * In-process Xposed-family injection detection. A DEX dump tool reaches
     * this app by loading its module code into our own process (classic
     * Xposed / libxposed module loaders), after which it can walk the
     * runtime's DexFile cookies and write our DEX out of memory. Module code
     * only ever executes on our threads when we are actually hooked, so
     * sampling every live thread's stack for foreign hook packages is direct
     * evidence of an injection - independent of how the module's dex was
     * mapped into memory (an anonymous InMemoryDexClassLoader leaves no file
     * path for the maps probe to see).
     *
     * Prefixes, not substrings: each entry is the package prefix of a known
     * in-process hook API surface, so ordinary application frames can never
     * match. The reported threat names only the matched prefix family, never
     * an attacker-chosen class name.
     */
    internal fun hookFrameThreat(frameClassNames: List<String>): String? {
        val prefixes = listOf(
            "de.robv.android.xposed.",
            "io.github.libxposed."
        )
        val hit = prefixes.firstOrNull { prefix ->
            frameClassNames.any { it.startsWith(prefix) }
        } ?: return null
        return "in-process hook frames from $hit"
    }

    private fun hookStackThreat(): String? = runCatching {
        val frames = Thread.getAllStackTraces().values
            .flatMap { stack -> stack.map { it.className } }
        hookFrameThreat(frames)
    }.getOrNull()

    /**
     * ROM-level ART/DEX dumping detection (FART family).
     *
     * The injection vector here is not a hook into our process: the platform
     * itself is patched. The instance analysed for this check is
     * ArkOS-angler-8.1, an AOSP 8.1 ROM for the Nexus 6P whose
     * `ro.product.model` is literally `Ark脱壳机(菜鸟八哥QQ2380494437)`. It
     * ships three patched platform pieces, all confirmed by static analysis of
     * the ROM's `system.img`:
     *
     *  - `lib64/libart.so` gains an `ArkDumpControl` component and exports
     *    `art::IsFartDumpEnabled` / `art::SetFartDumpEnabled` /
     *    `art::DumpFartDexFileDirect`, writing `<root>/<进程名>/classes.dex`
     *    and `classes%zu.dex` under `/sdcard/Ark脱壳机/`.
     *  - `android.app.ActivityThread` gains the whole Java pipeline:
     *    `readFartDumpSwitches`, `startFartDumpThreadIfNeeded`, `runFartDump`,
     *    `dumpDexClasses`, `dumpDexFromClassLoader`, `dumpSingleDexFile`,
     *    `isDumpDexFilesEnabled`, `writeFartApkAndManifest`, ...
     *  - `dalvik.system.DexFile` gains `public static native void
     *    setFartDumpEnabled(boolean)` as the switch the Java side flips.
     *
     * All three live on the boot classpath, so the patch is observable from
     * inside our own process with no permission, no hook and no file access:
     * a stock platform declares none of these members. Because the dumper
     * lives in the runtime that owns our DEX, no in-app countermeasure can
     * stop the dump itself - refusing to run is the only honest response, and
     * that is what reporting a threat here achieves (the gate fails closed).
     *
     * Split into a pure function over the two method-name lists so the rule is
     * pinnable off-device; the caller supplies only what reflection saw.
     */
    internal fun fartDumpThreat(dexFileMethods: List<String>, activityThreadMethods: List<String>): String? {
        if (FART_DEXFILE_SWITCH in dexFileMethods) {
            return "ART runtime carries the FART/Ark DEX-dump switch"
        }
        if (activityThreadMethods.any { it in FART_ACTIVITYTHREAD_MARKERS }) {
            return "framework carries the FART/Ark DEX-dump pipeline"
        }
        return null
    }

    /**
     * Identity check for the same ROM, independent of the framework patch. On
     * its own this is weaker than [fartDumpThreat] - a build.prop is editable
     * by anyone who can reflash - but it costs three string compares and still
     * fires if the dump classes are renamed. `Build.MODEL` is the load-bearing
     * field; DISPLAY and FINGERPRINT are passed too so a rebranded variant
     * that only moves the string does not silently turn the check off.
     */
    internal fun arkUnpackRomThreat(vararg identityFields: String?): String? =
        if (identityFields.any { field -> field != null && field.contains(ARK_ROM_MODEL_TOKEN) }) {
            "Ark unpacking ROM identity ($ARK_ROM_MODEL_TOKEN)"
        } else {
            null
        }

    private fun fartDumpRuntimeThreat(context: Context): String? = fartDumpThreat(
        declaredMethodNames("dalvik.system.DexFile", context.classLoader),
        declaredMethodNames("android.app.ActivityThread", context.classLoader)
    )

    /**
     * Every method name [className] declares, or an empty list when the class
     * does not resolve. `initialize = false` on purpose: only the declared
     * surface is evidence, never the class's static initialisation.
     */
    private fun declaredMethodNames(className: String, loader: ClassLoader?): List<String> = runCatching {
        Class.forName(className, false, loader).declaredMethods.map { it.name }
    }.getOrDefault(emptyList())

    private fun tracerPid(): Int = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')
                ?.trim()
                ?.toIntOrNull() ?: 0
        }
    }.getOrDefault(0)

    private fun procMapsIndicators(): List<String> = runCatching {
        val needles =
            listOf(
                "gum-js-loop",
                "edxp",
                "zygisk",
                "substrate",
                // Non-root runtime-patching / injection frameworks we defend against:
                "apptweak",
                "guobao",
                "tweakme",
                marked("7369676e61747572656b696c6c"),
                "yc/pm",
                marked("7369676e617475726566616b6572"),
                // DPatch payload + the inline/JNI hook engines it embeds, and
                // the SoLab signature-bypass native helper:
                "pandora",
                "dobby",
                "lsplant",
                marked("736f6c61625f7369676e6174757265"),
                // Classic Xposed API package (de.robv.android.xposed): hex-
                // encoded so the plain text stays out of the literal pool.
                marked("64652e726f6276")
            )
        val hits = linkedSetOf<String>()
        File("/proc/self/maps").useLines { lines ->
            lines.take(8_000).forEach { line ->
                val lower = line.lowercase()
                needles.firstOrNull { lower.contains(it) }?.let {
                    hits +=
                        "runtime hook artifact: $it"
                }
            }
        }
        hits.toList()
    }.getOrDefault(emptyList())

    /**
     * Decodes a hex-encoded marker at runtime. Keeping these markers out of the
     * literal pool avoids leaving their plain text in the compiled artifacts.
     */
    private fun marked(hex: String): String = hex.chunked(2).map { it.toInt(16).toChar() }.joinToString("")

    private fun packageInfo(context: Context): PackageInfo {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        }
    }

    private fun String.normalizeDigest(): String = normalizeFingerprint(this)
}

internal fun normalizeFingerprint(value: String): String = value.filter {
    it.isLetterOrDigit()
}.uppercase()
