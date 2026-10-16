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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pins the two false positives that made a correctly signed build report
 * "应用完整性校验失败" on a stock device: the androidx-merged component factory
 * and the non-null-but-genuine framework classloader behind
 * [android.content.pm.PackageInfo.CREATOR].
 */
class IntegrityGuardThreatTest {
    private val own = "com.soreverse.mcp"

    @Test
    fun androidxMergedFactoryIsNotAThreat() {
        // androidx.core:core declares this in its own manifest and the merger
        // copies it in, so every genuine build of this app carries it.
        assertNull(IntegrityGuard.foreignFactoryThreat("androidx.core.app.CoreComponentFactory", own))
    }

    @Test
    fun absentOrEmptyFactoryIsNotAThreat() {
        assertNull(IntegrityGuard.foreignFactoryThreat(null, own))
        assertNull(IntegrityGuard.foreignFactoryThreat("", own))
    }

    @Test
    fun ownPackageFactoryIsNotAThreat() {
        assertNull(IntegrityGuard.foreignFactoryThreat("$own.MyComponentFactory", own))
    }

    @Test
    fun repackFactoryIsAThreat() {
        // DPatch's hijack target.
        assertNotNull(IntegrityGuard.foreignFactoryThreat("com.pandora.core.AppFactory", own))
        // LSPatch's hijack target.
        assertNotNull(
            IntegrityGuard.foreignFactoryThreat("org.lsposed.lspatch.loader.LSPatchLoader", own)
        )
    }

    @Test
    fun allowlistMatchIsExactNotSubstring() {
        // A near-miss must not be waved through: the value is attacker-chosen,
        // so prefix-of-a-lookalike would be a trivial bypass.
        assertNotNull(IntegrityGuard.foreignFactoryThreat("androidx.core.app.CoreComponentFactoryX", own))
        assertNotNull(IntegrityGuard.foreignFactoryThreat("evil.androidx.core.app.CoreComponentFactory", own))
        // A different app's package prefix is not ours.
        assertNotNull(IntegrityGuard.foreignFactoryThreat("com.soreverse.mcp.evil.Factory", "com.soreverse.other"))
    }

    @Test
    fun threatDescriptionWithholdsTheOffendingValue() {
        val threat = IntegrityGuard.foreignFactoryThreat("com.pandora.core.AppFactory", own)
        assertEquals(
            "the reported threat must not echo the attacker's class name",
            false,
            threat!!.contains("pandora")
        )
    }

    /**
     * The release pipeline's VMP step embeds a shell that rewrites
     * appComponentFactory to its own bootstrap class. It is admitted by the
     * existing own-package-prefix rule, not by a bespoke exemption, because
     * tools/vmp/debrand_shell.py deliberately places the shell under this
     * app's own applicationId. This pins both halves of that contract: the
     * shell's real name passes, and the upstream project's original names —
     * which the same script renames away — would still be rejected. If someone
     * repoints the shell at a foreign package, or an attacker ships the
     * upstream name, this fails instead of the app silently dying at startup.
     */
    @Test
    fun vmpShellFactoryIsAdmittedByOwnPackagePrefix() {
        assertNull(
            IntegrityGuard.foreignFactoryThreat(
                "com.soreverse.mcp.rt.shell.BootstrapComponentFactory",
                own
            )
        )
        // The pre-rename upstream identity is not under our package and must
        // not be waved through by this pipeline's existence.
        assertNotNull(
            IntegrityGuard.foreignFactoryThreat(
                "com.yqsh.protector.shell.ProxyComponentFactory",
                own
            )
        )
    }

    /**
     * The DEX-dump vector (any classic Xposed / libxposed module) runs module
     * code on OUR threads. Frames from those packages are therefore direct
     * in-process injection evidence; each known hook API surface must be
     * caught by its package prefix.
     */
    @Test
    fun moduleHookFramesAreAThreat() {
        // Classic Xposed callback bridge firing inside our process, sandwiched
        // between ordinary application frames.
        assertNotNull(
            IntegrityGuard.hookFrameThreat(
                listOf(
                    "android.app.ActivityThread",
                    "de.robv.android.xposed.XposedBridge",
                    "com.soreverse.mcp.MainActivity"
                )
            )
        )
        // libxposed API module code running in-process.
        assertNotNull(
            IntegrityGuard.hookFrameThreat(listOf("io.github.libxposed.api.XposedModule"))
        )
    }

    @Test
    fun ordinaryApplicationFramesAreNotHookThreats() {
        assertNull(
            IntegrityGuard.hookFrameThreat(
                listOf(
                    "com.soreverse.mcp.core.IntegrityGuard",
                    "androidx.core.app.CoreComponentFactory",
                    "android.app.Application",
                    "kotlin.concurrent.ThreadKt"
                )
            )
        )
        assertNull(IntegrityGuard.hookFrameThreat(emptyList()))
    }

    /**
     * A lookalike package that merely contains a needle as a substring (no
     * package-prefix boundary) must not trip the hook-frame check, mirroring
     * the exact-match discipline of the factory allowlist above.
     */
    @Test
    fun hookFrameMatchRequiresPackagePrefixBoundary() {
        assertNull(
            IntegrityGuard.hookFrameThreat(
                listOf("com.soreverse.mcp.de.robv.android.xposed.Fake")
            )
        )
        // But the genuine package followed by any class still matches.
        assertNotNull(
            IntegrityGuard.hookFrameThreat(listOf("de.robv.android.xposed.XC_MethodHook"))
        )
    }

    /**
     * The ROM-level dumper (ArkOS-angler-8.1) patches the platform, not us:
     * `dalvik.system.DexFile` gains the switch, `android.app.ActivityThread`
     * gains the pipeline. Either half alone is decisive, because a stock
     * platform declares neither.
     */
    @Test
    fun fartDumpSwitchOnDexFileIsAThreat() {
        assertNotNull(
            IntegrityGuard.fartDumpThreat(
                listOf("openDexFileNative", "setFartDumpEnabled", "isDexOptNeeded"),
                emptyList()
            )
        )
    }

    @Test
    fun fartDumpPipelineOnActivityThreadIsAThreat() {
        assertNotNull(
            IntegrityGuard.fartDumpThreat(
                emptyList(),
                listOf("currentActivityThread", "runFartDump", "performLaunchActivity")
            )
        )
    }

    /**
     * The stock ActivityThread does have a dump surface - it backs `am dump`.
     * None of those names may be mistaken for the injected pipeline, and an
     * empty method list (reflection could not resolve the class) is not
     * evidence of anything, so it must stay silent rather than fail closed on
     * a lookup failure.
     */
    @Test
    fun stockDumpSurfaceAndEmptyEvidenceAreNotThreats() {
        assertNull(
            IntegrityGuard.fartDumpThreat(
                listOf(
                    "openDexFileNative",
                    "loadDex",
                    "openInMemoryDexFile",
                    "getDexFileOutputPaths",
                    "isDexOptNeeded",
                    "dumpDexFile"
                ),
                listOf(
                    "currentActivityThread",
                    "handleDumpActivity",
                    "handleDumpProvider",
                    "handleDumpService",
                    "handleDumpHeap",
                    "handleStopBinderTrackingAndDump",
                    "dumpMemInfoTable",
                    "nDumpGraphicsInfo",
                    "performLaunchActivity"
                )
            )
        )
        assertNull(IntegrityGuard.fartDumpThreat(emptyList(), emptyList()))
    }

    /**
     * Matching is by exact member name, not prefix: the injected names are
     * fixed identifiers, so a near-miss (a hypothetical future
     * `runFartDumpNow`, or a `setFartDumpEnabledX`) must not be reported as
     * the thing that was verified.
     */
    @Test
    fun fartDumpMatchIsExactNotPrefix() {
        assertNull(
            IntegrityGuard.fartDumpThreat(
                listOf("setFartDumpEnabledX", "xsetFartDumpEnabled"),
                listOf("runFartDumpNow", "notRunFartDump")
            )
        )
    }

    /**
     * `Build.MODEL` on the analysed ROM is
     * `Ark脱壳机(菜鸟八哥QQ2380494437)`; a version suffix or a changed QQ
     * number must not turn the identity check off.
     */
    @Test
    fun arkUnpackRomIdentityIsAThreat() {
        assertNotNull(IntegrityGuard.arkUnpackRomThreat("Ark脱壳机(菜鸟八哥QQ2380494437)"))
        assertNotNull(
            IntegrityGuard.arkUnpackRomThreat(
                "aosp_angler",
                "aosp_angler-userdebug 8.1.0 OPM8.190105.002 Ark脱壳机 v2 test-keys"
            )
        )
    }

    @Test
    fun ordinaryDeviceIdentityIsNotAThreat() {
        assertNull(
            IntegrityGuard.arkUnpackRomThreat(
                "Pixel 7",
                "aosp_angler-userdebug 8.1.0 OPM8.190105.002 eng.ubuntu.20260705.125925 test-keys",
                "Android/aosp_angler/angler:8.1.0/OPM8.190105.002/ubuntu07051259:userdebug/test-keys"
            )
        )
        assertNull(IntegrityGuard.arkUnpackRomThreat(null, null, null))
    }
}
