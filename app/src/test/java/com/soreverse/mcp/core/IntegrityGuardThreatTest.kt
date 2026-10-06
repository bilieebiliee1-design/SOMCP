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
}
