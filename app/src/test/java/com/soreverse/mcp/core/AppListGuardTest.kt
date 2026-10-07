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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppListGuardTest {
    private fun candidate(packageName: String, label: String) = AppListGuard.Candidate(packageName, label)

    @Test
    fun pinnedPackageMatchesExactlyAndIgnoresCase() {
        assertEquals(1, AppListGuard.matchThreats(listOf(candidate("com.qingfeng.app", "无关名称"))).size)
        assertEquals(1, AppListGuard.matchThreats(listOf(candidate("METK.HUB", "任意"))).size)
    }

    @Test
    fun hitIsReportedAsADerivativeBuildNotAsASignatureBypassTool() {
        // The pinned identities are repacks of *this* project (see
        // docs/legal/), not third-party tooling that attacks it. The wording
        // reaches the user verbatim through the gate dialog, so mislabelling
        // them accuses an unrelated app of shipping an attack tool.
        val hits = AppListGuard.matchThreats(listOf(candidate("com.qingfeng.app", "清风")))
        assertEquals(1, hits.size)
        assertTrue(hits.single().contains("derivative build"))
        assertFalse(hits.single().contains("signature-bypass"))
    }

    @Test
    fun pinnedPackageIsNotMatchedBySubstring() {
        assertTrue(AppListGuard.matchThreats(listOf(candidate("com.qingfeng.app.hook", "管理器"))).isEmpty())
    }

    @Test
    fun labelMatchIsContainmentSoRenamedRepacksStillHit() {
        val hits = AppListGuard.matchThreats(
            listOf(candidate("com.repacked.tool", "清风工具箱"), candidate("com.repacked.hub", "飘零浅醉Hub 2.1"))
        )
        assertEquals(2, hits.size)
        assertTrue(hits.all { it.contains("matched by name") })
    }

    @Test
    fun labelSeparatorsAndCaseAreNotIdentity() {
        val variants = listOf("飘零浅醉·hub", "飘零浅醉 Hub", "飘零浅醉HUB", "【飘零浅醉·Hub】")
        variants.forEach { label ->
            assertEquals("variant: $label", 1, AppListGuard.matchThreats(listOf(candidate("metk.other", label))).size)
        }
    }

    @Test
    fun unrelatedAppsAndBlankLabelsDoNotHit() {
        val clean = listOf(
            candidate("com.tencent.mm", "微信"),
            candidate("com.android.chrome", "Chrome"),
            candidate("com.blank.label", ""),
            candidate("com.spacey.label", "   ")
        )
        assertTrue(AppListGuard.matchThreats(clean).isEmpty())
    }

    @Test
    fun everyNeedleDecodesNonBlank() {
        // A needle that decoded to "" would make normalized.contains("") true for
        // every installed app and crash-loop the whole user base.
        val decoy = candidate("com.example.unrelated", "AB")
        assertTrue(AppListGuard.matchThreats(listOf(decoy)).isEmpty())
    }

    @Test
    fun oneHitPerMatchingApp() {
        val hits = AppListGuard.matchThreats(listOf(candidate("com.qingfeng.app", "清风")))
        assertEquals(1, hits.size)
    }
}
