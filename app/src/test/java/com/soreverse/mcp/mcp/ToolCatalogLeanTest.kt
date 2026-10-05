// SPDX-License-Identifier: AGPL-3.0-only
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
// Guards for the lean tool list. The load-bearing case is gateway visibility:
// lean mode is on by default, and a gateway classified EXTRA with a niche
// category can only enter the list through popularity promotion — which needs a
// prior successful call. That made `agent_api`, the only door to sub-agents,
// unreachable for a client that had never spawned one.
package com.soreverse.mcp.mcp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ToolCatalogLeanTest {
    @Test
    fun everyGatewayIsAdvertisedByDefault() {
        val lean = ToolCatalog.leanNames().toSet()
        val gateways = ToolCatalog.ALL.filter {
            it.meta.category == "lowlevel" || it.meta.category == "agent"
        }
        assertTrue("there must be gateways to check", gateways.isNotEmpty())
        gateways.forEach {
            assertTrue(
                "gateway ${it.meta.name} (${it.meta.category}) is hidden from the default lean list",
                it.meta.name in lean
            )
        }
    }

    @Test
    fun theSubAgentGatewayIsReachableWithoutPriorPopularity() {
        // The regression itself: no popularity map, no promotion slots, and the
        // tool is still advertised.
        assertTrue("agent_api must be in the default lean list", "agent_api" in ToolCatalog.leanNames())
        assertTrue(
            "agent_api must survive even with promotion switched off",
            "agent_api" in ToolCatalog.registry.leanNames(popularity = null, promotionSlots = 0)
        )
    }

    @Test
    fun nonGatewayExtrasStillNeedPromotion() {
        // The fix must not turn lean mode into "advertise everything": an EXTRA
        // tool outside a gateway category stays out until the client uses it.
        val exotic = ToolCatalog.ALL.filter {
            it.meta.cls == ToolClass.EXTRA &&
                it.meta.category != "lowlevel" &&
                it.meta.category != "agent"
        }
        assertTrue("there must be non-gateway extras", exotic.isNotEmpty())
        val lean = ToolCatalog.leanNames().toSet()
        exotic.forEach {
            assertFalse("${it.meta.name} should need promotion", it.meta.name in lean)
        }
    }

    @Test
    fun popularityPromotesNonGatewayExtrasOnly() {
        val target = ToolCatalog.ALL.first {
            it.meta.cls == ToolClass.EXTRA &&
                it.meta.category != "lowlevel" &&
                it.meta.category != "agent"
        }
        val lean = ToolCatalog.leanNames(popularity = mapOf(target.meta.name to 7L))
        assertTrue("a used extra should be promoted", target.meta.name in lean)
        // Promotion must not duplicate an already-present gateway.
        val count = lean.count { it == "agent_api" }
        assertTrue("agent_api listed $count times", count == 1)
    }

    @Test
    fun fullCatalogIsUnaffectedByTheGatewayRule() {
        assertTrue(ToolCatalog.names.contains("agent_api"))
        assertTrue("catalog shrank", ToolCatalog.names.size >= 46)
    }
}
