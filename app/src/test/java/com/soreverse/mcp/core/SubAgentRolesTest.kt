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
// Pure-JVM guards for the sub-agent gates. The whitelist assertions are the
// load-bearing ones: they are what lets agent_api advertise "no write path"
// without asking a reader to trust the role definitions by eye.
package com.soreverse.mcp.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubAgentRolesTest {
    @Test
    fun roleIdsAreUniqueAndNonBlank() {
        val ids = SubAgentRoles.ALL.map { it.id }
        assertTrue(ids.all { it.isNotBlank() })
        assertEquals(ids.size, ids.distinct().size)
        assertEquals(ids, SubAgentRoles.IDS)
    }

    @Test
    fun everyRoleHasADistinctFocusedWhitelist() {
        SubAgentRoles.ALL.forEach { role ->
            assertTrue("${role.id} needs tools", role.toolNames.size >= 3)
            assertEquals("${role.id} has duplicate tools", role.toolNames.size, role.toolNames.distinct().size)
            assertTrue("${role.id} needs a zh goal", role.goalZh.isNotBlank())
            assertTrue("${role.id} needs an en goal", role.goalEn.isNotBlank())
            assertTrue("${role.id} iteration suggestion is sane", role.suggestedIterations in 2..40)
        }
    }

    @Test
    fun noRoleIsHandedAWriteOrControlTool() {
        val forbidden = setOf(
            "edit_hex",
            "edit_asm",
            "edit_symbol",
            "edit_fix_sections",
            "build_so",
            "session_open",
            "session_history",
            "session_audit",
            "app_config",
            "system_control",
            "spawn_subagent"
        )
        SubAgentRoles.ALL.forEach { role ->
            assertTrue(
                "${role.id} must stay read-only, got ${role.toolNames.intersect(forbidden)}",
                role.toolNames.intersect(forbidden).isEmpty()
            )
        }
    }

    @Test
    fun resolvesByExactIdIgnoringCaseAndPadding() {
        assertEquals(SubAgentRoles.XREF_TRACER, SubAgentRoles.byId("xref_tracer"))
        assertEquals(SubAgentRoles.CRYPTO_LOCATOR, SubAgentRoles.byId("  Crypto_Locator  "))
        assertNull(SubAgentRoles.byId("make_me_a_sandwich"))
        assertNull(SubAgentRoles.byId(""))
    }

    @Test
    fun rootDepthAndCeilingsGateNesting() {
        // Root agent spawns children at depth 1: default ceiling of 1 stops there.
        assertTrue(SubAgentPolicy.spawnAllowed(childDepth = 1, maxDepth = 1))
        assertFalse(SubAgentPolicy.spawnAllowed(childDepth = 2, maxDepth = 1))
        assertTrue(SubAgentPolicy.spawnAllowed(childDepth = 2, maxDepth = 2))
        assertFalse(SubAgentPolicy.spawnAllowed(childDepth = 3, maxDepth = 2))
    }

    @Test
    fun roleSuggestionIsClampedByUserCeiling() {
        val role = SubAgentRoles.PACKER_PROFILER // suggests 10
        assertEquals(10, SubAgentPolicy.iterationsFor(role, ceiling = 40))
        assertEquals(4, SubAgentPolicy.iterationsFor(role, ceiling = 4))
        assertEquals(2, SubAgentPolicy.iterationsFor(role, ceiling = 0))
        // A generous ceiling still can't out-run the role's own suggestion.
        assertEquals(12, SubAgentPolicy.iterationsFor(SubAgentRoles.GENERALIST, ceiling = 999))
    }
}

class SubAgentBudgetTest {
    @Test
    fun grantsExactlyMaxRunsSpawns() {
        val budget = SubAgentBudget(3)
        assertEquals(3, budget.remaining())
        assertTrue(budget.tryConsume())
        assertTrue(budget.tryConsume())
        assertTrue(budget.tryConsume())
        assertFalse("quota must stop at 3", budget.tryConsume())
        assertEquals(0, budget.remaining())
        assertEquals(3, budget.consumedCount())
    }

    @Test
    fun zeroQuotaNeverGrants() {
        val budget = SubAgentBudget(0)
        assertFalse(budget.tryConsume())
        assertEquals(0, budget.remaining())
    }

    @Test
    fun concurrentConsumersNeverExceedQuota() {
        val budget = SubAgentBudget(8)
        val threads = (1..32).map {
            Thread { if (budget.tryConsume()) Thread.sleep(1) }.apply { start() }
        }
        threads.forEach { it.join() }
        assertEquals("CAS must not oversubscribe", 8, budget.consumedCount())
        assertEquals(0, budget.remaining())
    }
}
