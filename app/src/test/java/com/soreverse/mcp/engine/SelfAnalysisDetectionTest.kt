/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * SOMCP - SO Reverse Engineering MCP
 * Copyright (C) 2026 SoReverse MCP contributors
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, version 3. This program is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details. You should have received a copy of
 * the GNU General Public License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */
package com.soreverse.mcp.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelfAnalysisDetectionTest {
    @Test
    fun detectsOwnPackageMarkerAscii() {
        val bytes = "random lib \u0000 com.soreverse.mcp \u0000 stuff".toByteArray()
        assertTrue(containsPackageIdentifier(bytes))
    }

    @Test
    fun detectsOwnPackageMarkerUtf16le() {
        val bytes = "com.soreverse.mcp".toByteArray(Charsets.UTF_16LE)
        assertTrue(containsPackageIdentifier(bytes))
    }

    @Test
    fun doesNotFlagUnrelatedBytes() {
        val bytes = "com.example.other mcp soreverse.lib".toByteArray()
        assertFalse(containsPackageIdentifier(bytes))
    }

    @Test
    fun emptyBytesAreNotSelf() {
        assertFalse(containsPackageIdentifier(ByteArray(0)))
    }
}
