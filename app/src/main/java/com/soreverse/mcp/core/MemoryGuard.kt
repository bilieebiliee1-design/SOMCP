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

/**
 * Thrown when an analysis cannot start because the process heap does not have
 * enough headroom to safely hold the input file and its parse copies. Mapped by
 * [com.soreverse.mcp.engine.EngineRuntime.guarded] to the `INSUFFICIENT_MEMORY`
 * MCP error so callers see a clear message instead of an `OutOfMemoryError`.
 */
class InsufficientMemoryException(message: String) : IllegalStateException(message)

/**
 * Heap-aware gate that stops a memory-hungry analysis before it begins when the
 * process cannot safely accommodate the target file. SOMCP loads a whole ELF/APK
 * into a `ByteArray` and then keeps several parse copies (LIEF native parse,
 * xanso section recovery, rizin buffers), so a large library on a constrained
 * device can otherwise crash the app with an `OutOfMemoryError`.
 *
 * Used at the entry points that read a full file into memory:
 *  - [com.soreverse.mcp.engine.EngineRuntime.openWorkspace] (so_open / UI open /
 *    AI deep-analysis tools),
 *  - [com.soreverse.mcp.engine.EngineRuntime.analyzeApk] (apk_analyze),
 *  - the scan-time metadata fallback that parses a whole SO,
 *  - the Flutter (Blutter) inspect/analyze paths.
 */
object MemoryGuard {

    /** Transient copies a full ELF/APK parse typically needs (input + LIEF + rizin/recovery). */
    const val DEFAULT_MULTIPLICITY = 3

    /** Extra headroom (MiB) kept free so the app stays responsive after the parse. */
    const val DEFAULT_RESERVE_MIB = 48L

    /** Absolute floor (MiB): refuse when less than this much heap is left at all. */
    const val MIN_HEADROOM_MIB = 16L

    private const val MIB = 1024L * 1024L

    /** Heap (MiB) the process can still allocate before an OutOfMemoryError. */
    fun heapHeadroomMiB(): Long {
        val runtime = Runtime.getRuntime()
        val headroom = runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
        return (headroom.coerceAtLeast(0L)) / MIB
    }

    /**
     * Refuse to start an analysis that needs to hold [requiredBytes] of input in
     * memory. [what] names the operation for the error message. Throws
     * [InsufficientMemoryException] when the estimated requirement (input times
     * [DEFAULT_MULTIPLICITY] plus [DEFAULT_RESERVE_MIB]) exceeds the available heap
     * headroom, or when the process is already below [MIN_HEADROOM_MIB].
     */
    fun ensureAnalysisMemory(requiredBytes: Long, what: String) {
        val requirementMiB = (requiredBytes.coerceAtLeast(0L) * DEFAULT_MULTIPLICITY) / MIB
        val headroomMiB = heapHeadroomMiB()
        if (headroomMiB < MIN_HEADROOM_MIB || headroomMiB < requirementMiB + DEFAULT_RESERVE_MIB) {
            val runtime = Runtime.getRuntime()
            val maxMiB = runtime.maxMemory() / MIB
            val usedMiB = (runtime.totalMemory() - runtime.freeMemory()) / MIB
            throw InsufficientMemoryException(
                "$what needs about $requirementMiB MiB of heap headroom, but only ~$headroomMiB MiB is " +
                    "available (heap max ~$maxMiB MiB, used ~$usedMiB MiB). Close other opened SO workspaces " +
                    "or stop emulation, then retry — or analyze a smaller file."
            )
        }
    }
}
