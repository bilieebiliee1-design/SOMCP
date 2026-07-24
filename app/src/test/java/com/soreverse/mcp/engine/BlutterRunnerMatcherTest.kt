package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BlutterRunnerMatcherTest {
    private val exactEngine = BlutterRunnerDescriptor("engine", "3.4.2", "engine-a", "arm64-v8a", true, true, "a".repeat(64), "embedded", "blutter_engine", "commit")
    private val exactDart = BlutterRunnerDescriptor("dart", "3.4.2", "engine-b", "arm64-v8a", true, true, "b".repeat(64), "embedded", "blutter_dart", "commit")

    @Test
    fun prefersExactEngineRevision() {
        val selected = BlutterRunnerMatcher.select(BlutterRunnerRequirement("engine-a", "3.4.2", "arm64-v8a", true, true), listOf(exactDart, exactEngine))

        assertEquals("engine", selected?.runnerId)
    }

    @Test
    fun fallsBackToExactDartVersion() {
        val selected = BlutterRunnerMatcher.select(BlutterRunnerRequirement("unknown", "3.4.2", "arm64-v8a", true, true), listOf(exactDart))

        assertEquals("dart", selected?.runnerId)
    }

    @Test
    fun rejectsAbiPointerAndAnalysisMismatches() {
        val runners = listOf(
            exactDart.copy(abi = "x86_64"),
            exactDart.copy(compressedPointers = false),
            exactDart.copy(analysis = false),
        )

        assertNull(BlutterRunnerMatcher.select(BlutterRunnerRequirement(null, "3.4.2", "arm64-v8a", true, true), runners))
    }
}
