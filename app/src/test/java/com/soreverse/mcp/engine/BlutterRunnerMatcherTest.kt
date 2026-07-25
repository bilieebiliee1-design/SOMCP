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

    @Test
    fun matchesByEngineRevisionListWhenSingleFieldDiffers() {
        val listRunner = BlutterRunnerDescriptor(
            runnerId = "list", dartVersion = "1.0.0", engineRevision = "eng-main", abi = "arm64-v8a",
            compressedPointers = true, analysis = true, sha256 = "d".repeat(64), source = "embedded",
            libraryName = "blutter_list", upstreamCommit = "commit", engineRevisions = listOf("eng-a", "eng-b", "eng-c"),
        )
        // requirement.engineRevision is NOT the runner's single field, but IS in runner.engineRevisions.
        val selected = BlutterRunnerMatcher.select(BlutterRunnerRequirement("eng-b", "1.0.0", "arm64-v8a", true, true), listOf(listRunner))
        assertEquals("list", selected?.runnerId)
    }

    @Test
    fun matchesBySnapshotAliasWithoutExactVersion() {
        val aliasRunner = BlutterRunnerDescriptor(
            runnerId = "alias", dartVersion = "9.9.9", engineRevision = "eng-x", abi = "arm64-v8a",
            compressedPointers = true, analysis = true, sha256 = "c".repeat(64), source = "embedded",
            libraryName = "blutter_alias", upstreamCommit = "commit", snapshotAliases = listOf("deadbeef"),
            snapshotHash = "deadbeef",
        )
        val match = BlutterRunnerMatcher.match(BlutterRunnerRequirement(null, "1.2.3", "arm64-v8a", true, true, emptyList(), "deadbeef"), listOf(aliasRunner))
        assertEquals("alias", match?.descriptor?.runnerId)
        assertEquals(RunnerCompatibility.SNAPSHOT_ALIAS, match?.compatibility)
    }

    @Test
    fun noApproximateMatchWhenDisallowed() {
        val approxRunner = BlutterRunnerDescriptor(
            runnerId = "approx", dartVersion = "1.0.0", engineRevision = "eng-z", abi = "arm64-v8a",
            compressedPointers = true, analysis = true, sha256 = "e".repeat(64), source = "embedded",
            libraryName = "blutter_approx", upstreamCommit = "commit",
        )
        val requirement = BlutterRunnerRequirement("other", "2.0.0", "arm64-v8a", true, true)
        assertNull(BlutterRunnerMatcher.match(requirement, listOf(approxRunner), allowApproximate = false))
        val approximate = BlutterRunnerMatcher.match(requirement, listOf(approxRunner), allowApproximate = true)
        assertEquals(RunnerCompatibility.APPROXIMATE, approximate?.compatibility)
        assertEquals("approx", approximate?.descriptor?.runnerId)
    }
}
