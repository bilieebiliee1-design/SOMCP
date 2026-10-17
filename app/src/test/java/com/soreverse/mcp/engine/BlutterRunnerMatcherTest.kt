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
package com.soreverse.mcp.engine

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The manifest declares four compatibility keys per runner (snapshot hash, engine
 * revision, Dart version, pointer mode) but only two of them were ever consulted.
 * These tests pin the ranking and, crucially, the case the old matcher rejected
 * outright: Flutter 3.44.1 shares the 3.44.2–3.44.7 snapshot hash but ships Dart
 * 3.12.1 and an engine revision the runner entry does not list.
 */
class BlutterRunnerMatcherTest {
    private val snapshotHash = "ace654289f5abc240509fc941453ebc5"
    private val primaryEngine = "77e2e94772b6eb43759e34ed1ad7da4674e19cab"
    private val secondaryEngine = "a4ce257c68517c1410f4b48ac9852ab5642a3f8d"
    private val unlistedEngine = "c416acfeb8126e097f758c664aaa3da929e27da0"

    @Test
    fun matchesWhenOnlyTheSnapshotHashAgrees() {
        val runner = runner(aliases = listOf(snapshotHash))

        val selected = BlutterRunnerMatcher.select(
            requirement(dartVersion = "3.12.1", engineRevision = unlistedEngine, snapshotHash = snapshotHash),
            listOf(runner)
        )

        assertEquals(runner.runnerId, selected?.runnerId)
    }

    @Test
    fun matchesAnEngineRevisionFromTheManifestList() {
        val runner = runner(engineRevisions = listOf(primaryEngine, secondaryEngine))

        val selected = BlutterRunnerMatcher.select(
            requirement(dartVersion = null, engineRevision = secondaryEngine, snapshotHash = null),
            listOf(runner)
        )

        assertEquals(runner.runnerId, selected?.runnerId)
    }

    @Test
    fun coverageTableContributesSnapshotHashes() {
        val manifest = manifest(runners = JSONArray().put(runnerJson(aliases = emptyList())))
        val descriptors = BlutterRunnerManifest.runners(manifest, "embedded")

        assertEquals(setOf(snapshotHash), descriptors.single().snapshotHashes)
        assertNotNull(
            BlutterRunnerMatcher.select(
                requirement(dartVersion = "3.12.1", engineRevision = unlistedEngine, snapshotHash = snapshotHash),
                descriptors
            )
        )
    }

    @Test
    fun unknownFingerprintIsRejected() {
        val runner = runner(aliases = listOf(snapshotHash))

        assertNull(
            BlutterRunnerMatcher.select(
                requirement(dartVersion = "2.19.0", engineRevision = "ffff", snapshotHash = "deadbeef"),
                listOf(runner)
            )
        )
    }

    @Test
    fun compressedPointerMismatchIsRejected() {
        val runner = runner(aliases = listOf(snapshotHash))

        assertNull(
            BlutterRunnerMatcher.select(
                requirement(dartVersion = "3.12.2", compressedPointers = false),
                listOf(runner)
            )
        )
    }

    @Test
    fun analysisRequirementRejectsANonAnalysisRunner() {
        val runner = runner(aliases = listOf(snapshotHash), analysis = false)

        assertNull(BlutterRunnerMatcher.select(requirement(analysis = true), listOf(runner)))
        assertNotNull(BlutterRunnerMatcher.select(requirement(analysis = false), listOf(runner)))
    }

    @Test
    fun snapshotMatchOutranksDartVersionMatch() {
        val loose = runner(aliases = emptyList(), runnerId = "dart-3_12_2-loose")
        val exact = runner(aliases = listOf(snapshotHash), runnerId = "dart-3_12_2-exact")

        val selected = BlutterRunnerMatcher.select(requirement(snapshotHash = snapshotHash), listOf(loose, exact))

        assertEquals("dart-3_12_2-exact", selected?.runnerId)
    }

    @Test
    fun coverageHintsNameTheBuildToRebuildWith() {
        val manifest = manifest(runners = JSONArray().put(runnerJson(aliases = listOf(snapshotHash))))

        val hints = BlutterRunnerManifest.coverageHints(
            manifest,
            requirement(dartVersion = "3.12.1", engineRevision = unlistedEngine),
            limit = 3
        )

        assertEquals(1, hints.length())
        assertEquals("3.44.1", hints.getJSONObject(0).getString("flutterVersion"))
        assertEquals("3.12.1", hints.getJSONObject(0).getString("dartVersion"))
    }

    @Test
    fun supportedSummaryIsDerivedFromTheRunners() {
        val summary = BlutterRunnerManifest.supportedSummary(listOf(runner(aliases = emptyList())))

        assertEquals("3.44.2", summary.getJSONArray("flutterVersions").getString(0))
        assertEquals("3.12.2", summary.getJSONArray("dartVersions").getString(0))
        assertEquals("arm64-v8a", summary.getJSONArray("abis").getString(0))
    }

    @Test
    fun versionOrderingIsNumericNotLexicographic() {
        val sorted = listOf("3.44.10", "3.44.7", "3.44.2").sortedWith(BlutterRunnerManifest.VERSION_ORDER)

        assertEquals(listOf("3.44.2", "3.44.7", "3.44.10"), sorted)
    }

    @Test
    fun realManifestResolvesTheSharedSnapshotForFlutter3441() {
        // Runs only when the module directory is the working directory (the normal
        // AGP unit-test layout); skipped rather than failed otherwise.
        val file = File("src/main/assets/blutter/runners.json")
        assumeTrue(file.isFile)
        val manifest = JSONObject(file.readText(Charsets.UTF_8))
        val runners = BlutterRunnerManifest.runners(manifest, "embedded")
        assumeTrue(runners.isNotEmpty())

        val selected = BlutterRunnerMatcher.select(
            BlutterRunnerRequirement(
                engineRevision = unlistedEngine,
                dartVersion = "3.12.1",
                abi = "arm64-v8a",
                compressedPointers = true,
                analysis = true,
                snapshotHash = snapshotHash
            ),
            runners
        )

        assertNotNull(selected)
        assertEquals("3.12.2", selected?.dartVersion)
    }

    // ------------------------------------------------------------------ fixtures

    private fun requirement(
        dartVersion: String? = "3.12.2",
        engineRevision: String? = primaryEngine,
        snapshotHash: String? = null,
        compressedPointers: Boolean = true,
        analysis: Boolean = true
    ): BlutterRunnerRequirement = BlutterRunnerRequirement(
        engineRevision = engineRevision,
        dartVersion = dartVersion,
        abi = "arm64-v8a",
        compressedPointers = compressedPointers,
        analysis = analysis,
        snapshotHash = snapshotHash
    )

    private fun runner(
        aliases: List<String> = emptyList(),
        engineRevisions: List<String> = listOf(primaryEngine, secondaryEngine),
        analysis: Boolean = true,
        runnerId: String = "dart-3_12_2-5e4949e6decb093d82c1"
    ): BlutterRunnerDescriptor = BlutterRunnerManifest.runners(
        manifest(runners = JSONArray().put(runnerJson(aliases, engineRevisions, analysis, runnerId))),
        "embedded"
    ).single()

    private fun runnerJson(
        aliases: List<String>,
        engineRevisions: List<String> = listOf(primaryEngine, secondaryEngine),
        analysis: Boolean = true,
        runnerId: String = "dart-3_12_2-5e4949e6decb093d82c1"
    ): JSONObject = JSONObject()
        .put("runnerId", runnerId)
        .put("abi", "arm64-v8a")
        .put("analysis", analysis)
        .put("compressedPointers", true)
        .put("dartVersion", "3.12.2")
        .put("dartRevision", "d684a576a6aa954ae107a03b2b4e1d61c3bebe93")
        .put("engineRevision", primaryEngine)
        .put("engineRevisions", JSONArray(engineRevisions))
        .put("flutterVersions", JSONArray(listOf("3.44.2", "3.44.3", "3.44.4", "3.44.5", "3.44.6", "3.44.7")))
        .put("libraryName", "blutter_5e4949e6decb093d82c1")
        .put("sha256", "072d59c2f5744f5d293064e5598c93eb99f9137bf8d5e3af16ba7a07f5af18e1")
        .put("snapshotAliases", JSONArray(aliases))

    /**
     * Mirrors the shape of the real manifest: every engine revision a runner
     * lists has its own coverage row, and each row carries the snapshot hash
     * that build ships. The 3.44.1 row is the one the runner does *not* list —
     * it is reachable only through the shared snapshot hash. The last row is
     * unrelated noise, proving the union is keyed by engine revision instead of
     * absorbing every hash in the table.
     */
    private fun manifest(runners: JSONArray): JSONObject = JSONObject()
        .put("schemaVersion", 2)
        .put("upstreamCommit", "528acbe83ba35a3a53fb97b231cb5f968c7068d1")
        .put("runners", runners)
        .put(
            "coverage",
            JSONArray()
                .put(coverageRow(primaryEngine, snapshotHash, "3.12.2", "3.44.2"))
                .put(coverageRow(secondaryEngine, snapshotHash, "3.12.2", "3.44.3"))
                .put(coverageRow(unlistedEngine, snapshotHash, "3.12.1", "3.44.1"))
                .put(coverageRow("0".repeat(40), "f".repeat(32), "9.9.9", "9.9.9"))
        )

    private fun coverageRow(engineRevision: String, hash: String, dartVersion: String, flutterVersion: String): JSONObject = JSONObject()
        .put("engineRevision", engineRevision)
        .put("snapshotHash", hash)
        .put("dartVersion", dartVersion)
        .put("flutterVersion", flutterVersion)
        .put("status", "source_resolvable")
        .put("supported", true)
}
