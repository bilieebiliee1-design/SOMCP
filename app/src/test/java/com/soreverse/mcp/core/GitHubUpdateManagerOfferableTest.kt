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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pins the same-version update gate.
 *
 *  The fixtures below carry the timestamps the LIVE API actually returns for
 *  this repo (checked 2026-10-31 against
 *  `GET /repos/bilieebiliee1-design/SOMCP/releases?per_page=100`), not a
 *  hand-made shape: all 22 releases have `published_at > created_at`, because
 *  the release job creates the release record when the tag build starts and
 *  attaches the assets when it ends. The previous fixture used
 *  `published_at == created_at`, a shape no release in this repo ever had, so
 *  it passed while the shipped gate offered v1.0.23 to users already running
 *  v1.0.23. */
class GitHubUpdateManagerOfferableTest {
    private fun offerable(
        tag: String,
        publishedAt: String,
        createdAt: String = publishedAt,
        current: String = "1.0.23"
    ) = GitHubUpdateManager.isUpdateOfferable(tag, publishedAt, createdAt, current)

    /** Real v1.0.23 record: created 10:10:51Z (== the tag commit's committer
     *  date), published 11:35:46Z. Users on 1.0.23 must not be prompted. */
    @Test
    fun latestReleaseIsNotOfferedToUsersAlreadyOnIt() {
        assertFalse(offerable("v1.0.23", "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z"))
    }

    /** Real v1.0.22 record, for users still on 1.0.22 while 1.0.23 is out:
     *  the 1.0.22 release must not be offered, the 1.0.23 one must. */
    @Test
    fun realV1022TimesAreNotOfferedToV1022Users() {
        assertFalse(
            offerable("v1.0.22", "2026-10-24T09:08:08Z", "2026-10-24T06:46:00Z", current = "1.0.22")
        )
        assertTrue(
            offerable("v1.0.23", "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z", current = "1.0.22")
        )
    }

    /** The whole published set: no release may be offered to the version it
     *  carries, whatever the two timestamps say (they are all `>` in the live
     *  API, which is exactly what used to make this branch return true). */
    @Test
    fun noReleaseIsOfferedToTheVersionItCarries() {
        val releases = listOf(
            Triple("v1.0.23", "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z"),
            Triple("v1.0.22", "2026-10-24T09:08:08Z", "2026-10-24T06:46:00Z"),
            Triple("v1.0.21", "2026-09-18T13:53:44Z", "2026-09-18T12:51:51Z"),
            Triple("v1.0.20", "2026-08-26T03:30:04Z", "2026-08-25T02:34:43Z"),
            Triple("v1.0.17", "2026-08-17T10:38:50Z", "2026-08-03T04:30:38Z")
        )
        for ((tag, publishedAt, createdAt) in releases) {
            val installed = tag.removePrefix("v")
            assertFalse(
                "$tag must not be offered to $installed",
                offerable(tag, publishedAt, createdAt, current = installed)
            )
        }
    }

    /** Timestamps never rescue an equal version: this is the regression the
     *  release-record heuristic was built on, and it is not a republish
     *  signal in this pipeline. */
    @Test
    fun equalVersionIsNotOfferedWhateverTheTimestampsSay() {
        assertFalse(offerable("v1.0.23", "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z"))
        assertFalse(offerable("v1.0.23", "2026-11-30T00:00:00Z", "2026-01-01T00:00:00Z"))
        assertFalse(offerable("v1.0.23", "2026-10-30T11:35:46Z", "2026-10-30T11:35:46Z"))
        assertFalse(offerable("v1.0.23", ""))
        assertFalse(offerable("v1.0.23", "", ""))
    }

    @Test
    fun higherCoreIsOfferedRegardlessOfTimestamps() {
        assertTrue(offerable("v1.0.24", "2026-10-26T01:00:00Z", "2026-10-26T01:00:00Z"))
        assertTrue(offerable("v1.1.0", ""))
        assertTrue(offerable("v1.0.100", "2026-10-24T09:08:08Z", "2026-10-24T06:46:00Z"))
    }

    @Test
    fun lowerCoreIsNeverOffered() {
        assertFalse(offerable("v1.0.22", "2026-10-24T09:08:08Z"))
        assertFalse(offerable("v1.0.21", "2026-10-24T09:08:08Z", "2026-01-01T00:00:00Z"))
        assertFalse(offerable("v0.9.99", "2026-12-31T00:00:00Z", "2026-01-01T00:00:00Z"))
    }

    /** Beta channel: a beta under the CURRENT stable core is a lower/equal
     *  core and must not be pushed onto stable users. */
    @Test
    fun olderBetaIsNotOfferedToStableUser() {
        assertFalse(offerable("v1.0.21-beta3", "2026-09-20T00:00:00Z", "2026-09-01T00:00:00Z"))
        assertFalse(offerable("v1.0.23-beta1", "2026-10-30T12:00:00Z", "2026-10-30T10:00:00Z"))
    }

    /** Same core, higher pre-release ordering: a beta2 of the running version
     *  is a newer build and may be offered; a FINAL of the running version is
     *  not the beta user's own build either, so it stays offerable so a tester
     *  can leave the channel. A stable user never gets beta2, and never gets
     *  the final they already run (covered above). */
    @Test
    fun sameCoreBetaOrderingIsRespected() {
        assertTrue(
            GitHubUpdateManager.isUpdateOfferable(
                "v1.0.24-beta2", "2026-10-30T12:00:00Z", "2026-10-30T10:00:00Z", "1.0.24-beta1"
            )
        )
        assertFalse(
            GitHubUpdateManager.isUpdateOfferable(
                "v1.0.24-beta1", "2026-10-30T12:00:00Z", "2026-10-30T10:00:00Z", "1.0.24-beta2"
            )
        )
        assertTrue(
            GitHubUpdateManager.isUpdateOfferable(
                "v1.0.24", "2026-10-30T12:00:00Z", "2026-10-30T10:00:00Z", "1.0.24-beta2"
            )
        )
    }

    @Test
    fun nonVersionedTagsAreNeverOffered() {
        assertFalse(offerable("nightly", "2026-10-30T12:00:00Z", "2026-10-30T10:00:00Z"))
        assertFalse(GitHubUpdateManager.isNewerVersion("nightly", "1.0.23"))
    }
}
