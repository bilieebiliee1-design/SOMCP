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

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Pins release selection: the highest version wins, drafts never do, and two
 *  records of the same tag resolve to the newest record rather than to
 *  whichever was published last. */
class GitHubUpdateManagerNewestReleaseTest {
    private fun release(tag: String, id: Long, publishedAt: String, createdAt: String, prerelease: Boolean = false, draft: Boolean = false) = JSONObject()
        .put("tag_name", tag)
        .put("id", id)
        .put("published_at", publishedAt)
        .put("created_at", createdAt)
        .put("prerelease", prerelease)
        .put("draft", draft)

    private fun arrayOf(vararg releases: JSONObject) = JSONArray().apply { releases.forEach { put(it) } }

    @Test
    fun highestVersionWins() {
        val picked = GitHubUpdateManager.newestRelease(
            arrayOf(
                release("v1.0.21", 1, "2026-09-18T13:53:44Z", "2026-09-18T12:51:51Z"),
                release("v1.0.23", 3, "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z"),
                release("v1.0.22", 2, "2026-10-24T09:08:08Z", "2026-10-24T06:46:00Z")
            ),
            prerelease = false
        )
        assertEquals("v1.0.23", picked?.optString("tag_name"))
    }

    @Test
    fun draftsAndPrereleasesAreSkippedPerChannel() {
        val array = arrayOf(
            release("v1.0.24", 4, "2026-11-01T00:00:00Z", "2026-10-31T00:00:00Z", draft = true),
            release("v1.0.24-beta1", 5, "2026-11-01T02:00:00Z", "2026-11-01T01:00:00Z", prerelease = true),
            release("v1.0.23", 3, "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z")
        )
        assertEquals(
            "v1.0.23",
            GitHubUpdateManager.newestRelease(array, prerelease = false)?.optString("tag_name")
        )
        assertEquals(
            "v1.0.24-beta1",
            GitHubUpdateManager.newestRelease(array, prerelease = true)?.optString("tag_name")
        )
    }

    /** Two records of one tag: the newer record (higher id) is the one whose
     *  assets the gate must judge. Publishtime cannot order them — the
     *  recreated record can be published EARLIER than the one it replaced if
     *  that build was shorter, and picking the stale record would describe an
     *  artifact the release page no longer offers. */
    @Test
    fun sameTagResolvesToNewestRecordNotLatestPublishTime() {
        val array = arrayOf(
            release("v1.0.23", 9_001, "2026-10-30T20:00:00Z", "2026-10-30T19:00:00Z"),
            release("v1.0.23", 9_002, "2026-10-31T02:00:00Z", "2026-10-31T01:00:00Z")
        )
        assertEquals(9_002L, GitHubUpdateManager.newestRelease(array, prerelease = false)?.optLong("id"))
    }

    @Test
    fun emptyOrAllDraftYieldsNull() {
        assertNull(GitHubUpdateManager.newestRelease(arrayOf(), prerelease = false))
        assertNull(
            GitHubUpdateManager.newestRelease(
                arrayOf(release("v1.0.24", 4, "2026-11-01T00:00:00Z", "2026-10-31T00:00:00Z", draft = true)),
                prerelease = false
            )
        )
    }

    /** The selected record is exactly what the gate then judges: a real-shaped
     *  v1.0.23 record must come out as "not offerable" for a 1.0.23 build, end
     *  to end through selection + gate. */
    @Test
    fun selectedLatestReleaseIsNotOfferedToItsOwnUsers() {
        val picked = GitHubUpdateManager.newestRelease(
            arrayOf(release("v1.0.23", 3, "2026-10-30T11:35:46Z", "2026-10-30T10:10:51Z")),
            prerelease = false
        )!!
        assertEquals(
            false,
            GitHubUpdateManager.isUpdateOfferable(
                picked.optString("tag_name"),
                picked.optString("published_at"),
                picked.optString("created_at"),
                "1.0.23"
            )
        )
    }
}
