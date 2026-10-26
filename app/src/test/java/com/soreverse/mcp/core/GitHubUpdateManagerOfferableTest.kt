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

/** Pins the same-version update gate to the release record's own timestamps.
 *  The previous rule compared the release's published_at against the APK's
 *  embedded build instant, but the release job embeds its START time and
 *  publishes the release at its END, so published_at was always later than
 *  every installed build's baseline: the newest release was offered to its
 *  own users forever ("我已经是最新版，仍提示有最新版本"). */
class GitHubUpdateManagerOfferableTest {
    private fun offerable(tag: String, publishedAt: String, createdAt: String = publishedAt, current: String = "1.0.22") =
        GitHubUpdateManager.isUpdateOfferable(tag, publishedAt, createdAt, current)

    @Test
    fun higherCoreIsOfferedRegardlessOfTimestamps() {
        assertTrue(offerable("v1.0.23", "2026-10-26T01:00:00Z"))
        assertTrue(offerable("v1.1.0", ""))
    }

    @Test
    fun lowerCoreIsNeverOffered() {
        assertFalse(offerable("v1.0.21", "2026-10-24T09:08:08Z"))
        assertFalse(offerable("v1.0.21", "2026-10-24T09:08:08Z", "2026-01-01T00:00:00Z"))
    }

    /** The exact v1.0.22 shape (created == published at first publish): the
     *  newest release must NOT be offered to users already on it. */
    @Test
    fun firstPublishSameCoreIsNotOffered() {
        assertFalse(offerable("v1.0.22", "2026-10-24T09:08:08Z", "2026-10-24T09:08:08Z"))
    }

    /** A republish (delete/recreate, or draft-then-publish) moves published_at
     *  past the record's created_at: that is the only same-core offer signal,
     *  and it needs no build-time embedding. */
    @Test
    fun republishedSameCoreIsOffered() {
        assertTrue(offerable("v1.0.22", "2026-10-25T18:00:00Z", "2026-10-24T06:46:00Z"))
    }

    @Test
    fun equalCoreWithoutAnyTimestampsIsNotOffered() {
        assertFalse(offerable("v1.0.22", ""))
        assertFalse(offerable("v1.0.22", "", ""))
    }

    /** Beta channel: a beta under the CURRENT stable core is a lower/equal
     *  core and must not be pushed onto stable users. */
    @Test
    fun olderBetaIsNotOfferedToStableUser() {
        assertFalse(offerable("v1.0.21-beta3", "2026-09-20T00:00:00Z", "2026-09-01T00:00:00Z"))
    }
}
