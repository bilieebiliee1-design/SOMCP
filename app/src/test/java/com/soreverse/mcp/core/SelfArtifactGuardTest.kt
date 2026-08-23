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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONArray
import org.json.JSONObject

/** Context-free coverage of [SelfArtifactGuard] path detection and arg scanning. */
class SelfArtifactGuardTest {

    private val runningApk = "/data/app/~~somcp==/com.soreverse.mcp-1/base.apk"
    private val nativeLib = "/data/app/~~somcp==/com.soreverse.mcp-1/lib/arm64"

    @Test
    fun detectsRunningApkPathExactly() {
        assertTrue(SelfArtifactGuard.isSelfApkPathAgainst(listOf(runningApk), runningApk))
        assertFalse(
            SelfArtifactGuard.isSelfApkPathAgainst(
                listOf(runningApk),
                "/data/app/other.apk"
            )
        )
    }

    @Test
    fun detectsBundledSoUnderNativeLibDir() {
        assertTrue(
            SelfArtifactGuard.isSelfBundledSoAgainst(
                nativeLib,
                "$nativeLib/libsomcp_core.so"
            )
        )
        assertTrue(SelfArtifactGuard.isSelfBundledSoAgainst(nativeLib, nativeLib))
        assertFalse(
            SelfArtifactGuard.isSelfBundledSoAgainst(
                nativeLib,
                "/storage/emulated/0/Download/libfoo.so"
            )
        )
        assertFalse(SelfArtifactGuard.isSelfBundledSoAgainst(null, "$nativeLib/libx.so"))
    }

    @Test
    fun scanFlagsOwnApkPathInNestedArguments() {
        val args = JSONObject()
            .put("apkPath", runningApk)
            .put("sub", JSONObject().put("entries", JSONArray().put(JSONObject().put("path", runningApk))))
        assertEquals(runningApk, SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args))
    }

    @Test
    fun scanFlagsOwnBundledSo() {
        val ownSo = "$nativeLib/libsomcp_core.so"
        val args = JSONObject().put("filePath", ownSo)
        assertEquals(ownSo, SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args))
    }

    @Test
    fun scanAllowsThirdPartyPathsUrlsAndPackageNames() {
        val args = JSONObject()
            .put("apkPath", "/sdcard/Download/target.apk")
            .put("soPath", "/storage/emulated/0/work/libexample.so")
            .put("url", "https://example.com/libfoo.so")
            .put("packageName", "com.soreverse.mcp")
            .put("count", 3)
            .put("tags", JSONArray().put("a").put(JSONObject().put("b", "/tmp/other.apk")))
        assertNull(SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args))
    }

    @Test
    fun scanFlagsRenamedSelfSignedApkCopyWhenSignatureMatches() {
        val copy = "/sdcard/Download/copy-of-somcp.apk"
        val args = JSONObject().put("apkPath", copy)
        val checker: (String) -> Boolean = { it == copy }
        assertEquals(
            copy,
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, checker)
        )
    }

    @Test
    fun scanIgnoresRenamedApkWhenSignatureDoesNotMatch() {
        val args = JSONObject().put("apkPath", "/sdcard/Download/not-somcp.apk")
        val checker: (String) -> Boolean = { false }
        assertNull(
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, checker)
        )
    }

    @Test
    fun forbiddenResultUsesStableErrorCode() {
        val result = SelfArtifactGuard.forbidden(runningApk)
        assertEquals(false, result.optBoolean("ok", true))
        assertEquals("SELF_ANALYSIS_FORBIDDEN", result.optJSONObject("error")?.optString("code"))
    }
}