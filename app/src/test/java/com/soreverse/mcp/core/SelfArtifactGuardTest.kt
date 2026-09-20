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

import com.soreverse.mcp.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Context-free coverage of [SelfArtifactGuard] path detection and arg scanning. */
class SelfArtifactGuardTest {

    private val runningApk = "/data/app/~~somcp==/com.soreverse.mcp-1/base.apk"
    private val nativeLib = "/data/app/~~somcp==/com.soreverse.mcp-1/lib/arm64"
    private val ownLibs = setOf("libsomcp_core.so", "liblief_elf.so")

    @Before
    fun resetQuarantine() {
        SelfArtifactGuard.clearQuarantine()
    }

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
    fun scanFlagsRenamedOwnApkCopyWhenIdentityMatches() {
        val copy = "/sdcard/Download/copy-of-somcp.apk"
        val args = JSONObject().put("apkPath", copy)
        val checker: (String) -> Boolean = { it == copy }
        assertEquals(
            copy,
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, checker)
        )
    }

    @Test
    fun scanIgnoresRenamedApkWhenIdentityDoesNotMatch() {
        val args = JSONObject().put("apkPath", "/sdcard/Download/not-somcp.apk")
        val checker: (String) -> Boolean = { false }
        assertNull(
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, checker)
        )
    }

    @Test
    fun scanFlagsOwnLibApkEntryReference() {
        // APK-internal reference to an own bundled lib, APK itself unnamed/renamed.
        val args = JSONObject().put("filePath", "com.soreverse.mcp.apk!lib/arm64-v8a/liblief_elf.so")
        assertEquals(
            "com.soreverse.mcp.apk!lib/arm64-v8a/liblief_elf.so",
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, ownLibNames = ownLibs)
        )
    }

    @Test
    fun scanFlagsOwnLibInsideWorkDirectoryReference() {
        // The shape the work-directory scanner produces for an APK-embedded SO:
        // a relative APK path behind the `apk:` prefix. The entry name is what
        // identifies it — the relative APK path alone names no readable file.
        val ref = "apk:SOMCP_1.0.21.apk!lib/arm64-v8a/liblief_elf.so"
        val args = JSONObject().put("path", ref)
        assertEquals(
            ref,
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, ownLibNames = ownLibs)
        )
        assertNull(
            SelfArtifactGuard.findSelfArgAgainst(
                listOf(runningApk),
                nativeLib,
                JSONObject().put("apkPath", "SOMCP_1.0.21.apk"),
                ownLibNames = ownLibs
            )
        )
    }

    @Test
    fun scanAllowsThirdPartyLibEntryReference() {
        val outside = "target.apk!lib/arm64-v8a/libexample.so"
        val args = JSONObject().put("filePath", outside)
        assertNull(
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, ownLibNames = ownLibs)
        )
    }

    @Test
    fun scanIgnoresOwnNameWithoutLibEntryStructure() {
        // Same name but not in lib/<abi>/ form must not be over-blocked.
        val args = JSONObject().put("fileName", "libsomcp_core.so")
        assertNull(
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, args, ownLibNames = ownLibs)
        )
    }

    @Test
    fun forbiddenResultUsesStableErrorCode() {
        val result = SelfArtifactGuard.forbidden(runningApk)
        assertEquals(false, result.optBoolean("ok", true))
        assertEquals("SELF_ANALYSIS_FORBIDDEN", result.optJSONObject("error")?.optString("code"))
    }

    @Test
    fun flagsExtractedSoByContentMarker() {
        val marker = BuildConfig.APPLICATION_ID
        val f = java.io.File.createTempFile("extracted", ".so").apply {
            writeBytes((marker + "\u0000some bytes").toByteArray())
            deleteOnExit()
        }
        assertTrue(SelfArtifactGuard.isSelfFileByContent(f.absolutePath))
        // UTF-16LE encoding is also recognised.
        val u = java.io.File.createTempFile("extracted-utf16", ".so").apply {
            writeBytes(marker.toByteArray(Charsets.UTF_16LE))
            deleteOnExit()
        }
        assertTrue(SelfArtifactGuard.isSelfFileByContent(u.absolutePath))
    }

    @Test
    fun ignoresUnrelatedSoContent() {
        val path = java.io.File.createTempFile("thirdparty", ".so").apply {
            writeBytes("com.example.other lib".toByteArray())
            deleteOnExit()
        }.absolutePath
        assertFalse(SelfArtifactGuard.isSelfFileByContent(path))
        // Non-.so targets are never content-scanned.
        val txt = java.io.File.createTempFile("marker", ".txt").apply {
            writeBytes(BuildConfig.APPLICATION_ID.toByteArray())
            deleteOnExit()
        }.absolutePath
        assertFalse(SelfArtifactGuard.isSelfFileByContent(txt))
    }

    @Test
    fun scanFlagsExtractedSoViaContentCheck() {
        val extracted = java.io.File.createTempFile("extracted", ".so").apply {
            writeBytes((BuildConfig.APPLICATION_ID + " payload").toByteArray())
            deleteOnExit()
        }.absolutePath
        val args = JSONObject().put("localPath", extracted)
        val contentCheck: (String) -> Boolean = { it == extracted }
        assertEquals(
            extracted,
            SelfArtifactGuard.findSelfArgAgainst(
                listOf(runningApk),
                nativeLib,
                args,
                ownLibNames = ownLibs,
                contentCheck = contentCheck
            )
        )
    }

    @Test
    fun flagsBridgedResultThatOpenedOwnPackage() {
        // Shape of a bridged mt_apk_open answer: the identity of the archive is
        // only visible in the result, never in the arguments.
        val verdict = SelfArtifactGuard.ownArtifactFromBridgedResult(
            bridgedResult(
                JSONObject()
                    .put("workspaceId", "rqyyw6q")
                    .put("apkFileName", "SOMCP_1.0.21.apk")
                    .put("packageName", BuildConfig.APPLICATION_ID)
                    .put("signature", JSONObject().put("sha256", "00"))
            )
        )
        assertEquals(BuildConfig.APPLICATION_ID, verdict?.value)
        assertTrue(verdict!!.identifiers.contains("rqyyw6q"))
    }

    @Test
    fun flagsBridgedResultWhoseTextIsNotJson() {
        // The bridge parks an unparsable remote body under a plain string field,
        // so a text that is not JSON but still names the package must be caught.
        val result = JSONObject().put(
            "content",
            JSONArray().put(
                JSONObject()
                    .put("type", "text")
                    .put("text", "open failed for ${BuildConfig.APPLICATION_ID}")
            )
        )
        assertEquals(
            BuildConfig.APPLICATION_ID,
            SelfArtifactGuard.ownArtifactFromBridgedResult(result)?.value
        )
    }

    @Test
    fun allowsBridgedResultForThirdPartyPackage() {
        val verdict = SelfArtifactGuard.ownArtifactFromBridgedResult(
            bridgedResult(
                JSONObject()
                    .put("workspaceId", "other1")
                    .put("packageName", "com.example.other")
            )
        )
        assertNull(verdict)
        assertNull(SelfArtifactGuard.ownArtifactFromBridgedResult(null))
    }

    @Test
    fun quarantinedWorkspaceIsRefusedOnFollowUpCalls() {
        SelfArtifactGuard.quarantine(listOf("rqyyw6q"))
        val followUp = JSONObject()
            .put("workspaceId", "rqyyw6q")
            .put("locator", "dex_class:Lho3;")
            .put("limit", 200)
        assertEquals(
            "rqyyw6q",
            SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, followUp)
        )
        // A call that embeds the same handle in an archive reference is refused too.
        val embedded = "apk:rqyyw6q!lib/arm64-v8a/libexample.so"
        assertEquals(
            embedded,
            SelfArtifactGuard.findSelfArgAgainst(
                listOf(runningApk),
                nativeLib,
                JSONObject().put("filePath", embedded)
            )
        )
        SelfArtifactGuard.clearQuarantine()
        assertNull(SelfArtifactGuard.findSelfArgAgainst(listOf(runningApk), nativeLib, followUp))
    }

    /** Wraps [inner] the way the bridge forwards a remote tool result. */
    private fun bridgedResult(inner: JSONObject): JSONObject = JSONObject().put(
        "content",
        JSONArray().put(JSONObject().put("type", "text").put("text", inner.toString()))
    )
}
