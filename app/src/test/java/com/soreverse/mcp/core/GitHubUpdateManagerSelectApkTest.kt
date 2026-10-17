package com.soreverse.mcp.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Pins GitHubUpdateManager.selectApk to exact-token ABI matching in device
 *  preference order. The previous substring implementation mis-picked on
 *  x86-family devices: "x86" is contained in "x86_64", and the trailing
 *  "armeabi" of a 32-bit x86 device is contained in "armeabi-v7a", so asset
 *  order (alphabetical) decided which wrong split a device downloaded. */
class GitHubUpdateManagerSelectApkTest {
    /** Real release asset set and order (release.yml renames splits to
     *  SOMCP-<version>-<abi>.apk plus one -universal.apk; SHA256SUMS rides
     *  along as a non-APK asset). */
    private val assets = listOf(
        "SOMCP-1.0.22-arm64-v8a.apk",
        "SOMCP-1.0.22-armeabi-v7a.apk",
        "SHA256SUMS",
        "SOMCP-1.0.22-universal.apk",
        "SOMCP-1.0.22-x86.apk",
        "SOMCP-1.0.22-x86_64.apk"
    ).map { name -> asset(name) }

    private fun asset(name: String): JSONObject = JSONObject()
        .put("name", name)
        .put("browser_download_url", "https://github.com/bilieebiliee1-design/SOMCP/releases/download/v1.0.22/$name")

    @Test
    fun x86DevicePicksItsOwnSplitNotArmeabiV7a() {
        // Device ABI order as reported on a 32-bit x86 device; "armeabi" must
        // never match inside "armeabi-v7a".
        val picked = GitHubUpdateManager.selectApk(assets, arrayOf("x86", "armeabi"))
        assertEquals("SOMCP-1.0.22-x86.apk", picked?.optString("name"))
    }

    @Test
    fun x86_64DevicePicksTheX86_64SplitDespiteX86SortingFirst() {
        val picked = GitHubUpdateManager.selectApk(assets, arrayOf("x86_64", "x86"))
        assertEquals("SOMCP-1.0.22-x86_64.apk", picked?.optString("name"))
    }

    @Test
    fun arm64DevicePicksTheArm64Split() {
        val picked = GitHubUpdateManager.selectApk(
            assets,
            arrayOf("arm64-v8a", "armeabi-v7a", "armeabi")
        )
        assertEquals("SOMCP-1.0.22-arm64-v8a.apk", picked?.optString("name"))
    }

    @Test
    fun armeabiV7aDevicePicksTheArmeabiV7aSplit() {
        val picked = GitHubUpdateManager.selectApk(assets, arrayOf("armeabi-v7a", "armeabi"))
        assertEquals("SOMCP-1.0.22-armeabi-v7a.apk", picked?.optString("name"))
    }

    @Test
    fun exactTokenMatchStopsX86FromMatchingInsideX86_64() {
        val only64Bit = listOf(asset("SOMCP-1.0.22-x86_64.apk"))
        assertNull(GitHubUpdateManager.selectApk(only64Bit, arrayOf("x86")))
    }

    /** The single-APK fallback exists for legacy releases that shipped one
     *  ABI-agnostic APK (no ABI token in the name); it must keep working. */
    @Test
    fun loneAbiAgnosticApkIsStillPicked() {
        val legacy = listOf(asset("SOMCP-1.0.19.apk"))
        assertEquals(
            "SOMCP-1.0.19.apk",
            GitHubUpdateManager.selectApk(legacy, arrayOf("arm64-v8a"))?.optString("name")
        )
    }

    @Test
    fun deviceWithoutSplitFallsBackToUniversal() {
        val picked = GitHubUpdateManager.selectApk(assets, arrayOf("mips"))
        assertEquals("SOMCP-1.0.22-universal.apk", picked?.optString("name"))
    }

    @Test
    fun nonApkAssetsAreNeverPicked() {
        val checksumsOnly = listOf(asset("SHA256SUMS"), asset("SOMCP-1.0.22-x86.apk.sha256"))
        assertNull(GitHubUpdateManager.selectApk(checksumsOnly, arrayOf("x86")))
    }
}
