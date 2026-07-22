package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkAnalyzerTest {
    @Test
    fun readsApkContentsAndMetadata() {
        val apk = apkBytes(
            "AndroidManifest.xml" to "<manifest package=\"com.example.demo\"/>".toByteArray(),
            "classes.dex" to dexHeader(3),
            "classes2.dex" to dexHeader(7),
            "lib/arm64-v8a/libdemo.so" to byteArrayOf(1, 2),
            "lib/armeabi-v7a/libdemo.so" to byteArrayOf(3),
            "resources.arsc" to byteArrayOf(0),
            "META-INF/CERT.RSA" to byteArrayOf(1),
        )

        val result = ApkAnalyzer.analyze(apk, "demo.apk", 50)

        assertEquals("demo.apk", result.getString("path"))
        assertEquals(7, result.getInt("entryCount"))
        assertEquals(2, result.getJSONArray("dexFiles").length())
        assertTrue(result.getJSONArray("dexFiles").getJSONObject(0).getBoolean("valid"))
        assertEquals(7L, result.getJSONArray("dexFiles").getJSONObject(1).getLong("methodIds"))
        assertEquals(2, result.getJSONArray("nativeLibraries").length())
        assertEquals("arm64-v8a", result.getJSONArray("abis").getString(0))
        assertEquals("text_xml", result.getJSONObject("manifest").getString("format"))
        assertTrue(result.getBoolean("resourcesArsc"))
        assertTrue(result.getBoolean("hasV1Signature"))
        assertFalse(result.getBoolean("entriesTruncated"))
    }

    @Test
    fun boundsListedEntriesWithoutSkippingAnalysis() {
        val apk = apkBytes(
            "first.txt" to byteArrayOf(1),
            "classes.dex" to dexHeader(1),
            "lib/x86_64/libdemo.so" to byteArrayOf(2),
        )

        val result = ApkAnalyzer.analyze(apk, "limited.apk", 0)

        assertEquals(3, result.getInt("entryCount"))
        assertEquals(1, result.getJSONArray("entries").length())
        assertTrue(result.getBoolean("entriesTruncated"))
        assertEquals(1, result.getJSONArray("dexFiles").length())
        assertEquals(1, result.getJSONArray("nativeLibraries").length())
    }

    @Test
    fun rejectsTooManyEntries() {
        val apk = apkBytes("a" to byteArrayOf(1), "b" to byteArrayOf(2))

        assertLimitExceeded { ApkAnalyzer.analyze(apk, "many.apk", 10, ApkAnalyzer.Limits(maxEntries = 1)) }
    }

    @Test
    fun rejectsOversizedParsedEntry() {
        val apk = apkBytes("classes.dex" to ByteArray(256))

        assertLimitExceeded { ApkAnalyzer.analyze(apk, "large.apk", 10, ApkAnalyzer.Limits(maxParsedEntryBytes = 128)) }
    }

    @Test
    fun rejectsOversizedParsedTotal() {
        val apk = apkBytes("classes.dex" to ByteArray(80), "classes2.dex" to ByteArray(80))

        assertLimitExceeded { ApkAnalyzer.analyze(apk, "total.apk", 10, ApkAnalyzer.Limits(maxParsedEntryBytes = 100, maxParsedTotalBytes = 120)) }
    }

    private fun apkBytes(vararg entries: Pair<String, ByteArray>): ByteArray = ByteArrayOutputStream().use { output ->
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        output.toByteArray()
    }

    private fun dexHeader(methodIds: Int): ByteArray = ByteArray(0x70).also { bytes ->
        "dex\n035\u0000".toByteArray().copyInto(bytes)
        putU32(bytes, 0x20, bytes.size)
        putU32(bytes, 0x24, 0x70)
        putU32(bytes, 0x28, 0x12345678)
        putU32(bytes, 0x58, methodIds)
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }

    private fun assertLimitExceeded(block: () -> Unit) {
        try {
            block()
            fail("Expected ApkAnalysisLimitException")
        } catch (_: ApkAnalysisLimitException) {
        }
    }
}
