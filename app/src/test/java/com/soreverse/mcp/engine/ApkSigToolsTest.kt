// SPDX-License-Identifier: AGPL-3.0-only
//
// APK audit tests on synthetic ZIPs: layout parsing, signing-block discovery,
// unsigned/garbage-block verdicts, digest determinism and tamper sensitivity,
// ZIP anomaly checks and ABI coverage over the synthetic ELF fixture.
package com.soreverse.mcp.engine

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkSigToolsTest {
    private fun u32(v: Int): ByteArray = byteArrayOf(
        (v and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(),
        ((v shr 16) and 0xff).toByte(),
        ((v shr 24) and 0xff).toByte()
    )

    private fun u64(v: Long): ByteArray = ByteArray(8) { i -> ((v shr (i * 8)) and 0xff).toByte() }

    private fun buildZip(entries: List<Triple<String, ByteArray, Boolean>>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content, stored) ->
                val entry = ZipEntry(name)
                if (stored) {
                    entry.method = ZipEntry.STORED
                    entry.size = content.size.toLong()
                    entry.compressedSize = content.size.toLong()
                    entry.crc = CRC32().apply { update(content) }.value
                }
                zip.putNextEntry(entry)
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    /** Inserts a signing block before the CD and repoints the EOCD CD offset. */
    private fun insertBlock(apk: ByteArray, pairs: List<Pair<Long, ByteArray>>): Pair<ByteArray, Int> {
        val layout = ApkSigTools.parseZipLayout(apk)!!
        val pairsBytes = ByteArrayOutputStream().apply {
            pairs.forEach { (id, value) ->
                write(u64((4 + value.size).toLong()))
                write(u32(id.toInt()))
                write(value)
            }
        }.toByteArray()
        // size field counts everything after the leading size field: pairs + footer + magic
        val sizeValue = pairsBytes.size + 8 + 16
        val blockSize = 8 + sizeValue
        val out = ByteArrayOutputStream()
        out.write(apk, 0, layout.cdOffset)
        out.write(u64(sizeValue.toLong()))
        out.write(pairsBytes)
        out.write(u64(sizeValue.toLong()))
        out.write("APK Sig Block 42".toByteArray(Charsets.US_ASCII))
        out.write(apk, layout.cdOffset, apk.size - layout.cdOffset)
        val result = out.toByteArray()
        val eocd = result.size - 22
        val newCd = layout.cdOffset + blockSize
        for (i in 0 until 4) result[eocd + 16 + i] = ((newCd shr (i * 8)) and 0xff).toByte()
        return result to blockSize
    }

    @Test
    fun parsesZipLayoutFromARealZipStream() {
        val apk = buildZip(listOf(Triple("AndroidManifest.xml", "binary-xml".toByteArray(), false)))
        val layout = ApkSigTools.parseZipLayout(apk)
        assertNotNull(layout)
        assertEquals(1, layout!!.entries.size)
        assertEquals("AndroidManifest.xml", layout.entries[0].name)
    }

    @Test
    fun unsignedZipReportsUnsigned() {
        val apk = buildZip(listOf(Triple("AndroidManifest.xml", "x".toByteArray(), false)))
        val result = ApkSigTools.verify(apk)
        assertEquals("unsigned", result.getString("verdict"))
        assertTrue(!result.getJSONObject("v2").getBoolean("present"))
    }

    @Test
    fun signingBlockIsLocatedAndGarbageSignersLeaveParsedUnverified() {
        val apk = buildZip(listOf(Triple("AndroidManifest.xml", "x".toByteArray(), false)))
        val garbageSigner = u32(1) + u32(4) + u32(0)
        val (signed, blockSize) = insertBlock(apk, listOf(0x7109871aL to garbageSigner))
        val result = ApkSigTools.verify(signed)
        val block = result.getJSONObject("signingBlock")
        assertTrue(block.getInt("end") - block.getInt("start") >= blockSize)
        assertTrue(result.getJSONObject("v2").getBoolean("present"))
        assertEquals("parsed_unverified", result.getString("verdict"))
        assertEquals(0, result.getJSONArray("signers").length())
    }

    @Test
    fun contentDigestIsDeterministicAndTamperSensitive() {
        val apk = buildZip(listOf(Triple("classes.dex", ByteArray(2048) { (it % 251).toByte() }, false)))
        val layout = ApkSigTools.parseZipLayout(apk)!!
        val (signed, blockSize) = insertBlock(apk, listOf(0x7109871aL to u32(1) + u32(4) + u32(0)))
        val blockStart = layout.cdOffset
        val newCd = layout.cdOffset + blockSize
        val eocdOffset = signed.size - 22
        val d1 = ApkSigTools.computeContentDigest(signed, blockStart, newCd, eocdOffset, 256)
        val d2 = ApkSigTools.computeContentDigest(signed, blockStart, newCd, eocdOffset, 256)
        assertTrue(d1.contentEquals(d2))
        val tampered = signed.copyOf().also { it[10] = (it[10] + 1).toByte() }
        val d3 = ApkSigTools.computeContentDigest(tampered, blockStart, newCd, eocdOffset, 256)
        assertTrue(!d1.contentEquals(d3))
    }

    @Test
    fun zipAnomaliesDetectTraversalAndUnalignedStoredSo() {
        val so = SynthElf.build()
        val apk = buildZip(
            listOf(
                Triple("../evil.txt", "x".toByteArray(), false),
                Triple("assets/readme.txt", ByteArray(64), false),
                Triple("lib/arm64-v8a/libtest.so", so, true)
            )
        )
        val result = ApkSigTools.zipAnomalies(apk)
        assertTrue(result.getInt("anomalyCount") > 0)
        val kinds = (0 until result.getJSONArray("anomalies").length())
            .map { result.getJSONArray("anomalies").getJSONObject(it).getString("kind") }
        assertTrue("path_traversal" in kinds)
        assertTrue("unaligned_so" in kinds)
    }

    @Test
    fun abiCoverageGroupsByAbiAndReportsMissing() {
        val so = SynthElf.build()
        val stub = byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0)
        val apk = buildZip(
            listOf(
                Triple("lib/arm64-v8a/libtest.so", so, true),
                Triple("lib/armeabi-v7a/libtest.so", stub, true)
            )
        )
        val result = ApkSigTools.abiCoverage(apk)
        val abis = (0 until result.getJSONArray("abis").length()).map { result.getJSONArray("abis").getString(it) }
        assertTrue("arm64-v8a" in abis)
        assertTrue("armeabi-v7a" in abis)
        val findings = result.getJSONArray("findings")
        val findingsText = (0 until findings.length()).joinToString("\n") { findings.getString(it) }
        assertTrue("missing ABI: x86_64" in findingsText)
        assertTrue("32-bit only" !in findingsText)
        val arm64Files = result.getJSONArray("libraries").getJSONObject(0).getJSONArray("files")
        assertEquals("arm64", arm64Files.getJSONObject(0).getString("architecture"))
        assertEquals("libtest.so", arm64Files.getJSONObject(0).getString("soname"))
    }

    @Test
    fun certInfoWithoutSignaturesReturnsZeroCerts() {
        val apk = buildZip(listOf(Triple("AndroidManifest.xml", "x".toByteArray(), false)))
        assertEquals(0, ApkSigTools.certInfo(apk).getInt("certCount"))
    }
}
