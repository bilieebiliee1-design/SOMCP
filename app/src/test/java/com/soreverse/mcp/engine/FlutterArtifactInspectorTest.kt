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
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The inspector was rewritten around file-backed views, so these tests pin the
 * two properties that rewrite depends on:
 *
 *  - the on-disk path and the in-memory path produce the *same* fingerprint
 *    (otherwise a "memory optimisation" silently changes what gets analysed);
 *  - the bounded byte scanner agrees with the regex it replaced, including the
 *    cases a naive window scan gets wrong (an id straddling the window boundary,
 *    an id at the very end of the section, a run longer than an id).
 */
class FlutterArtifactInspectorTest {
    private val engineId = "77e2e94772b6eb43759e34ed1ad7da4674e19cab"
    private val snapshotHash = "0123456789abcdef0123456789abcdef"

    @Test
    fun fileAndByteInventoryAgree() {
        val apk = writeApk(library = syntheticElf(tail = versionAndIdTail()))
        val bytes = apk.readBytes()

        val fromFile = FlutterArtifactInspector.inspectApk(apk)
        val fromBytes = FlutterArtifactInspector.inspectApk(bytes, apk.path)

        assertEquals(fingerprintOf(fromBytes), fingerprintOf(fromFile))
        assertEquals(fromBytes.getInt("entryCount"), fromFile.getInt("entryCount"))
        assertEquals("arm64-v8a", fromFile.getJSONObject("selected").getString("abi"))
        assertTrue(fromFile.getJSONObject("flutter").getJSONArray("assets").length() > 0)
    }

    @Test
    fun extractionStreamsToDiskWithDigests() {
        val library = syntheticElf(tail = versionAndIdTail())
        val apk = writeApk(library = library)
        val target = File(apk.parentFile, "extracted")

        val files = FlutterArtifactInspector.extractLibrariesTo(apk, target)

        assertEquals(library.size.toLong(), files.libappSize)
        assertEquals(library.size.toLong(), files.libflutterSize)
        assertEquals(sha256(library), files.libappSha256)
        assertEquals(sha256(library), files.libflutterSha256)
        assertEquals(library.size.toLong(), files.libapp.length())
        assertEquals(sha256(files.libapp.readBytes()), files.libappSha256)
    }

    @Test
    fun mappedFileFingerprintMatchesInMemoryFingerprint() {
        val library = syntheticElf(tail = versionAndIdTail())
        val apk = writeApk(library = library)
        val files = FlutterArtifactInspector.extractLibrariesTo(apk, File(apk.parentFile, "extracted"))

        val fromFiles = FlutterArtifactInspector.inspectLibraries(files)
        val fromBytes = FlutterArtifactInspector.inspectLibraries(
            FlutterLibraries(apk.name, files.abi, library, library, "libapp.so", "libflutter.so")
        )

        assertEquals(fingerprintOf(fromBytes), fingerprintOf(fromFiles))
        assertEquals(
            fromBytes.getJSONObject("libappElf").getInt("dynamicSymbolCount"),
            fromFiles.getJSONObject("libappElf").getInt("dynamicSymbolCount")
        )
        assertTrue(fromFiles.getJSONObject("libflutterElf").getBoolean("hasRodata"))
    }

    @Test
    fun fingerprintReadsSnapshotHashFlagsVersionAndEngineId() {
        val apk = writeApk(library = syntheticElf(tail = versionAndIdTail()))
        val files = FlutterArtifactInspector.extractLibrariesTo(apk, File(apk.parentFile, "extracted"))

        val flutter = FlutterArtifactInspector.inspectLibraries(files).getJSONObject("flutter")

        assertEquals(snapshotHash, flutter.getString("snapshotHash"))
        assertEquals("3.12.2", flutter.getString("dartVersion"))
        assertEquals(engineId, flutter.getJSONArray("engineIds").getString(0))
        assertTrue(flutter.getBoolean("compressedPointers"))
        assertEquals("arm64", flutter.getString("architecture"))
        assertEquals(1.0, flutter.getDouble("confidence"), 0.0001)
    }

    @Test
    fun apkWithoutTheLibraryPairIsReportedAsNotFlutter() {
        val apk = writeApk(library = null)
        val inventory = FlutterArtifactInspector.inspectApk(apk)

        assertFalse(inventory.getJSONObject("flutter").getBoolean("detected"))
        assertNull(inventory.optJSONObject("selected"))
        val failure = runCatching { FlutterArtifactInspector.extractLibrariesTo(apk, File(apk.parentFile, "out")) }
        assertTrue(failure.exceptionOrNull()?.message.orEmpty().startsWith("FLUTTER_LIBS_NOT_FOUND"))
    }

    @Test
    fun engineIdStraddlingTheScanWindowIsFound() {
        // The scanner walks 64 KiB windows; an id that starts 20 bytes before the
        // boundary must still be reported once, not dropped and not duplicated.
        val padding = ByteArray(SCAN_WINDOW_BYTES - 20) { 'Q'.code.toByte() }
        val payload = padding + engineId.toByteArray(StandardCharsets.US_ASCII) + "-".toByteArray(StandardCharsets.US_ASCII)
        val view = ByteViews.of(payload)

        val ids = FlutterByteScan.engineIds(view, 0, payload.size.toLong())

        assertEquals(listOf(engineId), ids)
    }

    @Test
    fun engineIdAtTheEndOfTheRangeIsFound() {
        val payload = ("x" + engineId).toByteArray(StandardCharsets.US_ASCII)
        val view = ByteViews.of(payload)

        assertEquals(listOf(engineId), FlutterByteScan.engineIds(view, 0, payload.size.toLong()))
    }

    @Test
    fun longerHexRunIsNotAnEngineId() {
        val payload = ("x" + engineId + "a").toByteArray(StandardCharsets.US_ASCII)

        assertTrue(FlutterByteScan.engineIds(ByteViews.of(payload), 0, payload.size.toLong()).isEmpty())
    }

    @Test
    fun uppercaseHexRunIsNotAnEngineId() {
        // The regex this scanner replaced was lowercase-only; accepting A-F would
        // widen what counts as a compatibility key without any evidence for it.
        val payload = ("x" + engineId.uppercase()).toByteArray(StandardCharsets.US_ASCII)

        assertTrue(FlutterByteScan.engineIds(ByteViews.of(payload), 0, payload.size.toLong()).isEmpty())
    }

    @Test
    fun dartVersionSkipsASuffixWithoutAVersionRun() {
        val payload = " (stable) 3.12.2 (stable)".toByteArray(StandardCharsets.US_ASCII)

        assertEquals("3.12.2", FlutterByteScan.dartVersion(ByteViews.of(payload), 0, payload.size.toLong()))
    }

    @Test
    fun dartVersionIsBoundedAndReturnsNullWhenAbsent() {
        val payload = "no channel marker here".toByteArray(StandardCharsets.US_ASCII)

        assertNull(FlutterByteScan.dartVersion(ByteViews.of(payload), 0, payload.size.toLong()))
    }

    @Test
    fun truncatedLibraryDoesNotThrow() {
        val library = syntheticElf(tail = versionAndIdTail())
        val truncated = library.copyOfRange(0, 200)

        val fingerprint = FlutterArtifactInspector.inspectLibraries(
            FlutterLibraries("broken", "arm64-v8a", truncated, truncated, "libapp.so", "libflutter.so")
        ).getJSONObject("flutter")

        assertNotNull(fingerprint)
        assertEquals(JSONObject.NULL, fingerprint.get("snapshotHash"))
    }

    // ------------------------------------------------------------------ fixtures

    /** Stable projection of the fingerprint, so a diff names the field that moved. */
    private fun fingerprintOf(inventory: JSONObject): String {
        val flutter = inventory.getJSONObject("flutter")
        return listOf(
            flutter.optString("dartVersion"),
            flutter.optString("snapshotHash"),
            flutter.optString("architecture"),
            flutter.optString("os"),
            flutter.optString("compressedPointers"),
            flutter.optJSONArray("engineIds").strings().joinToString(","),
            flutter.optJSONArray("flags").strings().joinToString(","),
            flutter.optDouble("confidence").toString()
        ).joinToString("|")
    }

    /**
     * `org.json` 20250517 gives [org.json.JSONArray] a member `toList()`, which
     * shadows a same-named extension and throws on a null array. Hence the
     * distinct name.
     */
    private fun org.json.JSONArray?.strings(): List<String> {
        val array = this ?: return emptyList()
        return (0 until array.length()).map { array.optString(it) }
    }

    private val workRoot: File by lazy {
        File(System.getProperty("java.io.tmpdir"), "flutter-inspector-${System.nanoTime()}").apply { mkdirs() }
    }

    private fun versionAndIdTail(): ByteArray = "\u0000 3.12.2 (stable)\u0000x$engineId-".toByteArray(StandardCharsets.US_ASCII)

    private fun writeApk(library: ByteArray?): File {
        val apk = File(workRoot, "sample-${System.nanoTime()}.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(ByteArray(16))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/flutter_assets/AssetManifest.json"))
            zip.write("{}".toByteArray(StandardCharsets.US_ASCII))
            zip.closeEntry()
            if (library != null) {
                for (name in listOf("lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so")) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(library)
                    zip.closeEntry()
                }
            }
        }
        return apk
    }

    /**
     * Minimal ELF64 little-endian shared object with `.rodata`, `.dynstr`,
     * `.dynsym` and `.shstrtab`, exporting `_kDartVmSnapshotData` at the start of
     * `.rodata` followed by the 32-byte snapshot hash and the flag string.
     */
    private fun syntheticElf(tail: ByteArray): ByteArray {
        val prologue = "DART-SNAPSHOT-V1-XYZ".toByteArray(StandardCharsets.US_ASCII)
        val flags = "compressed-pointers\u0000".toByteArray(StandardCharsets.US_ASCII)
        val rodata = prologue + snapshotHash.toByteArray(StandardCharsets.US_ASCII) + flags + tail
        val dynstr = "\u0000_kDartVmSnapshotData\u0000".toByteArray(StandardCharsets.US_ASCII)
        val shstr = "\u0000.rodata\u0000.dynstr\u0000.dynsym\u0000.shstrtab\u0000".toByteArray(StandardCharsets.US_ASCII)

        val headerSize = 64
        val phSize = 56
        val rodataOffset = headerSize + phSize
        val dynstrOffset = rodataOffset + rodata.size
        val dynsymOffset = dynstrOffset + dynstr.size
        val shstrOffset = dynsymOffset + 24
        val sectionTableOffset = align8(shstrOffset + shstr.size)
        val total = sectionTableOffset + 5 * 64
        val bytes = ByteArray(total)

        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2
        bytes[5] = 1
        putU16(bytes, 16, 3)
        putU16(bytes, 18, 183)
        putU32(bytes, 20, 1)
        putU64(bytes, 32, headerSize.toLong())
        putU64(bytes, 40, sectionTableOffset.toLong())
        putU16(bytes, 52, headerSize)
        putU16(bytes, 54, phSize)
        putU16(bytes, 56, 1)
        putU16(bytes, 58, 64)
        putU16(bytes, 60, 5)
        putU16(bytes, 62, 4)

        putU32(bytes, headerSize, 1)
        putU32(bytes, headerSize + 4, 5)
        putU64(bytes, headerSize + 8, 0)
        putU64(bytes, headerSize + 16, 0x1000)
        putU64(bytes, headerSize + 24, 0x1000)
        putU64(bytes, headerSize + 32, total.toLong())
        putU64(bytes, headerSize + 40, total.toLong())
        putU64(bytes, headerSize + 48, 0x1000)

        rodata.copyInto(bytes, rodataOffset)
        dynstr.copyInto(bytes, dynstrOffset)
        shstr.copyInto(bytes, shstrOffset)

        val symbol = dynsymOffset
        putU32(bytes, symbol, 1)
        bytes[symbol + 4] = 0x12
        putU16(bytes, symbol + 6, 1)
        putU64(bytes, symbol + 8, 0x1000L + rodataOffset)
        putU64(bytes, symbol + 16, rodata.size.toLong())

        val sections = sectionTableOffset
        sectionHeader(bytes, sections, 0, 0, 0, 0, 0, 0)
        sectionHeader(bytes, sections + 64, 1, 1, (0x1000 + rodataOffset).toLong(), rodataOffset.toLong(), rodata.size.toLong(), 0)
        sectionHeader(bytes, sections + 128, 9, 3, 0, dynstrOffset.toLong(), dynstr.size.toLong(), 0)
        sectionHeader(bytes, sections + 192, 17, 11, 0, dynsymOffset.toLong(), 24, 24)
        sectionHeader(bytes, sections + 256, 25, 3, 0, shstrOffset.toLong(), shstr.size.toLong(), 0)
        putU32(bytes, sections + 192 + 40, 2)
        putU32(bytes, sections + 192 + 44, 1)
        return bytes
    }

    private fun sectionHeader(bytes: ByteArray, base: Int, name: Int, type: Int, addr: Long, offset: Long, size: Long, entsize: Long) {
        putU32(bytes, base, name)
        putU32(bytes, base + 4, type)
        putU64(bytes, base + 16, addr)
        putU64(bytes, base + 24, offset)
        putU64(bytes, base + 32, size)
        putU64(bytes, base + 56, entsize)
    }

    private fun align8(value: Int): Int = (value + 7) / 8 * 8

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        for (index in 0 until 4) bytes[offset + index] = ((value ushr (8 * index)) and 0xff).toByte()
    }

    private fun putU64(bytes: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 8) bytes[offset + index] = ((value ushr (8 * index)) and 0xff).toByte()
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        /** Mirrors FlutterByteScan's private window size. */
        const val SCAN_WINDOW_BYTES = 64 * 1024
    }
}
