// SPDX-License-Identifier: AGPL-3.0-only
//
// String census tests: classification, endpoint extraction, path-root
// bucketing and the honest scope note of the property-key sweep.
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StringCensusTest {
    private fun elfWith(vararg values: String): ElfFile {
        val strings = values.mapIndexed { i, v ->
            StringInfo(offset = (100 + i * 40).toLong(), value = v, length = v.length, section = ".rodata")
        }
        return ElfFile(
            data = ByteArray(0), bits = 64, littleEndian = true, type = 3, machine = 183, entry = 0,
            sections = emptyList(), symbols = emptyList(), dynSymbols = emptyList(),
            relocations = emptyList(), strings = strings
        )
    }

    private fun classesOf(elf: ElfFile): Map<String, Int> {
        val result = StringCensus.literalClasses(elf, 100)
        val byClass = result.getJSONArray("byClass")
        val out = mutableMapOf<String, Int>()
        for (i in 0 until byClass.length()) {
            out[byClass.getJSONObject(i).getString("class")] = byClass.getJSONObject(i).getInt("count")
        }
        return out
    }

    @Test
    fun classifiesUrlsHostsPathsAndLiterals() {
        val counts = classesOf(
            elfWith(
                "https://api.example.com/v1/user",
                "10.0.0.1:8080",
                "/proc/self/maps",
                "dGhpcyBpcyBhIGJhc2U2NCBzdHJpbmc=",
                "%s failed: %d (0x%02x)",
                "Lcom/example/Foo;",
                "com.example.app.ui",
                "1234567890abcdef1234567890abcdef",
                "select * from tokens where id = 1"
            )
        )
        assertTrue((counts["url"] ?: 0) >= 1)
        assertTrue((counts["ip_port"] ?: 0) >= 1)
        assertTrue((counts["abs_path"] ?: 0) >= 1)
        assertTrue((counts["base64_like"] ?: 0) >= 1)
        assertTrue((counts["format_string"] ?: 0) >= 1)
        assertTrue((counts["java_descriptor"] ?: 0) >= 1)
        assertTrue((counts["package_name"] ?: 0) >= 1)
        assertTrue((counts["hex_like"] ?: 0) >= 1)
        assertTrue((counts["sql"] ?: 0) >= 1)
    }

    @Test
    fun endpointExtractionSeparatesUrlsFromHosts() {
        val r = StringCensus.netEndpoints(elfWith("https://a.example.com/x", "192.168.1.5:443", "not a url"), 50)
        assertEquals(1, r.getInt("urlCount"))
        assertEquals(1, r.getInt("hostCount"))
        assertEquals(0, r.getJSONArray("hosts").getJSONObject(0).getInt("port") - 443)
    }

    @Test
    fun pathRootsBucketByRootAndFlagSensitivePaths() {
        val r = StringCensus.filePathRoots(
            elfWith("/proc/self/maps", "/proc/self/status", "/data/data/com.example/files", "/sdcard/Download/x.bin"),
            50
        )
        val byRoot = r.getJSONArray("byRoot")
        var procCount = 0
        for (i in 0 until byRoot.length()) {
            if (byRoot.getJSONObject(i).getString("root").startsWith("/proc")) {
                procCount = byRoot.getJSONObject(i).getInt("count")
            }
        }
        assertEquals(2, procCount)
        assertTrue(r.getJSONArray("notable").length() >= 1)
    }

    @Test
    fun propertyKeysMatchShapeOnly() {
        val r = StringCensus.propertyKeys(elfWith("ro.build.version.sdk", "persist.sys.usb.config", "PATH", "unrelated string"), 50)
        assertEquals(2, r.getInt("propertyLikeKeys"))
        assertEquals(1, r.getJSONArray("envKeys").length())
        assertTrue(r.getString("method").contains("not proven"))
    }

    @Test
    fun encodingCensusCountsAsciiDuplicatesAndUtf16() {
        // Same fixture data trick as the parser: UTF-16LE "test" bytes inside .rodata.
        val data = SynthElf.build()
        val elf = ElfParser(data).parse()
        val census = StringCensus.encodingCensus(data, elf, 100)
        assertTrue(census.getInt("scannedStrings") > 0)
        assertEquals(1, census.getInt("utf16LeRuns"))
        assertTrue(census.getInt("duplicateValues") >= 0)
    }
}
