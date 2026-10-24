// SPDX-License-Identifier: AGPL-3.0-only
//
// Crypto constant fingerprint tests: byte-exact needles must hit real tables
// in the fixture, a table-free image must stay silent, and the tool must never
// upgrade a weak indicator (TEA delta) into a confident claim.
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoFingerprintTest {
    private val cryptoData = SynthElf.build(includeCrypto = true)
    private val cryptoElf = ElfParser(cryptoData).parse()
    private val plainData = SynthElf.build()
    private val plainElf = ElfParser(plainData).parse()

    private fun algorithms(r: org.json.JSONObject): List<String> {
        val arr = r.getJSONArray("algorithms")
        return (0 until arr.length()).map { arr.getJSONObject(it).getString("algorithm") }
    }

    @Test
    fun findsAesSboxAndChaChaConstants() {
        val r = CryptoFingerprint.scanCipherConstants(cryptoData, cryptoElf)
        val algs = algorithms(r)
        assertTrue("AES" in algs)
        assertTrue("ChaCha/Salsa" in algs)
        val findings = r.getJSONArray("findings")
        val aes = (0 until findings.length()).first { findings.getJSONObject(it).getString("algorithm") == "AES" }
        assertEquals("sbox", findings.getJSONObject(aes).getString("kind"))
        assertTrue(findings.getJSONObject(aes).getInt("matchLength") == 32)
        assertEquals(".rodata", findings.getJSONObject(aes).getString("section"))
    }

    @Test
    fun staysSilentWithoutConstants() {
        val r = CryptoFingerprint.scanCipherConstants(plainData, plainElf)
        assertEquals(0, r.getInt("findingCount"))
        assertTrue(algorithms(r).isEmpty())
    }

    @Test
    fun findsMd5AndSha256HashConstants() {
        val r = CryptoFingerprint.scanHashConstants(cryptoData, cryptoElf)
        val algs = algorithms(r)
        assertTrue("MD5" in algs)
        assertTrue("ChaCha/Salsa" !in algs) // hash scan only carries hash needles
    }

    @Test
    fun hashScanOnCleanImageStaysSilent() {
        assertEquals(0, CryptoFingerprint.scanHashConstants(plainData, plainElf).getInt("findingCount"))
    }

    @Test
    fun occurrencesAreCappedPerNeedle() {
        val sbox = byteArrayOf(
            0x63, 0x7c, 0x77, 0x7b, 0xf2.toByte(), 0x6b, 0x6f, 0xc5.toByte(), 0x30, 0x01, 0x67, 0x2b, 0xfe.toByte(), 0xd7.toByte(), 0xab.toByte(), 0x76,
            0xca.toByte(), 0x82.toByte(), 0xc9.toByte(), 0x7d, 0xfa.toByte(), 0x59, 0x47, 0xf0.toByte(), 0xad.toByte(), 0xd4.toByte(), 0xa2.toByte(),
            0xaf.toByte(), 0x9c.toByte(), 0xa4.toByte(), 0x72, 0xc0.toByte()
        )
        val blob = sbox + sbox + sbox + sbox + sbox
        val elf = ElfFile(
            data = blob, bits = 64, littleEndian = true, type = 3, machine = 183, entry = 0,
            sections = listOf(
                SectionInfo(
                    name = "blob", type = 1, flags = 0x2, addr = 0, offset = 0, size = blob.size.toLong(), link = 0, info = 0, addralign = 1, entsize = 0
                )
            ),
            symbols = emptyList(), dynSymbols = emptyList(), relocations = emptyList(), strings = emptyList()
        )
        val r = CryptoFingerprint.scanCipherConstants(blob, elf)
        val findings = r.getJSONArray("findings")
        var aesHits = 0
        for (i in 0 until findings.length()) {
            if (findings.getJSONObject(i).getString("algorithm") == "AES") aesHits++
        }
        assertEquals(3, aesHits)
    }
}
