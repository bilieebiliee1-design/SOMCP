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
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The correctness anchor for assisted string decryption is the textual ratio:
 * real string literals read like language, ciphertext does not. These tests pin
 * that anchor, and equally pin the limits of what it can prove — a
 * repeating-key cipher defeats the sweep, and pretending otherwise would be the
 * most damaging possible bug in a tool whose output an analyst may act on.
 */
class StringDecryptorTest {

    private fun text(s: String) = s.toByteArray(Charsets.UTF_8)

    /** XOR every byte with `key`, producing the ciphertext the sweep must undo. */
    private fun xor(src: ByteArray, key: Int) = ByteArray(src.size) { (src[it].toInt() xor key).toByte() }

    /** Long enough that the confidence gate is satisfied (>= 32 bytes). */
    private val longPlain = "GET /api/v1/user HTTP/1.1 Authorization Bearer token0123456789"

    private fun topCandidate(r: org.json.JSONObject) = r.getJSONArray("candidates").getJSONObject(0)

    @Test
    fun printableRatioIsOneForPlainText() {
        assertEquals(1.0, StringDecryptor.printableRatio(text("hello world")), 0.0001)
    }

    @Test
    fun printableRatioCountsTabsAndNewlines() {
        assertEquals(1.0, StringDecryptor.printableRatio(text("a\tb\nc\rd")), 0.0001)
    }

    @Test
    fun printableRatioIsZeroForEmpty() {
        assertEquals(0.0, StringDecryptor.printableRatio(ByteArray(0)), 0.0001)
    }

    @Test
    fun textualRatioSeparatesRealTextFromPlausibleGarbage() {
        // This is the whole reason textualRatio exists. A Caesar shift maps
        // printable text to printable text, so both of these score a perfect
        // 1.00 printable ratio and only the textual ratio tells them apart.
        assertEquals(1.0, StringDecryptor.printableRatio(text("android.intent.action.VIEW")), 0.0001)
        assertEquals(1.0, StringDecryptor.printableRatio(text("kxn|ysn8sx~ox~8km~syx8")), 0.0001)
        assertEquals(1.0, StringDecryptor.textualRatio(text("android.intent.action.VIEW")), 0.0001)
        assertTrue(
            "wrong-key output must score lower on the textual ratio",
            StringDecryptor.textualRatio(text("kxn|ysn8sx~ox~8km~syx8")) < 0.75
        )
    }

    @Test
    fun recoversTheSingleByteXorKeyAndRanksItFirst() {
        val plain = longPlain
        val r = StringDecryptor.recover(xor(text(plain), 0x5A))
        assertEquals(plain, topCandidate(r).getString("text"))
        assertEquals("xor", topCandidate(r).getString("algorithm"))
    }

    @Test
    fun ranksCandidatesByTextualRatio() {
        val r = StringDecryptor.recover(xor(text(longPlain), 0x37))
        val candidates = r.getJSONArray("candidates")
        assertTrue(candidates.length() > 1)
        for (i in 1 until candidates.length()) {
            val prev = candidates.getJSONObject(i - 1).getDouble("textualRatio")
            val cur = candidates.getJSONObject(i).getDouble("textualRatio")
            assertTrue("candidates must be ranked by textual ratio", prev >= cur)
        }
    }

    @Test
    fun additiveCipherIsRecoverableButReportedAsAmbiguous() {
        // A Caesar shift maps letters to letters, so several shifts of an
        // all-letters literal score a perfect textual ratio and genuinely tie.
        // The pass must surface the right answer AND say the ranking is not
        // decisive — claiming a single winner here would be a coin flip.
        val plain = "android.intent.action.VIEW"
        val cipher = ByteArray(plain.length) { (plain[it].code + 0x20).toByte() }
        val r = StringDecryptor.recover(cipher)
        val texts = (0 until r.getJSONArray("candidates").length())
            .map { r.getJSONArray("candidates").getJSONObject(it).getString("text") }
        assertTrue("correct plaintext must be among the candidates", texts.contains(plain))
        assertTrue(
            "a tied top score must not be reported as decisive",
            r.getString("confidence") == "low"
        )
        assertTrue("ties must be counted", r.getInt("tiedTopCandidates") > 1)
    }

    @Test
    fun xorOnAMixedLiteralHasADecisiveWinner() {
        // Unlike a pure-letter literal, a string containing digits and spaces
        // breaks the tie, which is why the XOR case can reach medium.
        val plain = longPlain
        val r = StringDecryptor.recover(xor(text(plain), 0x5A))
        assertEquals(plain, topCandidate(r).getString("text"))
        assertEquals(1, r.getInt("tiedTopCandidates"))
        assertEquals("medium", r.getString("confidence"))
    }

    @Test
    fun rc4RoundTripsWithASuppliedKey() {
        // RC4 is symmetric, so encrypting with the implementation's own primitive
        // and decrypting it back proves the supplied-key path works end to end.
        val key = text("secret")
        val plain = "rc4 encrypted payload for verification here"
        val cipher = StringDecryptor.rc4(text(plain), key)
        val r = StringDecryptor.recover(cipher, key)
        assertEquals("high", r.getString("confidence"))
        assertEquals("rc4", topCandidate(r).getString("algorithm"))
        assertEquals(plain, topCandidate(r).getString("text"))
    }

    @Test
    fun suppliedKeyOutranksTheSweepAndReportsHighConfidence() {
        // The caller already knows the key, so this is not a guess.
        val key = text("KEY")
        val plain = "multi byte xor string that is long enough to rank well"
        val cipher = ByteArray(plain.length) { (plain[it].code xor key[it % key.size].code).toByte() }
        val r = StringDecryptor.recover(cipher, key)
        assertEquals("high", r.getString("confidence"))
        val first = topCandidate(r)
        assertEquals("xor_key", first.getString("algorithm"))
        assertEquals(plain, first.getString("text"))
    }

    @Test
    fun refusesToScoreATooShortSample() {
        val r = StringDecryptor.recover(byteArrayOf(1, 2, 3))
        assertEquals("none", r.getString("confidence"))
        assertEquals(0, r.getJSONArray("candidates").length())
        assertTrue(r.getString("reason").contains("at least"))
    }

    @Test
    fun shortSamplesCannotReachHighConfidence() {
        // 20 bytes is below the confidence floor, so even a clean sweep result
        // must be reported as low rather than as proof.
        val plain = "shortish secret"
        val r = StringDecryptor.recover(xor(text(plain), 0x5A))
        assertTrue("short sample must not be high confidence", r.getString("confidence") != "high")
    }

    @Test
    fun randomNoiseIsNotReportedAsRecovered() {
        // Deterministic high-entropy bytes: nothing here should read as text.
        val noise = ByteArray(32) { i -> ((i * 37 + 11) % 251).toByte() }
        val r = StringDecryptor.recover(noise)
        assertEquals("none", r.getString("confidence"))
        assertEquals(0, r.getJSONArray("candidates").length())
    }

    @Test
    fun everyReportedCandidateClearsTheTextGate() {
        val r = StringDecryptor.recover(xor(text(longPlain), 0x11))
        val candidates = r.getJSONArray("candidates")
        for (i in 0 until candidates.length()) {
            val c = candidates.getJSONObject(i)
            assertTrue(
                "candidate below the textual gate was reported",
                c.getDouble("textualRatio") >= 0.70
            )
            assertTrue(c.getBoolean("clearsTextGate"))
        }
    }

    @Test
    fun statesTheRepeatingKeyFailureModeExplicitly() {
        // A repeating-key cipher CAN produce a confident wrong answer. The tool
        // has to say so, or an analyst will read `medium` as proof.
        val r = StringDecryptor.recover(xor(text(longPlain), 0x5A))
        assertTrue(
            "must document the repeating-key failure mode",
            r.getString("knownFailureMode").contains("repeating-key", ignoreCase = true)
        )
        assertTrue(
            "must explain what confidence is based on",
            r.getString("confidenceBasis").contains("medium")
        )
    }

    @Test
    fun confidenceBasisDistinguishesSuppliedFromGuessedKeys() {
        val guessed = StringDecryptor.recover(xor(text(longPlain), 0x5A))
        val key = text("KEY")
        val supplied = StringDecryptor.recover(
            ByteArray(longPlain.length) { (longPlain[it].code xor key[it % key.size].code).toByte() },
            key
        )
        assertEquals("high", supplied.getString("confidence"))
        assertTrue(
            "a guessed key must never claim high confidence",
            guessed.getString("confidence") != "high"
        )
    }

    @Test
    fun asTextStopsAtTheNulTerminator() {
        assertEquals("abc", StringDecryptor.asText(byteArrayOf(97, 98, 99, 0, 100, 101)))
    }

    @Test
    fun escapedKeepsControlBytesVisible() {
        assertEquals("a\\tb\\x00", StringDecryptor.escaped(byteArrayOf(97, 9, 98, 0)))
    }

    @Test
    fun xorDoesNotChangeEntropyAndTheToolDoesNotPretendOtherwise() {
        // A single-byte XOR is a bijection on byte values, so it preserves
        // Shannon entropy EXACTLY. Entropy therefore cannot detect XOR
        // ciphertext — which is why blob location keys on printability instead,
        // and why no test here claims entropy separates the two.
        val plain = text(longPlain)
        val cipher = xor(plain, 0x5A)
        assertEquals(StringDecryptor.entropy(plain), StringDecryptor.entropy(cipher), 1e-9)
        assertTrue(
            "printability is what distinguishes them",
            StringDecryptor.printableRatio(plain) > StringDecryptor.printableRatio(cipher)
        )
    }

    @Test
    fun entropyStillRisesForRepeatingKeyCiphertext() {
        // Unlike single-byte XOR, a repeating key raises entropy because the
        // same plaintext byte maps to different ciphertext bytes by position.
        val plain = text(longPlain)
        val key = text("KEY")
        val cipher = ByteArray(plain.size) { (plain[it].toInt() xor key[it % key.size].toInt()).toByte() }
        assertTrue(
            StringDecryptor.entropy(cipher) >= StringDecryptor.entropy(plain)
        )
    }

    @Test
    fun blobScanSkipsPlainTextAndZeroPadding() {
        val data = ByteArray(64)
        text("hello world this is plaintext").copyInto(data, 0)
        for (i in 32 until 48) data[i] = (0x90 + i).toByte()
        val section = SectionInfo(
            name = ".rodata",
            type = 1,
            flags = 0x2L,
            addr = 0x1000,
            offset = 0,
            size = 64,
            link = 0,
            info = 0,
            addralign = 1,
            entsize = 0
        )
        val elf = ElfFile(
            data = data,
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = 0,
            sections = listOf(section),
            symbols = emptyList(),
            dynSymbols = emptyList(),
            relocations = emptyList(),
            strings = emptyList()
        )
        val blobs = StringDecryptor.findBlobs(data, elf, 40)
        assertEquals("only the non-text run should be a blob", 1, blobs.length())
        assertEquals(16, blobs.getJSONObject(0).getInt("length"))
    }

    @Test
    fun blobScanIgnoresNonAllocatedAndExecutableSections() {
        val data = ByteArray(32) { (0x90 + it).toByte() }
        val sections = listOf(
            SectionInfo(".text", 1, 0x6L, 0x1000, 0, 32, 0, 0, 1, 0),
            SectionInfo(".comment", 1, 0x0L, 0x2000, 0, 32, 0, 0, 1, 0)
        )
        val elf = ElfFile(
            data = data,
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = 0,
            sections = sections,
            symbols = emptyList(),
            dynSymbols = emptyList(),
            relocations = emptyList(),
            strings = emptyList()
        )
        assertEquals(0, StringDecryptor.findBlobs(data, elf, 40).length())
    }

    @Test
    fun blobScanRespectsTheBlobLimit() {
        val data = ByteArray(256)
        for (i in 0 until 256 step 16) {
            for (j in 0 until 8) data[i + j] = (0x80 + i + j).toByte()
        }
        val section = SectionInfo(".rodata", 1, 0x2L, 0x1000, 0, 256, 0, 0, 1, 0)
        val elf = ElfFile(
            data = data,
            bits = 64,
            littleEndian = true,
            type = 3,
            machine = 183,
            entry = 0,
            sections = listOf(section),
            symbols = emptyList(),
            dynSymbols = emptyList(),
            relocations = emptyList(),
            strings = emptyList()
        )
        assertTrue(StringDecryptor.findBlobs(data, elf, 3).length() <= 3)
    }

    @Test
    fun escapeOutputNeverThrowsOnArbitraryBytes() {
        val all = ByteArray(256) { it.toByte() }
        assertTrue(StringDecryptor.escaped(all).isNotEmpty())
        assertFalse(StringDecryptor.printableRatio(all) > 0.5)
    }
}
