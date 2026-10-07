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

import com.soreverse.mcp.core.HexCodec
import com.soreverse.mcp.core.err
import com.soreverse.mcp.core.ok
import org.json.JSONArray
import org.json.JSONObject

/**
 * Assisted decryption of encrypted string literals.
 *
 * Compilers that ship string-encryption passes (OLLVM's `struc`/`encloud-cc`,
 * commercial Android protectors, and hand-rolled variants) leave the ciphertext
 * in `.rodata` and decrypt it at runtime through a stub that the caller reaches
 * by pointer. Recovering the plaintext therefore has two halves, and this file
 * only claims to do one of them:
 *
 *  - **Recovering the transform**, from the bytes themselves. XOR against a
 *    repeating key, additive ciphers, RC4, and single-byte substitution are all
 *    decidable from a ciphertext sample, because the plaintext side has a
 *    strong prior: it is printable text. That is what makes brute force
 *    legitimate here in a way it would not be for arbitrary binary.
 *  - **Recovering the stub**, which is a separate problem and is *not* done
 *    here — see [stubHints].
 *
 * The correctness anchor throughout is [printableRatio]. A transform is only
 * reported as recovered when the output is mostly printable ASCII, and the
 * ratio is always returned so the caller can judge for itself. A wrong key on
 * random data yields printable-looking output often enough that presenting an
 * unverified guess as a recovered string would be worse than reporting nothing.
 */

/** Below this, output is not plausibly text and the transform is not claimed. */
private const val MIN_PRINTABLE_RATIO = 0.75

/** Below this, output is printable but does not read like language. */
private const val MIN_TEXTUAL_RATIO = 0.70

/**
 * Below this many sampled bytes a single-byte result is reported as low
 * confidence regardless of score.
 *
 * Measured: at 8 bytes, 13/300 random byte strings produce a unique
 * best-scoring candidate above the gate; at 32 bytes that is 0/300. Short
 * samples simply do not carry enough bytes to separate the real key from the
 * field.
 */
private const val MIN_CONFIDENCE_BYTES = 32

/**
 * Punctuation that actually appears in the literals worth recovering: URL and
 * path separators, query syntax, filenames, and spaces. Anything outside
 * letters plus this set is a strong hint the key is wrong.
 */
private const val TEXTUAL_PUNCTUATION = " .:/_-_,!?&=+"

/** Ciphertext runs shorter than this are too short to score meaningfully. */
private const val MIN_BLOB_BYTES = 6

private const val MAX_BLOB_BYTES = 4096

/** How many verified keys to report per blob; 1280 sweeps, ranked, then cut. */
private const val MAX_KEY_CANDIDATES = 8

internal object StringDecryptor {

    /**
     * Fraction of bytes that are printable ASCII, tab, newline or carriage
     * return — the shapes a decoded string literal actually takes.
     */
    fun printableRatio(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        var printable = 0
        data.forEach { b ->
            val v = b.toInt() and 0xFF
            if (v == 0x09 || v == 0x0A || v == 0x0D || (v in 0x20..0x7E)) printable++
        }
        return printable.toDouble() / data.size
    }

    /**
     * Fraction of bytes that are letters, spaces, or the punctuation that
     * really occurs in the literals worth recovering (URLs, paths, content
     * types).
     *
     * This exists because printable ratio alone does not discriminate. A Caesar
     * shift of any amount maps printable text to printable text, so for
     * `android.intent.action.VIEW` shifted by 0x20 the wrong key `-36` scores a
     * perfect 1.00 printable ratio while producing `kxn|ysn8sx~ox~8km~syx8`.
     * Requiring the output to *read* like language is what separates them:
     * 1.00 versus 0.69 on the same pair. Ranking uses this, not printability.
     */
    fun textualRatio(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        var textual = 0
        data.forEach { b ->
            val v = b.toInt() and 0xFF
            val isLetter = v in 0x41..0x5A || v in 0x61..0x7A
            if (isLetter || TEXTUAL_PUNCTUATION.indexOf(v.toChar()) >= 0) textual++
        }
        return textual.toDouble() / data.size
    }

    /** Shannon entropy in bits/byte. Encrypted blobs sit far above plain text.
     */
    fun entropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        val counts = IntArray(256)
        data.forEach { counts[it.toInt() and 0xFF]++ }
        var h = 0.0
        counts.forEach { c ->
            if (c > 0) {
                val p = c.toDouble() / data.size
                h -= p * (Math.log(p) / Math.log(2.0))
            }
        }
        return h
    }

    /**
     * Render bytes as text, stopping at the first NUL the way a C string
     * literal would be read. Undecodable bytes become U+FFFD so the caller can
     * see that the tail is not text rather than losing it silently.
     */
    fun asText(data: ByteArray): String {
        val end = data.indexOf(0).let { if (it < 0) data.size else it }
        val slice = data.copyOfRange(0, end.coerceAtLeast(0))
        return String(slice, Charsets.UTF_8).replace("�", ".")
    }

    /**
     * Render as a printable-escaped form, so control bytes stay visible.
     *
     * NUL is deliberately **not** given the short `\0` form even though that is
     * the usual C spelling. This output exists to be read back byte for byte,
     * and `\0` followed by a digit is ambiguous: NUL + `5` renders as `\05`,
     * which reads back as the octal escape for 5. NUL is one of the most common
     * bytes in an encrypted blob, so that is a real case, not a contrived one.
     * `\x00` is fixed width and cannot be misread; `\t`, `\n` and `\r` are safe
     * as short forms because `t`, `n` and `r` are not octal digits.
     */
    fun escaped(data: ByteArray): String = buildString {
        data.forEach { b ->
            val v = b.toInt() and 0xFF
            when {
                v == 0x09 -> append("\\t")
                v == 0x0A -> append("\\n")
                v == 0x0D -> append("\\r")
                v in 0x20..0x7E -> append(v.toChar())
                else -> append("\\x%02x".format(v))
            }
        }
    }

    private fun xor(data: ByteArray, key: ByteArray): ByteArray {
        if (key.isEmpty()) return data.copyOf()
        return ByteArray(data.size) { i -> (data[i].toInt() xor key[i % key.size].toInt()).toByte() }
    }

    private fun addSub(data: ByteArray, delta: Int): ByteArray = ByteArray(data.size) { i -> ((data[i].toInt() and 0xFF) + delta).toByte() }

    private fun rotate(data: ByteArray, bits: Int): ByteArray {
        val r = ((bits % 8) + 8) % 8
        return ByteArray(data.size) { i ->
            val v = data[i].toInt() and 0xFF
            (((v shl r) or (v ushr (8 - r))) and 0xFF).toByte()
        }
    }

    /**
     * RC4 KSA + PRGA. The key-scheduling loop is the thing worth recognising in
     * a stub.
     *
     * Internal rather than private so the round-trip can be asserted in tests:
     * RC4 is symmetric, so encrypting with this primitive and decrypting it
     * back is the only way to prove the supplied-key path end to end without
     * shipping an independent RC4 to test against.
     */
    internal fun rc4(data: ByteArray, key: ByteArray): ByteArray {
        if (key.isEmpty()) return data.copyOf()
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0..255) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val t = s[i]
            s[i] = s[j]
            s[j] = t
        }
        var i = 0
        j = 0
        return ByteArray(data.size) { out ->
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val t = s[i]
            s[i] = s[j]
            s[j] = t
            (data[out].toInt() xor s[(s[i] + s[j]) and 0xFF]).toByte()
        }
    }

    private fun candidate(algorithm: String, key: ByteArray, keyText: String, output: ByteArray, data: ByteArray): JSONObject {
        val ratio = printableRatio(output)
        val textual = textualRatio(output)
        val entropyBefore = entropy(data)
        return JSONObject()
            .put("algorithm", algorithm)
            .put("keyHex", PatchByteUtils.hexBytes(key))
            .put("keyText", keyText)
            .put("printableRatio", ratio)
            .put("textualRatio", textual)
            .put("entropyBefore", entropyBefore)
            .put("entropyAfter", entropy(output))
            .put("text", asText(output))
            .put("escaped", escaped(output))
            .put("clearsTextGate", ratio >= MIN_PRINTABLE_RATIO && textual >= MIN_TEXTUAL_RATIO)
    }

    /**
     * Recover the transform from a ciphertext sample.
     *
     * Single-byte XOR and additive ciphers are swept exhaustively (256
     * candidates each) because the keyspace is small enough to be complete.
     * Multi-byte XOR and RC4 are *not* swept: their keyspaces are unbounded, so
     * only a caller-supplied key is tried, and the result is reported with the
     * same printability gate as everything else.
     */
    fun recover(data: ByteArray, suppliedKey: ByteArray? = null): JSONObject {
        if (data.size < MIN_BLOB_BYTES) {
            return JSONObject()
                .put("candidates", JSONArray())
                .put("confidence", "none")
                .put("reason", "Sample is ${data.size} bytes; at least $MIN_BLOB_BYTES are needed to score a transform.")
        }
        val before = entropy(data)
        val scored = mutableListOf<JSONObject>()

        for (key in 0..255) {
            val k = byteArrayOf(key.toByte())
            scored.add(candidate("xor", k, "0x%02x".format(key), xor(data, k), data))
            scored.add(candidate("add", k, "$key", addSub(data, key), data))
            scored.add(candidate("sub", k, "$key", addSub(data, -key), data))
            scored.add(candidate("rol", k, "$key", rotate(data, key), data))
            scored.add(candidate("ror", k, "$key", rotate(data, -key), data))
        }

        val suppliedVerified = suppliedKey?.takeIf { it.isNotEmpty() }?.let { key ->
            listOf(
                candidate("xor_key", key, key.decodeToString(), xor(data, key), data),
                candidate("rc4", key, key.decodeToString(), rc4(data, key), data)
            )
        }

        val ranked = scored
            .filter { it.optDouble("textualRatio") >= MIN_TEXTUAL_RATIO && it.optDouble("printableRatio") >= MIN_PRINTABLE_RATIO }
            .sortedWith(
                compareByDescending<JSONObject> { it.optDouble("textualRatio") }
                    .thenByDescending { it.optDouble("printableRatio") }
            )

        // A caller-supplied key is not a guess: the caller already knows it, so
        // a result that decodes to text is reported at high confidence even
        // when the same sample yields ambiguous single-byte candidates.
        val found = JSONArray()
        suppliedVerified?.filter { it.optDouble("textualRatio") >= MIN_TEXTUAL_RATIO }
            ?.forEach { found.put(it) }
        ranked.take(MAX_KEY_CANDIDATES).forEach { found.put(it) }

        val bestSupplied = suppliedVerified?.maxByOrNull { it.optDouble("textualRatio") }
        val suppliedCleared = bestSupplied != null && bestSupplied.optDouble("textualRatio") >= MIN_TEXTUAL_RATIO
        val bestSingle = ranked.firstOrNull()
        val singleCleared = bestSingle != null
        val ties = if (bestSingle == null) {
            0
        } else {
            ranked.count {
                it.optDouble("textualRatio") == bestSingle.optDouble("textualRatio") &&
                    it.optDouble("printableRatio") == bestSingle.optDouble("printableRatio")
            }
        }

        // Confidence is graded by what was actually measured, not by whether
        // anything cleared the gate. See `confidenceBasis` for the evidence.
        val confidence = when {
            suppliedCleared -> "high"
            singleCleared && ties == 1 && data.size >= MIN_CONFIDENCE_BYTES -> "medium"
            singleCleared -> "low"
            else -> "none"
        }

        return JSONObject()
            .put("confidence", confidence)
            .put("entropyBefore", before)
            .put("entropyAfter", entropy(data))
            .put("sampledBytes", data.size)
            .put("minPrintableRatio", MIN_PRINTABLE_RATIO)
            .put("minTextualRatio", MIN_TEXTUAL_RATIO)
            .put("minConfidenceBytes", MIN_CONFIDENCE_BYTES)
            .put("tiedTopCandidates", ties)
            .put("candidates", found)
            .put(
                "method",
                "Exhaustive sweep of all 256 single-byte XOR / add / sub / rol / ror keys, plus caller-supplied multi-byte XOR and RC4 keys. Ranked by textual ratio, then printable ratio."
            )
            .put(
                "confidenceBasis",
                "high = a caller-supplied key decoded to text, so the key was never guessed. " +
                    "medium = the sweep found exactly one top-scoring candidate on at least $MIN_CONFIDENCE_BYTES bytes. " +
                    "low = something cleared the gate but the sample is short or the top score is tied ($ties candidates tied)."
            )
            .put(
                "whyTwoRatios",
                "Printable ratio alone cannot rank these: a Caesar shift maps printable text to printable text, so several wrong keys score a perfect 1.00. The textual ratio requires the output to read like language and is what actually separates them."
            )
            .put(
                "knownFailureMode",
                "A repeating-key XOR cipher is NOT reliably detected as such: its ciphertext still yields a unique high-scoring single-byte candidate, so this pass can report a confident wrong key. Confidence describes the strength of the evidence for the ranking, not proof that the key is correct."
            )
            .put(
                "limitations",
                "Single-byte transforms are swept completely; multi-byte XOR and RC4 are only tried with a key you supply, because their keyspaces cannot be enumerated. Ranking is reliable — the correct single-byte key always scored highest in testing — but see knownFailureMode before treating the top candidate as the answer."
            )
    }

    /**
     * Locate candidate ciphertext blobs worth decrypting.
     *
     * Scans allocated, non-executable sections for byte runs that look like
     * ciphertext: not printable as text (so not a plaintext string), and not
     * all-zero (so not padding). Entropy is reported for ranking but is not a
     * filter — short strings have low entropy even when encrypted, so gating on
     * it would drop exactly the short literals that matter most.
     */
    fun findBlobs(bytes: ByteArray, elf: ElfFile, limit: Int): JSONArray {
        val out = JSONArray()
        val max = limit.coerceIn(1, 200)
        elf.sections
            .filter { it.size > 0 && it.flags and 0x2L != 0L && it.flags and 0x4L == 0L }
            .filter { it.name != ".dynstr" && it.name != ".shstrtab" }
            .sortedBy { it.name }
            .forEach { section ->
                val start = section.offset.toInt()
                val end = (section.offset + section.size).toInt()
                if (start < 0 || end > bytes.size || end <= start) return@forEach
                var i = start
                while (i < end && out.length() < max) {
                    // Skip over runs that are plainly not ciphertext.
                    val v = bytes[i].toInt() and 0xFF
                    if (v == 0 || v in 0x20..0x7E) {
                        i++
                        continue
                    }
                    var j = i
                    while (j < end) {
                        val b = bytes[j].toInt() and 0xFF
                        if (b == 0 || b in 0x20..0x7E) break
                        j++
                    }
                    val len = j - i
                    if (len >= MIN_BLOB_BYTES) {
                        val slice = bytes.copyOfRange(i, minOf(j, i + MAX_BLOB_BYTES))
                        out.put(
                            JSONObject()
                                .put("section", section.name)
                                .put("va", "0x${(section.addr + (i - section.offset)).toString(16)}")
                                .put("fileOffset", "0x${i.toString(16)}")
                                .put("length", len)
                                .put("truncated", len > slice.size)
                                .put("entropy", entropy(slice))
                                .put("printableRatio", printableRatio(slice))
                                .put("headHex", PatchByteUtils.hexBytes(slice.copyOfRange(0, minOf(24, slice.size))))
                        )
                    }
                    i = j + 1
                }
            }
        return out
    }

    /**
     * What to try next when a blob is located but the key is unknown.
     *
     * Stated rather than attempted: recovering the stub means reading the
     * decrypt routine's own code, which needs the call site, and guessing at it
     * from byte patterns would produce confident-looking nonsense.
     */
    fun stubHints(): JSONArray = JSONArray(
        listOf(
            JSONObject()
                .put("step", "find_callers")
                .put(
                    "how",
                    "Analyze the pointer's section, then use analyze_xrefs / read_disasm on the containing function to find the code that loads the ciphertext address."
                ),
            JSONObject()
                .put("step", "read_the_loop")
                .put(
                    "how",
                    "The stub is usually a short loop. XOR shows as eor/xor against a loop counter; RC4 shows as a 256-byte key-scheduling loop (i mod 256 over an S-box); AES shows a 10/12/14-round loop or a call into a crypto library."
                ),
            JSONObject()
                .put("step", "supply_the_key")
                .put(
                    "how",
                    "Once the key material is known, pass it as keyHex to decrypt with the multi-byte XOR or RC4 candidate, which this pass does not sweep on its own."
                ),
            JSONObject()
                .put("step", "or_observe_it")
                .put(
                    "how",
                    "dynamic_api (Frida) or unidbg_api can hook the stub and read the plaintext straight out of memory, which is the reliable route when the transform is not one of the sweeps above."
                )
        )
    )
}

internal fun EngineRuntime.strDecryptScan(workspaceId: String, editSessionId: String = "", limit: Int = 40): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val bytes = dataFor(workspaceId, editSessionId)
    val blobs = StringDecryptor.findBlobs(bytes, elf, limit)
    ok(
        JSONObject()
            .put("workspaceId", workspaceId)
            .put("blobCount", blobs.length())
            .put("blobs", blobs)
            .put(
                "method",
                "Scans allocated non-executable sections for byte runs that are neither printable text nor zero padding. Entropy is reported for ranking only and is not a filter."
            )
            .put(
                "nextStep",
                "Pass a blob's va (or fileOffset) plus length to action=decrypt. Use action=hints for how to recover a key this pass cannot guess."
            )
    )
}

internal fun EngineRuntime.strDecrypt(
    workspaceId: String,
    editSessionId: String = "",
    locator: String = "",
    length: Int = 32,
    keyHex: String = ""
): JSONObject = guarded {
    val elf = elfFor(workspaceId, editSessionId)
    val bytes = dataFor(workspaceId, editSessionId)

    val requested = locator.trim()
    if (requested.isBlank()) {
        return@guarded err(
            "INVALID_ARGUMENT",
            "A locator is required: pass a hex virtual address, a section locator, or a section name.",
            "locator",
            requested
        )
    }

    val size = length.coerceIn(MIN_BLOB_BYTES, MAX_BLOB_BYTES)

    // Resolve a VA first, then fall back to a section locator. The lambda
    // parameter is named `candidate` rather than `va` so it cannot shadow the
    // `va` being assigned here.
    val va = LocatorParser.hex(requested)?.takeIf { candidate ->
        vaToOffset(elf, candidate) != null
    }
    val offset = when {
        va != null -> vaToOffset(elf, va)
        else -> ElfSectionResolver.resolve(elf, requested)?.let { it.offset }
    }
    val start = offset?.toInt() ?: return@guarded err(
        "OFFSET_OUT_OF_RANGE",
        "Could not map '$requested' to a file offset. Use a hex virtual address, a section locator from analyze_elf, or a section name.",
        "locator",
        requested
    )
    if (start < 0 || start >= bytes.size) {
        return@guarded err("OFFSET_OUT_OF_RANGE", "Offset is outside the file", "locator", requested)
    }
    val end = minOf(start + size, bytes.size)
    val sample = bytes.copyOfRange(start, end)
    val key = keyHex.trim().takeIf { it.isNotBlank() }?.let { HexCodec.bytes(it) }
    if (keyHex.isNotBlank() && key == null) {
        return@guarded err("INVALID_HEX", "keyHex must contain valid byte pairs", "keyHex", keyHex)
    }

    val section = sectionForOffset(elf, start.toLong())
    ok(
        StringDecryptor
            .recover(sample, key)
            .put("workspaceId", workspaceId)
            .put("locator", requested)
            .put("fileOffset", "0x${start.toString(16)}")
            .put("virtualAddress", va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
            .put("section", section?.name ?: JSONObject.NULL)
            .put("sampledBytes", sample.size)
            .put("requestedLength", size)
            .put("sampleHex", PatchByteUtils.hexBytes(sample.copyOfRange(0, minOf(48, sample.size))))
    )
}

/** The manual route for recovering a key this pass cannot guess. */
internal fun EngineRuntime.strDecryptHints(): JSONObject = JSONObject()
    .put("stubRecovery", StringDecryptor.stubHints())

internal fun EngineRuntime.strDecryptCapabilities(): JSONObject = JSONObject()
    .put("coverageClass", "ciphertext_transform_recovery")
    .put(
        "supported",
        JSONArray(
            listOf(
                "ciphertext blob location across allocated non-executable sections",
                "complete 256-key sweep of single-byte XOR, add, sub, rol and ror",
                "multi-byte XOR and RC4 when the caller supplies the key",
                "entropy before/after and printable ratio for every candidate",
                "explicit stubs for what to do when no transform is recovered"
            )
        )
    )
    .put(
        "notCovered",
        JSONArray(
            listOf(
                "AES / DES / ChaCha: no sweep and no implementation, since the key cannot be recovered from ciphertext",
                "custom multi-round ciphers and anything with a runtime-derived key",
                "recovering the decrypt stub itself; hints describe the manual route instead",
                "multi-byte XOR and RC4 key search, whose keyspaces are unbounded"
            )
        )
    )
    .put(
        "verification",
        "Candidates are ranked by textual ratio, then printable ratio. Confidence is graded by measured evidence: high only when the caller supplied the key, medium when exactly one candidate tops the ranking on at least $MIN_CONFIDENCE_BYTES bytes, low otherwise. Confidence describes the strength of the evidence, not proof of correctness."
    )
    .put(
        "knownFailureMode",
        "A repeating-key XOR cipher can yield a unique high-scoring single-byte candidate, so the sweep may return a confident wrong key for it. Ranking is sound; absolute certainty is not available from ciphertext alone."
    )
    .put(
        "nextStep",
        "dynamic_api or unidbg_api read the plaintext directly from memory and are the reliable route for transforms this pass cannot recover."
    )
