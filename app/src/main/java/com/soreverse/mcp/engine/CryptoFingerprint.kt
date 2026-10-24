// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cryptographic constant fingerprinting behind crypto_const_fingerprint and
// crypto_hash_constants. Each needle is matched byte-exact against section
// contents; a hit names the algorithm, the offset, the section and the match
// length as evidence. Hash constants and cipher tables live in separate
// needle sets so the two tools answer different questions.
package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal object CryptoFingerprint {
    data class Needle(val algorithm: String, val kind: String, val bytes: ByteArray, val note: String)

    private fun le(v: Long): ByteArray = byteArrayOf(
        (v and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(),
        ((v shr 16) and 0xff).toByte(),
        ((v shr 24) and 0xff).toByte()
    )

    private fun be(v: Long): ByteArray = byteArrayOf(
        ((v shr 24) and 0xff).toByte(),
        ((v shr 16) and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(),
        (v and 0xff).toByte()
    )

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte() }

    private val AES_SBOX = hex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    private val AES_INV_SBOX = hex("52096ad53036a538bf40a39e81f3d7fb07ca34072594129be4864114b0a9a8ed")
    private val SM4_SBOX = hex("d690e9fecce13db716b614c228fb2c052b674a2426b7808768528fb34aef56ba")
    private val BLOWFISH_P = hex("243f6a8885a308d313198a2e037073c1") // leading pi digits of the P-array
    private val DES_IP = hex("3a322a221a120a023c342c241c140c04") // initial permutation table prefix (decimal 58..4)
    private val CHACHA_CONST = "expand 32-byte k".toByteArray(Charsets.US_ASCII)
    private val BASE64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toByteArray(Charsets.US_ASCII)
    private val TEA_DELTA = 0x9E3779B9L

    val cipherNeedles: List<Needle> = buildList {
        add(Needle("AES", "sbox", AES_SBOX, "AES S-box first 32 bytes"))
        add(Needle("AES", "inverse_sbox", AES_INV_SBOX, "AES inverse S-box first 32 bytes"))
        add(Needle("SM4", "sbox", SM4_SBOX, "SM4 S-box first 32 bytes"))
        add(Needle("Blowfish/Twofish", "p_array", BLOWFISH_P, "Blowfish P-array leading words"))
        add(Needle("DES/3DES", "ip_table", DES_IP, "DES initial permutation table prefix"))
        add(Needle("ChaCha/Salsa", "sigma_constant", CHACHA_CONST, "expand 32-byte k"))
        add(Needle("BASE64", "alphabet", BASE64_STD, "standard base64 alphabet"))
        add(Needle("TEA/XTEA/XXTEA", "delta", le(TEA_DELTA), "0x9E3779B9 little-endian (weak: also used by hash mixing)"))
        add(Needle("TEA/XTEA/XXTEA", "delta_be", be(TEA_DELTA), "0x9E3779B9 big-endian (weak)"))
    }

    private val MD5_T0 = hex("78a576d7") // 0xd76aa478 little-endian
    private val SHA256_K = hex("982f8a4291443771cffbc0b5a5dbb5e9") // first 4 K words little-endian
    private val SHA256_IV = hex("67e6096a85ae67bb72f36e3c3af54fa5") // first 4 IV words little-endian
    private val SHA1_IV = hex("67452301efcdab8998badcfe10325476c3d2e1f0")
    private val CRC32_POLY = le(0xEDB88320L)
    private val FNV32_PRIME = le(0x01000193L)
    private val XXH64_P1 = hex("87caeb855eb1379e") // 0x9E3779B185EBCA87 little-endian
    private val MURMUR3_C1 = le(0xCC9E2D51L)

    val hashNeedles: List<Needle> = buildList {
        add(Needle("MD5", "t_table", MD5_T0, "MD5 T-table first constant 0xd76aa478 little-endian"))
        add(Needle("MD5/SHA-1", "init_vector", SHA1_IV, "67452301..c3d2e1f0 (MD5 init lacks c3d2e1f0; SHA-1 has all five)"))
        add(Needle("SHA-256", "k_table", SHA256_K, "SHA-256 round constants first 4 words little-endian"))
        add(Needle("SHA-256", "init_vector", SHA256_IV, "SHA-256 IV first 4 words little-endian"))
        add(Needle("CRC32", "poly", CRC32_POLY, "reflected CRC-32 polynomial 0xEDB88320"))
        add(Needle("FNV-1", "prime", FNV32_PRIME, "FNV-32 prime 0x01000193"))
        add(Needle("xxHash64", "prime", XXH64_P1, "xxHash64 prime1 little-endian"))
        add(Needle("MurmurHash3", "constant", MURMUR3_C1, "MurmurHash3 c1 0xCC9E2D51 (weak)"))
    }

    private fun sectionBytesOf(data: ByteArray, section: SectionInfo): ByteArray? {
        if (section.type == 8L || section.size <= 0) return null
        val start = section.offset.toInt().coerceIn(0, data.size)
        val end = minOf(data.size, start + section.size.toInt())
        if (start >= end) return null
        return data.copyOfRange(start, end)
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        var i = from
        while (i <= haystack.size - needle.size) {
            var j = 0
            while (j < needle.size && haystack[i + j] == needle[j]) j++
            if (j == needle.size) return i
            i++
        }
        return -1
    }

    private fun scanNeedles(data: ByteArray, elf: ElfFile, needles: List<Needle>, limit: Int): JSONObject {
        val findings = JSONArray()
        var scannedSections = 0
        for (section in elf.sections) {
            val bytes = sectionBytesOf(data, section) ?: continue
            scannedSections++
            needles.forEach { n ->
                var from = 0
                var hits = 0
                while (findings.length() < limit) {
                    val idx = indexOf(bytes, n.bytes, from)
                    if (idx < 0) break
                    hits++
                    findings.put(
                        JSONObject()
                            .put("algorithm", n.algorithm)
                            .put("kind", n.kind)
                            .put("section", section.name)
                            .put("fileOffset", "0x${(section.offset + idx).toString(16)}")
                            .put("va", "0x${(section.addr + idx).toString(16)}")
                            .put("matchLength", n.bytes.size)
                            .put("note", n.note)
                            .put("occurrence", hits)
                    )
                    from = idx + 1
                    if (hits >= 3) break
                }
            }
        }
        val algorithms = JSONArray()
        val byAlg = LinkedHashMap<String, Int>()
        for (i in 0 until findings.length()) {
            byAlg.merge(findings.getJSONObject(i).getString("algorithm"), 1, Int::plus)
        }
        byAlg.forEach { (k, v) -> algorithms.put(JSONObject().put("algorithm", k).put("hits", v)) }
        return JSONObject()
            .put("scannedSections", scannedSections)
            .put("findingCount", findings.length())
            .put("algorithms", algorithms)
            .put("findings", findings)
            .put("method", "Byte-exact needle match over every sized section. Occurrences capped at 3 per needle.")
    }

    fun scanCipherConstants(data: ByteArray, elf: ElfFile, limit: Int = 200): JSONObject = scanNeedles(data, elf, cipherNeedles, limit)

    fun scanHashConstants(data: ByteArray, elf: ElfFile, limit: Int = 200): JSONObject = scanNeedles(data, elf, hashNeedles, limit)
}
