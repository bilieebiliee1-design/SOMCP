// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure JVM-testable APK analysis behind apk_sig_verify, apk_cert_info,
// apk_zip_anomaly and apk_abi_coverage. The signing-block digest recomputation
// follows the APK Signature Scheme v2 spec: chunk digest = hash(0xa5 ||
// uint32le(chunkLen) || chunk) over 1MB chunks of sections 1/3/4, top digest =
// hash(0x5a || uint32le(chunkCount) || concat(chunk digests)), and the EOCD
// central-directory offset field treated as the signing-block offset.
package com.soreverse.mcp.engine

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.Inflater
import org.json.JSONArray
import org.json.JSONObject

internal object ApkSigTools {
    private const val CHUNK_SIZE = 1024 * 1024
    private const val CD_SIG = 0x02014b50L
    private const val LFH_SIG = 0x04034b50L
    private const val EOCD_SIG = 0x06054b50L
    private const val V2_BLOCK_ID = 0x7109871aL
    private const val V3_BLOCK_ID = 0xf05368c0L
    private const val DIGEST_CHUNKED_SHA256 = 0x0301L
    private const val DIGEST_CHUNKED_SHA512 = 0x0302L

    private fun u16(b: ByteArray, o: Int): Int {
        if (o < 0 || o + 2 > b.size) return 0
        return (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    }

    private fun u32(b: ByteArray, o: Int): Long {
        if (o < 0 || o + 4 > b.size) return 0L
        return (b[o].toLong() and 0xff) or ((b[o + 1].toLong() and 0xff) shl 8) or
            ((b[o + 2].toLong() and 0xff) shl 16) or ((b[o + 3].toLong() and 0xff) shl 24)
    }

    private fun put32le(out: ByteArrayOutputStream, v: Int) {
        out.write(v and 0xff)
        out.write((v shr 8) and 0xff)
        out.write((v shr 16) and 0xff)
        out.write((v shr 24) and 0xff)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun hexStr(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    // ── ZIP layout ──

    data class CdEntry(
        val name: String,
        val method: Int,
        val flags: Int,
        val crc: Long,
        val csize: Long,
        val usize: Long,
        val localOffset: Long,
        val extraLen: Int,
        val commentLen: Int
    )

    data class ZipLayout(val eocdOffset: Int, val cdOffset: Int, val cdSize: Int, val entries: List<CdEntry>)

    fun parseZipLayout(bytes: ByteArray): ZipLayout? {
        if (bytes.size < 22) return null
        var eocd = -1
        val scanFrom = maxOf(0, bytes.size - 22 - 65535)
        var i = bytes.size - 22
        while (i >= scanFrom) {
            if (u32(bytes, i) == EOCD_SIG && u16(bytes, i + 20) == bytes.size - i - 22) {
                eocd = i
                break
            }
            i--
        }
        if (eocd < 0) return null
        val cdOffset = u32(bytes, eocd + 16).toInt()
        val cdSize = u32(bytes, eocd + 12).toInt()
        if (cdOffset < 0 || cdOffset >= bytes.size) return null
        val entries = mutableListOf<CdEntry>()
        var p = cdOffset
        while (p + 46 <= bytes.size && u32(bytes, p) == CD_SIG && entries.size <= 65536) {
            val nameLen = u16(bytes, p + 28)
            val extraLen = u16(bytes, p + 30)
            val commentLen = u16(bytes, p + 32)
            val nameEnd = p + 46 + nameLen
            if (nameEnd > bytes.size) break
            entries += CdEntry(
                name = String(bytes, p + 46, nameLen, Charsets.UTF_8),
                method = u16(bytes, p + 10),
                flags = u16(bytes, p + 8),
                crc = u32(bytes, p + 16),
                csize = u32(bytes, p + 20),
                usize = u32(bytes, p + 24),
                localOffset = u32(bytes, p + 42),
                extraLen = extraLen,
                commentLen = commentLen
            )
            p = nameEnd + extraLen + commentLen
        }
        return ZipLayout(eocd, cdOffset, cdSize, entries)
    }

    /** Reads one entry's decompressed bytes via its local file header. */
    fun readEntry(bytes: ByteArray, entry: CdEntry, maxBytes: Int): ByteArray? {
        val off = entry.localOffset.toInt()
        if (off < 0 || off + 30 > bytes.size || u32(bytes, off) != LFH_SIG) return null
        val nameLen = u16(bytes, off + 26)
        val extraLen = u16(bytes, off + 28)
        val dataStart = off + 30 + nameLen + extraLen
        if (dataStart < 0 || dataStart + entry.csize > bytes.size) return null
        if (entry.csize > maxBytes) return null
        val raw = bytes.copyOfRange(dataStart, dataStart + entry.csize.toInt())
        return when (entry.method) {
            0 -> raw
            8 -> try {
                val inflater = Inflater()
                inflater.setInput(raw)
                val out = ByteArrayOutputStream()
                val buf = ByteArray(64 * 1024)
                while (!inflater.finished()) {
                    val n = inflater.inflate(buf)
                    if (n == 0 && inflater.needsInput()) break
                    if (out.size() + n > maxBytes) {
                        inflater.end()
                        return null
                    }
                    out.write(buf, 0, n)
                }
                inflater.end()
                out.toByteArray()
            } catch (error: java.util.zip.DataFormatException) {
                null
            }
            else -> null
        }
    }

    // ── APK Signing Block ──

    data class SigningBlock(val start: Int, val end: Int, val pairs: List<Pair<Long, ByteArray>>)

    fun parseSigningBlock(bytes: ByteArray, layout: ZipLayout): SigningBlock? {
        val cdOffset = layout.cdOffset
        if (cdOffset < 32) return null
        val magic = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
        val magicStart = cdOffset - 24
        if (magicStart < 0) return null
        for (i in magic.indices) {
            if (bytes[magicStart + 8 + i] != magic[i]) return null
        }
        val sizeFooter = u64(bytes, magicStart)
        // sizeFooter counts everything after the leading size field: blockStart = cdOffset - 8 - sizeFooter.
        val blockStart = cdOffset - 8 - sizeFooter.toInt()
        if (blockStart < 0 || u64(bytes, blockStart) != sizeFooter) return null
        val pairs = mutableListOf<Pair<Long, ByteArray>>()
        var p = blockStart + 8
        val pairsEnd = magicStart
        while (p + 12 <= pairsEnd) {
            val pairLen = u64(bytes, p).toInt()
            if (pairLen <= 4 || p + 8 + pairLen > pairsEnd) break
            val id = u32(bytes, p + 8)
            pairs += id to bytes.copyOfRange(p + 12, p + 8 + pairLen)
            p += 8 + pairLen
        }
        return SigningBlock(blockStart, cdOffset, pairs)
    }

    private fun u64(b: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[o + i].toLong() and 0xff)
        return v
    }

    private fun signerBlocks(value: ByteArray): List<ByteArray> {
        val signers = mutableListOf<ByteArray>()
        var p = 0
        while (p + 4 <= value.size && signers.size <= 64) {
            val len = u32(value, p).toInt()
            if (len <= 0 || p + 4 + len > value.size) break
            signers += value.copyOfRange(p + 4, p + 4 + len)
            p += 4 + len
        }
        return signers
    }

    private data class SignerData(
        val minSdk: Int?,
        val maxSdk: Int?,
        val digests: List<Pair<Long, ByteArray>>,
        val certs: List<ByteArray>,
        val signatures: List<Pair<Long, ByteArray>>,
        val signedData: ByteArray
    )

    private fun parseSigner(signer: ByteArray, v3: Boolean): SignerData? {
        var p = 0
        var minSdk: Int? = null
        var maxSdk: Int? = null
        if (v3) {
            if (signer.size < 8) return null
            minSdk = u32(signer, 0).toInt()
            maxSdk = u32(signer, 4).toInt()
            p = 8
        }
        if (p + 4 > signer.size) return null
        val sdLen = u32(signer, p).toInt()
        if (sdLen <= 0 || p + 4 + sdLen > signer.size) return null
        val signedData = signer.copyOfRange(p + 4, p + 4 + sdLen)
        var q = p + 4 + sdLen
        if (q + 4 > signer.size) return null
        val sigsLen = u32(signer, q).toInt()
        val sigsRaw = if (q + 4 + sigsLen <= signer.size) signer.copyOfRange(q + 4, q + 4 + sigsLen) else ByteArray(0)
        q += 4 + sigsLen
        val signatures = mutableListOf<Pair<Long, ByteArray>>()
        var r = 0
        while (r + 4 <= sigsRaw.size) {
            val sigLen = u32(sigsRaw, r).toInt()
            if (sigLen <= 4 || r + 4 + sigLen > sigsRaw.size) break
            signatures += u32(sigsRaw, r + 4) to sigsRaw.copyOfRange(r + 8, r + 4 + sigLen)
            r += 4 + sigLen
        }
        if (q + 4 > signer.size) return null
        val pkLen = u32(signer, q).toInt()
        q += 4 + pkLen
        // signed data: digests, certs, additional attributes
        var s = 0
        val digests = mutableListOf<Pair<Long, ByteArray>>()
        val certs = mutableListOf<ByteArray>()
        if (s + 4 <= signedData.size) {
            val dLen = u32(signedData, s).toInt()
            val dRaw = signedData.copyOfRange(s + 4, minOf(signedData.size, s + 4 + dLen))
            var t = 0
            while (t + 4 <= dRaw.size) {
                val recLen = u32(dRaw, t).toInt()
                if (recLen <= 4 || t + 4 + recLen > dRaw.size) break
                digests += u32(dRaw, t + 4) to dRaw.copyOfRange(t + 8, t + 4 + recLen)
                t += 4 + recLen
            }
            s += 4 + dLen
        }
        if (s + 4 <= signedData.size) {
            val cLen = u32(signedData, s).toInt()
            val cRaw = signedData.copyOfRange(s + 4, minOf(signedData.size, s + 4 + cLen))
            var t = 0
            while (t + 4 <= cRaw.size) {
                val certLen = u32(cRaw, t).toInt()
                if (certLen <= 0 || t + 4 + certLen > cRaw.size) break
                certs += cRaw.copyOfRange(t + 4, t + 4 + certLen)
                t += 4 + certLen
            }
        }
        return SignerData(minSdk, maxSdk, digests, certs, signatures, signedData)
    }

    private fun signatureAlgorithmName(id: Long): String = when (id) {
        0x0101L -> "RSASSA-PSS with SHA2-256"
        0x0102L -> "RSASSA-PSS with SHA2-512"
        0x0103L -> "RSASSA-PKCS1-v1_5 with SHA2-256"
        0x0104L -> "RSASSA-PKCS1-v1_5 with SHA2-512"
        0x0201L -> "ECDSA with SHA2-256"
        0x0202L -> "ECDSA with SHA2-512"
        0x0301L -> "DSA with SHA2-256"
        0x0421L -> "Verity RSA PKCS1 SHA2-256"
        0x0423L -> "Verity ECDSA SHA2-256"
        0x0425L -> "Verity DSA SHA2-256"
        else -> "UNKNOWN_0x${id.toString(16)}"
    }

    private fun verifySignature(signedData: ByteArray, signature: ByteArray, algorithmId: Long, cert: X509Certificate): String {
        val (algorithm, pss) = when (algorithmId) {
            0x0101L -> "SHA256withRSA/PSS" to 32
            0x0102L -> "SHA512withRSA/PSS" to 64
            0x0103L -> "SHA256withRSA" to 0
            0x0104L -> "SHA512withRSA" to 0
            0x0201L -> "SHA256withECDSA" to 0
            0x0202L -> "SHA512withECDSA" to 0
            0x0301L -> "SHA256withDSA" to 0
            else -> return "unsupported_algorithm"
        }
        return try {
            val verifier = Signature.getInstance(algorithm)
            if (pss > 0) {
                val digestLen = pss
                verifier.setParameter(
                    java.security.spec.PSSParameterSpec(
                        "SHA-${
                            if (digestLen == 32) "256" else "512"
                        }",
                        "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        digestLen,
                        1
                    )
                )
            }
            verifier.initVerify(cert.publicKey)
            verifier.update(signedData)
            if (verifier.verify(signature)) "verified" else "invalid"
        } catch (error: Exception) {
            "unverified:${error.javaClass.simpleName}"
        }
    }

    /**
     * Spec content digest. Sections: ZIP entries [0, blockStart), central
     * directory [cdOffset, eocdOffset), EOCD digested from a patched copy whose
     * CD-offset field contains the signing-block offset instead.
     */
    internal fun computeContentDigest(apk: ByteArray, blockStart: Int, cdOffset: Int, eocdOffset: Int, shaBits: Int): ByteArray {
        val eocdCopy = apk.copyOfRange(eocdOffset, apk.size)
        if (eocdCopy.size >= 20) put32leAt(eocdCopy, 16, blockStart)
        data class Section(val start: Int, val end: Int, val source: ByteArray)
        val sections = listOf(
            Section(0, blockStart, apk),
            Section(cdOffset, eocdOffset, apk),
            Section(0, eocdCopy.size, eocdCopy)
        )
        val md = MessageDigest.getInstance("SHA-$shaBits")
        val chunkDigests = mutableListOf<ByteArray>()
        var chunkCount = 0
        sections.forEach { sec ->
            var pos = sec.start
            while (pos < sec.end) {
                val chunkLen = minOf(CHUNK_SIZE, sec.end - pos)
                md.update(0xa5.toByte())
                put32le(md, chunkLen)
                md.update(sec.source, pos, chunkLen)
                chunkDigests += md.digest()
                chunkCount++
                pos += chunkLen
            }
        }
        md.update(0x5a.toByte())
        put32le(md, chunkCount)
        chunkDigests.forEach { md.update(it) }
        return md.digest()
    }

    private fun put32leAt(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xff).toByte()
        b[o + 1] = ((v shr 8) and 0xff).toByte()
        b[o + 2] = ((v shr 16) and 0xff).toByte()
        b[o + 3] = ((v shr 24) and 0xff).toByte()
    }

    private fun put32le(md: MessageDigest, v: Int) {
        md.update((v and 0xff).toByte())
        md.update(((v shr 8) and 0xff).toByte())
        md.update(((v shr 16) and 0xff).toByte())
        md.update(((v shr 24) and 0xff).toByte())
    }

    private fun digestJson(id: Long, expected: ByteArray, computed: ByteArray?): JSONObject {
        val item = JSONObject()
            .put("digestAlgorithm", "0x${id.toString(16)}")
            .put(
                "algorithmName",
                when (id) {
                    DIGEST_CHUNKED_SHA256 -> "CHUNKED_SHA256"
                    DIGEST_CHUNKED_SHA512 -> "CHUNKED_SHA512"
                    else -> "not_recomputed_0x${id.toString(16)}"
                }
            )
            .put("expected", hexStr(expected))
        if (computed != null) {
            item.put("computed", hexStr(computed)).put("match", computed.contentEquals(expected))
        }
        return item
    }

    /** Full v2/v3 parse + digest recompute + signature verification. */
    fun verify(apk: ByteArray): JSONObject {
        val layout = parseZipLayout(apk)
            ?: return err("APK_INVALID", "not a ZIP: EOCD not found")
        val block = parseSigningBlock(apk, layout)
        val result = JSONObject()
            .put("eocdOffset", layout.eocdOffset)
            .put("centralDirectoryOffset", layout.cdOffset)
        val v1 = layout.entries.any {
            it.name.startsWith("META-INF/", true) &&
                (it.name.endsWith(".RSA", true) || it.name.endsWith(".DSA", true) || it.name.endsWith(".EC", true))
        }
        result.put("v1", JSONObject().put("present", v1).put("scope", "META-INF signature file presence only"))
        if (block == null) {
            result.put("v2", JSONObject().put("present", false)).put("v3", JSONObject().put("present", false))
            result.put("verdict", if (v1) "v1_only" else "unsigned")
            return result
        }
        result.put("signingBlock", JSONObject().put("start", block.start).put("end", block.end).put("pairCount", block.pairs.size))
        val v2Value = block.pairs.firstOrNull { it.first == V2_BLOCK_ID }?.second
        val v3Value = block.pairs.firstOrNull { it.first == V3_BLOCK_ID }?.second
        var anyVerified = false
        var anyInvalid = false
        val signerReports = JSONArray()
        fun handleSigners(value: ByteArray?, v3: Boolean, scheme: String) {
            result.put(if (v3) "v3" else "v2", JSONObject().put("present", value != null))
            val signerList = value?.let { signerBlocks(it) } ?: return
            signerList.forEach { signer ->
                val parsed = parseSigner(signer, v3) ?: return@forEach
                val signerReport = JSONObject()
                    .put("scheme", scheme)
                    .put("certCount", parsed.certs.size)
                parsed.certs.firstOrNull()?.let { der ->
                    runCatching {
                        val cert = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
                        signerReport.put("certSha256", sha256(der))
                        signerReport.put("subject", cert.subjectDN.name.take(160))
                        if (parsed.minSdk != null) signerReport.put("minSdk", parsed.minSdk).put("maxSdk", parsed.maxSdk)
                        // digest recompute per signer's digest records
                        val digestReports = JSONArray()
                        parsed.digests.forEach { (id, expected) ->
                            val computed = when (id) {
                                DIGEST_CHUNKED_SHA256 ->
                                    computeContentDigest(apk, block.start, layout.cdOffset, layout.eocdOffset, 256)
                                DIGEST_CHUNKED_SHA512 ->
                                    computeContentDigest(apk, block.start, layout.cdOffset, layout.eocdOffset, 512)
                                else -> null
                            }
                            digestReports.put(digestJson(id, expected, computed))
                        }
                        signerReport.put("digests", digestReports)
                        // signature verification over signed data
                        val sigReports = JSONArray()
                        parsed.signatures.forEach { (sigId, sig) ->
                            val status = verifySignature(parsed.signedData, sig, sigId, cert)
                            if (status == "verified") anyVerified = true
                            if (status == "invalid") anyInvalid = true
                            sigReports.put(
                                JSONObject()
                                    .put("signatureAlgorithm", "0x${sigId.toString(16)}")
                                    .put("algorithmName", signatureAlgorithmName(sigId))
                                    .put("status", status)
                            )
                        }
                        signerReport.put("signatures", sigReports)
                    }.onFailure { error ->
                        signerReport.put("certParseError", error.message ?: error.javaClass.simpleName)
                    }
                }
                signerReports.put(signerReport)
            }
        }
        handleSigners(v2Value, v3 = false, scheme = "v2")
        handleSigners(v3Value, v3 = true, scheme = "v3")
        result.put("signers", signerReports)
        val digestMismatch = signerReports.hasDigestMismatch()
        result.put(
            "verdict",
            when {
                anyInvalid -> "signature_invalid"
                digestMismatch -> "digest_mismatch"
                anyVerified -> "verified"
                else -> "parsed_unverified"
            }
        )
        return result
    }

    private fun JSONArray.hasDigestMismatch(): Boolean {
        for (i in 0 until length()) {
            val signer = getJSONObject(i)
            val digests = signer.optJSONArray("digests") ?: continue
            for (j in 0 until digests.length()) {
                if (digests.getJSONObject(j).optBoolean("match", true) == false) return true
            }
        }
        return false
    }

    private fun err(code: String, message: String): JSONObject =
        JSONObject().put("ok", false).put("error", JSONObject().put("code", code).put("message", message))

    // ── apk_cert_info ──

    fun certJson(cert: X509Certificate): JSONObject {
        val md = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        val md1 = MessageDigest.getInstance("SHA-1").digest(cert.encoded)
        return JSONObject()
            .put("subject", cert.subjectDN.name)
            .put("issuer", cert.issuerDN.name)
            .put("serial", cert.serialNumber.toString(16))
            .put("notBefore", cert.notBefore.time)
            .put("notAfter", cert.notAfter.time)
            .put("sigAlgName", cert.sigAlgName)
            .put("publicKeyAlgorithm", cert.publicKey.algorithm)
            .put("selfSigned", cert.subjectDN == cert.issuerDN)
            .put("sha256", hexStr(md).uppercase())
            .put("sha1", hexStr(md1).uppercase())
    }

    fun certInfo(apk: ByteArray): JSONObject {
        val certs = mutableListOf<Pair<String, X509Certificate>>()
        val factory = CertificateFactory.getInstance("X.509")
        val layout = parseZipLayout(apk)
        if (layout != null) {
            val block = parseSigningBlock(apk, layout)
            if (block != null) {
                listOf(V2_BLOCK_ID to false, V3_BLOCK_ID to true).forEach { (id, v3) ->
                    val value = block.pairs.firstOrNull { it.first == id }?.second ?: return@forEach
                    signerBlocks(value).forEach { signer ->
                        val parsed = parseSigner(signer, v3) ?: return@forEach
                        parsed.certs.forEach { der ->
                            runCatching {
                                val cert = factory.generateCertificate(der.inputStream()) as X509Certificate
                                certs += "v${if (v3) 3 else 2} signing block" to cert
                            }
                        }
                    }
                }
            }
            layout.entries.filter {
                it.name.startsWith("META-INF/", true) &&
                    (it.name.endsWith(".RSA", true) || it.name.endsWith(".DSA", true) || it.name.endsWith(".EC", true))
            }.take(4).forEach { entry ->
                val data = readEntry(apk, entry, 4 * 1024 * 1024) ?: return@forEach
                runCatching {
                    factory.generateCertificates(data.inputStream()).forEach { cert ->
                        certs += entry.name to (cert as X509Certificate)
                    }
                }
            }
        }
        val items = JSONArray()
        certs.forEach { (source, cert) -> items.put(certJson(cert).put("source", source)) }
        return JSONObject()
            .put("certCount", certs.size)
            .put("certificates", items)
            .put("expired", certs.any { it.second.notAfter.time < System.currentTimeMillis() })
    }

    // ── apk_zip_anomaly ──

    fun zipAnomalies(apk: ByteArray): JSONObject {
        val layout = parseZipLayout(apk)
            ?: return err("APK_INVALID", "not a ZIP: EOCD not found")
        val anomalies = JSONArray()
        fun anomaly(kind: String, detail: String, entry: String? = null) {
            val item = JSONObject().put("kind", kind).put("detail", detail)
            if (entry != null) item.put("entry", entry)
            anomalies.put(item)
        }
        val seen = HashMap<String, Int>()
        layout.entries.forEach { e ->
            seen.merge(e.name, 1, Int::plus)
            if (e.name.startsWith("/") || e.name.contains("../") || e.name.contains("\\")) {
                anomaly("path_traversal", "entry name escapes the archive root", e.name)
            }
            if (e.name.length > 1 && e.name[1] == ':' && e.name[0].isLetter()) {
                anomaly("windows_drive", "drive-absolute entry name", e.name)
            }
            if (e.localOffset >= layout.cdOffset) anomaly("bad_local_offset", "local header points into central directory", e.name)
            if (e.flags and 0x1 != 0) anomaly("encrypted_entry", "entry is flagged encrypted", e.name)
            if (e.method != 0 && e.method != 8) anomaly("unknown_method", "compression method ${e.method}", e.name)
            if (e.name.endsWith(".so", true) && e.method == 0 && e.localOffset % 4096L != 0L) {
                anomaly("unaligned_so", "stored .so is not 4096-aligned (zipalign)", e.name)
            }
            if (e.method == 0 && e.csize != e.usize) anomaly("stored_size_mismatch", "stored entry csize != usize", e.name)
            if (e.extraLen > 1024) anomaly("large_extra", "extra field ${e.extraLen} bytes", e.name)
        }
        seen.filterValues { it > 1 }.forEach { (name, count) ->
            anomaly("duplicate_entry", "name appears $count times", name)
        }
        val cdActualEnd = layout.eocdOffset
        if (layout.cdOffset + layout.cdSize != cdActualEnd) {
            anomaly("cd_size_mismatch", "EOCD cdSize+cdOffset != EOCD offset (${layout.cdOffset}+${layout.cdSize} != $cdActualEnd)")
        }
        return JSONObject()
            .put("entryCount", layout.entries.size)
            .put("anomalyCount", anomalies.length())
            .put("anomalies", anomalies)
            .put("verdict", if (anomalies.length() == 0) "clean" else "findings")
    }

    // ── apk_abi_coverage ──

    private val KNOWN_ABIS = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

    fun abiCoverage(apk: ByteArray, maxParsedBytes: Int = 128 * 1024 * 1024): JSONObject {
        val layout = parseZipLayout(apk)
            ?: return err("APK_INVALID", "not a ZIP: EOCD not found")
        val libs = layout.entries.filter { Regex("^lib/[^/]+/[^/]+\\.so$").matches(it.name) && !it.name.endsWith("/") }
        val byAbi = LinkedHashMap<String, MutableList<CdEntry>>()
        libs.forEach { e ->
            val abi = e.name.split('/')[1]
            byAbi.getOrPut(abi) { mutableListOf() } += e
        }
        var parsedTotal = 0L
        val items = JSONArray()
        byAbi.forEach { (abi, entries) ->
            val files = JSONArray()
            entries.forEach { e ->
                val file = JSONObject().put("name", e.name.substringAfterLast('/')).put("size", e.usize)
                if (parsedTotal + e.usize <= maxParsedBytes) {
                    val data = readEntry(apk, e, (maxParsedBytes - parsedTotal).toInt().coerceAtLeast(0))
                    if (data != null && data.size >= 5 && data[0] == 0x7f.toByte()) {
                        parsedTotal += data.size
                        val elf = runCatching { ElfParser(data).parse() }.getOrNull()
                        if (elf != null) {
                            file.put("bits", elf.bits).put("architecture", elf.architecture)
                            val soname = runCatching { ElfAudit.soname(data, elf) }.getOrNull()
                            if (soname != null) file.put("soname", soname)
                        } else {
                            file.put("elfParse", "failed")
                        }
                    }
                }
                files.put(file)
            }
            items.put(JSONObject().put("abi", abi).put("libCount", entries.size).put("files", files))
        }
        val abis = byAbi.keys.toList()
        val findings = JSONArray()
        val has32 = abis.any { it == "armeabi-v7a" || it == "x86" }
        val has64 = abis.any { it == "arm64-v8a" || it == "x86_64" }
        if (has32 && !has64) findings.put("32-bit only: no arm64-v8a/x86_64 libraries")
        if (has64 && !has32) findings.put("64-bit only: legacy 32-bit devices unsupported")
        KNOWN_ABIS.filter { it !in abis }.forEach { findings.put("missing ABI: $it") }
        val sonames = HashMap<String, MutableSet<Long>>()
        for (i in 0 until items.length()) {
            val files = items.getJSONObject(i).getJSONArray("files")
            for (j in 0 until files.length()) {
                val f = files.getJSONObject(j)
                val soname = f.optString("soname", "")
                if (soname.isNotBlank()) sonames.getOrPut(soname) { mutableSetOf() } += f.getLong("size")
            }
        }
        sonames.filterValues { it.size > 1 }.forEach { (name, sizes) ->
            findings.put("soname $name maps to multiple sizes: $sizes")
        }
        return JSONObject()
            .put("abis", JSONArray(abis))
            .put("abiCount", abis.size)
            .put("libraries", items)
            .put("parsedBytes", parsedTotal)
            .put("findings", findings)
            .put(
                "method",
                "Groups lib/<abi>/*.so from the central directory; each SO is ELF-parsed for bits/architecture/SONAME within a byte budget."
            )
    }
}
