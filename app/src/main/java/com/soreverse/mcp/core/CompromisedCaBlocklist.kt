/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (C) 2026 bilieebiliee1-design
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 */

package com.soreverse.mcp.core

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient

/**
 * Rejects TLS chains built on the private keys leaked in CVE-2026-111943.
 *
 * On 2025-04-30 eMudhra generated eight intermediate CA key pairs whose P-384 scalars
 * carried under 256 bits of entropy, which made the private keys publicly recoverable
 * after the disclosure on 2026-10-17. Whoever holds one can mint a certificate for any
 * hostname, so this app's own HTTPS calls — quick-tunnel registration against
 * api.trycloudflare.com, the reachability probe of a published `*.trycloudflare.com`
 * tunnel, GitHub update checks, and every AI provider request — can be intercepted by a
 * position-in-the-path attacker even though the server is honest.
 *
 * The blocklist keys on the leaked *public keys* rather than on the eight certificates
 * eMudhra published, because every one of those intermediates is also cross-signed by
 * "AAA Certificate Services" (valid to 2028-12-31) under the very same key. Revocation
 * and root-program distrust are expressed as (issuer, serial) pairs taken from eMudhra's
 * own roots, so the AAA-signed copies keep validating on a device that has otherwise
 * caught up with the revocations. Blocking by key covers both, plus any further
 * re-encoding of the same material.
 *
 * Enforcement lives in the app process, not in the device trust store, so it holds
 * regardless of whether a given device has received the platform's distrust update.
 *
 * It does not cover the tunnel data plane. The cloudflared child does its own path
 * building against `/system/etc/security/cacerts` rather than through Conscrypt, so it
 * neither sees this wrapper nor inherits the Mainline distrusted-CA list. A child-side
 * route does exist — Go's crypto/x509 honours SSL_CERT_FILE and SSL_CERT_DIR — but it
 * means generating a filtered bundle at runtime, which would break every tunnel if it
 * is ever wrong, so it is deliberately not attempted here.
 */
object CompromisedCaBlocklist {

    /** One of the eight certificates asserting a leaked key, under one issuer. */
    class Issuance(val issuerCn: String, val serialHex: String, val certSha256Hex: String)

    /** One leaked intermediate key and every certificate known to assert it. */
    class CompromisedKey(val subjectCn: String, val usage: String, val spkiSha256Hex: String, val issuances: List<Issuance>)

    private val COMPROMISED_KEYS: List<CompromisedKey> = listOf(
        CompromisedKey(
            "EM EV TLS CA - G3B",
            "TLS server authentication",
            "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "C7C41EFE92D825F05EAE841A4A82C1",
                    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"
                ),
                issuance(
                    "AAA Certificate Services",
                    "D8F8685E4F2BD9D82402A85A1C1EB731",
                    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"
                )
            )
        ),
        CompromisedKey(
            "EM OV TLS CA - G3B",
            "TLS server authentication",
            "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "6CADA367FB1C100088120EA202D568",
                    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B"
                ),
                issuance(
                    "AAA Certificate Services",
                    "E94223BDE92F914E5AB9ACABFDAC3710",
                    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"
                )
            )
        ),
        CompromisedKey(
            "EM DV TLS CA - G3B",
            "TLS server authentication",
            "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "A4AEE678F23362B4C0E460B772F214",
                    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"
                ),
                // A second 875-byte encoding of the same (issuer, serial, subject, key)
                // circulates in CT, so the DER hash alone would not cover it.
                issuance(
                    "emSign Root TLS CA - G3",
                    "A4AEE678F23362B4C0E460B772F214",
                    "37E866582D43C35D7C17D47794B974F291B3047B868DC123382477F7A08AEFA8"
                ),
                issuance(
                    "AAA Certificate Services",
                    "A024FDF4BA665C785CE4A020483858B7",
                    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"
                )
            )
        ),
        CompromisedKey(
            "EM EV TLS CA - G3C",
            "TLS server authentication",
            "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "8009928A64107601AF05FA2F19F109",
                    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3"
                ),
                issuance(
                    "AAA Certificate Services",
                    "05F078752DECE7A1BB8595D303167171",
                    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"
                )
            )
        ),
        CompromisedKey(
            "EM OV TLS CA - G3C",
            "TLS server authentication",
            "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "296926C227A3A1526392B19482A504",
                    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F"
                ),
                issuance(
                    "AAA Certificate Services",
                    "8D5A4811939EF447D77111CDD9849AE9",
                    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"
                )
            )
        ),
        CompromisedKey(
            "EM DV TLS CA - G3C",
            "TLS server authentication",
            "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F",
            listOf(
                issuance(
                    "emSign Root TLS CA - G3",
                    "588B2E3C2BB8CDA13E1A1209254321",
                    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"
                ),
                issuance(
                    "AAA Certificate Services",
                    "91F347F1A5B7D39962B95E0EE4E299D1",
                    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"
                )
            )
        ),
        CompromisedKey(
            "EM OV CS CA - G3B",
            "code signing",
            "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6",
            listOf(
                issuance(
                    "emSign Root CS CA - G3",
                    "7818933F8F85B4619A2B35FBA83D0A",
                    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4"
                ),
                issuance(
                    "AAA Certificate Services",
                    "41E32B73AC185D6CE0D7480BACF84E69",
                    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"
                )
            )
        ),
        CompromisedKey(
            "EM OV CS CA - G3C",
            "code signing",
            "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30",
            listOf(
                issuance(
                    "emSign Root CS CA - G3",
                    "544B7F922C31AE220A4A922916F6E6",
                    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1"
                ),
                issuance(
                    "AAA Certificate Services",
                    "D6A5EF613B390F32EF9CDF349F772841",
                    "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"
                )
            )
        )
    )

    private fun issuance(issuerCn: String, serialHex: String, certSha256Hex: String) = Issuance(issuerCn, serialHex, certSha256Hex)

    private val BY_SPKI: Map<String, CompromisedKey> =
        COMPROMISED_KEYS.associateBy { it.spkiSha256Hex }

    private val BY_CERT_DER: Map<String, CompromisedKey> =
        COMPROMISED_KEYS.flatMap { key -> key.issuances.map { it.certSha256Hex to key } }.toMap()

    /** Every certificate asserted to hold one of the leaked keys. */
    val compromisedKeys: List<CompromisedKey> get() = COMPROMISED_KEYS

    fun isBlocked(cert: X509Certificate): Boolean = matchedKey(cert) != null

    /**
     * The leaked key behind [cert], if it asserts one. The public key is consulted first
     * because it is the only identifier shared by the eMudhra-issued certificate, its AAA
     * cross-signature, and any re-encoding of either.
     */
    fun matchedKey(cert: X509Certificate): CompromisedKey? {
        BY_SPKI[sha256Hex(publicKeyEncoding(cert))]?.let { return it }
        return BY_CERT_DER[sha256Hex(certEncoding(cert))]
    }

    /**
     * Refuse a chain that carries a certificate built on one of the leaked keys.
     *
     * Public so that tests can drive the exact rejection path a handshake takes, without
     * depending on whether the platform store happens to trust the chain being replayed.
     *
     * It must not log through AppLog: that object's initialiser constructs a
     * `Handler(Looper.getMainLooper())`, so touching it from here would make the whole
     * rejection path unusable anywhere the main looper is absent — including this class's
     * own unit tests, which fail with `ExceptionInInitializerError`. The callers already
     * record the thrown message, which names the certificate.
     */
    fun enforceNoCompromisedCert(chain: Array<X509Certificate>) {
        val blocked = chain.firstNotNullOfOrNull { matchedKey(it) } ?: return
        throw CertificateException(
            "TLS: rejecting a chain containing ${blocked.subjectCn}, whose private key is " +
                "leaked (CVE-2026-111943); refusing this connection"
        )
    }

    private fun publicKeyEncoding(cert: X509Certificate): ByteArray = runCatching {
        cert.publicKey.encoded ?: ByteArray(0)
    }.getOrDefault(ByteArray(0))

    private fun certEncoding(cert: X509Certificate): ByteArray = runCatching {
        cert.encoded
    }.getOrDefault(ByteArray(0))

    private fun sha256Hex(bytes: ByteArray): String = if (bytes.isEmpty()) {
        ""
    } else {
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02X".format(it) }
    }

    /**
     * Wraps the platform trust manager so normal validation still runs and only chains
     * carrying a leaked-key certificate are additionally refused.
     */
    private class BlockingTrustManager(private val delegate: X509TrustManager) : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = delegate.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            delegate.checkServerTrusted(chain, authType)
            enforceNoCompromisedCert(chain)
        }
    }

    @Volatile
    private var hardenedPair: Pair<SSLSocketFactory, X509TrustManager>? = null

    fun hardened(): Pair<SSLSocketFactory, X509TrustManager> {
        hardenedPair?.let { return it }
        synchronized(this) {
            hardenedPair?.let { return it }
            val factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            )
            factory.init(null as KeyStore?)
            val platform = factory.trustManagers
                .filterIsInstance<X509TrustManager>()
                .firstOrNull()
                ?: error("no X509TrustManager available from the platform")
            val wrapper = BlockingTrustManager(platform)
            val context = SSLContext.getInstance("TLS")
            context.init(null, arrayOf<TrustManager>(wrapper), null)
            val built = context.socketFactory to wrapper
            hardenedPair = built
            return built
        }
    }
}

/**
 * Route this client's TLS verification through [CompromisedCaBlocklist] in addition to
 * the platform rules. Applied to every HTTPS client in the app; safe to call twice.
 */
fun OkHttpClient.Builder.withCompromisedCaBlocklist(): OkHttpClient.Builder {
    val (socketFactory, trustManager) = CompromisedCaBlocklist.hardened()
    return sslSocketFactory(socketFactory, trustManager)
}
