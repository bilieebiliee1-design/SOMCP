// SPDX-License-Identifier: AGPL-3.0-or-later
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

package com.soreverse.mcp.core

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The table in [CompromisedCaBlocklist] is pinned to real certificate material here: the
 * fixtures are the actual DER of the CVE-2026-111943 intermediates and of the
 * "AAA Certificate Services" root, so a mistyped digest fails the build instead of
 * silently leaving the connection unguarded.
 */
class CompromisedCaBlocklistTest {

    private fun der(name: String): String = Base64.getDecoder().decode(name).let { bytes ->
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02X".format(it) }
    }

    private fun cert(base64Der: String): X509Certificate = CertificateFactory.getInstance("X509").generateCertificate(
        ByteArrayInputStream(Base64.getDecoder().decode(base64Der))
    ) as X509Certificate

    private fun serialHex(cert: X509Certificate): String = cert.serialNumber.toString(16).uppercase()

    private val issuedByEmSign by lazy { cert(EM_DV_G3B_ISSUED_BY_EM_SIGN) }
    private val reEncoded by lazy { cert(EM_DV_G3B_RE_ENCODED) }
    private val crossSignedByAaa by lazy { cert(EM_DV_G3B_CROSS_SIGNED_BY_AAA) }
    private val aaaRoot by lazy { cert(AAA_CERTIFICATE_SERVICES_ROOT) }

    @Test
    fun tableCoversSixTlsAndTwoCodeSigningKeysWithEveryKnownEncoding() {
        val keys = CompromisedCaBlocklist.compromisedKeys
        assertEquals(8, keys.size)
        assertEquals(6, keys.count { it.usage == "TLS server authentication" })
        assertEquals(2, keys.count { it.usage == "code signing" })
        val allCerts = keys.flatMap { it.issuances }
        assertEquals("every issuance must be a distinct certificate", 17, allCerts.size)
        assertEquals(17, allCerts.map { it.certSha256Hex }.toSet().size)
        assertEquals(8, keys.map { it.spkiSha256Hex }.toSet().size)
        keys.forEach { key ->
            assertTrue(key.subjectCn, HEX_64.matches(key.spkiSha256Hex))
            assertTrue(
                key.subjectCn + " must list the eMudhra issuance and its cross-signature",
                key.issuances.size >= 2
            )
            key.issuances.forEach {
                assertTrue(it.certSha256Hex, HEX_64.matches(it.certSha256Hex))
            }
        }
    }

    @Test
    fun issuedCertificateIsMatchedAndItsRecordedDigestsAreExact() {
        val key = CompromisedCaBlocklist.matchedKey(issuedByEmSign)
        assertNotNull(key)
        assertEquals("EM DV TLS CA - G3B", key!!.subjectCn)
        assertEquals("42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493", der(EM_DV_G3B_ISSUED_BY_EM_SIGN))
        assertEquals(
            "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
            key.issuances.first {
                it.serialHex == "A4AEE678F23362B4C0E460B772F214"
            }.certSha256Hex
        )
        assertEquals("EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105", key.spkiSha256Hex)
        // The blocklist hashes the SubjectPublicKeyInfo as the platform exposes it, which
        // is the same encoding openssl prints for `-pubkey`.
        assertEquals("EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105", sha256Hex(issuedByEmSign.publicKey.encoded))
        assertTrue(CompromisedCaBlocklist.isBlocked(issuedByEmSign))
    }

    /**
     * A second encoding of the same (subject, issuer, serial, key) circulates in CT. Its
     * DER digest differs, so a blocklist expressed only over certificate hashes would need
     * to enumerate every re-encoding; the leaked key does not change.
     */
    @Test
    fun reEncodedCopyOfTheSameCertificateMapsToTheSameLeakedKey() {
        assertEquals(issuedByEmSign.subjectX500Principal, reEncoded.subjectX500Principal)
        assertEquals(issuedByEmSign.issuerX500Principal, reEncoded.issuerX500Principal)
        assertEquals(issuedByEmSign.serialNumber, reEncoded.serialNumber)
        assertNotEquals(der(EM_DV_G3B_ISSUED_BY_EM_SIGN), der(EM_DV_G3B_RE_ENCODED))
        assertEquals("37E866582D43C35D7C17D47794B974F291B3047B868DC123382477F7A08AEFA8", der(EM_DV_G3B_RE_ENCODED))
        val key = CompromisedCaBlocklist.matchedKey(reEncoded)
        assertNotNull(key)
        assertSame(CompromisedCaBlocklist.matchedKey(issuedByEmSign), key)
    }

    /**
     * The live attack path. Every one of the eight intermediates was also cross-signed by
     * "AAA Certificate Services", whose root is in every trust store, under the very same
     * public key. Revocation entries are (issuer, serial) pairs naming eMudhra's own roots,
     * so this copy is not covered by them and only key matching catches it.
     */
    @Test
    fun crossSignatureUnderTheAaaRootSharesTheLeakedKeyAndIsBlocked() {
        assertTrue(
            crossSignedByAaa.issuerX500Principal.name,
            crossSignedByAaa.issuerX500Principal.name.contains("AAA Certificate Services")
        )
        assertNotEquals(serialHex(issuedByEmSign), serialHex(crossSignedByAaa))
        assertEquals("A024FDF4BA665C785CE4A020483858B7", serialHex(crossSignedByAaa))
        assertEquals("45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE", der(EM_DV_G3B_CROSS_SIGNED_BY_AAA))
        // same key, different issuer, different serial, different certificate bytes
        assertEquals(
            sha256Hex(issuedByEmSign.publicKey.encoded),
            sha256Hex(crossSignedByAaa.publicKey.encoded)
        )
        assertSame(
            CompromisedCaBlocklist.matchedKey(issuedByEmSign),
            CompromisedCaBlocklist.matchedKey(crossSignedByAaa)
        )
    }

    @Test
    fun theAaaRootThatSignedThoseCrossSignaturesIsStillTrusted() {
        assertEquals("D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", der(AAA_CERTIFICATE_SERVICES_ROOT))
        assertEquals(aaaRoot.subjectX500Principal, aaaRoot.issuerX500Principal)
        assertTrue(!CompromisedCaBlocklist.isBlocked(aaaRoot))
        // blocking the intermediates must not blacklist the ordinary CA above them
        assertTrue(
            aaaRoot.subjectX500Principal.name,
            aaaRoot.subjectX500Principal.name.contains("CN=AAA Certificate Services")
        )
    }

    @Test
    fun enforceRejectsATaintedChainAndPassesACleanOne() {
        val rejection = runCatching {
            CompromisedCaBlocklist.enforceNoCompromisedCert(arrayOf(crossSignedByAaa, aaaRoot))
        }.exceptionOrNull()
        assertTrue(
            "expected a refusal naming the leaked certificate, got " +
                "${rejection?.javaClass?.simpleName}: ${rejection?.message}",
            rejection?.message?.contains("EM DV TLS CA - G3B") == true
        )

        // the non-vacuity control: an unrelated valid chain must sail through
        CompromisedCaBlocklist.enforceNoCompromisedCert(arrayOf(aaaRoot))
    }

    @Test
    fun hardenedClientKeepsThePlatformAnchorSetAndUsesOurSocketFactory() {
        val (factory, trustManager) = CompromisedCaBlocklist.hardened()
        assertSame(factory, CompromisedCaBlocklist.hardened().first)
        assertSame(trustManager, CompromisedCaBlocklist.hardened().second)
        assertTrue(
            "delegating to the platform store must preserve its trusted anchors",
            trustManager.acceptedIssuers.isNotEmpty()
        )
        val client = OkHttpClient.Builder().withCompromisedCaBlocklist().build()
        assertSame(factory, client.sslSocketFactory)
    }

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02X".format(it) }

    companion object {
        private val HEX_64 = Regex("[0-9A-F]{64}")

        @JvmStatic
        private val EM_DV_G3B_ISSUED_BY_EM_SIGN: String =
            "MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhy" +
                "YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1NDA4WhcN" +
                "NDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0g" +
                "RzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/JhZ4eZ6+wTi+LyX90" +
                "hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx" +
                "401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD" +
                "AjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYL" +
                "KwYBBAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYi5lbXNpZ24uY29t" +
                "MD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0fBDAw" +
                "LjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI" +
                "MAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPOIbh1grvdULDC" +
                "AjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8gt2TlfJbHii+KNvK"

        @JvmStatic
        private val EM_DV_G3B_RE_ENCODED: String =
            "MIIDZzCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhy" +
                "YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1NDA4WhcN" +
                "NDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0g" +
                "RzNCMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/JhZ4eZ6+wTi+LyX90" +
                "hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx" +
                "401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD" +
                "AjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYL" +
                "KwYBBAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYi5lbXNpZ24uY29t" +
                "MD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0fBDAw" +
                "LjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI" +
                "MAYBAf8CAQAwCgYIKoZIzj0EAwMDZwAwZAIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPOIbh1grvdULDC" +
                "AjA6ZDRo6uVDkULYU9i1z0Oj6RXLe9PYX3ruXABIBP7vAvwwu/XF0xPk+pD7Qg6cTak="

        @JvmStatic
        private val EM_DV_G3B_CROSS_SIGNED_BY_AAA: String =
            "MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAwezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdy" +
                "ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFB" +
                "QSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0yODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYD" +
                "VQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATnntnASpdz" +
                "xHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BOL4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKT" +
                "XSnUT5HhVga2PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQU4h4v5xwZOQ5V" +
                "S2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF" +
                "BwMCMDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44hAQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0" +
                "dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcw" +
                "AYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldp" +
                "VE/vZn2TxC2y0s8oYiLR5ICEwqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxMQkPmjXAJbG5f" +
                "4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ" +
                "8UGgsxs7mG+xquMlbN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5VGUyRCEIDhF5TBUuKF4E3" +
                "kf1h"

        @JvmStatic
        private val AAA_CERTIFICATE_SERVICES_ROOT: String =
            "MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy" +
                "MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNl" +
                "cnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFu" +
                "Y2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZp" +
                "Y2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL6" +
                "86tdUIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe3M/vg4aijJRPn2jymJBGhCfH" +
                "dr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsX" +
                "eDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7o" +
                "L8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMB" +
                "Af8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0" +
                "oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8" +
                "AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHC" +
                "v8S5dIa2LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z8VlIMCFl" +
                "A2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XX" +
                "vi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg=="
    }
}
