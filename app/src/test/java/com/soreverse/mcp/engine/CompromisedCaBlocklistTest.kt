// SPDX-License-Identifier: AGPL-3.0-only
//
// Blocklist table integrity and matching rules against a real DER fixture of
// one of the eight compromised eMudhra intermediates (EM DV TLS CA - G3C,
// served by crt.sh, SHA-256 verified against the OneCRL issuer+serial entry).
package com.soreverse.mcp.engine

import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CompromisedCaBlocklistTest {
    private val realCompromisedIntermediate =
        "MIIDaDCCAu6gAwIBAgIPWIsuPCu4zaE+GhIJJUMhMAoGCCqGSM49BAMDMFYxCzAJBgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMSAwHgYDVQQD" +
            "DBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM1MDlaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIEluYzEbMBkGA1UEAwwS" +
            "RU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiL" +
            "dL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh3xsqRB0Bo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5Qrz" +
            "MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYL" +
            "KwYBBAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVwb3NpdG9y" +
            "eS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQy5wN2MwNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5jcmwwDgYDVR0PAQH/BAQD" +
            "AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwMDaAAwZQIxAMEN2HWMocbuWdy1d33pH6JpMvP/V/DIS5PtZbv1Q7TXEbxrcyxgyuddOJscYDJJlAIwB4sH1BpbScDzkdD4" +
            "tJBSwrG/1Mx82vb8YaySehNuu1+1oXNdAEKwaJ0mVzScy2+6"

    private fun realCert(): X509Certificate {
        val der = java.util.Base64.getDecoder().decode(realCompromisedIntermediate)
        return CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }

    @Test
    fun blocklistCarriesTheEightCompromisedIntermediatesWithWellformedIdentifiers() {
        assertEquals(8, CompromisedCaBlocklist.entries.size)
        val fingerprints = CompromisedCaBlocklist.entries.map { it.sha256 }
        assertEquals(8, fingerprints.toSet().size)
        val hex256 = Regex("^[0-9A-F]{64}$")
        val hexSerial = Regex("^[0-9a-f]{16,40}$")
        CompromisedCaBlocklist.entries.forEach { entry ->
            assertTrue(hex256.matches(entry.sha256))
            assertTrue(hexSerial.matches(entry.serial))
            assertTrue(entry.cn.startsWith("EM "))
        }
        assertTrue(fingerprints.contains("0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"))
        assertTrue(fingerprints.contains("E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"))
    }

    @Test
    fun realCompromisedIntermediateMatchesByFingerprint() {
        val match = CompromisedCaBlocklist.match(realCert())
        assertNotNull(match)
        assertEquals("EM DV TLS CA - G3C", match!!.ca)
        assertEquals("certificate_fingerprint", match.match)
        assertEquals("CVE-2026-111943", match.toJson().getString("cve"))
    }

    @Test
    fun certJsonFlagsTheRealIntermediateWithCompromisedCaMarker() {
        val json = ApkSigTools.certJson(realCert())
        val blocked = json.getJSONObject("compromisedCa")
        assertEquals("CVE-2026-111943", blocked.getString("cve"))
        assertEquals("EM DV TLS CA - G3C", blocked.getString("ca"))
        assertEquals("certificate_fingerprint", blocked.getString("match"))
        assertEquals("588b2e3c2bb8cda13e1a1209254321", json.getString("serial"))
    }

    @Test
    fun issuerDnMatchesRegardlessOfOrderCaseAndSpacing() {
        assertEquals(
            "EM DV TLS CA - G3C",
            CompromisedCaBlocklist.matchByIssuerDn("C=US,  O=eMudhra Inc, CN=EM DV TLS CA - G3C")!!.ca
        )
        assertEquals(
            "issuer_dn",
            CompromisedCaBlocklist.matchByIssuerDn("O=eMudhra Inc,C=US,CN=EM DV TLS CA - G3C")!!.match
        )
        assertEquals(
            "EM OV CS CA - G3B",
            CompromisedCaBlocklist.matchByIssuerDn("CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL")!!.ca
        )
    }

    @Test
    fun unrelatedIssuersDoNotMatch() {
        assertNull(CompromisedCaBlocklist.matchByIssuerDn("CN=emSign Root TLS CA - G3,O=eMudhra Technologies Limited,C=IN"))
        assertNull(CompromisedCaBlocklist.matchByIssuerDn("CN=DigiCert Global Root G3,O=DigiCert Inc,C=US"))
        assertNull(CompromisedCaBlocklist.matchByIssuerDn("CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL,OU=extra"))
        assertNull(CompromisedCaBlocklist.matchByFingerprint("00".repeat(32)))
    }

    @Test
    fun realIntermediateIssuerIsNotMistakenForItsOwnSubject() {
        val cert = realCert()
        assertNull(CompromisedCaBlocklist.matchByIssuerDn(cert.issuerDN.name))
        assertNull(CompromisedCaBlocklist.matchByIssuerDn("CN=EM DV TLS CA - G3D,O=eMudhra Inc,C=US"))
    }

    @Test
    fun canonicalDnNormalizesCaseOrderAndWhitespace() {
        assertEquals(
            CompromisedCaBlocklist.canonicalDn("CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US"),
            CompromisedCaBlocklist.canonicalDn("c=us, o = eMudhra Inc, cn=EM OV TLS CA - G3C")
        )
        assertFalse(
            CompromisedCaBlocklist.canonicalDn("CN=a,O=b") == CompromisedCaBlocklist.canonicalDn("CN=a,O=c")
        )
    }

    @Test
    fun fingerprintDigestHelperAgreesWithCertificateEncodedSha256() {
        val cert = realCert()
        val expected = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }.uppercase()
        assertNotNull(CompromisedCaBlocklist.matchByFingerprint(expected))
    }
}
