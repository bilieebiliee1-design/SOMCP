// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Known-compromised CA blocklist. Currently carries the eight eMudhra
// intermediate CA certificates whose private keys were leaked in
// CVE-2026-111943 (October 2026): six TLS intermediates under
// "emSign Root TLS CA - G3" were pushed to Mozilla OneCRL, and two
// codesigning intermediates under "emSign Root CS CA - G3" were blocked
// by Microsoft. Fingerprints were computed locally from the original DER
// served by crt.sh and cross-checked against the OneCRL issuer+serial
// entries; a leaf whose issuer DN matches one of these subjects is treated
// as issued under a compromised key, since APK analysis only ever sees the
// signer certificate, never the full chain.
package com.soreverse.mcp.engine

import java.security.MessageDigest
import java.security.cert.X509Certificate
import org.json.JSONObject

internal object CompromisedCaBlocklist {
    const val CVE_ID = "CVE-2026-111943"

    internal data class Entry(val cn: String, val subjectDn: String, val serial: String, val sha256: String, val source: String)

    internal data class Match(val ca: String, val match: String) {
        fun toJson(): JSONObject = JSONObject().put("cve", CVE_ID).put("ca", ca).put("match", match)
    }

    private const val MATCH_FINGERPRINT = "certificate_fingerprint"
    private const val MATCH_ISSUER_DN = "issuer_dn"

    internal val entries: List<Entry> = listOf(
        Entry(
            cn = "EM EV TLS CA - G3B",
            subjectDn = "CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL",
            serial = "c7c41efe92d825f05eae841a4a82c1",
            sha256 = "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM OV TLS CA - G3B",
            subjectDn = "CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL",
            serial = "6cada367fb1c100088120ea202d568",
            sha256 = "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM DV TLS CA - G3B",
            subjectDn = "CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL",
            serial = "a4aee678f23362b4c0e460b772f214",
            sha256 = "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM EV TLS CA - G3C",
            subjectDn = "CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US",
            serial = "8009928a64107601af05fa2f19f109",
            sha256 = "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM OV TLS CA - G3C",
            subjectDn = "CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US",
            serial = "296926c227a3a1526392b19482a504",
            sha256 = "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM DV TLS CA - G3C",
            subjectDn = "CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US",
            serial = "588b2e3c2bb8cda13e1a1209254321",
            sha256 = "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19",
            source = "Mozilla OneCRL"
        ),
        Entry(
            cn = "EM OV CS CA - G3B",
            subjectDn = "CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL",
            serial = "7818933f8f85b4619a2b35fba83d0a",
            sha256 = "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4",
            source = "Microsoft codesigning distrust"
        ),
        Entry(
            cn = "EM OV CS CA - G3C",
            subjectDn = "CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US",
            serial = "544b7f922c31ae220a4a922916f6e6",
            sha256 = "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1",
            source = "Microsoft codesigning distrust"
        )
    )

    fun match(cert: X509Certificate): Match? {
        val sha256 = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }.uppercase()
        matchByFingerprint(sha256)?.let { return it }
        return matchByIssuerDn(cert.issuerDN.name)
    }

    internal fun matchByFingerprint(sha256: String): Match? = entries.firstOrNull { it.sha256 == sha256.uppercase() }
        ?.let { Match(it.cn, MATCH_FINGERPRINT) }

    internal fun matchByIssuerDn(issuerDn: String): Match? {
        val issuer = canonicalDn(issuerDn)
        return entries.firstOrNull { canonicalDn(it.subjectDn) == issuer }
            ?.let { Match(it.cn, MATCH_ISSUER_DN) }
    }

    // javax X500Principal name ordering and spacing vary across providers;
    // comparison is only against the eight fixed subjects above, so a
    // case-insensitive, order-insensitive, whitespace-trimmed RDN bag is
    // sufficient and avoids DN-format false negatives.
    internal fun canonicalDn(name: String): String = name.split(',')
        .map { it.trim().replace(Regex("\\s+=\\s+"), "=").replace(Regex("\\s+"), " ").lowercase() }
        .sorted().joinToString(",")
}
