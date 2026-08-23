/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

package com.soreverse.mcp.nativecore

import android.content.Context
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.normalizeSignerDigest
import java.security.MessageDigest
import java.security.cert.CertificateFactory

/**
 * Native APK signature verifier.
 *
 * Unlike [com.soreverse.mcp.core.IntegrityGuard] which obtains the signing
 * certificate through the Java [android.content.pm.PackageManager] API, this
 * class reads the APK file directly from the filesystem in native (C++) code
 * and extracts the embedded X.509 certificate from the META-INF/ *.RSA/.DSA/.EC
 * PKCS7 signature file.
 *
 * Because the certificate is read at the filesystem level rather than through
 * the Java PackageManager Binder interface, it cannot be intercepted by the
 * Binder-proxy hook technique used by kstools / ApkSignatureKiller / MT.
 *
 * Reference:
 *   - https://github.com/fourbrother/kstools
 *   - https://github.com/L-JINBIN/ApkSignatureKiller
 *   - https://github.com/L-JINBIN/ApkSignatureKillerEx
 */
object SignatureVerifier {

    private const val TAG = "SignatureVerifier"

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var loadError: String = ""

    init {
        // Load from the same shared library that carries rz_native (CMake
        // builds both into the same .so).
        val result = runCatching { System.loadLibrary("rz_native") }
        loaded = result.isSuccess
        if (!loaded) {
            loadError = result.exceptionOrNull()?.message ?: "Unknown load error"
            AppLog.w("SignatureVerifier: rz_native load FAILED: $loadError")
        } else {
            AppLog.i("SignatureVerifier: rz_native load OK")
        }
    }

    // JNI: implemented in cpp/signature_verify.cpp
    private external fun nativeReadApkCertificate(apkPath: String): ByteArray?
    private external fun nativeReadApkV234Certificate(apkPath: String): ByteArray?
    private external fun nativeGetExpectedSignerDigest(): String
    private external fun nativeVerifyPackageName(packageName: String): Boolean
    private external fun nativeVerifyApkIntegrity(apkPath: String): Int
    private external fun nativeComputeSha256Hex(data: ByteArray): String?

    /**
     * Integrity error-code bitmask returned by [verifyApkIntegrity].
     * Mirrors the kIntegrity* constants in cpp/signature_verify.cpp.
     */
    object IntegrityCode {
        const val OK = 0
        const val READ_FAILED = 1 shl 0
        const val EOCD_NOT_FOUND = 1 shl 1
        const val CENTRAL_DIR_INVALID = 1 shl 2
        const val MISSING_CLASSES = 1 shl 3
        const val MISSING_MANIFEST = 1 shl 4
        const val MISSING_ARSC = 1 shl 5
        const val MISSING_SIGNATURE = 1 shl 6
        const val MISSING_NATIVE = 1 shl 7
        const val CRC_MISMATCH = 1 shl 8
        const val MISSING_APK_SIG_V234 = 1 shl 9
    }

    /**
     * Reads the APK signing certificate directly from the APK file, bypassing
     * the Java PackageManager API.
     *
     * @param apkPath Absolute path to the APK file (context.packageCodePath)
     * @return DER-encoded X.509 certificate bytes, or null on failure
     */
    fun readApkCertificate(apkPath: String): ByteArray? {
        if (!loaded) {
            AppLog.e("SignatureVerifier: native library not loaded: $loadError")
            return null
        }
        return try {
            nativeReadApkCertificate(apkPath)
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: nativeReadApkCertificate failed", e)
            null
        }
    }

    /**
     * Computes the SHA-256 digest of the first signing certificate found in
     * the APK, by reading the APK directly from the filesystem.
     *
     * @return SHA-256 hex digest (uppercase), or null on failure
     */
    fun computeApkSignerDigest(context: Context): String? {
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: cannot get packageCodePath", e)
            return null
        }

        val certBytes = readApkCertificate(apkPath) ?: return null
        return certBytesToDigest(certBytes)
    }

    /**
     * Computes the SHA-256 signer digest of an arbitrary APK file on disk.
     * @return uppercase hex digest, or null on failure.
     */
    fun signerDigest(apkPath: String): String? {
        if (!loaded) return null
        return readApkCertificate(apkPath)?.let { certBytesToDigest(it) }
    }

    /**
     * Maps a DER X.509 certificate (as extracted by native code) to its
     * SHA-256 hex digest.
     *
     * The digest is computed by native code (sha256_hex in signature_verify.cpp)
     * so a Java-layer hook of MessageDigest (used by signature-bypass
     * frameworks) cannot alter the result. Falls back to Java MessageDigest
     * only when the native library is unavailable.
     */
    private fun certBytesToDigest(certBytes: ByteArray): String? {
        nativeComputeSha256Hex(certBytes)?.let { return it }
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(certBytes.inputStream())
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            digest.joinToString("") { "%02X".format(it) }
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: certificate parsing failed", e)
            // Fallback: compute SHA-256 of the raw DER bytes
            try {
                val digest = MessageDigest.getInstance("SHA-256").digest(certBytes)
                digest.joinToString("") { "%02X".format(it) }
            } catch (e2: Exception) {
                AppLog.e("SignatureVerifier: fallback digest failed", e2)
                null
            }
        }
    }

    /**
     * True when the APK file at [apkPath] was signed with SOMCP's own official
     * signing key (its signer digest equals the pinned release signer digest).
     */
    fun isSelfSignedApk(apkPath: String): Boolean {
        if (!loaded) return false
        val expected = getExpectedSignerDigest().let { normalizeSignerDigest(it) }
        if (expected.isBlank()) return false // no release signer pin configured
        return signerDigest(apkPath) == expected
    }

    /**
     * Returns the expected signer digest from native code (XOR-obfuscated).
     */
    fun getExpectedSignerDigest(): String {
        if (!loaded) return ""
        return try {
            nativeGetExpectedSignerDigest()
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: nativeGetExpectedSignerDigest failed", e)
            ""
        }
    }

    /**
     * Verifies the APK's signing certificate against the expected digest from
     * native code (XOR-obfuscated in the .so binary).
     *
     * @return true if the APK signer matches the expected digest, false if
     *         verification fails or the expected digest is not configured
     */
    fun verify(context: Context): Boolean {
        val expected = nativeGetExpectedSignerDigest().let { normalizeSignerDigest(it) }
        if (expected.isBlank()) {
            AppLog.i(
                "SignatureVerifier: no release signer pin configured, skipping native verification"
            )
            return true // no pin configured, skip
        }

        // Scheme-agnostic verification. We require BOTH the v1 (JAR) certificate
        // AND the v2/v3 (APK Signing Block) certificate to match the pinned
        // digest. A scheme-confusion repack preserves the v1 files while
        // re-signing v2/v3 with a new key, so a v1-only check alone is
        // insufficient (see the WHY note in cpp/signature_verify.cpp).
        val actualV1 = computeApkSignerDigest(context) ?: return false
        val actualV234 = computeApkV234SignerDigest(context) ?: return false

        val match = actualV1 == expected && actualV234 == expected
        if (!match) {
            AppLog.e(
                "SignatureVerifier: APK signer MISMATCH " +
                    "(expected=$expected, v1=$actualV1, v2/v3=$actualV234)"
            )
        }
        return match
    }

    /**
     * Reads the signing certificate from the APK v2/v3 Signing Block and
     * returns its SHA-256 digest. Prefers the highest available scheme (v3).
     *
     * @return uppercase hex digest, or null if the APK has no v2/v3 signing
     *         block or the certificate cannot be extracted.
     */
    fun signerDigestV234(apkPath: String): String? {
        if (!loaded) return null
        val cert = try {
            nativeReadApkV234Certificate(apkPath)
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: nativeReadApkV234Certificate failed", e)
            null
        } ?: return null
        return certBytesToDigest(cert)
    }

    /**
     * Computes the SHA-256 signer digest of the currently running APK from its
     * v2/v3 APK Signing Block.
     * @return uppercase hex digest, or null when unavailable.
     */
    fun computeApkV234SignerDigest(context: Context): String? {
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: cannot get packageCodePath", e)
            return null
        }
        return signerDigestV234(apkPath)
    }

    /**
     * True when the APK at [apkPath] was signed with SOMCP's own official key
     * as recorded in its v2/v3 APK Signing Block.
     */
    fun isSelfSignedApkV234(apkPath: String): Boolean {
        if (!loaded) return false
        val expected = getExpectedSignerDigest().let { normalizeSignerDigest(it) }
        if (expected.isBlank()) return false
        return signerDigestV234(apkPath) == expected
    }

    /**
     * Native-only signature check over the v2/v3 APK Signing Block
     * certificate, executed at the filesystem level so it cannot be intercepted
     * by a Java PackageManager / Binder hook.
     *
     * @return true if a v2/v3 certificate was found and matches the pinned
     *         digest; false if it is missing or mismatched.
     */
    fun verifyV234(context: Context): Boolean {
        val expected = getExpectedSignerDigest().let { normalizeSignerDigest(it) }
        if (expected.isBlank()) return true // no pin configured, skip
        val actual = computeApkV234SignerDigest(context) ?: return false
        return actual == expected
    }

    /**
     * Verifies that the running package name matches the value pinned inside the
     * native library (XOR-obfuscated).
     *
     * The check runs in native code on the raw package name passed in, so a
     * Java-layer hook of [Context.getPackageName] (or the ApplicationInfo
     * source) cannot influence the comparison result.
     *
     * @return true if package name matches the pinned value, false otherwise
     *         (also false when the native library is unavailable).
     */
    fun verifyPackageName(context: Context): Boolean {
        if (!loaded) return false
        val packageName = try {
            context.packageName
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: cannot get packageName", e)
            return false
        }
        return try {
            nativeVerifyPackageName(packageName)
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: nativeVerifyPackageName failed", e)
            false
        }
    }

    /**
     * Verifies APK integrity entirely in native code:
     *   - ZIP End Of Central Directory (EOCD) structure is well formed;
     *   - central directory entries are consistent with local headers;
     *   - critical entries exist (classes.dex, AndroidManifest.xml,
     *     resources.arsc, META-INF signature files, and the bundled native
     *     library under lib/abi);
     *   - classes.dex stored CRC matches the CRC recorded in the central
     *     directory (detects repackaging that deflates a replaced dex).
     *
     * Performed at the filesystem level, so Java-layer hooks of
     * ZipFile / AssetManager / PackageManager cannot hide a tampered APK.
     *
     * @param context used to resolve the running APK path (packageCodePath)
     * @return [IntegrityCode.OK] (0) on success, otherwise a bitmask of
     *         [IntegrityCode] error flags; [IntegrityCode.READ_FAILED] if the
     *         native library is unavailable or the APK cannot be read.
     */
    fun verifyApkIntegrity(context: Context): Int {
        if (!loaded) return IntegrityCode.READ_FAILED
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: cannot get packageCodePath", e)
            return IntegrityCode.READ_FAILED
        }
        return try {
            nativeVerifyApkIntegrity(apkPath)
        } catch (e: Exception) {
            AppLog.e("SignatureVerifier: nativeVerifyApkIntegrity failed", e)
            IntegrityCode.READ_FAILED
        }
    }
}
