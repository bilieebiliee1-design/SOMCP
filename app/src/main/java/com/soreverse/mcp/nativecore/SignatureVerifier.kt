package com.soreverse.mcp.nativecore

import android.content.Context
import android.util.Log
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
    private external fun nativeGetExpectedSignerDigest(): String

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

        val actual = computeApkSignerDigest(context) ?: return false
        val match = actual == expected
        if (!match) {
            AppLog.e("SignatureVerifier: APK signer MISMATCH (expected=$expected, actual=$actual)")
        }
        return match
    }
}
