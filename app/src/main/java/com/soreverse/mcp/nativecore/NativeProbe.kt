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
import com.soreverse.mcp.core.normalizeFingerprint
import java.security.MessageDigest
import java.security.cert.CertificateFactory

/**
 * Native build-identity probe.
 *
 * Unlike [com.soreverse.mcp.core.IntegrityGuard] which reads the install record
 * through the Java [android.content.pm.PackageManager] API, this class reads the
 * package file directly from the filesystem in native (C++) code and extracts
 * the embedded X.509 record from the META-INF/ *.RSA/.DSA/.EC PKCS7 entry.
 *
 * Because the record is read at the filesystem level rather than through the
 * Java PackageManager Binder interface, it cannot be altered by a Binder-proxy
 * replacement of the package metadata.
 */
object NativeProbe {

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
            AppLog.w("NativeProbe: rz_native load FAILED: $loadError")
        } else {
            AppLog.i("NativeProbe: rz_native load OK")
        }
    }

    // JNI: implemented in cpp/native_probe.cpp
    private external fun nativeReadEnvelope(apkPath: String, requireRunning: Boolean): ByteArray?
    private external fun nativeReadEnvelopeV234(apkPath: String, requireRunning: Boolean): ByteArray?
    private external fun nativeGetPinnedFingerprint(): String
    private external fun nativeMatchPackageId(packageName: String): Boolean
    private external fun nativeProbeArchive(apkPath: String, requireRunning: Boolean): Int
    private external fun nativeComputeSha256Hex(data: ByteArray): String?
    private external fun nativeGetReportingKey(): String
    private external fun nativeVerifyBlock(apkPath: String): Int

    /**
     * Returns the log-report-platform API key injected into the native library
     * at build time (encrypted under a SHA-256-CTR keystream in
     * key_generated.h, decoded on demand in reporting_key.h and wiped right
     * after use). The key lives only in
     * the native layer; it is never a user setting and is never logged. Returns
     * an empty string when no key was injected or the native library is
     * unavailable.
     */
    fun reportingKey(): String {
        if (!loaded) return ""
        return try {
            nativeGetReportingKey()
        } catch (e: Exception) {
            // Deliberately silent: never surface key material or its absence
            // through logs / reports.
            ""
        }
    }

    /**
     * Archive probe error-code bitmask returned by [probeArchive].
     * Mirrors the kProbe* constants in cpp/native_probe.cpp.
     */
    object ProbeCode {
        const val OK = 0
        const val READ_FAILED = 1 shl 0
        const val EOCD_NOT_FOUND = 1 shl 1
        const val CENTRAL_DIR_INVALID = 1 shl 2
        const val MISSING_CLASSES = 1 shl 3
        const val MISSING_MANIFEST = 1 shl 4
        const val MISSING_ARSC = 1 shl 5
        const val MISSING_ENVELOPE = 1 shl 6
        const val MISSING_NATIVE = 1 shl 7
        const val CRC_MISMATCH = 1 shl 8
        const val MISSING_BLOCK_V234 = 1 shl 9
    }

    /**
     * Reads the embedded X.509 record directly from the package file, bypassing
     * the Java PackageManager API.
     *
     * The file is opened through the native anti-redirect channel (raw syscall
     * + fd/path inode cross-check), so a PLT-hook path substitution
     * (original_apk / DPatch style file redirection) cannot feed this a
     * preserved copy of the original APK undetected.
     *
     * @param apkPath Absolute path to the package file (context.packageCodePath)
     * @param requireRunning true when [apkPath] is this process's own package:
     *        native then additionally verifies the opened file is one of the
     *        `.apk` images mapped in /proc/self/maps (the kernel-authoritative
     *        "what am I actually running").
     * @return DER-encoded X.509 bytes, or null on failure
     */
    fun readEnvelope(apkPath: String, requireRunning: Boolean = false): ByteArray? {
        if (!loaded) {
            AppLog.e("NativeProbe: native library not loaded: $loadError")
            return null
        }
        return try {
            nativeReadEnvelope(apkPath, requireRunning)
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeReadEnvelope failed", e)
            null
        }
    }

    /**
     * Computes the SHA-256 fingerprint of the first embedded record found in
     * the package, by reading the file directly from the filesystem.
     *
     * @return SHA-256 hex digest (uppercase), or null on failure
     */
    fun fingerprintOf(context: Context): String? {
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("NativeProbe: cannot get packageCodePath", e)
            return null
        }

        val certBytes = readEnvelope(apkPath, requireRunning = true) ?: return null
        return bytesToFingerprint(certBytes)
    }

    /**
     * Computes the SHA-256 fingerprint of an arbitrary package file on disk.
     * @return uppercase hex digest, or null on failure.
     */
    fun fingerprint(apkPath: String): String? {
        if (!loaded) return null
        return readEnvelope(apkPath)?.let { bytesToFingerprint(it) }
    }

    /**
     * Maps raw DER X.509 bytes (as extracted by native code) to their SHA-256
     * hex digest.
     *
     * The digest is computed by native code (sha256_hex in native_probe.cpp) so
     * a Java-layer hook of MessageDigest cannot alter the result. Falls back to
     * Java MessageDigest only when the native library is unavailable.
     */
    private fun bytesToFingerprint(certBytes: ByteArray): String? {
        nativeComputeSha256Hex(certBytes)?.let { return it }
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(certBytes.inputStream())
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            digest.joinToString("") { "%02X".format(it) }
        } catch (e: Exception) {
            AppLog.e("NativeProbe: certificate parsing failed", e)
            // Fallback: compute SHA-256 of the raw DER bytes
            try {
                val digest = MessageDigest.getInstance("SHA-256").digest(certBytes)
                digest.joinToString("") { "%02X".format(it) }
            } catch (e2: Exception) {
                AppLog.e("NativeProbe: fallback digest failed", e2)
                null
            }
        }
    }

    /**
     * True when the package file at [apkPath] carries SOMCP's own official
     * build identity (its fingerprint equals the pinned release fingerprint).
     */
    fun isOwnApk(apkPath: String): Boolean {
        if (!loaded) return false
        val expected = pinnedFingerprint().let { normalizeFingerprint(it) }
        if (expected.isBlank()) return false // no release identity pin configured
        return fingerprint(apkPath) == expected
    }

    /**
     * Returns the pinned build-identity digest from native code (XOR-obfuscated).
     */
    fun pinnedFingerprint(): String {
        if (!loaded) return ""
        return try {
            nativeGetPinnedFingerprint()
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeGetPinnedFingerprint failed", e)
            ""
        }
    }

    /**
     * Matches the running package against the official build identity. Both the
     * v1 (JAR) record AND the v2/v3 (APK Signing Block) record must equal the
     * pinned digest, so a scheme-confusion repack that preserves the v1 files
     * while re-signing v2/v3 with a new key does not pass.
     *
     * @return true if the package identity matches the pinned digest, false if
     *         the check fails or no pinned digest is configured
     */
    fun matches(context: Context): Boolean {
        val expected = nativeGetPinnedFingerprint().let { normalizeFingerprint(it) }
        if (expected.isBlank()) {
            AppLog.i("NativeProbe: no pinned identity configured, skipping native probe")
            return true // no pin configured, skip
        }

        val actualV1 = fingerprintOf(context) ?: return false
        val actualV234 = fingerprintV234Of(context) ?: return false

        val match = actualV1 == expected && actualV234 == expected
        if (!match) {
            // Deliberately omits the values: a full-length digest in the log
            // hands the pinned identity to anyone with logcat access.
            AppLog.e("NativeProbe: build identity MISMATCH against pinned release")
        }
        return match
    }

    /**
     * Reads the v2/v3 record from the package Signing Block and returns its
     * SHA-256 fingerprint. Prefers the highest available scheme (v3).
     *
     * @return uppercase hex digest, or null if the package has no v2/v3 block
     *         or the record cannot be extracted.
     */
    fun fingerprintV234(apkPath: String, requireRunning: Boolean = false): String? {
        if (!loaded) return null
        val cert = try {
            nativeReadEnvelopeV234(apkPath, requireRunning)
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeReadEnvelopeV234 failed", e)
            null
        } ?: return null
        return bytesToFingerprint(cert)
    }

    /**
     * Computes the SHA-256 fingerprint of the currently running package from
     * its v2/v3 block.
     * @return uppercase hex digest, or null when unavailable.
     */
    fun fingerprintV234Of(context: Context): String? {
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("NativeProbe: cannot get packageCodePath", e)
            return null
        }
        return fingerprintV234(apkPath, requireRunning = true)
    }

    /**
     * True when the package at [apkPath] carries SOMCP's own official identity
     * as recorded in its v2/v3 block.
     */
    fun isOwnApkV234(apkPath: String): Boolean {
        if (!loaded) return false
        val expected = pinnedFingerprint().let { normalizeFingerprint(it) }
        if (expected.isBlank()) return false
        return fingerprintV234(apkPath) == expected
    }

    /**
     * Native-only identity match over the v2/v3 block record, executed at the
     * filesystem level so it cannot be intercepted by a Java PackageManager /
     * Binder hook.
     *
     * @return true if a v2/v3 record was found and matches the pinned digest;
     *         false if it is missing or mismatched.
     */
    fun matchesV234(context: Context): Boolean {
        val expected = pinnedFingerprint().let { normalizeFingerprint(it) }
        if (expected.isBlank()) return true // no pin configured, skip
        val actual = fingerprintV234Of(context) ?: return false
        return actual == expected
    }

    /**
     * Matches the running package name against the value pinned inside the
     * native library (XOR-obfuscated).
     *
     * The check runs in native code on the raw package name passed in, so a
     * Java-layer hook of [Context.getPackageName] (or the ApplicationInfo
     * source) cannot influence the comparison result.
     *
     * @return true if the package name matches the pinned value, false
     *         otherwise (also false when the native library is unavailable).
     */
    fun matchesId(context: Context): Boolean {
        if (!loaded) return false
        val packageName = try {
            context.packageName
        } catch (e: Exception) {
            AppLog.e("NativeProbe: cannot get packageName", e)
            return false
        }
        return try {
            nativeMatchPackageId(packageName)
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeMatchPackageId failed", e)
            false
        }
    }

    /**
     * Probes archive integrity entirely in native code:
     *   - ZIP End Of Central Directory (EOCD) structure is well formed;
     *   - central directory entries are consistent with local headers;
     *   - critical entries exist (classes.dex, AndroidManifest.xml,
     *     resources.arsc, META-INF entries, and the bundled native library
     *     under lib/abi);
     *   - classes.dex stored CRC matches the CRC recorded in the central
     *     directory (detects repackaging that deflates a replaced dex).
     *
     * Performed at the filesystem level, so Java-layer hooks of
     * ZipFile / AssetManager / PackageManager cannot hide a tampered archive.
     *
     * @param context used to resolve the running package path (packageCodePath)
     * @return [ProbeCode.OK] (0) on success, otherwise a bitmask of
     *         [ProbeCode] error flags; [ProbeCode.READ_FAILED] if the native
     *         library is unavailable or the archive cannot be read.
     */
    fun probeArchive(context: Context): Int {
        if (!loaded) return ProbeCode.READ_FAILED
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("NativeProbe: cannot get packageCodePath", e)
            return ProbeCode.READ_FAILED
        }
        return try {
            nativeProbeArchive(apkPath, requireRunning = true)
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeProbeArchive failed", e)
            ProbeCode.READ_FAILED
        }
    }

    /**
     * Error-code bitmask returned by [verifyBlock].
     * Mirrors the kBlock* constants in cpp/native_probe.cpp.
     */
    object BlockCode {
        const val OK = 0
        const val READ_FAILED = 1 shl 0
        const val NOT_FOUND = 1 shl 1
        const val MALFORMED = 1 shl 2
        const val CERT_MISMATCH = 1 shl 3
        const val SIG_ALGO_UNSUPPORTED = 1 shl 4
        const val SIG_INVALID = 1 shl 5
        const val CONTENT_MISMATCH = 1 shl 6
        const val DIGEST_UNSUPPORTED = 1 shl 7
    }

    /**
     * Verifies the v2/v3 signature record cryptographically: the signature is
     * checked against the public key of the pinned signing certificate and the
     * APK content digest is recomputed (1 MiB chunks, apksig framing) and
     * compared with the digest recorded in the block.
     *
     * Why this exists next to [matchesV234]: comparing the certificate in the
     * block only proves that the block *names* the pinned signer. The block
     * also carries the digests it signs, so a repack that edits the file
     * content and leaves the original signature record untouched (installable
     * wherever the installer's own signature verification is bypassed) still
     * passes that comparison. Only the signature check plus a recomputed
     * content digest reject it.
     *
     * The native side terminates the process on [BlockCode.SIG_INVALID] and
     * [BlockCode.CONTENT_MISMATCH] before returning, so a hook that rewrites
     * the value returned here cannot turn a rejection into a pass. It also
     * always cross-validates that [apkPath] is the APK image this process
     * executes from (raw-syscall open + inode cross-check against
     * /proc/self/maps): a substituted/redirected path terminates the process
     * the same way.
     *
     * @return a [BlockCode] bitmask.
     */
    fun verifyBlock(context: Context): Int {
        if (!loaded) return BlockCode.READ_FAILED
        val apkPath = try {
            context.packageCodePath
        } catch (e: Exception) {
            AppLog.e("NativeProbe: cannot get packageCodePath", e)
            return BlockCode.READ_FAILED
        }
        return try {
            nativeVerifyBlock(apkPath)
        } catch (e: Exception) {
            AppLog.e("NativeProbe: nativeVerifyBlock failed", e)
            BlockCode.READ_FAILED
        }
    }

    /**
     * True when a [verifyBlock] result proves tampering: the pinned signer is
     * present, but the signature or the content digest does not match it.
     *
     * Every other code means "could not verify" (missing block, unparsable
     * record, algorithm this build does not implement). Those states are
     * already rejected by the certificate-pin checks in the caller, and
     * treating them as tampering here would turn an unknown future signing
     * scheme into an unrecoverable startup kill.
     */
    fun isTamper(code: Int): Boolean = code == BlockCode.SIG_INVALID || code == BlockCode.CONTENT_MISMATCH
}
