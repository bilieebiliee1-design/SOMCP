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
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package com.soreverse.mcp.core

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypts and decrypts backup files using Argon2id key derivation + AES-256-GCM.
 *
 * Binary format (encrypted):
 *   [0..8]      "SOMCP_ENC" magic bytes (8 B)
 *   [8]         version (1 B)
 *   [9]         salt length (1 B)
 *   [10..10+N)  salt bytes (N B)
 *   [10+N]      nonce length (1 B)
 *   (10+N+1..]  nonce bytes (M B)
 *   [remainder] AES-GCM ciphertext (includes 16 B authentication tag)
 *
 * Plaintext backups (no password) are unchanged — raw JSON.
 *
 * This is the only container format. The earlier JSON-envelope variant
 * (`{"v","alg","salt","nonce","ciphertext"}`) belonged to the withdrawn
 * WebDAV/S3 remote backup and had no exporter left: every export since has
 * written this binary container, so the format and its import branch are gone.
 */
object BackupCrypto {
    init {
        // Dex2C (see the "Harden release APKs with Dex2C (dcc)" step in
        // .github/workflows/release.yml): in the hardened release APKs the
        // methods below are `native` and their bodies live in libnc.so, so the
        // library has to be loaded before the first call. Builds that were not
        // hardened (debug, local release) simply have no such library - the
        // load fails and the Java implementations stay in effect, which is why
        // the failure is swallowed instead of being fatal.
        runCatching { System.loadLibrary("nc") }
    }

    private const val MAGIC = "SOMCP_ENC"
    private const val BIN_VERSION: Byte = 1
    private const val BIN_SALT_SIZE = 16
    private const val BIN_NONCE_SIZE = 12
    private const val GCM_TAG_BITS = 128
    private const val KEY_BYTES = 32 // AES-256
    private const val ARGON2_MEMORY_KIB = 32 * 1024 // 32 MiB
    private const val ARGON2_ITERATIONS = 10
    private const val ARGON2_PARALLELISM = 4

    private val random = SecureRandom()
    private val argon2 = Argon2Kt()

    /**
     * Encrypt [plaintext] with [password] using Argon2id + AES-256-GCM.
     * Returns the binary blob (magic + params + ciphertext).
     */
    fun encrypt(plaintext: String, password: String): ByteArray {
        val salt = ByteArray(BIN_SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(BIN_NONCE_SIZE).also(random::nextBytes)
        val key = deriveKey(password, salt)

        val ciphertext = aesGcmEncrypt(plaintext.toByteArray(Charsets.UTF_8), key, nonce)

        return ByteArrayOutputStream().apply {
            write(MAGIC.toByteArray(Charsets.UTF_8))
            write(BIN_VERSION.toInt())
            write(salt.size)
            write(salt)
            write(nonce.size)
            write(nonce)
            write(ciphertext)
        }.toByteArray()
    }

    /**
     * Decrypt [data] with [password]. Asserts magic + version, then
     * extracts salt / nonce / ciphertext and runs AES-256-GCM.
     */
    fun decrypt(data: ByteArray, password: String): String {
        var offset = 0

        val magic = data.copyOfRange(offset, offset + MAGIC.length).decodeToString()
        require(magic == MAGIC) { "Not a valid encrypted backup" }
        offset += MAGIC.length

        val version = data[offset].toInt() and 0xFF
        require(version == BIN_VERSION.toInt()) { "Unsupported encryption version: $version" }
        offset++

        val saltLen = data[offset].toInt() and 0xFF
        offset++
        val salt = data.copyOfRange(offset, offset + saltLen)
        offset += saltLen

        val nonceLen = data[offset].toInt() and 0xFF
        offset++
        val nonce = data.copyOfRange(offset, offset + nonceLen)
        offset += nonceLen

        val ciphertext = data.copyOfRange(offset, data.size)
        val key = deriveKey(password, salt)

        return aesGcmDecrypt(ciphertext, key, nonce).decodeToString()
    }

    /** Returns true when [data] starts with the encrypted-backup magic bytes. */
    fun isEncrypted(data: ByteArray): Boolean {
        if (data.size < MAGIC.length) return false
        return data.copyOfRange(0, MAGIC.length).decodeToString() == MAGIC
    }

    private fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val hash = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = salt,
            mCostInKibibyte = ARGON2_MEMORY_KIB,
            tCostInIterations = ARGON2_ITERATIONS,
            parallelism = ARGON2_PARALLELISM,
            hashLengthInBytes = KEY_BYTES
        )
        return hash.rawHashAsByteArray()
    }

    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(ciphertext)
    }
}
