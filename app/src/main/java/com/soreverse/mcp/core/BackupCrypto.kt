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
 * File format (encrypted):
 *   [0..8]      "SOMCP_ENC" magic bytes (8 B)
 *   [8]         version (1 B)
 *   [9]         salt length (1 B)
 *   [10..10+N)  salt bytes (N B)
 *   [10+N]      nonce length (1 B)
 *   (10+N+1..]  nonce bytes (M B)
 *   [remainder] AES-GCM ciphertext (includes 16 B authentication tag)
 *
 * Plaintext backups (no password) are unchanged — raw JSON.
 */
object BackupCrypto {

    private const val MAGIC = "SOMCP_ENC"
    private const val VERSION: Byte = 1
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val GCM_TAG_BITS = 128
    private const val KEY_BYTES = 32 // AES-256

    private val random = SecureRandom()
    private val argon2 = Argon2Kt()

    /**
     * Encrypt [plaintext] with [password] using Argon2id + AES-256-GCM.
     * Returns the binary blob (magic + params + ciphertext).
     */
    fun encrypt(plaintext: String, password: String): ByteArray {
        val salt = ByteArray(SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        return ByteArrayOutputStream().apply {
            write(MAGIC.toByteArray(Charsets.UTF_8))
            write(VERSION.toInt())
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
        require(version == VERSION.toInt()) { "Unsupported encryption version: $version" }
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

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(ciphertext).decodeToString()
    }

    /** Returns true when [data] starts with the encrypted-backup magic bytes. */
    fun isEncrypted(data: ByteArray): Boolean {
        if (data.size < MAGIC.length) return false
        return data.copyOfRange(0, MAGIC.length).decodeToString() == MAGIC
    }

    private fun deriveKey(password: String, salt: ByteArray): ByteArray {
        return argon2.hash(
            mode = Argon2Mode.Argon2id,
            password = password.toByteArray(Charsets.UTF_8),
            salt = salt,
            iterations = 3,
            memoryCostInPowOfTwo = 16,  // 2^16 KiB = 64 MiB
            hashLengthInBytes = KEY_BYTES,
            parallelism = 2,
        ).hash
    }
}