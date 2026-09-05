package com.soreverse.mcp.core

import android.util.Base64
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

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
 * JSON format (encrypted):
 *   { "v": 1, "alg": "argon2id+aes-gcm", "salt": "&lt;base64&gt;", "nonce": "&lt;base64&gt;", "ciphertext": "&lt;base64&gt;" }
 *
 * Plaintext backups (no password) are unchanged — raw JSON.
 */
object BackupCrypto {
    // Binary format constants
    private const val MAGIC = "SOMCP_ENC"
    private const val BIN_VERSION: Byte = 1
    private const val BIN_SALT_SIZE = 16
    private const val BIN_NONCE_SIZE = 12
    private const val GCM_TAG_BITS = 128
    private const val KEY_BYTES = 32 // AES-256

    // JSON format constants
    private const val JSON_VERSION = 1
    private const val ALGORITHM = "argon2id+aes-gcm"
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val TAG_SIZE_BITS = 128
    private const val ARGON2_MEMORY_KIB = 32 * 1024 // 32 MiB
    private const val ARGON2_ITERATIONS = 10
    private const val ARGON2_PARALLELISM = 4
    private const val ARGON2_KEY_LENGTH = 32 // 256 bits for AES-256

    private val random = SecureRandom()
    private val argon2 = Argon2Kt()

    // ===== Binary format (HEAD) =====

    /**
     * Encrypt [plaintext] with [password] using Argon2id + AES-256-GCM.
     * Returns the binary blob (magic + params + ciphertext).
     */
    fun encrypt(plaintext: String, password: String): ByteArray {
        val salt = ByteArray(BIN_SALT_SIZE).also(random::nextBytes)
        val nonce = ByteArray(BIN_NONCE_SIZE).also(random::nextBytes)
        val key = deriveKeyBinary(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

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
        val key = deriveKeyBinary(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        return cipher.doFinal(ciphertext).decodeToString()
    }

    /** Returns true when [data] starts with the encrypted-backup magic bytes. */
    fun isEncrypted(data: ByteArray): Boolean {
        if (data.size < MAGIC.length) return false
        return data.copyOfRange(0, MAGIC.length).decodeToString() == MAGIC
    }

    private fun deriveKeyBinary(password: String, salt: ByteArray): ByteArray {
        val hash = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = salt,
            mCostInKibibyte = ARGON2_MEMORY_KIB,
            tCostInIterations = ARGON2_ITERATIONS,
            hashLengthInBytes = KEY_BYTES,
            parallelism = ARGON2_PARALLELISM
        )
        return hash.rawHashAsByteArray()
    }

    // ===== JSON format (REMOTE) =====

    /** Encrypt [plaintext] bytes with [password] using Argon2id + AES-256-GCM. */
    fun encrypt(plaintext: ByteArray, password: String): JSONObject {
        val salt = ByteArray(SALT_SIZE).apply { random.nextBytes(this) }
        val nonce = ByteArray(NONCE_SIZE).apply { random.nextBytes(this) }

        val key = deriveKey(password, salt)
        val ciphertext = aesGcmEncrypt(plaintext, key, nonce)

        return JSONObject().apply {
            put("v", JSON_VERSION)
            put("alg", ALGORITHM)
            put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            put("nonce", Base64.encodeToString(nonce, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
        }
    }

    /** Decrypt an encrypted backup [obj] with [password]. */
    fun decrypt(obj: JSONObject, password: String): ByteArray {
        val version = obj.optInt("v", -1)
        if (version != JSON_VERSION) {
            throw IllegalArgumentException("Unsupported backup version: $version")
        }
        val alg = obj.optString("alg", "")
        if (alg != ALGORITHM) {
            throw IllegalArgumentException("Unsupported algorithm: $alg")
        }

        val salt = Base64.decode(obj.getString("salt"), Base64.NO_WRAP)
        val nonce = Base64.decode(obj.getString("nonce"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(obj.getString("ciphertext"), Base64.NO_WRAP)

        val key = deriveKey(password, salt)
        return aesGcmDecrypt(ciphertext, key, nonce)
    }

    /** Check whether a JSON object is an encrypted backup (has the expected structure). */
    fun isEncryptedBackup(obj: JSONObject): Boolean = obj.optInt("v", -1) == JSON_VERSION &&
        obj.optString("alg", "") == ALGORITHM &&
        obj.has("salt") &&
        obj.has("nonce") &&
        obj.has("ciphertext")

    private fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val hash = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(),
            salt = salt,
            mCostInKibibyte = ARGON2_MEMORY_KIB,
            tCostInIterations = ARGON2_ITERATIONS,
            parallelism = ARGON2_PARALLELISM,
            hashLengthInBytes = ARGON2_KEY_LENGTH
        )
        return hash.rawHashAsByteArray()
    }

    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(TAG_SIZE_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(TAG_SIZE_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(ciphertext)
    }
}
