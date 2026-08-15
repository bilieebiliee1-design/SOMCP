package com.soreverse.mcp.core

import android.util.Base64
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.io.ByteArrayOutputStream
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypts and decrypts backup files using Argon2id key derivation + AES-256-GCM.
 *
 * Binary format (encrypted):
 *   [0..9)      "SOMCP_ENC" magic bytes (9 B)
 *   [9]         version (1 B)
 *   [10]        salt length (1 B)
 *   [11..11+N)  salt bytes (N B)
 *   [11+N]      nonce length (1 B)
 *   [12+N..)    nonce bytes (M B)
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
    private const val ARGON2_KEY_LENGTH = 32            // 256 bits for AES-256

    // Argon2id KDF parameters. These are part of the on-disk format: neither
    // format stores them, so changing a value makes every previously exported
    // backup of that format undecryptable. The two formats were shipped with
    // different parallelism values (binary=2, JSON=4); both are kept verbatim
    // and named so a future edit cannot silently unify them.
    private const val ARGON2_MEMORY_KIB = 64 * 1024     // 64 MiB, both formats
    private const val ARGON2_ITERATIONS = 3             // both formats
    private const val ARGON2_PARALLELISM_BIN_V1 = 2     // binary format, do not change
    private const val ARGON2_PARALLELISM_JSON_V1 = 4    // JSON format, do not change

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
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
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
        // Every field length below comes from the file itself, so each read is
        // bounds-checked. Without this a truncated or hand-edited backup surfaced
        // as an ArrayIndexOutOfBoundsException instead of a clear format error.
        fun need(count: Int, field: String) {
            require(count >= 0 && offset + count <= data.size) {
                "Encrypted backup is truncated or malformed (reading $field)"
            }
        }

        need(MAGIC.length, "magic")
        val magic = data.copyOfRange(offset, offset + MAGIC.length).decodeToString()
        require(magic == MAGIC) { "Not a valid encrypted backup" }
        offset += MAGIC.length

        need(1, "version")
        val version = data[offset].toInt() and 0xFF
        require(version == BIN_VERSION.toInt()) { "Unsupported encryption version: $version" }
        offset++

        need(1, "salt length")
        val saltLen = data[offset].toInt() and 0xFF
        offset++
        need(saltLen, "salt")
        val salt = data.copyOfRange(offset, offset + saltLen)
        offset += saltLen

        need(1, "nonce length")
        val nonceLen = data[offset].toInt() and 0xFF
        offset++
        need(nonceLen, "nonce")
        val nonce = data.copyOfRange(offset, offset + nonceLen)
        offset += nonceLen

        require(salt.isNotEmpty()) { "Encrypted backup has an empty salt" }
        require(nonce.isNotEmpty()) { "Encrypted backup has an empty nonce" }
        // GCM output always carries a 16-byte tag, so anything shorter cannot
        // authenticate and would fail deep inside the cipher.
        require(data.size - offset > GCM_TAG_BITS / 8) { "Encrypted backup has no ciphertext" }
        val ciphertext = data.copyOfRange(offset, data.size)
        val key = deriveKeyBinary(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
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
            parallelism = ARGON2_PARALLELISM_BIN_V1,
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
    fun isEncryptedBackup(obj: JSONObject): Boolean {
        return obj.optInt("v", -1) == JSON_VERSION && obj.optString("alg", "") == ALGORITHM &&
                obj.has("salt") && obj.has("nonce") && obj.has("ciphertext")
    }

    private fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val hash = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(),
            salt = salt,
            mCostInKibibyte = ARGON2_MEMORY_KIB,
            tCostInIterations = ARGON2_ITERATIONS,
            parallelism = ARGON2_PARALLELISM_JSON_V1,
            hashLengthInBytes = ARGON2_KEY_LENGTH,
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