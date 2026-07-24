package com.soreverse.mcp.core

import android.content.Context
import android.os.Build
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Unified backup & restore for the whole app configuration (the settings snapshot).
 *
 * The app already exposed a lossless `SettingsStore.snapshot()/applyPatch()` pair used by the
 * `app_config` MCP tool, but there was no single user-facing "backup & restore" entry point.
 * [BackupManager] wraps that snapshot in a small, versioned envelope and adds:
 *
 *  - Local export / import of the config snapshot as a portable JSON document (via SAF).
 *  - Optional WebDAV / S3-compatible remote backup.
 *
 * Secret handling is opt-in: [build] masks token/key fields by default (`includeSecrets = false`)
 * and only embeds raw credentials when the user explicitly ticks the "include secrets" box.
 * On [restore], secret fields are only written back when the envelope was created with secrets
 * *and* the caller allows it, so a masked backup can never overwrite a real token with a
 * `abcd…wxyz` placeholder — [SettingsStore.applyPatch] simply skips secret keys when
 * `allowSecrets = false`.
 */
object BackupManager {
    const val FORMAT = "somcp.backup"
    const val FORMAT_VERSION = 1

    private val JSON = "application/json; charset=utf-8".toMediaType()
    private val OCTET = "application/octet-stream".toMediaType()

    private fun client(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    // ---------------------------------------------------------------------
    // Envelope build / (de)serialize / restore
    // ---------------------------------------------------------------------

    /** Build a backup envelope from the current settings. Secrets are masked unless
     *  [includeSecrets] is true. */
    fun build(context: Context, settings: SettingsStore, includeSecrets: Boolean): JSONObject {
        val pkg = runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0)
        }.getOrNull()
        val versionCode = when {
            pkg == null -> 0L
            Build.VERSION.SDK_INT >= 28 -> pkg.longVersionCode
            else -> @Suppress("DEPRECATION") pkg.versionCode.toLong()
        }
        return JSONObject()
            .put("format", FORMAT)
            .put("formatVersion", FORMAT_VERSION)
            .put("app", context.packageName)
            .put("appVersionName", pkg?.versionName ?: "")
            .put("appVersionCode", versionCode)
            .put("createdAt", iso8601(Date()))
            .put("createdAtEpoch", System.currentTimeMillis())
            .put("includesSecrets", includeSecrets)
            .put("settings", settings.snapshot(maskSecrets = !includeSecrets))
    }

    fun serialize(envelope: JSONObject): ByteArray = envelope.toString(2).toByteArray(Charsets.UTF_8)

    /** Parse and validate a backup document. Throws [IllegalArgumentException] on malformed input. */
    fun parse(bytes: ByteArray): JSONObject {
        val text = bytes.toString(Charsets.UTF_8).trim()
        require(text.isNotEmpty()) { "empty backup file" }
        val obj = JSONObject(text)
        val fmt = obj.optString("format")
        require(fmt == FORMAT) { "unrecognized backup format: '$fmt'" }
        require(obj.has("settings")) { "backup has no settings section" }
        return obj
    }

    /** Apply a parsed backup envelope to [settings].
     *
     * @param importSecrets caller intent to restore credentials. The effective decision is
     *   `importSecrets && envelope.includesSecrets`, so a masked backup never touches secrets.
     * @return the [SettingsStore.applyPatch] result (ok / changed keys / masked config).
     */
    fun restore(settings: SettingsStore, envelope: JSONObject, importSecrets: Boolean): JSONObject {
        val includesSecrets = envelope.optBoolean("includesSecrets", false)
        val settingsPatch = envelope.optJSONObject("settings") ?: JSONObject()
        val allowSecrets = importSecrets && includesSecrets
        return settings.applyPatch(settingsPatch, allowSecrets = allowSecrets)
    }

    fun suggestedFileName(): String {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
            .apply { timeZone = TimeZone.getDefault() }
            .format(Date())
        return "somcp-backup-$ts.json"
    }

    // ---------------------------------------------------------------------
    // WebDAV
    // ---------------------------------------------------------------------

    fun webdavUpload(baseUrl: String, user: String, password: String, fileName: String, bytes: ByteArray) {
        val url = joinUrl(baseUrl, fileName)
        val builder = Request.Builder().url(url).put(bytes.toRequestBody(JSON))
        if (user.isNotBlank()) builder.header("Authorization", Credentials.basic(user, password))
        client().newCall(builder.build()).execute().use { resp ->
            check(resp.isSuccessful) { "WebDAV PUT failed: ${resp.code} ${resp.message}" }
        }
    }

    fun webdavDownload(baseUrl: String, user: String, password: String, fileName: String): ByteArray {
        val url = joinUrl(baseUrl, fileName)
        val builder = Request.Builder().url(url).get()
        if (user.isNotBlank()) builder.header("Authorization", Credentials.basic(user, password))
        client().newCall(builder.build()).execute().use { resp ->
            check(resp.isSuccessful) { "WebDAV GET failed: ${resp.code} ${resp.message}" }
            return resp.body?.bytes() ?: ByteArray(0)
        }
    }

    // ---------------------------------------------------------------------
    // S3-compatible object storage (AWS Signature V4, path-style addressing)
    // ---------------------------------------------------------------------

    data class S3Config(
        /** e.g. https://s3.us-east-1.amazonaws.com or http://192.168.1.10:9000 (MinIO). */
        val endpoint: String,
        val region: String,
        val bucket: String,
        val accessKey: String,
        val secretKey: String,
        val prefix: String = "",
    )

    fun s3Upload(cfg: S3Config, fileName: String, bytes: ByteArray) {
        val key = objectKey(cfg.prefix, fileName)
        val signed = signS3("PUT", cfg, key, bytes)
        val builder = Request.Builder().url(signed.url).put(bytes.toRequestBody(OCTET))
        signed.headers.forEach { (k, v) -> builder.header(k, v) }
        client().newCall(builder.build()).execute().use { resp ->
            check(resp.isSuccessful) { "S3 PUT failed: ${resp.code} ${resp.message}" }
        }
    }

    fun s3Download(cfg: S3Config, fileName: String): ByteArray {
        val key = objectKey(cfg.prefix, fileName)
        val signed = signS3("GET", cfg, key, ByteArray(0))
        val builder = Request.Builder().url(signed.url).get()
        signed.headers.forEach { (k, v) -> builder.header(k, v) }
        client().newCall(builder.build()).execute().use { resp ->
            check(resp.isSuccessful) { "S3 GET failed: ${resp.code} ${resp.message}" }
            return resp.body?.bytes() ?: ByteArray(0)
        }
    }

    private class SignedS3(val url: String, val headers: Map<String, String>)

    private fun signS3(method: String, cfg: S3Config, key: String, body: ByteArray): SignedS3 {
        val endpoint = cfg.endpoint.trim().trimEnd('/')
        val host = endpoint.substringAfter("://").substringBefore("/")
        val canonicalUri = "/" + cfg.bucket.trim('/') + "/" +
            key.split("/").joinToString("/") { uriEncode(it, encodeSlash = false) }
        val fullUrl = "$endpoint$canonicalUri"

        val now = Date()
        val amzDate = utc("yyyyMMdd'T'HHmmss'Z'").format(now)
        val dateStamp = utc("yyyyMMdd").format(now)
        val payloadHash = hex(sha256(body))

        val headers = sortedMapOf(
            "host" to host,
            "x-amz-content-sha256" to payloadHash,
            "x-amz-date" to amzDate,
        )
        val signedHeaders = headers.keys.joinToString(";")
        val canonicalHeaders = headers.entries.joinToString("") { "${it.key}:${it.value.trim()}\n" }
        val canonicalRequest = listOf(
            method,
            canonicalUri,
            "", // canonical query string (none)
            canonicalHeaders,
            signedHeaders,
            payloadHash,
        ).joinToString("\n")

        val service = "s3"
        val scope = "$dateStamp/${cfg.region}/$service/aws4_request"
        val stringToSign = listOf(
            "AWS4-HMAC-SHA256",
            amzDate,
            scope,
            hex(sha256(canonicalRequest.toByteArray(Charsets.UTF_8))),
        ).joinToString("\n")

        val kDate = hmac(("AWS4" + cfg.secretKey).toByteArray(Charsets.UTF_8), dateStamp)
        val kRegion = hmac(kDate, cfg.region)
        val kService = hmac(kRegion, service)
        val kSigning = hmac(kService, "aws4_request")
        val signature = hex(hmac(kSigning, stringToSign))

        val authorization =
            "AWS4-HMAC-SHA256 Credential=${cfg.accessKey}/$scope, " +
                "SignedHeaders=$signedHeaders, Signature=$signature"

        // Host is set automatically by OkHttp from the URL; we only send the amz + auth headers.
        val outHeaders = mapOf(
            "x-amz-date" to amzDate,
            "x-amz-content-sha256" to payloadHash,
            "Authorization" to authorization,
        )
        return SignedS3(fullUrl, outHeaders)
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    private fun objectKey(prefix: String, fileName: String): String {
        val p = prefix.trim().trim('/')
        return if (p.isEmpty()) fileName else "$p/$fileName"
    }

    private fun joinUrl(base: String, fileName: String): String {
        val b = base.trim()
        return if (b.endsWith("/")) "$b$fileName" else "$b/$fileName"
    }

    private fun iso8601(date: Date): String = utc("yyyy-MM-dd'T'HH:mm:ss'Z'").format(date)

    private fun utc(pattern: String): SimpleDateFormat =
        SimpleDateFormat(pattern, Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hmac(key: ByteArray, data: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8))
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun uriEncode(input: String, encodeSlash: Boolean): String {
        val sb = StringBuilder()
        for (raw in input.toByteArray(Charsets.UTF_8)) {
            val code = raw.toInt() and 0xFF
            val c = code.toChar()
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' ||
                    c == '-' || c == '_' || c == '.' || c == '~' -> sb.append(c)
                c == '/' && !encodeSlash -> sb.append(c)
                else -> sb.append('%').append("%02X".format(code))
            }
        }
        return sb.toString()
    }
}
