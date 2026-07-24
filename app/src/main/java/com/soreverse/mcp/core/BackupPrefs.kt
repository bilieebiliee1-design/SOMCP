package com.soreverse.mcp.core

import android.content.Context

/**
 * Persistence for the *destination* of remote backups (WebDAV / S3) and the local
 * "include secrets" preference.
 *
 * These are intentionally kept out of [SettingsStore.snapshot]: they describe *where* a backup
 * goes, not the app configuration that gets backed up, so they should not travel inside a backup
 * file. They live in the same `so_reverse_mcp` SharedPreferences so they survive app restarts.
 * Secret fields (passwords / secret keys) are run through [sanitizeCredential] like every other
 * credential in the app.
 */
class BackupPrefs(context: Context) {
    private val prefs = context.getSharedPreferences("so_reverse_mcp", Context.MODE_PRIVATE)

    var includeSecrets: Boolean
        get() = prefs.getBoolean("backupIncludeSecrets", false)
        set(value) = prefs.edit().putBoolean("backupIncludeSecrets", value).apply()

    /** none | webdav | s3 */
    var remoteType: String
        get() = prefs.getString("backupRemoteType", "none") ?: "none"
        set(value) = prefs.edit().putString(
            "backupRemoteType",
            if (value in setOf("none", "webdav", "s3")) value else "none",
        ).apply()

    // ---- WebDAV ----
    var webdavUrl: String
        get() = prefs.getString("backupWebdavUrl", "") ?: ""
        set(value) = prefs.edit().putString("backupWebdavUrl", value.trim()).apply()

    var webdavUser: String
        get() = prefs.getString("backupWebdavUser", "") ?: ""
        set(value) = prefs.edit().putString("backupWebdavUser", value).apply()

    var webdavPassword: String
        get() = sanitizeCredential(prefs.getString("backupWebdavPassword", "").orEmpty())
        set(value) = prefs.edit().putString("backupWebdavPassword", sanitizeCredential(value)).apply()

    // ---- S3-compatible ----
    var s3Endpoint: String
        get() = prefs.getString("backupS3Endpoint", "") ?: ""
        set(value) = prefs.edit().putString("backupS3Endpoint", value.trim()).apply()

    var s3Region: String
        get() = prefs.getString("backupS3Region", "us-east-1") ?: "us-east-1"
        set(value) = prefs.edit().putString("backupS3Region", value.trim().ifBlank { "us-east-1" }).apply()

    var s3Bucket: String
        get() = prefs.getString("backupS3Bucket", "") ?: ""
        set(value) = prefs.edit().putString("backupS3Bucket", value.trim()).apply()

    var s3AccessKey: String
        get() = prefs.getString("backupS3AccessKey", "") ?: ""
        set(value) = prefs.edit().putString("backupS3AccessKey", value.trim()).apply()

    var s3SecretKey: String
        get() = sanitizeCredential(prefs.getString("backupS3SecretKey", "").orEmpty())
        set(value) = prefs.edit().putString("backupS3SecretKey", sanitizeCredential(value)).apply()

    var s3Prefix: String
        get() = prefs.getString("backupS3Prefix", "") ?: ""
        set(value) = prefs.edit().putString("backupS3Prefix", value.trim()).apply()
}
