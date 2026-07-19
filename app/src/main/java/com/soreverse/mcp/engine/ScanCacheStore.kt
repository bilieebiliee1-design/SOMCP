package com.soreverse.mcp.engine

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class CachedApkSo(
    val apkPath: String,
    val entry: String,
    val name: String,
    val abi: String,
    val size: Long,
)

data class CachedSourceSummary(
    val architecture: String,
    val bits: Int,
    val endian: String,
    val hasDebugInfo: Boolean,
    val stripped: Boolean,
)

class ScanCacheStore(context: Context) : SQLiteOpenHelper(context, "somcp_scan_cache.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE apk_so_entries (
                tree_uri TEXT NOT NULL,
                apk_path TEXT NOT NULL,
                apk_size INTEGER NOT NULL,
                apk_modified INTEGER NOT NULL,
                entry TEXT NOT NULL,
                name TEXT NOT NULL,
                abi TEXT NOT NULL,
                entry_size INTEGER NOT NULL,
                PRIMARY KEY(tree_uri, apk_path, apk_size, apk_modified, entry)
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE source_summaries (
                tree_uri TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                modified INTEGER NOT NULL,
                architecture TEXT NOT NULL,
                bits INTEGER NOT NULL,
                endian TEXT NOT NULL,
                has_debug INTEGER NOT NULL,
                stripped INTEGER NOT NULL,
                PRIMARY KEY(tree_uri, path, size, modified)
            )
            """.trimIndent(),
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS apk_so_entries")
        db.execSQL("DROP TABLE IF EXISTS source_summaries")
        onCreate(db)
    }

    fun apkEntries(treeUri: String, apkPath: String, apkSize: Long, apkModified: Long): List<CachedApkSo> {
        readableDatabase.query(
            "apk_so_entries",
            arrayOf("entry", "name", "abi", "entry_size"),
            "tree_uri=? AND apk_path=? AND apk_size=? AND apk_modified=?",
            arrayOf(treeUri, apkPath, apkSize.toString(), apkModified.toString()),
            null,
            null,
            "entry",
        ).use { cursor ->
            val out = mutableListOf<CachedApkSo>()
            val entryCol = cursor.getColumnIndexOrThrow("entry")
            val nameCol = cursor.getColumnIndexOrThrow("name")
            val abiCol = cursor.getColumnIndexOrThrow("abi")
            val sizeCol = cursor.getColumnIndexOrThrow("entry_size")
            while (cursor.moveToNext()) {
                out += CachedApkSo(
                    apkPath = apkPath,
                    entry = cursor.getString(entryCol),
                    name = cursor.getString(nameCol),
                    abi = cursor.getString(abiCol),
                    size = cursor.getLong(sizeCol),
                )
            }
            return out
        }
    }

    fun putApkEntries(treeUri: String, apkPath: String, apkSize: Long, apkModified: Long, entries: List<CachedApkSo>) {
        writableDatabase.beginTransaction()
        try {
            writableDatabase.delete(
                "apk_so_entries",
                "tree_uri=? AND apk_path=?",
                arrayOf(treeUri, apkPath),
            )
            entries.forEach { entry ->
                writableDatabase.insertWithOnConflict(
                    "apk_so_entries",
                    null,
                    ContentValues().apply {
                        put("tree_uri", treeUri)
                        put("apk_path", apkPath)
                        put("apk_size", apkSize)
                        put("apk_modified", apkModified)
                        put("entry", entry.entry)
                        put("name", entry.name)
                        put("abi", entry.abi)
                        put("entry_size", entry.size)
                    },
                    SQLiteDatabase.CONFLICT_REPLACE,
                )
            }
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun sourceSummary(treeUri: String, path: String, size: Long, modified: Long): CachedSourceSummary? {
        readableDatabase.query(
            "source_summaries",
            arrayOf("architecture", "bits", "endian", "has_debug", "stripped"),
            "tree_uri=? AND path=? AND size=? AND modified=?",
            arrayOf(treeUri, path, size.toString(), modified.toString()),
            null,
            null,
            null,
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            return CachedSourceSummary(
                architecture = cursor.getString(cursor.getColumnIndexOrThrow("architecture")),
                bits = cursor.getInt(cursor.getColumnIndexOrThrow("bits")),
                endian = cursor.getString(cursor.getColumnIndexOrThrow("endian")),
                hasDebugInfo = cursor.getInt(cursor.getColumnIndexOrThrow("has_debug")) != 0,
                stripped = cursor.getInt(cursor.getColumnIndexOrThrow("stripped")) != 0,
            )
        }
    }

    fun putSourceSummary(treeUri: String, path: String, size: Long, modified: Long, summary: CachedSourceSummary) {
        writableDatabase.insertWithOnConflict(
            "source_summaries",
            null,
            ContentValues().apply {
                put("tree_uri", treeUri)
                put("path", path)
                put("size", size)
                put("modified", modified)
                put("architecture", summary.architecture)
                put("bits", summary.bits)
                put("endian", summary.endian)
                put("has_debug", if (summary.hasDebugInfo) 1 else 0)
                put("stripped", if (summary.stripped) 1 else 0)
            },
            SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    fun clear() {
        writableDatabase.delete("apk_so_entries", null, null)
        writableDatabase.delete("source_summaries", null, null)
    }
}
