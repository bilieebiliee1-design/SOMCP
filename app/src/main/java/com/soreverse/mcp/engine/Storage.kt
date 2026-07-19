package com.soreverse.mcp.engine

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.soreverse.mcp.core.AppLog
import java.io.ByteArrayOutputStream
import java.util.zip.ZipInputStream

data class SoSource(
    val path: String,
    val source: String,
    val name: String,
    val size: Long,
    val modified: Long,
    val treeDocumentUri: Uri?,
    val apkPath: String? = null,
    val apkEntry: String? = null,
    val abi: String? = null,
) {
    override fun equals(other: Any?): Boolean = other is SoSource && other.path == path
    override fun hashCode(): Int = path.hashCode()
}

data class ScanOptions(
    val scanApks: Boolean = true,
    val scanSubdirectories: Boolean = true,
    val maxDepth: Int = 8,
    val skipFilesLargerThanBytes: Long = 512L * 1024L * 1024L,
)

data class FileFingerprint(
    val path: String,
    val size: Long,
    val modified: Long,
)

class WorkDirectory(private val context: Context, private val treeUri: Uri) {
    private val resolver: ContentResolver = context.contentResolver
    private val cache = ScanCacheStore(context.applicationContext)
    private val treeKey = treeUri.toString()

    fun fingerprint(options: ScanOptions): List<FileFingerprint> {
        val out = mutableListOf<FileFingerprint>()
        runCatching { walk(treeUri, "", 0, options) { _, displayName, relativePath, size, modified ->
            if (displayName.endsWith(".so", ignoreCase = true) || (options.scanApks && displayName.endsWith(".apk", ignoreCase = true))) {
                out += FileFingerprint(relativePath, size, modified)
            }
        } }.onFailure { AppLog.w("Failed to fingerprint work directory: ${it.message}") }
        return out.sortedWith(compareBy<FileFingerprint> { it.path }.thenBy { it.modified }.thenBy { it.size })
    }

    fun listSos(options: ScanOptions = ScanOptions()): List<SoSource> {
        val out = mutableListOf<SoSource>()
        runCatching { walk(treeUri, "", 0, options) { docUri, displayName, relativePath, size, modified ->
            if (displayName.endsWith(".so", ignoreCase = true)) {
                out += SoSource(relativePath, "filesystem", displayName, size, modified, docUri)
            } else if (options.scanApks && displayName.endsWith(".apk", ignoreCase = true)) {
                runCatching {
                    val cached = runCatching { cache.apkEntries(treeKey, relativePath, size, modified) }.getOrElse {
                        AppLog.w("Failed to read scan cache for $relativePath: ${it.message}")
                        emptyList()
                    }
                    if (cached.isNotEmpty()) {
                        out += cached.map {
                            SoSource(
                                path = "apk:$relativePath!${it.entry}",
                                source = "apk",
                                name = it.name,
                                size = it.size,
                                modified = modified,
                                treeDocumentUri = docUri,
                                apkPath = relativePath,
                                apkEntry = it.entry,
                                abi = it.abi,
                            )
                        }
                    } else {
                        val apkBytes = readBytes(docUri)
                        val entries = listApkSos(relativePath, docUri, apkBytes, modified)
                        runCatching { cache.putApkEntries(
                            treeKey,
                            relativePath,
                            size,
                            modified,
                            entries.map { CachedApkSo(relativePath, it.apkEntry.orEmpty(), it.name, it.abi.orEmpty(), it.size) },
                        ) }.onFailure { AppLog.w("Failed to update scan cache for $relativePath: ${it.message}") }
                        out += entries
                    }
                }.onFailure { AppLog.w("Failed to scan APK $relativePath: ${it.message}") }
            }
        } }.onFailure { AppLog.w("Failed to scan work directory: ${it.message}") }
        return out.sortedBy { it.path }
    }

    fun cachedSummary(source: SoSource): CachedSourceSummary? =
        cache.sourceSummary(treeKey, source.path, source.size, source.modified)

    fun putCachedSummary(source: SoSource, summary: CachedSourceSummary) {
        cache.putSourceSummary(treeKey, source.path, source.size, source.modified, summary)
    }

    fun clearPersistentCache() {
        cache.clear()
    }

    fun readSource(source: SoSource): ByteArray {
        return if (source.source == "apk") {
            val apkBytes = readBytes(source.treeDocumentUri ?: error("Missing APK document uri"))
            extractZipEntry(apkBytes, source.apkEntry ?: error("Missing APK entry"))
        } else {
            readBytes(source.treeDocumentUri ?: error("Missing document uri"))
        }
    }

    fun readFile(relativePath: String): ByteArray {
        var found: Uri? = null
        walk(treeUri, "", 0, ScanOptions(scanApks = true, scanSubdirectories = true, maxDepth = 32)) { uri, _, path, _, _ ->
            if (path == relativePath) found = uri
        }
        return readBytes(found ?: error("File not found in work directory: $relativePath"))
    }

    fun writeRootFile(displayName: String, bytes: ByteArray, mimeType: String = "application/octet-stream"): SoSource {
        val safeName = displayName.substringAfterLast('/').substringAfterLast('\\').ifBlank { "downloaded.so" }
        val parent = documentUriForTree()
        val uri = DocumentsContract.createDocument(resolver, parent, mimeType, safeName)
            ?: error("Cannot create file in work directory parent=$parent tree=$treeUri")
        resolver.openOutputStream(uri, "wt").use { out ->
            requireNotNull(out) { "Cannot open output stream for $safeName" }
            out.write(bytes)
        }
        return SoSource(safeName, "filesystem", safeName, bytes.size.toLong(), System.currentTimeMillis(), uri)
    }

    fun documentUriForTree(): Uri {
        val treeDocumentId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrElse {
            error("Invalid work directory tree URI: $treeUri (${it.message})")
        }
        return DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocumentId)
    }

    fun isAccessible(): Boolean = runCatching {
        val doc = documentUriForTree()
        resolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { it.count >= 0 } == true
    }.getOrDefault(false)

    private fun listApkSos(apkPath: String, apkUri: Uri, apkBytes: ByteArray, modified: Long): List<SoSource> {
        val items = mutableListOf<SoSource>()
        ZipInputStream(apkBytes.inputStream()).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                if (!entry.isDirectory && entry.name.matches(Regex("^lib/[^/]+/[^/]+\\.so$"))) {
                    val abi = entry.name.split('/')[1]
                    items += SoSource(
                        path = "apk:$apkPath!${entry.name}",
                        source = "apk",
                        name = entry.name.substringAfterLast('/'),
                        size = entry.size.takeIf { it >= 0 } ?: 0L,
                        modified = modified,
                        treeDocumentUri = apkUri,
                        apkPath = apkPath,
                        apkEntry = entry.name,
                        abi = abi,
                    )
                }
                zis.closeEntry()
            }
        }
        return items
    }

    private fun extractZipEntry(zipBytes: ByteArray, entryName: String): ByteArray {
        ZipInputStream(zipBytes.inputStream()).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                if (!entry.isDirectory && entry.name == entryName) {
                    return zis.readBytes()
                }
                zis.closeEntry()
            }
        }
        error("Entry not found: $entryName")
    }

    private fun walk(dirUri: Uri, prefix: String, depth: Int, options: ScanOptions, onFile: (Uri, String, String, Long, Long) -> Unit) {
        val treeDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
        val documentId = if (dirUri == treeUri) {
            treeDocumentId
        } else {
            DocumentsContract.getDocumentId(dirUri).ifEmpty { treeDocumentId }
        }
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
        resolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            val idCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            while (cursor.moveToNext()) {
                val id = cursor.getString(idCol)
                val name = cursor.getString(nameCol) ?: continue
                val mime = cursor.getString(mimeCol).orEmpty()
                val size = if (cursor.isNull(sizeCol)) 0L else cursor.getLong(sizeCol)
                val modified = if (modifiedCol >= 0 && !cursor.isNull(modifiedCol)) cursor.getLong(modifiedCol) else 0L
                val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id)
                val rel = if (prefix.isBlank()) name else "$prefix/$name"
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    if (options.scanSubdirectories && depth < options.maxDepth) {
                        runCatching { walk(docUri, rel, depth + 1, options, onFile) }
                            .onFailure { AppLog.w("Failed to scan directory $rel: ${it.message}") }
                    }
                } else if (size <= options.skipFilesLargerThanBytes || name.endsWith(".so", ignoreCase = true)) {
                    onFile(docUri, name, rel, size, modified)
                }
            }
        }
    }

    private fun readBytes(uri: Uri): ByteArray {
        resolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Cannot open $uri" }
            val out = ByteArrayOutputStream()
            input.copyTo(out)
            return out.toByteArray()
        }
    }

    companion object {
        fun displayPath(uri: Uri): String {
            val id = runCatching { DocumentsContract.getTreeDocumentId(uri) }.getOrNull().orEmpty()
            if (id.startsWith("primary:")) {
                val rel = id.substringAfter("primary:").trim('/')
                return if (rel.isBlank()) "/storage/emulated/0" else "/storage/emulated/0/$rel"
            }
            if (id.startsWith("home:")) {
                val rel = id.substringAfter("home:").trim('/')
                return if (rel.isBlank()) "/storage/emulated/0/Documents" else "/storage/emulated/0/Documents/$rel"
            }
            val volume = id.substringBefore(':', "")
            val rel = id.substringAfter(':', "").trim('/')
            if (volume.isNotBlank()) return if (rel.isBlank()) "/storage/$volume" else "/storage/$volume/$rel"
            return uri.toString()
        }
    }
}
