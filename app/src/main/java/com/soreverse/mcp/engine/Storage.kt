package com.soreverse.mcp.engine

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.soreverse.mcp.core.AppLog
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext

data class SoSource(
    val path: String,
    val source: String,
    val name: String,
    val size: Long,
    val modified: Long,
    val treeDocumentUri: Uri?,
    val apkPath: String? = null,
    val apkEntry: String? = null,
    val abi: String? = null
) {
    override fun equals(other: Any?): Boolean = other is SoSource && other.path == path
    override fun hashCode(): Int = path.hashCode()
}

data class ScanOptions(
    val scanApks: Boolean = true,
    val scanSubdirectories: Boolean = true,
    val maxDepth: Int = 8,
    val skipFilesLargerThanBytes: Long = 512L * 1024L * 1024L
)

/** Files >= this size (10 MiB) use the fast channel-based read path. */
private const val LARGE_FILE_THRESHOLD = 10L * 1024L * 1024L

data class FileFingerprint(val path: String, val size: Long, val modified: Long)

class WorkDirectory(private val context: Context, private val treeUri: Uri) {
    private val resolver: ContentResolver = context.contentResolver
    private val cache = ScanCacheStore(context.applicationContext)
    private val treeKey = treeUri.toString()

    fun fingerprint(options: ScanOptions): List<FileFingerprint> {
        val out = mutableListOf<FileFingerprint>()
        runCatching {
            walk(treeUri, "", 0, options) { _, displayName, relativePath, size, modified ->
                if (displayName.endsWith(".so", ignoreCase = true) ||
                    (options.scanApks && displayName.endsWith(".apk", ignoreCase = true))
                ) {
                    out += FileFingerprint(relativePath, size, modified)
                }
            }
        }.onFailure { AppLog.w("Failed to fingerprint work directory: ${it.message}") }
        return out.sortedWith(
            compareBy<FileFingerprint> {
                it.path
            }.thenBy { it.modified }.thenBy { it.size }
        )
    }

    fun listSos(options: ScanOptions = ScanOptions()): List<SoSource> {
        val out = mutableListOf<SoSource>()
        val apkPaths = mutableListOf<Pair<String, Uri>>()
        runCatching {
            walk(treeUri, "", 0, options) { docUri, displayName, relativePath, size, modified ->
                if (displayName.endsWith(".so", ignoreCase = true)) {
                    out += SoSource(relativePath, "filesystem", displayName, size, modified, docUri)
                } else if (options.scanApks && displayName.endsWith(".apk", ignoreCase = true)) {
                    apkPaths += relativePath to docUri
                }
            }
        }.onFailure { AppLog.w("Failed to scan work directory: ${it.message}") }

        // Scan APKs in parallel
        if (apkPaths.isNotEmpty()) {
            val entries = runCatching {
                kotlinx.coroutines.runBlocking {
                    apkPaths.map { (relPath, uri) ->
                        async(Dispatchers.IO) {
                            scanApk(relPath, uri, modified = System.currentTimeMillis())
                        }
                    }.awaitAll().flatten()
                }
            }.getOrElse { emptyList() }
            out += entries
        }

        return out.sortedBy { it.path }
    }

    /**
     * Single-pass scan that returns SO sources AND fingerprints simultaneously,
     * avoiding the need for a separate [fingerprint] walk.
     */
    fun listSosWithFingerprint(
        options: ScanOptions = ScanOptions()
    ): Pair<List<SoSource>, List<FileFingerprint>> {
        val sources = mutableListOf<SoSource>()
        val fingerprints = mutableListOf<FileFingerprint>()
        val apkPaths = mutableListOf<Pair<String, Uri>>()

        runCatching {
            walk(treeUri, "", 0, options) { docUri, displayName, relativePath, size, modified ->
                if (displayName.endsWith(".so", ignoreCase = true)) {
                    sources +=
                        SoSource(relativePath, "filesystem", displayName, size, modified, docUri)
                    fingerprints += FileFingerprint(relativePath, size, modified)
                } else if (options.scanApks && displayName.endsWith(".apk", ignoreCase = true)) {
                    apkPaths += relativePath to docUri
                    fingerprints += FileFingerprint(relativePath, size, modified)
                }
            }
        }.onFailure { AppLog.w("Failed to scan work directory: ${it.message}") }

        // Scan APKs in parallel
        if (apkPaths.isNotEmpty()) {
            val entries = runCatching {
                kotlinx.coroutines.runBlocking {
                    apkPaths.map { (relPath, uri) ->
                        async(Dispatchers.IO) {
                            scanApk(relPath, uri, modified = System.currentTimeMillis())
                        }
                    }.awaitAll().flatten()
                }
            }.getOrElse { emptyList() }
            sources += entries
        }

        val sorted = sources.sortedBy { it.path }
        val sortedFp = fingerprints.sortedWith(
            compareBy<FileFingerprint> {
                it.path
            }.thenBy { it.modified }.thenBy { it.size }
        )
        return sorted to sortedFp
    }

    fun cachedSummary(source: SoSource): CachedSourceSummary? =
        cache.sourceSummary(treeKey, source.path, source.size, source.modified)

    fun putCachedSummary(source: SoSource, summary: CachedSourceSummary) {
        cache.putSourceSummary(treeKey, source.path, source.size, source.modified, summary)
    }

    fun clearPersistentCache() {
        cache.clear()
    }

    fun readSource(source: SoSource): ByteArray = if (source.source == "apk") {
        val heapBudget = (Runtime.getRuntime().maxMemory() / 8L).coerceIn(
            8L * 1024L * 1024,
            64L * 1024L * 1024
        )
        val declaredLimit = source.size.takeIf { it > 0 }?.plus(1L) ?: heapBudget
        extractZipEntry(
            source.treeDocumentUri ?: error("Missing APK document uri"),
            source.apkEntry ?: error("Missing APK entry"),
            minOf(declaredLimit, heapBudget)
        )
    } else {
        val uri = source.treeDocumentUri ?: error("Missing document uri")
        if (source.size >= LARGE_FILE_THRESHOLD) {
            readBytesChannel(uri, source.size) ?: readBytes(uri)
        } else {
            readBytes(uri)
        }
    }

    /**
     * Read a specific byte range from a file using ParcelFileDescriptor for efficient seeking.
     * Returns null if the URI doesn't support file descriptors.
     */
    fun readByteRange(uri: Uri, offset: Long, size: Int): ByteArray? = try {
        resolver.openFileDescriptor(uri, "r")?.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { fis ->
                fis.channel.use { channel ->
                    val buf = ByteBuffer.allocate(size)
                    channel.position(offset)
                    while (buf.hasRemaining()) {
                        val n = channel.read(buf)
                        if (n < 0) break
                    }
                    buf.flip()
                    val result = ByteArray(buf.remaining())
                    buf.get(result)
                    result
                }
            }
        }
    } catch (e: Exception) {
        null
    }

    /**
     * Fast path for reading large files: uses ParcelFileDescriptor + FileChannel
     * with direct buffers for better I/O throughput compared to the ContentResolver stream.
     * Returns null if the URI doesn't support file descriptors.
     */
    private fun readBytesChannel(uri: Uri, size: Long): ByteArray? {
        if (size > 256L * 1024L * 1024L) return null // cap at 256 MiB
        return try {
            resolver.openFileDescriptor(uri, "r")?.use { pfd ->
                FileInputStream(pfd.fileDescriptor).use { fis ->
                    fis.channel.use { channel ->
                        val buf = ByteBuffer.allocateDirect(size.toInt())
                        while (buf.hasRemaining()) {
                            val n = channel.read(buf)
                            if (n < 0) break
                        }
                        buf.flip()
                        val result = ByteArray(buf.remaining())
                        buf.get(result)
                        result
                    }
                }
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse ELF header from a file URI to extract source summary metadata.
     * Uses [readByteRange] for efficient seeking — only reads the ELF header,
     * section header table, and section name string table instead of the full file.
     * Returns null if the URI doesn't support file descriptors or parsing fails.
     */
    internal fun readElfSummary(uri: Uri): SourceSummary? {
        // Read ELF header (64 bytes max — covers both 32-bit and 64-bit)
        val header = readByteRange(uri, 0L, 64) ?: return null
        if (header.size < 52 || header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() ||
            header[2] != 'L'.code.toByte() ||
            header[3] != 'F'.code.toByte()
        ) {
            return null
        }

        val bits = when (header[4].toInt() and 0xff) {
            1 -> 32
            2 -> 64
            else -> return null
        }
        val isLittle = (header[5].toInt() and 0xff) != 2
        val order = if (isLittle) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val headerBuf = ByteBuffer.wrap(header, 0, header.size).order(order)

        // e_machine at offset 18 (uint16)
        val machine = headerBuf.getShort(18).toInt() and 0xFFFF
        val architecture = when (machine) {
            3 -> "x86"
            40 -> "ARM"
            62 -> "x86_64"
            183 -> "AArch64"
            8 -> "MIPS"
            20 -> "PowerPC"
            50 -> "IA-64"
            243 -> "RISC-V"
            else -> "unknown"
        }
        val endian = if (isLittle) "little" else "big"

        // Parse section header table location
        val shoff: Long
        val shnum: Int
        val shentsize: Int
        val shstrndx: Int
        if (bits == 64) {
            if (header.size < 64) return SourceSummary(architecture, bits, endian, false, true)
            shoff = headerBuf.getLong(0x28)
            shnum = headerBuf.getShort(0x3C).toInt() and 0xFFFF
            shentsize = headerBuf.getShort(0x3A).toInt() and 0xFFFF
            shstrndx = headerBuf.getShort(0x3E).toInt() and 0xFFFF
        } else {
            shoff = headerBuf.getInt(0x20).toLong() and 0xFFFFFFFFL
            shnum = headerBuf.getShort(0x30).toInt() and 0xFFFF
            shentsize = headerBuf.getShort(0x2E).toInt() and 0xFFFF
            shstrndx = headerBuf.getShort(0x32).toInt() and 0xFFFF
        }

        if (shoff <= 0 || shnum <= 0 ||
            shentsize <= 0
        ) {
            return SourceSummary(architecture, bits, endian, false, true)
        }

        // Read section header table
        val shdrTotal = shnum * shentsize
        val shdrBytes = readByteRange(uri, shoff, shdrTotal) ?: return null
        if (shdrBytes.size <
            shdrTotal
        ) {
            return SourceSummary(architecture, bits, endian, false, true)
        }

        // Use a single ByteBuffer for all section header reads
        val shdrBuf = ByteBuffer.wrap(shdrBytes).order(order)

        // Read section name string table header
        val shstrHdrOff = shstrndx * shentsize
        if (shstrHdrOff + shentsize >
            shdrBytes.size
        ) {
            return SourceSummary(architecture, bits, endian, false, true)
        }

        val shstrtabOff = if (bits ==
            64
        ) {
            shdrBuf.getLong(shstrHdrOff + 24)
        } else {
            (
                shdrBuf.getInt(shstrHdrOff + 16).toLong() and
                    0xFFFFFFFFL
                )
        }
        val shstrtabSize = if (bits ==
            64
        ) {
            shdrBuf.getLong(shstrHdrOff + 32)
        } else {
            (
                shdrBuf.getInt(shstrHdrOff + 20).toLong() and
                    0xFFFFFFFFL
                )
        }
        if (shstrtabOff <= 0 || shstrtabSize <= 0 ||
            shstrtabSize > 1024 * 1024
        ) {
            return SourceSummary(architecture, bits, endian, false, true)
        }

        // Read section name string table
        val shstrtabBytes = readByteRange(uri, shstrtabOff, shstrtabSize.toInt()) ?: return null
        if (shstrtabBytes.size <
            shstrtabSize.toInt()
        ) {
            return SourceSummary(architecture, bits, endian, false, true)
        }

        // Scan section headers for .debug section names and symbol table presence
        var hasDebug = false
        var hasSymbols = false
        for (i in 0 until shnum) {
            val hdrOff = i * shentsize
            if (hdrOff + 4 > shdrBytes.size) break
            val nameOff = shdrBuf.getInt(hdrOff)
            if (nameOff < 0 || nameOff >= shstrtabBytes.size) continue

            // Read null-terminated section name from strtab
            val nameEnd = nameOff.let { off ->
                var e = off
                while (e < shstrtabBytes.size &&
                    shstrtabBytes[e].toInt() != 0
                ) {
                    e++
                }
                e
            }
            val name = if (nameEnd >
                nameOff
            ) {
                shstrtabBytes.copyOfRange(nameOff, nameEnd).toString(Charsets.UTF_8)
            } else {
                ""
            }

            if (name.startsWith(".debug")) hasDebug = true
            if (!hasSymbols && (name == ".symtab" || name == ".dynsym")) {
                val symSize = if (bits ==
                    64
                ) {
                    shdrBuf.getLong(hdrOff + 32)
                } else {
                    (
                        shdrBuf.getInt(hdrOff + 20).toLong() and
                            0xFFFFFFFFL
                        )
                }
                if (symSize > 0) hasSymbols = true
            }
        }

        return SourceSummary(architecture, bits, endian, hasDebug, !hasSymbols)
    }

    fun readFile(relativePath: String, maxBytes: Long = Long.MAX_VALUE): ByteArray {
        var found: Uri? = null
        walk(
            treeUri,
            "",
            0,
            ScanOptions(scanApks = true, scanSubdirectories = true, maxDepth = 32)
        ) {
                uri,
                _,
                path,
                _,
                _
            ->
            if (path == relativePath) found = uri
        }
        return readBytes(
            found ?: error("File not found in work directory: $relativePath"),
            maxBytes
        )
    }

    fun writeRootFile(
        displayName: String,
        bytes: ByteArray,
        mimeType: String = "application/octet-stream"
    ): SoSource {
        val safeName = displayName.substringAfterLast('/').substringAfterLast('\\').ifBlank {
            "downloaded.so"
        }
        val parent = documentUriForTree()
        val uri = DocumentsContract.createDocument(resolver, parent, mimeType, safeName)
            ?: error("Cannot create file in work directory parent=$parent tree=$treeUri")
        resolver.openOutputStream(uri, "wt").use { out ->
            requireNotNull(out) { "Cannot open output stream for $safeName" }
            out.write(bytes)
        }
        return SoSource(
            safeName,
            "filesystem",
            safeName,
            bytes.size.toLong(),
            System.currentTimeMillis(),
            uri
        )
    }

    fun documentUriForTree(): Uri {
        val treeDocumentId = runCatching {
            DocumentsContract.getTreeDocumentId(treeUri)
        }.getOrElse {
            error("Invalid work directory tree URI: $treeUri (${it.message})")
        }
        return DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocumentId)
    }

    fun rootAbsolutePath(): String = displayPath(treeUri)

    fun isAccessible(): Boolean = runCatching {
        val doc = documentUriForTree()
        resolver.query(
            doc,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID),
            null,
            null,
            null
        )?.use {
            it.count >=
                0
        } ==
            true
    }.getOrDefault(false)

    // Shared APK scanning with caching — used by both listSos and listSosWithFingerprint
    private fun scanApk(relativePath: String, docUri: Uri, modified: Long): List<SoSource> {
        val size = 0L // size not available at this point; cached path uses the cached value
        return runCatching {
            val cached = runCatching {
                cache.apkEntries(treeKey, relativePath, size, modified)
            }.getOrElse {
                AppLog.w("Failed to read scan cache for $relativePath: ${it.message}")
                emptyList()
            }
            if (cached.isNotEmpty()) {
                cached.map {
                    SoSource(
                        path = "apk:$relativePath!${it.entry}",
                        source = "apk",
                        name = it.name,
                        size = it.size,
                        modified = modified,
                        treeDocumentUri = docUri,
                        apkPath = relativePath,
                        apkEntry = it.entry,
                        abi = it.abi
                    )
                }
            } else {
                val entries = listApkSos(relativePath, docUri, modified)
                runCatching {
                    cache.putApkEntries(
                        treeKey,
                        relativePath,
                        size,
                        modified,
                        entries.map {
                            CachedApkSo(
                                relativePath,
                                it.apkEntry.orEmpty(),
                                it.name,
                                it.abi.orEmpty(),
                                it.size
                            )
                        }
                    )
                }.onFailure {
                    AppLog.w("Failed to update scan cache for $relativePath: ${it.message}")
                }
                entries
            }
        }.getOrElse {
            AppLog.w("Failed to scan APK $relativePath: ${it.message}")
            emptyList()
        }
    }

    private fun listApkSos(apkPath: String, apkUri: Uri, modified: Long): List<SoSource> {
        val items = mutableListOf<SoSource>()
        resolver.openInputStream(apkUri).use { input ->
            requireNotNull(input) { "Cannot open $apkUri" }
            ZipInputStream(input).use { zis ->
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
                            abi = abi
                        )
                    }
                    zis.closeEntry()
                }
            }
        }
        return items
    }

    private fun extractZipEntry(apkUri: Uri, entryName: String, maxBytes: Long): ByteArray {
        resolver.openInputStream(apkUri).use { input ->
            requireNotNull(input) { "Cannot open $apkUri" }
            ZipInputStream(input).use { zis ->
                while (true) {
                    val entry = zis.nextEntry ?: break
                    if (!entry.isDirectory && entry.name == entryName) {
                        if (entry.size >
                            maxBytes
                        ) {
                            throw ApkAnalysisLimitException(
                                "APK entry exceeds $maxBytes byte heap budget"
                            )
                        }
                        val out = ByteArrayOutputStream(32 * 1024)
                        val buffer = ByteArray(64 * 1024)
                        var total = 0L
                        while (true) {
                            val count = zis.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total >
                                maxBytes
                            ) {
                                throw ApkAnalysisLimitException(
                                    "APK entry exceeds $maxBytes byte limit"
                                )
                            }
                            out.write(buffer, 0, count)
                        }
                        return out.toByteArray()
                    }
                    zis.closeEntry()
                }
            }
        }
        error("Entry not found: $entryName")
    }

    private fun walk(
        dirUri: Uri,
        prefix: String,
        depth: Int,
        options: ScanOptions,
        onFile: (Uri, String, String, Long, Long) -> Unit
    ) {
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
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            ),
            null,
            null,
            null
        )?.use { cursor ->
            val idCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME
            )
            val mimeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            while (cursor.moveToNext()) {
                val id = cursor.getString(idCol)
                val name = cursor.getString(nameCol) ?: continue
                val mime = cursor.getString(mimeCol).orEmpty()
                val size = if (cursor.isNull(sizeCol)) 0L else cursor.getLong(sizeCol)
                val modified = if (modifiedCol >= 0 &&
                    !cursor.isNull(modifiedCol)
                ) {
                    cursor.getLong(modifiedCol)
                } else {
                    0L
                }
                val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id)
                val rel = if (prefix.isBlank()) name else "$prefix/$name"
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    if (options.scanSubdirectories && depth < options.maxDepth) {
                        runCatching { walk(docUri, rel, depth + 1, options, onFile) }
                            .onFailure { AppLog.w("Failed to scan directory $rel: ${it.message}") }
                    }
                } else if (size <= options.skipFilesLargerThanBytes ||
                    name.endsWith(".so", ignoreCase = true)
                ) {
                    onFile(docUri, name, rel, size, modified)
                }
            }
        }
    }

    private fun readBytes(uri: Uri, maxBytes: Long = Long.MAX_VALUE): ByteArray {
        resolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Cannot open $uri" }
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total >
                    maxBytes
                ) {
                    throw ApkAnalysisLimitException("Input exceeds $maxBytes byte limit")
                }
                out.write(buffer, 0, count)
            }
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
