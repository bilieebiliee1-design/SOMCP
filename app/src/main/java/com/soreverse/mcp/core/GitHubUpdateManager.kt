package com.soreverse.mcp.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import com.soreverse.mcp.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.TimeUnit

data class GitHubRelease(
    val tag: String,
    val name: String,
    val notes: String,
    val pageUrl: String,
    val apkName: String,
    val apkUrl: String,
    val apkSize: Long,
    val checksumUrl: String?,
)

sealed interface UpdateCheckResult {
    data class Available(val release: GitHubRelease) : UpdateCheckResult
    data object Current : UpdateCheckResult
}

sealed interface UpdateDownloadEvent {
    data class Probing(val total: Int) : UpdateDownloadEvent
    data class ProbeResult(
        val source: String,
        val reachable: Boolean,
        val latencyMs: Long,
        val completed: Int,
        val total: Int,
    ) : UpdateDownloadEvent
    data class Selected(val source: String) : UpdateDownloadEvent
    data class Downloading(val source: String, val percent: Int) : UpdateDownloadEvent
    data object Verifying : UpdateDownloadEvent
    /** Emitted when checksum verification is skipped (asset missing/unreachable). */
    data class VerifySkipped(val reason: String) : UpdateDownloadEvent
}

/** The checksum asset could not be fetched; verification is skipped (soft). */
class ChecksumUnavailableException(message: String) : Exception(message)

/** A checksum was fetched but did not match the download; hard failure. */
class ChecksumMismatchException(message: String) : Exception(message)

class GitHubUpdateManager(private val context: Context) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()
    private val probeClient = client.newBuilder()
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    // Serializes the whole download() body. When the user switches mirrors we
    // cancel the previous download coroutine, but cancellation is cooperative and
    // the old coroutine may still be mid-write when the new one starts. Without
    // this lock two coroutines could race on the same .part file, and a
    // late-finishing old mirror could overwrite/verify on top of the new one
    // (exactly the "mirror A finishes then B downloads again" bug). Holding the
    // mutex for the entire download makes a new attempt wait until the previous
    // one has fully unwound.
    private val downloadMutex = Mutex()

    suspend fun check(): Result<UpdateCheckResult> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url(LATEST_RELEASE_URL)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "SOMCP/${BuildConfig.VERSION_NAME}")
                .build()
            val result = client.newCall(request).await().use { response ->
                if (response.code == 404) return@use UpdateCheckResult.Current
                if (!response.isSuccessful) error("GitHub HTTP ${response.code} ${response.message}")
                val root = JSONObject(response.body.string())
                val tag = root.optString("tag_name")
                if (!isNewer(tag, BuildConfig.VERSION_NAME)) return@use UpdateCheckResult.Current
                val assets = root.optJSONArray("assets") ?: error("Release has no assets")
                val apk = selectApk((0 until assets.length()).map { assets.getJSONObject(it) })
                    ?: error("Release has no APK for ${Build.SUPPORTED_ABIS.joinToString()}")
                val checksum = (0 until assets.length())
                    .map { assets.getJSONObject(it) }
                    .firstOrNull {
                        val name = it.optString("name")
                        name == "${apk.optString("name")}.sha256" || name == "SHA256SUMS"
                    }
                UpdateCheckResult.Available(
                    GitHubRelease(
                        tag = tag,
                        name = root.optString("name").ifBlank { tag },
                        notes = root.optString("body"),
                        pageUrl = root.optString("html_url"),
                        apkName = apk.getString("name"),
                        apkUrl = apk.getString("browser_download_url"),
                        apkSize = apk.optLong("size"),
                        checksumUrl = checksum?.optString("browser_download_url")?.takeIf(String::isNotBlank),
                    ),
                )
            }
            Result.success(result)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Throwable) {
            Result.failure(error)
        }
    }

    suspend fun download(
        release: GitHubRelease,
        forcedSource: String? = null,
        onEvent: (UpdateDownloadEvent) -> Unit,
    ): Result<File> =
        withContext(Dispatchers.IO) {
            try {
                downloadMutex.withLock {
                suspend fun emit(event: UpdateDownloadEvent) {
                    withContext(Dispatchers.Main.immediate) { onEvent(event) }
                }
                // A previous (now-cancelled) attempt may have just completed and
                // populated the cache; re-check inside the lock so a mirror switch
                // that raced a finishing download reuses the verified file instead
                // of downloading again.
                cachedDownload(release)?.let { return@withLock Result.success(it) }
                val directory = File(context.cacheDir, "updates").apply { mkdirs() }
                val target = File(directory, release.apkName.substringAfterLast('/'))
                val partial = File(directory, "${target.name}.part")
                val verified = File(directory, "${target.name}.verified")
                directory.listFiles()?.filter { it !in setOf(target, verified) }?.forEach { it.delete() }
                // When the user manually picks a mirror we honour it first and
                // skip the speed probe entirely (their choice solves the
                // "fast to probe but slow to download" case); the remaining
                // mirrors stay as automatic fallbacks after it.
                val candidates = if (forcedSource != null) {
                    val all = DownloadMirrorPolicy.candidates(release.apkUrl)
                    val preferred = all.filter { sourceName(it) == forcedSource }
                    (preferred + all.filterNot { it in preferred }).ifEmpty { all }
                } else {
                    rankedDownloadUrls(release.apkUrl, ::emit)
                }
                var lastFailure: Throwable? = null
                var downloaded = false
                for (url in candidates) {
                    ensureActive()
                    partial.delete()
                    try {
                        emit(UpdateDownloadEvent.Selected(sourceName(url)))
                        val request = Request.Builder()
                            .url(url)
                            .header("User-Agent", "SOMCP/${BuildConfig.VERSION_NAME}")
                            .build()
                        client.newCall(request).await().use { response ->
                            if (!response.isSuccessful) error("Download HTTP ${response.code} ${response.message}")
                            val body = response.body
                            val total = body.contentLength().takeIf { it > 0 } ?: release.apkSize
                            body.byteStream().use { input ->
                                partial.outputStream().use { output ->
                                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                                    var copied = 0L
                                    var lastPercent = -1
                                    while (true) {
                                        currentCoroutineContext().ensureActive()
                                        val count = input.read(buffer)
                                        if (count < 0) break
                                        output.write(buffer, 0, count)
                                        copied += count
                                        if (total > 0) {
                                            val percent = ((copied * 100) / total).toInt().coerceIn(0, 100)
                                            if (percent != lastPercent) {
                                                lastPercent = percent
                                                emit(UpdateDownloadEvent.Downloading(sourceName(url), percent))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (partial.length() > 4 && partial.inputStream().use {
                                val header = ByteArray(4)
                                it.read(header) == 4 && header.contentEquals(byteArrayOf(0x50, 0x4B, 0x03, 0x04))
                            }) {
                            downloaded = true
                            break
                        }
                        error("Downloaded asset is not a valid APK archive")
                    } catch (error: CancellationException) {
                        partial.delete()
                        throw error
                    } catch (error: Throwable) {
                        lastFailure = error
                    }
                }
                require(downloaded) { lastFailure?.message ?: "All download mirrors failed" }
                emit(UpdateDownloadEvent.Verifying)
                // Checksum verification is best-effort: the payload has already
                // been validated as a well-formed APK/ZIP above. If the checksum
                // asset cannot be fetched in time (mirror down / slow / missing),
                // we must NOT hang or hard-fail the whole update — we downgrade to
                // an unverified-but-installable result instead of dying on one
                // tree. A checksum that is fetched AND mismatches is still a hard
                // failure (that means tampering / corruption).
                val verifiedHash = release.checksumUrl?.let { url ->
                    runCatching { verifyChecksum(partial, url, target.name) }
                        .onFailure { emit(UpdateDownloadEvent.VerifySkipped(it.message ?: "checksum unavailable")) }
                        .getOrElse { failure ->
                            if (failure is ChecksumMismatchException) throw failure
                            null
                        }
                } ?: run {
                    emit(UpdateDownloadEvent.VerifySkipped("no checksum published"))
                    null
                }
                runCatching {
                    Files.move(partial.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                }.getOrElse {
                    Files.move(partial.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
                }
                // Only persist the .verified marker when we actually verified the
                // hash; otherwise the cached-download fast path must re-check.
                if (verifiedHash != null) verified.writeText(verifiedHash) else verified.delete()
                Result.success(target)
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Throwable) {
                File(File(context.cacheDir, "updates"), "${release.apkName.substringAfterLast('/')}.part").delete()
                Result.failure(error)
            }
        }

    fun cachedDownload(release: GitHubRelease): File? {
        val file = File(File(context.cacheDir, "updates"), release.apkName.substringAfterLast('/'))
        val verified = File(file.parentFile, "${file.name}.verified")
        if (!file.isFile || file.length() <= 4) return null
        val sizeOk = release.apkSize <= 0 || file.length() == release.apkSize
        if (!sizeOk) return null
        val expectedHash = verified.readTextOrNull()?.trim()?.lowercase()?.takeIf { it.matches(Regex("[a-f0-9]{64}")) }
        if (expectedHash != null) {
            // Re-hash the actual bytes: a predictable marker alone must never be trusted.
            val actualHash = runCatching { fileSha256(file) }.getOrNull() ?: return null
            return file.takeIf { actualHash == expectedHash }
        }
        // No verified marker (checksum was unavailable at download time). Fall back
        // to a structural check so a previously downloaded APK is still reusable
        // instead of forcing a slow re-download that would likely be unverifiable
        // again anyway.
        val looksLikeApk = runCatching {
            file.inputStream().use {
                val header = ByteArray(4)
                it.read(header) == 4 && header.contentEquals(byteArrayOf(0x50, 0x4B, 0x03, 0x04))
            }
        }.getOrDefault(false)
        return file.takeIf { looksLikeApk }
    }

    private suspend fun rankedDownloadUrls(
        original: String,
        emit: suspend (UpdateDownloadEvent) -> Unit,
    ): List<String> = coroutineScope {
        val candidates = DownloadMirrorPolicy.candidates(original)
        emit(UpdateDownloadEvent.Probing(candidates.size))
        val completed = java.util.concurrent.atomic.AtomicInteger(0)
        val ranked = candidates.map { url -> async(Dispatchers.IO) {
                ensureActive()
                val started = System.nanoTime()
                val reachable = try {
                    probeClient.newCall(
                        Request.Builder()
                            .head()
                            .url(url)
                            .header("User-Agent", "SOMCP/${BuildConfig.VERSION_NAME}")
                            .build(),
                    ).await().use { it.isSuccessful || it.code in 300..399 || it.code == 405 }
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Throwable) {
                    false
                }
                val latencyMs = (System.nanoTime() - started) / 1_000_000
                emit(
                    UpdateDownloadEvent.ProbeResult(
                        sourceName(url),
                        reachable,
                        latencyMs,
                        completed.incrementAndGet(),
                        candidates.size,
                    ),
                )
                Triple(url, reachable, latencyMs)
            }
        }.awaitAll()
        ranked.sortedWith(
            compareByDescending<Triple<String, Boolean, Long>> { it.second }.thenBy { it.third },
        ).map { it.first }
    }

    private fun sourceName(url: String): String = runCatching { Uri.parse(url).host.orEmpty() }
        .getOrDefault(url.substringBefore('/'))

    /** Distinct, user-selectable mirror host names for [release], in policy order. */
    fun mirrorSources(release: GitHubRelease): List<String> =
        DownloadMirrorPolicy.candidates(release.apkUrl).map(::sourceName).filter { it.isNotBlank() }.distinct()


    fun install(file: File): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            return false
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        context.startActivity(
            Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION),
        )
        return true
    }

    private fun selectApk(assets: List<JSONObject>): JSONObject? {
        val apks = assets.filter { it.optString("name").endsWith(".apk", true) }
        val abiNames = Build.SUPPORTED_ABIS.flatMap { abi ->
            listOf(abi.lowercase(), abi.lowercase().replace('-', '_'))
        }
        return apks.firstOrNull { asset -> abiNames.any { it in asset.optString("name").lowercase() } }
            ?: apks.firstOrNull { "universal" in it.optString("name").lowercase() }
            ?: apks.singleOrNull()
    }

    private fun isNewer(remote: String, local: String): Boolean {
        val remoteParts = remote.trim().removePrefix("v").split('.', '-', '+').mapNotNull(String::toIntOrNull)
        val localParts = local.trim().removePrefix("v").split('.', '-', '+').mapNotNull(String::toIntOrNull)
        for (index in 0 until maxOf(remoteParts.size, localParts.size)) {
            val comparison = (remoteParts.getOrNull(index) ?: 0).compareTo(localParts.getOrNull(index) ?: 0)
            if (comparison != 0) return comparison > 0
        }
        return false
    }

    private suspend fun verifyChecksum(file: File, url: String, assetName: String = file.name): String {
        var expected: String? = null
        var lastFailure: Throwable? = null
        // Bound the total time spent chasing checksum mirrors so a slow/hanging
        // mirror cannot make the whole update appear stuck. Try a limited number
        // of ranked candidates, each already under probeClient/client timeouts.
        val candidates = rankedDownloadUrls(url) {}.take(CHECKSUM_MIRROR_ATTEMPTS)
        for (candidate in candidates) {
            try {
                val request = Request.Builder().url(candidate).header("User-Agent", "SOMCP/${BuildConfig.VERSION_NAME}").build()
                expected = client.newCall(request).await().use { response ->
                    if (!response.isSuccessful) error("Checksum HTTP ${response.code}")
                    val text = response.body.string()
                    Regex("(?i)([a-f0-9]{64})\\s+\\*?${Regex.escape(assetName)}(?:\\s|$)")
                        .find(text)?.groupValues?.get(1)
                        ?: Regex("(?i)^[a-f0-9]{64}$").find(text.trim())?.value
                        ?: error("Checksum file does not contain $assetName")
                }
                break
            } catch (error: CancellationException) {
                throw error
            } catch (error: Throwable) {
                lastFailure = error
            }
        }
        // Could not obtain a checksum -> signal "unavailable" (soft failure that
        // the caller downgrades to an unverified install), NOT a mismatch.
        val expectedHash = expected ?: throw ChecksumUnavailableException(lastFailure?.message ?: "All checksum mirrors failed")
        val actual = fileSha256(file)
        // Obtained a checksum but it does not match -> hard failure (tampering).
        if (!actual.equals(expectedHash, true)) throw ChecksumMismatchException("APK SHA-256 verification failed")
        return actual.lowercase()
    }

    private fun fileSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun File.readTextOrNull(): String? = runCatching { takeIf(File::isFile)?.readText() }.getOrNull()

    companion object {
        const val REPOSITORY_URL = "https://github.com/bilieebiliee1-design/SOMCP"
        private const val LATEST_RELEASE_URL = "https://api.github.com/repos/bilieebiliee1-design/SOMCP/releases/latest"
        private const val CHECKSUM_MIRROR_ATTEMPTS = 4
    }
}
