// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
package com.soreverse.mcp.core

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.lang.reflect.Method

/**
 * Reads assets that the release packer may have encrypted.
 *
 * The release and test-v10 APKs are packed with the VMP shell's
 * `--encrypt-assets`: every business asset under `assets/` is replaced by
 * `PAS1 || AES-GCM` ciphertext at `assets/rtcore/aenc/<path>` and the plaintext
 * entry is deleted. The shell's own `assets/rtcore/` subtree is excluded by
 * the packer itself, which is also why [INDEX_ASSET] stays readable.
 *
 * There is no transparent `AssetManager` hook (upstream documents this
 * explicitly), so the app has to decrypt those blobs itself. The AES-128 key
 * lives inside `librtcore.so` and is never handed to Java, so decryption has to
 * go through the shell's native entry point
 * `com.soreverse.mcp.rt.shell.NativeBridge.decryptAssetBlob(byte[])`. That class
 * is not on this module's compile classpath — the shell is injected at packaging
 * time — hence reflection; the shell's own proguard rules `-keep` the class and
 * its native methods, so the name survives R8. Both workflows assert the name is
 * still present in the exported shell dex.
 *
 * Everything here degrades to plain `AssetManager` reads for builds without the
 * shell (debug builds, fork PRs, local installs): the plaintext path is tried
 * first and only a missing plaintext entry falls back to the ciphertext.
 */
object ShellAssets {
    /** De-branded shell class exposing the PAS1 decryptor (keep-ruled upstream). */
    private const val BRIDGE_CLASS = "com.soreverse.mcp.rt.shell.NativeBridge"
    private const val BRIDGE_METHOD = "decryptAssetBlob"

    /** Ciphertext root and index written by the packer's `--encrypt-assets`. */
    private const val AENC_ROOT = "rtcore/aenc"
    private const val INDEX_ASSET = "rtcore/assets.map"
    private const val INDEX_COMMENT = "#"

    /** PAS1 magic (4) + AES-GCM nonce (12) + tag (16): a valid blob cannot be shorter. */
    private const val BLOB_OVERHEAD = 4 + 12 + 16

    @Volatile
    private var decryptMethod: Method? = null

    @Volatile
    private var bridgeProbed = false

    /**
     * Opens [path], transparently decrypting it when only the ciphertext exists.
     *
     * [path] is relative to `assets/`; a leading `/` or `assets/` is tolerated so
     * a caller cannot get this wrong by accident. The `rtcore/aenc/` prefix is an
     * implementation detail of this class and is not accepted here — callers
     * address assets by their plaintext name in both layouts.
     *
     * Rethrows the original [FileNotFoundException] when neither form is present,
     * so callers keep the stock "asset missing" semantics for a genuinely absent
     * file.
     */
    fun open(context: Context, path: String): InputStream {
        val rel = normalize(path)
        return try {
            context.assets.open(rel)
        } catch (plain: FileNotFoundException) {
            decrypt(context, rel) ?: throw plain
        }
    }

    /** [open] as UTF-8 text — the blutter manifest is the only text asset here. */
    fun readText(context: Context, path: String): String = open(context, path).bufferedReader().use { it.readText() }

    /**
     * Paths the packer encrypted, relative to `assets/`, in index order.
     *
     * Empty when the APK was packed without `--encrypt-assets`. Encryption
     * removes the plaintext tree, so `AssetManager.list()` can no longer
     * enumerate it — directory walks have to be driven by this index instead.
     */
    fun encryptedPaths(context: Context): List<String> {
        val index = try {
            context.assets.open(INDEX_ASSET).bufferedReader().use { it.readText() }
        } catch (missing: IOException) {
            return emptyList()
        }
        return index.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith(INDEX_COMMENT) }
            .toList()
    }

    private fun decrypt(context: Context, rel: String): InputStream? {
        val blob = try {
            context.assets.open("$AENC_ROOT/$rel").use { it.readBytes() }
        } catch (missing: FileNotFoundException) {
            return null
        }
        if (blob.size < BLOB_OVERHEAD) {
            throw IOException("PAS1 asset too short ($rel, ${blob.size} bytes)")
        }
        val plain = invokeDecrypt(blob) ?: throw IOException("PAS1 asset decrypt failed: $rel")
        return ByteArrayInputStream(plain)
    }

    private fun invokeDecrypt(blob: ByteArray): ByteArray? {
        val method = decryptMethodOrNull() ?: return null
        val result = runCatching { method.invoke(null, blob) }.getOrNull()
        return result as? ByteArray
    }

    private fun decryptMethodOrNull(): Method? {
        if (bridgeProbed) return decryptMethod
        synchronized(this) {
            if (!bridgeProbed) {
                decryptMethod = runCatching {
                    Class.forName(BRIDGE_CLASS).getMethod(BRIDGE_METHOD, ByteArray::class.java)
                }.getOrNull()
                bridgeProbed = true
            }
        }
        return decryptMethod
    }

    private fun normalize(path: String): String {
        var rel = path.replace('\\', '/')
        while (rel.startsWith("/")) {
            rel = rel.substring(1)
        }
        if (rel.startsWith("assets/")) {
            rel = rel.substring("assets/".length)
        }
        return rel
    }
}
