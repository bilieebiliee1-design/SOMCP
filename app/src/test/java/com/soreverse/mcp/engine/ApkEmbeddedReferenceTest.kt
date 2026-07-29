package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApkEmbeddedReferenceTest {
    @Test
    fun parsesCanonicalApkPrefixedReference() {
        val ref = parseApkEmbeddedReference("apk:games/App.apk!lib/arm64-v8a/libfoo.so")
        assertEquals("App.apk", ref?.apkBasename)
        assertEquals("lib/arm64-v8a/libfoo.so", ref?.entry)
    }

    @Test
    fun parsesAbsolutePathWithBangEntry() {
        val ref = parseApkEmbeddedReference("/storage/emulated/0/x/App.apk!lib/arm64-v8a/libfoo.so")
        assertEquals("App.apk", ref?.apkBasename)
        assertEquals("lib/arm64-v8a/libfoo.so", ref?.entry)
    }

    @Test
    fun parsesContentApkUriWithNestedApkPath() {
        val ref = parseApkEmbeddedReference("content://apk/sub/App.apk/lib/armeabi-v7a/libbar.so")
        assertEquals("App.apk", ref?.apkBasename)
        assertEquals("lib/armeabi-v7a/libbar.so", ref?.entry)
    }

    @Test
    fun parsesApkSlashEntryWithoutContentPrefix() {
        val ref = parseApkEmbeddedReference("/data/App.apk/lib/x86_64/libbaz.so")
        assertEquals("App.apk", ref?.apkBasename)
        assertEquals("lib/x86_64/libbaz.so", ref?.entry)
    }

    @Test
    fun parsesBareLibEntryWithNoApkHint() {
        val ref = parseApkEmbeddedReference("lib/arm64-v8a/libfoo.so")
        assertNull(ref?.apkBasename)
        assertEquals("lib/arm64-v8a/libfoo.so", ref?.entry)
    }

    @Test
    fun normalizesLeadingSlashAndDotSlashInEntry() {
        val ref = parseApkEmbeddedReference("apk:App.apk!/./lib/arm64-v8a/libfoo.so")
        assertEquals("App.apk", ref?.apkBasename)
        assertEquals("lib/arm64-v8a/libfoo.so", ref?.entry)
    }

    @Test
    fun rejectsPlainFilesystemPath() {
        assertNull(parseApkEmbeddedReference("/storage/emulated/0/libfoo.so"))
    }

    @Test
    fun rejectsApkReferenceWithoutEntry() {
        assertNull(parseApkEmbeddedReference("apk:App.apk!"))
    }

    @Test
    fun rejectsBlankInput() {
        assertNull(parseApkEmbeddedReference("   "))
    }
}
