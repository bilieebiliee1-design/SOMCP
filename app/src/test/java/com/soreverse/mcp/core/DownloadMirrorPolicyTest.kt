package com.soreverse.mcp.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DownloadMirrorPolicyTest {
    @Test
    fun includesOriginalAndDistinctProxyCandidates() {
        val original = "https://github.com/example/app/releases/download/v1/app.apk"
        val candidates = DownloadMirrorPolicy.candidates(original)
        assertEquals(candidates.size, candidates.distinct().size)
        assertTrue(original in candidates)
        assertTrue("https://ghproxy.net/$original" in candidates)
        assertTrue(
            "https://xget.xi-xu.me/gh/example/app/releases/download/v1/app.apk" in candidates
        )
        assertTrue("https://kkgithub.com/example/app/releases/download/v1/app.apk" in candidates)
    }

    @Test
    fun doesNotRewriteNonGithubUrls() {
        val original = "https://cdn.example.com/app.apk"
        val candidates = DownloadMirrorPolicy.candidates(original)
        assertEquals(listOf(original), candidates)
    }

    @Test
    fun checksumCandidatesNeverRouteThroughMirrors() {
        val official = "https://github.com/example/app/releases/download/v1/app.apk.sha256"
        assertEquals(listOf(official), DownloadMirrorPolicy.checksumCandidates(official))
        // Non-github origins have no mirror set; they pass through unchanged.
        val other = "https://cdn.example.com/app.sha256"
        assertEquals(listOf(other), DownloadMirrorPolicy.checksumCandidates(other))
    }
}
