package com.soreverse.mcp.core

object DownloadMirrorPolicy {
    private val prefixes = listOf(
        "https://ghproxy.net/",
        "https://gh-proxy.com/",
        "https://ghp.ci/",
        "https://mirror.ghproxy.com/",
        "https://v6.gh-proxy.org/",
        "https://gh.llkk.cc/",
        "https://github-proxy.memory-echoes.cn/",
        "https://hub.gitmirror.com/",
        "https://moeyy.cn/gh-proxy/",
        "https://gh.zwy.one/",
    )

    fun candidates(original: String): List<String> {
        if (!original.startsWith("https://github.com/")) return listOf(original)
        val replacements = listOf("https://kkgithub.com", "https://bgithub.xyz").mapNotNull { host ->
            original.replaceFirst("https://github.com", host)
        }
        val xget = original.replaceFirst("https://github.com", "https://xget.xi-xu.me/gh")
        return (prefixes.map { it + original } + replacements + xget + original).distinct()
    }
}
