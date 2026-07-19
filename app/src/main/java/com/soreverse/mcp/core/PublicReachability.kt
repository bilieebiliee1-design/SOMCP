package com.soreverse.mcp.core

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

object PublicReachability {
    private val client = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    fun probe(url: String, zh: Boolean, callback: (String) -> Unit) {
        Thread {
            val body = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"android-probe","version":"1.0"}}}"""
                .toRequestBody("application/json".toMediaType())
            val req = Request.Builder()
                .url(url)
                .post(body)
                .header("Accept", "application/json, text/event-stream")
                .build()
            val result = runCatching {
                client.newCall(req).execute().use { response ->
                    if (zh) {
                        "HTTP ${response.code}：${if (response.isSuccessful) "此设备路径可访问" else response.message}"
                    } else {
                        "HTTP ${response.code}: ${if (response.isSuccessful) "reachable from this device path" else response.message}"
                    }
                }
            }.getOrElse { if (zh) "探测失败：${it.message}" else "Probe failed: ${it.message}" }
            AppLog.i("Reachability $url -> $result")
            callback(result)
        }.start()
    }
}
