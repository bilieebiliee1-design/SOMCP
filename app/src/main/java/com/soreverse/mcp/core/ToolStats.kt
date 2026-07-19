package com.soreverse.mcp.core

import android.content.Context
import com.soreverse.mcp.mcp.ToolCatalog
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * ToolStats
 *
 * In-memory per-tool call statistics with optional persistence to
 * externalFilesDir/toolstats.json. Two reasons this exists:
 *  - process restart otherwise wipes stats, so the settings-page bar chart and
 *    meta_info (action=stats) cannot answer "which tool is slow over the week" questions;
 *  - the popularity weights fed back into ToolCatalog (adaptive CORE set)
 *    need a stable view across restarts to converge.
 *
 * Persistence is throttled: at most one flush every 15 s, so a hot tool loop
 * cannot thrash the disk. reset() also deletes the file.
 */
object ToolStats {
    private data class Stat(
        var calls: Long = 0,
        var ok: Long = 0,
        var failed: Long = 0,
        var totalMicros: Long = 0,
        var maxMicros: Long = 0,
        var lastError: String = "",
        var lastAt: Long = 0,
    )

    private val stats = ConcurrentHashMap<String, Stat>()
    @Volatile private var enabled = true
    @Volatile private var startedAt = System.currentTimeMillis()
    @Volatile private var persistEnabled = true
    private var ctx: Context? = null
    @Volatile private var lastFlushAt = 0L
    private const val FLUSH_MIN_GAP_MS = 15_000L

    fun setEnabled(v: Boolean) { enabled = v }
    fun setPersistEnabled(v: Boolean) { persistEnabled = v }
    fun attachContext(context: Context) {
        ctx = context.applicationContext
        if (persistEnabled) loadFromDisk()
    }

    fun reset() {
        stats.clear()
        startedAt = System.currentTimeMillis()
        runCatching { statsFile()?.delete() }
    }

    fun record(name: String, ok: Boolean, micros: Long, error: String = "") {
        if (!enabled) return
        val s = stats.computeIfAbsent(name) { Stat() }
        synchronized(s) {
            s.calls++
            if (ok) s.ok++ else s.failed++
            s.totalMicros += micros
            if (micros > s.maxMicros) s.maxMicros = micros
            if (!ok) s.lastError = error
            s.lastAt = System.currentTimeMillis()
        }
        maybePersist()
    }

    private fun maybePersist() {
        if (!persistEnabled) return
        val now = System.currentTimeMillis()
        if (now - lastFlushAt < FLUSH_MIN_GAP_MS) return
        lastFlushAt = now
        Thread(::persistToDisk, "toolstats-flush").start()
    }

    private fun statsFile(): File? {
        val c = ctx ?: return null
        val dir = File(c.getExternalFilesDir(null) ?: c.filesDir, "stats")
        if (!dir.exists()) dir.mkdirs()
        return File(dir, "toolstats.json")
    }

    private fun loadFromDisk() {
        val f = statsFile() ?: return
        if (!f.exists()) return
        runCatching {
            val obj = JSONObject(f.readText())
            val arr = obj.optJSONArray("tools") ?: return@runCatching
            for (i in 0 until arr.length()) {
                val t = arr.optJSONObject(i) ?: continue
                val name = t.optString("tool")
                if (name.isBlank()) continue
                val s = Stat()
                s.calls = t.optLong("calls")
                s.ok = t.optLong("ok")
                s.failed = t.optLong("failed")
                s.totalMicros = (t.optDouble("avgMs") * 1000.0).toLong() * s.calls
                s.maxMicros = (t.optDouble("maxMs") * 1000.0).toLong()
                s.lastError = t.optString("lastError", "")
                s.lastAt = t.optLong("lastAt")
                stats[name] = s
            }
            startedAt = obj.optLong("startedAt", System.currentTimeMillis())
        }.onFailure { AppLog.w("toolstats load failed: ${it.message}") }
    }

    private fun persistToDisk() {
        val f = statsFile() ?: return
        runCatching {
            val snap = snapshot()
            f.writeText(snap.toString())
        }.onFailure { AppLog.w("toolstats persist failed: ${it.message}") }
    }

    fun snapshot(): JSONObject {
        val now = System.currentTimeMillis()
        val arr = JSONArray()
        var totalCalls = 0L
        var totalOk = 0L
        var totalFailed = 0L
        stats.entries.sortedByDescending { it.value.lastAt }.forEach { (name, s) ->
            val snapshot = s
            val avgMicros = if (snapshot.calls > 0) snapshot.totalMicros / snapshot.calls else 0
            arr.put(JSONObject()
                .put("tool", name)
                .put("calls", snapshot.calls)
                .put("ok", snapshot.ok)
                .put("failed", snapshot.failed)
                .put("avgMs", avgMicros / 1000.0)
                .put("maxMs", snapshot.maxMicros / 1000.0)
                .put("lastError", snapshot.lastError)
                .put("lastAt", snapshot.lastAt))
            totalCalls += snapshot.calls
            totalOk += snapshot.ok
            totalFailed += snapshot.failed
        }
        return JSONObject()
            .put("collecting", enabled)
            .put("persistEnabled", persistEnabled)
            .put("uptimeMillis", now - startedAt)
            .put("totalCalls", totalCalls)
            .put("totalOk", totalOk)
            .put("totalFailed", totalFailed)
            .put("distinctTools", stats.size)
            .put("tools", arr)
    }

    /**
     * Popularity score per tool name used by ToolCatalog to adapt the lean
     * CORE set. Score = total calls weighted by recency (last 7 days count
     * twice as much as older calls). Failure-only tools never get into CORE.
     */
    fun popularity(): Map<String, Long> {
        val now = System.currentTimeMillis()
        val week = 7L * 24 * 3600 * 1000
        val out = HashMap<String, Long>()
        stats.forEach { (name, s) ->
            val recent = if (s.lastAt > 0 && now - s.lastAt < week) 2L else 1L
            val okRatio = if (s.calls == 0L) 0.0 else s.ok.toDouble() / s.calls
            if (okRatio < 0.5) return@forEach
            out[name] = s.calls * recent
        }
        // Always include curated registry tools with a tiny floor so adaptive
        // promotion can outrank them when usage grows.
        ToolCatalog.ALL.forEach { e ->
            if (out[e.meta.name] == null && e.meta.cls == com.soreverse.mcp.mcp.ToolClass.CORE) {
                out[e.meta.name] = 1L
            }
        }
        return out
    }
}
