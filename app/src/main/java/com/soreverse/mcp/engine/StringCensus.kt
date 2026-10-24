// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure JVM-testable string census logic behind str_encoding_census,
// str_literal_classes, net_endpoint_extract, file_path_roots and
// env_property_keys. Input is the parsed string table (StringInfo list) plus
// the raw bytes for the UTF-16LE sweep the parser does not perform.
package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject

internal object StringCensus {
    private val URL_RE = Regex("^(https?|wss?|ftp|rtmp|rtsp)://\\S+$")
    private val IP_PORT_RE = Regex("^(\\d{1,3}(\\.\\d{1,3}){3}):(\\d{1,5})$")
    private val HOST_PORT_RE = Regex("^[a-zA-Z][\\w.-]{2,}:\\d{2,5}$")
    private val ABS_PATH_RE = Regex("^/[\\w@%+=:,.~^\\-/ ]+$")
    private val BASE64_RE = Regex("^[A-Za-z0-9+/]{16,}={0,2}$")
    private val BASE64_URL_RE = Regex("^[A-Za-z0-9_-]{16,}={0,2}$")
    private val HEXISH_RE = Regex("^[0-9a-fA-F]{16,}$")
    private val FORMAT_RE = Regex("%[-#0+ .\\d]*(s|d|u|x|X|o|f|e|g|c|p|n|\\d+\\$)")
    private val JAVA_DESC_RE = Regex("^L[a-zA-Z_$/][\\w/$]*;$")
    private val PACKAGE_RE = Regex("^[a-z][a-z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*){2,}$")
    private val UUID_RE = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val SQL_RE = Regex("(?i)^(select|insert|update|delete|create table)\\b.{4,}$")
    private val VERSION_RE = Regex("^\\d+(\\.\\d+){1,3}([_.-][\\w.]+)?$")

    private fun classify(value: String): List<String> {
        val out = mutableListOf<String>()
        if (URL_RE.matches(value)) out += "url"
        if (IP_PORT_RE.matches(value)) {
            out += "ip_port"
        } else if (HOST_PORT_RE.matches(value) && !PACKAGE_RE.matches(value)) {
            out += "host_port"
        }
        if (JAVA_DESC_RE.matches(value)) out += "java_descriptor"
        if (ABS_PATH_RE.matches(value) && !URL_RE.matches(value)) out += "abs_path"
        if (FORMAT_RE.containsMatchIn(value)) out += "format_string"
        if (BASE64_RE.matches(value) || BASE64_URL_RE.matches(value)) out += "base64_like"
        if (HEXISH_RE.matches(value)) out += "hex_like"
        if (PACKAGE_RE.matches(value)) out += "package_name"
        if (UUID_RE.matches(value)) out += "uuid"
        if (SQL_RE.matches(value)) out += "sql"
        if (VERSION_RE.matches(value)) out += "version_like"
        if (value.length >= 4 && value.endsWith(".so")) out += "library_name"
        return out
    }

    // ── str_encoding_census ──

    /** UTF-16LE runs inside alloc non-exec sections; the parser only decodes UTF-8. */
    fun utf16LeStrings(data: ByteArray, elf: ElfFile, limit: Int): List<Triple<Long, String, String>> {
        val out = mutableListOf<Triple<Long, String, String>>()
        for (section in elf.sections) {
            if (section.type == 8L || section.size <= 0 || section.flags and 0x4L != 0L || section.flags and 0x2L == 0L) continue
            val start = section.offset.toInt().coerceIn(0, data.size)
            val end = minOf(data.size, start + section.size.toInt())
            var i = start
            var runStart = -1
            while (i + 1 < end) {
                val c = data[i].toInt() and 0xff
                val hi = data[i + 1].toInt() and 0xff
                val printable = c in 0x20..0x7e && hi == 0
                if (printable) {
                    if (runStart < 0) runStart = i
                } else {
                    if (runStart >= 0 && i - runStart >= 8) {
                        val text = String(data, runStart, i - runStart, Charsets.UTF_16LE)
                        out += Triple(section.offset + (runStart - start), text, section.name)
                    }
                    runStart = -1
                }
                i += if (printable) 2 else 1
            }
            if (runStart >= 0 && end - runStart >= 8) {
                val text = String(data, runStart, end - runStart, Charsets.UTF_16LE)
                out += Triple(section.offset + (runStart - start), text, section.name)
            }
            if (out.size >= limit) break
        }
        return out
    }

    fun encodingCensus(data: ByteArray, elf: ElfFile, limit: Int): JSONObject {
        val strings = elf.strings
        var ascii = 0
        var utf8Multi = 0
        var cjk = 0
        val duplicates = HashMap<String, Int>()
        strings.forEach { s ->
            if (s.value.all { it.code < 0x80 }) ascii++ else utf8Multi++
            if (s.value.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }) cjk++
            duplicates.merge(s.value, 1, Int::plus)
        }
        val utf16 = utf16LeStrings(data, elf, limit)
        val topDup = JSONArray()
        duplicates.entries.filter { it.value > 1 }.sortedByDescending { it.value }.take(20).forEach { (v, n) ->
            topDup.put(JSONObject().put("value", v.take(120)).put("count", n))
        }
        return JSONObject()
            .put("scannedStrings", strings.size)
            .put("ascii", ascii)
            .put("utf8Multibyte", utf8Multi)
            .put("containsCjk", cjk)
            .put("utf16LeRuns", utf16.size)
            .put(
                "utf16LeSamples",
                JSONArray().apply {
                    utf16.take(30).forEach { (off, text, sec) ->
                        put(JSONObject().put("offset", "0x${off.toString(16)}").put("value", text.take(120)).put("section", sec))
                    }
                }
            )
            .put("duplicateValues", duplicates.count { it.value > 1 })
            .put("topDuplicates", topDup)
            .put(
                "scope",
                JSONObject()
                    .put("utf8Source", "parser string table (.rodata/.strtab/.dynstr)")
                    .put("utf16Source", "raw scan of alloc non-exec sections")
            )
    }

    // ── str_literal_classes ──

    fun literalClasses(elf: ElfFile, limit: Int): JSONObject {
        val counts = LinkedHashMap<String, Int>()
        val items = JSONArray()
        elf.strings.forEach { s ->
            val classes = classify(s.value)
            if (classes.isEmpty()) return@forEach
            classes.forEach { counts.merge(it, 1, Int::plus) }
            if (items.length() < limit) {
                items.put(
                    JSONObject()
                        .put("offset", "0x${s.offset.toString(16)}")
                        .put("section", s.section)
                        .put("value", s.value.take(160))
                        .put("classes", JSONArray(classes))
                )
            }
        }
        val byClass = JSONArray()
        counts.entries.sortedByDescending { it.value }.forEach { (k, v) -> byClass.put(JSONObject().put("class", k).put("count", v)) }
        return JSONObject()
            .put("scannedStrings", elf.strings.size)
            .put("classified", counts.values.sum())
            .put("byClass", byClass)
            .put("items", items)
    }

    // ── net_endpoint_extract ──

    fun netEndpoints(elf: ElfFile, limit: Int): JSONObject {
        val urls = LinkedHashMap<String, JSONObject>()
        val hosts = LinkedHashMap<String, JSONObject>()
        elf.strings.forEach { s ->
            val v = s.value.trim()
            if (URL_RE.matches(v) && urls.size < limit) {
                val host = runCatching { java.net.URI(v).host }.getOrNull()
                urls[v] = JSONObject()
                    .put("url", v.take(200))
                    .put("scheme", v.substringBefore("://"))
                    .put("host", host)
                    .put("offset", "0x${s.offset.toString(16)}")
                    .put("section", s.section)
            } else {
                val m = IP_PORT_RE.matchEntire(v)
                if (m != null && hosts.size < limit) {
                    hosts[v] = JSONObject()
                        .put("host", m.groupValues[1])
                        .put("port", m.groupValues[3].toInt())
                        .put("raw", v)
                        .put("offset", "0x${s.offset.toString(16)}")
                        .put("section", s.section)
                } else if (HOST_PORT_RE.matches(v) && !PACKAGE_RE.matches(v) && hosts.size < limit) {
                    hosts[v] = JSONObject()
                        .put("host", v.substringBeforeLast(':'))
                        .put("port", v.substringAfterLast(':').toIntOrNull() ?: -1)
                        .put("raw", v.take(120))
                        .put("offset", "0x${s.offset.toString(16)}")
                        .put("section", s.section)
                }
            }
        }
        return JSONObject()
            .put("scannedStrings", elf.strings.size)
            .put("urlCount", urls.size)
            .put("hostCount", hosts.size)
            .put("urls", JSONArray(urls.values.take(limit)))
            .put("hosts", JSONArray(hosts.values.take(limit)))
    }

    // ── file_path_roots ──

    private val ROOTS = listOf(
        "/proc/self", "/proc/", "/sys/", "/dev/", "/system/bin/", "/system/xbin/", "/system/lib", "/system/app",
        "/vendor/", "/data/data/", "/data/app/", "/data/local/tmp/", "/data/local/", "/data/misc/", "/data/",
        "/sdcard/", "/storage/emulated/", "/storage/", "/etc/", "/cache/", "/sbin/", "/su", "/magisk"
    )

    private val SENSITIVE = listOf(
        "/proc/self/maps", "/proc/self/status", "/proc/self/cmdline", "/proc/version", "/proc/cpuinfo",
        "su", "magisk", "frida", "xposed", "/system/bin/su", "busybox"
    )

    fun filePathRoots(elf: ElfFile, limit: Int): JSONObject {
        val counts = LinkedHashMap<String, Int>()
        val items = JSONArray()
        val notable = JSONArray()
        elf.strings.forEach { s ->
            val v = s.value.trim()
            if (!ABS_PATH_RE.matches(v)) return@forEach
            val root = ROOTS.firstOrNull { v.startsWith(it) } ?: "/"
            counts.merge(root, 1, Int::plus)
            if (items.length() < limit) {
                items.put(JSONObject().put("path", v.take(160)).put("root", root).put("section", s.section).put("offset", "0x${s.offset.toString(16)}"))
            }
            if (notable.length() < 40 && SENSITIVE.any { v.contains(it, ignoreCase = true) }) {
                notable.put(JSONObject().put("path", v.take(160)).put("reason", "anti-analysis or privilege surface"))
            }
        }
        val byRoot = JSONArray()
        counts.entries.sortedByDescending { it.value }.forEach { (k, v) -> byRoot.put(JSONObject().put("root", k).put("count", v)) }
        return JSONObject()
            .put("scannedStrings", elf.strings.size)
            .put("absPathCount", counts.values.sum())
            .put("byRoot", byRoot)
            .put("items", items)
            .put("notable", notable)
    }

    // ── env_property_keys ──

    private val PROPERTY_RE = Regex("^(ro\\.|persist\\.|sys\\.|debug\\.|service\\.|ctl\\.|vendor\\.|hw\\.|ro\\.build\\.)[\\w.]+")
    private val ENV_KEYS = setOf(
        "PATH", "CLASSPATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "TMPDIR", "HOME", "ANDROID_DATA",
        "ANDROID_ROOT", "BOOTCLASSPATH", "ANDROID_ART_ROOT", "DEX2OATBOOTCLASSPATH", "I18N_CLASSPATH"
    )

    fun propertyKeys(elf: ElfFile, limit: Int): JSONObject {
        val properties = JSONArray()
        val env = JSONArray()
        elf.strings.forEach { s ->
            val v = s.value.trim()
            if (properties.length() < limit && PROPERTY_RE.matches(v)) {
                properties.put(JSONObject().put("key", v.take(120)).put("section", s.section).put("offset", "0x${s.offset.toString(16)}"))
            } else if (env.length() < 40 && v in ENV_KEYS) {
                env.put(JSONObject().put("key", v).put("section", s.section))
            }
        }
        return JSONObject()
            .put("scannedStrings", elf.strings.size)
            .put("propertyLikeKeys", properties.length())
            .put("properties", properties)
            .put("envKeys", env)
            .put(
                "method",
                "String-shape only: keys that look like Android system properties or known env names. " +
                    "Call-site binding (getenv/__system_property_get) is not proven without disassembly."
            )
    }
}
