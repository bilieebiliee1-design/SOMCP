// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// FridaBridge: an on-device Frida integration for the dynamic-analysis
// workflow. It drives a remote `frida-server` / `frida-gadget` over TCP from
// pure Kotlin and runs real Frida JavaScript agents (Interceptor/Module/
// Memory/Process) against a target process.
//
// Availability model (mirrors the Unidbg backend):
//   - `frida-server` / `frida-gadget` is NOT bundled in the APK. The user must
//     install it on the device ("requires-extra-install"), reachable at the
//     configured host:port (default 127.0.0.1:27042, the frida-server control
//     port). When unreachable, every Frida op reports a structured
//     FRIDA_UNAVAILABLE error instead of pretending the backend works.
//
// NOTE ON THE WIRE PROTOCOL:
//   This bridge implements the Frida host<->daemon connection over the raw
//   control socket: a line-oriented D-Bus-style handshake (AUTH ANONYMOUS /
//   BEGIN) followed by NUL-terminated-length-prefixed JSON messages. Frida's
//   framing can evolve between releases, so the transport is isolated in
//   [FridaTransport] and must be validated against the exact frida-server
//   release deployed on the device before trust.
package com.soreverse.mcp.engine

import android.content.Context
import com.soreverse.mcp.core.AppLog
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.Charset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONArray
import org.json.JSONObject

internal data class FridaTarget(
    val host: String = "127.0.0.1",
    val port: Int = 27042,
    val connectTimeoutMillis: Long = 5_000L,
    val readTimeoutMillis: Long = 15_000L
)

/**
 * An open TCP link to a frida daemon. Implements [AutoCloseable] so callers
 * can use `use {}` and so that closing the session releases every underlying
 * I/O resource (streams and socket) in one place.
 */
internal class FridaConnection(val target: FridaTarget, val socket: Socket, val input: BufferedInputStream, val output: BufferedOutputStream) : AutoCloseable {
    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { socket.close() }
    }
}

/**
 * Wire framing for the Frida host transport.
 *
 * The daemon on the control port (default 27042) speaks the D-Bus-style
 * connection protocol on top of the raw socket:
 *
 *  1. A line-oriented handshake: we offer authentication (`AUTH ANONYMOUS`)
 *     and, on acceptance, start the byte stream (`BEGIN`).
 *  2. Read-write message frames use a NUL-terminated ASCII length prefix
 *     followed by the UTF-8 payload.
 *
 * Frida's framing can shift between daemon releases, so the transport is kept
 * in this object and [negotiate] surfaces a precise error when the deployed
 * daemon does not follow the expected handshake, instead of failing silently.
 */
internal object FridaTransport {
    private val utf8: Charset = Charsets.UTF_8
    private const val MAX_FRAME = 64 * 1024 * 1024

    /**
     * Perform the connection-level handshake with the daemon. Returns the
     * daemon's initial greeting line (for diagnostics) once the stream is
     * usable for framed messages.
     */
    fun negotiate(connection: FridaConnection): String {
        val input = connection.input
        val output = connection.output
        // Offer anonymous authentication, as the frida host transport does.
        writeLine(output, "AUTH ANONYMOUS")
        val authReply = readLine(input)
        when {
            authReply == null -> throw EOFException("Frida daemon closed during AUTH handshake")

            authReply.startsWith("REJECTED") ->
                throw IOException("Frida daemon rejected anonymous auth: $authReply")

            !authReply.startsWith("OK ") ->
                throw IOException("Unexpected AUTH reply from Frida daemon: ${authReply.take(120)}")
        }
        // Gracefully begin the stream; the response is the session token.
        val token = authReply.removePrefix("OK ").trim()
        writeLine(output, "BEGIN")
        val beginReply = readLine(input)
        if (beginReply != null && beginReply.startsWith("REJECTED")) {
            throw IOException("Frida daemon rejected BEGIN: $beginReply")
        }
        return beginReply ?: token
    }

    fun writeMessage(connection: FridaConnection, text: String) {
        val bytes = text.toByteArray(utf8)
        val out = connection.output
        // D-Bus stream framing: NUL-terminated decimal length + payload.
        out.write("${bytes.size}\u0000".toByteArray(Charsets.US_ASCII))
        out.write(bytes)
        out.flush()
    }

    fun readMessage(connection: FridaConnection): String {
        // The D-Bus stream framing writes a NUL (0x00) terminated decimal
        // length prefix, so read bytes until 0x00 (NOT until '\n') to parse it.
        val length = readLengthPrefix(connection.input)
        if (length < 0 || length > MAX_FRAME) {
            throw IOException("Frida frame has invalid payload length $length")
        }
        val body = ByteArray(length)
        var done = 0
        while (done < length) {
            val n = connection.input.read(body, done, length - done)
            if (n < 0) throw EOFException("Frida transport closed while reading frame body")
            done += n
        }
        return String(body, utf8)
    }

    private fun readLengthPrefix(input: BufferedInputStream): Int {
        var length = 0
        while (true) {
            val value = input.read()
            if (value < 0) throw EOFException("Frida transport closed while reading frame header")
            if (value == 0x00) return length
            if (value < '0'.code || value > '9'.code) {
                throw IOException("Frida frame header has non-numeric byte 0x${value.toString(16)}")
            }
            length = Math.multiplyExact(length, 10) + (value - '0'.code)
        }
    }

    private fun writeLine(output: BufferedOutputStream, line: String) {
        output.write(line.toByteArray(utf8))
        output.write("\r\n".toByteArray(Charsets.US_ASCII))
        output.flush()
    }

    private fun readLine(input: BufferedInputStream): String? {
        // 64 KiB cap comfortably fits any handshake line (long OK tokens,
        // REJECTED diagnostics) emitted by frida daemon releases.
        val buffer = ByteArray(64 * 1024)
        var length = 0
        while (true) {
            val value = input.read()
            if (value < 0) {
                return if (length == 0) null else String(buffer, 0, length, utf8)
            }
            if (value == '\n'.code) {
                return String(buffer, 0, length, utf8).trimEnd('\r')
            }
            if (length == buffer.size) {
                throw IOException("Frida handshake line too long")
            }
            buffer[length++] = value.toByte()
        }
    }
}

/**
 * A managed Frida instrumentation session bound to a spawned or attached
 * target process. Holds the negotiated process/script handles and the hook /
 * memory operations exposed to the parent engine.
 */
internal class FridaSession(val id: String, val target: FridaTarget, val connection: FridaConnection, val mode: String, val targetIdentifier: String) {
    var processId: Int = -1
    var scriptLoaded: Boolean = false
    val collectedMessages = ConcurrentHashMap<String, JSONArray>()
    private val _closed = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Serializes the write + read pair of each RPC call; see [FridaBridge.invokeRpc]. */
    internal val ioLock = Any()

    val closed: Boolean get() = _closed.get()

    fun close() {
        if (_closed.compareAndSet(false, true)) {
            runCatching { FridaBridge.sendScriptMessage(connection, "detach") }
            // Releasing the streams and the socket in one place guarantees no
            // I/O resource is left open when the session is abandoned.
            runCatching { connection.close() }
        }
    }

    internal companion object {
        const val MSG_CHANNEL = "soreverse-dynamic"
    }
}

/**
 * Pure-Kotlin Frida bridge. Intentionally keeps the daemon-specific framing in
 * [FridaTransport] so the rest of the workflow is stable across Frida versions.
 */
internal class FridaBridge(private val context: Context) {
    private val sessions = ConcurrentHashMap<String, FridaSession>()

    /** True when a configured frida daemon accepts a TCP connection. */
    fun available(target: FridaTarget = FridaTarget()): Boolean = runCatching {
        connect(target).use { true }
    }.getOrDefault(false)

    fun connectionStatus(target: FridaTarget = FridaTarget()): JSONObject = JSONObject().apply {
        put("available", available(target))
        put("backend", "frida-gadget / frida-server")
        put(
            "setup",
            if (available(target)) {
                "bundled-ok"
            } else {
                "requires-extra-install: frida-server or frida-gadget is NOT bundled in this APK — ${unavailableReason(target)}"
            }
        )
        put("host", target.host)
        put("port", target.port)
        put(
            "note",
            "Frida performs on-device dynamic analysis on a real (rooted) environment. Unlike unidbg, the target .so is loaded into the live process address space and driven with Frida JavaScript (Interceptor/Module/Memory)."
        )
    }

    fun unavailableReason(target: FridaTarget = FridaTarget()): String {
        if (!available(target)) {
            return "no frida daemon reachable at ${target.host}:${target.port} — " +
                "install and start frida-server (or use frida-gadget) on the device, " +
                "then set the target host/port via the dynamic_analyze tool arguments"
        }
        return ""
    }

    private fun connect(target: FridaTarget): FridaConnection {
        val socket = Socket()
        socket.tcpNoDelay = true
        socket.connect(
            InetSocketAddress(target.host, target.port),
            target.connectTimeoutMillis.toInt()
        )
        socket.soTimeout = target.readTimeoutMillis.toInt()
        return FridaConnection(
            target,
            socket,
            BufferedInputStream(socket.getInputStream(), 64 * 1024),
            BufferedOutputStream(socket.getOutputStream(), 64 * 1024)
        )
    }

    // ── Session lifecycle (object API used by EngineRuntimeDynamic) ──

    fun listSessions(): JSONArray = JSONArray(sessions.keys)

    fun getSession(id: String): FridaSession? = sessions[id]

    fun createSession(target: FridaTarget, mode: String, targetIdentifier: String, script: String): FridaSession {
        val connection = connect(target)
        try {
            // Negotiate the daemon-level handshake and establish the session.
            val hello = runCatching { FridaTransport.negotiate(connection) }
                .getOrElse { throw IOException("Frida handshake failed: ${it.message}", it) }
            AppLog.i("Frida daemon hello: ${hello.take(200)}")
            val session = FridaSession(
                UUID.randomUUID().toString().substring(0, 8),
                target,
                connection,
                mode,
                targetIdentifier
            )
            // Deploy and run the agent. The agent registers rpc.exports so the
            // Kotlin side can invoke hi-level operations (hook, call, dump).
            FridaBridge.sendScriptMessage(connection, "loadScript")
            FridaBridge.sendScriptPayload(connection, "run", JSONObject().put("source", script))
            session.scriptLoaded = true
            sessions[session.id] = session
            return session
        } catch (error: Exception) {
            runCatching { connection.close() }
            throw error
        }
    }

    fun closeSession(id: String) {
        sessions.remove(id)?.close()
    }

    fun invokeRpc(sessionId: String, operation: String, params: JSONObject): JSONObject {
        val session = sessions[sessionId]
            ?: throw IllegalStateException("Frida session $sessionId not found")
        if (session.closed) throw IllegalStateException("Frida session $sessionId is closed")
        // The request/response pair must be atomic on the shared socket: a
        // concurrent writer could interleave frames and corrupt the framing.
        // Holding the session's ioLock serializes every RPC on the link.
        return synchronized(session.ioLock) {
            sendScriptPayload(
                session.connection,
                "rpc",
                JSONObject()
                    .put("operation", operation)
                    .put("params", params)
            )
            collectResponse(session, operation)
        }
    }

    private fun collectResponse(session: FridaSession, operation: String): JSONObject {
        // The link is half-duplex request/response, but the agent may push
        // asynchronous frames (log / error / agent events) at any time. Skip
        // non-`rpc` frames until the matching rpc response arrives, so stray
        // async traffic cannot misalign or break the framing.
        while (true) {
            val text = FridaTransport.readMessage(session.connection)
            val json = runCatching { JSONObject(text) }.getOrNull()
                ?: JSONObject().put("raw", text)
            if (json.optString("type") != "rpc") {
                session.collectedMessages.putIfAbsent(operation, JSONArray())
                session.collectedMessages[operation]?.put(json)
                continue
            }
            if (json.optString("error").isNotBlank()) {
                throw IllegalStateException("Frida agent error: ${json.optString("error")}")
            }
            return json
        }
    }

    // ── Script / payload transfer ──

    internal companion object FridaBridgeCompanion {
        fun sendScriptMessage(connection: FridaConnection, message: String) {
            FridaTransport.writeMessage(connection, JSONObject().put("type", message).toString())
        }

        fun sendScriptPayload(connection: FridaConnection, type: String, payload: JSONObject) {
            FridaTransport.writeMessage(
                connection,
                JSONObject()
                    .put("type", type)
                    .put("payload", payload)
                    .toString()
            )
        }
    }

    /** Default Frida JavaScript agent for the standalone dynamic-analysis flow. */
    fun defaultAgentHtml(moduleName: String, retaddr: Boolean): String {
        // Real Frida agent: Interceptor.attach on a resolved native export,
        // capture registers, optional memory dump, send events back over rpc.
        return """
        'use strict';
        // Module-level hook event buffer so events survive across RPC frames.
        const __events = [];
        let __lastContext = null;

        rpc.exports = {
            hookFunction(functionName) {
                const mod = Process.findModuleByName(${moduleName.asJsLiteral()});
                if (!mod) return { error: 'module-not-found' };
                const addr = Module.getExportByName(${moduleName.asJsLiteral()}, functionName) ||
                             Module.getGlobalExportByName(functionName);
                if (!addr) return { error: 'export-not-found' };
                Interceptor.attach(addr, {
                    onEnter(args) {
                        __lastContext = this.context;
                        __events.push({
                            kind: 'enter',
                            args: [].slice.call(args, 0, 8).map(function (a) {
                                return a && a.toString ? a.toString() : String(a);
                            })
                        });
                    },
                    onLeave(retval) {
                        __events.push({ kind: 'leave', retval: retval.toInt32() });
                    }
                });
                return { hook: 'attached', at: addr.toString() };
            },
            getEvents() {
                const snapshot = __events.slice();
                __events.length = 0;
                return { events: snapshot };
            },
            callFunction(functionName, argsJson) {
                const addr = Module.getExportByName(${moduleName.asJsLiteral()}, functionName);
                if (!addr) return { error: 'export-not-found' };
                const args = JSON.parse(argsJson);
                const fn = new NativeFunction(addr, 'int', args.map(function (a) { return 'int'; }));
                return { retval: fn(...args) };
            },
            readMemory(ptrStr, size) {
                const p = ptr(ptrStr);
                return { hex: hexdump(p, { length: size, ansi: false }).slice(0, size * 3) };
            },
            registers() {
                if (__lastContext) {
                    const c = __lastContext;
                    const bt = Thread.backtrace(c, Backtracer.ACCURATE);
                    return {
                        backtrace: bt.map(function (a) { return a.toString(); }),
                        $ret: ${if (retaddr) "c.retAddress ? c.retAddress.toString() : c.pc.toString()" else "null"}
                    };
                }
                return { error: 'no-context-captured-yet' };
            }
        };
        """.trimIndent()
    }

    private fun String.asJsLiteral(): String = "'" + replace("\\", "\\\\").replace("'", "\\'") + "'"
}
