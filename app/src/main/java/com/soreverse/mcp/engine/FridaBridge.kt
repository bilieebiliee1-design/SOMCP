// SPDX-License-Identifier: AGPL-3.0-or-later
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
// WIRE PROTOCOL (modern Frida, 16.x):
//   Frida 16 replaced the old line-oriented D-Bus handshake with a WebSocket
//   control channel. We speak that protocol here:
//
//     1. HTTP/1.1 Upgrade (`GET /ws`) with Sec-WebSocket-* headers.
//     2. RFC 6455 binary frames; clients mask their outgoing frames.
//     3. Each frame contains one little-endian GVariant-serialized D-Bus
//        message (16-byte header + fields + 8-aligned body).
//     4. Methods are called on /re/frida/HostSession (EnumerateProcesses,
//        Ping, Attach) and on /re/frida/AgentSession/<handle> (CreateScript,
//        LoadScript, PostMessages). The daemon pushes agent output back as
//        METHOD_CALLs to /re/frida/AgentMessageSink/<handle>, which we ack.
//     5. rpc.exports are invoked by posting `["frida:rpc", <id>, "call",
//        "name", [args]]` messages; the reply arrives on the message sink.
//
//   This framing was validated end-to-end against a real frida-server 16.x
//   (EnumerateProcesses -> Attach -> CreateScript -> LoadScript -> RPC call
//   -> sink reply).
package com.soreverse.mcp.engine

import android.content.Context
import android.util.Base64
import com.soreverse.mcp.core.AppLog
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.Charset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONArray
import org.json.JSONException
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
    /**
     * Per-connection side-channel used by [FridaTransport] to carry the
     * WebSocket handshake/frame state across [readMessage] calls without
     * changing the public connection shape.
     */
    private val attrs = ConcurrentHashMap<String, Any?>()

    fun putAttr(key: String, value: Any?) {
        attrs[key] = value
    }

    fun <T> attr(key: String): T? {
        @Suppress("UNCHECKED_CAST")
        return attrs[key] as? T
    }

    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { socket.close() }
    }
}

internal class FridaConnectionException(message: String, cause: Throwable? = null) : IOException(message, cause)

// ─────────────────────────────────────────────────────────────────────────
// Little-endian GVariant writer (mirrors the wire bytes produced/consumed by
// frida-core's gvariant D-Bus codec).
// ─────────────────────────────────────────────────────────────────────────
internal object Gvariant {
    private val utf8: Charset = Charsets.UTF_8

    /** Round an offset up to a power-of-two alignment. */
    fun align(p: Int, a: Int): Int = if (a <= 1) p else (p + (a - 1)) and (a - 1).inv()

    class W {
        val b: ByteArrayOutputStream = ByteArrayOutputStream()

        fun pad(a: Int) {
            val n = (a - (b.size() % a)) % a
            repeat(n) { b.write(0) }
        }

        fun raw(v: Int) = b.write(v and 0xff)

        private fun le32(v: Int) {
            b.write(v and 0xff)
            b.write((v shr 8) and 0xff)
            b.write((v shr 16) and 0xff)
            b.write((v shr 24) and 0xff)
        }

        fun u32(v: Int) {
            pad(4)
            le32(v)
        }

        fun i32(v: Int) {
            pad(4)
            le32(v)
        }

        fun str(s: String) {
            val d = s.toByteArray(utf8)
            pad(4)
            le32(d.size)
            b.write(d)
            b.write(0)
        }

        fun g(s: String) {
            val d = s.toByteArray(utf8)
            b.write(d.size)
            b.write(d)
            b.write(0)
        }
    }

    fun le4(bytes: ByteArray, o: Int): Int = (bytes[o].toInt() and 0xff) or
        ((bytes[o + 1].toInt() and 0xff) shl 8) or
        ((bytes[o + 2].toInt() and 0xff) shl 16) or
        ((bytes[o + 3].toInt() and 0xff) shl 24)

    fun le8(bytes: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((bytes[o + i].toLong() and 0xff) shl (8 * i))
        return v
    }
}

// A D-Bus header field (code, signature, string-encoded value).
internal class DBusField(val code: Int, val sig: String, val value: String)

/**
 * One serialized D-Bus message. `mtype`: 1=METHOD_CALL, 2=METHOD_RETURN,
 * 3=ERROR, 4=SIGNAL. Field codes follow the D-Bus spec: 1=path(o), 2=iface(s),
 * 3=member(s), 4=error(s), 5=reply_serial(u), 8=signature(g).
 */
internal class DBusMessage(val mtype: Int, val flags: Int, val serial: Int, val fields: Map<Int, String>, val body: ByteArray) {
    val path: String? get() = fields[1]
    val hasError: Boolean get() = mtype == 3
    val errorName: String? get() = fields[4]
}

/**
 * WebSocket + D-Bus framing over a [FridaConnection]. Replaces the legacy
 * line-oriented transport.
 */
internal object FridaTransport {
    private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    private val utf8: Charset = Charsets.UTF_8

    /** Random per-process WebSocket handshake key (RFC 6455 §4.1 recommends a
     *  fresh random value; the daemon echoes its SHA-1 + GUID digest). */
    private val secretKey: String = Base64.encodeToString(
        ByteArray(16) { (0..255).random().toByte() },
        Base64.NO_WRAP
    )

    /** WebSocket handshake state (upgrade + pending frame bytes). */
    private class WsState {
        var upgraded = false
        val pending = ByteArrayOutputStream()
        var closed = false
    }

    /**
     * Perform the connection-level handshake with the daemon. Returns a short
     * diagnostic greeting. In modern Frida the handshake is just an HTTP
     * Upgrade to `/ws`; there is no separate `AUTH ANONYMOUS`/`BEGIN` phase.
     */
    fun negotiate(connection: FridaConnection): String {
        upgrade(connection)
        return "websocket upgraded at ${connection.target.host}:${connection.target.port}"
    }

    private fun upgrade(connection: FridaConnection): String {
        val state = WsState()
        try {
            val output = connection.output
            val sb = StringBuilder()
            sb.append("GET /ws HTTP/1.1\r\n")
            sb.append("Upgrade: websocket\r\n")
            sb.append("Connection: Upgrade\r\n")
            sb.append("Sec-WebSocket-Key: ").append(secretKey).append("\r\n")
            sb.append("Sec-WebSocket-Version: 13\r\n")
            sb.append("Host: ").append(connection.target.host).append("\r\n")
            sb.append("User-Agent: SOMCP/1.0.21\r\n")
            sb.append("\r\n")
            output.write(sb.toString().toByteArray(Charsets.US_ASCII))
            output.flush()

            val resp = ByteArrayOutputStream()
            var nl = 0
            while (nl < 4) {
                val c = connection.input.read()
                if (c < 0) throw EOFException("Frida daemon closed during websocket upgrade")
                resp.write(c)
                nl = if (c == '\r'.code || c == '\n'.code) nl + 1 else 0
            }
            val head = String(resp.toByteArray(), Charsets.US_ASCII)
            connection.putAttr("frida.ws", state)
            if (!head.startsWith("HTTP/1.1 101")) {
                throw FridaConnectionException("Frida daemon rejected websocket upgrade: ${head.take(200)}")
            }
            return head
        } catch (e: IOException) {
            throw FridaConnectionException("Frida websocket upgrade failed: ${e.message}", e)
        }
    }

    /**
     * Serialize and send a D-Bus message as one masked WebSocket binary frame.
     */
    fun writeMessage(connection: FridaConnection, message: ByteArray) {
        val frame = frameBinaryClient(message)
        connection.output.write(frame)
        connection.output.flush()
    }

    fun writeMessage(connection: FridaConnection, message: DBusMessage) {
        val bytes = dbusMessageBytes(message)
        writeMessage(connection, bytes)
    }

    /**
     * Read the next D-Bus message from the wire, buffering across WebSocket
     * frames as needed. Returns null on a clean close frame.
     */
    fun readMessage(connection: FridaConnection): DBusMessage? {
        val state = connection.attr<WsState>("frida.ws")
            ?: return null
        if (state.closed) return null

        // D-Bus message: 16-byte header { 'l', mtype, flags, version, bodylen@4,
        // serial@8, fieldslen@12 } then fields then 8-aligned body.
        val header = readBytes(connection, state, 16)
        if (header == null) return null
        val mtype = header[1].toInt() and 0xff
        val flags = header[2].toInt() and 0xff
        val bodyLen = Gvariant.le4(header, 4)
        val serial = Gvariant.le4(header, 8)
        val fieldsLen = Gvariant.le4(header, 12)

        val fieldsBytes = readBytes(connection, state, fieldsLen) ?: return null

        // Body starts 8-aligned after header + fields.
        val fend = 16 + fieldsLen
        val pad = (8 - (fend % 8)) % 8
        if (pad > 0) readBytes(connection, state, pad)

        val body = readBytes(connection, state, bodyLen) ?: return null

        val fields = parseFields(fieldsBytes)
        return DBusMessage(mtype, flags, serial, fields, body)
    }

    private fun parseFields(fieldsBytes: ByteArray): Map<Int, String> {
        val fields = HashMap<Int, String>()
        var p = 0
        while (p + 2 <= fieldsBytes.size) {
            p = Gvariant.align(p, 8)
            if (p + 2 > fieldsBytes.size) break
            val code = fieldsBytes[p].toInt() and 0xff
            p++
            val sigLen = fieldsBytes[p].toInt() and 0xff
            p++
            if (p + sigLen + 1 > fieldsBytes.size) break
            val sig = String(fieldsBytes, p, sigLen, utf8)
            p += sigLen + 1
            when (sig) {
                "o", "s" -> {
                    p = Gvariant.align(p, 4)
                    if (p + 4 > fieldsBytes.size) break
                    val len = Gvariant.le4(fieldsBytes, p)
                    p += 4
                    if (p + len + 1 > fieldsBytes.size) break
                    fields[code] = String(fieldsBytes, p, len, utf8)
                    p += len + 1
                }
                "u" -> {
                    p = Gvariant.align(p, 4)
                    if (p + 4 > fieldsBytes.size) break
                    fields[code] = Gvariant.le4(fieldsBytes, p).toString()
                    p += 4
                }
                "g" -> {
                    if (p + 1 > fieldsBytes.size) break
                    val l = fieldsBytes[p].toInt() and 0xff
                    p++
                    if (p + l + 1 > fieldsBytes.size) break
                    fields[code] = String(fieldsBytes, p, l, utf8)
                    p += l + 1
                }
                else -> {
                    // Skip unknown field type conservatively.
                    break
                }
            }
        }
        return fields
    }

    // ── D-Bus message encoder ──
    fun callMessage(serial: Int, path: String, iface: String, member: String, sig: String, body: ByteArray, flags: Int = 0): ByteArray = dbusMessageBytes(
        DBusMessage(
            1,
            flags,
            serial,
            mapOf(
                1 to path,
                2 to iface,
                8 to sig,
                3 to member
            ),
            body
        )
    )

    fun replyMessage(newSerial: Int, replyTo: Int, sig: String, body: ByteArray): ByteArray = dbusMessageBytes(
        DBusMessage(2, 0, newSerial, mapOf(5 to replyTo.toString()), body)
    )

    fun dbusMessageBytes(msg: DBusMessage): ByteArray {
        val w = Gvariant.W()
        w.raw('l'.code)
        w.raw(msg.mtype)
        w.raw(msg.flags)
        w.raw(1) // protocol version
        w.raw(0)
        w.raw(0)
        w.raw(0)
        w.raw(0) // bodylen placeholder @4
        w.u32(msg.serial) // @8
        // fields a(yv)
        val fe = Gvariant.W()
        msg.fields.entries.sortedBy { it.key }.forEach { (code, value) ->
            val sig = fieldSignature(code, value)
            fe.pad(8)
            fe.raw(code)
            fe.g(sig)
            when (sig) {
                "o", "s" -> fe.str(value)
                "g" -> fe.g(value)
                "u" -> fe.u32(value.toInt())
                else -> throw FridaConnectionException("Unsupported field signature $sig")
            }
        }
        w.u32(fe.b.size()) // fieldslen @12
        w.b.write(fe.b.toByteArray())
        // body 8-aligned
        w.pad(8)
        val bodyStart = w.b.size()
        w.b.write(msg.body)
        val out = w.b.toByteArray()
        val bl = out.size - bodyStart
        out[4] = (bl and 0xff).toByte()
        out[5] = ((bl shr 8) and 0xff).toByte()
        out[6] = ((bl shr 16) and 0xff).toByte()
        out[7] = ((bl shr 24) and 0xff).toByte()
        return out
    }

    private fun fieldSignature(code: Int, value: String): String = when (code) {
        1 -> "o" // path
        2, 4, 3 -> "s" // iface / error-name / member
        5 -> "u" // reply_serial
        8 -> "g" // signature
        else -> "s"
    }

    // ── WebSocket frame codec ──
    private fun frameBinaryClient(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x82) // FIN + binary opcode
        val len = payload.size
        val maskKey = (0..Int.MAX_VALUE).random()
        val mask = byteArrayOf(
            (maskKey and 0xff).toByte(),
            ((maskKey shr 8) and 0xff).toByte(),
            ((maskKey shr 16) and 0xff).toByte(),
            ((maskKey shr 24) and 0xff).toByte()
        )
        when {
            len < 126 -> out.write(0x80 or len) // mask bit + short length
            len < 65536 -> {
                out.write(0x80 or 126)
                out.write((len shr 8) and 0xff)
                out.write(len and 0xff)
            }
            else -> {
                out.write(0x80 or 127)
                for (i in 7 downTo 0) out.write((len.toLong() shr (8 * i)).toInt() and 0xff)
            }
        }
        out.write(mask)
        for (i in payload.indices) out.write((payload[i].toInt() xor mask[i % 4].toInt()) and 0xff)
        return out.toByteArray()
    }

    /** Read exactly [n] payload bytes, pulling and decodifying WS frames. */
    private fun readBytes(connection: FridaConnection, state: WsState, n: Int): ByteArray? {
        val input = connection.input
        while (state.pending.size() < n) {
            if (state.closed) return null
            // Read one WebSocket frame (server -> client, unmasked).
            val b0 = input.read()
            if (b0 < 0) throw EOFException("Frida transport closed while reading frame header")
            val opcode = b0 and 0x0f
            val b1 = input.read()
            if (b1 < 0) throw EOFException("Frida transport closed")
            val masked = (b1 shr 7) and 1
            var frameLen = (b1 and 0x7f).toLong()
            if (frameLen == 126L) {
                val h = readStream(input, 2)
                frameLen = ((((h[0].toInt() and 0xff) shl 8) or (h[1].toInt() and 0xff)).toLong())
            } else if (frameLen == 127L) {
                val h = readStream(input, 8)
                var v = 0L
                for (i in 0 until 8) v = (v shl 8) or (h[i].toLong() and 0xff)
                frameLen = v
            }
            var mask: ByteArray? = null
            if (masked == 1) mask = readStream(input, 4)
            val payload = readStream(input, frameLen.toInt())
            val p = if (mask != null) {
                ByteArray(payload.size) { i -> (payload[i].toInt() xor (mask!![i % 4].toInt() and 0xff)).toByte() }
            } else {
                payload
            }
            when (opcode) {
                8 -> {
                    state.closed = true
                    return null
                } // close
                9 -> { /* ping -> pong (ignored; frida stays quiet) */ }
                0, 2 -> {
                    state.pending.write(p, 0, p.size)
                } // continuation / binary data
            }
        }
        val all = state.pending.toByteArray()
        val result = ByteArray(n)
        System.arraycopy(all, 0, result, 0, n)
        state.pending.reset()
        state.pending.write(all, n, all.size - n)
        return result
    }

    private fun readStream(input: BufferedInputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var done = 0
        while (done < n) {
            val r = input.read(buf, done, n - done)
            if (r < 0) throw EOFException("Frida transport closed while reading frame")
            done += r
        }
        return buf
    }
}

/** A managed Frida instrumentation session bound to an attached target process.
 * Holds the negotiated agent-session/script handles and lets the parent engine
 * call rpc.exports on the injected agent.
 */
internal class FridaSession(val id: String, val target: FridaTarget, val connection: FridaConnection, val mode: String, val targetIdentifier: String) {
    var processId: Int = -1
    var scriptLoaded: Boolean = false
    val collectedMessages = ConcurrentHashMap<String, JSONArray>()
    private val _closed = AtomicBoolean(false)

    // Host/agent-session/script handles negotiated against the daemon.
    internal var agentPath: String = "/re/frida/HostSession"
    internal var agentIfcVersion: Int = FridaBridge.INTERFACE_VERSION
    internal var scriptId: Int = -1

    /** Serializes the write + read pair of each RPC call ([FridaBridge.invokeRpc]). */
    internal val ioLock = Any()

    internal val nextSerial = java.util.concurrent.atomic.AtomicInteger(1)

    val closed: Boolean get() = _closed.get()

    fun close() {
        if (_closed.compareAndSet(false, true)) {
            FridaBridge.closeSessionRemote(this)
            runCatching { connection.close() }
        }
    }

    internal companion object {
        const val MSG_CHANNEL = "soreverse-dynamic"
    }
}

/**
 * Pure-Kotlin Frida bridge speaking the modern WebSocket + D-Bus protocol.
 */
internal class FridaBridge(private val context: Context) {
    private val sessions = ConcurrentHashMap<String, FridaSession>()

    internal companion object {
        const val INTERFACE_VERSION = 17

        /** Detach the remote agent session/script when a [FridaSession] is closed. */
        fun closeSessionRemote(session: FridaSession) {
            if (session.scriptId >= 0 && session.agentPath != "/re/frida/HostSession") {
                runCatching {
                    val body = Gvariant.W().apply { u32(session.scriptId) }.b.toByteArray()
                    FridaTransport.writeMessage(
                        session.connection,
                        FridaTransport.callMessage(
                            session.nextSerial.getAndIncrement(),
                            session.agentPath,
                            "re.frida.AgentSession${session.agentIfcVersion}",
                            "DestroyScript",
                            "(u)",
                            body
                        )
                    )
                }
                runCatching {
                    FridaTransport.writeMessage(
                        session.connection,
                        FridaTransport.callMessage(
                            session.nextSerial.getAndIncrement(),
                            session.agentPath,
                            "re.frida.AgentSession${session.agentIfcVersion}",
                            "Close",
                            "()",
                            ByteArray(0)
                        )
                    )
                }
            }
        }
    }

    /** True when a configured frida daemon accepts a WebSocket control channel. */
    fun available(target: FridaTarget = FridaTarget()): Boolean = runCatching {
        val connection = connect(target)
        try {
            FridaTransport.negotiate(connection)
            true
        } finally {
            runCatching { connection.close() }
        }
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

    // ── Session lifecycle ──

    fun listSessions(): JSONArray = JSONArray(sessions.keys)

    fun getSession(id: String): FridaSession? = sessions[id]

    /**
     * Establish a session: upgrade, ping the host session, resolve the target
     * pid, attach, deploy and load the agent script, then register the session.
     */
    fun createSession(target: FridaTarget, mode: String, targetIdentifier: String, script: String): FridaSession {
        val connection = connect(target)
        try {
            FridaTransport.negotiate(connection)
            val session = FridaSession(
                UUID.randomUUID().toString().substring(0, 8),
                target,
                connection,
                mode,
                targetIdentifier
            )

            // 1) Ping the host session to init the service.
            sendPing(session)

            // 2) Resolve + attach a real target process.
            session.processId = resolvePid(session, targetIdentifier)
            val attachBody = attachBody(session.processId)
            val attachReply = callForReply(
                session,
                "/re/frida/HostSession",
                "re.frida.HostSession${session.agentIfcVersion}",
                "Attach",
                "ua{sv}",
                attachBody
            )
            val handle = bodyString(attachReply)
            session.agentPath = "/re/frida/AgentSession/$handle"
            if (handle.isEmpty()) {
                throw FridaConnectionException("Frida daemon returned an empty AgentSession handle")
            }

            // 3) Create + load the agent script.
            session.scriptId = createScript(session, script)
            loadScript(session, session.scriptId)
            session.scriptLoaded = true

            sessions[session.id] = session
            AppLog.i("Frida session ${session.id}: pid=${session.processId} path=${session.agentPath} scriptId=${session.scriptId}")
            return session
        } catch (error: Exception) {
            runCatching { connection.close() }
            throw error
        }
    }

    fun closeSession(id: String) {
        sessions.remove(id)?.close()
    }

    /** Closes every tracked session. */
    fun closeAll() {
        sessions.keys.toList().forEach { closeSession(it) }
    }

    /**
     * Invoke `rpc.exports.<operation>` on the injected agent by posting a
     * frida:rpc "call" message and waiting for the matching sink reply.
     */
    fun invokeRpc(sessionId: String, operation: String, params: JSONObject): JSONObject {
        val session = sessions[sessionId]
            ?: throw IllegalStateException("Frida session $sessionId not found")
        if (session.closed) throw IllegalStateException("Frida session $sessionId is closed")
        return synchronized(session.ioLock) {
            val args = rpcArgs(session, operation, params)
            val payload = JSONArray()
                .put("frida:rpc")
                .put(session.scriptId)
                .put("call")
                .put(operation)
                .put(args)
            val text = JSONObject()
                .put("type", "send")
                .put("payload", payload)
                .toString()
            postMessage(session, text)
            waitForRpcReply(session, operation)
        }
    }

    // ── Host / agent RPC primitives ──

    private fun sendPing(session: FridaSession) {
        // NO_REPLY_EXPECTED (flags=1) ping, like the frida client does after upgrade.
        val serial = session.nextSerial.getAndIncrement()
        val body = Gvariant.W().apply { u32(0) }.b.toByteArray()
        FridaTransport.writeMessage(
            session.connection,
            FridaTransport.callMessage(
                serial,
                "/re/frida/HostSession",
                "re.frida.HostSession${session.agentIfcVersion}",
                "Ping",
                "u",
                body,
                flags = 1
            )
        )
    }

    /** EnumerateProcesses -> list of (pid, name). */
    private fun enumerateProcesses(session: FridaSession): List<Pair<Int, String>> {
        val reply = callForReply(
            session,
            "/re/frida/HostSession",
            "re.frida.HostSession${session.agentIfcVersion}",
            "EnumerateProcesses",
            "a{sv}",
            Gvariant.W().apply { u32(0) }.b.toByteArray()
        )
        return parseEnumerate(reply.body)
    }

    /** EnumerateProcesses reply body is `a(usa{sv})`: [(pid u, name s, args a{sv}), ...]. */
    private fun parseEnumerate(b: ByteArray): List<Pair<Int, String>> {
        val out = ArrayList<Pair<Int, String>>()
        if (b.size < 8) return out
        var p = 0
        val arrLen = Gvariant.le4(b, p)
        p += 4
        p = Gvariant.align(p, 8)
        val end = p + arrLen
        while (p < end && p + 8 <= b.size) {
            p = Gvariant.align(p, 8) // struct align 8
            if (p + 8 > b.size) break
            val pid = Gvariant.le4(b, p)
            p += 4 // u
            p = Gvariant.align(p, 4)
            if (p + 4 > b.size) break
            val sl = Gvariant.le4(b, p)
            p += 4
            if (p + sl + 1 > b.size) break
            val name = String(b, p, sl, Charsets.UTF_8)
            p += sl + 1 // s
            // args a{sv}: array header (u32) then skip to end
            p = Gvariant.align(p, 4)
            if (p + 4 > b.size) break
            val dl = Gvariant.le4(b, p)
            p += 4 + dl
            out.add(pid to name)
        }
        return out
    }

    private fun resolvePid(session: FridaSession, targetIdentifier: String): Int {
        val trimmed = targetIdentifier.trim()
        trimmed.toIntOrNull()?.let { return it }
        // Fall back to a name lookup if the identifier is a known process name.
        val procs = enumerateProcesses(session)
        procs.firstOrNull { it.second == trimmed || it.second.contains(trimmed) }?.first?.let { return it }
        if (trimmed.isEmpty()) {
            throw FridaConnectionException(
                "Cannot determine a target pid from an empty targetIdentifier; " +
                    "pass a numeric pid (e.g. targetIdentifier='0' to attach the analyzer) "
            )
        }
        throw FridaConnectionException(
            "No process named '$trimmed' found; pass a numeric pid or an existing process name " +
                "(available: ${procs.take(8).joinToString(", ") { "${it.first}:${it.second}" }})"
        )
    }

    private fun createScript(session: FridaSession, source: String): Int {
        val body = Gvariant.W().apply {
            str(source)
            u32(0) // options a{sv} (empty)
        }.b.toByteArray()
        val reply = callForReply(
            session,
            session.agentPath,
            "re.frida.AgentSession${session.agentIfcVersion}",
            "CreateScript",
            "sa{sv}",
            body
        )
        val scriptId = bodyUint(reply)
        if (scriptId < 0) throw FridaConnectionException("Frida created an invalid script id")
        return scriptId
    }

    private fun loadScript(session: FridaSession, scriptId: Int) {
        val body = Gvariant.W().apply { u32(scriptId) }.b.toByteArray()
        callForReply(
            session,
            session.agentPath,
            "re.frida.AgentSession${session.agentIfcVersion}",
            "LoadScript",
            "(u)",
            body
        )
    }

    /**
     * Post one script message (e.g. a frida:rpc "call") to the agent. Sent
     * fire-and-forget; the reply arrives on the message sink.
     */
    private fun postMessage(session: FridaSession, text: String) {
        val serial = session.nextSerial.getAndIncrement()
        val body = postBody(session.scriptId, text, 0)
        FridaTransport.writeMessage(
            session.connection,
            FridaTransport.callMessage(
                serial,
                session.agentPath,
                "re.frida.AgentSession${session.agentIfcVersion}",
                "PostMessages",
                "a(i(u)sbay)u",
                body,
                flags = 1
            )
        )
    }

    /**
     * Wait for the RPC reply. The agent answers through the message sink as a
     * fire-and-forget METHOD_CALL carrying a JSON text whose payload begins
     * with `["frida:rpc", <id>, "ok"|"error", ...]`.
     */
    private fun waitForRpcReply(session: FridaSession, operation: String): JSONObject {
        val deadline = System.currentTimeMillis() + session.target.readTimeoutMillis
        val collected = JSONArray()
        while (System.currentTimeMillis() < deadline) {
            val msg = FridaTransport.readMessage(session.connection)
                ?: throw IOException("Frida session closed while waiting for $operation reply")
            when (msg.mtype) {
                1 -> {
                    // Fire-and-forget call: reply to free up the daemon, then inspect.
                    val isSink = msg.path?.startsWith("/re/frida/AgentMessageSink/") == true
                    if (isSink) {
                        FridaTransport.writeMessage(
                            session.connection,
                            FridaTransport.replyMessage(
                                session.nextSerial.getAndIncrement(),
                                msg.serial,
                                "",
                                ByteArray(0)
                            )
                        )
                        val texts = parseSinkTexts(msg.body)
                        for (text in texts) {
                            val parsed = parseRpcMessage(session, text)
                            if (parsed != null) {
                                val result = parsed
                                // Keep async events, but surface the rpc result as the response.
                                result.put("_asyncEvents", collected)
                                return result
                            }
                            runCatching { collected.put(JSONObject(text)) }
                        }
                    }
                }
                3 -> throw IOException("Frida error: ${msg.errorName ?: "unknown"}")
                2 -> { /* unrelated return; ignore */ }
            }
        }
        throw IOException("Timed out waiting for Frida $operation reply (script may have thrown)")
    }

    private fun parseRpcMessage(session: FridaSession, text: String): JSONObject? {
        val json = try {
            JSONObject(text)
        } catch (e: JSONException) {
            return null
        }
        if (json.optString("type") != "send") return null
        val payload = json.optJSONArray("payload") ?: return null
        if (payload.length() < 3) return null
        if (payload.opt(0) != "frida:rpc") return null
        val msgId = payload.optInt(1)
        if (msgId != session.scriptId) return null
        return when (payload.optString(2)) {
            "ok" -> {
                val result = payload.opt(3)
                if (result is JSONObject) {
                    result.put("ok", true)
                    result
                } else if (result is JSONArray) {
                    JSONObject().put("result", result).put("ok", true)
                } else if (result is Number || result is String || result is Boolean) {
                    JSONObject().put("result", result).put("ok", true)
                } else {
                    JSONObject().put("ok", true)
                }
            }
            "error" -> {
                throw IllegalStateException("Frida RPC ${payload.optString(3, "failed")}")
            }
            else -> null
        }
    }

    // ── Reply plumbing ──

    private fun callForReply(session: FridaSession, path: String, iface: String, member: String, sig: String, body: ByteArray): DBusMessage {
        val serial = session.nextSerial.getAndIncrement()
        FridaTransport.writeMessage(
            session.connection,
            FridaTransport.callMessage(serial, path, iface, member, sig, body)
        )
        return callForReply(session, serial)
    }

    private fun callForReply(session: FridaSession, serial: Int): DBusMessage {
        val deadline = System.currentTimeMillis() + session.target.readTimeoutMillis
        while (System.currentTimeMillis() < deadline) {
            val msg = FridaTransport.readMessage(session.connection)
                ?: throw IOException("Frida connection closed while awaiting reply $serial")
            if (msg.mtype == 1 && msg.path?.startsWith("/re/frida/AgentMessageSink/") == true) {
                FridaTransport.writeMessage(
                    session.connection,
                    FridaTransport.replyMessage(session.nextSerial.getAndIncrement(), msg.serial, "", ByteArray(0))
                )
                val texts = parseSinkTexts(msg.body)
                for (text in texts) {
                    runCatching {
                        // Unrelated async script events can be dropped/collected here.
                        session.collectedMessages.putIfAbsent("async", JSONArray())
                        session.collectedMessages["async"]?.put(JSONObject(text))
                    }
                }
                continue
            }
            val replySerial = msg.fields[5]?.toIntOrNull()
            if (replySerial == serial) {
                if (msg.hasError) throw IOException("Frida call failed: ${msg.errorName}")
                return msg
            }
            // Ignore other strays.
        }
        throw IOException("Timed out awaiting Frida reply $serial")
    }

    // ── Body helpers ──

    private fun bodyString(reply: DBusMessage): String {
        val b = reply.body
        if (b.size >= 4) {
            val len = Gvariant.le4(b, 0)
            if (len in 1..(b.size - 4)) {
                return String(b, 4, len, Charsets.UTF_8)
            }
        }
        return ""
    }

    private fun bodyUint(reply: DBusMessage): Int {
        if (reply.body.size >= 4) return Gvariant.le4(reply.body, 0)
        return -1
    }

    private fun attachBody(pid: Int): ByteArray = Gvariant.W().apply {
        u32(pid)
        u32(0) // options a{sv} (empty)
    }.b.toByteArray()

    /**
     * PostMessages body for one message: `a(i(u)sbay)u`. Inner struct:
     * i kind=1, (u) script_id(8-aligned), s text, b has_data=false, ay empty.
     */
    private fun postBody(scriptId: Int, text: String, batch: Int): ByteArray {
        val elem = Gvariant.W()
        elem.i32(1)
        elem.pad(8)
        elem.u32(scriptId)
        elem.str(text)
        elem.raw(0) // b has_data=false
        elem.pad(4)
        elem.u32(0) // ay empty (header align 4)
        val elemBytes = elem.b.toByteArray()
        val aligned = (elemBytes.size + 7) and 7.inv()
        val arr = Gvariant.W()
        arr.pad(4)
        arr.u32(aligned)
        arr.pad(8)
        arr.b.write(elemBytes)
        repeat(aligned - elemBytes.size) { arr.b.write(0) }
        arr.u32(batch)
        return arr.b.toByteArray()
    }

    /** Parse the sink body elements `(t i s b ay)` and return each `s` text. */
    private fun parseSinkTexts(body: ByteArray): List<String> {
        val texts = ArrayList<String>()
        if (body.size < 4) return texts
        var p = 4 // skip array length u32
        p = Gvariant.align(p, 8)
        val arrLen = Gvariant.le4(body, 0)
        val end = p + arrLen
        val b = body
        while (p + 16 <= end && p + 16 <= b.size) {
            p = Gvariant.align(p, 8)
            // t uint64 id, i int32 type
            p += 8 + 4
            p = Gvariant.align(p, 4)
            if (p + 4 > b.size) break
            val textLen = Gvariant.le4(b, p)
            p += 4
            if (p + textLen + 1 > b.size) break
            val text = String(b, p, textLen, Charsets.UTF_8)
            p += textLen + 1
            p += 1 // b has_data
            p = Gvariant.align(p, 4)
            if (p + 4 > b.size) break
            val dataLen = Gvariant.le4(b, p)
            p += 4 + dataLen
            texts.add(text)
        }
        return texts
    }

    /** Build the positional argument array for an rpc.exports call. */
    private fun rpcArgs(session: FridaSession, operation: String, params: JSONObject): JSONArray = when (operation) {
        "hookFunction" -> JSONArray().put(params.optString("functionName"))
        "getEvents", "registers" -> JSONArray()
        "callFunction" -> JSONArray()
            .put(params.optString("functionName"))
            .put(params.optString("argsJson"))
        "readMemory" -> JSONArray()
            .put(params.optString("ptrStr"))
            .put(params.optInt("size", 256))
        else -> JSONArray().apply {
            val arr = params.names()
            if (arr != null) for (i in 0 until arr.length()) put(params.opt(arr.getString(i)))
        }
    }

    /** Default Frida JavaScript agent for the standalone dynamic-analysis flow. */
    fun defaultAgentHtml(moduleName: String, retaddr: Boolean): String {
        // Real Frida agent: resolve a native export, Interceptor.attach it,
        // buffer the enter/leave events + captured context, and expose them via
        // rpc.exports so the engine can hook / call / read / backtrace a target
        // function running inside a live device process.
        val captureRetAddress = if (retaddr) {
            "retAddress: __lastContext.retAddress ? __lastContext.retAddress.toString() : __lastContext.pc.toString()"
        } else {
            "retAddress: null"
        }
        return """
        'use strict';
        const __events = [];
        let __lastContext = null;

        function resolveExport(name) {
            name = '' + name;
            try { return Module.getExportByName('$moduleName', name); } catch (e) {}
            // Fall back to scanning every loaded module for the export.
            const mods = Process.enumerateModules();
            for (const i = 0; i !== mods.length; i++) {
                try {
                    const found = Module.findExportByName(mods[i].name, name);
                    if (found) return found;
                } catch (e) {}
            }
            return null;
        }

        rpc.exports = {
            hookFunction(functionName) {
                const addr = resolveExport('' + functionName);
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
                const addr = resolveExport('' + functionName);
                if (!addr) return { error: 'export-not-found' };
                const args = JSON.parse('' + argsJson).map(function (n) { return n | 0; });
                const types = new Array(Math.max(args.length, 1)).fill('int');
                const fn = new NativeFunction(addr, 'int', types);
                const retval = fn.apply(null, args);
                return { retval: retval };
            },
            readMemory(ptrStr, size) {
                const p = ptr('' + ptrStr);
                const bytes = Memory.readByteArray(p, size | 0);
                return { hex: bytes ? hexdump(p, { offset: 0, length: size, ansi: false }) : null };
            },
            registers() {
                if (!__lastContext) return { error: 'no-context-captured-yet' };
                try {
                    const bt = Thread.backtrace(__lastContext, Backtracer.ACCURATE);
                    return {
                        backtrace: bt.map(function (a) { return a.toString(); }),
                        $captureRetAddress
                    };
                } catch (e) {
                    return { error: 'backtrace-failed: ' + e };
                }
            }
        };
        """.trimIndent()
    }
}
