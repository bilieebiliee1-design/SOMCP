package com.soreverse.mcp.engine

import android.content.Context
import capstone.Capstone
import com.soreverse.mcp.core.AppLog
import com.sun.jna.NativeLibrary
import keystone.Keystone
import keystone.KeystoneArchitecture
import keystone.KeystoneMode
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.lang.reflect.InvocationTargetException

/**
 * Native-library emulation backend backed by Unidbg
 * (com.github.zhkl0228:unidbg-android). Unidbg is a pure-Java Android ARM/ARM64
 * emulator built on Unicorn; it loads an ELF .so, resolves its imports against
 * a configurable hook table, and executes a chosen export — letting us *verify*
 * a patch's runtime semantics on-device without flashing or root.
 *
 * This version adds full DalvikVM support, which is the critical missing piece:
 * without a DalvikVM, Java_* JNI native functions cannot execute because the
 * JNI environment (JNIEnv*) is never created. With DalvikVM, the emulator can:
 *  - Run JNI_OnLoad
 *  - Call Java_* exported functions with a real JNIEnv
 *  - Resolve Java objects passed across the JNI boundary
 *  - Hook functions and observe calls
 *  - Dump memory at arbitrary addresses
 *
 * The emulator is reflectively driven so a missing class never breaks the
 * build. Unidbg's API surface evolves across versions; reflection keeps the
 * Kotlin layer decoupled and resilient.
 */
class UnidbgEmulator(private val context: Context) {

    init {
        appNativeLibraryDir = context.applicationInfo.nativeLibraryDir
        System.setProperty("soreverse.nativeLibraryDir", context.applicationInfo.nativeLibraryDir)
        System.setProperty("jna.library.path", context.applicationInfo.nativeLibraryDir)
    }

    companion object {
        @Volatile private var nativeLoadError: Throwable? = null
        @Volatile private var availabilityError: Throwable? = null
        @Volatile private var nativeLoaded = false
        @Volatile private var capstoneSelfTest = false
        @Volatile private var keystoneSelfTest = false
        @Volatile private var demumbleSelfTest = false
        @Volatile private var nativeSelfTestStage = "not-started"

        fun ensureNativeLibraries(): Boolean = synchronized(this) {
            if (nativeLoaded) return@synchronized true
            if (nativeLoadError != null) return@synchronized false
            runCatching {
                val nativeDir = appNativeLibraryDir ?: ""
                if (nativeDir.isNotEmpty()) {
                    System.setProperty("soreverse.nativeLibraryDir", nativeDir)
                    System.setProperty("jna.library.path", nativeDir)
                    listOf("capstone", "keystone", "unicorn", "jnidispatch", "disassembler", "demumble").forEach { NativeLibrary.addSearchPath(it, nativeDir) }
                }
                listOf("capstone", "keystone", "unicorn", "jnidispatch", "disassembler", "demumble").forEach { System.loadLibrary(it) }
                nativeSelfTestStage = "keystone-open"
                val assembler = Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)
                nativeSelfTestStage = "keystone-assemble"
                val machineCode = assembler.assemble("nop").machineCode
                assembler.close()
                check(machineCode.isNotEmpty())
                keystoneSelfTest = true
                nativeSelfTestStage = "capstone-open"
                val disassembler = Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM)
                nativeSelfTestStage = "capstone-disasm"
                val instructions = disassembler.disasm(machineCode, 0x1000)
                disassembler.close()
                check(instructions.isNotEmpty())
                capstoneSelfTest = true
                nativeSelfTestStage = "demumble"
                val demangle = Class.forName("com.github.zhkl0228.demumble.Demangler").getDeclaredMethod("demangle", String::class.java)
                demangle.isAccessible = true
                check((demangle.invoke(null, "_Z3foov") as String).contains("foo"))
                demumbleSelfTest = true
                nativeSelfTestStage = "completed"
            }.onSuccess {
                nativeLoaded = true
            }.onFailure {
                nativeLoadError = it
                AppLog.e("Unidbg native dependency load failed", it)
            }
            nativeLoaded
        }

        fun nativeDependencyError(): Throwable? = nativeLoadError
        fun availabilityError(): Throwable? = availabilityError
        fun nativeDependencyErrorChain(): JSONArray {
            val chain = JSONArray()
            var current = nativeLoadError
            while (current != null && chain.length() < 8) {
                chain.put(JSONObject().put("type", current.javaClass.name).put("message", current.message ?: JSONObject.NULL))
                current = current.cause
            }
            return chain
        }
        fun nativeSelfTest(): JSONObject = JSONObject()
            .put("stage", nativeSelfTestStage)
            .put("capstone", capstoneSelfTest)
            .put("keystone", keystoneSelfTest)
            .put("demumble", demumbleSelfTest)
            .put("errorType", nativeLoadError?.javaClass?.name ?: JSONObject.NULL)
            .put("error", nativeLoadError?.toString() ?: JSONObject.NULL)
            .put("errorChain", nativeDependencyErrorChain())

        @Volatile var appNativeLibraryDir: String? = null
    }

    data class LiveSession(
        val emulator: Any,
        val vm: Any?,
        val module: Any,
        val backend: Any?,
        val arch: String,
        val path: File,
        val backendFactory: String,
        val lock: Any = Any(),
        val breakpoints: MutableMap<String, Any> = LinkedHashMap(),
        val objects: MutableMap<String, Any> = LinkedHashMap(),
        val traceHooks: MutableMap<String, Any> = LinkedHashMap(),
        val traceEvents: MutableList<JSONObject> = ArrayList(),
    )

    fun available(): Boolean = runCatching {
        appNativeLibraryDir = context.applicationInfo.nativeLibraryDir
        if (!ensureNativeLibraries()) return@runCatching false
        Class.forName("com.github.unidbg.AndroidEmulator")
        Class.forName("com.github.unidbg.linux.android.AndroidEmulatorBuilder")
        true
    }.onFailure {
        availabilityError = it
        AppLog.e("Unidbg availability check failed", it)
    }.getOrDefault(false)

    /**
     * Emulate a single exported function of the (patched) SO.
     *
     * If the symbol starts with "Java_" (a JNI native method), the function is
     * called with a real JNIEnv* and a null jobject as the first two arguments,
     * enabling full JNI emulation. If JNI_OnLoad is present, it is called first.
     *
     * @param bytes the SO bytes to load (already patched by the edit session)
     * @param arch "arm64" | "arm32" | "x86" | "x86_64"
     * @param symbolName the JNI/exported symbol to call
     * @param argsJson array of integer/string/pointer arguments
     * @param enableTrace whether to enable Unidbg instruction tracing (verbose)
     * @return JSONObject with ok, returnValue, symbol, args, traced, elapsedMs
     */
    fun emulate(
        bytes: ByteArray,
        arch: String,
        symbolName: String,
        argsJson: JSONArray,
        enableTrace: Boolean,
    ): JSONObject = runCatching {
        if (!available()) return@runCatching JSONObject()
            .put("ok", false)
            .put("error", JSONObject().put("code", "EMULATOR_UNAVAILABLE")
                .put("message", "Unidbg classes not on classpath; check dependency com.github.zhkl0228:unidbg-android"))

        val t0 = System.nanoTime()
        val result = JSONObject()
        runCatching { doEmulate(bytes, arch, symbolName, argsJson, enableTrace, result) }
            .onFailure { e ->
                val root = rootCause(e)
                AppLog.w("Unidbg emulation failed: ${e.message}")
                result.put("ok", false)
                    .put("error", JSONObject().put("code", "EMULATION_ERROR")
                        .put("message", root.message ?: root.javaClass.simpleName)
                        .put("exception", e.javaClass.name)
                        .put("rootException", root.javaClass.name)
                        .put("stage", result.optString("stage", "unknown"))
                        .put("nextActions", JSONArray()
                            .put("Call analyze_elf(view=list, subView=dynsyms) to confirm the symbol is exported")
                            .put("Try symbolName=JNI_OnLoad first to verify library initialization")
                            .put("Use trace=true only for small functions because traces are verbose")))
            }
        val elapsedMs = (System.nanoTime() - t0) / 1_000_000
        if (result.optBoolean("ok", false)) result.put("elapsedMs", elapsedMs)
        result
    }.getOrElse { e ->
        JSONObject().put("ok", false)
            .put("error", JSONObject().put("code", "EMULATION_ERROR").put("message", e.message ?: "unknown"))
    }

    /**
     * Dump raw memory at a virtual address after loading the SO.
     *
     * Loads the SO into the emulator (optionally running JNI_OnLoad), then
     * reads [size] bytes at [addr]. Useful for inspecting decoded data,
     * decrypted buffers, or patched code at runtime.
     *
     * @return JSONObject with ok, hex, ascii, size
     */
    fun dumpMemory(
        bytes: ByteArray,
        arch: String,
        addr: Long,
        size: Int,
    ): JSONObject = runCatching {
        if (!available()) return@runCatching JSONObject()
            .put("ok", false)
            .put("error", JSONObject().put("code", "EMULATOR_UNAVAILABLE")
                .put("message", "Unidbg not available"))

        val result = JSONObject()
        runCatching { doDumpMemory(bytes, arch, addr, size, result) }
            .onFailure { e ->
                val root = rootCause(e)
                result.put("ok", false)
                    .put("error", JSONObject().put("code", "DUMP_ERROR")
                        .put("message", root.message ?: root.javaClass.simpleName)
                        .put("exception", e.javaClass.name)
                        .put("rootException", root.javaClass.name)
                        .put("stage", result.optString("stage", "unknown")))
            }
        result
    }.getOrElse { e ->
        JSONObject().put("ok", false)
            .put("error", JSONObject().put("code", "DUMP_ERROR").put("message", e.message ?: "unknown"))
    }

    fun openSession(bytes: ByteArray, arch: String, callJniOnLoad: Boolean = true): JSONObject {
        val result = JSONObject()
        return runCatching {
            val live = createLiveSession(bytes, arch, callJniOnLoad, result)
            result.put("ok", true)
                .put("live", live)
                .put("backend", live.backend?.javaClass?.name ?: JSONObject.NULL)
                .put("backendFactory", live.backendFactory)
                .put("architecture", arch)
        }.getOrElse { e ->
            val root = rootCause(e)
            result.put("ok", false)
                .put("error", JSONObject().put("code", "SESSION_OPEN_ERROR")
                    .put("message", root.message ?: root.javaClass.simpleName)
                    .put("exception", e.javaClass.name)
                    .put("rootException", root.javaClass.name)
                    .put("stage", result.optString("stage", "unknown")))
        }
    }

    fun closeSession(live: LiveSession) {
        synchronized(live.lock) {
            runCatching { live.emulator.javaClass.getMethod("close").invoke(live.emulator) }
            runCatching { live.path.delete() }
        }
    }

    fun sessionCall(live: LiveSession, symbolName: String, argsJson: JSONArray, enableTrace: Boolean): JSONObject = runCatching {
        val result = JSONObject()
        synchronized(live.lock) {
            runCatching { doLiveCall(live, symbolName, argsJson, enableTrace, result) }
                .onFailure { e ->
                    val root = rootCause(e)
                    result.put("ok", false)
                        .put("error", JSONObject().put("code", "EMULATION_ERROR")
                            .put("message", root.message ?: root.javaClass.simpleName)
                            .put("exception", e.javaClass.name)
                            .put("rootException", root.javaClass.name)
                            .put("stage", result.optString("stage", "unknown")))
                }
        }
        addSuspiciousReturnWarning(result, symbolName, enableTrace)
        result
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "EMULATION_ERROR").put("message", e.message ?: "unknown")) }

    fun sessionDump(live: LiveSession, addr: Long, size: Int): JSONObject = runCatching {
        val result = JSONObject()
        synchronized(live.lock) {
            runCatching { readLiveMemory(live, addr, size, result) }
                .onFailure { e ->
                    val root = rootCause(e)
                    result.put("ok", false)
                        .put("error", JSONObject().put("code", "DUMP_ERROR")
                            .put("message", root.message ?: root.javaClass.simpleName)
                            .put("exception", e.javaClass.name)
                            .put("rootException", root.javaClass.name)
                            .put("stage", result.optString("stage", "unknown")))
                }
        }
        result
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "DUMP_ERROR").put("message", e.message ?: "unknown")) }

    fun sessionMemoryMaps(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val memory = live.emulator.javaClass.getMethod("getMemory").invoke(live.emulator)
            val maps = memory.javaClass.getMethod("getMemoryMap").invoke(memory) as? Collection<*> ?: emptyList<Any>()
            val items = JSONArray()
            maps.forEach { map ->
                if (map == null) return@forEach
                val cls = map.javaClass
                val base = cls.getField("base").getLong(map)
                val size = cls.getField("size").getLong(map)
                val prot = cls.getField("prot").getInt(map)
                items.put(JSONObject()
                    .put("base", "0x${base.toString(16)}")
                    .put("end", "0x${(base + size).toString(16)}")
                    .put("size", size)
                    .put("prot", prot)
                    .put("permissions", memoryProt(prot)))
            }
            JSONObject().put("ok", true).put("persistent", true).put("addressSpace", "runtimeAbsoluteVirtualAddress").put("memoryMaps", items)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_MAP_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionRegisters(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val context = live.emulator.javaClass.getMethod("getContext").invoke(live.emulator) ?: throw IllegalStateException("Register context unavailable")
            val values = if (live.arch == "arm64" || live.arch == "x86_64") readArm64Context(context) else readArm32Context(context)
            JSONObject().put("ok", true).put("persistent", true).put("registerScope", "generalPurposeSnapshot").put("note", "This is a general-purpose register snapshot. SIMD/FP/system registers require explicit backend-specific support.").put("registers", values)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "REGISTERS_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionMemoryWrite(live: LiveSession, addr: Long, hexBytes: String): JSONObject = runCatching {
        synchronized(live.lock) {
            val data = hexToBytes(hexBytes)
            val memWrite = live.backend?.javaClass?.methods?.firstOrNull { it.name == "mem_write" && it.parameterCount == 2 }
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "BACKEND_ERROR").put("message", "mem_write not available"))
            memWrite.invoke(live.backend, addr, data)
            JSONObject().put("ok", true).put("persistent", true).put("addr", "0x${addr.toString(16)}").put("size", data.size)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_WRITE_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionMemoryMap(live: LiveSession, addr: Long, size: Long, prot: Int): JSONObject = runCatching {
        synchronized(live.lock) {
            val memory = live.emulator.javaClass.getMethod("getMemory").invoke(live.emulator)
            val mmap2 = memory.javaClass.methods.firstOrNull { it.name == "mmap2" && it.parameterCount == 6 }
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_API_ERROR").put("message", "mmap2 not available"))
            val flags = if (addr == 0L) 0x22 else 0x32
            val mapped = (mmap2.invoke(memory, addr, size.toInt(), prot, flags, -1, 0) as Number).toLong()
            check(mapped >= 0) { "mmap2 failed: $mapped" }
            JSONObject().put("ok", true).put("persistent", true).put("requestedAddr", "0x${addr.toString(16)}").put("addr", "0x${mapped.toString(16)}").put("size", size).put("prot", prot).put("permissions", memoryProt(prot))
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_MAP_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionMemoryProtect(live: LiveSession, addr: Long, size: Long, prot: Int): JSONObject = runCatching {
        synchronized(live.lock) {
            val memory = live.emulator.javaClass.getMethod("getMemory").invoke(live.emulator)
            val memProtect = memory.javaClass.methods.firstOrNull { it.name == "mprotect" && it.parameterCount == 3 }
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_API_ERROR").put("message", "mprotect not available"))
            val result = (memProtect.invoke(memory, addr, size.toInt(), prot) as Number).toInt()
            check(result >= 0) { "mprotect failed: $result" }
            JSONObject().put("ok", true).put("persistent", true).put("addr", "0x${addr.toString(16)}").put("size", size).put("prot", prot).put("permissions", memoryProt(prot))
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_PROTECT_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionMemoryUnmap(live: LiveSession, addr: Long, size: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val memory = live.emulator.javaClass.getMethod("getMemory").invoke(live.emulator)
            val memUnmap = memory.javaClass.methods.firstOrNull { it.name == "munmap" && it.parameterCount == 2 }
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_API_ERROR").put("message", "munmap not available"))
            val result = (memUnmap.invoke(memory, addr, size.toInt()) as Number).toInt()
            check(result >= 0) { "munmap failed: $result" }
            JSONObject().put("ok", true).put("persistent", true).put("addr", "0x${addr.toString(16)}").put("size", size)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MEMORY_UNMAP_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionModules(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val memory = live.emulator.javaClass.getMethod("getMemory").invoke(live.emulator)
            val modules = memory.javaClass.methods.firstOrNull { it.name == "getLoadedModules" && it.parameterCount == 0 }?.invoke(memory) as? Collection<*> ?: listOf(live.module)
            val items = JSONArray()
            modules.forEach { module -> if (module != null) items.put(moduleJson(module)) }
            JSONObject().put("ok", true).put("persistent", true).put("modules", items)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "MODULES_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionExports(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val symbols = live.module.javaClass.methods.firstOrNull { it.name == "getExportedSymbols" && it.parameterCount == 0 }?.invoke(live.module) as? Collection<*> ?: emptyList<Any>()
            val items = JSONArray()
            symbols.forEach { symbol -> if (symbol != null) items.put(symbolJson(symbol)) }
            JSONObject().put("ok", true).put("persistent", true).put("exports", items)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "EXPORTS_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionCallAddress(live: LiveSession, address: Long, argsJson: JSONArray): JSONObject = runCatching {
        synchronized(live.lock) {
            val moduleClass = Class.forName("com.github.unidbg.Module")
            val emulateFunction = moduleClass.getMethod("emulateFunction", Class.forName("com.github.unidbg.Emulator"), Long::class.javaPrimitiveType, Array<Any>::class.java)
            val ret = emulateFunction.invoke(null, live.emulator, address, toArgList(argsJson).toTypedArray())
            JSONObject().put("ok", true).put("persistent", true).put("addr", "0x${address.toString(16)}").put("returnValue", ret?.toString() ?: "0").put("args", summarizeArgs(argsJson)).also { addSuspiciousReturnWarning(it, "address:0x${address.toString(16)}", false) }
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "CALL_ADDRESS_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionTraceCode(live: LiveSession, begin: Long, end: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val method = live.emulator.javaClass.methods.firstOrNull { it.name == "traceCode" && it.parameterCount == 2 }
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "TRACE_UNAVAILABLE").put("message", "traceCode(begin,end) not available"))
            val hook = method.invoke(live.emulator, begin, end)
            JSONObject().put("ok", true).put("persistent", true).put("trace", "code").put("begin", "0x${begin.toString(16)}").put("end", "0x${end.toString(16)}").put("hook", hook?.javaClass?.name ?: JSONObject.NULL)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "TRACE_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionTraceStart(live: LiveSession, type: String, begin: Long, end: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val listenerClass = Class.forName(when (type) {
                "read" -> "com.github.unidbg.listener.TraceReadListener"
                "write" -> "com.github.unidbg.listener.TraceWriteListener"
                else -> "com.github.unidbg.listener.TraceCodeListener"
            })
            val listener = java.lang.reflect.Proxy.newProxyInstance(listenerClass.classLoader, arrayOf(listenerClass)) { _, method, callbackArgs ->
                val values = callbackArgs ?: emptyArray()
                val event = JSONObject().put("index", live.traceEvents.size).put("type", type).put("method", method.name).put("timestamp", System.currentTimeMillis())
                if (values.size > 1 && values[1] is Number) event.put("address", "0x${(values[1] as Number).toLong().toString(16)}")
                when (type) {
                    "code" -> if (values.size > 2) event.put("instruction", values[2]?.toString() ?: JSONObject.NULL)
                    "read" -> if (values.size > 2) event.put("bytes", (values[2] as? ByteArray)?.joinToString("") { "%02x".format(it) } ?: JSONObject.NULL).put("label", values.getOrNull(3)?.toString() ?: JSONObject.NULL)
                    "write" -> if (values.size > 3) event.put("size", values[2]).put("value", "0x${(values[3] as Number).toLong().toString(16)}")
                }
                if (live.traceEvents.size >= 100000) live.traceEvents.removeAt(0)
                live.traceEvents.add(event)
                method.returnType == Boolean::class.javaPrimitiveType
            }
            val methodName = when (type) { "read" -> "traceRead"; "write" -> "traceWrite"; else -> "traceCode" }
            val method = live.emulator.javaClass.methods.first { it.name == methodName && it.parameterCount == 3 && it.parameterTypes[2] == listenerClass }
            val hook = method.invoke(live.emulator, begin, end, listener) ?: throw IllegalStateException("Trace hook unavailable")
            val traceId = "trace-${type}-${live.traceHooks.size + 1}"
            live.traceHooks[traceId] = hook
            JSONObject().put("ok", true).put("persistent", true).put("traceId", traceId).put("type", type).put("begin", "0x${begin.toString(16)}").put("end", "0x${end.toString(16)}")
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "TRACE_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionTraceEvents(live: LiveSession, cursor: Int, limit: Int): JSONObject = synchronized(live.lock) {
        val start = cursor.coerceIn(0, live.traceEvents.size)
        val end = (start + limit.coerceIn(1, 1000)).coerceAtMost(live.traceEvents.size)
        JSONObject().put("ok", true).put("persistent", true).put("cursor", start).put("nextCursor", end).put("total", live.traceEvents.size).put("hasMore", end < live.traceEvents.size).put("events", JSONArray(live.traceEvents.subList(start, end)))
    }

    fun sessionTraceStop(live: LiveSession, traceId: String): JSONObject = runCatching {
        synchronized(live.lock) {
            val hook = live.traceHooks.remove(traceId) ?: throw IllegalArgumentException("Trace hook not found")
            hook.javaClass.methods.first { it.name == "stopTrace" && it.parameterCount == 0 }.invoke(hook)
            JSONObject().put("ok", true).put("persistent", true).put("traceId", traceId).put("stopped", true)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "TRACE_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionTraceClear(live: LiveSession): JSONObject = synchronized(live.lock) {
        val count = live.traceEvents.size
        live.traceEvents.clear()
        JSONObject().put("ok", true).put("persistent", true).put("cleared", count)
    }

    fun sessionHookStart(live: LiveSession, type: String, begin: Long, end: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val backend = live.backend ?: throw IllegalStateException("Backend unavailable")
            val interfaceName = when (type) {
                "interrupt", "syscall" -> "com.github.unidbg.arm.backend.InterruptHook"
                "read" -> "com.github.unidbg.arm.backend.ReadHook"
                "write" -> "com.github.unidbg.arm.backend.WriteHook"
                else -> "com.github.unidbg.arm.backend.CodeHook"
            }
            val hookClass = Class.forName(interfaceName)
            val hookId = "hook-${type}-${live.traceHooks.size + 1}"
            val callback = java.lang.reflect.Proxy.newProxyInstance(hookClass.classLoader, arrayOf(hookClass)) { _, method, callbackArgs ->
                val values = callbackArgs ?: emptyArray()
                when (method.name) {
                    "onAttach" -> if (values.isNotEmpty() && values[0] != null) live.traceHooks[hookId] = values[0]
                    "detach" -> live.traceHooks.remove(hookId)
                    "hook" -> {
                        val event = JSONObject().put("index", live.traceEvents.size).put("type", type).put("timestamp", System.currentTimeMillis())
                        if (type == "interrupt" || type == "syscall") {
                            event.put("intno", values.getOrNull(1)).put("swi", values.getOrNull(2))
                        } else {
                            event.put("address", "0x${(values.getOrNull(1) as? Number)?.toLong()?.toString(16)}").put("size", values.getOrNull(2))
                            if (type == "write") event.put("value", "0x${(values.getOrNull(3) as? Number)?.toLong()?.toString(16)}")
                        }
                        if (live.traceEvents.size >= 100000) live.traceEvents.removeAt(0)
                        live.traceEvents.add(event)
                    }
                }
                method.returnType == Boolean::class.javaPrimitiveType
            }
            val method = if (type == "interrupt" || type == "syscall") {
                backend.javaClass.methods.first { it.name == "hook_add_new" && it.parameterCount == 2 && it.parameterTypes[0] == hookClass }
            } else {
                backend.javaClass.methods.first { it.name == "hook_add_new" && it.parameterCount == 4 && it.parameterTypes[0] == hookClass }
            }
            if (method.parameterCount == 2) method.invoke(backend, callback, hookId) else method.invoke(backend, callback, begin, end, hookId)
            live.traceHooks.putIfAbsent(hookId, callback)
            JSONObject().put("ok", true).put("persistent", true).put("hookId", hookId).put("type", type).put("begin", "0x${begin.toString(16)}").put("end", "0x${end.toString(16)}")
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "HOOK_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionHookStop(live: LiveSession, hookId: String): JSONObject = runCatching {
        synchronized(live.lock) {
            val hook = live.traceHooks.remove(hookId) ?: throw IllegalArgumentException("Hook not found")
            val unhook = hook.javaClass.methods.firstOrNull { it.name == "unhook" && it.parameterCount == 0 }
            val detach = hook.javaClass.methods.firstOrNull { it.name == "detach" && it.parameterCount == 0 }
            when {
                unhook != null -> unhook.invoke(hook)
                detach != null -> detach.invoke(hook)
                else -> throw IllegalStateException("Hook does not expose unhook/detach")
            }
            JSONObject().put("ok", true).put("persistent", true).put("hookId", hookId).put("stopped", true)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "HOOK_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionHookList(live: LiveSession): JSONObject = synchronized(live.lock) {
        JSONObject().put("ok", true).put("persistent", true).put("hooks", JSONArray(live.traceHooks.keys))
    }

    fun sessionBreakpointAdd(live: LiveSession, address: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val debugger = live.emulator.javaClass.methods.firstOrNull { it.name == "attach" && it.parameterCount == 0 }?.invoke(live.emulator)
                ?: return@runCatching JSONObject().put("ok", false).put("error", JSONObject().put("code", "DEBUGGER_UNAVAILABLE").put("message", "attach() returned null"))
            val breakpoint = debugger.javaClass.methods.firstOrNull { it.name == "addBreakPoint" && it.parameterCount == 1 && it.parameterTypes[0] == Long::class.javaPrimitiveType }?.invoke(debugger, address)
            val breakpointId = "bp-${address.toString(16)}-${live.breakpoints.size + 1}"
            if (breakpoint != null) live.breakpoints[breakpointId] = breakpoint
            JSONObject().put("ok", breakpoint != null).put("persistent", true).put("addr", "0x${address.toString(16)}").put("breakpointId", breakpointId).put("backendHandleType", breakpoint?.javaClass?.name ?: JSONObject.NULL)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "BREAKPOINT_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionDebuggerStatus(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val debugger = debugger(live)
            val points = debugger.javaClass.methods.first { it.name == "getBreakPoints" && it.parameterCount == 0 }.invoke(debugger) as? Map<*, *> ?: emptyMap<Any, Any>()
            val items = JSONArray()
            points.forEach { (address, point) -> items.put(JSONObject().put("address", "0x${(address as Number).toLong().toString(16)}").put("temporary", point?.javaClass?.methods?.firstOrNull { it.name == "isTemporary" }?.invoke(point) ?: false).put("thumb", point?.javaClass?.methods?.firstOrNull { it.name == "isThumb" }?.invoke(point) ?: false)) }
            JSONObject().put("ok", true).put("persistent", true).put("isDebugging", debugger.javaClass.methods.first { it.name == "isDebugging" }.invoke(debugger)).put("hasRunnable", debugger.javaClass.methods.first { it.name == "hasRunnable" }.invoke(debugger)).put("breakpoints", items)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "DEBUGGER_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionBreakpointRemove(live: LiveSession, address: Long): JSONObject = runCatching {
        synchronized(live.lock) {
            val debugger = debugger(live)
            val removed = debugger.javaClass.methods.first { it.name == "removeBreakPoint" && it.parameterCount == 1 }.invoke(debugger, address) as Boolean
            live.breakpoints.entries.removeAll { it.key.contains(address.toString(16), true) }
            JSONObject().put("ok", true).put("persistent", true).put("removed", removed).put("address", "0x${address.toString(16)}")
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "BREAKPOINT_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionSingleStep(live: LiveSession, count: Int): JSONObject = runCatching {
        synchronized(live.lock) {
            val backend = live.backend ?: throw IllegalStateException("Backend unavailable")
            backend.javaClass.methods.first { it.name == "setSingleStep" && it.parameterCount == 1 }.invoke(backend, count.coerceAtLeast(1))
            JSONObject().put("ok", true).put("persistent", true).put("singleStepCount", count.coerceAtLeast(1))
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "SINGLE_STEP_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    fun sessionEmuStop(live: LiveSession): JSONObject = runCatching {
        synchronized(live.lock) {
            val backend = live.backend ?: throw IllegalStateException("Backend unavailable")
            backend.javaClass.methods.first { it.name == "emu_stop" && it.parameterCount == 0 }.invoke(backend)
            JSONObject().put("ok", true).put("persistent", true).put("stopped", true)
        }
    }.getOrElse { e -> JSONObject().put("ok", false).put("error", JSONObject().put("code", "EMU_STOP_ERROR").put("message", rootCause(e).message ?: e.javaClass.simpleName)) }

    private fun debugger(live: LiveSession): Any {
        return live.objects["debugger"] ?: (live.emulator.javaClass.methods.first { it.name == "attach" && it.parameterCount == 0 }.invoke(live.emulator)
            ?: throw IllegalStateException("Debugger unavailable")).also { live.objects["debugger"] = it }
    }

    fun sessionReflectRoots(live: LiveSession): JSONObject = synchronized(live.lock) {
        live.objects["emulator"] = live.emulator
        live.vm?.let { live.objects["vm"] = it }
        live.objects["module"] = live.module
        live.backend?.let { live.objects["backend"] = it }
        runCatching { live.emulator.javaClass.methods.firstOrNull { it.name == "getMemory" && it.parameterCount == 0 }?.invoke(live.emulator) }.getOrNull()?.let { live.objects["memory"] = it }
        runCatching { live.emulator.javaClass.methods.firstOrNull { it.name == "getSyscallHandler" && it.parameterCount == 0 }?.invoke(live.emulator) }.getOrNull()?.let { live.objects["syscallHandler"] = it }
        live.objects["debugger"] = debugger(live)
        val roots = JSONObject()
        live.objects.forEach { (handle, value) -> roots.put(handle, JSONObject().put("handle", handle).put("class", value.javaClass.name)) }
        JSONObject().put("ok", true).put("persistent", true).put("roots", roots)
    }

    fun sessionReflectMethods(live: LiveSession, handle: String): JSONObject = synchronized(live.lock) {
        sessionReflectRoots(live)
        val target = live.objects[handle] ?: return@synchronized JSONObject().put("ok", false).put("error", JSONObject().put("code", "OBJECT_HANDLE_NOT_FOUND").put("message", "Unknown Unidbg object handle: $handle"))
        val methods = JSONArray()
        target.javaClass.methods.sortedWith(compareBy({ it.name }, { it.parameterCount })).forEach { method ->
            methods.put(JSONObject().put("name", method.name).put("returnType", method.returnType.name).put("parameterTypes", JSONArray(method.parameterTypes.map { it.name })).put("signature", method.toGenericString()))
        }
        JSONObject().put("ok", true).put("persistent", true).put("handle", handle).put("class", target.javaClass.name).put("methods", methods)
    }

    fun sessionReflectInvoke(live: LiveSession, handle: String, methodName: String, args: JSONArray): JSONObject = synchronized(live.lock) {
        sessionReflectRoots(live)
        val target = live.objects[handle] ?: return@synchronized JSONObject().put("ok", false).put("error", JSONObject().put("code", "OBJECT_HANDLE_NOT_FOUND").put("message", "Unknown Unidbg object handle: $handle"))
        val candidates = target.javaClass.methods.filter { it.name == methodName && it.parameterCount == args.length() }
        val failures = JSONArray()
        for (method in candidates) {
            val attempt = runCatching {
                val converted = Array(method.parameterCount) { index -> reflectArgument(live, args.opt(index), method.parameterTypes[index]) }
                method.invoke(target, *converted)
            }
            if (attempt.isSuccess) return@synchronized JSONObject()
                .put("ok", true)
                .put("persistent", true)
                .put("handle", handle)
                .put("method", methodName)
                .put("signature", method.toGenericString())
                .put("result", reflectResult(live, attempt.getOrNull()))
            failures.put(JSONObject().put("signature", method.toGenericString()).put("error", rootCause(attempt.exceptionOrNull()!!).toString()))
        }
        JSONObject().put("ok", false).put("error", JSONObject().put("code", "REFLECT_INVOKE_FAILED").put("message", "No compatible public method overload succeeded").put("handle", handle).put("method", methodName).put("failures", failures))
    }

    fun sessionNativeToolSchemas(live: LiveSession): JSONObject = synchronized(live.lock) {
        runCatching {
            val tools = nativeMcpTools(live)
            val schemas = tools.javaClass.getMethod("getToolSchemas").invoke(tools)
            JSONObject().put("ok", true).put("persistent", true).put("source", "unidbg-upstream-mcp").put("schemas", JSONArray(schemas.toString()))
        }.getOrElse { error ->
            JSONObject().put("ok", false).put("error", JSONObject().put("code", "UNIDBG_NATIVE_MCP_UNAVAILABLE").put("message", rootCause(error).toString()))
        }
    }

    fun sessionNativeToolCall(live: LiveSession, toolName: String, args: JSONObject): JSONObject = synchronized(live.lock) {
        runCatching {
            val tools = nativeMcpTools(live)
            val fastJsonClass = Class.forName("com.alibaba.fastjson.JSONObject")
            val fastArgs = fastJsonClass.getConstructor(Map::class.java).newInstance(jsonObjectToMap(args))
            val dispatch = tools.javaClass.getDeclaredMethod("dispatchTool", String::class.java, fastJsonClass).apply { isAccessible = true }
            val result = dispatch.invoke(tools, toolName, fastArgs)
            JSONObject(result.toString()).put("persistent", true).put("source", "unidbg-upstream-mcp").put("nativeTool", toolName)
        }.getOrElse { error ->
            JSONObject().put("ok", false).put("error", JSONObject().put("code", "UNIDBG_NATIVE_TOOL_FAILED").put("message", rootCause(error).toString()).put("tool", toolName))
        }
    }

    private fun nativeMcpTools(live: LiveSession): Any {
        live.objects["nativeMcpTools"]?.let { return it }
        val emulatorClass = Class.forName("com.github.unidbg.Emulator")
        val serverClass = Class.forName("com.github.unidbg.mcp.McpServer")
        val server = serverClass.getConstructor(emulatorClass, Int::class.javaPrimitiveType).newInstance(live.emulator, 0)
        val toolsClass = Class.forName("com.github.unidbg.mcp.McpTools")
        val tools = toolsClass.getConstructor(emulatorClass, serverClass).newInstance(live.emulator, server)
        live.objects["nativeMcpServer"] = server
        live.objects["nativeMcpTools"] = tools
        return tools
    }

    private fun jsonObjectToMap(value: JSONObject): Map<String, Any?> {
        val result = LinkedHashMap<String, Any?>()
        value.keys().forEach { key -> result[key] = jsonValueToJava(value.opt(key)) }
        return result
    }

    private fun jsonValueToJava(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> (0 until value.length()).map { jsonValueToJava(value.opt(it)) }
        else -> value
    }

    private fun reflectArgument(live: LiveSession, value: Any?, type: Class<*>): Any? {
        if (value == null || value == JSONObject.NULL) return null
        if (value is JSONObject && value.has("handle")) return live.objects[value.getString("handle")] ?: throw IllegalArgumentException("Unknown object handle")
        if (type == String::class.java || type == CharSequence::class.java) return value.toString()
        if (type == Boolean::class.javaPrimitiveType || type == Boolean::class.javaObjectType) return if (value is Boolean) value else value.toString().toBooleanStrict()
        if (type == Byte::class.javaPrimitiveType || type == Byte::class.javaObjectType) return (value as Number).toByte()
        if (type == Short::class.javaPrimitiveType || type == Short::class.javaObjectType) return (value as Number).toShort()
        if (type == Int::class.javaPrimitiveType || type == Int::class.javaObjectType) return (value as Number).toInt()
        if (type == Long::class.javaPrimitiveType || type == Long::class.javaObjectType) return (value as Number).toLong()
        if (type == Float::class.javaPrimitiveType || type == Float::class.javaObjectType) return (value as Number).toFloat()
        if (type == Double::class.javaPrimitiveType || type == Double::class.javaObjectType) return (value as Number).toDouble()
        if (type == ByteArray::class.java && value is String) return hexToBytes(value)
        if (type.isEnum) return type.enumConstants?.firstOrNull { (it as Enum<*>).name == value.toString() } ?: throw IllegalArgumentException("Unknown enum value")
        if (type.isInstance(value)) return value
        throw IllegalArgumentException("Cannot convert ${value.javaClass.name} to ${type.name}")
    }

    private fun reflectResult(live: LiveSession, value: Any?): Any {
        if (value == null) return JSONObject.NULL
        if (value is String || value is Number || value is Boolean) return value
        if (value is ByteArray) return value.joinToString("") { "%02x".format(it) }
        if (value.javaClass.isArray) return JSONArray((0 until java.lang.reflect.Array.getLength(value)).map { reflectResult(live, java.lang.reflect.Array.get(value, it)) })
        if (value is Iterable<*>) return JSONArray(value.map { reflectResult(live, it) })
        if (value is Map<*, *>) return JSONObject().also { json -> value.forEach { (key, item) -> json.put(key.toString(), reflectResult(live, item)) } }
        val handle = "obj-${live.objects.size + 1}"
        live.objects[handle] = value
        return JSONObject().put("handle", handle).put("class", value.javaClass.name).put("display", value.toString())
    }

    /** Reflectively drive Unidbg so a missing class never breaks the build. */
    private fun doEmulate(
        bytes: ByteArray,
        arch: String,
        symbolName: String,
        argsJson: JSONArray,
        enableTrace: Boolean,
        out: JSONObject,
    ) {
        val live = createLiveSession(bytes, arch, true, out)
        try {
            doLiveCall(live, symbolName, argsJson, enableTrace, out)
        } finally {
            closeSession(live)
        }
    }

    private fun createLiveSession(bytes: ByteArray, arch: String, callJniOnLoad: Boolean, out: JSONObject): LiveSession {
        val emulatorBuilderCls = Class.forName("com.github.unidbg.linux.android.AndroidEmulatorBuilder")
        out.put("stage", "builder")
        val for64Bit = arch == "arm64" || arch == "x86_64"
        val builder = emulatorBuilderCls.getDeclaredMethod(if (for64Bit) "for64Bit" else "for32Bit").invoke(null)!!
        val backendFactory = addUnicorn2Backend(builder)
        out.put("backendFactory", backendFactory)
        val emulator = emulatorBuilderCls.getDeclaredMethod("build").invoke(builder)!!
        out.put("stage", "resolver")
        setAndroidResolver(emulator)
        out.put("stage", "createDalvikVM")
        val backend = emulator.javaClass.getMethod("getBackend").invoke(emulator)
        out.put("backend", backend?.javaClass?.name ?: JSONObject.NULL)
        val vm = emulator.javaClass.getMethod("createDalvikVM").invoke(emulator)
        out.put("stage", "loadLibrary")
        val file = writeTemp(bytes, "session")
        val dalvikModule = vm?.javaClass?.methods?.firstOrNull { it.name == "loadLibrary" && it.parameterCount >= 2 }?.invoke(vm, file, false)
        val module = dalvikModule?.javaClass?.getMethod("getModule")?.invoke(dalvikModule)
            ?: throw IllegalStateException("Unidbg failed to load SO")
        val live = LiveSession(emulator, vm, module, backend, arch, file, backendFactory)
        if (callJniOnLoad) callJniOnLoad(live)
        return live
    }

    private fun callJniOnLoad(live: LiveSession) {
        val findSym = live.module.javaClass.getMethod("findSymbolByName", String::class.java, Boolean::class.javaPrimitiveType)
        val jniOnLoad = findSym.invoke(live.module, "JNI_OnLoad", true)
        if (jniOnLoad != null) runCatching { callSymbol(jniOnLoad, live.emulator, listOf(live.vm)) }
            .onFailure { e -> AppLog.w("JNI_OnLoad failed: ${e.message}") }
    }

    private fun doLiveCall(live: LiveSession, symbolName: String, argsJson: JSONArray, enableTrace: Boolean, out: JSONObject) {
        if (enableTrace && live.vm != null) runCatching { live.vm.javaClass.methods.firstOrNull { it.name == "setVerbose" && it.parameterCount == 1 }?.invoke(live.vm, true) }
        out.put("stage", "findSymbol")
        val findSym = live.module.javaClass.getMethod("findSymbolByName", String::class.java, Boolean::class.javaPrimitiveType)
        val symbol = findSym.invoke(live.module, symbolName, true)
        if (symbol == null) {
            out.put("ok", false).put("error", JSONObject().put("code", "SYMBOL_NOT_FOUND").put("message", "Symbol $symbolName not exported by the SO"))
            return
        }
        val args = toArgList(argsJson)
        val isJni = symbolName.startsWith("Java_")
        val callArgs = if (isJni) {
            val jniEnv = runCatching { live.vm?.javaClass?.methods?.firstOrNull { it.name == "getJNIEnv" }?.invoke(live.vm) }.getOrNull()
            listOf(jniEnv ?: 0L, 0L) + args
        } else args
        out.put("stage", "callSymbol")
        val ret = callSymbol(symbol, live.emulator, callArgs)
        out.put("ok", true)
            .put("stage", "completed")
            .put("symbol", symbolName)
            .put("jni", isJni)
            .put("returnValue", ret?.toString() ?: "0")
            .put("args", summarizeArgs(argsJson))
            .put("traced", enableTrace)
            .put("persistent", true)
    }

    private fun setAndroidResolver(emulator: Any) {
        val resolverCls = Class.forName("com.github.unidbg.linux.android.AndroidResolver")
        val resolver = resolverCls.getConstructor(Int::class.javaPrimitiveType, Array<String>::class.java)
            .newInstance(23, emptyArray<String>())
        val resolverInterface = Class.forName("com.github.unidbg.LibraryResolver")
        emulator.javaClass.getMethod("getMemory").invoke(emulator)?.let { mem ->
            mem.javaClass.getMethod("setLibraryResolver", resolverInterface).invoke(mem, resolver)
        }
    }

    private fun doDumpMemory(
        bytes: ByteArray,
        arch: String,
        addr: Long,
        size: Int,
        out: JSONObject,
    ) {
        val live = createLiveSession(bytes, arch, true, out)
        try {
            readLiveMemory(live, addr, size, out)
        } finally {
            closeSession(live)
        }
    }

    private fun readLiveMemory(live: LiveSession, addr: Long, size: Int, out: JSONObject) {
        out.put("stage", "readMemory")
        val memRead = live.backend?.javaClass?.methods?.firstOrNull { it.name == "mem_read" && it.parameterCount == 2 }
        if (memRead == null) {
            out.put("ok", false).put("error", JSONObject().put("code", "BACKEND_ERROR").put("message", "mem_read not available on backend"))
            return
        }
        val dumpSize = size.coerceIn(1, 65536)
        val raw = memRead.invoke(live.backend, addr, dumpSize) as? ByteArray
        if (raw == null || raw.isEmpty()) {
            out.put("ok", false).put("error", JSONObject().put("code", "READ_FAILED").put("message", "Memory read returned empty"))
            return
        }
        val hex = raw.joinToString("") { "%02x".format(it) }
        val ascii = raw.joinToString("") { if (it in 32..126) it.toInt().toChar().toString() else "." }
        out.put("ok", true)
            .put("addr", addr)
            .put("size", raw.size)
            .put("hex", hex)
            .put("ascii", ascii)
            .put("persistent", true)
    }

    private fun memoryProt(prot: Int): String {
        val chars = charArrayOf('-', '-', '-')
        if ((prot and 1) != 0) chars[0] = 'r'
        if ((prot and 2) != 0) chars[1] = 'w'
        if ((prot and 4) != 0) chars[2] = 'x'
        return String(chars)
    }

    private fun readArm64Context(context: Any): JSONObject {
        val values = JSONObject()
        val getXLong = context.javaClass.methods.firstOrNull { it.name == "getXLong" && it.parameterCount == 1 }
        for (i in 0..28) {
            runCatching { getXLong?.invoke(context, i) }
                .onSuccess { values.put("x$i", it?.toString() ?: "0") }
                .onFailure { values.put("x$i", JSONObject().put("error", rootCause(it).message ?: it.javaClass.simpleName)) }
        }
        listOf("getFp" to "fp", "getLR" to "lr", "getStackPointer" to "sp", "getPCPointer" to "pc").forEach { (methodName, name) ->
            runCatching { context.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 }?.invoke(context) }
                .onSuccess { values.put(name, pointerValue(it)) }
                .onFailure { values.put(name, JSONObject().put("error", rootCause(it).message ?: it.javaClass.simpleName)) }
        }
        return values
    }

    private fun readArm32Context(context: Any): JSONObject {
        val values = JSONObject()
        for (i in 0..12) {
            val methodName = "getR${i}Long"
            runCatching { context.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 }?.invoke(context) }
                .onSuccess { values.put("r$i", it?.toString() ?: "0") }
                .onFailure { values.put("r$i", JSONObject().put("error", rootCause(it).message ?: it.javaClass.simpleName)) }
        }
        listOf("getLR" to "lr", "getStackPointer" to "sp", "getPCPointer" to "pc").forEach { (methodName, name) ->
            runCatching { context.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 }?.invoke(context) }
                .onSuccess { values.put(name, pointerValue(it)) }
                .onFailure { values.put(name, JSONObject().put("error", rootCause(it).message ?: it.javaClass.simpleName)) }
        }
        return values
    }

    private fun pointerValue(value: Any?): String = when (value) {
        null -> "0"
        is Number -> value.toString()
        else -> runCatching { value.javaClass.getMethod("peer").invoke(value)?.toString() }.getOrNull() ?: value.toString()
    }

    private fun moduleJson(module: Any): JSONObject {
        val cls = module.javaClass
        return JSONObject()
            .put("name", cls.getField("name").get(module)?.toString() ?: module.toString())
            .put("base", "0x${cls.getField("base").getLong(module).toString(16)}")
            .put("size", cls.getField("size").getLong(module))
            .put("path", runCatching { cls.getMethod("getPath").invoke(module)?.toString() }.getOrDefault(""))
            .put("fileSize", runCatching { cls.getMethod("getFileSize").invoke(module) }.getOrDefault(0).toString())
    }

    private fun symbolJson(symbol: Any): JSONObject {
        val cls = symbol.javaClass
        val address = runCatching { cls.getMethod("getAddress").invoke(symbol) as? Number }.getOrNull()?.toLong() ?: 0L
        val value = runCatching { cls.getMethod("getValue").invoke(symbol) as? Number }.getOrNull()?.toLong() ?: 0L
        return JSONObject()
            .put("name", runCatching { cls.getMethod("getName").invoke(symbol)?.toString() }.getOrDefault(symbol.toString()))
            .put("module", runCatching { cls.getMethod("getModuleName").invoke(symbol)?.toString() }.getOrDefault(""))
            .put("address", "0x${address.toString(16)}")
            .put("value", "0x${value.toString(16)}")
            .put("undef", runCatching { cls.getMethod("isUndef").invoke(symbol) as? Boolean }.getOrDefault(false))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val normalized = hex.removePrefix("0x").replace(Regex("\\s+"), "")
        require(normalized.length % 2 == 0) { "hex byte string must have even length" }
        return ByteArray(normalized.length / 2) { index -> normalized.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun callSymbol(symbol: Any, emulator: Any, args: List<Any?>): Any? {
        val argArray = args.toTypedArray()
        val callMethod = symbol.javaClass.methods.firstOrNull {
            it.name == "call" && it.parameterCount == 2
        } ?: symbol.javaClass.methods.firstOrNull {
            it.name == "call" && it.parameterCount == 1
        }
        return if (callMethod?.parameterCount == 2) {
            callMethod.isAccessible = true
            callMethod.invoke(symbol, emulator, argArray)
        } else {
            callMethod?.isAccessible = true
            callMethod?.invoke(symbol, emulator)
        }
    }

    private fun addUnicorn2Backend(builder: Any): String {
        val factoryClass = runCatching { Class.forName("com.github.unidbg.arm.backend.Unicorn2Factory") }.getOrNull() ?: return "missing"
        val factory = factoryClass.constructors.firstOrNull { it.parameterCount == 1 && it.parameterTypes[0] == Boolean::class.javaPrimitiveType }
            ?.newInstance(true)
            ?: factoryClass.getDeclaredConstructor().newInstance()
        val builderClass = Class.forName("com.github.unidbg.EmulatorBuilder")
        val backendFactoryClass = Class.forName("com.github.unidbg.arm.backend.BackendFactory")
        builderClass.getMethod("addBackendFactory", backendFactoryClass).invoke(builder, factory)
        return factoryClass.name
    }

    private fun rootCause(error: Throwable): Throwable {
        var current = if (error is InvocationTargetException && error.targetException != null) error.targetException else error
        while (current.cause != null && current.cause !== current) current = current.cause!!
        return current
    }

    private fun writeTemp(bytes: ByteArray, symbolName: String): File {
        val dir = File(context.cacheDir, "unidbg").apply { mkdirs() }
        val safeName = symbolName.filter { it.isLetterOrDigit() || it == '_' }.take(48)
        val f = File(dir, "emu_${System.currentTimeMillis()}_$safeName.so")
        f.writeBytes(bytes)
        f.deleteOnExit()
        return f
    }

    private fun toArgList(argsJson: JSONArray): List<Any?> {
        return (0 until argsJson.length()).map { i ->
            when (val v = argsJson.opt(i)) {
                is Number -> v.toLong()
                is Boolean -> if (v) 1L else 0L
                null -> 0L
                else -> v.toString()
            }
        }
    }

    private fun summarizeArgs(argsJson: JSONArray): JSONObject {
        val summary = JSONObject()
        val arr = JSONArray()
        for (i in 0 until argsJson.length()) {
            arr.put(argsJson.opt(i)?.toString() ?: "")
        }
        summary.put("count", argsJson.length())
        summary.put("values", arr)
        return summary
    }

    private fun addSuspiciousReturnWarning(result: JSONObject, symbolName: String, traced: Boolean) {
        if (!result.optBoolean("ok", false)) return
        if (result.optString("returnValue") != "-1") return
        result.put("resultConfidence", "suspicious")
            .put("semanticWarning", "Unidbg completed without a backend exception, but returnValue=-1 is suspicious for JNI boolean/int probes such as signal/setjmp guards. Treat this as an emulation-result warning, not proof of target logic success.")
            .put("diagnostics", JSONObject()
                .put("symbol", symbolName)
                .put("traced", traced)
                .put("nextActions", JSONArray()
                    .put("Confirm function semantics from disassembly/decompile output")
                    .put("Use runtime absolute addresses and mapped readable test buffers")
                    .put("Add target-specific signal/sigsetjmp/siglongjmp/syscall hooks if the function relies on signal recovery")
                    .put("Use trace_code plus external log capture when instruction trace lines are required")))
    }
}
