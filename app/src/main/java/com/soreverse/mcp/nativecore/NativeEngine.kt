package com.soreverse.mcp.nativecore

import android.content.Context
import com.soreverse.mcp.core.AppLog
import java.io.File

/**
 * Abstraction over the native disassembly / assembly / analysis backend.
 *
 * The MCP protocol layer and [com.soreverse.mcp.engine.NativeSoEngine] depend
 * on this interface (Dependency Inversion), never on a concrete engine. The
 * active backend is resolved at runtime through [active] and can be swapped at
 * any time via [select] — this is the single, clean seam that lets the project
 * migrate backends without touching any call site or recompiling the Kotlin
 * layer.
 *
 * Contract guarantees every backend must honour:
 *  - [disassemble] returns a multi-line text where each line is
 *    `0xADDR: BB BB ...    mnemonic op_str` (the downstream pager in
 *    NativeSoEngine.disasm parses this exact shape). On failure return "".
 *  - [assemble] returns the encoded machine bytes, or an empty array on
 *    failure (the Kotlin caller then falls back to architecture NOPs).
 *  - [available] must be cheap and side-effect free; it is probed before
 *    the backend is selected as active.
 *
 * Backend: [RizinNativeEngine] — Rizin (librz_asm/librz_analysis/librz_bin)
 * via JNI, statically linked into librz_native.so, powers this interface's
 * disassemble/assemble path.
 *
 * NOTE: Capstone and Keystone are NOT part of this NativeEngine backend, but
 * they are still shipped and REQUIRED by the Unidbg emulation path
 * ([com.soreverse.mcp.engine.UnidbgEmulator], which loads and self-tests
 * libcapstone.so / libkeystone.so / libunicorn.so). Do not remove those
 * native libraries on the assumption that "the engine dropped Capstone" —
 * the emulator still hard-depends on them.
 */
interface NativeEngine {
    val backendName: String

    fun disassemble(bytes: ByteArray, arch: String, address: Long, thumb: Boolean, limit: Int): String

    fun assemble(asm: String, arch: String, address: Long, thumb: Boolean): ByteArray

    fun available(): Boolean

    fun loadStatus(): String

    fun analyze(bytes: ByteArray, arch: String): String

    fun functions(bytes: ByteArray, arch: String): String

    fun cfg(bytes: ByteArray, arch: String, funcVa: Long): String

    fun xrefs(bytes: ByteArray, arch: String, atVa: Long, direction: String = "to"): String

    fun searchBytes(bytes: ByteArray, arch: String, pattern: String, fromVa: Long = 0, toVa: Long = 0): String

    fun scanCrypto(bytes: ByteArray, arch: String): String

    fun esilStep(bytes: ByteArray, arch: String, startVa: Long, stepCount: Int): String

    fun diff(bytesA: ByteArray, bytesB: ByteArray): String

    fun command(bytes: ByteArray, arch: String, command: String, unsafe: Boolean = false): String

    fun decompile(bytes: ByteArray, arch: String, funcVa: Long): String

    companion object {
        @Volatile
        private var instance: NativeEngine = resolveDefault()

        fun active(): NativeEngine = instance

        /**
         * Select a backend by name. Returns true when the named backend exists
         * and reports [available]; otherwise the previous backend is kept and
         * false is returned. Unknown names are logged and rejected so a
         * misconfigured setting never silently downgrades to a no-op backend.
         */
        fun select(name: String): Boolean {
            val candidate = when (name.lowercase()) {
                "rizin", "" -> RizinNativeEngine

                else -> {
                    AppLog.w(
                        "NativeEngine: unknown backend '$name'; keeping ${instance.backendName}"
                    )
                    return false
                }
            }
            if (!candidate.available()) {
                AppLog.w(
                    "NativeEngine: backend '${candidate.backendName}' not available on this ABI; disasm/asm will degrade to pseudo/NOP"
                )
                return false
            }
            instance = candidate
            AppLog.i("NativeEngine backend -> ${candidate.backendName}")
            return true
        }

        private fun resolveDefault(): NativeEngine {
            if (RizinNativeEngine.available()) return RizinNativeEngine
            AppLog.w(
                "NativeEngine: Rizin backend unavailable on this ABI; disasm/asm degrade to pseudo/NOP until librz_native.so is built"
            )
            return RizinNativeEngine
        }
    }
}

/**
 * Rizin backend (librz_arch/librz_analysis/librz_asm/librz_bin) exposed through
 * a dedicated JNI surface in librz_native.so. This is the sole NativeEngine
 * disasm/asm backend; Capstone/Keystone are not used here (though they remain
 * shipped for the Unidbg emulation path).
 *
 * librz_native.so is built by CMake from rizin_core.cpp and statically links
 * the Rizin archives produced by the meson cross-compile (see
 * rizin-cross-*.ini). When the .so is present for an ABI, [available] returns
 * true and the backend drives disasm/asm/xrefs with Rizin's full analysis
 * engine — real function boundaries, real cross-references, real instruction
 * decoding — capabilities Capstone/Keystone never had.
 */
object RizinNativeEngine : NativeEngine {
    override val backendName: String = "rizin"

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var loadError: String = ""

    init {
        val loadResult = runCatching { System.loadLibrary("rz_native") }
        if (loadResult.isFailure) {
            loaded = false
            loadError = loadResult.exceptionOrNull()?.message ?: "Unknown load error"
            AppLog.w("RizinNativeEngine: librz_native load FAILED: $loadError")
        } else {
            // JNI 冒烟自检：真实 librz_native.so 提供 rzSelfTest，空 stub
            // （rizin_stub.cpp，常见于 Rizin 静态库缺失时的 fallback 构建）
            // 没有该符号，调用会抛 UnsatisfiedLinkError。仅凭 dlopen 成功
            // 就报告 loaded 会让 stub 被误判为可用，导致所有 rz* 调用静默
            // 降级（pseudo-fallback / {"error":"failed"}）。
            val selfTest = runCatching { rzSelfTest() }
            val selfTestText = selfTest.getOrNull().orEmpty().trim()
            if (selfTest.isSuccess &&
                selfTestText.isNotEmpty() &&
                !selfTestText.startsWith("ERROR:")
            ) {
                loaded = true
                loadError = ""
                AppLog.i("RizinNativeEngine: librz_native load OK (selfTest: $selfTestText)")
            } else {
                loaded = false
                loadError =
                    "librz_native.so 加载成功但 JNI 自检失败——该 .so 可能是空 stub（Rizin 静态库缺失时的 fallback 构建）。${
                        selfTest.exceptionOrNull()?.message ?: selfTestText.ifBlank {
                            "rzSelfTest returned empty"
                        }
                    }"
                AppLog.e("RizinNativeEngine: selfTest FAILED: $loadError")
            }
        }
    }

    // JNI surface implemented in cpp/rizin_core.cpp.
    external fun rzSelfTest(): String
    external fun rzDisassemble(bytes: ByteArray, arch: String, address: Long, thumb: Boolean, limit: Int): String
    external fun rzAssemble(asm: String, arch: String, address: Long, thumb: Boolean): ByteArray
    external fun rzXrefs(bytes: ByteArray, arch: String, atVa: Long, direction: String): String
    external fun rzAnalyze(bytes: ByteArray, arch: String): String
    external fun rzFunctions(bytes: ByteArray, arch: String): String
    external fun rzCfg(bytes: ByteArray, arch: String, funcVa: Long): String
    external fun rzSearchBytes(bytes: ByteArray, arch: String, pattern: String, fromVa: Long, toVa: Long): String
    external fun rzScanCrypto(bytes: ByteArray, arch: String): String
    external fun rzEsilStep(bytes: ByteArray, arch: String, startVa: Long, stepCount: Int): String
    external fun rzDiff(bytesA: ByteArray, bytesB: ByteArray): String
    external fun rzCommand(bytes: ByteArray, arch: String, command: String, unsafe: Boolean): String
    external fun rzDecompile(bytes: ByteArray, arch: String, funcVa: Long): String
    external fun rzConfigureGhidra(pluginDir: String, sleighHome: String): Boolean

    fun configureGhidra(context: Context): Boolean {
        if (!available()) return false
        return runCatching {
            val root = File(context.filesDir, "rizin")
            val plugins = File(context.applicationInfo.nativeLibraryDir)
            val sleigh = File(root, "plugins/rz_ghidra_sleigh")
            if (sleigh.exists()) sleigh.deleteRecursively()
            copyAssetDir(context, "rizin/plugins/rz_ghidra_sleigh", sleigh)
            val slaCount = sleigh.walkTopDown().count { it.isFile && it.extension == "sla" }
            val ldefsCount = sleigh.walkTopDown().count { it.isFile && it.extension == "ldefs" }
            val ok = rzConfigureGhidra(plugins.absolutePath, sleigh.absolutePath)
            AppLog.i(
                "RizinNativeEngine: ghidra pluginDir=${plugins.absolutePath} sleighHome=${sleigh.absolutePath} sla=$slaCount ldefs=$ldefsCount ok=$ok"
            )
            ok
        }.onFailure {
            AppLog.w("RizinNativeEngine: ghidra configure failed: ${it.message}")
        }.getOrDefault(false)
    }

    override fun available(): Boolean = loaded

    override fun loadStatus(): String = if (loaded) "loaded" else "failed: $loadError"

    // Rizin's RzCore and its global subsystems (rz_util buffers, egg, debug,
    // analysis/bin registries) are NOT thread-safe. Every rz* entry point below
    // spins up and tears down a fresh RzCore in native code; running two of them
    // concurrently from different MCP coroutines corrupts Rizin's global state
    // and crashes in rz_core_free / rz_buf_free (observed SIGSEGV). Serialize ALL
    // native Rizin calls behind one process-wide lock so only a single RzCore is
    // ever alive/mutated at a time. This is the minimal, safe fix and applies to
    // every rz* method, not just the one that happened to crash.
    private val nativeLock = java.util.concurrent.locks.ReentrantLock()

    private inline fun <T> serial(block: () -> T): T {
        nativeLock.lock()
        try {
            return block()
        } finally {
            nativeLock.unlock()
        }
    }

    override fun disassemble(bytes: ByteArray, arch: String, address: Long, thumb: Boolean, limit: Int): String {
        if (!available()) return ""
        return serial {
            runCatching { rzDisassemble(bytes, arch, address, thumb, limit) }.getOrDefault("")
        }
    }

    override fun assemble(asm: String, arch: String, address: Long, thumb: Boolean): ByteArray {
        if (!available()) return ByteArray(0)
        return serial {
            runCatching { rzAssemble(asm, arch, address, thumb) }.getOrDefault(ByteArray(0))
        }
    }

    override fun xrefs(bytes: ByteArray, arch: String, atVa: Long, direction: String): String {
        if (!available()) return "{\"xrefs\":[]}"
        return serial {
            runCatching { rzXrefs(bytes, arch, atVa, direction) }.getOrDefault("{\"xrefs\":[]}")
        }
    }

    override fun analyze(bytes: ByteArray, arch: String): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching { rzAnalyze(bytes, arch) }.getOrDefault("{\"error\":\"failed\"}")
        }
    }

    override fun functions(bytes: ByteArray, arch: String): String {
        if (!available()) return "[]"
        return serial { runCatching { rzFunctions(bytes, arch) }.getOrDefault("[]") }
    }

    override fun cfg(bytes: ByteArray, arch: String, funcVa: Long): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching { rzCfg(bytes, arch, funcVa) }.getOrDefault("{\"error\":\"failed\"}")
        }
    }

    override fun searchBytes(bytes: ByteArray, arch: String, pattern: String, fromVa: Long, toVa: Long): String {
        if (!available()) return "{\"hits\":[]}"
        return serial {
            runCatching {
                rzSearchBytes(bytes, arch, pattern, fromVa, toVa)
            }.getOrDefault("{\"hits\":[]}")
        }
    }

    override fun scanCrypto(bytes: ByteArray, arch: String): String {
        if (!available()) return "{\"hits\":[]}"
        return serial { runCatching { rzScanCrypto(bytes, arch) }.getOrDefault("{\"hits\":[]}") }
    }

    override fun esilStep(bytes: ByteArray, arch: String, startVa: Long, stepCount: Int): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching {
                rzEsilStep(bytes, arch, startVa, stepCount)
            }.getOrDefault("{\"error\":\"failed\"}")
        }
    }

    override fun diff(bytesA: ByteArray, bytesB: ByteArray): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching { rzDiff(bytesA, bytesB) }.getOrDefault("{\"error\":\"failed\"}")
        }
    }

    override fun command(bytes: ByteArray, arch: String, command: String, unsafe: Boolean): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching {
                rzCommand(bytes, arch, command, unsafe)
            }.getOrDefault("{\"error\":\"failed\"}")
        }
    }

    override fun decompile(bytes: ByteArray, arch: String, funcVa: Long): String {
        if (!available()) return "{\"error\":\"unavailable\"}"
        return serial {
            runCatching { rzDecompile(bytes, arch, funcVa) }
                .onSuccess { AppLog.i("RizinNativeEngine: rzDecompile returned ${it.take(160)}") }
                .onFailure { AppLog.e("RizinNativeEngine: rzDecompile failed", it) }
                .getOrDefault("{\"error\":\"failed\"}")
        }
    }
}

private fun copyAssetDir(context: Context, assetPath: String, outDir: File) {
    val names = context.assets.list(assetPath).orEmpty()
    outDir.mkdirs()
    for (name in names) {
        val childAsset = "$assetPath/$name"
        val listed = context.assets.list(childAsset).orEmpty()
        val out = File(outDir, name)
        if (listed.isNotEmpty()) {
            copyAssetDir(context, childAsset, out)
        } else if (!out.exists() || out.length() == 0L) {
            out.parentFile?.mkdirs()
            context.assets.open(childAsset).use { input ->
                out.outputStream().use { input.copyTo(it) }
            }
        }
    }
}
