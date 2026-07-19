package com.soreverse.mcp.engine

import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Builds the ELF overview payload used by the native Analyze tab, matching
 * the SO预览 "ELF总览" sections (basic attrs, segment stats, security features,
 * reverse difficulty, entropy, needed libs).
 */
object ElfOverviewBuilder {
    private const val PF_X = 0x1L
    private const val PF_W = 0x2L
    private const val PF_R = 0x4L
    private const val PT_LOAD = 1L
    private const val PT_GNU_STACK = 0x6474e551L
    private const val PT_GNU_RELRO = 0x6474e552L
    private const val DT_NEEDED = 1L
    private const val DT_SONAME = 14L
    private const val DT_FLAGS = 30L
    private const val DT_FLAGS_1 = 0x6ffffffbL
    private const val DT_BIND_NOW = 24L
    private const val DT_TEXTREL = 22L
    private const val DF_BIND_NOW = 0x8L
    private const val DF_1_NOW = 0x1L

    private val knownLibs = mapOf(
        "libc.so" to "C标准库 (系统调用、内存分配)",
        "libm.so" to "数学库 (Math functions)",
        "libdl.so" to "动态链接器接口",
        "libz.so" to "Zlib数据压缩库",
        "liblog.so" to "Android Log日志库",
        "libstdc++.so" to "C++标准库",
        "libc++.so" to "LLVM C++标准库",
        "libGLESv2.so" to "OpenGL ES 2.0 图形库",
        "libEGL.so" to "EGL图形接口",
        "libandroid.so" to "Android NDK核心库",
        "libjnigraphics.so" to "JNI Bitmap处理库",
        "libcutils.so" to "Android cutils 工具库",
        "libutils.so" to "Android utils 工具库",
        "libart.so" to "Android Runtime (ART)",
        "libcrypto.so" to "OpenSSL 加密库",
        "libssl.so" to "OpenSSL TLS 库",
        "libbinder.so" to "Android Binder IPC",
        "libbase.so" to "Android base 库",
        "libmedia.so" to "Android 媒体库",
        "libOpenSLES.so" to "OpenSL ES 音频库",
        "libvulkan.so" to "Vulkan 图形库",
        "libnativewindow.so" to "ANativeWindow 接口",
        "libcamera2ndk.so" to "Camera2 NDK",
        "libaaudio.so" to "AAudio 音频库",
    )

    fun build(
        elf: ElfFile,
        bytes: ByteArray,
        fileName: String,
        sha256: String,
        size: Long = bytes.size.toLong(),
        functionCountHint: Int = -1,
    ): JSONObject {
        val allSymbols = (elf.symbols + elf.dynSymbols).distinctBy { it.name to it.value to it.imported }
        val imported = elf.dynSymbols.filter { it.imported }
        val exported = elf.dynSymbols.filter { it.exported || (!it.imported && it.value > 0 && it.bind in setOf("GLOBAL", "WEAK")) }
        val namedFunctions = allSymbols.filter { it.type == "FUNC" && !it.imported && it.value > 0 }
        val jniFuncs = exported.filter { it.name.startsWith("Java_") || it.name == "JNI_OnLoad" }
        val strings = elf.strings.map { it.value }
        val needed = neededLibraries(elf, bytes)
        val soname = dynString(elf, bytes, DT_SONAME)
        val baseAddr = elf.programHeaders.firstOrNull { it.type == PT_LOAD }?.vaddr ?: 0L
        val buildId = extractBuildId(elf, bytes)

        val segmentRows = elf.programHeaders.map {
            SegmentRow(it.type, it.flags, max(0L, it.filesz), max(0L, it.memsz))
        }
        val loadable = segmentRows.filter { it.type == PT_LOAD }
        val segmentBasis = if (loadable.isNotEmpty()) loadable else segmentRows.filter { it.filesz > 0 || it.memsz > 0 }
        val segReadable = segmentRows.count { it.flags and PF_R != 0L }
        val segWritable = segmentRows.count { it.flags and PF_W != 0L }
        val segExecutable = segmentRows.count { it.flags and PF_X != 0L }
        val segAllocated = if (loadable.isNotEmpty()) loadable.size else segmentBasis.size
        val classCounts = segmentBasis.groupingBy { classifySegment(it) }.eachCount()
        val classSizes = segmentBasis.groupBy { classifySegment(it) }.mapValues { (_, rows) -> rows.sumOf { it.filesz } }
        val szExec = classSizes["exec"] ?: 0L
        val szRead = classSizes["read"] ?: 0L
        val szWrite = classSizes["write"] ?: 0L
        val szOther = classSizes["other"] ?: 0L
        val szTotal = max(1L, szExec + szRead + szWrite + szOther)
        val hasOriginalSectionHeaders = elf.sections.isNotEmpty() &&
            !elf.sections.all { it.name.startsWith("SEG_") }

        val hasGnuStack = elf.programHeaders.any { it.type == PT_GNU_STACK }
        val stackExec = elf.programHeaders.any { it.type == PT_GNU_STACK && it.flags and PF_X != 0L }
        val nxEnabled = if (hasGnuStack) !stackExec else true
        val flags = dynFirst(elf, DT_FLAGS)
        val flags1 = dynFirst(elf, DT_FLAGS_1)
        val bindNow = (flags and DF_BIND_NOW != 0L) || (flags1 and DF_1_NOW != 0L) || dynHas(elf, DT_BIND_NOW)
        val hasRelro = elf.programHeaders.any { it.type == PT_GNU_RELRO }
        val relroLevel = when {
            hasRelro && bindNow -> "Full RELRO"
            hasRelro -> "Partial RELRO"
            else -> "No RELRO"
        }
        val isPie = elf.type == 3
        val hasCanary = allSymbols.any { it.name.contains("__stack_chk_fail") }
        val hasFortify = allSymbols.any { it.name.endsWith("_chk") }
        val hasCfi = allSymbols.any { it.name.contains("__cfi_check") || it.name.contains("__cfi_slowpath") }
        val hasAntiDebugSym = allSymbols.any { nameMatches(it.name, Regex("ptrace|inotify_add_watch|__android_log_is_debuggable", RegexOption.IGNORE_CASE)) }
        val hasAntiDebugStr = strings.any { nameMatches(it, Regex("/proc/self/status|TracerPid|/proc/self/maps|/proc/%d/wchan|frida|xposed|substrate", RegexOption.IGNORE_CASE)) }
        val hasRootDetect = strings.any { nameMatches(it, Regex("/system/app/Superuser|com\\.topjohnwu\\.magisk|su$|/su\\b|daemonsu|Magisk|SuperSU", RegexOption.IGNORE_CASE)) }
        val hasEmulatorDetect = strings.any { nameMatches(it, Regex("goldfish|generic_x86|vbox86|nox|bluestacks|genymotion|android_x86|qemu\\.sf", RegexOption.IGNORE_CASE)) }
        val hasSslPinning = allSymbols.any { nameMatches(it.name, Regex("ssl_verify|SSL_CTX_set_verify|X509_verify_cert|certificate_verify", RegexOption.IGNORE_CASE)) } ||
            strings.any { nameMatches(it, Regex("pinning|CertificatePinner|ssl_error|TrustManager", RegexOption.IGNORE_CASE)) }
        val hasDynLoad = allSymbols.any { it.name in setOf("dlopen", "dlsym", "dlclose", "android_dlopen_ext") }
        val hasDynRegister = allSymbols.any { it.name == "JNI_OnLoad" } || exported.any { it.name == "JNI_OnLoad" }
        val hasStrEncrypt = strings.count { it.length > 10 && it.matches(Regex("^[A-Za-z0-9+/=]{16,}$")) } > 10
        val entropyHead = calcEntropy(bytes, 0, min(bytes.size, 65536))
        val entropyGlobal = calcGlobalSampleEntropy(bytes)
        val entropyBuckets = calcEntropyBuckets(bytes, 64)
        val hasOllvm = namedFunctions.count { nameMatches(it.name, Regex("\\.cold\\.|__clang_call_terminate|bcf\\.", RegexOption.IGNORE_CASE)) } > 5 || entropyGlobal > 7.2
        val hasInitArray = elf.sections.any { it.name == ".init_array" }
        val isStripped = elf.symbols.isEmpty() || elf.sections.none { it.name == ".symtab" }
        val totallyStripped = elf.symbols.isEmpty() && elf.dynSymbols.isEmpty()
        val hasDwarf = elf.sections.any { it.name.startsWith(".debug") }
        val hasTextRel = dynHas(elf, DT_TEXTREL)
        val totalFuncSymbols = allSymbols.count { it.type == "FUNC" && it.value > 0 }
        val exportedFuncs = exported.count { it.type == "FUNC" }
        val visibility = if (totalFuncSymbols > 0) ((exportedFuncs * 100.0) / totalFuncSymbols).roundToInt() else 0
        val namedVisible = namedFunctions.count { !it.name.startsWith("sub_") }
        val functionCount = if (functionCountHint >= 0) functionCountHint else namedFunctions.size
        val enLv = entropyLevel(entropyGlobal)
        val difficulty = calcDifficulty(
            isStripped = isStripped,
            totallyStripped = totallyStripped,
            hasOllvm = hasOllvm,
            hasStrEncrypt = hasStrEncrypt,
            hasCfi = hasCfi,
            hasAntiDebug = hasAntiDebugSym || hasAntiDebugStr,
            hasRootDetect = hasRootDetect,
            hasSslPinning = hasSslPinning,
            hasDynLoad = hasDynLoad,
            hasDynRegister = hasDynRegister,
            entropyGlobal = entropyGlobal,
            hasDwarf = hasDwarf,
            jniCount = jniFuncs.size,
        )

        val security = JSONArray()
            .put(feature("pie", isPie, if (isPie) "PIE 启用" else "非 PIE (无随机化)", if (isPie) "ok" else "danger",
                "Position Independent Executable：代码位置无关。开启后，操作系统(ASLR)可将模块随机加载到内存任意位置，防止黑客通过固定地址执行ROP攻击。"))
            .put(feature("nx", nxEnabled, if (nxEnabled) "NX (DEP) 启用" else "栈可执行 (高危)", if (nxEnabled) "ok" else "danger",
                "Non-Executable Stack：栈内存不可执行。开启后，防止缓冲区溢出攻击者在堆栈中注入恶意Shellcode并直接执行。"))
            .put(feature("relro", hasRelro, relroLevel, relroTone(relroLevel),
                "Relocation Read-Only：控制全局偏移表(GOT)是否只读。Full 模式下彻底封堵了通过覆写GOT表来实现函数劫持(Hook)的攻击路径。"))
            .put(feature("canary", hasCanary, if (hasCanary) "Canary 栈保护" else "无 Canary", if (hasCanary) "ok" else "danger",
                "Stack Canary：在栈帧返回地址前插入的一个随机“金丝雀”值。若发生栈溢出，该值会被篡改从而触发崩溃，阻断攻击进程。"))
            .put(feature("fortify", hasFortify, if (hasFortify) "FORTIFY_SOURCE" else "无 FORTIFY", if (hasFortify) "ok" else "warn",
                "安全函数替换：编译时自动将高风险的内存/字符串操作(如 strcpy, memcpy)替换为附带边界检查的安全版本(如 __strcpy_chk)。"))
            .put(feature("cfi", hasCfi, if (hasCfi) "CFI 保护" else "未发现 CFI", if (hasCfi) "ok" else "warn",
                "Control Flow Integrity：控制流完整性。在间接调用（如虚函数）之前验证目标地址的合法性，能极大增加逆向修改和漏洞利用的难度。"))
            .put(feature("anti_debug", hasAntiDebugSym || hasAntiDebugStr, if (hasAntiDebugSym || hasAntiDebugStr) "反调试" else "未检测到反调试", if (hasAntiDebugSym || hasAntiDebugStr) "danger" else "ok",
                "Anti-Debug：通过ptrace自绑定、检测TracerPid、扫描/proc/self/maps中Frida/Xposed特征等手段阻止调试器附加和动态分析工具运行。"))
            .put(feature("root", hasRootDetect, if (hasRootDetect) "Root检测" else "未检测Root", if (hasRootDetect) "warn" else "ok",
                "Root Detection：扫描Magisk/SuperSU/su二进制等特征文件，检测设备是否已Root。Root环境下逆向工具权限更高，因此应用会主动对抗。"))
            .put(feature("emulator", hasEmulatorDetect, if (hasEmulatorDetect) "模拟器检测" else "未检测模拟器", if (hasEmulatorDetect) "warn" else "ok",
                "Emulator Detection：检测goldfish/genymotion/nox等模拟器特征硬件标识，阻止在虚拟环境中运行分析。"))
            .put(feature("dyn_load", hasDynLoad, if (hasDynLoad) "动态加载(dlopen)" else "无动态加载", if (hasDynLoad) "warn" else "ok",
                "Dynamic Loading：调用dlopen/dlsym在运行时动态加载其他SO或函数，常用于隐藏关键逻辑、防止静态分析发现真正的功能代码。"))
            .put(feature("ssl_pinning", hasSslPinning, if (hasSslPinning) "SSL Pinning" else "未检测SSL固定", if (hasSslPinning) "warn" else "ok",
                "Certificate Pinning：将服务器TLS证书指纹硬编码到客户端，防止中间人(MITM)抓包。逆向通信协议时需先绕过此保护。"))
            .put(feature("ollvm", hasOllvm, if (hasOllvm) "疑似OLLVM混淆" else "未检测OLLVM", if (hasOllvm) "danger" else "ok",
                "OLLVM / Obfuscation：LLVM级别的指令级混淆（控制流平坦化/虚假控制流/指令替换），编译后的代码极难静态阅读。"))
            .put(feature("str_encrypt", hasStrEncrypt, if (hasStrEncrypt) "疑似字符串加密" else "明文字符串", if (hasStrEncrypt) "danger" else "ok",
                "String Encryption：将日志、URL、密钥等明文字符串在编译时加密，运行时动态解密。导致静态分析无法通过字符串定位关键逻辑。"))
            .put(feature("init_array", hasInitArray, if (hasInitArray) ".init_array 存在" else "无 .init_array", if (hasInitArray) "warn" else "ok",
                "Init Array：动态库加载时最先执行的初始化函数列表。加固壳和反调试逻辑通常隐藏在这里，早于JNI_OnLoad执行。"))
            .put(feature("stripped", isStripped, if (isStripped) "Stripped (已剥离)" else "符号表完整", if (isStripped) "warn" else "ok",
                "Symbol Stripping：编译后移除内部符号表(.symtab)。移除后IDA等工具无法自动识别非导出函数名，增加逆向工作量。"))
            .put(feature("dwarf", hasDwarf, if (hasDwarf) "有DWARF调试" else "无调试信息", if (hasDwarf) "ok" else "warn",
                "DWARF Debug Info：编译器嵌入的完整调试信息（源码文件名、行号、变量名）。发布版本通常会移除，保留则说明是调试版本。"))
            .put(feature("textrel", hasTextRel, if (hasTextRel) "TEXTREL (代码段有写入)" else "无 TEXTREL", if (hasTextRel) "danger" else "ok",
                "Text Relocations：代码段(.text)包含需要运行时修改的重定位。除兼容性问题外，也可能暗示使用了自修改代码(SMC)反逆向技术。"))

        val neededArr = JSONArray()
        needed.forEach { lib ->
            neededArr.put(
                JSONObject()
                    .put("name", lib)
                    .put("description", knownLibs[lib] ?: knownLibs.entries.firstOrNull { lib.startsWith(it.key.removeSuffix(".so")) }?.value ?: "未知自定义或第三方库"),
            )
        }

        val attackSurface = JSONArray()
            .put(attackItem("export", "warn", "导出函数数量", "${exported.size}", "（每个都是潜在Hook点）"))
            .put(attackItem("jni", if (jniFuncs.isNotEmpty()) "danger" else "ok", "JNI 函数入口", "${jniFuncs.size}", "（Java层调用Native的桥梁）"))
            .put(attackItem("import", "warn", "导入函数数量", "${imported.size}", "（可Hook拦截外部调用行为）"))
            .put(attackItem("visibility", if (visibility >= 40) "ok" else if (visibility >= 15) "warn" else "danger", "符号可见比例", "$visibility%", "（越高越容易通过名称定位功能）"))
            .put(attackItem("named", if (namedVisible > 0) "ok" else "warn", "可直接定位的命名函数", "$namedVisible", ""))
            .put(attackItem("strings", if (strings.size > 50) "ok" else "warn", "明文字符串数量", "${strings.size}", "（逆向分析最重要的线索来源）"))
        if (hasDynRegister) {
            attackSurface.put(attackItem("dyn_reg", "danger", "⚠ JNI_OnLoad 动态注册", "", "无法通过导出表直接找到Java方法对应的Native实现，需动态Hook跟踪"))
        }
        if (hasInitArray) {
            attackSurface.put(attackItem("init_array", "danger", "⚠ .init_array 存在", "", "库加载时会先执行这些初始化函数，可能包含反调试/脱壳逻辑"))
        }
        if (hasDynLoad) {
            attackSurface.put(attackItem("dlopen", "warn", "动态加载", "dlopen/dlsym", "运行时再加载代码路径，静态调用图可能不完整"))
        }

        return JSONObject()
            .put("fileName", fileName)
            .put("size", size)
            .put("elfType", eTypeName(elf.type))
            .put("elfTypeCode", elf.type)
            .put("architecture", machineDisplay(elf))
            .put("architectureCode", elf.architecture)
            .put("machine", elf.machineName)
            .put("bits", elf.bits)
            .put("endian", if (elf.littleEndian) "Little Endian (小端)" else "Big Endian (大端)")
            .put("endianCode", elf.endian)
            .put("entryPoint", hex(elf.entry))
            .put("baseAddr", hex(baseAddr))
            .put("sha256", sha256)
            .put("buildId", buildId)
            .put("soname", soname)
            .put("stripped", isStripped)
            .put("totallyStripped", totallyStripped)
            .put("hasDebugInfo", hasDwarf)
            .put("hasJniOnLoad", hasDynRegister)
            .put("sectionCount", elf.sections.size)
            .put("segmentCount", elf.programHeaders.size)
            .put("hasOriginalSectionHeaders", hasOriginalSectionHeaders)
            .put("segmentClass", JSONObject()
                .put("execCount", classCounts["exec"] ?: 0)
                .put("readCount", classCounts["read"] ?: 0)
                .put("writeCount", classCounts["write"] ?: 0)
                .put("otherCount", classCounts["other"] ?: 0)
                .put("execSize", szExec)
                .put("readSize", szRead)
                .put("writeSize", szWrite)
                .put("otherSize", szOther)
                .put("totalSize", szTotal)
                .put("execPct", pct(szExec, szTotal))
                .put("readPct", pct(szRead, szTotal))
                .put("writePct", pct(szWrite, szTotal))
                .put("otherPct", pct(szOther, szTotal)))
            .put("segmentPermissions", JSONObject()
                .put("loadable", segAllocated)
                .put("readable", segReadable)
                .put("writable", segWritable)
                .put("executable", segExecutable))
            .put("functionCount", functionCount)
            .put("stringCount", strings.size)
            .put("importCount", imported.size)
            .put("exportCount", exported.size)
            .put("neededCount", needed.size)
            .put("symbolCount", elf.symbols.size)
            .put("dynsymCount", elf.dynSymbols.size)
            .put("securityFeatures", security)
            .put("difficulty", difficulty)
            .put("attackSurface", attackSurface)
            .put("entropy", JSONObject()
                .put("head64k", entropyHead)
                .put("globalSample", entropyGlobal)
                .put("level", enLv.optString("txt"))
                .put("levelClass", enLv.optString("cls"))
                .put("buckets", JSONArray(entropyBuckets)))
            .put("neededLibraries", neededArr)
            .put("visibilityPct", visibility)
            .put("namedFunctionCount", namedVisible)
            .put("jniCount", jniFuncs.size)
            .put("flags", JSONObject()
                .put("pie", isPie)
                .put("nx", nxEnabled)
                .put("relro", relroLevel)
                .put("canary", hasCanary)
                .put("fortify", hasFortify)
                .put("cfi", hasCfi)
                .put("antiDebug", hasAntiDebugSym || hasAntiDebugStr)
                .put("rootDetect", hasRootDetect)
                .put("emulatorDetect", hasEmulatorDetect)
                .put("dynLoad", hasDynLoad)
                .put("sslPinning", hasSslPinning)
                .put("ollvm", hasOllvm)
                .put("strEncrypt", hasStrEncrypt)
                .put("initArray", hasInitArray)
                .put("textRel", hasTextRel)
                .put("dwarf", hasDwarf))
    }

    private data class SegmentRow(val type: Long, val flags: Long, val filesz: Long, val memsz: Long)

    private fun classifySegment(seg: SegmentRow): String = when {
        seg.flags and PF_X != 0L -> "exec"
        seg.flags and PF_W != 0L -> "write"
        seg.flags and PF_R != 0L -> "read"
        else -> "other"
    }

    private fun neededLibraries(elf: ElfFile, bytes: ByteArray): List<String> {
        val dynstr = elf.sections.firstOrNull { it.name == ".dynstr" } ?: return emptyList()
        return elf.dynamicEntries.asSequence()
            .filter { it.tag == DT_NEEDED }
            .mapNotNull { entry -> readDynstr(bytes, dynstr, entry.value) }
            .distinct()
            .toList()
    }

    private fun dynString(elf: ElfFile, bytes: ByteArray, tag: Long): String {
        val dynstr = elf.sections.firstOrNull { it.name == ".dynstr" } ?: return ""
        val entry = elf.dynamicEntries.firstOrNull { it.tag == tag } ?: return ""
        return readDynstr(bytes, dynstr, entry.value).orEmpty()
    }

    private fun readDynstr(bytes: ByteArray, dynstr: SectionInfo, value: Long): String? {
        val start = (dynstr.offset + value).toInt()
        if (start !in bytes.indices) return null
        var end = start
        while (end < bytes.size && bytes[end].toInt() != 0) end++
        return bytes.copyOfRange(start, end).toString(Charsets.UTF_8).takeIf { it.isNotBlank() }
    }

    private fun dynFirst(elf: ElfFile, tag: Long): Long =
        elf.dynamicEntries.firstOrNull { it.tag == tag }?.value ?: 0L

    private fun dynHas(elf: ElfFile, tag: Long): Boolean =
        elf.dynamicEntries.any { it.tag == tag }

    private fun extractBuildId(elf: ElfFile, bytes: ByteArray): String {
        val note = elf.sections.firstOrNull { it.name == ".note.gnu.build-id" } ?: return ""
        val start = note.offset.toInt().coerceIn(0, bytes.size)
        val end = min(bytes.size, start + note.size.toInt().coerceAtLeast(0))
        if (end - start < 16) return ""
        // Skip note header (namesz, descsz, type) + name ("GNU\0") when possible.
        var off = start + 16
        if (off >= end) off = start
        val hex = StringBuilder()
        for (i in off until end) {
            hex.append("%02x".format(bytes[i].toInt() and 0xff))
            if (hex.length >= 40) break
        }
        return hex.toString()
    }

    private fun calcEntropy(bytes: ByteArray, offset: Int, length: Int): Double {
        if (length <= 0 || offset !in bytes.indices) return 0.0
        val end = min(bytes.size, offset + length)
        val n = end - offset
        if (n <= 0) return 0.0
        val cnt = IntArray(256)
        for (i in offset until end) cnt[bytes[i].toInt() and 0xff]++
        var e = 0.0
        val invLn2 = 1.0 / ln(2.0)
        for (c in cnt) {
            if (c == 0) continue
            val p = c.toDouble() / n
            e -= p * ln(p) * invLn2
        }
        return e
    }

    private fun calcGlobalSampleEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val sampleN = min(131072, bytes.size)
        val sample = ByteArray(sampleN)
        val step = bytes.size.toDouble() / sampleN
        for (i in 0 until sampleN) {
            sample[i] = bytes[min(bytes.size - 1, (i * step).toInt())]
        }
        return calcEntropy(sample, 0, sampleN)
    }

    private fun calcEntropyBuckets(bytes: ByteArray, bucketCount: Int): List<Double> {
        if (bytes.isEmpty() || bucketCount <= 0) return emptyList()
        val out = ArrayList<Double>(bucketCount)
        val bucketSize = max(1, (bytes.size + bucketCount - 1) / bucketCount)
        for (i in 0 until bucketCount) {
            val start = i * bucketSize
            if (start >= bytes.size) {
                out += 0.0
            } else {
                out += calcEntropy(bytes, start, min(bucketSize, bytes.size - start))
            }
        }
        return out
    }

    private fun entropyLevel(e: Double): JSONObject = when {
        e < 5.2 -> JSONObject().put("cls", "ok").put("txt", "低（常规代码/数据）")
        e < 7.0 -> JSONObject().put("cls", "warn").put("txt", "中（一般二进制文件）")
        e < 7.6 -> JSONObject().put("cls", "warn").put("txt", "偏高（可能压缩或混淆）")
        else -> JSONObject().put("cls", "danger").put("txt", "高（加壳/加密/强混淆）")
    }

    private fun calcDifficulty(
        isStripped: Boolean,
        totallyStripped: Boolean,
        hasOllvm: Boolean,
        hasStrEncrypt: Boolean,
        hasCfi: Boolean,
        hasAntiDebug: Boolean,
        hasRootDetect: Boolean,
        hasSslPinning: Boolean,
        hasDynLoad: Boolean,
        hasDynRegister: Boolean,
        entropyGlobal: Double,
        hasDwarf: Boolean,
        jniCount: Int,
    ): JSONObject {
        var score = 0.0
        val factors = JSONArray()
        if (isStripped) {
            score += 2
            factors.put(factorItem("stripped", 2.0, "danger", "符号表被剥离 (Stripped)", "内部 .symtab 缺失或为空，未导出函数失去原始名称，静态定位成本显著上升"))
        }
        if (totallyStripped) {
            score += 1
            factors.put(factorItem("totally_stripped", 1.0, "danger", "几乎无可用符号", "连 dynsym 也稀少/缺失，函数边界与名称高度依赖反汇编与启发式恢复"))
        }
        if (hasOllvm) {
            score += 3
            factors.put(factorItem("ollvm", 3.0, "danger", "疑似 OLLVM / 强混淆", "控制流平坦化或高熵代码特征会显著增加阅读与还原成本"))
        }
        if (hasStrEncrypt) {
            score += 2
            factors.put(factorItem("str_encrypt", 2.0, "danger", "疑似字符串加密", "大量高熵/类 Base64 数据会削弱字符串交叉引用这条最常用线索"))
        }
        if (hasCfi) {
            score += 1
            factors.put(factorItem("cfi", 1.0, "warn", "CFI 控制流完整性", "间接调用校验会提高补丁与 Hook 的失败率，需要更精细的绕过"))
        }
        if (hasAntiDebug) {
            score += 1
            factors.put(factorItem("anti_debug", 1.0, "danger", "反调试机制", "ptrace / TracerPid / Frida 特征扫描等会阻断常规动态分析流程"))
        }
        if (hasRootDetect) {
            score += 0.5
            factors.put(factorItem("root", 0.5, "warn", "Root / Magisk 检测", "可能在 Root 环境下主动降级或退出，影响 Frida/Xposed 方案"))
        }
        if (hasSslPinning) {
            score += 0.5
            factors.put(factorItem("ssl_pinning", 0.5, "warn", "SSL Pinning", "抓包与协议还原前通常需要先绕过证书固定"))
        }
        if (hasDynLoad && hasDynRegister) {
            score += 1
            factors.put(factorItem("dyn_reg", 1.0, "danger", "动态加载+动态注册JNI", ""))
        }
        if (entropyGlobal > 7.5) {
            score += 2
            factors.put(factorItem("entropy_high", 2.0, "danger", "超高熵值", "全局抽样熵 ${"%.2f".format(entropyGlobal)}，更像加壳、加密资源或强混淆产物"))
        } else if (entropyGlobal > 7.0) {
            score += 1
            factors.put(factorItem("entropy_mid", 1.0, "warn", "偏高熵值", "全局抽样熵 ${"%.2f".format(entropyGlobal)}，可能存在压缩段、混淆或加密数据"))
        }
        if (!hasDwarf && isStripped) {
            score += 0.5
            factors.put(factorItem("no_dwarf", 0.5, "warn", "无调试信息", "缺少 DWARF 行号/变量名，源级还原几乎不可用"))
        }
        score = min(10.0, score)
        val (level, cls) = when {
            score >= 7 -> "极难" to "danger"
            score >= 5 -> "困难" to "danger"
            score >= 3 -> "中等" to "warn"
            score >= 1 -> "较易" to "ok"
            else -> "简单" to "ok"
        }
        val summary = when (cls) {
            "danger" -> "该样本具备多项加固/混淆特征，纯静态阅读成本高，建议静态定位入口 + 动态验证并行推进。"
            "warn" -> "存在一定保护或线索缺失，但仍有可用入口；优先从导出/JNI/字符串与初始化路径切入。"
            else -> "保护强度相对较低，可优先利用符号、导出与字符串快速建立功能地图。"
        }
        val recommend = JSONArray()
            .put("• 使用 IDA Pro / Ghidra 进行静态分析")
        if (hasDynRegister) recommend.put("• 使用 Frida hook JNI_OnLoad 跟踪动态注册函数映射")
        if (hasAntiDebug) recommend.put("• 使用 Frida 绕过反调试(patch ptrace/TracerPid)")
        if (hasOllvm) recommend.put("• 使用 D-810/Obpo 等IDA插件去除OLLVM混淆")
        if (hasStrEncrypt) recommend.put("• 使用 Frida 动态dump解密后的字符串")
        if (hasSslPinning) recommend.put("• 使用 objection/Frida 绕过SSL Pinning")
        if (hasRootDetect) recommend.put("• 使用 Magisk Zygisk 模块隐藏Root")
        if (entropyGlobal > 7.5) recommend.put("• 使用 UniDbg/Unidbg 模拟执行脱壳")
        if (!isStripped) recommend.put("• 符号表完整，可直接定位关键函数")
        if (jniCount > 0) recommend.put("• 发现 ${jniCount} 个JNI导出函数，是分析入口点")
        recommend.put("• 使用 Frida/Xposed 进行动态Hook分析")
        return JSONObject()
            .put("score", "%.1f".format(score))
            .put("scoreValue", score)
            .put("level", level)
            .put("cls", cls)
            .put("summary", summary)
            .put("factors", factors)
            .put("recommend", recommend)
            .put("scoreGuide", "评分范围 0–10：<1 简单，1–3 较易，3–5 中等，5–7 困难，≥7 极难。分值由符号剥离、混淆、反调试、熵值、动态注册等加权累加。")
    }

    private fun feature(id: String, active: Boolean, label: String, tone: String, description: String): JSONObject =
        JSONObject()
            .put("id", id)
            .put("active", active)
            .put("label", label)
            .put("tone", tone)
            .put("description", description)

    private fun factorItem(id: String, weight: Double, tone: String, title: String, detail: String): JSONObject =
        JSONObject()
            .put("id", id)
            .put("weight", weight)
            .put("tone", tone)
            .put("title", title)
            .put("detail", detail)
            .put("text", title)

    private fun recommendItem(id: String, tone: String, title: String, detail: String): JSONObject =
        JSONObject()
            .put("id", id)
            .put("tone", tone)
            .put("title", title)
            .put("detail", detail)
            .put("text", "• $title：$detail")

    private fun attackItem(id: String, tone: String, title: String, value: String, detail: String): JSONObject =
        JSONObject()
            .put("id", id)
            .put("tone", tone)
            .put("title", title)
            .put("value", value)
            .put("detail", detail)
            .put("text", if (value.isBlank()) "$title：$detail" else "$title：$value$detail")

    private fun relroTone(level: String): String {
        val r = level.lowercase()
        return when {
            "full" in r -> "ok"
            "partial" in r -> "warn"
            else -> "danger"
        }
    }

    private fun eTypeName(t: Int): String = when (t) {
        1 -> "REL (可重定位目标文件)"
        2 -> "EXEC (可执行文件)"
        3 -> "DYN (共享对象库/PIE)"
        4 -> "CORE (核心转储)"
        else -> "Unknown($t)"
    }

    private fun machineDisplay(elf: ElfFile): String = when (elf.machine) {
        0x02 -> "SPARC"
        0x03 -> "x86 (i386)"
        0x08 -> "MIPS"
        0x14 -> "PowerPC"
        0x28 -> "ARM"
        0x2A -> "SuperH"
        0x32 -> "IA-64"
        0x3E -> "x86_64 (AMD64)"
        0xB7 -> "AArch64 (ARM64)"
        0xF3 -> "RISC-V"
        else -> elf.machineName
    }

    private fun pct(value: Long, total: Long): Double =
        if (total > 0) (value * 1000.0 / total).roundToInt() / 10.0 else 0.0

    private fun hex(v: Long): String = "0x${v.toString(16)}"

    private fun nameMatches(value: String, regex: Regex): Boolean = regex.containsMatchIn(value)
}
