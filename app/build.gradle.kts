/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 */

import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val releaseKeystoreProperties = Properties().apply {
    val file = rootProject.file("release/keystore.properties")
    if (file.isFile) file.inputStream().use(::load)
}

// Distribution channel, reported as the `app_channel` field by LogReporter.
// Defaults to "github" for release builds and "dev" for debug builds; a
// re-packaged channel build can override it with -PappChannel=<value> or the
// APP_CHANNEL environment variable. Values are filtered to [A-Za-z0-9._-] so a
// malformed override cannot break the generated string literal.
val appChannelOverride = ((findProperty("appChannel") as String?) ?: System.getenv("APP_CHANNEL"))
    ?.trim()
    ?.filter { it.isLetterOrDigit() || it == '.' || it == '_' || it == '-' }
    ?.takeIf { it.isNotEmpty() }

android {
    namespace = "com.soreverse.mcp"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "com.soreverse.mcp"
        minSdk = 26
        targetSdk = 36
        versionCode = 24
        versionName = "1.0.23"

        externalNativeBuild {
            cmake {
                cppFlags += listOf(
                    "-std=c++17", "-fexceptions", "-frtti",
                    // Additional compile-time checks
                    "-Wall", "-Wextra"
                )
                // c++_static keeps every self-built .so (rz_native /
                // xanso_native / blutter_bridge) self-contained: the hardened
                // (VMP/Dex2C) repack may drop libc++_shared.so from lib/, and a
                // c++_shared-linked librz_native.so then fails dlopen with
                // "cannot locate symbol _ZTVNSt6__ndk1..." and kills startup.
                arguments += listOf("-DANDROID_STL=c++_static")
                // Rizin source tree location. Optional: defaults to the repo's
                // third_party/rizin-src (see CMakeLists.txt); set RIZIN_SRC to
                // point at an existing checkout when it lives elsewhere.
                // 过滤 ';' / '"' / 空格：防止注入额外 CMake 缓存变量。
                System.getenv("RIZIN_SRC")?.takeIf {
                    it.isNotBlank() && it.none { c -> c == ';' || c == '"' || c == ' ' }
                }?.let {
                    arguments += listOf("-DRIZIN_SRC=$it")
                }
            }
        }

        // Key and encoded arrays are generated at build time by generate_header.py
        // from the TM GitHub Actions secret (CI only). There is no local fallback.
        // Build requires: $env:TM = '<16-hex-chars>'
    }

    buildFeatures {
        aidl = true
        compose = true
        buildConfig = true
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            isUniversalApk = true
        }
    }

    lint {
        // Static analysis is run explicitly (e.g. `lintDebug` / `lintRelease`)
        // in CI and locally, with a baseline capturing pre-existing findings so
        // only new regressions surface. `checkReleaseBuilds` is kept off so the
        // release *packaging* path is not gated by lint-vital (which aborts on
        // baseline creation and couples assembly to analysis); lint remains a
        // first-class, non-optional step of its own.
        checkReleaseBuilds = false
        abortOnError = false
        baseline = file("lint-baseline.xml")
    }

    signingConfigs {
        create("release") {
            // Prefer CI-provided secrets via environment variables; fall back to
            // a local release/keystore.properties for local development only.
            storeFile =
                rootProject.file(
                    System.getenv("STORE_FILE")
                        ?: releaseKeystoreProperties.getProperty(
                            "storeFile",
                            "release/so-reverse-mcp-release.jks"
                        )
                )
            storePassword = System.getenv("STORE_PASSWORD")
                ?: releaseKeystoreProperties.getProperty("storePassword", "")
            keyAlias = System.getenv("KEY_ALIAS")
                ?: releaseKeystoreProperties.getProperty("keyAlias", "")
            keyPassword = System.getenv("KEY_PASSWORD")
                ?: releaseKeystoreProperties.getProperty("keyPassword", "")
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    }

    buildTypes {
        debug {
            isJniDebuggable = true
            buildConfigField("String", "APP_CHANNEL", "\"${appChannelOverride ?: "dev"}\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            isJniDebuggable = false
            signingConfig = signingConfigs.getByName("release")
            buildConfigField("String", "APP_CHANNEL", "\"${appChannelOverride ?: "github"}\"")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // Unidbg's Android backend depends on three native libs that are NOT
    // shipped by the unidbg Maven artifacts for Android (capstone/keystone/
    // unicorn inside the jars are linux_64 / linux_aarch64 only). They must
    // be cross-compiled from the in-repo submodules and dropped into
    // src/main/jniLibs/<abi>/. Make that the default, "normal" packaging path
    // so the APK always bundles them (build-unidbg-native.ps1 does the work).
    packaging {
        jniLibs {
            useLegacyPackaging = true
            // JNA 5.10 still ships libjnidispatch.so for the long-dead armeabi /
            // mips / mips64 ABIs. The ABI splits filter them out via
            // splits.abi.include, but the universal APK packaged all three dead
            // directories - and the release Dex2C hardening step derives APP_ABI
            // from the APK itself, so NDK 29 aborted with "The armeabi ABI is no
            // longer supported" (dcc's copy_compiled_libs has no fallback for
            // mips/mips64 either). Nothing running this app is on those ABIs;
            // drop the dead libs from every APK.
            excludes += setOf("lib/armeabi/**", "lib/mips/**", "lib/mips64/**")
        }
        resources {
            excludes += setOf(
                "DebugProbesKt.bin",
                "cc.c",
                "r_styles.ini",
                "r_values.ini",
                "win32-x86/**",
                "win32-x86-64/**",
                "darwin/**",
                "natives/osx_*/**",
                "natives/windows_*/**",
                "com/sun/jna/aix-*/**",
                "com/sun/jna/darwin-*/**",
                "com/sun/jna/win32-*/**"
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Unidbg native libraries: capstone / keystone / unicorn
// ---------------------------------------------------------------------------
// Unidbg's Android backend (com.github.zhkl0228:unidbg-android) loads
// System.loadLibrary("capstone"|"keystone"|"unicorn"|"jnidispatch"). The first
// three are NOT present in the unidbg Maven artifacts for Android and must be
// cross-compiled from third_party/* submodules into src/main/jniLibs/<abi>/.
// libjnidispatch.so is supplied automatically by the JNA AAR
// (net.java.dev.jna:jna) and needs no action.
//
// Wire the cross-compile into the build so the libs are bundled "normally"
// instead of relying on a manual, easily-forgotten build-unidbg-native.ps1 /
// build-unidbg-native.sh invocation. The task is non-fatal: if NDK / submodules
// / ninja are missing it logs a warning and the APK still builds (Unidbg then
// falls back to EMULATOR_UNAVAILABLE, i.e. today's behaviour). On a properly
// provisioned build machine the libs are produced automatically for every ABI
// split, on Windows via the .ps1 and on Linux/macOS via the .sh.
// ---------------------------------------------------------------------------
// Configuration-cache compatible task: injects ExecOperations instead of
// touching `project` at execution time, and declares every input as a
// serializable Property so the CC can store the task graph.
abstract class UnidbgNativeBuildTask : DefaultTask() {
    @get:Inject
    abstract val execOperations: ExecOperations

    @get:InputFiles
    abstract val nativeScript: Property<File>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val nativeLibs: ListProperty<String>

    @get:Input
    abstract val hostIsWindows: Property<Boolean>

    @get:Internal
    abstract val jniLibsRoot: Property<File>

    @TaskAction
    fun build() {
        val script = nativeScript.get()
        if (!script.exists()) {
            logger.warn("${script.name} not found at ${script.path}; skipping Unidbg native build")
            return
        }
        val libs = nativeLibs.get()
        val haveAll = abis.get().all { abi ->
            val dir = jniLibsRoot.get().resolve(abi)
            // unicorn (QEMU, __uint128_t) only compiles for the 64-bit ABIs;
            // the 32-bit ABIs get capstone/keystone only (Unidbg degrades
            // gracefully there but the APKs still build).
            val required = if (abi == "arm64-v8a" || abi == "x86_64") libs else libs - "unicorn"
            dir.isDirectory && required.all { lib ->
                val artifact = dir.resolve("lib$lib.so")
                // libunicorn.so must be unidbg's unicorn2 JNI bridge, which
                // links the whole emulation engine and therefore weighs
                // megabytes. The engine-only library shipped before the fix
                // was ~54 KB and could never serve the backend, so treat a
                // tiny one as stale and rebuild instead of reusing it
                // (issue #91).
                artifact.exists() && (lib != "unicorn" || artifact.length() > 1L * 1024 * 1024)
            }
        }
        if (haveAll) {
            logger.lifecycle("[unidbg-native] libs already present in jniLibs; skipping build")
            return
        }
        try {
            abis.get().forEach { abi ->
                logger.lifecycle("[unidbg-native] building native libs for $abi ...")
                execOperations.exec {
                    if (hostIsWindows.get()) {
                        commandLine(
                            "powershell", "-ExecutionPolicy", "Bypass",
                            "-File", script.path, "-Abi", abi
                        )
                    } else {
                        commandLine("bash", script.path, "--abi", abi)
                    }
                }
            }
            logger.lifecycle("[unidbg-native] DONE - capstone/keystone/unicorn copied into jniLibs; they will be packaged into the APK")
        } catch (e: Exception) {
            logger.warn(
                "Unidbg native build failed (${e.message}); this usually means the Android NDK, " +
                    "ninja, or the third_party/* submodules are missing. The APK will be built " +
                    "WITHOUT these libs and Unidbg will report EMULATOR_UNAVAILABLE. " +
                    "Run 'git submodule update --init --recursive', install NDK 29 + ninja " +
                        "(and chmod +x build-unidbg-native.sh on Linux/macOS), then rebuild."
            )
        }
    }
}

val unidbgAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
val unidbgNativeLibs = listOf("capstone", "keystone", "unicorn")
val nativeBuildOnWindows = System.getProperty("os.name").lowercase().contains("windows")
val unidbgNativeScript = rootProject.file(
    if (nativeBuildOnWindows) "build-unidbg-native.ps1" else "build-unidbg-native.sh"
)

val buildUnidbgNative = tasks.register<UnidbgNativeBuildTask>("buildUnidbgNative") {
    group = "native"
    description = "Cross-compile capstone/keystone/unicorn into app/src/main/jniLibs (Unidbg backend)."
    nativeScript.set(unidbgNativeScript)
    abis.set(unidbgAbis)
    nativeLibs.set(unidbgNativeLibs)
    hostIsWindows.set(nativeBuildOnWindows)
    jniLibsRoot.set(file("src/main/jniLibs"))
}

// Populate jniLibs before compiling/packaging so the libs land in every APK.
tasks.named("preBuild") { dependsOn(buildUnidbgNative) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("io.ktor:ktor-server-core-jvm:3.5.1")
    implementation("io.ktor:ktor-server-cio-jvm:3.5.1")
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("com.squareup.okhttp3:okhttp-sse:5.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("com.github.rikkahub:markdown:d79a97cc8e")
    implementation("org.jsoup:jsoup:1.22.2")
    // patched jar 只用于 unidbg-api / unidbg-android / capstone / keystone 四个坐标：
    // 它们的上游 artifact 会被 unidbg-unicorn2 当传递依赖带进来，与 files() 的
    // patched jar 在 classpath 上撞成重复类，所以上游坐标一律排掉（见文件末尾
    // configurations.configureEach）。
    //
    // 两个 -patched.jar 与上游的差别只有两个类，且都是 Android 上必需的：
    //   * unidbg-api  AbstractEmulator: ManagementFactory.getRuntimeMXBean().getName()
    //     取 pid → 改成反射调 android.os.Process.myPid()（Android 上 rt.jar 的管理
    //     MBean 不可用，留着会在 emulator 构造时就抛异常）；
    //   * unidbg-android BaseVM.printMemoryInfo(): MemoryMXBean → Runtime 内存数。
    // 因此不能直接换成上游坐标，只能把「上游坐标」从依赖图里排掉。
    implementation(files("libs/unidbg-api-0.9.9-android-patched.jar"))
    implementation(files("libs/unidbg-android-0.9.9-android-patched.jar"))
    implementation(files("libs/capstone-3.1.8-android-patched.jar"))
    implementation(files("libs/keystone-0.9.7-android-patched.jar"))
    implementation("net.java.dev.jna:jna:5.10.0@aar")
    implementation("commons-codec:commons-codec:1.21.0")
    implementation("org.apache.commons:commons-collections4:4.5.0")
    implementation("commons-io:commons-io:2.21.0")
    implementation("com.alibaba:fastjson:1.2.83")
    implementation("com.github.zhkl0228:demumble:1.0.4")
    implementation("net.dongliu:apk-parser:2.6.10")
    // unidbg-* 上游坐标的排除写在文件末尾的 configurations.configureEach，
    // 这里刻意不写 exclude：依赖块里的 exclude 只作用于本依赖这一条传递路径，
    // 漏一条上游坐标就又会撞成重复类。
    //
    // 写成 module(...) 而不是裸字符串：同一段依赖声明，字符串形式在「配置上后设的
    // exclude」面前不保证被排除，而 module() 是已解析好的依赖对象，行为确定。
    // 真正不看时序的判据是文件末尾的 withDependencies。
    implementation(module("com.github.zhkl0228:unidbg-unicorn2:0.9.9"))
    // unicorn2 后端（Unicorn2Backend → 反射注册的 Unicorn2Factory）来自上面这个
    // 坐标，两个 patched jar 里都没有它 —— 删掉这条，应用再也注册不到后端工厂，
    // 只剩 BackendFactory.createBackend 兜底的 UnicornBackend。
    // patched unidbg-api 仍带着 BackendFactory + UnicornBackend，字节码引用
    // unicorn.Unicorn / UnicornConst / UnicornException（Unicorn2Backend 也一样），
    // 这些类来自 com.github.zhkl0228:unicorn，它本是 unidbg-api 的传递依赖，排掉
    // unidbg-api 后就没来源了。缺了它 UnicornBackend 会以
    // ClassNotFoundException: unicorn_Unicorn 死在 session_open。
    // 全局 exclude 只排 unidbg-api / unidbg-android / capstone / keystone 四个坐标，
    // 不碰 unicorn，所以这条必须留着 —— 它是 unicorn.* 唯一的来源。
    implementation("com.github.zhkl0228:unicorn:1.0.15")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")

    // Argon2 key derivation for encrypted backup/restore
    implementation("com.lambdapioneer.argon2kt:argon2kt:1.6.0")
}

// upstream unidbg-* 必须从**整个依赖图**里排掉。
//
// 这些 jar 的 patched 版本走 files()（libs/*-patched.jar），maven 没有对应的
// 坐标，所以只能把上游坐标排干净：com.github.zhkl0228:unidbg-unicorn2:0.9.9 会把
// unidbg-api / unidbg-android 当传递依赖带进来，同一批 com.github.unidbg.* 类出现两次
// （unicorn2 本身要留着，它提供 Unicorn2Factory / Unicorn2Backend 这两个工厂类）：
//   > Task :app:checkDebugDuplicateClasses FAILED
//     Duplicate class com.github.unidbg.AbstractEmulator found in modules
//       unidbg-api-0.9.9-android-patched.jar and unidbg-api-0.9.9.jar
//   > Task :app:mergeDebugJavaResource FAILED
//     2 files found with path 'android/sdk23/system/usr/share/zoneinfo/.../tzdata'
//
// 写在 configuration 上而不是某个依赖块里：同一坐标可能有多条传递路径，
// 逐块写 exclude 只能挡住自己那一条，漏掉的那条照样把重复类带回来。
//
// 但这段代码前两版都没生效，报错一模一样（332 条 Duplicate class 加 tzdata 同名
// 文件）：exclude 是在 dependencies {} **之后**才设到配置上的，而此时依赖已经解析
// 成 Dependency 对象，是否吃到这条 exclude 取决于它是以什么形式绑上去的 ——
// 写在 dependencies 里的字符串依赖不吃，所以上面那条 unidbg-unicorn2 改成了
// module(...)。真正不看时序的判据是下面那段 withDependencies。
configurations.configureEach {
    exclude(group = "com.github.zhkl0228", module = "unidbg-android")
    exclude(group = "com.github.zhkl0228", module = "unidbg-api")
    exclude(group = "com.github.zhkl0228", module = "capstone")
    exclude(group = "com.github.zhkl0228", module = "keystone")
}

// 真正不看时序的判据：在依赖解析那一刻直接删掉上游坐标，与 exclude 何时设置、
// 依赖以什么顺序加入都无关。
// unidbg-api / unidbg-android 的上游 POM 还会把 capstone 3.1.8 / keystone 0.9.7 /
// unicorn 1.0.15 / demumble 1.0.4 带进来（capstone / keystone 的 patched jar 走
// files()，unicorn 同时是 unicorn2 后端的 JNI 类来源，两条都已有显式声明），
// 所以四个模块一起删。
val upstreamUnidbgModules = listOf("unidbg-api", "unidbg-android", "capstone", "keystone")
configurations.configureEach {
    withDependencies {
        removeAll { it.group == "com.github.zhkl0228" && it.name in upstreamUnidbgModules }
    }
}
