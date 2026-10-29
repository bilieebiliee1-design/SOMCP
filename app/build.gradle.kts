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
    // 把 app/libs/*-patched.jar 按「上游坐标 + 高版本号」发布进本地 Maven 仓库（buildSrc）。
    id("somcp.patched-local-jars")
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
    namespace = rootProject.extra["somcpNamespace"] as String
    compileSdk = rootProject.extra["somcpCompileSdk"] as Int
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "com.soreverse.mcp"
        minSdk = rootProject.extra["somcpMinSdk"] as Int
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
                // unidbg-android 的上游 jar 与 patched jar 各带一份同样的 tzdata，
                // :app:mergeDebugJavaResource 以
                //   「2 files found with path 'android/sdk23/system/usr/share/zoneinfo/tzdata'」
                // 直接失败。两份内容一致（patched jar 只改过 Java 类），排掉不影响产物。
                // 与 class 重复是两回事：上面那些 exclude 管的是依赖图，这一条管的是
                // java 资源合并，依赖排干净了它在某些路径上仍可能被合并器看见。
                "android/sdk23/system/usr/share/zoneinfo/tzdata",
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


// buildSrc 的 somcp.patched-local-jars 把工厂挂在 project.ext 上（见该文件的注释）。
// Kotlin DSL 访问 ext 属性必须走 extraProperties，所以这里包一层。
val patchedJar: (String, String) -> Any = { fileName: String, coordinates: String ->
    (extensions.extraProperties.properties["patchedLocalJarDependency"] as groovy.lang.Closure<*>)
        .call(fileName, coordinates)
}

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
    // 这四个是上游同名模块的重打包版本，由 buildSrc 的 somcp.patched-local-jars
    // 在文件依赖**被声明的那一刻**换成「上游坐标 + 高版本号」（`x.y.z.1`）：
    // file 依赖不进图，上游那份就算经 unidbg-api 的 POM 传递依赖进来，冲突解析
    // 也只会留下高版本那份，于是 checkDebugDuplicateClasses /
    // mergeDebugJavaResource 不再报同名 class。坐标依赖的 jar 与 POM 由插件写进
    // `app/libs/build/patched-jars-repo`，也就是 `settings.gradle.kts` 里
    // `somcpPatchedLocal` 那个仓库的 url（两边必须是同一个绝对路径）。刻意不开在
    // `build/` 下：buildDir 中途被清空会让 `.1` 变成「找不到依赖」，见插件里
    // somcpPatchedRepo 那一段。
    // 这里的坐标必须与 buildSrc 那张口径表逐字相同（表是唯一真源，对不上会直接
    // 在配置期报错）。
    //
    // **文件路径要在声明时就存在**：Gradle 在 `places files()` 那一刻就把它们记成
    // 任务的输入，路径不存在会当场抛
    //   Cannot fingerprint input property '...': file .../libs/xxx.jar does not exist,
    // 而且是在所有被声明的地方一起抛 —— 一行写错，报错会落到别的依赖上。
    // 那四个 jar 是随仓库提交的实体文件，`app/libs/` 会跟着 checkout 一起在场，
    // 所以这条约束对它们天然成立；本地仓库那个目录不需要占位文件（`build/` 是构建
    // 产物目录，插件在建依赖之前先 mkdirs，见插件注释）。
    implementation(patchedJar("unidbg-api-0.9.9-android-patched.jar", "com.github.zhkl0228:unidbg-api:0.9.9.1"))
    implementation(patchedJar("unidbg-android-0.9.9-android-patched.jar", "com.github.zhkl0228:unidbg-android:0.9.9.1"))
    implementation(patchedJar("capstone-3.1.8-android-patched.jar", "com.github.zhkl0228:capstone:3.1.8.1"))
    implementation(patchedJar("keystone-0.9.7-android-patched.jar", "com.github.zhkl0228:keystone:0.9.7.1"))
    implementation("net.java.dev.jna:jna:5.10.0@aar")
    implementation("commons-codec:commons-codec:1.21.0")
    implementation("org.apache.commons:commons-collections4:4.5.0")
    implementation("commons-io:commons-io:2.21.0")
    implementation("com.alibaba:fastjson:1.2.83")
    implementation("com.github.zhkl0228:demumble:1.0.4")
    implementation("net.dongliu:apk-parser:2.6.10")
    implementation("com.github.zhkl0228:unidbg-unicorn2:0.9.9") {
        exclude(group = "com.github.zhkl0228", module = "unidbg-api")
        exclude(group = "com.github.zhkl0228", module = "capstone")
        exclude(group = "com.github.zhkl0228", module = "keystone")
    }
    // The patched unidbg-api jar still ships BackendFactory + UnicornBackend whose
    // bytecode references unicorn.Unicorn / unicorn.UnicornConst / unicorn.UnicornException
    // (and Unicorn2Backend in unidbg-unicorn2 references unicorn.UnicornConst /
    // unicorn.UnicornException as well). Those classes come from
    // com.github.zhkl0228:unicorn, which is a transitive of unidbg-api and therefore
    // drops out of the classpath the moment we exclude unidbg-api above. Without
    // this direct dependency, BackendFactory.createBackend() falls back from
    // Unicorn2Backend to UnicornBackend and then dies with
    //   ClassNotFoundException: unicorn_Unicorn
    // during session_open on every architecture. Pulling the original unicorn
    // artifact in explicitly restores the unicorn.* classes without re-introducing
    // unidbg-api (which would conflict with our patched jar).
    implementation("com.github.zhkl0228:unicorn:1.0.15")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")

    // Argon2 key derivation for encrypted backup/restore
    implementation("com.lambdapioneer.argon2kt:argon2kt:1.6.0")
}

// `net.java.dev.jna:jna:5.10.0` 在同一个依赖图里有两个 artifact，且**同版本**：
// 上面那条 `@aar` 加上 capstone / keystone 的 POM 各自带的 jar。Gradle 的冲突解析
// 只在**模块**层面合并，同版本的模块只会剩一个，但 artifact 是两条（`.aar` 与
// `.jar`），于是 checkDebugDuplicateClasses 报满屏
//   Duplicate class com.sun.jna.CallbackReference found in modules
//     jna-5.10.0.aar -> jna-5.10.0-runtime and jna-5.10.0.jar -> jna-5.10.0
// 这类「同一个模块的两个 artifact」冲突，`exclude` 与版本对齐都救不了 —— 它们按
// group:module 匹配，会把 `.aar` 一起排掉（实测剩下的 classpath 里连 jna 都没有）。
//
// 必须留 `.aar` 而不是 `.jar`：`libjnidispatch.so`（arm64-v8a / armeabi-v7a / x86 /
// x86_64）只在 aar 里，jna 在 Android 上靠它加载 native；只留 jar 会在运行期
// UnsatisfiedLinkError。aar 内含 classes.jar + jni/*，两者都齐。
//
// 做法是在**解析期**把这一组的产物换成 aar 那一个文件：`eachDependency` 是规则，
// 只改「选哪个模块/哪个 artifact」，不删候选，也不动其它模块的解析结果。
//
// 为什么不是 `components.withModule(...).allVariants { withFiles { ... } }`：那个钩子
// 对**所有**变体生效，包括 AGP 自己拉起来的 `:app:androidLintTool` —— 它会请求
// `net.java.dev.jna:jna:5.6.0`（lint 自带的坐标），被同一份 withFiles 改写成
// 「只要 jna-5.10.0.aar」，于是
//   Could not find jna-5.10.0.aar (net.java.dev.jna:jna:5.6.0)
//   Searched in .../net/java/dev/jna/jna/5.6.0/jna-5.10.0.aar
// 那条 URL 永远不会存在，Android Lint 直接红（cnb-h86-1k62fspsh）。
// 判据要落在「这个模块的 5.10.0」上，而不是「这个模块的所有变体」。
//
// **版本也要判**：`artifactSelection` 若只按 group+name 匹配，`:app:androidLintTool`
// 那条 `jna:5.6.0` 同样会被要求选 aar —— 而 5.6.0 只有 jar。本地实测该写法在普通
// 配置上会退回来（日志不报错），但那正是「看起来好了」的一类：真到 AGP 的 lint 工具
// 配置里，`Could not find jna-5.6.0.aar` 会再次出现。加上 `requested.version == "5.10.0"`
// 才是判据落点 —— 只有 app 运行时那条需要 aar。
//
// 本地实测两个方向：
//   jna 5.10.0（app 运行时）-> jna-5.10.0.aar，duplicated = []
//   jna 5.6.0（lint 工具）  -> jna-5.6.0.jar，原样放行
configurations.configureEach {
    resolutionStrategy.eachDependency {
        // Kotlin DSL 的 eachDependency / artifactSelection 都是**带接收者**的 lambda
        // （DependencyResolveDetails / ArtifactSelectionDetails），作用域里没有 `it`。
        // 写成 `it.requested...` 是 Groovy 的语法，在 .kts 里是编译期错误：
        //   e: Unresolved reference 'it'
        // 而预热第一遍就是按仓库原样编译这个脚本，编译不过则整层预热一分依赖不下
        // （cnb-ql2-1k62gkso0）。
        if (requested.group == "net.java.dev.jna" && requested.name == "jna" &&
            requested.version == "5.10.0"
        ) {
            artifactSelection {
                selectArtifact("aar", "aar", null)
            }
        }
    }
}
