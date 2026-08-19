import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val releaseKeystoreProperties = Properties().apply {
    val file = rootProject.file("release/keystore.properties")
    if (file.isFile) file.inputStream().use(::load)
}

android {
    namespace = "com.soreverse.mcp"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "com.soreverse.mcp"
        minSdk = 26
        targetSdk = 36
        versionCode = 18
        versionName = "1.0.17"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-fexceptions", "-frtti")
                arguments += listOf("-DANDROID_STL=c++_shared")
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
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            isJniDebuggable = false
            signingConfig = signingConfigs.getByName("release")
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
            dir.isDirectory && libs.all { lib -> dir.resolve("lib$lib.so").exists() }
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
    implementation("com.github.zhkl0228:unidbg-unicorn2:0.9.9") {
        exclude(group = "com.github.zhkl0228", module = "unidbg-api")
        exclude(group = "com.github.zhkl0228", module = "capstone")
        exclude(group = "com.github.zhkl0228", module = "keystone")
    }
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")

    // Argon2 key derivation for encrypted backup/restore
    implementation("com.lambdapioneer.argon2kt:argon2kt:1.6.0")
}
