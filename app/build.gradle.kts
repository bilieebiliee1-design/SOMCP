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
        versionCode = 3
        versionName = "1.0.2"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-fexceptions", "-frtti")
                arguments += listOf("-DANDROID_STL=c++_shared")
            }
        }
    }

    buildFeatures {
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
        checkReleaseBuilds = false
    }

    signingConfigs {
        create("release") {
            storeFile = rootProject.file(releaseKeystoreProperties.getProperty("storeFile", "release/so-reverse-mcp-release.jks"))
            storePassword = releaseKeystoreProperties.getProperty("storePassword", "")
            keyAlias = releaseKeystoreProperties.getProperty("keyAlias", "")
            keyPassword = releaseKeystoreProperties.getProperty("keyPassword", "")
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    }

    buildTypes {
        debug {
            isJniDebuggable = true
            buildConfigField("String", "EXPECTED_SIGNER_SHA256", "\"\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            isJniDebuggable = false
            buildConfigField("String", "EXPECTED_SIGNER_SHA256", "\"90FEDAC1F020C6C5D1DD1A635DB5C3B7579F5B87647E2C2C00966D3BCB0F8B6F\"")
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
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
                "com/sun/jna/win32-*/**",
            )
        }
    }
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
}
