pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // 打补丁的 unidbg jar 由 buildSrc 的 somcp.patched-local-jars 插件发布成
        // 带 module 元数据的同版本模块，落在这里。必须排在 google/mavenCentral
        // **之前**：本地这份与上游同为 0.9.9，Gradle 的默认策略是「见到的第一个
        // 同版本胜出」，排后面就轮不到它，又会退回上游那份未打补丁的 jar。
        // 目录由插件在配置期生成（内容只有这两个坐标），空目录不影响其他解析。
        maven {
            name = "somcpPatchedLocalJars"
            // 与 buildSrc 插件里的 patchedJarRepo 指向同一路径。
            // 目录还不存在时 Gradle 当成「什么都找不到」，不会报错。
            url = uri(settingsDir.resolve("buildSrc/build/patched-jar-repository"))
        }
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

rootProject.name = "SoReverseNativeMcp"
include(":app")
