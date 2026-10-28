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
        // app/libs/*-patched.jar 的本地仓库（由 buildSrc/somcp.patched-local-jars 生成）。
        //
        // 排**第一**：`x.y.z.1` 这个版本只有这里有。它后面那些仓库里一个都没有，
        // 排第一等于「命中即停」，不必让每个 `.1` 都去 google / Central / JitPack
        // 各撞一次 404（冷启动撞的是 Maven Central 的 429，那会直接判死整次解析）。
        // 上游坐标 `x.y.z` 也的确在这里没有，照样落到后面的真仓库。
        //
        // 目录在 `:app` 的 build 目录下，首次配置前可能还不存在；Gradle 对不存在的
        // 本地仓库只会跳过（真要解析 `.1` 时插件已经把它生成好了）。
        maven {
            name = "somcpPatchedLocal"
            url = uri(rootDir.resolve("app/build/patched-jars-repo"))
        }
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

rootProject.name = "SoReverseNativeMcp"
include(":app")
