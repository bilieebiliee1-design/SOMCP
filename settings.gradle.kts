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
        google()
        mavenCentral()
        maven("https://jitpack.io")
        // app/libs/*-patched.jar 的本地仓库（由 buildSrc/somcp.patched-local-jars 生成）。
        // 必须排在真仓库**之后**：上游版本照样从前面的仓库解析，`x.y.z.1`
        // 这个版本只有这里有 —— 两个版本都进图，Gradle 按「高版本胜出」只留
        // patched 那份，上游那份从图上消失，重名 class 也就无从发生。
        // 目录在 `:app` 的 build 目录下，首次配置前可能还不存在；Gradle 对不存在的
        // 本地仓库只会跳过（解析到 patched 版本时它已经被插件生成好了）。
        maven {
            name = "somcpPatchedLocal"
            url = uri(rootDir.resolve("app/build/patched-jars-repo"))
        }
    }
}

rootProject.name = "SoReverseNativeMcp"
include(":app")
