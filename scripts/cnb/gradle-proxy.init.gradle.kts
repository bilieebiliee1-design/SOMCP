// SPDX-License-Identifier: AGPL-3.0-only
//
// SOMCP - scripts/cnb/gradle-proxy.init.gradle.kts
// Copyright (C) 2026 SOMCP authors
// Upstream: https://github.com/bilieebiliee1-design/SOMCP
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License version 3 as published by
// the Free Software Foundation.
//
// Gradle 初始化脚本：把 CI 环境下注入的 HTTP(S)_PROXY / NO_PROXY 桥接成 JVM 代理属性。
//
// 为什么放在 init script：CNB 会把 Runner 宿主机的代理变量同步进容器，
// 但 Gradle 的 daemon JVM 不读它们；而构建脚本（build.gradle.kts）里的设置
// 时机又太晚 —— 插件解析在脚本求值之前就发生了。init script 在 daemon 启动、
// 构建配置之前执行，是唯一不侵入仓库其余部分的位置。
//
// 为什么**不能**不加判断地设置：一个空 host 的代理值（例如 `HTTP_PROXY=:8080`）
// 一旦被写成 https.proxyHost=""，所有依赖请求都会退化成连本机的那一类场景，
// 表现同样是「Plugin [id: ...] was not found in any of the following sources」。
// 代理只是网络条件，判据不能挂在它身上，所以这里只在 host 非空时设置。
//
// 用法（仅在流水线里显式传参，本地不加这个参数就完全不受影响）：
//   gradle --init-script scripts/cnb/gradle-proxy.init.gradle.kts <task>
//
// 另外断言 429 的重试配置真的生效（gradle.properties 里的 systemProp.*）：
// 缺了就直接报出修复方法 —— 否则 429 会再被翻译成
// 「Plugin [id: 'org.jetbrains.kotlin.android', version: '2.4.0'] was not found」，
// 看起来像版本号写错，实际是重试用尽。
//
// 没有（有效的）代理变量时，代理部分什么都不做；离线复核模式见下面 cnbCacheOnlyCheck。

fun proxyParts(raw: String?): Pair<String, Int>? {
    // `:8080` 这类只有端口的值没有 host，转成 URI 后 host 为 null，直接放弃。
    val value = raw?.trim()?.takeIf { it.isNotEmpty() && it != ":" } ?: return null
    val uri =
        runCatching { java.net.URI(value) }.getOrNull()
            ?: runCatching { java.net.URI("http://$value") }.getOrNull()
            ?: return null
    val host = uri.host?.trim()?.takeIf { it.isNotEmpty() } ?: return null
    return host to (uri.port.takeIf { it > 0 } ?: 80)
}

proxyParts(System.getenv("HTTP_PROXY"))?.let { (host, port) ->
    System.setProperty("http.proxyHost", host)
    System.setProperty("http.proxyPort", port.toString())
}
proxyParts(System.getenv("HTTPS_PROXY"))?.let { (host, port) ->
    System.setProperty("https.proxyHost", host)
    System.setProperty("https.proxyPort", port.toString())
}
System.getenv("NO_PROXY")?.trim()?.takeIf { it.isNotEmpty() }?.let { raw ->
    // JVM 的非代理列表用 '|' 分隔，环境变量惯例用 ','
    val list = raw.replace(",", "|")
    System.setProperty("http.nonProxyHosts", list)
    System.setProperty("https.nonProxyHosts", list)
}

// 「只看缓存」复核模式：--offline 只禁止联网，不禁止 Gradle 按仓库名去
// $GRADLE_USER_HOME 里查缓存索引，于是「镜像预热没做完」和「仓库此刻不可达」
// 分不开 —— 曾出现预热成功、运行期 --offline 复核却报
//   was not found in any of the following sources: Google, cnb-plugin-mirror-0(...), ...
// 把网络问题误判成缓存不完整。做法是把插件仓库与依赖仓库都换成同一个空的本地
// 文件仓库（于是只剩已预热进 $GRADLE_USER_HOME 的构件可用），实现在
// scripts/cnb/gradle-cache-only.gradle，由镜像放到
// $GRADLE_USER_HOME/cnb-cache-only.gradle。
// 只由 scripts/cnb/setup-build-env.sh 用 -PcnbCacheOnlyCheck 打开，其余场景不受影响。
fun cnbHasProjectProperty(name: String): Boolean =
    runCatching { gradle.startParameter.projectProperties.containsKey(name) }.getOrDefault(false)

if (System.getenv("CNB_BUILD_ID") != null && cnbHasProjectProperty("cnbCacheOnlyCheck")) {
    // 拆成独立脚本的理由：本文件是 .kts，`beforeSettings` 收的是 bridged 的
    // org.gradle.api.Action，Kotlin 侧要额外的 SAM 适配才好写；那半段逻辑一次成型、
    // 不值得把整个 init script 改成 Groovy（代理那段已经稳定）。
    val cacheOnlyScript = File(System.getProperty("user.home"), ".gradle/cnb-cache-only.gradle")
    if (!cacheOnlyScript.isFile) {
        throw IllegalStateException(
            "cnbCacheOnlyCheck requested but ${cacheOnlyScript} is missing; " +
                "the image must COPY scripts/cnb/gradle-cache-only.gradle to \$GRADLE_USER_HOME/cnb-cache-only.gradle",
        )
    }
    apply(from = cacheOnlyScript)
}

// 让日志能自证代理是否真的生效（不打印账号密码）。
gradle.beforeProject {
    if (System.getProperty("https.proxyHost") != null) {
        logger.lifecycle(
            "[cnb-proxy] http=${System.getProperty("http.proxyHost")}:${System.getProperty("http.proxyPort")} " +
                "https=${System.getProperty("https.proxyHost")}:${System.getProperty("https.proxyPort")}"
        )
    }
}

// --- 429 重试配置自证 -------------------------------------------------------
// 这两个键是 Gradle 自己的仓库级重试设置（源码：
// ErrorHandlingModuleComponentRepository，`Integer.getInteger(...)` 读 JVM 属性），
// 只能靠 gradle.properties 的 systemProp.* 或命令行 -D 注入。
// 注意是 max.tentatives 而不是 max.retries —— 后者在 Gradle 8 里不存在，写了静默无效。
// 前缀也不能省：不带 systemProp. 的那几行看着更像「Gradle 属性」，实际 Gradle 不读
// （A/B 实测：不带前缀 BUILD FAILED，带前缀 12 次 BUILD SUCCESSFUL）。
val cnbRequiredSystemProperties =
    listOf(
        "org.gradle.internal.repository.max.tentatives",
        "org.gradle.internal.repository.initial.backoff",
    )

gradle.settingsEvaluated {
    // 离线复核（cnbCacheOnlyCheck）本来就不联网，缺这两个属性不算问题。
    if (System.getenv("CNB_BUILD_ID") != null && !cnbHasProjectProperty("cnbCacheOnlyCheck")) {
        val missing = cnbRequiredSystemProperties.filter { System.getProperty(it) == null }
        require(missing.isEmpty()) {
            "缺少 Gradle 仓库重试配置 $missing（Maven Central 429 会伪装成插件解析失败）；" +
                "确认 gradle.properties 里有对应的 systemProp.*，或命令行传 -D<key>=<value>"
        }
        logger.lifecycle(
            "[cnb-repos] tentatives=${System.getProperty("org.gradle.internal.repository.max.tentatives")} " +
                "backoff=${System.getProperty("org.gradle.internal.repository.initial.backoff")}ms",
        )
    }
}
