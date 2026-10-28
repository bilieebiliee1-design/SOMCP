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
// 另外两件事，都只影响「网络条件」，不放松任何判据：
//
//   1. 插件仓库顺序调成 Central 优先。settings.gradle.kts 里 `google()` 排在
//      `mavenCentral()` 前面，而 Google Maven 上没有
//      `org.jetbrains.kotlin.android.gradle.plugin` 这类标记 artifact：每个插件都要
//      先在 Google 吃一次 404 再回落。CI 冷启动几十个请求并发，正是这轮 404 把
//      Central 的出口限流（429）撞了出来。只挪顺序，不增删仓库。
//   2. 断言 429 的重试配置真的生效（gradle.properties 里的 systemProp.*）。
//      缺了就直接报出修复方法 —— 否则 429 会再被翻译成
//      「Plugin [id: 'org.jetbrains.kotlin.android', version: '2.4.0'] was not found」，
//      看起来像版本号写错，实际是重试用尽。
//
// 没有（有效的）代理变量时，只有代理那一段不做任何事。

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

// 让日志能自证代理是否真的生效（不打印账号密码）。
gradle.beforeProject {
    if (System.getProperty("https.proxyHost") != null) {
        logger.lifecycle(
            "[cnb-proxy] http=${System.getProperty("http.proxyHost")}:${System.getProperty("http.proxyPort")} " +
                "https=${System.getProperty("https.proxyHost")}:${System.getProperty("https.proxyPort")}"
        )
    }
}

// --- 插件仓库顺序 -----------------------------------------------------------
// 把 Maven Central 挪到 pluginManagement 的第一位。为什么在这里挪、而不改
// settings.gradle.kts：Google 优先只在 CI 冷启动的并发下才会把 Central 的出口
// 限流撞出来，本地开发不受影响，不该为 CI 去动本地构建的配置。
//
// 为什么是「remove + addFirst」（实测 Gradle 8.10.2）：
//   - `RepositoryHandler.move` 在 Gradle 8 里不存在（9 才有），直接 Unresolved reference；
//   - `clear()` 后重建会丢掉原有仓库的凭据与 content filters，还会把
//     scripts/cnb/gradle-init.gradle 追加的镜像一起清掉；
//   - `addFirst(已在列表中的实例)` 会被同名检查挡住；
//   - `remove()` 是 `NamedDomainObjectList` 的标准能力，移出再插回首位可行，
//     且不动仓库实例本身，配置全部保留。
//
// 为什么顺序仍然敏感：pluginManagement 里 `google()` 在 `mavenCentral()` 前面，
// 而 Google Maven 上没有 `org.jetbrains.kotlin.android.gradle.plugin` 这类标记
// artifact。每个插件（以及它引出的 BOM）都要先在 Google 吃一次 404 再回落 Central；
// 冷启动时这一轮 404 会和真正要拉的 POM 一起把 429 打出来。前置 Central 不改
// 「谁能提供什么」，只是把无谓的 404 省掉，镜像仍留在列表末尾做兜底。
fun RepositoryHandler.centralFirst() {
    val central = findByName("MavenRepo") ?: return
    if (indexOf(central) == 0) return
    remove(central)
    addFirst(central)
}

// 这两个键是 Gradle 自己的仓库级重试设置（源码：
// ErrorHandlingModuleComponentRepository，`Integer.getInteger(...)` 读 JVM 属性），
// 只能靠 gradle.properties 的 systemProp.* 或命令行 -D 注入。
// 注意是 max.tentatives 而不是 max.retries —— 后者在 Gradle 8 里不存在，写了静默无效。
val REQUIRED_SYSTEM_PROPERTIES =
    listOf(
        "org.gradle.internal.repository.max.tentatives",
        "org.gradle.internal.repository.initial.backoff",
    )

gradle.settingsEvaluated {
    // 重试/退避属性只认 gradle.properties 的 systemProp.* 与命令行 -D，
    // 在 init script 里改 System 属性已经太晚（仓库传输组件早已初始化），
    // 所以这里只做自证：缺了直接报出修复方法，而不是让 429 又一次
    // 伪装成「Plugin ... was not found」。
    val missing = REQUIRED_SYSTEM_PROPERTIES.filter { System.getProperty(it) == null }
    require(missing.isEmpty()) {
        "缺少 Gradle 仓库重试配置 $missing（Maven Central 429 会伪装成插件解析失败）；" +
            "确认 gradle.properties 里有对应的 systemProp.*，或命令行传 -D<key>=<value>"
    }
    logger.lifecycle(
        "[cnb-repos] tentatives=${System.getProperty("org.gradle.internal.repository.max.tentatives")} " +
            "backoff=${System.getProperty("org.gradle.internal.repository.initial.backoff")}ms",
    )
    pluginManagement.repositories.centralFirst()
    logger.lifecycle("[cnb-repos] plugin 仓库顺序: ${pluginManagement.repositories.map { it.name }}")
}
