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
// 为什么必须放在 init script：CNB 会把 Runner 宿主机的代理变量同步进容器，
// 但 Gradle 的 daemon JVM 不读它们，依赖解析会绕过代理直连外网，在需要代理的
// 网络里表现为「Plugin [id: ...] was not found in any of the following sources」。
// 构建脚本（build.gradle.kts）里设置时机太晚 —— 插件解析在脚本求值之前就发生了；
// 写进 gradle.properties 的 systemProp.* 又会污染本地开发环境。init script 在
// daemon 启动、构建配置之前执行，是唯一不侵入仓库其余部分的位置。
//
// 用法（仅在流水线里显式传参，本地不加这个参数就完全不受影响）：
//   gradle --init-script scripts/cnb/gradle-proxy.init.gradle.kts <task>
//
// 没有设置代理变量时，本脚本不做任何事。

fun proxyParts(raw: String?): Pair<String, Int>? {
    val value = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
    val uri =
        runCatching { java.net.URI(value) }.getOrNull()
            ?: runCatching { java.net.URI("http://$value") }.getOrNull()
            ?: return null
    val host = uri.host ?: return null
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
