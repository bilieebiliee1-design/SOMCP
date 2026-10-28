/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * SOMCP - buildSrc/build.gradle.kts
 * Copyright (C) 2026 SOMCP authors
 * Upstream: https://github.com/bilieebiliee1-design/SOMCP
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License version 3 as published by
 * the Free Software Foundation.
 */

// 只为了让 buildSrc/src/main/kotlin/somcp.patched-local-jar.gradle.kts 那个预编译
// 脚本插件能被加载：`kotlin-dsl` 会带上 Kotlin 编译器与 stdlib。
//
// 版本必须**写死**，不能让它跟着 Gradle 的缺省值走：`kotlin-dsl` 的 marker
// 版本是 gradle-kotlin-dsl-<Gradle 版本>-<发布时间戳>，形如 6.6.4-20260114.081327-6，
// Gradle 每次都去 plugins 的**那个**时间戳找构件。同一个 Gradle 版本在不同时间
// 运行可能读到不同的 marker（缺省值里带时间戳），缓存里存下的键与下一次请求的
// 键对不上 —— 表现是「明明预热过，却报 kotlin-dsl 找不到」。
//
// 挑一个固定版本还顺带把下面的仓库收窄成一件事：查什么、去哪查，都写在这儿。
plugins {
    id("org.gradle.kotlin.kotlin-dsl") version "6.6.4"
}

// buildSrc 不会继承 settings.gradle.kts 的仓库声明，必须自己写一份，
// 否则 kotlin-stdlib / kotlin-reflect 解析不到（报 "no repositories are defined"）。
//
// 顺序与 settings.gradle.kts 一致：CNB 的 init script 只会往这个列表**前面**插镜像，
// 本地开发则直连。
//
// 这份列表也是 `kotlin-dsl` 插件 marker 唯一的来源：Gradle 编译 buildSrc 发生在
// 配置根工程之前，`settings.gradle.kts` 的 pluginManagement 与镜像传的
// `--init-script` 都管不到这儿（详见 docs/cnb-test-v10.md「buildSrc 必须自带
// 插件仓库」）。缺 gradlePluginPortal() 就直接是
//   Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found
repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
}
