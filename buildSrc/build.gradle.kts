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
plugins {
    `kotlin-dsl`
}

// buildSrc 不会继承 settings.gradle.kts 的仓库声明，必须自己写一份，
// 否则 kotlin-stdlib / kotlin-reflect 解析不到（报 "no repositories are defined"）。
// 与 settings.gradle.kts 的顺序保持一致：CNB 的 init script 会在这个列表前面
// 插入镜像，本地开发则直连。
repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
}
