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

// 只放一个预编译脚本插件（src/main/groovy），用来把 app/libs 下打补丁的 jar
// 当成上游同名模块的替代品挂进依赖图。
//
// 这里**不能**用 `kotlin-dsl`。它要从 Gradle Plugin Portal 解析自己的插件 marker，
// 而 buildSrc 是 included build：既不继承 settings.gradle.kts 的 pluginManagement，
// `--init-script` 传进去的仓库对它也不生效，只能靠本文件下面那三行去拿。实测三行
// 齐了、版本钉死了，仍然会在 CNB 的 `--offline` 复核里报
//
//   Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found
//   Searched in the following repositories: Gradle Central Plugin Repository
//
// —— marker 从没进过镜像预热出来的那份用户目录（预热工程里没有 buildSrc），
// 复核又是全程离线的。为一个二十行的依赖修补去改预热的判据不划算。
// Gradle 自带的 `groovy-gradle-plugin` 零外部插件依赖，功能上完全够。
plugins {
    `groovy-gradle-plugin`
}

// buildSrc 不继承 settings.gradle.kts 的仓库，必须自己声明；否则连
// `groovy-gradle-plugin` 自身要用的 Groovy 都解析不到（"no repositories are defined"）。
repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
}
