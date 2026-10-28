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
    // Plugin Portal 的 Maven 端点，排在这里而不是只靠末尾的 gradlePluginPortal()。
    //
    // `kotlin-dsl` 的 marker 解析发生在 buildSrc 这一层，而 buildSrc 不继承
    // settings.gradle.kts 的 pluginManagement，init script 的镜像也管不到它 ——
    // 这个列表就是全部来源。`gradlePluginPortal()` 自己也是 Maven 端点
    // （plugins.gradle.org/m2），但它排在 mavenCentral() 之后，而 marker 的
    // **传递依赖**（kotlin-gradle-plugin-api / kotlin-gradle-plugins-bom 等）
    // 在 Maven Central 上一片 429：本地实测 39 次 429、耗时 9 分 42 秒才勉强解析完，
    // 而镜像预热的「只看缓存」复核是离线的，一旦那次联网预热没把这些构件下全，
    // 复核就报
    //   Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found
    //     Searched in the following repositories:
    //       Gradle Central Plugin Repository
    // 提到前面之后同一场景 429 不再挡路（plugins.gradle.org 那边是 200）。
    //
    // 与 google() / mavenCentral() 并列而不是替换：从 Portal 取不到时照样轮到
    // 后面两个，失败语义不变；本地开发命中同一个端点，字节也一致。
    maven {
        name = "gradlePluginPortalMaven"
        url = uri("https://plugins.gradle.org/m2")
    }
    mavenCentral()
    gradlePluginPortal()
}
