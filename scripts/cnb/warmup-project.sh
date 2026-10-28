#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/warmup-project.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# 把 /tmp/cnb-warmup/ 里拷进来的仓库构建脚本改写成「只解析插件」的最小工程。
# 由 image/cnb-tools.Dockerfile 的预热段调用（镜像构建期，工作目录必须已经在
# /tmp/cnb-warmup），也可以本地对着任意目录跑一遍看改写结果。
#
# 为什么不是几行 sed：改写要保证「插件声明」和「仓库声明」两半都在，而且
# 后半段（仓库）恰恰是之前每个版本都丢掉的 —— settings.gradle.kts 一旦被
# 清空成一行 rootProject.name，Gradle 就只剩缺省的 gradlePluginPortal，
# 预热去 Google 找不到 AGP 的 marker，运行期又反过来缺 aliyun 镜像。
# 用 grep 取整块，取不到就失败（比静默生成一个残缺工程强）。
set -euo pipefail

DIR="${1:-/tmp/cnb-warmup}"
cd "$DIR"

# --- 先把 SDK / namespace 读出来 --------------------------------------------
# 见 MAGIC-WARMUP-READVAL
read_val() { sed -n "s/^[[:space:]]*extra\[\"$1\"\][[:space:]]*=[[:space:]]*\"\{0,1\}\([^\"[:space:]]*\)\"\{0,1\}[[:space:]]*$/\1/p" build.gradle.kts | head -1; }

# --- MAGIC-WARMUP-READVAL：必须留在改写根脚本**之前** ------------------------
WARMUP_NAMESPACE="$(read_val somcpNamespace)"
WARMUP_COMPILE_SDK="$(read_val somcpCompileSdk)"
WARMUP_MIN_SDK="$(read_val somcpMinSdk)"
[ -n "$WARMUP_NAMESPACE" ] || { echo "[warmup] ERROR: no namespace in root build.gradle.kts" >&2; exit 1; }
[ -n "$WARMUP_COMPILE_SDK" ] || { echo "[warmup] ERROR: no compileSdk in root build.gradle.kts" >&2; exit 1; }
[ -n "$WARMUP_MIN_SDK" ] || { echo "[warmup] ERROR: no minSdk in root build.gradle.kts" >&2; exit 1; }

# --- 根 build.gradle.kts：只留 plugins {} ----------------------------------
# 只保留**根**工程的插件声明，`plugins {}` 块之外的任何一行都不进预热工程：
# 根脚本里那些 `configurations.configureEach { ... }` / `tasks.withType<...>` 在
# 预热工程里没有对应的插件与子工程，求值会直接抛异常；而把 `dependencies { ... }`
# 整块搬过去更糟 —— warmup 工程里没有 libs/ 下的 jar，也没有仓库能补回来。
awk '
  /^plugins[[:space:]]*\{/ { inblock = 1 }
  inblock { print }
  inblock && /^\}/ { exit }
' build.gradle.kts > build.gradle.kts.new
grep -q 'com.android.application' build.gradle.kts.new \
  || { echo "[warmup] ERROR: no plugins {} block in build.gradle.kts" >&2; exit 1; }
mv build.gradle.kts.new build.gradle.kts

# --- app/build.gradle.kts：生成一个只声明插件的模块脚本 ----------------------
# **绝不能把仓库里 app 的脚本整份留下来**。预热工程的 app 模块只是为了触发
# AGP 配置（拿插件 marker、AGP、lint、:app 的运行时依赖图），而 app 脚本里那些
# 依赖与配置在最小工程里根本不成立：
#   * `implementation(files("libs/*-patched.jar"))` 指向的文件不在预热上下文里
#     （.cnb.yml 的 docker:cache.by 只带构建脚本，不带 libs/）；
#   * `configurations.configureEach { ... }` / 自定义 task 依赖仓库里其余源码；
#   * 更要命的是任何一句 Kotlin DSL 编译不过的写法（历史例子：
#     `implementation(module("g:a:v"))`，Dependencies.module 只收三个参数）——
#     脚本一编译失败，整次预热就以 BUILD FAILED 收场，镜像里一个依赖都没落下，
#     而报错点看起来跟依赖图毫无关系。
# 所以这里干脆**不读**仓库的 app 脚本（它也不在构建上下文里），直接生成一份
# 只剩 `plugins {}` 的模块脚本：:app 用了哪些插件，从根 build.gradle.kts 的
# plugins 块里认（本仓库的 :app 用的就是根里 apply false 的那两个）。
grep -q 'com.android.application' build.gradle.kts \
  || { echo "[warmup] ERROR: root build.gradle.kts has no com.android.application plugin" >&2; exit 1; }
{
  echo 'plugins {'
  echo '    id("com.android.application")'
  grep -q 'org.jetbrains.kotlin.plugin.compose' build.gradle.kts \
    && echo '    id("org.jetbrains.kotlin.plugin.compose")'
  echo '}'
} > app/build.gradle.kts

# app 脚本只剩 plugins {} 之后，AGP 建模块级模型还缺 namespace / compileSdk /
# minSdk，缺了会在配置阶段就报 "Namespace not specified"。值从仓库自己的
# 根 build.gradle.kts 里读（本仓库 app 的 compileSdk 36 / minSdk 26 与根里的
# 插件版本同源，都随仓库走），读不到就判失败 —— 预热必须跟着仓库的 SDK 版本，
# 否则镜像里预热的是 A、运行期用 B，缓存里就差一份 platform 的依赖。
cat >> app/build.gradle.kts <<APPBLOCK

// 由 scripts/cnb/warmup-project.sh 生成；值取自仓库根 build.gradle.kts。
android {
    namespace = "${WARMUP_NAMESPACE}"
    compileSdk = ${WARMUP_COMPILE_SDK}
    defaultConfig {
        minSdk = ${WARMUP_MIN_SDK}
    }
}
APPBLOCK

# --- settings.gradle.kts：pluginManagement + 预热工程自己的依赖仓库 ----------
# 上半段（pluginManagement）决定插件去哪解析，必须保留。下半段
# dependencyResolutionManagement 必须**换成**本工程的仓库列表：插件的
# buildscript classpath（AGP 9 / kotlin 插件自身的依赖，如
# org.jetbrains.kotlin:fus-statistics-gradle-plugin）解析用的是它，而
# RepositoriesMode.FAIL_ON_PROJECT_REPOS 下插件也不能自己声明仓库 —— 丢掉这半段，
# 预热解析 classpath 时只剩隐式的 MavenRepo（repo.maven.apache.org），冷启动
# 一口气几十个 POM 必然吃 429，预热整段直接失败（镜像层只打 warning，
# 运行期复核再报「warmup cache is incomplete」）。
awk '
  /^pluginManagement[[:space:]]*\{/ { inp = 1 }
  inp { print }
  inp && /^\}/ { exit }
' settings.gradle.kts > settings.gradle.kts.new
grep -q 'mavenCentral\|google()' settings.gradle.kts.new \
  || { echo "[warmup] ERROR: pluginManagement repositories not found in settings.gradle.kts" >&2; exit 1; }
# 子项目必须声明：只解析插件时，:app 的运行时依赖（androidx / compose / ktor /
# okhttp…）一个都不会进缓存 —— 运行期照样现场冲网，预热等于只做了一半。
# AGP 配置子项目时要查 SDK，因此这条只在镜像里成立（ANDROID_HOME 由 ENV 给出，
# sdkmanager 装齐的 android-36 就在同一个镜像里）。
#
# dependencyResolutionManagement 必须**照抄仓库自己的那份**，不能手写一份
# `google() + mavenCentral()`：本仓库还依赖 JitPack 的 com.github.<owner>:<repo>
# 坐标，手写的列表里没有 jitpack.io，预热就会在 `:app:dependencies` 处把它解析成
# FAILED（实测日志里出现 `com.github.rikkahub:markdown:d79a97cc8e FAILED`、
# jitpack.io 一次都没被请求），而运行期是有的 —— 预热的仓库列表与运行期不一致，
# 等于给运行期留了一份「预热没覆盖到」的依赖。
awk '
  /^dependencyResolutionManagement[[:space:]]*\{/ { indep = 1 }
  indep { print }
  indep && /^\}/ { exit }
' settings.gradle.kts > dependency-resolution.tmp
[ -s dependency-resolution.tmp ] \
  || { echo "[warmup] ERROR: dependencyResolutionManagement not found in settings.gradle.kts" >&2; exit 1; }
# 预热工程不需要真正的项目名，但不能没有（Gradle 9 缺省用目录名，留着原文更明确）。
printf '\n' >> settings.gradle.kts.new
cat dependency-resolution.tmp >> settings.gradle.kts.new
cat >> settings.gradle.kts.new <<'SETTINGS'

rootProject.name = "cnb-warmup"
include(":app")
SETTINGS
rm -f dependency-resolution.tmp
mv settings.gradle.kts.new settings.gradle.kts

echo "[warmup] project rewritten in $DIR:"
sed 's/^/[warmup]   /' build.gradle.kts
sed 's/^/[warmup]   /' app/build.gradle.kts
sed 's/^/[warmup]   /' settings.gradle.kts
