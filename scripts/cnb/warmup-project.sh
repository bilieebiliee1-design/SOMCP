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

# --- build.gradle.kts：只留 plugins {} -------------------------------------
awk '
  /^plugins[[:space:]]*\{/ { inblock = 1 }
  inblock { print }
  inblock && /^\}/ { exit }
' build.gradle.kts > build.gradle.kts.new
grep -q 'com.android.application' build.gradle.kts.new \
  || { echo "[warmup] ERROR: no plugins {} block in build.gradle.kts" >&2; exit 1; }
mv build.gradle.kts.new build.gradle.kts

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
# 预热工程不需要真正的项目名，但不能没有（Gradle 9 缺省用目录名，留着原文更明确）。
cat >> settings.gradle.kts.new <<'SETTINGS'

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "cnb-warmup"
SETTINGS
mv settings.gradle.kts.new settings.gradle.kts

echo "[warmup] project rewritten in $DIR:"
sed 's/^/[warmup]   /' build.gradle.kts
sed 's/^/[warmup]   /' settings.gradle.kts
