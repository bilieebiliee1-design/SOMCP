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
# 把 /tmp/cnb-warmup/ 里拷进来的仓库构建脚本跑成「能把依赖下全」的预热工程：
# 先按仓库原样跑一遍，再改写成最小工程跑第二遍。
# 由 image/cnb-tools.Dockerfile 的预热段调用（镜像构建期，工作目录必须已经在
# /tmp/cnb-warmup）。
#
# 为什么不是几行 sed：改写要保证「插件声明」和「仓库声明」两半都在，而且
# 后半段（仓库）恰恰是之前每个版本都丢掉的 —— settings.gradle.kts 一旦被
# 清空成一行 rootProject.name，Gradle 就只剩缺省的 gradlePluginPortal，
# 预热去 Google 找不到 AGP 的 marker，运行期又反过来缺 aliyun 镜像。
# 用 grep 取整块，取不到就失败（比静默生成一个残缺工程强）。
#
# 构建上下文里不带 buildSrc/，:app 脚本里那行 `id("somcp.patched-local-jars")` 在
# 两遍里都注释掉：插件的实现与声明一旦只剩一边，:app 的脚本就编译不过，而它的
# dependencies {} 写在 plugins {} 之后 —— 编译不过就一行都求值不到。
# 详见 disable_buildsrc_plugin() 的注释。
#
# 两遍：第一遍用**仓库原样**跑（:app 的真实脚本 + app/libs/ 都在，才解析得到
# 那一整张依赖图），第二遍才把工程改写成最小形态、再跑一次。
set -euo pipefail

DIR="${1:-/tmp/cnb-warmup}"
cd "$DIR"

# --- app：第一遍之前的准备 ---------------------------------------------------
# **第一遍必须按仓库原样跑**：:app 的真实脚本里有 androidx / compose / ktor /
# okhttp 与 files("libs/*-patched.jar")，只有按真实脚本求值一次，那些依赖才进得了
# 缓存。手写一份最小 :app 等于自己决定「预热覆盖哪些依赖」，漏掉的那些运行期照样
# 现场冲网。
#
# 所以改写之前做两件事：把 app/libs/ 里的 jar 打印出来（少了它们，
# files("libs/*-patched.jar") 那两条依赖解析不到），以及停用 buildSrc 的插件
# （见 disable_buildsrc_plugin）。
prepare_runtime_layout() {
  mkdir -p app
  [ -f app/build.gradle.kts ] \
    || { echo "[warmup] ERROR: app/build.gradle.kts missing in $DIR (must be in docker:cache.by)" >&2; exit 1; }
  if [ -d app/libs ] && [ -n "$(ls -A app/libs 2> /dev/null)" ]; then
    echo "[warmup] app/libs: $(ls app/libs | tr '\n' ' ')"
  else
    echo "[warmup] WARNING: app/libs is empty in the build context; the patched-jar file dependencies stay unresolved" >&2
  fi
}

# 第一遍：仓库原样（只停用 buildSrc 插件）。报错就是运行期会遇到的报错，
# 所以失败即整层失败。
cold_build() {
  CNB_BUILD_ID=warmup GRADLE_USER_HOME=/tmp/cnb-warmup-home timeout 900 \
    /opt/gradle/bin/gradle --no-daemon --console=plain --info \
    --no-configuration-cache \
    --init-script /opt/cnb/gradle-init.gradle \
    --init-script /opt/cnb/gradle-proxy.init.gradle.kts \
    -Dcnb.cacheOnlyScript=/opt/cnb/gradle-cache-only.gradle \
    help :app:dependencies --configuration releaseRuntimeClasspath
}

# 第二遍：改写后的最小工程。依赖在第一遍已经下来了，这一遍只为「最小工程自己也
# 跑得通」，失败只打 WARNING —— 历史上这里反过来过：改写后的小工程跑不通就把
# 整层预热判死，而真正需要的依赖其实早就下完了。
warm_build() {
  CNB_BUILD_ID=warmup GRADLE_USER_HOME=/tmp/cnb-warmup-home timeout 600 \
    /opt/gradle/bin/gradle --no-daemon --console=plain --info \
    --no-configuration-cache \
    --init-script /opt/cnb/gradle-init.gradle \
    --init-script /opt/cnb/gradle-proxy.init.gradle.kts \
    -Dcnb.cacheOnlyScript=/opt/cnb/gradle-cache-only.gradle \
    help :app:dependencies --configuration releaseRuntimeClasspath
}

# --- buildSrc 的插件不进预热工程 ---------------------------------------------
# 不在 plugins {} 里声明版本、只躺在 buildSrc/src 里的插件（本仓库的
# `somcp.patched-local-jars`）在预热工程里两头堵：
#
#   * 留着 buildSrc 却不在 :app 声明它，Gradle 报
#     `Plugin [id: '...'] was not found ... Plugin Repositories (plugin dependency
#      must include a version number for this source)`；
#   * 删掉 buildSrc 却保留那行 `id("...")`，报的是同一句，落在
#     app/build.gradle.kts 的 plugins {} 上（cnb-hkj-1k624u580）。而 :app 的
#     dependencies {} 全写在 plugins {} 之后 —— 脚本编译不过，androidx / compose /
#     ktor / okhttp 一行都求值不到，预热等于只做了一半。
#
# 所以两边一起断：预热目录里没有 buildSrc/，app 脚本里那行 id(...) 行尾注释掉。
# 这个插件干的是「把 app/libs 下的 jar 顶掉上游同坐标模块」，而预热工程里那些
# 上游坐标本来就不出现，去掉它不影响依赖图的完整性。
disable_buildsrc_plugin() {
  rm -rf buildSrc
  if grep -q 'somcp\.patched-local-jars' app/build.gradle.kts; then
    # 注释加在**行尾**，不是整行替换：行号不能动。app 脚本里 :app 的签名配置用
    # `releaseKeystoreProperties.getProperty(...)` 读 release/keystore.properties，
    # 而那个文件在 Dockerfile 里是先 `mkdir -p release` 写好、再跑本脚本的 ——
    # 文件在、内容在，写的却是一次性的 CI 临时 keystore（第一个下标的 jar 也正
    # 躺在 app/libs 里），:app 的脚本本来就能完整求值。整行替换成一个空格加注释，
    # 缩进、列位、行号全变，Kotlin DSL 里行号/列位是有意义的（报错定位、行内
    # 语义），没有任何理由为了行尾一句话去改它们。
    sed -i 's|^\([[:space:]]*\)id("somcp\.patched-local-jars".*$|\1// [cnb-warmup] disabled: &|' app/build.gradle.kts
    # 判据从「那行 id(...) 没了」改成「它被注释掉了」：行尾追加意味着原文还在，
    # 只按 `^[[:space:]]*id("somcp.patched-local-jars")` 去找会永远命中，把
    # 「sed 什么都没改」放过去 —— 断言必须看行首有没有被注释符挡住。
    if grep -qE '^[[:space:]]*id\("somcp\.patched-local-jars"' app/build.gradle.kts; then
      echo "[warmup] ERROR: could not disable somcp.patched-local-jars in the app script" >&2
      exit 1
    fi
    echo "[warmup] disabled somcp.patched-local-jars in the warmup app script"
  fi
}

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

# --- 根 build.gradle.kts：只留 plugins {} 与 extra 三件套 --------------------
# 只保留**根**工程的插件声明，`plugins {}` 块之外的任何一行都不进预热工程：
# 根脚本里那些 `configurations.configureEach { ... }` / `tasks.withType<...>` 在
# 预热工程里没有对应的插件与子工程，求值会直接抛异常；而把 `dependencies { ... }`
# 整块搬过去更糟 —— warmup 工程里没有 libs/ 下的 jar，也没有仓库能补回来。
#
# 例外是 `extra["somcp*"]` 那几行：第一遍跑的是**真实的** app/build.gradle.kts，
# 它里面写着 `rootProject.extra["somcpNamespace"] as String`。把这几行剪掉，
# :app 一进配置阶段就抛
#     Cannot get property 'somcpNamespace' on extra properties extension as it does not exist
# （cnb-qno-1k625acuu），而报错点看起来跟预热裁剪毫无关系。这几行是纯字面量
# 赋值、不引用任何插件，留在预热工程里没有副作用。
rewrite_root_script() {
  # 目标文件名不能是 `build.gradle.kts.new`：Kotlin DSL 按扩展名认脚本，
  # `.kts.new` 只是一个普通文件，Gradle 根本不会把它当构建脚本读，改写就成了
  # 「写了但没生效」—— 下一遍跑的还是原文件。
  awk '
    /^plugins[[:space:]]*\{/ { inblock = 1 }
    inblock { print }
    inblock && /^\}/ { exit }
  ' build.gradle.kts > root-plugins-block.kts
  grep -q 'com.android.application' root-plugins-block.kts \
    || { echo "[warmup] ERROR: no plugins {} block in build.gradle.kts" >&2; exit 1; }
  # extra 赋值要在覆盖根脚本**之前**取出来：先覆盖再 grep 同一个文件，就是
  # `grep: build.gradle.kts: input file is also the output`，一行都拿不到。
  grep -E '^[[:space:]]*extra\["somcp' build.gradle.kts > root-extra-lines.kts || true
  cp root-plugins-block.kts build.gradle.kts
  rm -f root-plugins-block.kts
  cat root-extra-lines.kts >> build.gradle.kts
  rm -f root-extra-lines.kts
  # 判据：预热工程里必须能读到那几行，否则第一遍的真实 :app 脚本求值必炸。
  for key in somcpNamespace somcpCompileSdk somcpMinSdk; do
    grep -q "extra\[\"$key\"\]" build.gradle.kts \
      || { echo "[warmup] ERROR: extra[\"$key\"] lost in the warmup root script" >&2; exit 1; }
  done
}

# --- app/build.gradle.kts：第二遍才改写成只声明插件的模块脚本 ---------------
# **第一遍用仓库里真实的 app 脚本**（app/build.gradle.kts 与 app/libs/ 都进了
# 构建上下文）：:app 的依赖图只有按真实脚本求值才解析得全，手写一份最小 :app
# 等于自己决定「预热覆盖哪些依赖」，漏掉的那些运行期照样现场冲网。
#
# 第二遍才换成生成的 `plugins {}` + 最小 `android {}`，因为改写后的工程里那些
# 配置不成立：
#   * `configurations.configureEach { ... }` / 自定义 task 依赖仓库里其余源码；
#   * 更要命的是任何一句 Kotlin DSL 编译不过的写法（历史例子：
#     `implementation(module("g:a:v"))`，Dependencies.module 只收三个参数）——
#     脚本一编译失败，整次预热就以 BUILD FAILED 收场，而报错点看起来跟依赖图无关。
# 拆成两遍之后，「脚本编译不过」只影响第二遍，而第二遍失败只打 WARNING。
#
# :app 用了哪些插件，从根 build.gradle.kts 的 plugins 块里认（本仓库的 :app 用的
# 就是根里 apply false 的那两个）。
simplify_app_script() {
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
}

# --- settings.gradle.kts：pluginManagement + 预热工程自己的依赖仓库 ----------
# 由第二遍（simplify_settings_script）调用。第一遍用仓库原文件，所以这里的改写
# 只影响第二遍。
#
# 上半段（pluginManagement）决定插件去哪解析，必须保留。下半段
# dependencyResolutionManagement 必须**照抄仓库自己的那份**，不能手写一份
# `google() + mavenCentral()`：本仓库还依赖 JitPack 的 com.github.<owner>:<repo>
# 坐标，手写的列表里没有 jitpack.io，:app 的依赖解析就会 FAILED（实测日志里出现
# `com.github.rikkahub:markdown:... FAILED`、jitpack.io 一次都没被请求），
# 而运行期是有的 —— 预热与运行期两张不同的仓库列表，等于给运行期留了一份
# 「预热没覆盖到」的依赖。
simplify_settings_script() {
  awk '
    /^pluginManagement[[:space:]]*\{/ { inp = 1 }
    inp { print }
    inp && /^\}/ { exit }
  ' settings.gradle.kts > settings.gradle.kts.new
  grep -q 'mavenCentral\|google()' settings.gradle.kts.new \
    || { echo "[warmup] ERROR: pluginManagement repositories not found in settings.gradle.kts" >&2; exit 1; }

  awk '
    /^dependencyResolutionManagement[[:space:]]*\{/ { indep = 1 }
    indep { print }
    indep && /^\}/ { exit }
  ' settings.gradle.kts > dependency-resolution.tmp
  [ -s dependency-resolution.tmp ] \
    || { echo "[warmup] ERROR: dependencyResolutionManagement not found in settings.gradle.kts" >&2; exit 1; }
  printf '\n' >> settings.gradle.kts.new
  cat dependency-resolution.tmp >> settings.gradle.kts.new
  cat >> settings.gradle.kts.new <<'SETTINGS'

rootProject.name = "cnb-warmup"
include(":app")
SETTINGS
  rm -f dependency-resolution.tmp
  mv settings.gradle.kts.new settings.gradle.kts
}

# --- 两遍执行 ---------------------------------------------------------------
# 顺序不能换，理由见各自函数的注释：
#   1. prepare_runtime_layout → disable_buildsrc_plugin → cold_build
#      （仓库原样，联网，失败即整层失败）
#   2. simplify_* → warm_build（最小工程，失败只打 WARNING）
echo "[warmup] pass 1/2: repository as-is (app/build.gradle.kts + app/libs)"
prepare_runtime_layout
disable_buildsrc_plugin
rewrite_root_script
if cold_build > /tmp/cnb-warmup.log 2>&1; then
  echo "[warmup] pass 1 OK: repository as-is"
else
  echo "[warmup] ERROR: pass 1 failed; the cache could not be populated." >&2
  echo "[warmup] ERROR: network-layer evidence first, then the tail:" >&2
  grep -E "Could not (GET|HEAD|resolve)|rate limit|429|proxy|Connection|timed out" /tmp/cnb-warmup.log | tail -n 40 >&2 || true
  tail -n 80 /tmp/cnb-warmup.log >&2 || true
  exit 1
fi

echo "[warmup] pass 2/2: minimal project (generated :app script)"
simplify_app_script
simplify_settings_script

echo "[warmup] project rewritten in $DIR:"
sed 's/^/[warmup]   /' build.gradle.kts
sed 's/^/[warmup]   /' app/build.gradle.kts
sed 's/^/[warmup]   /' settings.gradle.kts

if warm_build > /tmp/cnb-warmup-2.log 2>&1; then
  echo "[warmup] pass 2 OK: minimal project"
else
  echo "[warmup] WARNING: pass 2 (minimal project) failed; the pass-1 cache is kept" >&2
  grep -E "Could not (GET|HEAD|resolve)|rate limit|429|proxy|Connection|timed out" /tmp/cnb-warmup-2.log | tail -n 20 >&2 || true
  tail -n 40 /tmp/cnb-warmup-2.log >&2 || true
fi
