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
# :app 脚本里那个 `somcp.patched-local-jars` 插件在第一遍之前整个摘掉（声明、工厂、
# 调用点三处）：它的实现住在 buildSrc 里，而这份实现按设计只在真构建里生效 ——
# 插件生成的本地仓库（`x.y.z.1`）不该进镜像缓存。详见 disable_buildsrc_plugin()。
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
# 所以改写之前做两件事：把 app/libs/ 里的 jar 打印出来（第一遍的真实脚本里
# 那四条依赖指着它们），以及摘掉 buildSrc 那个插件（见 disable_buildsrc_plugin）。
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

# --- 第一遍：只停用 buildSrc 插件的**声明**，不删 buildSrc ---------------------
# 不在 plugins {} 里声明版本、只躺在 buildSrc/src 里的插件（本仓库的
# `somcp.patched-local-jars`）在第一遍里必须停用：第一遍跑的是真实的
# app/build.gradle.kts，而预热工程要跑的是「仓库的依赖图」，不是「这个插件改造过的
# 依赖图」。停用之后 patched jar 由下面两个函数换成普通坐标。
#
# **第一遍不能删 buildSrc**：预热的目的就是把它那份插件 marker 及其传递依赖下进
# 用户目录；而运行期每个 stage 都要真的编译 buildSrc，`--offline` 复核读的正是
# 这份缓存。
#
# 要摘掉三处，缺一处第一遍就配置失败：
#   * `id("somcp.patched-local-jars")` —— 插件声明；
#   * `val patchedJar = ...patchedLocalJarDependency...` 工厂 —— 插件不 apply 时
#     `project.ext` 上根本没有这个属性，取出来是 null，非空转换当场抛
#     `null cannot be cast to non-null type groovy.lang.Closure<*>`
#     （cnb-ooc-1k626h4rl，报错点落在那行 lambda，看着跟插件毫无关系）；
#   * 调用它的 `implementation(patchedJar(...))`。
#
# 判据只用**锚点行**（`id(...)` / `val patchedJar` / `patchedJar(`），注释一行都不认：
# 早先这里按注释原文逐条 sed（`/这四个是上游同名模块的重打包版本/d` 之类），
# 先删工厂后删注释，注释措辞一改就只删掉一半 —— 留在原地的注释在讲一个已经不
# 存在的工厂，接盘的人只能顺着注释去猜。整个函数最后再用 `patchedJar` 断言一次。
#
# **不能改成「保留工厂、换成同坐标字符串」**（`neutralize_patched_factory` 那一版）：
# 那样第一遍解析的就是 `x.y.z.1`，而这份本地仓库要靠插件生成，插件又必须删掉 ——
# 于是 `Searched in` 里一个仓库都不认 `.1`，报「找不到依赖」。
#
# 删掉这四条依赖不会让依赖图失真：patched jar 就是上游同名模块的重打包版本，
# 上游 `unidbg-android:0.9.9` 会经 unidbg-unicorn2 的传递依赖自己进来，它带出的
# 传递依赖（apk-parser / jna / demumble …）一条不少，与运行期只差「同名的那份
# 字节」—— 而预热要的是坐标，不是字节。
disable_buildsrc_plugin() {
  local script=app/build.gradle.kts
  grep -q 'somcp\.patched-local-jars' "$script" \
    || return 0

  # 锚点只有两处：单行的插件声明 / 调用点，和 `val patchedJar` 到第一个顶格 `}`
  # 的工厂整块（逐行删会留下没有主人的 `}`，Kotlin DSL 当场编译失败）。
  # 注释里提到 patched jar 的那些行也一并丢掉 —— 它们解释的东西马上就要消失，
  # 留着只会让后来的人顺着注释去找一个不存在的工厂。判据是关键词，不是注释原文。
  awk '
    /^val patchedJar[[:space:]]*:/ { in_factory = 1; ncomments = 0; next }
    in_factory {
      if ($0 == "}") { in_factory = 0 }
      next
    }
    /^[[:space:]]*id\("somcp\.patched-local-jars"\)[[:space:]]*$/ { next }
    /^[[:space:]]*implementation\(patchedJar\(/ { next }
    /^[[:space:]]*\/\// {
      # 讲 patched jar 的注释跟着工厂一起走，别的注释照常排队。
      if ($0 ~ /patchedJar|patchedLocalJarDependency|patched-local-jars|patched-jars-repo|重打包版本/) { next }
      comments[++ncomments] = $0
      next
    }
    {
      for (i = 1; i <= ncomments; i++) print comments[i]
      ncomments = 0
      print
    }
    END {
      # 只收尾：`patchedJar` 工厂整块没有闭合的 `}` 时判失败（留下来的半块一定
      # 编译不过）。工厂本身可以不在（已经只剩插件声明与调用点的那种写法），
      # 最终判据交给下面那条 `patchedJar` 断言。
      if (in_factory) exit 3
      for (i = 1; i <= ncomments; i++) print comments[i]
    }
  ' "$script" > "$script.cnb-strip" 2>/dev/null || {
    rm -f "$script.cnb-strip"
    echo "[warmup] ERROR: unexpected shape of the patchedJar factory in the app script" >&2
    exit 1
  }
  mv "$script.cnb-strip" "$script"

  # 断言：锚点一个不剩，且脚本花括号仍然配平。
  if grep -nE 'somcp\.patched-local-jars|patchedLocalJarDependency|patchedJar' "$script"; then
    echo "[warmup] ERROR: patched-jar leftovers above; the app script would not compile." >&2
    echo "[warmup] ERROR: the strip matches anchor lines only -- update" >&2
    echo "[warmup] ERROR: disable_buildsrc_plugin to match app/build.gradle.kts." >&2
    exit 1
  fi
  local balance
  balance="$(tr -cd '{}' < "$script" | awk '{ n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); print n - m }')"
  [ "$balance" = "0" ] \
    || { echo "[warmup] ERROR: app script braces unbalanced (${balance}) after stripping the patched-jar block" >&2; exit 1; }
  echo "[warmup] app script: patched-jar plugin, factory and call sites removed"
}

# --- 第二遍：buildSrc 换成占位（不删） ---------------------------------------
# 第一遍已经把真实 buildSrc 的插件 marker 连同传递依赖下进缓存，第二遍写什么都
# 不影响结果；占位只为「第二遍这份小工程自己也跑得通」，且保持与运行期同形状。
#
# 占位内容：
#   * plugins {} 里的插件 id **从仓库那份 buildSrc/build.gradle.kts 读**，不写死 ——
#     「两边用同一个插件」必须由源码决定，靠人记同步迟早对不上；
#   * 仓库列表只取 pluginManagement 里那层 repositories（**不能整块复制**
#     pluginManagement，那是 settings 才有的 DSL，放进 build 脚本会报
#     `Unresolved reference 'pluginManagement'`）；
#   * 没有 src/：只解析、不产出。仓库那份里定义的 somcp.patched-local-jars 在第二遍
#     的 app 脚本里已经被注释掉，用不上。
stage_buildsrc_placeholder() {
  local plugin_line
  plugin_line="$(awk '
    /^plugins[[:space:]]*\{/ { inp = 1; next }
    inp && /^\}/ { exit }
    inp && /`[a-z-]+`/ { line = $0 }
    END { if (line != "") print line }
  ' buildSrc/build.gradle.kts | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [ -n "$plugin_line" ] \
    || { echo "[warmup] ERROR: no backtick plugin id in buildSrc/build.gradle.kts; the placeholder needs the same plugin as the real buildSrc" >&2; exit 1; }

  # 截取的是 `repositories { … }` 这一块本身（缩进原样保留），所以下面写进占位
  # 时必须原样 `cat`，**不能加缩进**：加一层空格后那一行就不再以 `repositories`
  # 开头，而是落在 `plugins {}` 块里 —— Kotlin DSL 报
  #   Unresolved reference 'repositories'
  # 而且是配置阶段就失败，整遍预热一分依赖都没下。
  awk '
    /^pluginManagement[[:space:]]*\{/ { inpm = 1; next }
    !inpm { next }
    /^[[:space:]]*repositories[[:space:]]*\{/ { inrepo = 1; depth = 0 }
    inrepo {
      depth += gsub(/\{/, "{")
      depth -= gsub(/\}/, "}")
      print
      if (depth == 0) { exit }
    }
  ' settings.gradle.kts > buildsrc-repositories.tmp
  grep -q 'mavenCentral\|google()\|gradlePluginPortal()' buildsrc-repositories.tmp \
    || { echo "[warmup] ERROR: pluginManagement repositories not found in settings.gradle.kts" >&2; exit 1; }

  rm -rf buildSrc
  mkdir -p buildSrc
  {
    echo '// 由 scripts/cnb/warmup-project.sh 生成：预热第二遍用的 buildSrc 占位。'
    echo '// 插件与仓库选择抄仓库那份 buildSrc —— 预热的工程形状必须等于运行期，'
    echo '// 否则它的插件 marker 不会被预热，运行期的 --offline 复核就会缺件。'
    echo 'plugins {'
    echo "    ${plugin_line}"
    echo '}'
    echo ''
    echo '// 取自仓库 settings.gradle.kts 的 pluginManagement：buildSrc 是 included'
    echo '// build，主工程的仓库声明与 --init-script 的仓库对它都不生效。'
    echo '// 这一段按原文件缩进照抄，不重新缩进 —— 见 stage_buildsrc_placeholder 的注释。'
    cat buildsrc-repositories.tmp
  } > buildSrc/build.gradle.kts
  rm -f buildsrc-repositories.tmp
  echo "[warmup] buildSrc/ replaced with a marker-only placeholder (same plugin as the repo)"
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
  # 模块脚本里另起的 `repositories {}` 也要一并搬进来，否则改写后的工程少掉那几个仓库。
  # 本仓库正好是这种形状：仓库级仓库列表在 `settings.gradle.kts` 的
  # dependencyResolutionManagement 里，而模块级只在 `app/build.gradle.kts` 里 ——
  # 只抄 settings 那一份，预热工程就会少掉模块声明的那几个仓库；第二遍是两遍里
  # 唯一真解析依赖图的一遍，少一个仓库就等于那块依赖没人预热。
  #
  # `repositoriesMode.set(FAIL_ON_PROJECT_REPOS)` 会拦住任何模块级仓库声明（合并进来的
  # 那几条也算），所以合并之后把它从预热工程里删掉：第二遍的 :app 脚本里已经没有任何
  # repositories {}，这条模式没有别的作用。判据落在最终文件上（见下），不靠「sed 命中
  # 了哪一行」—— 文件名与行号一旦对不上，这里就会静默放行一个带模式的工程。
  #
  # 只是照抄，不判断也不去重：预热要覆盖的正是「运行期可能用到的每一个仓库」。
  local module_repos=""
  rm -f module-repositories.tmp
  if [ -f app/build.gradle.kts ]; then
    awk '
      /^repositories[[:space:]]*\{/ { inrepo = 1; depth = 0 }
      inrepo {
        depth += gsub(/\{/, "{")
        depth -= gsub(/\}/, "}")
        print
        if (depth == 0) { exit }
      }
    ' app/build.gradle.kts > module-repositories.tmp
  fi
  if [ -s module-repositories.tmp ]; then
    cat module-repositories.tmp >> settings.gradle.kts.new
    module_repos="app"
  fi
  sed -i '/repositoriesMode\.set([[:space:]]*RepositoriesMode\.FAIL_ON_PROJECT_REPOS)/d' settings.gradle.kts.new
  # 判据落在最终文件上，不依赖 sed 是否命中：模式还在，模块级声明就被拦。
  ! grep -q 'FAIL_ON_PROJECT_REPOS' settings.gradle.kts.new \
    || { echo "[warmup] ERROR: repositoriesMode still FAIL_ON_PROJECT_REPOS in the warmup settings" >&2; exit 1; }
  rm -f module-repositories.tmp
  if [ -n "$module_repos" ]; then
    echo "[warmup] repositories from ${module_repos}/build.gradle.kts merged (FAIL_ON_PROJECT_REPOS dropped)"
  fi
  cat >> settings.gradle.kts.new <<'SETTINGS'

rootProject.name = "cnb-warmup"
include(":app")
SETTINGS
  rm -f dependency-resolution.tmp
  mv settings.gradle.kts.new settings.gradle.kts
}

# --- 两遍执行 ---------------------------------------------------------------
# 顺序不能换，理由见各自函数的注释：
#   1. prepare_runtime_layout → disable_buildsrc_plugin → rewrite_root_script
#      → cold_build
#      （仓库原样，联网，失败即整层失败）
#   2. stage_buildsrc_placeholder → simplify_* → warm_build（最小工程，只打 WARNING）
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

echo "[warmup] pass 2/2: minimal project (buildSrc placeholder, generated :app script)"
stage_buildsrc_placeholder
simplify_app_script
simplify_settings_script

echo "[warmup] project rewritten in $DIR:"
sed 's/^/[warmup]   /' build.gradle.kts
sed 's/^/[warmup]   /' app/build.gradle.kts
sed 's/^/[warmup]   /' buildSrc/build.gradle.kts
sed 's/^/[warmup]   /' settings.gradle.kts

if warm_build > /tmp/cnb-warmup-2.log 2>&1; then
  echo "[warmup] pass 2 OK: minimal project"
else
  echo "[warmup] WARNING: pass 2 (minimal project) failed; the pass-1 cache is kept" >&2
  grep -E "Could not (GET|HEAD|resolve)|rate limit|429|proxy|Connection|timed out" /tmp/cnb-warmup-2.log | tail -n 20 >&2 || true
  tail -n 40 /tmp/cnb-warmup-2.log >&2 || true
fi
