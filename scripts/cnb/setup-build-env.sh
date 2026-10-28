#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/setup-build-env.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# 校验 CNB 容器里由 image/cnb-tools.Dockerfile 提供的工具链，并核对
# third_party/ 下的原生依赖是否齐全。
#
# 为什么需要它：GitHub 侧这些由 actions/checkout（submodules: recursive）、
# actions/setup-java、gradle/actions/setup-gradle、android-actions/setup-android
# 保证；CNB 侧没有对应动作，只能用「镜像预装 + 运行期断言」达到同样的保证。
# 少了 submodule 不会让构建失败，只会产出缺原生后端的 APK（unidbg 缺库时
# emulate_* 返回 EMULATOR_UNAVAILABLE），静默降级，所以必须显式失败。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"

log() { echo "[setup] $*"; }
fail() {
  # CNB 没有 ::error:: 注解，失败一律落到 stderr + 退出码。
  echo "[setup] ERROR: $*" >&2
  exit 1
}

# --- JDK 17 ----------------------------------------------------------------
JAVA_MAJOR="$(java -XshowSettings:properties -version 2>&1 \
  | sed -n 's/^ *java\.specification\.version = //p' | head -1)"
[ "$JAVA_MAJOR" = "17" ] \
  || fail "Java 17 required (found '${JAVA_MAJOR:-none}'); the image must ship Temurin 17 like setup-java does upstream"
log "java: $(java -version 2>&1 | head -1)"

# --- Gradle ----------------------------------------------------------------
# 仓库故意不提交 gradlew / gradle-wrapper.jar（见 build.yml 的注释），
# 所以这里只能用发行版 gradle，不能改用 ./gradlew。
command -v gradle > /dev/null || fail "gradle not on PATH"
GRADLE_ACTUAL="$(gradle --version 2> /dev/null | sed -n 's/^Gradle //p' | head -1)"
[ "$GRADLE_ACTUAL" = "9.6.1" ] \
  || fail "Gradle 9.6.1 required (found '${GRADLE_ACTUAL:-none}'); keep it in step with gradle/wrapper/gradle-wrapper.properties"
# 缓存语义与原工作流一致：gradle/actions/setup-gradle 的 cache-disabled: true
# 表示「不复用、也不写远程缓存」。这里用的 /root/.gradle 是 data 类型卷，
# 只在本次流水线内跨 stage 共享，流水线结束即销毁。
#
# 卷必须挂在镜像 ENV 写死的位置：环境变量不跨 stage 传递，各 stage 的
# GRADLE_USER_HOME 取的是镜像里的值，不是上一 stage export 的值。挂在
# /gradle-home 再 export 是无效的，实测表现为每个 stage 都用空用户目录、
# 现场冲网解析插件（Plugin ... was not found）。
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/root/.gradle}"
mkdir -p "$GRADLE_USER_HOME/init.d"
# data 卷首次挂载是空目录，把镜像里预置的用户目录（init script + 预热好的依赖）
# 搬进去。只在 init script 还不存在时搬：后续 stage 复用同一份卷，重搬会覆盖
# 本流水线刚下好的缓存。
GRADLE_IMAGE_HOME="${GRADLE_IMAGE_HOME:-/opt/gradle-user-home}"
if [ -d "$GRADLE_IMAGE_HOME" ] && [ ! -e "$GRADLE_USER_HOME/init.d/cnb-init.gradle" ]; then
  cp -a "$GRADLE_IMAGE_HOME/." "$GRADLE_USER_HOME/" 2> /dev/null || true
fi
[ -f "$GRADLE_USER_HOME/init.d/cnb-init.gradle" ] \
  || fail "missing $GRADLE_USER_HOME/init.d/cnb-init.gradle (image warmup did not run)"
# 复核脚本由 gradle-init.gradle 的 deployCacheOnlyScript 从 /opt/cnb 投放；
# 缺了它 -PcnbCacheOnlyCheck 会在求值 init script 时就抛错，报错点比
# 「缓存不完整」更难读，所以这里补一条断言（init script 那边只打 warning）。
[ -f "$GRADLE_USER_HOME/cnb-cache-only.gradle" ] \
  || fail "missing $GRADLE_USER_HOME/cnb-cache-only.gradle (image must COPY scripts/cnb/gradle-cache-only.gradle)"

# 复核镜像里的预热结果：镜像构建时预热失败不判死镜像（否则一次网络抖动就要
# 连 SDK/NDK 一起重建），改为在这里用 --offline 复跑一次 `gradle help` ——
# 离线跑得通，说明插件与构建期依赖确实都在用户目录里；跑不通就是缓存不完整，
# 当场失败，报错点比后面某个 stage 的 "Plugin ... was not found" 近得多。
#
# 必须跟运行期同一条路：`scripts/cnb/gradle.sh`（同一个 API 级 init script →
# 必要时走代理）+ 预热自己用的那份 init script。早先这里跑的是**裸 gradle**，
# 既不给 proxy init script 也不给 api-version 对齐，于是预热带代理、复核不带，
# 两边根本不是同一个判据；而镜像里 GRADLE_USER_HOME 也不是 bash 的 export，
# 裸 gradle 读不到。改为直接复用 shim：shim 里已经 cd 到工作区并透传参数。
#
# 判据是「缓存里有没有」，不是「网通不通」：`--offline` 只是禁止联网，Gradle 仍然
# 会按各仓库的名字去 $GRADLE_USER_HOME 里找缓存，网络不可达时同样报
#   Plugin [id: ...] was not found in any of the following sources: Google, cnb-plugin-mirror-0(...)
# —— 「缓存里的插件索引在、但远端此刻连不上」会被误报成「镜像预热没做完」。
# 所以额外传 -PcnbCacheOnlyCheck，由 gradle-proxy.init.gradle.kts 把仓库列表原样
# 换成本地空目录（顺序、数量都不变，靠 repo-info.json 把缓存索引指回原 url）：
# 命中缓存 = 通过，没命中 = 真的没预热到（overlay 与缓存 key 绑定，镜像重建后
# 第一次运行必然是空缓存，这时才该指向 Dockerfile 的预热段）。
# 代价是「缓存里有这份构件、但索引对不上」时也要判失败 —— 这是想要的严格：
# 运行期用的正是同一份索引。
WARMUP_CHECK="${GRADLE_WARMUP_CHECK:-1}"
if [ "$WARMUP_CHECK" = "1" ]; then
  if ( cd "$WS" && GRADLE_USER_HOME="$GRADLE_USER_HOME" \
       bash scripts/cnb/gradle.sh --offline -q -PcnbCacheOnlyCheck help > /tmp/cnb-warmup-check.log 2>&1 ); then
    log "gradle user home: warmup cache verified (cache-only help OK)"
  else
    log "gradle user home: warmup cache is incomplete (see tail below)"
    if grep -q 'cnb-cache-only' /tmp/cnb-warmup-check.log; then
      log "hint: the base image was rebuilt with a new cache key, so docker:cache produced a"
      log "hint: fresh overlay with an empty Gradle user home. A re-run of this same pipeline"
      log "hint: (same key) reuses it, but the cache is only populated once the image is built"
      log "hint: with network access to Google / Maven Central (image/cnb-tools.Dockerfile)."
      log "hint: every repository listed in the rejection is normally the same list the image"
      log "hint: warmed up; if this repeats with a populated cache, check the repo-info.json"
      log "hint: trick in scripts/cnb/gradle-cache-only.gradle."
    fi
    tail -n 40 /tmp/cnb-warmup-check.log >&2 || true
    fail "gradle warmup cache is incomplete: cache-only \`gradle help\` failed. Either the image warmup step (image/cnb-tools.Dockerfile) did not finish, or the docker:cache overlay was recreated with an empty user home; copy the tail above into the PR before re-running (set GRADLE_WARMUP_CHECK=0 to skip this check while debugging)"
  fi
  rm -f /tmp/cnb-warmup-check.log
fi
log "gradle: ${GRADLE_ACTUAL} (GRADLE_USER_HOME=${GRADLE_USER_HOME}, data volume, no cross-build cache)"

# --- Android SDK / NDK -----------------------------------------------------
[ -n "${ANDROID_HOME:-}" ] || fail "ANDROID_HOME is not set"
[ -d "${ANDROID_HOME}/platforms/android-36" ] || fail "missing Android SDK platform android-36 under ${ANDROID_HOME}"
[ -d "${ANDROID_HOME}/build-tools/36.0.0" ] || fail "missing Android build-tools 36.0.0 under ${ANDROID_HOME}"
[ -f "${ANDROID_HOME}/ndk/29.0.14206865/ndk-build" ] \
  || fail "missing Android NDK 29.0.14206865 (dcc needs its ndk-build) under ${ANDROID_HOME}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_HOME}/ndk/29.0.14206865}"
log "android sdk: ${ANDROID_HOME} (ndk ${ANDROID_NDK_HOME})"

# 原生构建产物目录换成 data 卷，再由软链接回仓库相对路径：build-native-android.sh
# 与 app/src/main/cpp/CMakeLists.txt 里写的都是仓库内的相对路径（rizin-build/、
# third_party/lief-build/），把它们指到卷上即可跨 stage 共享，且脚本无需改动。
# 卷路径不能与 CNB_BUILD_WORKSPACE 互相包含，所以只能这样软链。
NATIVE_STORE="${NATIVE_BUILD_STORE:-/native-build}"
if [ -d "$NATIVE_STORE" ]; then
  for pair in "rizin-build:rizin-build" "third_party/lief-build:lief-build"; do
    link="${pair%%:*}"
    target="$NATIVE_STORE/${pair##*:}"
    mkdir -p "$target"
    if [ -L "$link" ]; then
      rm -f "$link"
    elif [ -e "$link" ]; then
      # 非软链（例如上一次遗留的真实目录）：内容已经在卷外，直接搬过去再软链。
      cp -a "$link/." "$target/" 2> /dev/null || true
      rm -rf "$link"
    fi
    mkdir -p "$(dirname "$link")"
    ln -s "$target" "$link"
  done
  log "native build outputs linked into ${NATIVE_STORE}"
else
  log "warning: ${NATIVE_STORE} missing; native outputs stay inside the workspace"
fi

# --- 宿主机原生构建工具 ----------------------------------------------------
# 对应原工作流 "Install native build tools" / Blutter 步骤里的 apt-get 安装。
for tool in meson ninja cmake gcc g++ pkg-config python3 git; do
  command -v "$tool" > /dev/null || fail "missing host build tool '$tool'"
done
# app/generate_header.py 由 CMake 在配置期调用（生成 key_generated.h）。CMake 侧
# 已经先 find_program(NAMES python python3) 再调用，找不到会自己报清楚；这里断言
# python3 是为了让「镜像少装了解释器」在流水线早期暴露，而不是等到 Debug 构建的
# CMake 配置里 —— 那里失败了也只有一句 [key-gen]，红点还会落到后面 Dex2C 的
# no release APK 上。
command -v python3 > /dev/null \
  || fail "missing python3 on PATH (app/generate_header.py is invoked at CMake configure time)"
log "host tools: $(meson --version | sed 's/^/meson /')$(ninja --version | sed 's/^/ ninja /')$(cmake --version | head -1 | sed 's/^/ /')"

# --- submodule 完整性 ------------------------------------------------------
# 与 checkout 的 submodules: recursive 对齐：这里只断言，不负责拉取。
# CNB 代码准备阶段默认拉取 submodule（pipeline 的 git.submodules.enable 已显式声明），
# 但拉取失败/被跳过时工作区仍会留下空目录，必须当场拦下。
mapfile -t SUBMODULES < <(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' | awk '{print $2}')
[ "${#SUBMODULES[@]}" -gt 0 ] || fail "no submodules parsed from .gitmodules"
missing=()
for path in "${SUBMODULES[@]}"; do
  if [ ! -d "$path" ] || [ -z "$(ls -A "$path" 2> /dev/null)" ]; then
    missing+=("$path")
  fi
done
[ "${#missing[@]}" -eq 0 ] \
  || fail "third_party submodules not checked out (native backends would silently degrade): ${missing[*]}"
log "submodules: ${#SUBMODULES[@]} present"

echo "[setup] toolchain OK"
