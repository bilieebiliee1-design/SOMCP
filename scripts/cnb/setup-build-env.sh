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
# 表示「不复用、也不写远程缓存」。这里用的 /gradle-home 是 data 类型卷，
# 只在本次流水线内跨 stage 共享，流水线结束即销毁。
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/gradle-home}"
mkdir -p "$GRADLE_USER_HOME"
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
