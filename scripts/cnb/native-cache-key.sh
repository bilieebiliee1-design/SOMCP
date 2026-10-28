#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/native-cache-key.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Cache native backends (Rizin + LIEF)
#   key: native-linux-${{ hashFiles('build-native-android.sh', 'rizin-cross-*.ini',
#                                   'rizin-native.ini', 'app/src/main/cpp/CMakeLists.txt') }}
#        -ndk29-rizin091
#
# CNB 侧没有 actions/cache。CNB 的节点缓存不按 key 失效，直接照搬会出现
# 「改了 build-native-android.sh，仍复用旧归档」的静默错误——比不缓存更糟。
# 因此这里保留 actions/cache 真正起作用的那个语义：**key 变了就必须重编**。
#   * key 未变：保留 rizin-build/ 与 third_party/lief-build/，脚本自身的
#     「归档已存在则跳过」短路让重编成本接近零；
#   * key 变化：清空两个产物目录，强制完整重建。
# 跨流水线持久化交给 CNB 数据卷（见 .cnb.yml 的 volumes）。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"

# key 文件放在与产物同一个 data 卷里：它会随流水线销毁，作用域与产物一致，
# 不会出现「key 记住了但产物没了」或反过来的错位。
NATIVE_STORE="${NATIVE_BUILD_STORE:-/native-build}"
if [ -d "$NATIVE_STORE" ]; then
  KEY_FILE="$NATIVE_STORE/native-cache.key"
else
  KEY_FILE="$WS/.ci-tmp/native-cache.key"
fi
mkdir -p "$(dirname "$KEY_FILE")"

# hashFiles 的等价物：把各输入文件的内容拼起来求 sha256，缺文件时按空内容计入
# （与 actions/cache 的 hashFiles 一致：文件不存在不会报错，只是 hash 里没有它）。
mapfile -t INPUTS < <(
  printf '%s\n' build-native-android.sh rizin-native.ini \
    app/src/main/cpp/CMakeLists.txt
  ls -1 rizin-cross-*.ini 2> /dev/null | sort
)
NEW_KEY="native-linux-$(
  for f in "${INPUTS[@]}"; do
    if [ -f "$f" ]; then cat "$f"; else echo "<missing:$f>"; fi
  done | sha256sum | cut -d' ' -f1
)-ndk29-rizin091"

echo "[native-cache] key: $NEW_KEY"
echo "[native-cache] inputs: ${INPUTS[*]}"

if [ -f "$KEY_FILE" ] && [ "$(cat "$KEY_FILE")" = "$NEW_KEY" ]; then
  echo "[native-cache] key unchanged; keeping existing native archives"
else
  echo "[native-cache] key changed or absent; dropping stale native archives"
  # 产物目录通常已被 setup-build-env.sh 软链到 data 卷上（在那里就等于在卷里），
  # 但也可能仍是工作区内的真实目录（卷不可用时的回退路径）。
  # 软链要清的是链接指向的内容而不是链接本身，否则后续 stage 会失去这个共享入口。
  for dir in "$WS/rizin-build" "$WS/third_party/lief-build"; do
    if [ -L "$dir" ]; then
      find "$(readlink -f "$dir")" -mindepth 1 -delete 2> /dev/null || true
    else
      rm -rf "$dir"
    fi
  done
fi
printf '%s' "$NEW_KEY" > "$KEY_FILE"
