#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-native-tools.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Install native build tools
#   sudo apt-get install -y --no-install-recommends meson ninja-build gcc g++ pkg-config
#
# 迁移说明：镜像会在流水线开始前把上述工具装进容器（见
# image/cnb-tools.Dockerfile），运行期再 apt-get 只会额外拉一次索引。
# 所以这一步退化为「断言工具存在且能跑」——判据不变（缺工具则后续
# build-native-android.sh 必然失败），但失败点提前且有清晰报错。
set -euo pipefail

fail=0
check() {
  local bin="$1" label="$2"
  if command -v "$bin" > /dev/null; then
    echo "[native-tools] OK   $label ($bin)"
  else
    echo "[native-tools] MISSING $label ($bin)" >&2
    fail=1
  fi
}

check meson "meson"
check ninja "ninja-build"
check gcc "gcc"
check g++ "g++"
check pkg-config "pkg-config"
# CMake 未出现在原步骤里，但 LIEF 段用 CMake -G Ninja 交叉编译，缺了必然失败。
check cmake "cmake"

if [ "$fail" -ne 0 ]; then
  echo "[native-tools] install the missing packages in image/cnb-tools.Dockerfile" >&2
  exit 1
fi

echo "[native-tools] versions: meson $(meson --version), ninja $(ninja --version), $(gcc -dumpversion | sed 's/^/gcc /'), $(cmake --version | head -1)"
