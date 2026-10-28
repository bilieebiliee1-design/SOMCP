#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/clone-rizin.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Clone Rizin source (v0.9.1)
# 命令与 pin 住的 tag 原样保留；只把「已存在则跳过」的短路保留下来。
#
# 为什么单独成文件而不是写在 .cnb.yml 的多行 script 里：CNB 的多行 script 由
# /bin/sh（dash）执行，`set -euo pipefail` 在 dash 里是非法选项，会以退出码 2
# 直接判死。把判定逻辑放进 bash 脚本，平台用什么 shell 都不再影响判据。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"

if [ ! -d third_party/rizin-src/librz/include ]; then
  git clone --depth 1 --branch v0.9.1 https://github.com/rizinorg/rizin.git third_party/rizin-src
else
  echo "third_party/rizin-src already populated, skipping clone"
fi
