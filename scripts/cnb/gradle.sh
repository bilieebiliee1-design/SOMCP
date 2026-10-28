#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/gradle.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# CNB 侧的 gradle 入口：等价于原工作流里的裸 `gradle ...`，额外带上
# scripts/cnb/gradle-proxy.init.gradle.kts 把 CI 代理变量桥接进 JVM。
# 参数原样透传，退出码原样返回。
#
# 为什么需要包装而不是改 build.gradle.kts：插件解析发生在构建脚本求值之前，
# 在脚本里设 JVM 属性已经太晚（详见 init script 的注释）。
#
# 为什么外层还要重试：`Plugin [id: 'org.jetbrains.kotlin.android', version: '2.4.0']
# was not found in any of the following sources` 在 CI 上的真实成因常是 Maven Central
# 的 429 限流（版本本身存在，单独 curl 就是 200）。Gradle 的重试窗口不等，实测
# 仍会漏；这里按「失败 → 等一会儿 → 原命令重跑」复用已经下载好的依赖，
# 冷启动代价主要在第一次拉取，重跑只是重新解析。判据不变：真失败重跑仍然失败。
#
# CNB_GRADLE_ATTEMPTS 可覆盖尝试次数（默认 3），CNB_GRADLE_ATTEMPT_DELAY 为首次退避秒数（默认 20）。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
INIT_SCRIPT="$WS/scripts/cnb/gradle-proxy.init.gradle.kts"
ATTEMPTS="${CNB_GRADLE_ATTEMPTS:-3}"
DELAY="${CNB_GRADLE_ATTEMPT_DELAY:-20}"

cd "$WS"

attempt=1
while :; do
  if gradle --init-script "$INIT_SCRIPT" "$@"; then
    exit 0
  fi
  # gradle 以 0/非 0 表达成败，set -e 不会在这里中断，故用显式 if 捕获。
  rc=$?
  if [ "$attempt" -ge "$ATTEMPTS" ]; then
    echo "[gradle] 第 ${attempt}/${ATTEMPTS} 次运行失败（退出码 ${rc}），放弃" >&2
    exit "$rc"
  fi
  echo "[gradle] 第 ${attempt}/${ATTEMPTS} 次运行失败（退出码 ${rc}），${DELAY}s 后重跑同一命令" >&2
  sleep "$DELAY"
  DELAY=$((DELAY * 2))
  attempt=$((attempt + 1))
done
