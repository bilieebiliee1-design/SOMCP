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
# scripts/cnb/gradle-proxy.init.gradle.kts 把 CI 代理变量桥接进 JVM，
# 并把插件仓库的 Maven Central 前置。
# 参数原样透传，退出码原样返回。
#
# 为什么需要包装而不是改 build.gradle.kts：插件解析发生在构建脚本求值之前，
# 在脚本里设 JVM 属性已经太晚（详见 init script 的注释）。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
INIT_SCRIPT="$WS/scripts/cnb/gradle-proxy.init.gradle.kts"

cd "$WS"

# 为什么这里不能直接 `exec`：镜像预热解决的是「依赖已经下好」，但限流发生在缓存
# 还没建起来的时候（首个 gradle stage 就是 Lint）。失败一次就重跑整条命令：
# 已下载的依赖不会重下，重跑只重新解析。判据不变：真失败重跑仍然失败，
# 且退出码必须原样传出。
ATTEMPTS="${CNB_GRADLE_ATTEMPTS:-3}"
DELAY="${CNB_GRADLE_ATTEMPT_DELAY:-20}"

attempt=1
while :; do
  # 必须用 `cmd || rc=$?`，不能在 `if cmd; then ... fi` 之后再读 `rc=$?`：
  # if 语句本身会把 $? 重置为 0，日志会说「退出码 0」，最后的 `exit "$rc"`
  # 还会把真失败当成成功。
  rc=0
  gradle --init-script "$INIT_SCRIPT" "$@" || rc=$?
  [ "$rc" -eq 0 ] && exit 0
  if [ "$attempt" -ge "$ATTEMPTS" ]; then
    echo "[gradle] 第 ${attempt}/${ATTEMPTS} 次运行失败（退出码 ${rc}），放弃" >&2
    exit "$rc"
  fi
  echo "[gradle] 第 ${attempt}/${ATTEMPTS} 次运行失败（退出码 ${rc}），${DELAY}s 后重跑同一命令" >&2
  sleep "$DELAY"
  DELAY=$((DELAY * 2))
  attempt=$((attempt + 1))
done
