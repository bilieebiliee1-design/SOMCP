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
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
INIT_SCRIPT="$WS/scripts/cnb/gradle-proxy.init.gradle.kts"

cd "$WS"
exec gradle --init-script "$INIT_SCRIPT" "$@"
