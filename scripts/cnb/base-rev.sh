#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/base-rev.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# 计算 PR / push 的 base revision，并写进 CNB 的环境变量导出通道。
#
# 对应 Test v10 的 "Determine base revision" 步骤（id: base-rev）：
#   pull_request → github.event.pull_request.base.sha（PR 目标分支基线）
#   其它事件     → HEAD~1（推送前一个提交）
#
# 平台差异：
#   * github.event_name            → CNB_EVENT
#   * base.sha                     → CNB_PULL_REQUEST_TARGET_SHA；
#     它按文档取「目标分支最新 SHA」，而 GitHub 的 base.sha 是 PR 分叉点，
#     fetch-depth: 0 的等价物是「本地有完整历史」，所以这里取 merge-base
#     还原成分叉点；取不到（浅克隆 / 无关历史）时退回目标分支 SHA。
#   * GITHUB_OUTPUT                → ##[set-output k=v]，再由 job exports 导出
#
# 输出：BASE_REV（通过 ##[set-output base=...] 提供给后续 stage）
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"

EVENT="${CNB_EVENT:-}"
if [ "$EVENT" = "pull_request" ]; then
  [ -n "${CNB_PULL_REQUEST_TARGET_SHA:-}" ] \
    || { echo "[base-rev] ERROR: CNB_PULL_REQUEST_TARGET_SHA is empty on a pull_request event" >&2; exit 1; }
  TARGET="$CNB_PULL_REQUEST_TARGET_SHA"
  # 完整历史才能算分叉点；拿不到就退回目标分支头（判据不变，只是基线更靠后）
  BASE="$(git merge-base "$TARGET" HEAD 2> /dev/null || echo "$TARGET")"
  echo "[base-rev] pull_request: base.sha≈$BASE (target $TARGET)"
else
  # push / workflow_dispatch：原工作流同样用 HEAD~1，不用 CNB_BEFORE_SHA，
  # 原因是最新提交在 base 分支上的时候两者才等价，HEAD~1 语义更稳（见
  # .github/workflows/test-v10.yml 的 history）。保持原样是为了不改变判据。
  BASE="HEAD~1"
  echo "[base-rev] $EVENT: base=HEAD~1 (CNB_BEFORE_SHA=${CNB_BEFORE_SHA:-unset})"
fi

echo "##[set-output base=$BASE]"
