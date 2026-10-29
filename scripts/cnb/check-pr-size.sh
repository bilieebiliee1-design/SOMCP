#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-pr-size.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: PR size check
# >50 文件 / >2000 行为 warning，不阻断（原步骤就是 ::warning::，退出码恒 0）。
set -euo pipefail

BASE="${1:?base revision required}"
cd "${CNB_BUILD_WORKSPACE:-/workspace}"

total_files=$(git diff --name-only "$BASE"...HEAD | wc -l)
total_additions=$(git diff "$BASE"...HEAD --diff-filter=AM --numstat | awk '{s+=$1} END {print s}')
echo "[pr-size] PR stats: $total_files files changed, ~${total_additions:-0} additions"
if [ "$total_files" -gt 50 ]; then
  echo "[pr-size] WARNING: Large PR: $total_files files changed. Consider splitting into smaller, focused PRs."
fi
if [ "${total_additions:-0}" -gt 2000 ]; then
  echo "[pr-size] WARNING: Large PR: ~$total_additions lines added. Consider splitting into smaller, focused PRs."
fi
