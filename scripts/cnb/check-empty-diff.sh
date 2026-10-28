#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-empty-diff.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Check for empty PR
# CNB 平台差异：`::error::` 注解没有对应语法，错误文案原样写到 stderr，
# 用退出码表达失败。
set -euo pipefail

BASE="${1:?base revision required}"
cd "${CNB_BUILD_WORKSPACE:-/workspace}"

changed_files=$(git diff --name-only "$BASE"...HEAD 2> /dev/null || echo "")
if [ -z "$changed_files" ]; then
  echo "[empty-diff] This PR contains no meaningful changes compared to the base branch." >&2
  exit 1
fi
echo "Changed files:"
echo "$changed_files"
