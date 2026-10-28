#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-ktlint.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: ktlint — Kotlin code style check
# 版本钉死 1.5.0（不要升）：仓库基线就是按 1.5.0 的规则集校准的，
# 升版本会引入新规则、把既有代码判红。下载地址与命令保持原样。
set -euo pipefail

KTLINT_VERSION="1.5.0"
cd "${CNB_BUILD_WORKSPACE:-/workspace}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

( cd "$work" && curl -sSLO -L "https://github.com/ktlint/ktlint/releases/download/${KTLINT_VERSION}/ktlint" && chmod +x ktlint )

violations=$("$work/ktlint" --relative "app/src/**/*.kt" 2>&1) || true
if [ -n "$violations" ]; then
  echo "[ktlint] Kotlin code style violations found:" >&2
  echo "$violations" >&2
  exit 1
fi
echo "ktlint check passed."
