#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-license.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: AGPL-3.0-only license compliance check
# 三条判据与原步骤逐条对应：LICENSE 不得删除、被改动时首行仍须是 AGPL、
# 新增源码文件前 30 行须带许可证声明。
set -euo pipefail

BASE="${1:?base revision required}"
cd "${CNB_BUILD_WORKSPACE:-/workspace}"

exit_code=0
if git diff "$BASE"...HEAD --name-only --diff-filter=D | grep -q "^LICENSE$"; then
  echo "[license] The LICENSE file must not be deleted. This project is AGPL-3.0-only." >&2
  exit_code=1
fi
if git diff "$BASE"...HEAD --name-only --diff-filter=M | grep -q "^LICENSE$"; then
  if ! head -n 1 LICENSE | grep -qi "GNU AFFERO GENERAL PUBLIC LICENSE"; then
    echo "[license] The LICENSE file must remain licensed under AGPL-3.0-only." >&2
    exit_code=1
  fi
fi
NEW_SOURCE_FILES=$(git diff "$BASE"...HEAD --name-only --diff-filter=A \
  | grep -E '\.(kt|java|cpp|c|h|hpp|py|rs|go|sh|gradle|groovy)$' || true)
if [ -n "$NEW_SOURCE_FILES" ]; then
  while IFS= read -r file; do
    if ! head -n 30 "$file" | grep -qi "GNU.*Affero.*General.*Public.*License\|AGPL[- ]3\.0\|AGPL-3\.0-only"; then
      echo "[license] New source file '$file' is missing a AGPL-3.0 license header. All new files must be licensed under AGPL-3.0-only." >&2
      exit_code=1
    fi
  done <<< "$NEW_SOURCE_FILES"
fi
if [ $exit_code -eq 0 ]; then
  echo "AGPL-3.0-only compliance check passed."
fi
exit $exit_code
