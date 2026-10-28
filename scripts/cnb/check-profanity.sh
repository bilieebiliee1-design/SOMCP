#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/check-profanity.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Profanity check
# PATTERNS 词表与匹配方式（diff 全文 + grep -i -E，仅 AM 变更）原样迁移。
set -euo pipefail

BASE="${1:?base revision required}"
cd "${CNB_BUILD_WORKSPACE:-/workspace}"

PATTERNS="\bfuck\b|\bshit\b|\bbitch\b|\bass\b|\bdamn\b|\bcrap\b|\bdick\b|\bbastard\b|\bslut\b|\bwhore\b|\bpiss\b|\bcock\b|\bcunt\b|\basshole\b|\bmotherfucker\b|\bfucker\b|\bfucking\b|\bsonofabitch\b|\b混蛋\b|\b傻逼\b|\b操你妈\b|\b草泥马\b|\b他妈\b|\b尼玛\b|\b艹\b|\bfuckyou\b|\bfk\b"
violations=$(git diff "$BASE"...HEAD --diff-filter=AM \
  | grep -n -i -E "$PATTERNS" \
  | sed 's/^/  /' || true)
if [ -n "$violations" ]; then
  echo "[profanity] Profanity detected in the following diff lines:" >&2
  echo "$violations" >&2
  exit 1
fi
echo "Profanity check passed."
