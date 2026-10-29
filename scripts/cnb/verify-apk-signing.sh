#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/verify-apk-signing.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Verify and ensure v2/v3 APK signing
#
# 从 release/keystore.properties 读签名配置（上一步写好：要么来自密钥仓库，
# 要么是 CI-only 临时 keystore），逐个 APK 校验；缺 v2/v3 时用 apksigner 重签，
# 最后一律 --print-certs 复核。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"

PROPS="release/keystore.properties"
[ -f "$PROPS" ] || {
  echo "[apksign] $PROPS missing; the keystore stage must run first" >&2
  exit 1
}

storeFile=$(grep '^storeFile=' "$PROPS" | head -1 | cut -d= -f2-)
storePassword=$(grep '^storePassword=' "$PROPS" | head -1 | cut -d= -f2-)
keyAlias=$(grep '^keyAlias=' "$PROPS" | head -1 | cut -d= -f2-)
keyPassword=$(grep '^keyPassword=' "$PROPS" | head -1 | cut -d= -f2-)
APKSIGNER="${ANDROID_HOME}/build-tools/36.0.0/apksigner"

shopt -s nullglob
APKS=(app/build/outputs/apk/release/*.apk)
shopt -u nullglob
[ "${#APKS[@]}" -gt 0 ] || {
  echo "[apksign] no release APK found under app/build/outputs/apk/release/" >&2
  exit 1
}

for apk in "${APKS[@]}"; do
  echo "=== Checking signing schemes: $(basename "$apk") ==="
  if "$APKSIGNER" verify --verbose "$apk" 2>&1 | grep -qi "NOT PRESENT"; then
    echo "[apksign] WARNING: v2/v3 signing NOT verified in $(basename "$apk"); re-signing with apksigner"
    "$APKSIGNER" sign \
      --ks "$storeFile" \
      --ks-pass "pass:$storePassword" \
      --ks-key-alias "$keyAlias" \
      --key-pass "pass:$keyPassword" \
      --v1-signing-enabled true \
      --v2-signing-enabled true \
      --v3-signing-enabled true \
      --v4-signing-enabled true \
      "$apk"
  fi
  "$APKSIGNER" verify --print-certs "$apk"
  echo "OK $(basename "$apk") has valid v2/v3 signing"
done
