#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/prepare-keystore.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Restore release signing keystore (or CI fallback)
#
# 平台差异：GitHub 侧是仓库 secrets（KEYSTORE / PASSWORD / ALIAS / ALIAS_PASSWORD），
# CNB 侧对应私密仓库 SOMCP/key 的 android-signing.yml，由 stage 的 imports 注入为
# 环境变量（KEYSTORE 是 BASE64 编码的 JKS）。四个变量任一缺失即视为
# 「无 secrets」，走 CI-only 临时 keystore 分支——与原步骤一致，不阻断。
#
# 导出（由 job exports 转成后续 stage 的环境变量）：
#   store_file / store_password / key_alias / key_password
# app/build.gradle.kts 的 release signingConfig 优先读同名环境变量
# （STORE_FILE / STORE_PASSWORD / KEY_ALIAS / KEY_PASSWORD），所以后续
# gradle 任务直接复用导出的值，不必再写 keystore.properties。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
cd "$WS"
mkdir -p release

if [ -n "${KEYSTORE:-}" ] && [ -n "${PASSWORD:-}" ] && [ -n "${ALIAS:-}" ] && [ -n "${ALIAS_PASSWORD:-}" ]; then
  # 真实发布 keystore（BASE64 编码）。
  printf '%s' "$KEYSTORE" | base64 -d > release/so-reverse-mcp-release.jks
  store_file="release/so-reverse-mcp-release.jks"
  store_password="$PASSWORD"
  key_alias="$ALIAS"
  key_password="$ALIAS_PASSWORD"
  {
    echo "storeFile=$store_file"
    echo "storePassword=$store_password"
    echo "keyAlias=$key_alias"
    echo "keyPassword=$key_password"
  } > release/keystore.properties
  echo "Restored release signing keystore from secrets."
else
  # Fallback（例如 fork PR 拿不到 secrets）：CI-only 一次性 keystore，
  # 每次运行随机密钥，不可分发。用它签出的 APK 无法覆盖安装真实发布包
  # （docs/forum-post.md），只用于构建验证。
  STORE_PASS="ci-$(openssl rand -hex 16)"
  keytool -genkeypair -v \
    -storetype JKS \
    -keystore release/so-reverse-mcp-release.jks \
    -alias so-reverse-mcp \
    -keyalg RSA \
    -keysize 2048 \
    -validity 36500 \
    -storepass "$STORE_PASS" \
    -keypass "$STORE_PASS" \
    -dname "CN=SOMCP CI, O=SoReverse MCP, C=CN"
  store_file="release/so-reverse-mcp-release.jks"
  store_password="$STORE_PASS"
  key_alias="so-reverse-mcp"
  key_password="$STORE_PASS"
  {
    echo "storeFile=$store_file"
    echo "storePassword=$store_password"
    echo "keyAlias=$key_alias"
    echo "keyPassword=$key_password"
  } > release/keystore.properties
  echo "Secrets unavailable; generated CI-only signing keystore (not for distribution)."
fi

# 绝对路径供 Dex2C / VMP 步骤使用（那两个脚本会 cd 到别处）。
printf '##[set-output store_file=%s]\n' "$WS/$store_file"
printf '##[set-secret store_password=%s]\n' "$store_password"
printf '##[set-output key_alias=%s]\n' "$key_alias"
printf '##[set-secret key_password=%s]\n' "$key_password"
