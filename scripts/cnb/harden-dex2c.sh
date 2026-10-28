#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/harden-dex2c.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Harden release APKs with Dex2C (dcc)   [timeout-minutes: 90]
#
# 逐行迁移，只改平台相关变量：
#   $GITHUB_WORKSPACE → ${CNB_BUILD_WORKSPACE:-/workspace}
#   $RUNNER_TEMP      → ${WORK_ROOT}（工作区内自建临时目录，流水线结束即消失）
#   ${{ secrets.* }}  → 由 prepare-keystore 导出的 STORE_FILE / *_PASSWORD / KEY_ALIAS
# 所有 pin 值（dcc commit、apktool 2.12.1、build-tools/ndk 路径）保持不变。
#
# 判据（任一不满足即失败，宁可不发也不发一个「声称加固」的包）：
#   * filter 里的 "=" 目标必须真的被转换；
#   * 每个 lib/<abi>/ 都要有 libnc.so；
#   * 重打包后必须用发布密钥重新 zipalign + apksigner。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
WORK_ROOT="${WORK_ROOT:-$WS/.ci-tmp}"
cd "$WS"

DCC_COMMIT="17de4fd3202bd0e46735974211a43cda39fca5f3" # dcc master @ 2024-02-07
APKTOOL_VERSION="2.12.1"                              # 2.x keeps the CLI dcc was written against
BUILD_TOOLS="${ANDROID_HOME}/build-tools/36.0.0"
NDK_DIR="${ANDROID_HOME}/ndk/29.0.14206865"
WORK="$WORK_ROOT/dex2c"
FILTER="$WS/tools/dex2c/filter.txt"
STORE_FILE="${STORE_FILE:-$WS/release/so-reverse-mcp-release.jks}"
STORE_PASSWORD="${STORE_PASSWORD:-}"
KEY_ALIAS="${KEY_ALIAS:-}"
KEY_PASSWORD="${KEY_PASSWORD:-}"

mkdir -p "$WORK"

# dcc 用 ndk-build 造 libnc.so。布局若变，在这里给出可执行的报错，
# 而不是让 dcc 深处抛异常。
test -x "$NDK_DIR/ndk-build" || {
  echo "[dex2c] ndk-build not found at $NDK_DIR/ndk-build; dcc needs it to build libnc.so" >&2
  exit 1
}
test -f "$FILTER" || {
  echo "[dex2c] Dex2C filter $FILTER is missing" >&2
  exit 1
}

rm -rf "$WORK/dcc"
git clone --quiet https://github.com/amimo/dcc.git "$WORK/dcc"
git -C "$WORK/dcc" checkout --quiet "$DCC_COMMIT"
# dcc 无条件用自带的 signapk.jar 给 apktool 重建的 APK 签名，而它 import 了
# Java 9 起已移除的 sun.misc.BASE64Encoder，在 JDK 17 下会 NoClassDefFoundError。
# 那个测试密钥签名本来就是一次性的（下面会重新对齐并用发布密钥重签），
# 因此把 signapk 调用替换成纯拷贝。
python3 - "$WORK/dcc/dcc.py" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
src = p.read_text()
old = "subprocess.check_call(['java', '-jar', SIGNJAR, pem, pk8, unsigned_apk, signed_apk])"
if old not in src:
    raise SystemExit("signapk call not found in dcc.py; pinned dcc moved")
p.write_text(src.replace(old, "shutil.copyfile(unsigned_apk, signed_apk)"))
PY
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --quiet --disable-pip-version-check \
  -r "$WORK/dcc/requirements.txt"
curl -fsSL --retry 3 -o "$WORK/dcc/tools/apktool.jar" \
  "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
# dcc 相对自身目录解析 dcc.cfg / filter.txt / project/，因此从那里驱动、传绝对路径。
printf '{"apktool": "%s", "ndk_dir": "%s"}\n' \
  "$WORK/dcc/tools/apktool.jar" "$NDK_DIR" > "$WORK/dcc/dcc.cfg"

# 小工具：ABI 列表与 zip 条目检查。runner 的 python 本就是 dcc 的依赖，
# 不必为这两件事再引额外工具。
cat > "$WORK/abilist.py" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    abis = {n.split('/')[1] for n in z.namelist()
            if n.startswith('lib/') and n.count('/') >= 2}
print(' '.join(sorted(abis)))
PY
cat > "$WORK/zipcheck.py" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    names = set(z.namelist())
missing = [n for n in sys.argv[2:] if n not in names]
for n in missing:
    print('missing entry: %s' % n)
sys.exit(1 if missing else 0)
PY
cat > "$WORK/filtercheck.py" <<'PY'
import sys

filter_path, compiled_path = sys.argv[1], sys.argv[2]

# filter 里的 "=" 条目是精确全名匹配（dcc 放进 set 做字符串相等判断，不是正则），
# 因此每一条都必须逐字出现在转换结果里。dcc 找不到目标时什么都不报，
# 只有这个断言能挡住「类被改名/删除后，方法悄悄以字节码形式发布」。
targets = []
with open(filter_path) as fp:
    for line in fp:
        line = line.strip()
        if line.startswith('='):
            targets.append(line[1:].strip())

with open(compiled_path) as fp:
    converted = set(fp.read().splitlines())

missing = [t for t in targets if t not in converted]
for name in missing:
    print('not converted: %s' % name)
if missing:
    sys.exit(1)

# dcc 写入时没有行尾换行，所以报真实条数而不是 wc -l。
print('%d/%d filter target(s) converted' % (len(targets), len(targets)))
for name in targets:
    print('    %s' % name)
PY

cd "$WORK/dcc"
shopt -s nullglob
APKS=("$WS"/app/build/outputs/apk/release/*.apk)
shopt -u nullglob
[ "${#APKS[@]}" -gt 0 ] || {
  echo "[dex2c] no release APK found under $WS/app/build/outputs/apk/release/" >&2
  exit 1
}

for apk in "${APKS[@]}"; do
  base="$(basename "$apk")"

  # dcc 要求 APK 里每个 lib/<abi>/ 都有 libnc.so（否则 copy_compiled_libs 抛
  # "ABI <abi> is not supported!"），而它 2019 年的 Application.mk 只造
  # android-19 的 arm64-v8a/armeabi-v7a —— 平台 NDK 29 已不接受。
  # 两个值都从 APK 自身推导：ABI 分包只有一个 ABI，通用包四个都有。
  # APP_PLATFORM 抬到 app 的 minSdk。
  abis="$("$WORK/venv/bin/python" "$WORK/abilist.py" "$apk")"
  if [ -z "$abis" ]; then
    echo "[dex2c] $base has no lib/<abi>/ entries, so dcc cannot know which ABIs to build" >&2
    exit 1
  fi
  sed -i -e "s|^APP_ABI.*|APP_ABI := $abis|" \
    -e "s|^APP_PLATFORM.*|APP_PLATFORM := android-26|" \
    "$WORK/dcc/project/jni/Application.mk"

  mkdir -p "$WORK/out"
  out="$WORK/out/$base"
  # --source-dir 保留生成的 C 源码作为日志/证据，也是 dcc 造 libnc.so 的输入；
  # 同时让 dcc 跳过它自己的 project-source.zip 归档。
  src="$WORK/src/$base"
  "$WORK/venv/bin/python" dcc.py "$apk" -o "$out" \
    --filter "$FILTER" --source-dir "$src"

  # filter 一个都没命中时 dcc 不写输出 APK（类被 R8 改名或删除），
  # 部分转换同样不可接受：两者都必须让发布失败。
  test -f "$out" || {
    echo "[dex2c] dcc produced no hardened APK for $base: tools/dex2c/filter.txt matched no method" >&2
    exit 1
  }
  converted="$src/jni/nc/compiled_methods.txt"
  # 断言 filter 里每个 "=" 目标真的被转换。只 grep 类前缀不够：
  # 一个方法留下就能让检查全绿，其余七个悄悄以字节码发布。
  "$WORK/venv/bin/python" "$WORK/filtercheck.py" "$FILTER" "$converted" | sed 's/^/    /' || {
    echo "[dex2c] $base: a tools/dex2c/filter.txt target is missing from $converted" >&2
    exit 1
  }

  for abi in $abis; do
    "$WORK/venv/bin/python" "$WORK/zipcheck.py" "$out" "lib/$abi/libnc.so" || {
      echo "[dex2c] $base is missing lib/$abi/libnc.so after Dex2C" >&2
      exit 1
    }
  done

  # apktool 重建过 APK（gradle 的签名已失效），dcc 又用自带的测试密钥签了名。
  # 用发布密钥重新对齐并重签：测试密钥签的产物既无法覆盖安装已装的 SOMCP，
  # 也会触发 app 自己的签名 pin。先签到一个临时路径，失败也不会毁掉
  # gradle 产出的 APK。
  "$BUILD_TOOLS/zipalign" -f -p 4 "$out" "$WORK/aligned-$base"
  "$BUILD_TOOLS/apksigner" sign \
    --ks "$STORE_FILE" \
    --ks-pass "pass:$STORE_PASSWORD" \
    --ks-key-alias "$KEY_ALIAS" \
    --key-pass "pass:$KEY_PASSWORD" \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled true \
    --out "$WORK/signed-$base" \
    "$WORK/aligned-$base"
  mv -f "$WORK/signed-$base" "$apk"
  echo "[dex2c] $base hardened, re-aligned and re-signed with the release key"
done
echo "Dex2C hardening applied to every release APK."
