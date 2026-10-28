#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - scripts/cnb/harden-vmp.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# GitHub step: Harden release APKs with VMP (shell)   [timeout-minutes: 120]
#
# 逐行迁移，只改平台相关变量：
#   $GITHUB_WORKSPACE → $WS（CNB_BUILD_WORKSPACE）
#   $RUNNER_TEMP      → $WORK_ROOT（工作区内自建临时目录）
#   ${{ secrets.* }}  → prepare-keystore 导出的 STORE_FILE / *_PASSWORD / KEY_ALIAS
#   ::error:: 注解     → "[vmp] ..." 写到 stderr + 非零退出码
# XopProtector / packer / mapping 派生的判据一律未改。
#
# 顺序是承重的：必须在 Dex2C 之后。dcc 通过 androguard 读 classes.dex，而本步骤
# 把所有业务 dex 搬进加密的 assets/rtcore/dexes.zip 并从 APK 删除 classes*.dex
# —— 先跑 VMP 会让 dcc 无 dex 可转，静默不加固。
set -euo pipefail

WS="${CNB_BUILD_WORKSPACE:-/workspace}"
WORK_ROOT="${WORK_ROOT:-$WS/.ci-tmp}"
cd "$WS"

STORE_FILE="${STORE_FILE:-$WS/release/so-reverse-mcp-release.jks}"
STORE_PASSWORD="${STORE_PASSWORD:-}"
KEY_ALIAS="${KEY_ALIAS:-}"
KEY_PASSWORD="${KEY_PASSWORD:-}"
mkdir -p "$WORK_ROOT"

# Virtual-machine protection on top of Dex2C. The selected methods'
# bytecode is translated into a private instruction set (PVM2, image
# format v4) that only the embedded interpreter can execute, so the
# logic is no longer recoverable from any DEX in the package.
#
# ORDER IS load-bearing: this must run AFTER the dcc step. dcc reads
# classes.dex through androguard, while this step moves every business
# dex into an encrypted assets/rtcore/dexes.zip and deletes
# classes*.dex from the APK — running VMP first would leave dcc with
# no dex to convert and silently harden nothing.
#
# The engine (XopProtector, Apache-2.0) is built from a pinned commit
# and its shell is de-branded by tools/vmp/debrand_shell.py before the
# build: upstream publishes the shell's entry-point class names, so a
# stock build would ship a manifest naming the protector and its
# version to anyone who unzips the APK. The patch renames the package,
# the entry classes and the native library consistently across the
# Java sources, the JNI paths hardcoded in C++, and the proguard
# keep rules, and asserts each linkage instead of trusting sed.
VMP_COMMIT="e408b87871ea18e197b189e787c73cc5ae3e2ee6"  # main @ 2026-09-19
WORK="$WORK_ROOT/vmp"
DEBRAND="$WS/tools/vmp/debrand_shell.py"
BUILD_TOOLS="$ANDROID_HOME/build-tools/36.0.0"

mkdir -p "$WORK"

test -f "$DEBRAND" || {
  echo "[vmp] $DEBRAND is missing"
  exit 1
}
# The shell's own build: AGP 8.2.2 pins compileSdk 34 and CMake
# 3.22.1, neither of which the release job installs for the app
# itself (android-36 / the app's own NDK).
# 镜像已预装这两个包（见 image/cnb-tools.Dockerfile）；这里保留等价调用，
# 幂等且能在镜像被改动时立刻暴露，而不是等到壳的 Gradle 构建里才炸。
sdkmanager "platforms;android-34" "cmake;3.22.1"

git clone --quiet https://github.com/xopJack/XopProtector.git "$WORK/shell"
git -C "$WORK/shell" checkout --quiet "$VMP_COMMIT"
# Upstream commits gradlew with mode 100644 (no exec bit, the whole
# tree has zero 100755 entries), so ./gradlew would die with
# "Permission denied" / exit 126 right after checkout.
chmod +x "$WORK/shell/gradlew"
# Upstream lists its author's own SDK directory as UniMP candidates
# via two entries evaluated while settings.gradle.kts loads: a
# hardcoded file("E:/Android/...") and an unimp.sdk.libs property in
# gradle.properties (backslash form, E:\Android\...) fed to the
# property-driven candidate on the line above it. On a Linux runner
# neither literal is a path but a malformed URI: it parses as the
# scheme "E" and the file() call throws URISyntaxException -- before
# Gradle reaches any task of ours. The guard around the candidates
# already treats missing libs as "skip :unimp-host", so dropping
# them is the intended behaviour.
#
# Upstream also commits its author's local.properties
# (sdk.dir=D:\...). exportShellFiles resolves the SDK through
# local.properties BEFORE ANDROID_HOME, so on the runner its d8
# lookup dies with "build-tools not found" (AGP itself falls back
# to ANDROID_HOME, which is why the module build got that far).
# Deleting the file makes both paths resolve the same SDK.
python3 - "$WORK/shell" <<'PATCH'
import os, sys
root = sys.argv[1]
sp = os.path.join(root, "settings.gradle.kts")
src = open(sp, encoding="utf-8").read()
needle = '    file("E:/Android/SDK-Android@5.14-20260706/SDK/libs"),\n'
if needle not in src:
    print("upstream no longer carries that Windows-only candidate;"
          " re-check whether this patch is still needed")
    sys.exit(1)
open(sp, "w", encoding="utf-8", newline="\n").write(src.replace(needle, ""))
gp = os.path.join(root, "gradle.properties")
gsrc = open(gp, encoding="utf-8").read()
glines = [l for l in gsrc.splitlines(keepends=True)
          if not l.strip().startswith("unimp.sdk.libs=")]
open(gp, "w", encoding="utf-8", newline="\n").write("".join(glines))
lp = os.path.join(root, "local.properties")
if os.path.exists(lp):
    os.remove(lp)
print("patched shell: dropped the Windows-only UniMP candidates"
      " (settings.gradle.kts + gradle.properties) and the committed"
      " local.properties")
PATCH
python3 "$DEBRAND" "$WORK/shell"

# :packer:jar is the build-time engine (plain JVM); exportShellFiles
# cross-compiles the on-device librtcore.so for all four ABIs and
# stages the shell dex next to it. -PskipDemo avoids configuring the
# upstream sample app, which needs SDK AARs we do not ship.
( cd "$WORK/shell" && ./gradlew --no-daemon -q :packer:jar exportShellFiles )

PACKER_JAR=$(ls "$WORK/shell"/packer/build/libs/rtcore-packer-*.jar | head -1)
SHELL_DIR="$WORK/shell/executable/shell-files"
test -f "$PACKER_JAR" || { echo "[vmp] packer jar was not built"; exit 1; }
test -f "$SHELL_DIR/dex/classes.dex" || {
  echo "[vmp] $SHELL_DIR/dex/classes.dex missing; shell not exported"
  exit 1
}
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
  test -f "$SHELL_DIR/libs/$abi/librtcore.so" || {
    echo "[vmp] $SHELL_DIR/libs/$abi/librtcore.so missing; shell ABI $abi not built"
    exit 1
  }
done

# The app reads its encrypted assets through the shell's PAS1 entry
# point, resolved reflectively as
# com.soreverse.mcp.rt.shell.NativeBridge.decryptAssetBlob (no
# build-time dependency on the shell exists). The shell's own
# proguard rules -keep that class and its native methods, so the
# names must survive R8 into the exported dex; assert the export
# rather than trusting the keep rule.
grep -aq 'decryptAssetBlob' "$SHELL_DIR/dex/classes.dex" || {
  echo "[vmp] $SHELL_DIR/dex/classes.dex does not carry decryptAssetBlob; the app could not read encrypted assets"
  exit 1
}

# R8 renames every non-kept class, so literal source-name prefixes
# cannot address the shipped dex. Independently verified against the
# restored 1.0.22 dex: only 25 classes still live under
# Lcom/soreverse/mcp/ (keep rules + manifest components); the rest
# moved to short obfuscated roots (a00, dk1, n90, ...). Most renamed
# dex classes are R8-renamed library classes, not app classes — the
# app package itself is ~479 classes (real-CI mapping baseline, see
# the mapprefix.py guard). Both
# --true-vmp-prefix entries for IntegrityGuard/AppListGuard matched
# zero methods in that build, and code.bin carried only ~95 method
# bodies. Derive the real descriptors from the R8 mapping produced by
# this same build instead: every com.soreverse.mcp.* class becomes a
# --hollow-prefix, and the integrity guards additionally become
# --true-vmp-prefix targets.
MAPPING="$WS/app/build/outputs/mapping/release/mapping.txt"
test -f "$MAPPING" || {
  echo "[vmp] R8 mapping.txt not found at $MAPPING; release minify must stay enabled"
  exit 1
}
cat > "$WORK/mapprefix.py" <<'PY'
import os, re, sys
mapping_path, out_dir = sys.argv[1], sys.argv[2]
renamed = {}
with open(mapping_path, encoding="utf-8") as fp:
    for line in fp:
        m = re.match(r"^(\S+) -> (\S+):$", line)
        if not m:
            continue
        orig, new = m.groups()
        if orig.startswith("com.soreverse.mcp."):
            renamed[orig] = "L" + new.replace(".", "/") + ";"
# Floor calibrated on real CI runs (2026-10-14: 479 entries on
# ed32f92 / cebfd86 / PR #163 alike — the earlier ~6800 estimate
# misattributed R8-renamed library classes to the app package). The
# floor exists to catch parse breakage (would parse 0) or a mass
# loss of mapped app classes, not to pin an exact count; 300 keeps
# >35% headroom below the observed baseline. Guard-class presence
# is asserted separately below.
if len(renamed) < 300:
    sys.exit("[vmp] only %d com.soreverse.mcp.* entries parsed from mapping.txt;"
             " obfuscation or mapping format drifted" % len(renamed))
guards = [
    "com.soreverse.mcp.core.IntegrityGuard",
    "com.soreverse.mcp.core.AppListGuard",
    "com.soreverse.mcp.core.SelfArtifactGuard",
]
missing = [g for g in guards if g not in renamed]
if missing:
    sys.exit("[vmp] integrity guard classes absent from mapping.txt (R8 stripped?): "
             + ", ".join(missing))
with open(os.path.join(out_dir, "hollow_prefixes.txt"), "w",
          encoding="utf-8", newline="\n") as fp:
    for desc in sorted(renamed.values()):
        fp.write(desc + "\n")
with open(os.path.join(out_dir, "vmp_prefixes.txt"), "w",
          encoding="utf-8", newline="\n") as fp:
    for g in guards:
        fp.write(renamed[g] + "\n")
print("mapping-derived prefixes: %d hollow classes, true-vmp %s"
      % (len(renamed), " ".join(renamed[g] for g in guards)))
PY
python3 "$WORK/mapprefix.py" "$MAPPING" "$WORK"
HOLLOW_ARGS=()
while IFS= read -r p; do HOLLOW_ARGS+=(--hollow-prefix "$p"); done < "$WORK/hollow_prefixes.txt"
VMP_ARGS=()
while IFS= read -r p; do VMP_ARGS+=(--true-vmp-prefix "$p"); done < "$WORK/vmp_prefixes.txt"

cat > "$WORK/abilist.py" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    abis = {n.split('/')[1] for n in z.namelist()
            if n.startswith('lib/') and n.count('/') >= 2}
print(' '.join(sorted(abis)))
PY
cat > "$WORK/apkcheck.py" <<'PY'
import sys, zipfile
apk, abi = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk) as z:
    names = set(z.namelist())
    manifest = z.read("AndroidManifest.xml")
# The containers plus the renamed native lib prove the shell was
# embedded. config.json/code.bin/dexes.zip are what the on-device
# bootstrap refuses to start without, so all three being present is
# the difference between a protected APK and a broken one.
required = [
    "assets/rtcore/config.json",
    "assets/rtcore/code.bin",
    "assets/rtcore/dexes.zip",
    "lib/%s/librtcore.so" % abi,
]
missing = [n for n in required if n not in names]
for n in missing:
    print("missing entry: %s" % n)
# The binary manifest keeps its string pool as UTF-16LE, so the
# entry-point names appear NUL-interleaved. Compare on the decoded
# form (strip the NULs) rather than hand-writing interleaved literals,
# which cannot be decoded back for the error message.
pool = manifest[-16384:].replace(b"\x00", b"")
for needle, want in ((b"BootstrapEntry", True),
                     (b"BootstrapComponentFactory", True),
                     (b"ProxyApplication", False),
                     (b"ProxyComponentFactory", False)):
    found = needle in pool
    if found != want:
        print("manifest entry-point check failed: %s present=%s expected=%s"
              % (needle.decode("ascii"), found, want))
        missing.append("manifest-entry-point")
sys.exit(1 if missing else 0)
PY


shopt -s nullglob
APKS=("$WS"/app/build/outputs/apk/release/*.apk)
shopt -u nullglob
[ "${#APKS[@]}" -gt 0 ] || {
  echo "[vmp] no release APK found under $WS/app/build/outputs/apk/release/" >&2
  exit 1
}

for apk in "${APKS[@]}"; do
  base="$(basename "$apk")"
  out="$WORK/vmp/$base"
  mkdir -p "$WORK/vmp"

  # --hollow-prefix (not --profile aggressive) is what actually hollows
  # the app package: the balanced profile is encrypt-first and hollows
  # nothing on its own, while an explicit prefix allowlist is honoured
  # on every profile except max. It still skips Android components
  # (Activity/Service/Provider/...), which is required — upstream notes
  # hollowing a component body to a stub raises VerifyError on
  # Android 14+.
  #
  # The literal prefix only reaches classes that survive R8 with their
  # names (kept classes + manifest components). "${HOLLOW_ARGS[@]}"
  # carries the mapping-derived descriptors for every renamed
  # com.soreverse.mcp.* class, and "${VMP_ARGS[@]}" the renamed
  # integrity-guard classes for TRUE_VMP. BackupCrypto is keep-ruled
  # and stays addressable by its literal name. Real volume: 479
  # hollow classes (2026-10-14 CI baseline), far under the 65535
  # per-dex record cap of the code.bin container format.
  #
  # --no-protect-so: RC4-encrypting .text would fight this app's own
  # integrity checks (native_probe.cpp verifies its shipped payload)
  # and force dlopen interception for four ABIs' worth of Rizin/LIEF
  # libraries, for a layer this release does not claim.
  #
  # --encrypt-assets: every business asset under assets/** is stored
  # as PAS1 || AES-GCM at assets/rtcore/aenc/<path> and the plaintext
  # entry is deleted; assets/rtcore/** (the shell's own containers) is
  # excluded by the packer itself. There is no transparent
  # AssetManager hook, so this flag and the app's read path are ONE
  # contract: the app resolves ShellAssets -> the shell's
  # NativeBridge.decryptAssetBlob reflectively (plaintext fallback for
  # un-shelled builds). Flipping the flag without that read path ships
  # an APK whose assets are unreadable at runtime.
  java -jar "$PACKER_JAR" "$apk" -o "$out" \
    --shell-dir "$SHELL_DIR" \
    --profile balanced \
    --hollow-prefix 'Lcom/soreverse/mcp/' \
    --true-vmp-prefix 'Lcom/soreverse/mcp/core/BackupCrypto;' \
    "${HOLLOW_ARGS[@]}" \
    "${VMP_ARGS[@]}" \
    --no-protect-so \
    --encrypt-assets \
    --no-res-protect \
    --keystore "$STORE_FILE" \
    --alias "$KEY_ALIAS" \
    --storepass "$STORE_PASSWORD" \
    --keypass "$KEY_PASSWORD" | tee "$WORK/vmp-$base.log"

  test -f "$out" || {
    echo "[vmp] VMP produced no output APK for $base"
    exit 1
  }

  # The engine must have actually virtualized something, otherwise
  # the APK is only encrypted and the release note would overstate it.
  # Successful PVM2 compilations print "TRUE_VMP <descriptor>->..."
  # while failures print "TRUE_VMP skip ...", so the count is anchored
  # on the descriptor's leading "L". Zero admissions means every
  # guard method failed compilation and shipped as plain bytecode.
  vmp_count="$(grep -c '^TRUE_VMP L' "$WORK/vmp-$base.log" || true)"
  if [ "$vmp_count" -eq 0 ]; then
    echo "[vmp] $base: no TRUE_VMP method admitted; virtualization silently degraded"
    exit 1
  fi
  echo "[vmp] $base: $vmp_count TRUE_VMP method(s) admitted"

  # Derive the ABI list from the APK itself rather than assuming
  # arm64: the release publishes four single-ABI splits plus a
  # universal APK, and each split only carries its own lib/<abi>/.
  # Checking a fixed ABI would fail every non-arm64 split.
  abis="$(python3 "$WORK/abilist.py" "$out")"
  test -n "$abis" || {
    echo "[vmp] $base has no lib/<abi>/ entries after VMP; shell was not embedded"
    exit 1
  }
  for abi in $abis; do
    python3 "$WORK/apkcheck.py" "$out" "$abi" || {
      echo "[vmp] $base failed the VMP shell check for ABI $abi"
      exit 1
    }
  done

  # Assets encryption contract (.github/scripts/assetcheck.py,
  # shared by both workflows so the two call sites cannot drift).
  # Runs once per APK: the asset inventory is ABI-independent, so
  # it does not belong inside the per-ABI loop above.
  python3 "$WS/.github/scripts/assetcheck.py" "$out" || {
    echo "[vmp] $base failed the assets-encryption check"
    exit 1
  }

  mv -f "$out" "$apk"
  echo "[vmp] $base virtualized, signed with the release key"
done
echo "VMP hardening applied to every release APK."
