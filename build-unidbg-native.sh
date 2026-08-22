#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# SOMCP - build-unidbg-native.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# build-unidbg-native.sh - Cross-compile the Android native libraries required
# by the Unidbg emulation backend using the Android NDK.
#
# Linux/macOS counterpart of build-unidbg-native.ps1.
#
# Background: unidbg 0.9.9 Maven artifacts only ship Linux natives (the
# libcapstone.so / libkeystone.so / libunicorn.so inside the jars are
# linux_64 / linux_aarch64 only), and there is no reliable Android prebuilt
# download, so the APK does not bundle them by default and emulate_* returns
# EMULATOR_UNAVAILABLE. This script builds the shared libs from the in-repo
# submodules (third_party/*) for a given ABI and copies them into
# app/src/main/jniLibs/<ABI>/; rebuild the APK afterwards to enable Unidbg.
#
# Usage:
#   ./build-unidbg-native.sh
#   ./build-unidbg-native.sh -Abi armeabi-v7a
#   ./build-unidbg-native.sh -Ndk /opt/android-ndk/29.0.14206865 -SkipKeystone
#
# Options:
#   -Abi <abi>        Android ABI to build (default: arm64-v8a)
#                     [arm64-v8a|armeabi-v7a|x86|x86_64]
#   -Ndk <path>       Android NDK root (default: $ANDROID_HOME / $ANDROID_SDK_ROOT
#                     or common install locations; expects NDK 29.0.14206865)
#   -CMake <path>     cmake binary (default: SDK cmake 3.22.1 if found, else PATH)
#   -SkipCapstone     skip building capstone
#   -SkipKeystone     skip building keystone
#   -SkipUnicorn      skip building unicorn
#   -h, --help        show this help
#
# Notes:
#   - libjnidispatch.so is provided automatically by the JNA AAR
#     (net.java.dev.jna:jna); no need to build it.
#   - libdisassembler.so / libdemumble.so only serve optional diagnostic
#     paths in unidbg 0.9.9 and have no Android prebuilt source;
#     UnidbgEmulator loads them tolerantly (warning only), so they are not
#     built here either.
#   - The CMake flags target NDK 29 / CMake 3.22 / unidbg 0.9.9; if you bump
#     the NDK or CMake, adjust the flags per the upstream READMEs.
set -euo pipefail

ABI="${ABI:-arm64-v8a}"
NDK="${NDK:-}"
CMAKE_BIN="${CMAKE_BIN:-}"
SKIP_CAPSTONE=0
SKIP_KEYSTONE=0
SKIP_UNICORN=0

usage() {
  cat <<'EOF'
Usage: build-unidbg-native.sh [options]

Cross-compile capstone/keystone/unicorn for Android and copy the .so into
app/src/main/jniLibs/<ABI>/ (enables the Unidbg emulation backend in the APK).
Linux/macOS counterpart of build-unidbg-native.ps1.

Options:
  -Abi <abi>          Android ABI to build (default: arm64-v8a)
                      [arm64-v8a|armeabi-v7a|x86|x86_64]
  -Ndk <path>         Android NDK root (default: ANDROID_HOME/ANDROID_SDK_ROOT
                      or common install locations; expects NDK 29.0.14206865)
  -CMake <path>       cmake binary (default: SDK cmake 3.22.1 if found, else PATH)
  -SkipCapstone       skip building capstone
  -SkipKeystone       skip building keystone
  -SkipUnicorn        skip building unicorn
  -h, --help          show this help

Prerequisites:
  - git submodule update --init --recursive
  - Android NDK 29 + ninja (Linux: ninja-build, macOS: brew install ninja)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -Abi|--abi) ABI="$2"; shift 2 ;;
    -Ndk|--ndk) NDK="$2"; shift 2 ;;
    -CMake|--cmake) CMAKE_BIN="$2"; shift 2 ;;
    -SkipCapstone|--skip-capstone) SKIP_CAPSTONE=1; shift ;;
    -SkipKeystone|--skip-keystone) SKIP_KEYSTONE=1; shift ;;
    -SkipUnicorn|--skip-unicorn) SKIP_UNICORN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Whitelist the ABI so the value is never interpolated into filesystem or
# cmake arguments from untrusted input (path-traversal guard).
VALID_ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
abi_ok=0
for a in "${VALID_ABIS[@]}"; do
  if [[ "$a" == "$ABI" ]]; then abi_ok=1; break; fi
done
if [[ $abi_ok -eq 0 ]]; then
  echo "error: unsupported ABI '$ABI' - must be one of: ${VALID_ABIS[*]}" >&2
  exit 1
fi

# Script lives at the repo root, so the script dir IS the project root.
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNI_LIBS="$PROJECT/app/src/main/jniLibs/$ABI"
mkdir -p "$JNI_LIBS"

# --- Locate the Android NDK -------------------------------------------------
if [[ -z "$NDK" ]]; then
  for cand in \
    "$ANDROID_HOME/ndk/29.0.14206865" \
    "$ANDROID_SDK_ROOT/ndk/29.0.14206865" \
    "$HOME/Library/Android/sdk/ndk/29.0.14206865" \
    "$HOME/Android/Sdk/ndk/29.0.14206865" \
    /opt/android-sdk/ndk/29.0.14206865 \
    /opt/android-ndk/29.0.14206865
  do
    if [[ -f "$cand/build/cmake/android.toolchain.cmake" ]]; then
      NDK="$cand"
      break
    fi
  done
fi
if [[ -z "$NDK" || ! -f "$NDK/build/cmake/android.toolchain.cmake" ]]; then
  echo "error: NDK toolchain not found. Set -Ndk or ANDROID_HOME/ANDROID_SDK_ROOT (expects NDK 29.0.14206865)." >&2
  exit 1
fi
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
echo "[unidbg-native] NDK: $NDK"

# --- Locate cmake (prefer the SDK's 3.22.1, mirroring the PS1 default) -------
NINJA_BIN="$(command -v ninja || true)"
if [[ -z "$CMAKE_BIN" ]]; then
  for base in "$ANDROID_HOME" "$ANDROID_SDK_ROOT" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [[ -z "$base" || ! -d "$base" ]] && continue
    for v in 3.22.1.5040 3.22.1.5000 3.22.1.4700 3.22.1.4501 3.22.1; do
      if [[ -x "$base/cmake/$v/bin/cmake" ]]; then
        CMAKE_BIN="$base/cmake/$v/bin/cmake"
        NINJA_BIN="$base/cmake/$v/bin/ninja"
        break 2
      fi
    done
    if [[ -z "$CMAKE_BIN" && -x "$base/cmake/bin/cmake" ]]; then
      CMAKE_BIN="$base/cmake/bin/cmake"
    fi
  done
fi
CMAKE_BIN="${CMAKE_BIN:-cmake}"
if ! command -v "$CMAKE_BIN" >/dev/null 2>&1 && [[ ! -x "$CMAKE_BIN" ]]; then
  echo "error: cmake not found. Set -CMake or install cmake >= 3.22." >&2
  exit 1
fi
if [[ -z "$NINJA_BIN" ]]; then
  NINJA_BIN="$(command -v ninja || true)"
fi
if [[ -z "$NINJA_BIN" || ! -x "$NINJA_BIN" ]]; then
  echo "error: ninja not found - install it (Linux: ninja-build, macOS: brew install ninja) or use the ninja shipped with the Android SDK CMake package." >&2
  exit 1
fi
# Make sure the Ninja generator can find ninja even when it only lives inside
# the SDK's cmake directory.
NINJA_DIR="$(dirname "$NINJA_BIN")"
export PATH="$NINJA_DIR:$PATH"
echo "[unidbg-native] cmake: $CMAKE_BIN (ninja: $NINJA_BIN)"

BUILD_ROOT="$PROJECT/third_party/unidbg-native-build/$ABI"

build_one() {
  local name="$1" src="$2"
  shift 2
  if [[ ! -d "$src" ]]; then
    echo "error: $name source missing: $src - run 'git submodule update --init --recursive' first" >&2
    exit 1
  fi
  local build="$BUILD_ROOT/$name"
  rm -rf "$build"
  mkdir -p "$build"
  echo "[unidbg-native] configuring $name ..."
  "$CMAKE_BIN" -S "$src" -B "$build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM=android-26 \
    -DCMAKE_BUILD_TYPE=Release \
    "$@"
  echo "[unidbg-native] building $name ..."
  "$CMAKE_BIN" --build "$build" --parallel 4
}

if [[ $SKIP_CAPSTONE -eq 0 ]]; then
  # Prefer the zhkl0228 fork (the unidbg 0.9.9 JNA bindings were written
  # against its API); fall back to the official capstone-4.0.2-src
  # (cs_open/cs_disasm ABI is stable and compatible).
  cap="$PROJECT/third_party/zhkl-capstone-src"
  [[ -d "$cap" ]] || cap="$PROJECT/third_party/capstone-4.0.2-src"
  build_one capstone "$cap" \
    -DCAPSTONE_BUILD_STATIC=OFF -DCAPSTONE_BUILD_SHARED=ON \
    -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF \
    -DCAPSTONE_ARM_SUPPORT=ON -DCAPSTONE_ARM64_SUPPORT=ON
  cp "$BUILD_ROOT/capstone/libcapstone.so" "$JNI_LIBS/"
  echo "[unidbg-native] copied libcapstone.so -> $JNI_LIBS"
fi

if [[ $SKIP_KEYSTONE -eq 0 ]]; then
  build_one keystone "$PROJECT/third_party/keystone-engine-src" \
    -DBUILD_SHARED_LIBS=ON -DBUILD_LIBS_ONLY=ON -DLLVM_BUILD_TOOLS=OFF
  # keystone's bundled LLVM build redirects libkeystone.so into
  # <build>/llvm/lib/ (LIBRARY_OUTPUT_DIRECTORY from its llvm CMake), not the
  # build root; locate it defensively in case the layout changes upstream.
  keystone_so="$BUILD_ROOT/keystone/llvm/lib/libkeystone.so"
  if [[ ! -f "$keystone_so" ]]; then
    keystone_so="$(find "$BUILD_ROOT/keystone" -name 'libkeystone.so' -print -quit || true)"
  fi
  if [[ -z "$keystone_so" || ! -f "$keystone_so" ]]; then
    echo "error: libkeystone.so not found under $BUILD_ROOT/keystone" >&2
    exit 1
  fi
  cp "$keystone_so" "$JNI_LIBS/"
  echo "[unidbg-native] copied $(basename "$keystone_so") -> $JNI_LIBS"
fi

if [[ $SKIP_UNICORN -eq 0 ]]; then
  # unicorn's bundled QEMU uses __uint128_t (CONFIG_INT128 in host-utils.h),
  # which the Android NDK does not provide for 32-bit targets (armeabi-v7a,
  # x86), so it only compiles for 64-bit ABIs. On 32-bit ABIs we skip
  # libunicorn so the (still 32-bit) APKs build; Unidbg is unavailable there
  # but degrades gracefully via UnidbgEmulator's native load handling.
  # capstone/keystone compile for every ABI.
  if [[ "$ABI" != "arm64-v8a" && "$ABI" != "x86_64" ]]; then
    echo "[unidbg-native] WARNING: unicorn cannot compile on 32-bit ABI '$ABI' (needs __uint128_t); skipping libunicorn.so for this ABI"
  else
    # unidbg 0.9.9's Unicorn2Factory uses unicorn2 (the zhkl0228 fork).
    uni="$PROJECT/third_party/unicorn-zhkl0228"
    [[ -d "$uni" ]] || uni="$PROJECT/third_party/unicorn-engine-unicorn2"
    build_one unicorn "$uni" \
      -DUNICORN_ARCH=arm,aarch64 -DUNICORN_BUILD_TESTS=OFF -DUNICORN_BUILD_SAMPLES=OFF
    cp "$BUILD_ROOT/unicorn/libunicorn.so" "$JNI_LIBS/"
    echo "[unidbg-native] copied libunicorn.so -> $JNI_LIBS"
  fi
fi

echo "[unidbg-native] DONE - rebuild the APK to enable the Unidbg backend (libjnidispatch.so is provided automatically by the JNA AAR)"
