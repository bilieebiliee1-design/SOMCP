#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - build-unidbg-native.sh
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License version 3 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License along
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
# libunicorn.so is special: unidbg's unicorn2 backend is a JNI binding, so the
# library must carry the JNI bridge (Java_com_github_unidbg_arm_backend_unicorn_
# Unicorn_*), not only the raw uc_* engine API. See the unicorn section below
# and tools/verify_unicorn_jni.py.
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
#   - libunicorn.so is built as unidbg's unicorn2 JNI bridge (unicorn engine
#     archive + backend/unicorn2/src/main/native/unicorn.c). The script
#     refuses to install a library that does not export that bridge, so an
#     engine-only libunicorn.so can no longer reach the APK (issue #91).
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

# Refuse to install a libunicorn.so that cannot serve unidbg's unicorn2
# backend. Prefers the python verifier (real .dynsym inspection); falls back to
# a raw symbol scan so the guard also works where python is unavailable.
verify_unicorn_jni() {
  local so="$1" runner="" hits=""
  for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1; then
      runner="$candidate"
      break
    fi
  done
  if [[ -n "$runner" && -f "$PROJECT/tools/verify_unicorn_jni.py" ]]; then
    "$runner" "$PROJECT/tools/verify_unicorn_jni.py" "$so"
    return $?
  fi
  echo "[unidbg-native] python not found - falling back to a raw symbol scan"
  hits="$(LC_ALL=C grep -a -o 'Java_com_github_unidbg_arm_backend_unicorn_Unicorn_' "$so" 2>/dev/null | wc -l | tr -d ' ')"
  if [[ -z "$hits" || "$hits" -lt 20 ]]; then
    echo "error: $so exports only ${hits:-0} unicorn2 JNI symbols (need >= 20); it looks like the raw unicorn engine instead of unidbg's JNI bridge" >&2
    return 1
  fi
  echo "[unidbg-native] JNI bridge symbol scan passed ($hits symbol references)"
  return 0
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
    # ---------------------------------------------------------------------
    # libunicorn.so must be unidbg's *unicorn2 JNI bridge*, not the raw engine.
    #
    # The backend the app registers (Unicorn2Factory -> Unicorn2Backend) calls
    # com.github.unidbg.arm.backend.unicorn.Unicorn, whose entry points are JNI
    # `native` methods. Android resolves them by symbol name, so the library
    # must export
    #     Java_com_github_unidbg_arm_backend_unicorn_Unicorn_*
    # which the plain unicorn engine does not: it only exports the flat uc_*
    # API. An engine-only lib loads fine, so UnidbgEmulator still reports the
    # backend as available; the failure only appears when a session is opened -
    # Unicorn2Backend cannot bind, and because the app constructs
    # Unicorn2Factory(true), BackendFactory.newBackend swallows the error and
    # falls back to the legacy UnicornBackend, which then dies with
    # NoClassDefFoundError: unicorn.Unicorn (issue #91).
    #
    # Two defects used to be baked in here:
    #   1. `-DUNICORN_ARCH=arm,aarch64` is a single bogus CMake token - the arch
    #      list must be semicolon separated. With it, no arm-softmmu /
    #      aarch64-softmmu backend was compiled in at all: the result was a
    #      ~54 KB library exporting the whole uc_* surface with no emulation
    #      core behind it.
    #   2. A correct engine build still carries no JNI bridge; that has to be
    #      compiled from unidbg's backend/unicorn2/src/main/native/unicorn.c and
    #      linked against the engine archive.
    # The steps below mirror unidbg's own
    # backend/unicorn2/src/main/native/{Dockerfile,CMakeLists.txt}.
    # ---------------------------------------------------------------------
    uni="$PROJECT/third_party/unicorn-engine-unicorn2"
    if [[ ! -f "$uni/include/unicorn/unicorn.h" ]] ||
      ! grep -q "uc_ctl_set_cpu_model" "$uni/include/unicorn/unicorn.h"; then
      echo "error: unicorn 2.x engine source not found at $uni" >&2
      echo "       run 'git submodule update --init --recursive'. unidbg's JNI bridge needs the" >&2
      echo "       unicorn 2.x API (uc_ctl_set_cpu_model / uc_ctl_remove_cache); the 1.0.x snapshot" >&2
      echo "       in third_party/unicorn-zhkl0228 cannot build it." >&2
      exit 1
    fi
    jni_dir="$PROJECT/third_party/unidbg-zhkl0228/backend/unicorn2/src/main/native"
    if [[ ! -f "$jni_dir/unicorn.c" ]]; then
      echo "error: unidbg unicorn2 JNI bridge sources missing: $jni_dir/unicorn.c" >&2
      echo "       run 'git submodule update --init --recursive' (needs third_party/unidbg-zhkl0228)" >&2
      exit 1
    fi

    # 1) engine: arm + aarch64 back ends, Release, position independent, plus
    #    the all-in-one libunicorn.a archive the bridge links against.
    #    The JNI bridge is written against the unicorn 2.x API (uc_init,
    #    uc_ctl_*), which third_party/unicorn-engine-unicorn2 tracks.
    build_one unicorn "$uni" \
      -DUNICORN_ARCH="arm;aarch64" \
      -DBUILD_SHARED_LIBS=ON \
      -DUNICORN_LEGACY_STATIC_ARCHIVE=ON \
      -DUNICORN_BUILD_TESTS=OFF -DUNICORN_INSTALL=OFF -DUNICORN_TRACER=OFF

    engine_lib="$BUILD_ROOT/unicorn/libunicorn.a"
    if [[ ! -f "$engine_lib" ]]; then
      engine_lib="$(find "$BUILD_ROOT/unicorn" -maxdepth 1 -name 'libunicorn*.a' -print -quit || true)"
    fi
    if [[ -z "$engine_lib" || ! -f "$engine_lib" ]]; then
      echo "error: unicorn engine archive (libunicorn.a) not found under $BUILD_ROOT/unicorn" >&2
      exit 1
    fi
    echo "[unidbg-native] unicorn engine archive: $engine_lib"
    # Extra archives are harmless inside --start-group: the linker only pulls
    # the members it still needs.
    engine_extra=()
    while IFS= read -r extra; do
      if [[ -z "$extra" || "$extra" == "$engine_lib" ]]; then continue; fi
      engine_extra+=("$extra")
    done < <(find "$BUILD_ROOT/unicorn" -maxdepth 1 \( -name 'lib*-softmmu.a' -o -name 'libunicorn-common.a' \) 2>/dev/null | sort)

    # 2) JNI bridge -> libunicorn.so, compiled with the NDK toolchain.
    host_tag=""
    for candidate in linux-x86_64 linux-aarch64 darwin-x86_64 darwin-arm64 windows-x86_64; do
      if [[ -d "$NDK/toolchains/llvm/prebuilt/$candidate" ]]; then
        host_tag="$candidate"
        break
      fi
    done
    if [[ -z "$host_tag" ]]; then
      echo "error: NDK LLVM prebuilt toolchain not found under $NDK/toolchains/llvm/prebuilt" >&2
      exit 1
    fi
    case "$ABI" in
      arm64-v8a) clang_triple="aarch64-linux-android" ;;
      x86_64) clang_triple="x86_64-linux-android" ;;
      *)
        echo "error: unexpected 64-bit ABI '$ABI'" >&2
        exit 1
        ;;
    esac
    bridge_cc="$NDK/toolchains/llvm/prebuilt/$host_tag/bin/${clang_triple}26-clang"
    if [[ ! -x "$bridge_cc" ]]; then
      echo "error: NDK clang not found: $bridge_cc" >&2
      exit 1
    fi
    ndk_include="$NDK/toolchains/llvm/prebuilt/$host_tag/sysroot/usr/include"
    if [[ ! -f "$ndk_include/jni.h" ]]; then
      echo "error: jni.h not found in the NDK sysroot: $ndk_include" >&2
      exit 1
    fi

    bridge_so="$BUILD_ROOT/libunicorn.so"
    rm -f "$bridge_so"
    echo "[unidbg-native] linking the unicorn2 JNI bridge for $ABI ..."
    "$bridge_cc" -shared -fPIC -O3 -DNDEBUG -Wall -Wno-missing-braces \
      -I "$jni_dir" -I "$uni/include" -I "$ndk_include" \
      "$jni_dir/unicorn.c" "$jni_dir/sample_arm.c" "$jni_dir/sample_arm64.c" \
      -Wl,--start-group "$engine_lib" ${engine_extra[@]+"${engine_extra[@]}"} -Wl,--end-group \
      -llog -lm -ldl \
      -o "$bridge_so"

    # 3) never install a library that cannot satisfy the backend.
    if ! verify_unicorn_jni "$bridge_so"; then
      echo "error: refusing to install $bridge_so - it does not export the unicorn2 JNI bridge" >&2
      exit 1
    fi
    cp "$bridge_so" "$JNI_LIBS/libunicorn.so"
    echo "[unidbg-native] copied libunicorn.so (unicorn2 JNI bridge) -> $JNI_LIBS"
  fi
fi

echo "[unidbg-native] DONE - rebuild the APK to enable the Unidbg backend (libjnidispatch.so is provided automatically by the JNA AAR)"
