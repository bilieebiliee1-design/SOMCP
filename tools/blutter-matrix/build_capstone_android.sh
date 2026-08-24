# SPDX-License-Identifier: AGPL-3.0-or-later

# Copyright (C) 2026 bilieebiliee1-design

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# build_capstone_android.sh - Cross-compile capstone 4.0.2 as a static library
# for Android arm64-v8a using the Android NDK.
#
# Linux/macOS counterpart of build_capstone_android.ps1. The Blutter runner
# links statically against capstone, so this builds a static libcapstone.a
# (capstone shared rules, no tools/tests).
#
# Usage:
#   bash build_capstone_android.sh <ndk> <prefix> [jobs]
#
# Arguments:
#   <ndk>     Android NDK root (expects NDK 29.0.14206865)
#   <prefix>  install prefix that receives <prefix>/lib/libcapstone.a
#   [jobs]    parallel build jobs (default: 4)
#
# Prerequisites:
#   - capstone source submodule checked out (tools/blutter-matrix needs
#     `git submodule update --init --recursive` at the repo root)
#   - cmake >= 3.22 and ninja on PATH
set -euo pipefail

NDK="$1"
INSTALL="${2:-}"
JOBS="${3:-4}"
if [[ -z "$NDK" || -z "$INSTALL" ]]; then
  echo "error: expected <ndk> and <prefix> arguments" >&2
  exit 1
fi

# Script lives at <repo>/tools/blutter-matrix.
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$PROJECT/third_party/capstone-4.0.2-src"
if [[ ! -d "$SRC" ]]; then
  echo "error: capstone source missing ($SRC) - run 'git submodule update --init --recursive' first" >&2
  exit 1
fi

TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [[ ! -f "$TOOLCHAIN" ]]; then
  echo "error: Android NDK toolchain not found: $TOOLCHAIN (expects NDK 29.0.14206865)" >&2
  exit 1
fi

CMAKE_BIN="${CMAKE_BIN:-cmake}"
if ! command -v "$CMAKE_BIN" >/dev/null 2>&1 && [[ ! -x "$CMAKE_BIN" ]]; then
  echo "error: cmake not found (set CMAKE_BIN or install cmake >= 3.22)" >&2
  exit 1
fi
if ! command -v ninja >/dev/null 2>&1; then
  echo "error: ninja not found on PATH" >&2
  exit 1
fi

BUILD="$INSTALL/../capstone-build"
rm -rf "$BUILD" "$INSTALL"
mkdir -p "$INSTALL"

echo "[capstone] configuring (Android arm64-v8a, static) ..."
"$CMAKE_BIN" -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCAPSTONE_BUILD_STATIC=ON \
  -DCAPSTONE_BUILD_SHARED=OFF \
  -DCAPSTONE_BUILD_TESTS=OFF \
  -DCAPSTONE_BUILD_CSTOOL=OFF \
  -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF \
  -DCAPSTONE_ARM64_SUPPORT=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL"

echo "[capstone] building ..."
"$CMAKE_BIN" --build "$BUILD" --target install --parallel "$JOBS"

if [[ ! -f "$INSTALL/lib/libcapstone.a" ]]; then
  echo "error: libcapstone.a missing after build" >&2
  exit 1
fi
echo "[capstone] DONE - $INSTALL/lib/libcapstone.a"