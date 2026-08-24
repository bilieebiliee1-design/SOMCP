#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 bilieebiliee1-design
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
set -euo pipefail

root="$1"
ndk="$2"
jobs="${3:-4}"
src="$root/source"
if [ ! -x "$src/configure" ] && [ -x "$root/icu/source/configure" ]; then
  src="$root/icu/source"
fi
if [ ! -x "$src/configure" ] && [ -f "$root/icu4c-76_1-src.tgz" ]; then
  rm -rf "$root/icu"
  mkdir -p "$root/icu"
  tar -xzf "$root/icu4c-76_1-src.tgz" -C "$root/icu"
  src="$root/icu/source"
  if [ ! -x "$src/configure" ] && [ -x "$root/icu/icu/source/configure" ]; then
    src="$root/icu/icu/source"
  fi
fi
if [ ! -f "$root/LICENSE" ]; then
  if [ -f "$src/LICENSE" ]; then
    cp "$src/LICENSE" "$root/LICENSE"
  elif [ -f "$src/../license.html" ]; then
    cp "$src/../license.html" "$root/LICENSE"
  fi
fi
host="$root/host"
target="$root/android-arm64"
install="$root/../arm64-v8a/icu"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$toolchain" ]; then
  toolchain="$ndk/toolchains/llvm/prebuilt/windows-x86_64"
fi

rm -rf "$target" "$install"
mkdir -p "$host" "$target" "$install"

if [ ! -x "$host/bin/genccode" ] || [ ! -x "$host/bin/pkgdata" ]; then
  rm -rf "$host"
  mkdir -p "$host"
  cd "$host"
  "$src/configure" \
    --prefix="$host/install" \
    --enable-static \
    --disable-shared \
    --enable-tools=yes \
    --enable-tests=no \
    --enable-samples=no \
    --enable-extras=no \
    --enable-layout=no \
    --enable-layoutex=no \
    --enable-dyload=no \
    --with-data-packaging=archive \
    CFLAGS="-O2" \
    CXXFLAGS="-O2 -std=c++17"
  make -j"$jobs"
  make install
fi
test -x "$host/bin/genccode"
test -x "$host/bin/pkgdata"

cd "$target"
"$src/configure" \
  --prefix="$install" \
  --host=aarch64-linux-android \
  --enable-static \
  --disable-shared \
  --enable-tools=no \
  --enable-tests=no \
  --enable-samples=no \
  --enable-extras=no \
  --enable-layout=no \
  --enable-layoutex=no \
  --enable-dyload=no \
  --with-cross-build="$host" \
  --with-data-packaging=static \
  CC="$toolchain/bin/aarch64-linux-android26-clang" \
  CXX="$toolchain/bin/aarch64-linux-android26-clang++" \
  AR="$toolchain/bin/llvm-ar" \
  RANLIB="$toolchain/bin/llvm-ranlib" \
  ac_cv_prog_ac_ct_CC="$toolchain/bin/aarch64-linux-android26-clang" \
  CFLAGS="-O2 -fPIC" \
  CXXFLAGS="-O2 -std=c++17 -fPIC"
make -j"$jobs"
make install
test -f "$install/lib/libicuuc.a"
test -f "$install/lib/libicudata.a"
