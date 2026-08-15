#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# SOMCP - Android native SO reverse-engineering MCP server
# Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
# This file is part of SOMCP and is licensed under the GNU General Public License v3.0.
# Host-side tests for the native APK signature parser (app/src/main/cpp/signature_verify.cpp).
#
# These run on the build machine with any C++17 compiler; no device, NDK or JVM is
# needed. The stub/ directory supplies the few Android headers the translation
# unit includes. Sanitizers are enabled because the cases here deliberately feed
# malformed ZIP/DER structures at the parser.
#
# Usage:
#   tools/native-tests/run.sh            # uses c++ from PATH
#   CXX=clang++ tools/native-tests/run.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cxx=${CXX:-c++}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "[native-tests] compiling with $cxx"
"$cxx" -std=c++17 -g -O1 \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DSOMCP_TEST_HARNESS \
    -DSOMCP_TEST_TMPDIR="\"$tmp\"" \
    -I"$here/stub" \
    -Wall -Wextra -Wno-unused-parameter -Wno-comment -Wno-unused-const-variable \
    -o "$tmp/signature_verify_test" \
    "$here/signature_verify_test.cpp"

echo "[native-tests] running"
ASAN_OPTIONS=detect_leaks=0 "$tmp/signature_verify_test"
