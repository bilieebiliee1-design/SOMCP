// SPDX-License-Identifier: GPL-3.0-only
// SOMCP - Android native SO reverse-engineering MCP server
// Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
// This file is part of SOMCP and is licensed under the GNU General Public License v3.0.
// Minimal Android logging shim so signature_verify.cpp compiles off-device.
#pragma once
#include <cstdio>
#define ANDROID_LOG_INFO 4
#define ANDROID_LOG_ERROR 6
static inline int __android_log_print(int, const char*, const char* fmt, ...) {
    (void)fmt;
    return 0;
}
