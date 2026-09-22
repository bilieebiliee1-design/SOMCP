// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 bilieebiliee1-design
//
// Host round-trip harness for the reporting API key codec.
//
// Compiles the *production* decoder (app/src/main/cpp/reporting_key.h +
// sha256_impl.h) together with a build of key_generated.h and rk_expected.h
// produced by tools/test_reporting_key.py, to wasm32, and executes it under
// node. check() returns 0 when the decoder reproduces the expected plaintext
// byte-for-byte. Driven by tools/test_reporting_key.py — not built by Gradle.

#include "reporting_key.h"
#include "rk_expected.h"  // kExpected[], RK_EXPECTED_LEN (test-generated)

extern "C" __attribute__((export_name("check"))) int check() {
    uint8_t buf[rk::kMaxKeyLen + 1];
    size_t n = rk::decode_api_key(buf, sizeof(buf));
    if (n != RK_EXPECTED_LEN) return 1;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] != kExpected[i]) return 2;
    }
    rk::secure_zero(buf, sizeof(buf));
    return 0;
}
