// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
//
// Host round-trip harness for the native key codecs.
//
// Compiles the *production* decoders (app/src/main/cpp/reporting_key.h +
// pin_decode.h + sha256_impl.h) together with a build of key_generated.h,
// rk_expected.h and pins_expected.h produced by tools/test_reporting_key.py,
// to wasm32, and executes it under node. check() returns 0 when the decoder
// reproduces the expected reporting-key plaintext byte-for-byte; check_pins()
// does the same for the SHA-256-CTR-encoded signer-pin arrays. Driven by
// tools/test_reporting_key.py — not built by Gradle.
//
// No libc/libc++ calls anywhere: the wasm build is -nostdlib, so the
// comparisons below are hand-rolled.

#include "reporting_key.h"
#include "pin_decode.h"
#include "rk_expected.h"    // kExpected[], RK_EXPECTED_LEN (test-generated)
#include "pins_expected.h"  // kExpectedSha256, ... (test-generated)

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

// Byte-for-byte comparison against a NUL-terminated expected literal,
// without libc (strlen/memcmp are unavailable under -nostdlib).
static bool matches_literal(const char* plain, const char* buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (plain[i] == '\0' || plain[i] != buf[i]) return false;
    }
    return plain[n] == '\0';
}

// Round-trips every signer-pin array through the production pin decoder.
// Return codes: 0 ok; 10+i = array i mismatched (table order below).
extern "C" __attribute__((export_name("check_pins"))) int check_pins() {
    const struct {
        const uint8_t* enc;
        size_t len;
        const char* plain;
    } cases[] = {
        {kEncodedExpectedSha256, kEncodedExpectedSha256Len, kExpectedSha256},
        {kEncodedMD5, kEncodedMD5Len, kExpectedMD5},
        {kEncodedSHA1, kEncodedSHA1Len, kExpectedSHA1},
        {kEncodedSHA512, kEncodedSHA512Len, kExpectedSHA512},
        {kEncodedExpectedPackage, kEncodedExpectedPackageLen, kExpectedPackage},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char buf[pin::kMaxPinLen];
        size_t n = pin::decode(cases[i].enc, cases[i].len, buf, sizeof(buf));
        bool ok = matches_literal(cases[i].plain, buf, n);
        pin::secure_zero(buf, sizeof(buf));
        if (!ok) return 10 + static_cast<int>(i);
    }
    return 0;
}
