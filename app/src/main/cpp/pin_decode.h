// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
//
// Runtime decoder for the SHA-256-CTR-encoded signer-pin arrays in
// key_generated.h (expected certificate digests + package name).
//
// Same construction as the reporting API key (see reporting_key.h):
//   master          = SHA256(kTmKey || kPinSalt)
//   keystream blk i = SHA256(master || LE32(i))
//   plaintext       = kEncoded* XOR keystream
// The salt is the fixed domain-separation constant baked in by
// generate_header.py (PIN_SALT), not a per-build nonce, because the pins are
// build constants — the header must stay a pure function of the TM secret.
// There is no short repeating key pattern and no plaintext anywhere in the
// artifact. Dependency-free (no libc calls, no libc++) so the exact same
// code can be unit-tested on the host — see tools/test_reporting_key.cpp.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sha256_impl.h"
#include "key_generated.h"

namespace pin {

// Upper bound for one pin array. The longest pin is the SHA-512 hex digest
// (128 chars); 160 leaves headroom. A longer array is a build/generator
// mismatch and is refused rather than silently truncated.
constexpr size_t kMaxPinLen = 160;

// Volatile-store zeroing: the compiler must not elide it as "dead" writes.
inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

// Decodes one encoded pin array (e.g. kEncodedExpectedSha256 with
// kEncodedExpectedSha256Len) into [out] (at most [cap] bytes).
// Returns the plaintext length, or 0 when the array is empty or the buffer
// is too small. The caller wipes the buffer once done.
inline size_t decode(const uint8_t* encoded, size_t len, char* out, size_t cap) {
    if (len == 0 || len > cap || len > kMaxPinLen) {
        return 0;
    }

    uint8_t master[32];
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, kTmKey, kTmKeyLen);
    sha256_update(&s, kPinSalt, kPinSaltLen);
    sha256_final(&s, master);
    secure_zero(&s, sizeof(s));

    uint8_t input[36];  // master || LE32(counter)
    for (int i = 0; i < 32; i++) input[i] = master[i];
    secure_zero(master, sizeof(master));

    uint32_t ctr = 0;
    size_t produced = 0;
    while (produced < len) {
        uint8_t ks[32];
        input[32] = static_cast<uint8_t>(ctr & 0xFF);
        input[33] = static_cast<uint8_t>((ctr >> 8) & 0xFF);
        input[34] = static_cast<uint8_t>((ctr >> 16) & 0xFF);
        input[35] = static_cast<uint8_t>((ctr >> 24) & 0xFF);
        ctr++;
        Sha256 hs;
        sha256_init(&hs);
        sha256_update(&hs, input, sizeof(input));
        sha256_final(&hs, ks);
        secure_zero(&hs, sizeof(hs));
        for (size_t j = 0; j < 32 && produced < len; j++, produced++) {
            out[produced] = static_cast<char>(encoded[produced] ^ ks[j]);
        }
        secure_zero(ks, sizeof(ks));
    }
    secure_zero(input, sizeof(input));
    return produced;
}

}  // namespace pin
