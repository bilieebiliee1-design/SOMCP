// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
//
// Runtime decoder for the log-report-platform reporting API key.
//
// The key is injected at build time (see app/generate_header.py) and stored
// in key_generated.h encrypted under a SHA-256 counter-mode keystream:
//   master          = SHA256(kXorKey || kRkSalt)
//   keystream blk i = SHA256(master || LE32(i))
//   plaintext       = kRepApiKeyCipher XOR keystream
// There is no short repeating XOR pattern and no plaintext anywhere in the
// artifact; the intermediate buffers below are wiped once the key is handed
// to the caller. Dependency-free (no libc calls) so the exact same code can
// be unit-tested on the host — see tools/test_reporting_key.cpp.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sha256_impl.h"
#include "key_generated.h"

namespace rk {

constexpr size_t kMaxKeyLen = 512;  // must match RK_MAX_KEY_LEN in generate_header.py

// Volatile-store zeroing: the compiler must not elide it as "dead" writes.
inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

// Derives the 32-byte reporting master from the build-time TM secret and the
// per-build salt. Computed per call and wiped by the caller; never cached.
inline void derive_master(uint8_t master[32]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, kXorKey, kXorKeyLen);
    sha256_update(&s, kRkSalt, 16);
    sha256_final(&s, master);
    secure_zero(&s, sizeof(s));
}

// Decrypts kRepApiKeyCipher into [out] (at most [cap] bytes).
// Returns the plaintext length, or 0 when no key was injected, the buffer is
// too small, or the material exceeds the sanity bound.
inline size_t decode_api_key(uint8_t* out, size_t cap) {
    if (kRepApiKeyCipherLen == 0 || kRepApiKeyCipherLen > cap ||
        kRepApiKeyCipherLen > kMaxKeyLen) {
        return 0;
    }
    uint8_t master[32];
    derive_master(master);

    uint8_t input[36];  // master || LE32(counter)
    for (int i = 0; i < 32; i++) input[i] = master[i];
    secure_zero(master, sizeof(master));

    uint32_t ctr = 0;
    size_t produced = 0;
    while (produced < kRepApiKeyCipherLen) {
        uint8_t ks[32];
        input[32] = static_cast<uint8_t>(ctr & 0xFF);
        input[33] = static_cast<uint8_t>((ctr >> 8) & 0xFF);
        input[34] = static_cast<uint8_t>((ctr >> 16) & 0xFF);
        input[35] = static_cast<uint8_t>((ctr >> 24) & 0xFF);
        ctr++;
        Sha256 s;
        sha256_init(&s);
        sha256_update(&s, input, sizeof(input));
        sha256_final(&s, ks);
        secure_zero(&s, sizeof(s));
        for (size_t j = 0; j < 32 && produced < kRepApiKeyCipherLen; j++, produced++) {
            out[produced] = static_cast<uint8_t>(kRepApiKeyCipher[produced] ^ ks[j]);
        }
        secure_zero(ks, sizeof(ks));
    }
    secure_zero(input, sizeof(input));
    return produced;
}

}  // namespace rk
