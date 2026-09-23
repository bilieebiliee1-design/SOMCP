// SPDX-License-Identifier: AGPL-3.0-only
//
// Copyright (C) 2026 bilieebiliee1-design
//
// SHA-256 (FIPS 180-4) — self-contained implementation.
//
// Moved out of native_probe.cpp so host-side unit tests can compile the same
// primitives (via reporting_key.h) with a plain clang++ and no Android deps.
// Kept dependency-free (no OpenSSL/BoringSSL) because Java MessageDigest is
// hookable at runtime, while the native -> JNI bridge itself is not.
#pragma once

#include <stddef.h>
#include <stdint.h>

struct Sha256 {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buflen;
};

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(Sha256* s, const uint8_t* chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)chunk[i * 4] << 24) | ((uint32_t)chunk[i * 4 + 1] << 16) |
               ((uint32_t)chunk[i * 4 + 2] << 8) | ((uint32_t)chunk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->state[0], b = s->state[1], c = s->state[2], d = s->state[3];
    uint32_t e = s->state[4], f = s->state[5], g = s->state[6], h = s->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->state[0] += a; s->state[1] += b; s->state[2] += c; s->state[3] += d;
    s->state[4] += e; s->state[5] += f; s->state[6] += g; s->state[7] += h;
}

static void sha256_init(Sha256* s) {
    s->state[0] = 0x6a09e667; s->state[1] = 0xbb67ae85;
    s->state[2] = 0x3c6ef372; s->state[3] = 0xa54ff53a;
    s->state[4] = 0x510e527f; s->state[5] = 0x9b05688c;
    s->state[6] = 0x1f83d9ab; s->state[7] = 0x5be0cd19;
    s->bitlen = 0;
    s->buflen = 0;
}

static void sha256_update(Sha256* s, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        s->buffer[s->buflen++] = data[i];
        s->bitlen += 8;
        if (s->buflen == 64) {
            sha256_transform(s, s->buffer);
            s->buflen = 0;
        }
    }
}

static void sha256_final(Sha256* s, uint8_t out[32]) {
    uint64_t bitlen = s->bitlen;
    uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    uint8_t zero = 0;
    while (s->buflen != 56) sha256_update(s, &zero, 1);
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) len_bytes[7 - i] = static_cast<uint8_t>(bitlen >> (i * 8));
    sha256_update(s, len_bytes, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = static_cast<uint8_t>(s->state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(s->state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(s->state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(s->state[i]);
    }
}
