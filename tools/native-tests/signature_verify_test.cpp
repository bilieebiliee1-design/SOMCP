// SPDX-License-Identifier: GPL-3.0-only
// SOMCP - Android native SO reverse-engineering MCP server
// Copyright (C) 2026 SOMCP authors <https://github.com/bilieebiliee1-design/SOMCP>
// This file is part of SOMCP and is licensed under the GNU General Public License v3.0.
// Functional harness for signature_verify.cpp's ZIP + PKCS7 parsing.
//
// Compiles the production translation unit with SOMCP_TEST_HARNESS defined so the
// JNI entry points are replaced by a plain C++ entry that takes a file path. Each
// case below exercises one of the defects fixed in this branch.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Pull in the implementation under test. SOMCP_TEST_HARNESS exposes
// somcp_test_read_apk_certificate() in place of the JNI entry point.
#include "../../app/src/main/cpp/signature_verify.cpp"

#ifndef SOMCP_TEST_TMPDIR
#define SOMCP_TEST_TMPDIR "."
#endif

static int g_failures = 0;
static int g_checks = 0;

static void check(bool cond, const char* name, const char* detail = "") {
    ++g_checks;
    if (cond) {
        printf("  PASS  %s %s\n", name, detail);
    } else {
        printf("  FAIL  %s %s\n", name, detail);
        ++g_failures;
    }
}

// ---------------------------------------------------------------------------
// Byte assembly helpers
// ---------------------------------------------------------------------------
static void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(v & 0xff);
    out.push_back((v >> 8) & 0xff);
}
static void put32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(v & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 24) & 0xff);
}
static void putBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    out.insert(out.end(), v.begin(), v.end());
}

// DER TLV with definite length.
static std::vector<uint8_t> der(uint8_t tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> out;
    out.push_back(tag);
    const size_t n = value.size();
    if (n < 128) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n < 256) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(n));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>(n & 0xff));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// A recognisable fake X.509: SEQUENCE { SEQUENCE(tbs) , BITSTRING(sig) }.
// `marker` is embedded so we can prove which certificate came back.
static std::vector<uint8_t> makeCert(uint8_t marker, size_t tbsPadding) {
    std::vector<uint8_t> tbsBody(tbsPadding, marker);
    auto tbs = der(0x30, tbsBody);
    auto sig = der(0x03, std::vector<uint8_t>(16, 0x5a));
    return der(0x30, concat({tbs, sig}));
}

// PKCS7 ContentInfo { OID signedData, [0] { SignedData { ver, digestAlgs,
// contentInfo, [0] certificates } } }
static std::vector<uint8_t> makePkcs7(const std::vector<std::vector<uint8_t>>& certs) {
    auto version = der(0x02, {0x01});
    auto digestAlgs = der(0x31, {});
    auto encapInfo = der(0x30, der(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}));
    std::vector<uint8_t> certBlob;
    for (const auto& c : certs) certBlob.insert(certBlob.end(), c.begin(), c.end());
    auto certificates = der(0xa0, certBlob);
    auto signerInfos = der(0x31, {});
    auto signedData = der(0x30, concat({version, digestAlgs, encapInfo, certificates, signerInfos}));
    auto wrapper = der(0xa0, signedData);
    auto oid = der(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02});
    return der(0x30, concat({oid, wrapper}));
}

struct ZipEntrySpec {
    std::string name;
    std::vector<uint8_t> data;
    uint16_t compression = 0;
    // Overrides used to forge malformed archives; 0 means "use the real value".
    uint32_t forcedUncompressedSize = 0;
    uint32_t forcedCompressedSize = 0;
};

struct ZipOverrides {
    uint32_t centralDirOffset = 0;   // 0 = real
    uint32_t centralDirSize = 0;     // 0 = real
};

static std::vector<uint8_t> buildZip(const std::vector<ZipEntrySpec>& entries,
                                     const ZipOverrides& ov = {}) {
    std::vector<uint8_t> out;
    std::vector<uint32_t> localOffsets;

    for (const auto& e : entries) {
        localOffsets.push_back(static_cast<uint32_t>(out.size()));
        put32(out, 0x04034b50);
        put16(out, 20);
        put16(out, 0);
        put16(out, e.compression);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0);
        put32(out, e.forcedCompressedSize ? e.forcedCompressedSize : static_cast<uint32_t>(e.data.size()));
        put32(out, e.forcedUncompressedSize ? e.forcedUncompressedSize : static_cast<uint32_t>(e.data.size()));
        put16(out, static_cast<uint16_t>(e.name.size()));
        put16(out, 0);
        out.insert(out.end(), e.name.begin(), e.name.end());
        putBytes(out, e.data);
    }

    const uint32_t cdStart = static_cast<uint32_t>(out.size());
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        put32(out, 0x02014b50);
        put16(out, 20);
        put16(out, 20);
        put16(out, 0);
        put16(out, e.compression);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0);
        put32(out, e.forcedCompressedSize ? e.forcedCompressedSize : static_cast<uint32_t>(e.data.size()));
        put32(out, e.forcedUncompressedSize ? e.forcedUncompressedSize : static_cast<uint32_t>(e.data.size()));
        put16(out, static_cast<uint16_t>(e.name.size()));
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0);
        put32(out, localOffsets[i]);
        out.insert(out.end(), e.name.begin(), e.name.end());
    }
    const uint32_t cdSize = static_cast<uint32_t>(out.size()) - cdStart;

    put32(out, 0x06054b50);
    put16(out, 0);
    put16(out, 0);
    put16(out, static_cast<uint16_t>(entries.size()));
    put16(out, static_cast<uint16_t>(entries.size()));
    put32(out, ov.centralDirSize ? ov.centralDirSize : cdSize);
    put32(out, ov.centralDirOffset ? ov.centralDirOffset : cdStart);
    put16(out, 0);
    return out;
}

static std::string writeTemp(const std::string& name, const std::vector<uint8_t>& data) {
    std::string path = std::string(SOMCP_TEST_TMPDIR) + "/" + name;
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        printf("  FAIL  could not write fixture %s\n", path.c_str());
        ++g_failures;
        return path;
    }
    if (!data.empty()) fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return path;
}

int main() {
    printf("signature_verify parser harness\n\n");

    const auto certA = makeCert(0xAA, 200);
    const auto certB = makeCert(0xBB, 300);

    // ---- Case 1: well-formed stored .RSA yields the first certificate ----
    printf("case 1: well-formed v1 signature block\n");
    {
        auto pkcs7 = makePkcs7({certA, certB});
        auto zip = buildZip({
            {"AndroidManifest.xml", std::vector<uint8_t>(64, 0x11)},
            {"META-INF/CERT.RSA", pkcs7},
        });
        auto path = writeTemp("case1.apk", zip);
        auto got = somcp_test_read_apk_certificate(path);
        check(!got.empty(), "certificate extracted");
        check(got == certA, "matches the first certificate in the SET",
              got == certA ? "" : "(wrong certificate returned)");
    }

    // ---- Case 2: uncompressed_size >> compressed_size must not over-read ----
    // This is the P0-A out-of-bounds read: the guard used compressed_size while
    // the copy used uncompressed_size.
    printf("\ncase 2: forged uncompressed_size (out-of-bounds read attempt)\n");
    {
        auto pkcs7 = makePkcs7({certA});
        ZipEntrySpec sig{"META-INF/CERT.RSA", pkcs7};
        sig.forcedUncompressedSize = 0x0FFFFFFF;  // ~256 MiB, file is ~1 KiB
        auto zip = buildZip({{"a.txt", std::vector<uint8_t>(16, 0x22)}, sig});
        auto path = writeTemp("case2.apk", zip);
        auto got = somcp_test_read_apk_certificate(path);
        check(got.empty(), "entry rejected instead of over-reading the heap");
    }

    // ---- Case 3: central directory offset+size wraps uint32 ----
    // P0-B: the bounds check added two uint32 values before widening.
    printf("\ncase 3: central directory offset/size uint32 wrap\n");
    {
        auto pkcs7 = makePkcs7({certA});
        ZipOverrides ov;
        ov.centralDirOffset = 0xFFFFFF00u;
        ov.centralDirSize = 0x200u;  // wraps to 0x100 in 32-bit math
        auto zip = buildZip({{"META-INF/CERT.RSA", pkcs7}}, ov);
        auto path = writeTemp("case3.apk", zip);
        auto got = somcp_test_read_apk_certificate(path);
        check(got.empty(), "wrapped central directory rejected");
    }

    // ---- Case 4: deflated signature entry is refused ----
    printf("\ncase 4: deflated signature entry\n");
    {
        auto pkcs7 = makePkcs7({certA});
        ZipEntrySpec sig{"META-INF/CERT.RSA", pkcs7};
        sig.compression = 8;  // deflate
        auto zip = buildZip({sig});
        auto path = writeTemp("case4.apk", zip);
        auto got = somcp_test_read_apk_certificate(path);
        check(got.empty(), "compressed PKCS7 not treated as DER");
    }

    // ---- Case 5: DER parser terminates on hostile nesting ----
    // P0-C: the discarded first child loop could spin forever.
    printf("\ncase 5: DER parser termination\n");
    {
        // 40 levels of nested SEQUENCEs, past kMaxDerDepth.
        std::vector<uint8_t> deep = der(0x02, {0x01});
        for (int i = 0; i < 40; ++i) deep = der(0x30, deep);
        auto node = parse_der(deep.data(), 0, deep.size());
        check(true, "deeply nested input returned (no hang, no stack overflow)");

        // Truncated/garbage bodies must also terminate.
        std::vector<uint8_t> garbage = der(0x30, std::vector<uint8_t>(64, 0xff));
        auto g = parse_der(garbage.data(), 0, garbage.size());
        check(true, "garbage constructed body returned");

        // A zero-length child must still advance the cursor.
        auto emptyChildren = der(0x30, concat({der(0x05, {}), der(0x05, {}), der(0x02, {0x07})}));
        auto e = parse_der(emptyChildren.data(), 0, emptyChildren.size());
        check(e.children.size() == 3, "zero-length children each advance the cursor",
              ("children=" + std::to_string(e.children.size())).c_str());
    }

    // ---- Case 6: recursion populates nested children ----
    // The old parser never recursed, so extract_certificate_from_pkcs7 always
    // fell through to the loose byte-scanning fallback.
    printf("\ncase 6: structured extraction (not fallback)\n");
    {
        auto pkcs7 = makePkcs7({certA});
        auto structured = extract_certificate_from_pkcs7(pkcs7);
        check(!structured.empty(), "structured PKCS7 path returns a certificate");
        check(structured == certA, "structured path picked the real certificate");
    }

    // ---- Case 7: no signature file at all ----
    printf("\ncase 7: archive without META-INF signature\n");
    {
        auto zip = buildZip({{"classes.dex", std::vector<uint8_t>(32, 0x33)}});
        auto path = writeTemp("case7.apk", zip);
        auto got = somcp_test_read_apk_certificate(path);
        check(got.empty(), "missing signature reported as failure");
    }

    // ---- Case 8: truncated / empty inputs ----
    printf("\ncase 8: degenerate inputs\n");
    {
        auto p1 = writeTemp("case8a.apk", {});
        check(somcp_test_read_apk_certificate(p1).empty(), "empty file");
        auto p2 = writeTemp("case8b.apk", std::vector<uint8_t>{0x50, 0x4b, 0x03, 0x04});
        check(somcp_test_read_apk_certificate(p2).empty(), "4-byte file");
        auto p3 = writeTemp("case8c.apk", std::vector<uint8_t>(80, 0x00));
        check(somcp_test_read_apk_certificate(p3).empty(), "no EOCD signature");
        check(somcp_test_read_apk_certificate("/nonexistent/path.apk").empty(), "missing file");
    }

    // ---- Case 9: expected signer digest decodes ----
    printf("\ncase 9: obfuscated expected digest\n");
    {
        auto digest = decode_xor_hex(kEncodedExpectedSha256, kEncodedExpectedSha256Len);
        check(digest == "90FEDAC1F020C6C5D1DD1A635DB5C3B7579F5B87647E2C2C00966D3BCB0F8B6F",
              "XOR-encoded pin decodes to the documented value", digest.c_str());
    }

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
