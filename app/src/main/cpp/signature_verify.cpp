/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

/**
 * signature_verify.cpp
 *
 * Native APK signature verification.
 *
 * WHY THIS IS NEEDED (context from ApkSignatureKiller / kstools):
 *   Cracking tools like kstools and ApkSignatureKiller work by hooking the
 *   Java-level PackageManager.getPackageInfo() method at the Binder layer.
 *   When the app calls getPackageInfo() with GET_SIGNATURES or
 *   GET_SIGNING_CERTIFICATES, the hook replaces the returned signature array
 *   with the original signer's certificate, so tampered/re-signed APKs appear
 *   to have the original signature.
 *
 * HOW THIS COUNTERS THAT:
 *   This code reads the APK file directly from the filesystem, parses the ZIP
 *   central directory, extracts the META-INF/ *.RSA/.DSA/.EC signature file,
 *   and returns the embedded X.509 certificate. Because it accesses the APK
 *   file at the filesystem level rather than through the Java PackageManager
 *   API, it cannot be intercepted by the Binder-level hook used by kstools
 *   and ApkSignatureKiller.
 *
 *   The calling Kotlin code then computes the SHA-256 digest of the certificate
 *   and compares it against the expected value from BuildConfig.
 */

#include <jni.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define LOG_TAG "SignatureVerify"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Memory-mapped APK reader
//
// Loading a large APK into a heap std::vector can exhaust the device memory
// and trigger an OOM crash. Instead we mmap() the file read-only: the kernel
// pages the file in on demand from the shared page cache, so only the EOCD,
// the central directory and the specific payloads we touch are ever resident,
// with no full-file copy in the process heap.
// ---------------------------------------------------------------------------
class MappedApk {
public:
    MappedApk() = default;
    ~MappedApk() { reset(); }
    MappedApk(const MappedApk&) = delete;
    MappedApk& operator=(const MappedApk&) = delete;

    bool map(const char* path) {
        reset();
        fd_ = ::open(path, O_RDONLY);
        if (fd_ < 0) return false;
        struct stat st;
        if (::fstat(fd_, &st) != 0 || st.st_size <= 0) {
            reset();
            return false;
        }
        size_ = static_cast<size_t>(st.st_size);
        data_ = static_cast<uint8_t*>(
            ::mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd_, 0));
        if (data_ == MAP_FAILED) {
            data_ = nullptr;
            size_ = 0;
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        return true;
    }

    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }

    void reset() {
        if (data_ && size_) ::munmap(data_, size_);
        data_ = nullptr;
        size_ = 0;
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
    int fd_ = -1;
};

// ---------------------------------------------------------------------------
// ZIP structures (little-endian)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct ZipEocd {
    uint32_t signature;        // 0x06054b50
    uint16_t disk_number;
    uint16_t central_dir_disk;
    uint16_t entries_on_disk;
    uint16_t total_entries;
    uint32_t central_dir_size;
    uint32_t central_dir_offset;
    uint16_t comment_length;
};

struct ZipCentralDirEntry {
    uint32_t signature;        // 0x02014b50
    uint16_t version_made;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
    uint16_t comment_length;
    uint16_t disk_start;
    uint16_t internal_attrs;
    uint32_t external_attrs;
    uint32_t local_header_offset;
};

struct ZipLocalFileHeader {
    uint32_t signature;        // 0x04034b50
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Overflow-safe bounds helper
//
// ZIP offsets/sizes come straight from the file and are 32-bit. On 32-bit
// ABIs a naive `a + b > cap` can wrap around (e.g. local_header_offset near
// 0xFFFFFFFF) and bypass the boundary check, leading to an out-of-bounds read
// (Segfault) on a hostile APK. Always compare in 64-bit.
// ---------------------------------------------------------------------------
static inline bool sum_exceeds(size_t a, size_t b, size_t cap) {
    return static_cast<uint64_t>(a) + static_cast<uint64_t>(b) >
           static_cast<uint64_t>(cap);
}

// ---------------------------------------------------------------------------
// Minimal DER/PKCS7 parser
// ---------------------------------------------------------------------------
struct DerNode {
    uint8_t tag;
    bool constructed;
    std::vector<uint8_t> value;   // raw value bytes (tag+length stripped)
    std::vector<DerNode> children;
};

static DerNode parse_der(const uint8_t* data, size_t offset, size_t end) {
    DerNode node;
    if (offset + 2 > end) return node;

    node.tag = data[offset];
    node.constructed = (node.tag & 0x20) != 0;
    size_t pos = offset + 1;

    // Length
    size_t length = 0;
    if (data[pos] & 0x80) {
        int num_bytes = data[pos] & 0x7f;
        if (num_bytes == 0 || num_bytes > 4) return node; // indefinite or too long
        pos++;
        if (pos + num_bytes > end) return node;
        for (int i = 0; i < num_bytes; i++) {
            length = (length << 8) | data[pos++];
        }
    } else {
        length = data[pos++];
    }

    // Clamp hostile long-form lengths (up to 0xFFFFFFFF) without overflow:
    // compare against the remaining space directly, never `pos + length`.
    if (length > end - pos) {
        length = end - pos;
    }

    node.value.assign(data + pos, data + pos + length);

    // Parse children for constructed tags
    if (node.constructed) {
        size_t child_pos = 0;
        while (child_pos < node.value.size()) {
            auto child = parse_der(node.value.data(), child_pos, node.value.size());
            if (child.value.empty() && child.children.empty()) break;
            node.children.push_back(child);
            child_pos += (child.tag == 0) ? 0 : (child.value.data() - node.value.data() + child.value.size() - child_pos);
            // Better: advance by the full encoded length
            // Recalculate:
            size_t consumed = 0;
            for (const auto& c : node.children) {
                consumed += 2; // tag + length (at minimum)
                if (c.value.size() > 127) consumed += (c.value.size() > 255) ? 3 : 2; // long-form length
                consumed += c.value.size();
            }
            child_pos = consumed;
        }
        // Re-parse more accurately
        node.children.clear();
        child_pos = 0;
        while (child_pos < node.value.size()) {
            // Skip tag byte
            if (child_pos >= node.value.size()) break;
            uint8_t child_tag = node.value[child_pos];
            size_t child_len_pos = child_pos + 1;
            if (child_len_pos >= node.value.size()) break;

            size_t child_length = 0;
            size_t child_len_bytes = 1;
            if (node.value[child_len_pos] & 0x80) {
                child_len_bytes = (node.value[child_len_pos] & 0x7f) + 1;
                if (child_len_bytes > 5) break;
                for (size_t i = 1; i < child_len_bytes; i++) {
                    if (child_len_pos + i >= node.value.size()) { child_len_bytes = 0; break; }
                    child_length = (child_length << 8) | node.value[child_len_pos + i];
                }
                if (child_len_bytes == 0) break;
            } else {
                child_length = node.value[child_len_pos];
            }

            size_t header_size = 1 + child_len_bytes;
            size_t child_end = child_pos + header_size + child_length;
            if (child_end > node.value.size()) break;

            DerNode child;
            child.tag = child_tag;
            child.constructed = (child_tag & 0x20) != 0;
            child.value.assign(node.value.data() + child_pos + header_size,
                               node.value.data() + child_end);
            if (child.constructed) {
                // Recursively parse children
                // (skip for now, we only need the leaf certificate)
            }
            node.children.push_back(child);
            child_pos = child_end;
        }
    }

    return node;
}

// Find a child node by tag (recursive, first match)
static const DerNode* find_der_child(const DerNode* node, uint8_t tag) {
    if (!node) return nullptr;
    for (const auto& child : node->children) {
        if (child.tag == tag) return &child;
    }
    for (const auto& child : node->children) {
        auto* found = find_der_child(&child, tag);
        if (found) return found;
    }
    return nullptr;
}

// Extract X.509 certificate from a PKCS7 SignedData (.RSA/.DSA/.EC file)
// The .RSA file is a DER-encoded PKCS7 ContentInfo containing SignedData.
// The certificates are in the "certificates" field [0] EXPLICIT SET OF Certificate.
static std::vector<uint8_t> extract_certificate_from_pkcs7(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    auto root = parse_der(data.data(), 0, data.size());
    if (root.children.empty()) return {};

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    auto* content_info = &root;
    if (content_info->tag != 0x30) { // SEQUENCE
        // Try the first child
        if (!content_info->children.empty())
            content_info = &content_info->children[0];
    }
    if (content_info->tag != 0x30) return {};

    // Find SignedData content [0] (context-specific, constructed, tag 0xa0)
    // ContentInfo.SEQUENCE -> first child is OID (0x06), second is [0] (0xa0)
    const DerNode* signed_data = nullptr;
    for (const auto& child : content_info->children) {
        if (child.tag == 0xa0) {
            // [0] EXPLICIT -> SignedData SEQUENCE inside
            if (!child.children.empty() && child.children[0].tag == 0x30) {
                signed_data = &child.children[0];
            }
        }
    }
    if (!signed_data) return {};

    // SignedData ::= SEQUENCE {
    //   version INTEGER,
    //   digestAlgorithms SET,
    //   encapContentInfo SEQUENCE,
    //   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,  <-- we want this
    //   ...
    // }
    // Find [0] (0xa0) tag in SignedData children
    for (const auto& child : signed_data->children) {
        if (child.tag == 0xa0) {
            // [0] IMPLICIT SET OF Certificate
            // Each child is a SEQUENCE (Certificate)
            for (const auto& cert : child.children) {
                if (cert.tag == 0x30) { // SEQUENCE = Certificate
                    // Reconstruct the full DER-encoded certificate
                    // Tag + length + value
                    std::vector<uint8_t> result;
                    // Construct the full DER encoding
                    size_t total_len = cert.value.size();
                    result.push_back(0x30); // SEQUENCE tag
                    if (total_len < 128) {
                        result.push_back(static_cast<uint8_t>(total_len));
                    } else if (total_len < 256) {
                        result.push_back(0x81);
                        result.push_back(static_cast<uint8_t>(total_len));
                    } else {
                        result.push_back(0x82);
                        result.push_back(static_cast<uint8_t>((total_len >> 8) & 0xff));
                        result.push_back(static_cast<uint8_t>(total_len & 0xff));
                    }
                    result.insert(result.end(), cert.value.begin(), cert.value.end());
                    return result;
                }
            }
        }
    }

    return {};
}

// Fallback: try to find the certificate by scanning for SEQUENCE tag at the
// right nesting level (simpler but less precise)
static std::vector<uint8_t> extract_certificate_fallback(const std::vector<uint8_t>& data) {
    // Look for the pattern: [0xa0] ... [0x30 <len> ...] (certificate)
    // This is a best-effort approach
    for (size_t i = 0; i + 4 < data.size(); i++) {
        // Look for a SEQUENCE (0x30) with reasonable length
        if (data[i] == 0x30) {
            size_t len = data[i + 1];
            size_t len_bytes = 1;
            if (len & 0x80) {
                len_bytes = len & 0x7f;
                if (len_bytes > 3) continue;
                len = 0;
                for (size_t j = 0; j < len_bytes; j++) {
                    if (i + 2 + j >= data.size()) { len = 0; break; }
                    len = (len << 8) | data[i + 2 + j];
                }
                len_bytes++; // include the length byte itself
            }
            if (len < 50 || len > 4096) continue; // unlikely to be a certificate

            // Check if this looks like a certificate (starts with TBSCertificate SEQUENCE)
            size_t header = 1 + len_bytes;
            if (i + header + 2 >= data.size()) continue;

            // A certificate starts with SEQUENCE { SEQUENCE { ... } }
            // The inner SEQUENCE (TBSCertificate) should be at offset header
            if (data[i + header] == 0x30) {
                // Good candidate - return the full DER encoding
                size_t full_len = header + len;
                if (i + full_len > data.size()) full_len = data.size() - i;
                return std::vector<uint8_t>(data.data() + i, data.data() + i + full_len);
            }
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Inflate a DEFLATE-compressed ZIP payload (compression method 8 / deflate).
// ZIP deflate streams have no zlib/gzip wrapper, so we pass -15 as the
// windowBits to inflateRaw.
//
// Used only for the small META-INF signature files; classes.dex is validated
// with the streaming helper below so a large dex is never materialized.
//
// Returns the decompressed bytes, or empty on failure.
static std::vector<uint8_t> inflate_deflate(
    const uint8_t* compressed, size_t compressed_len, size_t expected_uncompressed) {
    if (!compressed || compressed_len == 0) return {};

    z_stream strm = {};
    strm.next_in  = const_cast<Bytef*>(compressed);
    strm.avail_in = static_cast<uInt>(compressed_len);
    strm.zalloc   = Z_NULL;
    strm.zfree    = Z_NULL;
    strm.opaque   = Z_NULL;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) return {};

    std::vector<uint8_t> out;
    if (expected_uncompressed > 0 && expected_uncompressed <= 1u << 20)
        out.reserve(expected_uncompressed);

    std::vector<uint8_t> buf(16384);
    int status;
    do {
        strm.next_out  = buf.data();
        strm.avail_out = static_cast<uInt>(buf.size());
        status = inflate(&strm, Z_SYNC_FLUSH);
        if (status == Z_STREAM_ERROR || status == Z_DATA_ERROR ||
            status == Z_NEED_DICT || status == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return {};
        }
        size_t produced = buf.size() - strm.avail_out;
        if (produced > 0) {
            out.insert(out.end(), buf.data(), buf.data() + produced);
        }
        if (out.size() > 4u * 1024 * 1024) {
            LOGE("Inflated size exceeds 4 MB, aborting");
            inflateEnd(&strm);
            return {};
        }
        // Truncated / corrupted stream: input exhausted without reaching
        // Z_STREAM_END and no progress was made -> cannot continue.
        if (produced == 0 && strm.avail_in == 0 && status != Z_STREAM_END) {
            inflateEnd(&strm);
            return {};
        }
    } while (status != Z_STREAM_END);

    inflateEnd(&strm);

    if (expected_uncompressed > 0 && out.size() != expected_uncompressed) {
        LOGE("Inflate size mismatch: got %zu, expected %zu",
             out.size(), expected_uncompressed);
        return {};
    }
    return out;
}

// ---------------------------------------------------------------------------
// Streaming CRC32 over a DEFLATE payload.
//
// Inflates in small fixed-size chunks and feeds each chunk through crc32,
// discarding the data as it goes. A large classes.dex is therefore validated
// without ever being fully resident in memory, and without a hard output-size
// cap that would falsely fail legitimate multi-MB dex files.
//
// Returns true when the produced byte count matches [expected_uncompressed]
// and the resulting CRC32 equals [expected_crc].
// ---------------------------------------------------------------------------
static bool crc32_matches_inflated(const uint8_t* compressed, size_t compressed_len,
                                   size_t expected_uncompressed, uint32_t expected_crc) {
    if (!compressed || compressed_len == 0) return false;

    z_stream strm = {};
    strm.next_in  = const_cast<Bytef*>(compressed);
    strm.avail_in = static_cast<uInt>(compressed_len);
    strm.zalloc   = Z_NULL;
    strm.zfree    = Z_NULL;
    strm.opaque   = Z_NULL;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) return false;

    uint8_t buf[64 * 1024];
    uLong crc = crc32(0L, Z_NULL, 0);
    size_t produced_total = 0;
    int status;
    do {
        strm.next_out  = buf;
        strm.avail_out = sizeof(buf);
        status = inflate(&strm, Z_SYNC_FLUSH);
        if (status == Z_STREAM_ERROR || status == Z_DATA_ERROR ||
            status == Z_NEED_DICT || status == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return false;
        }
        size_t produced = sizeof(buf) - strm.avail_out;
        if (produced > 0) {
            crc = crc32(crc, buf, static_cast<uInt>(produced));
            produced_total += produced;
        }
        // Truncated / corrupted stream: input exhausted without reaching
        // Z_STREAM_END and no progress was made -> cannot continue.
        if (produced == 0 && strm.avail_in == 0 && status != Z_STREAM_END) {
            inflateEnd(&strm);
            return false;
        }
    } while (status != Z_STREAM_END);
    inflateEnd(&strm);

    if (produced_total != expected_uncompressed) return false;
    return static_cast<uint32_t>(crc) == expected_crc;
}

// ---------------------------------------------------------------------------
// Obfuscated expected signer digest
//
// The SHA-256 hex string of the official release signing certificate is
// stored XOR-encoded so it never appears as a plain-text literal in the
// binary. This makes it harder for crackers to find and replace the
// expected value when re-signing the APK with a different key.
//
// The expected hash below is:
//   90FEDAC1F020C6C5D1DD1A635DB5C3B7579F5B87647E2C2C00966D3BCB0F8B6F
// Encoded with XOR key 0xA5.
// ---------------------------------------------------------------------------
static const uint8_t kEncodedExpectedSha256[] = {
    0x9C, 0x95, 0xE3, 0xE0, 0xE1, 0xE4, 0xE6, 0x94, 0xE3, 0x95,
    0x97, 0x95, 0xE6, 0x93, 0xE6, 0x90, 0xE1, 0x94, 0xE1, 0xE1,
    0x94, 0xE4, 0x93, 0x96, 0x90, 0xE1, 0xE7, 0x90, 0xE6, 0x96,
    0xE7, 0x92, 0x90, 0x92, 0x9C, 0xE3, 0x90, 0xE7, 0x9D, 0x92,
    0x93, 0x91, 0x92, 0xE0, 0x97, 0xE6, 0x97, 0xE6, 0x95, 0x95,
    0x9C, 0x93, 0x93, 0xE1, 0x96, 0xE7, 0xE6, 0xE7, 0x95, 0xE3,
    0x9D, 0xE7, 0x93, 0xE3
};
static const size_t kEncodedExpectedSha256Len = 64;

// Also store MD5, SHA1, SHA512 for reference (all XOR-encoded with key 0xA5).
static const uint8_t kEncodedMD5[] = {
    0x91, 0x90, 0x96, 0x9C, 0x91, 0xE7, 0x93, 0xE4, 0x92, 0xE6,
    0x92, 0xE0, 0x91, 0x94, 0x90, 0x96, 0x9D, 0x93, 0x9D, 0x9D,
    0x96, 0xE7, 0xE4, 0xE3, 0xE6, 0xE6, 0x91, 0x90, 0xE7, 0x96,
    0xE7, 0xE1
};
static const uint8_t kEncodedSHA1[] = {
    0x92, 0xE4, 0x90, 0x9D, 0x90, 0x95, 0xE1, 0x93, 0xE4, 0xE6,
    0x96, 0x96, 0x96, 0x96, 0xE1, 0x90, 0xE0, 0xE7, 0x92, 0xE7,
    0xE6, 0xE7, 0x93, 0x91, 0x91, 0xE0, 0xE6, 0xE4, 0xE1, 0x96,
    0xE1, 0x90, 0xE4, 0x93, 0xE7, 0x9D, 0x9C, 0x91, 0x93, 0x90
};
static const uint8_t kEncodedSHA512[] = {
    0xE4, 0xE0, 0x91, 0x95, 0x97, 0xE1, 0x94, 0x93, 0x93, 0x90,
    0x95, 0x90, 0x97, 0x91, 0x93, 0x97, 0x93, 0xE4, 0xE4, 0x9D,
    0x96, 0x91, 0xE3, 0xE7, 0xE1, 0x95, 0xE7, 0x96, 0x97, 0x97,
    0xE3, 0x96, 0xE0, 0x93, 0x96, 0x95, 0x93, 0xE4, 0x95, 0x91,
    0x94, 0x9C, 0x9C, 0x91, 0xE7, 0x9C, 0x9D, 0x91, 0xE0, 0x95,
    0x96, 0x9D, 0xE0, 0xE6, 0x90, 0x91, 0x92, 0x97, 0x95, 0x90,
    0x95, 0xE6, 0x92, 0x90, 0x92, 0x93, 0xE6, 0x95, 0x97, 0x92,
    0xE7, 0xE3, 0xE3, 0xE6, 0x90, 0x92, 0x90, 0x90, 0xE1, 0x94,
    0x90, 0x96, 0xE6, 0x9D, 0x9D, 0x9D, 0x94, 0x9D, 0x9C, 0xE6,
    0x90, 0x9D, 0x91, 0xE6, 0x9C, 0x91, 0x91, 0x93, 0xE4, 0x92,
    0x92, 0x93, 0x93, 0xE4, 0x90, 0xE1, 0xE4, 0x91, 0x97, 0x91,
    0xE1, 0xE1, 0x9C, 0x96, 0x9D, 0xE7, 0xE3, 0x97, 0xE4, 0x9D,
    0x94, 0x92, 0xE4, 0x9C, 0xE7, 0x9C, 0xE0, 0x96
};

static const uint8_t kXorKey = 0xA5;

/**
 * Decodes a XOR-encoded hex string into a plain hex string.
 * The encoded data is XOR'd with kXorKey byte by byte.
 */
static std::string decode_xor_hex(const uint8_t* encoded, size_t len) {
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; i++) {
        result.push_back(static_cast<char>(encoded[i] ^ kXorKey));
    }
    return result;
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
//
// Self-contained implementation so the signer digest and APK hashes can be
// computed without Java MessageDigest, which hooking frameworks
// (TweakMe / SigKill / SignatureKiller) are able to intercept at the Java
// layer. The Java -> native bridge itself cannot be hooked the same way.
// ---------------------------------------------------------------------------
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

/**
 * Computes the SHA-256 of [data] and returns it as an UPPERCASE hex string.
 *
 * Uppercase matches the Kotlin-side fallback (java.util.Formatter "%02X"), so
 * native and Java computed digests compare equal regardless of which path
 * produced them.
 */
static std::string sha256_hex(const uint8_t* data, size_t len) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, data, len);
    uint8_t digest[32];
    sha256_final(&s, digest);
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; i++) {
        out.push_back(kHex[digest[i] >> 4]);
        out.push_back(kHex[digest[i] & 0x0F]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Expected package name pin
//
// The app's package name ("com.soreverse.mcp") is pinned here, XOR-obfuscated
// with the same key as the signer digest, so a repackaged build that changes
// the package / applicationId is rejected at the native layer even if the
// Java-level context.packageName is spoofed.
// ---------------------------------------------------------------------------
static const uint8_t kEncodedExpectedPackage[] = {
    0xC6, 0xCA, 0xC8, 0x8B, 0xD6, 0xCA, 0xD7, 0xC0, 0xD3, 0xC0,
    0xD7, 0xD6, 0xC0, 0x8B, 0xC8, 0xC6, 0xD5
};
static const size_t kEncodedExpectedPackageLen = sizeof(kEncodedExpectedPackage);

// ---------------------------------------------------------------------------
// APK integrity verification
//
// Parses the APK ZIP central directory and checks:
//   1. the ZIP structure is well-formed (EOCD + central directory in bounds);
//   2. the critical entries exist (classes.dex, AndroidManifest.xml,
//      resources.arsc, a META-INF/ *.RSA/.DSA/.EC signature file and at least
//      one bundled lib/<abi>/librz_native.so);
//   3. the classes.dex payload CRC32 matches the value declared in the central
//      directory, catching in-place byte patching of the dex.
//
// Errors are reported as a bitmask so callers can log the precise failure.
// ---------------------------------------------------------------------------
enum : int {
    kIntegrityOk                = 0,
    kIntegrityReadFailed        = 1 << 0, // APK unreadable / empty
    kIntegrityEocdNotFound      = 1 << 1, // not a valid ZIP
    kIntegrityCentralDirInvalid = 1 << 2, // central directory out of bounds
    kIntegrityMissingClasses    = 1 << 3, // classes.dex absent
    kIntegrityMissingManifest   = 1 << 4, // AndroidManifest.xml absent
    kIntegrityMissingArsc       = 1 << 5, // resources.arsc absent
    kIntegrityMissingSignature  = 1 << 6, // META-INF/*.{RSA,DSA,EC} absent
    kIntegrityMissingNative     = 1 << 7, // lib/<abi>/librz_native.so absent
    kIntegrityCrcMismatch       = 1 << 8, // classes.dex content CRC mismatch
};

// The bundled native library name is librz_native.so: CMakeLists.txt declares
// "add_library(rz_native SHARED ...)" (which yields librz_native.so), and the
// Kotlin side loads it via System.loadLibrary("rz_native"). The integrity
// check below therefore verifies that this exact library ships inside the APK
// under lib/<abi>/, so a repackaged build that strips the native verification
// code is rejected.

static int verify_apk_integrity(const uint8_t* apk, size_t apk_size) {
    if (!apk || apk_size < sizeof(ZipEocd)) return kIntegrityReadFailed;

    // Locate the End of Central Directory scanning backwards (the trailing
    // comment may be up to 64 KiB).
    size_t eocd_pos = apk_size - sizeof(ZipEocd);
    size_t search_start = (apk_size > 65557) ? apk_size - 65557 : 0;
    bool found = false;
    for (size_t i = eocd_pos; i >= search_start && i < apk_size; i--) {
        ZipEocd e;
        if (sum_exceeds(i, sizeof(ZipEocd), apk_size)) continue;
        std::memcpy(&e, apk + i, sizeof(ZipEocd));
        if (e.signature == 0x06054b50) { eocd_pos = i; found = true; break; }
        if (i == 0) break;
    }
    if (!found) return kIntegrityEocdNotFound;

    ZipEocd eocd;
    std::memcpy(&eocd, apk + eocd_pos, sizeof(ZipEocd));
    if (static_cast<uint64_t>(eocd.central_dir_offset) +
            static_cast<uint64_t>(eocd.central_dir_size) > apk_size) {
        return kIntegrityCentralDirInvalid;
    }

    bool has_classes = false, has_manifest = false, has_arsc = false;
    bool has_signature = false, has_native = false;
    bool crc_fail = false;

    size_t cd_pos = eocd.central_dir_offset;
    for (uint16_t i = 0;
         i < eocd.total_entries && !sum_exceeds(cd_pos, sizeof(ZipCentralDirEntry), apk_size);
         i++) {
        ZipCentralDirEntry entry;
        std::memcpy(&entry, apk + cd_pos, sizeof(ZipCentralDirEntry));
        if (entry.signature != 0x02014b50) break;
        if (sum_exceeds(cd_pos, sizeof(ZipCentralDirEntry) + entry.filename_length, apk_size)) break;

        std::string name(
            reinterpret_cast<const char*>(apk + cd_pos + sizeof(ZipCentralDirEntry)),
            entry.filename_length);

        if (name == "classes.dex") {
            has_classes = true;
            // Verify the on-disk payload CRC32 against the central directory
            // value, so in-place patching of the dex is detected even when the
            // ZIP structure itself is still intact. Uses bounded memory: stored
            // payloads are crc'd in place, deflate payloads are streamed.
            size_t local_offset = entry.local_header_offset;
            if (sum_exceeds(local_offset, sizeof(ZipLocalFileHeader), apk_size)) {
                crc_fail = true;
            } else {
                ZipLocalFileHeader local;
                std::memcpy(&local, apk + local_offset, sizeof(ZipLocalFileHeader));
                if (local.signature != 0x04034b50) {
                    crc_fail = true;
                } else {
                    uint64_t data_off = static_cast<uint64_t>(local_offset) +
                                        sizeof(ZipLocalFileHeader) +
                                        local.filename_length + local.extra_length;
                    if (data_off > apk_size ||
                        data_off + entry.compressed_size > apk_size) {
                        crc_fail = true;
                    } else {
                        size_t data_offset = static_cast<size_t>(data_off);
                        if (entry.compression == 0) {
                            uLong actual = crc32(0L, Z_NULL, 0);
                            actual = crc32(actual, apk + data_offset,
                                           static_cast<uInt>(entry.compressed_size));
                            if (static_cast<uint32_t>(actual) != entry.crc32) crc_fail = true;
                        } else if (entry.compression == 8) {
                            if (!crc32_matches_inflated(
                                    apk + data_offset, entry.compressed_size,
                                    entry.uncompressed_size, entry.crc32)) {
                                crc_fail = true;
                            }
                        } else {
                            crc_fail = true; // unsupported compression for classes.dex
                        }
                    }
                }
            }
        } else if (name == "AndroidManifest.xml") {
            has_manifest = true;
        } else if (name == "resources.arsc") {
            has_arsc = true;
        } else if (name.rfind("META-INF/", 0) == 0) {
            std::string lower = name;
            for (auto& c : lower) c = static_cast<char>(tolower(c));
            if (lower.size() > 4) {
                std::string ext = lower.substr(lower.size() - 4);
                if (ext == ".rsa" || ext == ".dsa" || ext == ".ec") has_signature = true;
            }
        } else if (name.rfind("lib/", 0) == 0 &&
                   name.find("librz_native.so") != std::string::npos) {
            has_native = true;
        }

        // Advance to the next central-directory entry. Compute in 64-bit and
        // stop as soon as the next entry would leave the file, so a hostile
        // APK cannot make cd_pos wrap around on 32-bit ABIs.
        uint64_t next_cd =
            static_cast<uint64_t>(cd_pos) + sizeof(ZipCentralDirEntry) +
            entry.filename_length + entry.extra_length + entry.comment_length;
        if (next_cd > apk_size) break;
        cd_pos = static_cast<size_t>(next_cd);
    }

    int result = kIntegrityOk;
    if (!has_classes) result |= kIntegrityMissingClasses;
    if (!has_manifest) result |= kIntegrityMissingManifest;
    if (!has_arsc) result |= kIntegrityMissingArsc;
    if (!has_signature) result |= kIntegrityMissingSignature;
    if (!has_native) result |= kIntegrityMissingNative;
    if (crc_fail) result |= kIntegrityCrcMismatch;
    return result;
}

// ---------------------------------------------------------------------------
// JNI entry points
// ---------------------------------------------------------------------------

/**
 * Returns the expected SHA-256 digest of the official release signing
 * certificate. The value is stored XOR-encoded in the binary and decoded
 * at runtime, so it does not appear as a plain-text literal.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_SignatureVerifier_nativeGetExpectedSignerDigest(
    JNIEnv* env, jobject thiz) {
    std::string digest = decode_xor_hex(kEncodedExpectedSha256, kEncodedExpectedSha256Len);
    return env->NewStringUTF(digest.c_str());
}

/**
 * Reads the APK file directly from the filesystem and extracts the first
 * X.509 signing certificate from the META-INF/ *.RSA/.DSA/.EC signature file.
 *
 * This bypasses the Java PackageManager API, which is what kstools and
 * ApkSignatureKiller hook to replace signatures.
 *
 * @param env       JNI environment
 * @param thiz      JNI object
 * @param apkPath   Absolute path to the APK file (e.g., context.packageCodePath)
 * @return          DER-encoded X.509 certificate bytes, or null on failure
 */
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_nativecore_SignatureVerifier_nativeReadApkCertificate(
    JNIEnv* env, jobject thiz, jstring apkPath) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return nullptr;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    LOGI("Reading APK: %s", path.c_str());

    // Map the APK read-only instead of loading the whole file into the heap
    // (avoids OOM on large APKs).
    MappedApk apk;
    if (!apk.map(path.c_str())) {
        LOGE("Failed to map APK: %s", path.c_str());
        return nullptr;
    }
    const uint8_t* apk_data = apk.data();
    size_t apk_size = apk.size();

    // Find End of Central Directory
    if (apk_size < sizeof(ZipEocd)) {
        LOGE("APK too small");
        return nullptr;
    }

    // Search for EOCD signature from the end (with max comment length)
    size_t eocd_pos = apk_size - sizeof(ZipEocd);
    size_t search_start = (apk_size > 65557) ? apk_size - 65557 : 0;
    bool found_eocd = false;

    for (size_t i = eocd_pos; i >= search_start && i < apk_size; i--) {
        ZipEocd eocd;
        if (sum_exceeds(i, sizeof(ZipEocd), apk_size)) continue;
        std::memcpy(&eocd, apk_data + i, sizeof(ZipEocd));
        if (eocd.signature == 0x06054b50) {
            eocd_pos = i;
            found_eocd = true;
            break;
        }
        if (i == 0) break;
    }

    if (!found_eocd) {
        LOGE("EOCD not found");
        return nullptr;
    }

    ZipEocd eocd;
    std::memcpy(&eocd, apk_data + eocd_pos, sizeof(ZipEocd));
    LOGI("Central dir: offset=%u, size=%u, entries=%u",
         eocd.central_dir_offset, eocd.central_dir_size, eocd.total_entries);

    if (sum_exceeds(eocd.central_dir_offset, eocd.central_dir_size, apk_size)) {
        LOGE("Central directory exceeds file bounds");
        return nullptr;
    }

    // Scan central directory for META-INF signature files
    const char* signature_prefix = "META-INF/";
    size_t prefix_len = strlen(signature_prefix);
    std::vector<uint8_t> signature_file_data;
    std::string signature_filename;

    size_t cd_pos = eocd.central_dir_offset;
    for (uint16_t i = 0; i < eocd.total_entries; i++) {
        if (sum_exceeds(cd_pos, sizeof(ZipCentralDirEntry), apk_size)) {
            LOGE("Central directory entry %d out of bounds", i);
            break;
        }

        ZipCentralDirEntry entry;
        std::memcpy(&entry, apk_data + cd_pos, sizeof(ZipCentralDirEntry));

        if (entry.signature != 0x02014b50) {
            LOGE("Invalid central directory signature at entry %d", i);
            break;
        }

        if (sum_exceeds(cd_pos, sizeof(ZipCentralDirEntry) + entry.filename_length,
                        apk_size)) {
            break;
        }

        std::string filename(
            reinterpret_cast<const char*>(apk_data + cd_pos + sizeof(ZipCentralDirEntry)),
            entry.filename_length);

        // Check if this is a META-INF signature file
        if (filename.size() > prefix_len &&
            filename.compare(0, prefix_len, signature_prefix) == 0) {

            // Check file extension
            std::string lower = filename;
            for (auto& c : lower) c = static_cast<char>(tolower(c));
            bool is_sig_file = false;
            if (lower.size() > 4) {
                std::string ext = lower.substr(lower.size() - 4);
                is_sig_file = (ext == ".rsa" || ext == ".dsa" || ext == ".ec");
            }

            if (is_sig_file) {
                LOGI("Found signature file: %s (compression=%u, size=%u)",
                     filename.c_str(), entry.compression, entry.uncompressed_size);

                // Read the file data from the local file header
                size_t local_offset = entry.local_header_offset;
                if (sum_exceeds(local_offset, sizeof(ZipLocalFileHeader), apk_size)) {
                    LOGE("Local header offset out of bounds for %s", filename.c_str());
                    continue;
                }

                ZipLocalFileHeader local;
                std::memcpy(&local, apk_data + local_offset, sizeof(ZipLocalFileHeader));

                if (local.signature != 0x04034b50) {
                    LOGE("Invalid local file header signature for %s", filename.c_str());
                    continue;
                }

                uint64_t data_off = static_cast<uint64_t>(local_offset) +
                                    sizeof(ZipLocalFileHeader) +
                                    local.filename_length + local.extra_length;
                if (data_off > apk_size ||
                    data_off + entry.compressed_size > apk_size) {
                    LOGE("File data out of bounds for %s", filename.c_str());
                    continue;
                }
                size_t data_offset = static_cast<size_t>(data_off);

                // For META-INF signature files, compression is typically 0 (stored)
                if (entry.compression == 0) {
                    signature_file_data.assign(
                        apk_data + data_offset,
                        apk_data + data_offset + entry.uncompressed_size);
                    signature_filename = filename;
                    LOGI("Read signature file: %s (%zu bytes)", filename.c_str(), signature_file_data.size());
                    break;
                } else {
                    LOGI("Signature file %s is compressed (type %u), decompressing",
                         filename.c_str(), entry.compression);
                    if (entry.compression == 8) {
                        // Raw DEFLATE stream (no zlib/gzip wrapper): feed the
                        // mapped compressed bytes to inflate_deflate and obtain
                        // the uncompressed PKCS7 bytes.
                        signature_file_data =
                            inflate_deflate(apk_data + data_offset,
                                            entry.compressed_size,
                                            entry.uncompressed_size);
                        if (signature_file_data.empty()) {
                            LOGE("Failed to decompress %s", filename.c_str());
                            continue;
                        }
                        signature_filename = filename;
                        LOGI("Decompressed signature file: %s (%u -> %zu bytes)",
                             filename.c_str(), entry.compressed_size,
                             signature_file_data.size());
                        break;
                    }
                    LOGE("Unsupported compression method %u for %s",
                         entry.compression, filename.c_str());
                }
            }
        }

        // Advance to the next central-directory entry. Compute in 64-bit and
        // stop as soon as the next entry would leave the file, so a hostile
        // APK cannot make cd_pos wrap around on 32-bit ABIs.
        uint64_t next_cd =
            static_cast<uint64_t>(cd_pos) + sizeof(ZipCentralDirEntry) +
            entry.filename_length + entry.extra_length + entry.comment_length;
        if (next_cd > apk_size) break;
        cd_pos = static_cast<size_t>(next_cd);
    }

    if (signature_file_data.empty()) {
        LOGE("No signature file found in META-INF");
        return nullptr;
    }

    LOGI("Signature file size: %zu bytes", signature_file_data.size());

    // Extract certificate from PKCS7 signature
    auto cert = extract_certificate_from_pkcs7(signature_file_data);
    if (cert.empty()) {
        LOGI("Structured PKCS7 parsing failed, trying fallback");
        cert = extract_certificate_fallback(signature_file_data);
    }

    if (cert.empty()) {
        LOGE("Failed to extract certificate from signature file");
        return nullptr;
    }

    LOGI("Extracted certificate: %zu bytes", cert.size());

    // Return the certificate bytes to Java
    jbyteArray result = env->NewByteArray(static_cast<jsize>(cert.size()));
    if (!result) {
        LOGE("Failed to allocate Java byte array");
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(cert.size()),
                            reinterpret_cast<const jbyte*>(cert.data()));
    return result;
}

/**
 * Verifies that the running package name matches the pinned value
 * ("com.soreverse.mcp"). The expected value is stored XOR-obfuscated in the
 * binary, so a repackaged build with a changed applicationId is rejected here
 * even if the Java context reports a spoofed package name.
 *
 * @return JNI_TRUE if [packageName] matches the pin, JNI_FALSE otherwise.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_nativecore_SignatureVerifier_nativeVerifyPackageName(
    JNIEnv* env, jobject thiz, jstring packageName) {

    if (!packageName) {
        LOGE("packageName is null");
        return JNI_FALSE;
    }

    const char* pkg = env->GetStringUTFChars(packageName, nullptr);
    if (!pkg) {
        LOGE("Failed to read package name");
        return JNI_FALSE;
    }
    std::string actual(pkg);
    env->ReleaseStringUTFChars(packageName, pkg);

    std::string expected =
        decode_xor_hex(kEncodedExpectedPackage, kEncodedExpectedPackageLen);
    if (actual != expected) {
        LOGE("Package name MISMATCH (expected=%s, actual=%s)",
             expected.c_str(), actual.c_str());
        return JNI_FALSE;
    }
    LOGI("Package name verified: %s", expected.c_str());
    return JNI_TRUE;
}

/**
 * Verifies the integrity of the APK at [apkPath] by parsing its ZIP central
 * directory directly from the filesystem:
 *   - structural sanity (EOCD / central directory bounds);
 *   - presence of critical entries (classes.dex, AndroidManifest.xml,
 *     resources.arsc, META-INF signature file, lib/<abi>/librz_native.so);
 *   - CRC32 of the classes.dex payload vs. the central directory value.
 *
 * @return 0 on success, or a bitmask of kIntegrity* flags on failure.
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_soreverse_mcp_nativecore_SignatureVerifier_nativeVerifyApkIntegrity(
    JNIEnv* env, jobject thiz, jstring apkPath) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return kIntegrityReadFailed;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    if (!path_cstr) {
        LOGE("Failed to read apkPath");
        return kIntegrityReadFailed;
    }
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    MappedApk apk;
    if (!apk.map(path.c_str())) {
        LOGE("Failed to map APK for integrity check: %s", path.c_str());
        return kIntegrityReadFailed;
    }

    int result = verify_apk_integrity(apk.data(), apk.size());
    if (result != kIntegrityOk) {
        LOGE("APK integrity check FAILED (code=0x%X): %s", result, path.c_str());
    }
    return result;
}

/**
 * Computes the SHA-256 of [data] and returns it as an UPPERCASE hex string.
 *
 * Kotlin uses this instead of java.security.MessageDigest so a Java-layer
 * hook of MessageDigest (used by signature-bypass frameworks) cannot alter
 * the digest result. Uppercase matches the Java fallback formatter ("%02X").
 *
 * @return uppercase hex SHA-256 string, or null on failure.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_SignatureVerifier_nativeComputeSha256Hex(
    JNIEnv* env, jobject thiz, jbyteArray data) {

    if (!data) {
        LOGE("data is null");
        return nullptr;
    }

    jsize len = env->GetArrayLength(data);
    if (len < 0) {
        LOGE("Invalid array length");
        return nullptr;
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(len));
    env->GetByteArrayRegion(data, 0, len,
                            reinterpret_cast<jbyte*>(bytes.data()));

    std::string hex = sha256_hex(bytes.data(), bytes.size());
    return env->NewStringUTF(hex.c_str());
}