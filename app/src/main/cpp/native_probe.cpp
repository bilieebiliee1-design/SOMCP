/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (C) 2026 bilieebiliee1-design
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * native_probe.cpp
 *
 * Filesystem-level package record reader.
 *
 * WHY THE FILE IS READ DIRECTLY:
 *   The package metadata exposed through the Java PackageManager Binder
 *   interface can be substituted in place by runtime patching frameworks. When
 *   the app calls getPackageInfo() with GET_SIGNATURES or
 *   GET_SIGNING_CERTIFICATES, such a hook replaces the returned certificate
 *   array with the original one, so a repackaged build appears to carry the
 *   original record.
 *
 * WHAT THIS DOES INSTEAD:
 *   This code reads the package file directly from the filesystem, parses the
 *   ZIP central directory, extracts the META-INF/ *.RSA/.DSA/.EC entry, and
 *   returns the embedded X.509 record. Because it accesses the file at the
 *   filesystem level rather than through the Java PackageManager API, a
 *   Binder-level substitution cannot reach it.
 *
 *   The calling Kotlin code then computes the SHA-256 fingerprint of the
 *   record and compares it against the pinned release value.
 */

#include <jni.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/sysmacros.h>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#define LOG_TAG "NativeProbe"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
// ---------------------------------------------------------------------------
// Anti-redirect raw file access
//
// Every filesystem-level identity check in this file used to open the package
// file through the libc `open`, which lives on this .so's PLT/GOT. Hooking
// frameworks (xhook/bhook PLT patching — the SoLab "original_apk" mode and the
// DPatch "native redirect" payload do exactly this) redirect open/openat/fopen
// for a target ELF to a preserved copy of the ORIGINAL APK, which makes every
// file-content check pass against the untampered file while the process really
// executes the repack. Defense in depth used here:
//   1. open via a raw `svc` instruction on arm64 (no PLT/GOT entry involved;
//      the payloads only patch libc symbol stubs, never inline assembly);
//   2. cross-check fstat(fd) against stat(path) by dev+ino, so an open that
//      was redirected to a different file is caught even without maps;
//   3. for checks against the RUNNING package, require the opened inode to be
//      one of the `.apk` files mapped into this process according to
//      /proc/self/maps — the image the kernel actually executes from. The
//      path string may be attacker-influenced (it comes through JNI), but the
//      mapping set is produced by the kernel at exec/dlopen time.
// ---------------------------------------------------------------------------

static int raw_sys_openat(const char* path) {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_openat;
    register long x0 __asm__("x0") = AT_FDCWD;
    register long x1 __asm__("x1") = reinterpret_cast<long>(path);
    register long x2 __asm__("x2") = O_RDONLY | O_CLOEXEC;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return static_cast<int>(x0);
#elif defined(__arm__)
    // R7 is a reserved register on Android ARM (frame pointer / TLS), so the
    // compiler rejects binding a C variable to it. Load the syscall number into
    // R7 from a plain input inside the asm and clobber R7 so the frame pointer
    // is preserved across the svc.
    register long r0 __asm__("r0") = AT_FDCWD;
    register long r1 __asm__("r1") = reinterpret_cast<long>(path);
    register long r2 __asm__("r2") = O_RDONLY | O_CLOEXEC;
    long nr = SYS_openat;
    __asm__ volatile("mov r7, %1\n"
                     "svc #0\n"
                     : "+r"(r0)
                     : "r"(nr), "r"(r1), "r"(r2)
                     : "r7", "memory");
    return static_cast<int>(r0);
#else
    return static_cast<int>(::syscall(SYS_openat, AT_FDCWD, path,
                                      O_RDONLY | O_CLOEXEC, 0));
#endif
}

/** Result of mapping a package file through the anti-redirect channel. */
enum MapStatus {
    kMapOk = 0,
    kMapFailed = 1,         // could not open/read the path at all
    kMapRedirected = 2,     // fd and path name different files (open() hooked)
    kMapNotRunningApk = 3,  // opened file is not the mapped running APK
};

/**
 * Verifies that [fd] refers to one of the `.apk` images this process actually
 * executes from, per /proc/self/maps. Returns false only when the maps listing
 * DOES contain .apk mappings and none of them matches [fd]'s dev+ino; an
 * unreadable or .apk-free listing (fully-extracted install) is inconclusive
 * and reported as a pass so a quirk of the device cannot brick the app.
 */
static bool fd_is_mapped_apk(int fd) {
    struct stat st;
    if (::fstat(fd, &st) != 0) return true;  // inconclusive

    int mfd = raw_sys_openat("/proc/self/maps");
    if (mfd < 0) return true;

    bool saw_apk = false;
    bool matched = false;
    char buf[4096];
    std::string carry;
    for (;;) {
        ssize_t n = ::read(mfd, buf, sizeof(buf));
        if (n <= 0) break;
        carry.append(buf, static_cast<size_t>(n));
        size_t nl;
        while ((nl = carry.find('\n')) != std::string::npos) {
            std::string line = carry.substr(0, nl);
            carry.erase(0, nl + 1);
            // format: start-end perms offset dev inode [path]
            // dev/ino come after 4 whitespace-separated fields; the path (if
            // any) starts at the 6th field, after exactly one space.
            std::string f[5];
            size_t pos = 0;
            bool has_path = true;
            for (size_t fi = 0; fi < 5; fi++) {
                while (pos < line.size() && line[pos] == ' ') pos++;
                size_t s = pos;
                while (pos < line.size() && line[pos] != ' ') pos++;
                if (pos == s) { has_path = false; break; }
                f[fi] = line.substr(s, pos - s);
            }
            if (!has_path) continue;
            while (pos < line.size() && line[pos] == ' ') pos++;
            if (pos >= line.size()) continue;  // no path column ([vdso], anon)
            std::string path = line.substr(pos);
            size_t bang = path.find('!');  // "base.apk!lib/foo.so"
            if (bang != std::string::npos) path = path.substr(0, bang);
            if (path.size() < 4 || path.compare(path.size() - 4, 4, ".apk") != 0)
                continue;
            saw_apk = true;
            // f[3] is "dev" as hex:hex, f[4] is the inode in decimal
            unsigned int major = 0, minor = 0;
            if (std::sscanf(f[3].c_str(), "%x:%x", &major, &minor) != 2)
                continue;
            dev_t dev = makedev(major, minor);
            ino_t ino = static_cast<ino_t>(std::strtoull(f[4].c_str(), nullptr, 10));
            if (dev == st.st_dev && ino == st.st_ino) {
                matched = true;
                break;
            }
        }
        if (matched) break;
        if (carry.size() > (1u << 20)) carry.clear();  // unbounded-line guard
    }
    ::close(mfd);
    if (!saw_apk) return true;  // inconclusive
    return matched;
}

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

    bool map(const char* path) { return map_status(path, false) == kMapOk; }

    /**
     * Maps [path] through the anti-redirect channel.
     * @param require_running true when [path] claims to be the package this
     *        process executes from; the mapping is then additionally cross-
     *        checked against /proc/self/maps.
     */
    MapStatus map_status(const char* path, bool require_running) {
        reset();
        fd_ = raw_sys_openat(path);
        if (fd_ < 0) return kMapFailed;
        struct stat st_fd;
        if (::fstat(fd_, &st_fd) != 0 || st_fd.st_size <= 0) {
            reset();
            return kMapFailed;
        }
        struct stat st_path;
        if (::stat(path, &st_path) == 0 &&
            (st_path.st_dev != st_fd.st_dev || st_path.st_ino != st_fd.st_ino)) {
            // open() was redirected: the fd names a different file than path.
            reset();
            return kMapRedirected;
        }
        if (require_running && !fd_is_mapped_apk(fd_)) {
            reset();
            return kMapNotRunningApk;
        }
        size_ = static_cast<size_t>(st_fd.st_size);
        data_ = static_cast<uint8_t*>(
            ::mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd_, 0));
        if (data_ == MAP_FAILED) {
            data_ = nullptr;
            size_ = 0;
            reset();
            return kMapFailed;
        }
        return kMapOk;
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
// Little-endian readers with bounds checks
// ---------------------------------------------------------------------------
static inline bool in_bounds(size_t off, size_t len, size_t end) {
    return off <= end && len <= end - off;
}

static bool read_u32le(const uint8_t* p, size_t off, size_t end, uint32_t* out) {
    if (!in_bounds(off, 4, end)) return false;
    const uint8_t* b = p + off;
    *out = static_cast<uint32_t>(b[0]) |
           (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
    return true;
}

static bool read_u64le(const uint8_t* p, size_t off, size_t end, uint64_t* out) {
    if (!in_bounds(off, 8, end)) return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<uint64_t>(p[off + i]) << (8 * i);
    }
    *out = v;
    return true;
}

// ---------------------------------------------------------------------------
// APK Signature Scheme v2 / v3 verification support
//
// WHY (compare with google/apksigner's strongest-scheme rule):
//   Modern APKs are signed with up to three schemes: v1 (JAR) whose signing
//   certificate lives in META-INF/ *.RSA, and v2/v3 whose signing certificate
//   lives in the "APK Signing Block" located immediately before the ZIP
//   central directory.
//
//   Android reads the highest available scheme and treats the
//   schemes as independent. A subtle, well-known bypass (demonstrated by
//   a documented scheme-confusion case) works by
//   exploiting the difference between v1 and v2/v3 handling:
//     * an attacker preserves the ORIGINAL META-INF/ *.RSA v1 signature files
//       (so a checker that only reads v1 sees the genuine certificate and
//       passes the digest comparison), while
//     * re-signing the same APK with a NEW key in the v2/v3 APK Signing Block
//       (which cryptographically covers the file content), so the system
//       install path accepts the attacker's key.
//   A check that reads only the v1 certificate therefore accepts a
//   repackaged APK controlled by the attacker - exactly the failure mode our
//   own previous implementation was exposed to.
//
//   This implementation therefore ALSO reads the signing
//   certificate from the v2/v3 APK Signing Block. Because the v2/v3 signature
//   covers the whole file, an attacker cannot keep our certificate there while
//   using their own key; requiring the v2/v3 signer digest to match the pin
//   closes the scheme-confusion gap.
// ---------------------------------------------------------------------------

// ASCII "APK Sig Block 42" (16 bytes), tags the end of the APK Signing Block.
static const uint8_t kApkSigBlockMagic[16] = {
    'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
    'B', 'l', 'o', 'c', 'k', ' ', '4', '2'
};

// v2 / v3 APK Signing Block entry IDs.
static const uint32_t kApkSigSchemeV2BlockId = 0x7109871a;
static const uint32_t kApkSigSchemeV3BlockId = 0xf05368c0;

/**
 * Locates a signing certificate inside an APK Signature Scheme v2/v3 block.
 *
 * @param block      pointer to the block payload for the requested scheme
 * @param block_len  length of the block payload
 * @param out_cert   receives the first X.509 certificate (DER) if found
 * @return true when a certificate was extracted
 */
static bool extract_cert_from_sign_block(const uint8_t* block, size_t block_len,
                                         std::vector<uint8_t>& out_cert) {
    out_cert.clear();
    if (!block || block_len == 0) return false;

    // Block layout (AOSP apksig): the scheme-block value is
    //   LengthPrefixed( sequence of LengthPrefixed(signer) )
    // i.e. an outer 4-byte length wraps the whole signers sequence, and each
    // signer inside it carries its own length prefix. A previous version of
    // this parser skipped the outer length prefix, which shifted every field
    // one level up: it treated the signers-sequence length as the signer
    // length, then read signedData/digests lengths from the next level's
    // length fields. The "certificate" it returned was actually read from the
    // middle of the signatures blob (a wrong-size chunk whose digest can never
    // match the pin) - that is why the v2/v3 check failed on the release APKs
    // and killed the app at startup (issues #56 / #59).
    size_t pos = 0;

    // --- signers : length-prefixed sequence ---
    uint32_t seq_len = 0;
    if (!read_u32le(block, pos, block_len, &seq_len)) return false;
    if (!in_bounds(pos + 4, seq_len, block_len)) return false;
    const size_t seq = pos + 4;
    const size_t seq_end = seq + seq_len;

    // --- signer : length-prefixed ---
    uint32_t signer_len = 0;
    if (!read_u32le(block, seq, seq_end, &signer_len)) return false;
    if (!in_bounds(seq + 4, signer_len, seq_end)) return false;
    const size_t signer = seq + 4;
    const size_t signer_end = signer + signer_len;

    // --- signer.signedData : length-prefixed ---
    uint32_t sd_len = 0;
    if (!read_u32le(block, signer, signer_end, &sd_len)) return false;
    if (!in_bounds(signer + 4, sd_len, signer_end)) return false;
    const size_t sd = signer + 4;
    const size_t sd_end = sd + sd_len;

    // --- signedData.digests : length-prefixed, then certificates ---
    uint32_t digests_len = 0;
    if (!read_u32le(block, sd, sd_end, &digests_len)) return false;
    if (!in_bounds(sd + 4, digests_len, sd_end)) return false;

    uint32_t certs_len = 0;
    const size_t digests_end = sd + 4 + digests_len;
    if (!in_bounds(digests_end, 4, sd_end)) return false;
    if (!read_u32le(block, digests_end, sd_end, &certs_len)) return false;
    if (!in_bounds(digests_end + 4, certs_len, sd_end)) return false;

    // --- certificates : sequence of length-prefixed X.509 certs ---
    const size_t certs = digests_end + 4;
    const size_t certs_end = certs + certs_len;
    size_t c = certs;
    uint32_t cert_len = 0;
    if (!read_u32le(block, c, certs_end, &cert_len)) return false;
    if (!in_bounds(c + 4, cert_len, certs_end)) return false;
    out_cert.assign(block + c + 4, block + c + 4 + cert_len);
    return !out_cert.empty();
}

/**
 * Finds the APK Signing Block (the v2/v3 signing-block container) and, if the
 * requested scheme block is present, extracts its first signing certificate.
 *
 * Layout (see google/apksigner ApkSigningBlockUtils):
 *   ... [ uint64 signingBlockSize ][ block pairs (each uint64 size + uint32 id
 *   + value) ... ][ uint64 signingBlockSize ][ "APK Sig Block 42" magic ]
 *   |<------------ signing_block_size bytes ----------------->|
 *   immediately followed by the ZIP central directory.
 *
 * @param apk                 mapped APK bytes
 * @param apk_size            size of the mapping
 * @param central_dir_offset  byte offset of the first central-directory entry
 * @param prefer_v3           prefer the v3 signer certificate over v2
 * @param out_cert            receives the signing certificate (DER) if found
 * @return 1 if a v2/v3 sequence signer was found and parsed, 0 if no signing
 *         block / no matching scheme id was found, -1 on a malformed block
 *         (bounds violation) that should be treated as a hard failure.
 */
static int find_apk_sign_block_cert(const uint8_t* apk, size_t apk_size,
                                    uint64_t central_dir_offset,
                                    bool prefer_v3,
                                    std::vector<uint8_t>& out_cert) {
    out_cert.clear();
    if (central_dir_offset < 16 ||
        central_dir_offset > static_cast<uint64_t>(apk_size)) {
        return -1;
    }

    const size_t magic_off = static_cast<size_t>(central_dir_offset) - 16;
    if (std::memcmp(apk + magic_off, kApkSigBlockMagic, sizeof(kApkSigBlockMagic)) != 0) {
        return 0; // not signed with a v2/v3 signing block
    }

    uint64_t block_size = 0;
    if (!read_u64le(apk, magic_off - 8, apk_size, &block_size)) return -1;

    const uint64_t block_end = static_cast<uint64_t>(magic_off) - 8;
    // Guard against underflow on tiny/hostile APKs: there must be room for the
    // trailing 8-byte size field plus a leading size field before the first
    // block pair may be read.
    if (block_end < 16) return -1;
    if (block_size > block_end) return -1; // hostile size: cannot wrap

    // [region_start, block_end) is the APK Signing Block payload. Some real
    // signers emit a handful of signing-block "header"/extension bytes before
    // the first pair, so the leading size field is NOT guaranteed to sit at
    // exactly `block_end - block_size`, and a strict `leading == trailing`
    // cross-check would reject legitimate APKs (the app's own signed builds,
    // for instance, carry such header bytes). We therefore do NOT hard-fail on
    // that cross-check; instead we scan the region for a v2/v3 signer pair and
    // parse it in place.
    const size_t region_start = static_cast<size_t>(block_end - block_size);
    const size_t region_end   = static_cast<size_t>(block_end);

    std::vector<uint8_t> v2_cert, v3_cert;
    bool scheme_reported = false; // any valid v2/v3 signer found

    // Scan for a length-prefixed pair with a v2/v3 block id. The pair is laid
    // out as [uint64 pair_size][uint32 id][value]. We locate the id, then read
    // the size field eight bytes before it and extract the value that follows.
    // Scanning rather than walking sequentially also tolerates nonstandard
    // bytes between blocks. False positives inside another block's value are
    // harmless: extract_cert_from_sign_block bounds-checks the signer
    // structure and simply fails, so we keep scanning.
    for (size_t off = region_start;
         off + 4 <= region_end; off++) {
        uint32_t id = 0;
        if (!read_u32le(apk, off, region_end, &id)) break;
        if (id != kApkSigSchemeV3BlockId && id != kApkSigSchemeV2BlockId) continue;

        // A valid pair header has its 8-byte size field within the region and
        // the value fully in bounds.
        if (off < region_start + 8) continue;
        uint64_t pair_size = 0;
        if (!read_u64le(apk, off - 8, region_end, &pair_size)) continue;
        if (pair_size < 4) continue; // must contain the 4-byte id plus value
        if (pair_size - 4 > region_end - off - 4) continue;

        const size_t value_len = static_cast<size_t>(pair_size - 4);
        const uint8_t* value = apk + off + 4;

        if (id == kApkSigSchemeV3BlockId) {
            if (extract_cert_from_sign_block(value, value_len, v3_cert)) scheme_reported = true;
        } else {
            if (extract_cert_from_sign_block(value, value_len, v2_cert)) scheme_reported = true;
        }
    }

    if (!scheme_reported) return 0; // signing block present but no valid v2/v3 signer

    // Prefer the highest available scheme (v3 over v2) unless the caller asked
    // otherwise, mirroring Android's "strongest scheme wins" behaviour.
    std::vector<uint8_t> chosen;
    if (prefer_v3 && !v3_cert.empty()) chosen = std::move(v3_cert);
    else if (!v2_cert.empty()) chosen = std::move(v2_cert);
    else if (!v3_cert.empty()) chosen = std::move(v3_cert);
    if (chosen.empty()) return 0;

    out_cert = std::move(chosen);
    return 1;
}

// ---------------------------------------------------------------------------
// Minimal DER/PKCS7 parser
// ---------------------------------------------------------------------------
struct DerNode {
    uint8_t tag = 0;
    bool constructed = false;
    size_t header_len = 0;   // tag + length-of-length bytes
    std::vector<uint8_t> value;   // raw value bytes (tag+length stripped)
    std::vector<DerNode> children;
};

static DerNode parse_der(const uint8_t* data, size_t offset, size_t end) {
    DerNode node;
    // Need at least a tag octet and a length octet before any element access.
    if (offset >= end || end - offset < 2) return node;

    node.tag = data[offset];
    node.constructed = (node.tag & 0x20) != 0;
    size_t pos = offset + 1;

    // Length: short form when the high bit is clear, long form otherwise.
    if (pos >= end) return node; // need the length octet itself
    size_t length = 0;
    size_t header_len = 1; // the tag byte
    if (data[pos] & 0x80) {
        int num_bytes = data[pos] & 0x7f;
        if (num_bytes == 0 || num_bytes > 4) return node; // indefinite or too long
        // num_bytes value-octets follow the length octet at pos; guard the
        // long-form read so a truncated/malformed DER cannot read past `end`.
        if (num_bytes > end - pos - 1) return node;
        pos++;
        for (int i = 0; i < num_bytes; i++) {
            length = (length << 8) | data[pos++];
        }
        header_len += 1 + static_cast<size_t>(num_bytes);
    } else {
        length = data[pos++];
        header_len += 1;
    }

    // Clamp hostile long-form lengths (up to 0xFFFFFFFF) without overflow:
    // compare against the remaining space directly, never `pos + length`.
    if (length > end - pos) length = end - pos;

    node.header_len = header_len;
    node.value.assign(data + pos, data + pos + length);

    // Recursively parse children of a constructed node. The value of a
    // constructed node is itself a stream of one or more DER nodes; a child
    // occupies (header_len + value.size()) bytes of that stream, so advance by
    // that prefix sum. Without this recursive population the PKCS7 certificate
    // extraction below cannot walk down to the certificates SET and falls back
    // to a loose heuristic that returns a wrong-sized "certificate".
    if (node.constructed) {
        size_t child_pos = 0;
        while (child_pos < node.value.size()) {
            DerNode child = parse_der(node.value.data(), child_pos, node.value.size());
            if (child.header_len == 0) break;      // parse failure at this offset
            size_t consumed = child.header_len + child.value.size();
            if (consumed == 0) break;              // no progress -> avoid infinite loop
            node.children.push_back(std::move(child));
            child_pos += consumed;
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
// stored with a rotating multi-byte XOR cipher so it never appears as a
// plain-text literal in the binary. The encoded arrays and key are defined
// in key_generated.h (generated at build time from the TM GitHub secret).
// ---------------------------------------------------------------------------
// All encoded arrays and the XOR key are defined in key_generated.h:
//   #include "key_generated.h"  (at line 787 below)
// ---------------------------------------------------------------------------

#include "key_generated.h"
#include "reporting_key.h"  // pulls in sha256_impl.h (shared SHA-256 primitives)

/**
 * Decodes a rotating multi-byte XOR-encoded hex string into a plain hex string.
 * Each byte is XOR'd with kXorKey[i % kXorKeyLen] (from key_generated.h).
 *
 * Used only for the signer-pin arrays. The reporting API key deliberately
 * does NOT go through this scheme — see reporting_key.h.
 */
static std::string decode_xor_hex(const uint8_t* encoded, size_t len) {
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; i++) {
        result.push_back(static_cast<char>(encoded[i] ^ kXorKey[i % kXorKeyLen]));
    }
    return result;
}

/**
 * Wipes a decoded secret (pinned digest / package) from memory once the
 * caller is done with it, so repeated checks do not leave plain-text pin
 * material lying around in the heap for a memory scan to recover.
 */
static void wipe_string(std::string& s) {
    if (!s.empty()) rk::secure_zero(&s[0], s.size());
    s.clear();
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
//
// Self-contained implementation so the signer digest and APK hashes can be
// computed without Java MessageDigest, which hooking frameworks
// cannot intercept at the Java
// layer. The Java -> native bridge itself cannot be hooked the same way.
// The primitives (struct Sha256 + transform/init/update/final) live in
// sha256_impl.h, shared with reporting_key.h and its host unit test.
// ---------------------------------------------------------------------------

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

/**
 * Block-oriented SHA-256 update.
 *
 * sha256_update() advances one byte at a time, which is fine for the small
 * inputs it was written for (a certificate, a package name) but would dominate
 * startup time when hashing a whole APK section. Same state machine, buffered.
 */
static void sha256_update_bulk(Sha256* s, const uint8_t* data, size_t len) {
    if (s->buflen) {
        size_t take = 64 - s->buflen;
        if (take > len) take = len;
        std::memcpy(s->buffer + s->buflen, data, take);
        s->buflen += take;
        s->bitlen += static_cast<uint64_t>(take) * 8;
        data += take;
        len -= take;
        if (s->buflen == 64) {
            sha256_transform(s, s->buffer);
            s->buflen = 0;
        }
    }
    while (len >= 64) {
        sha256_transform(s, data);
        data += 64;
        len -= 64;
        s->bitlen += 512;
    }
    if (len) {
        std::memcpy(s->buffer, data, len);
        s->buflen = len;
        s->bitlen += static_cast<uint64_t>(len) * 8;
    }
}

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
//
// Required by the APK Signature Scheme v2/v3 verification below: apksigner
// picks RSASSA-PKCS1-v1_5 with SHA-512 (algorithm id 0x0104) for a 4096-bit
// RSA release key, and the recorded content digest is keyed by that same
// algorithm, so the SHA-512 digest of the APK content is what the block
// commits to.
// ---------------------------------------------------------------------------
struct Sha512 {
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
    size_t buflen;
};

static const uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64_t rotr64(uint64_t x, uint64_t n) {
    return (x >> n) | (x << (64 - n));
}

static void sha512_transform(Sha512* s, const uint8_t* chunk) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | chunk[i * 8 + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        const uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = s->state[0], b = s->state[1], c = s->state[2], d = s->state[3];
    uint64_t e = s->state[4], f = s->state[5], g = s->state[6], h = s->state[7];
    for (int i = 0; i < 80; i++) {
        const uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const uint64_t ch = (e & f) ^ (~e & g);
        const uint64_t t1 = h + s1 + ch + kSha512K[i] + w[i];
        const uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->state[0] += a; s->state[1] += b; s->state[2] += c; s->state[3] += d;
    s->state[4] += e; s->state[5] += f; s->state[6] += g; s->state[7] += h;
}

static void sha512_init(Sha512* s) {
    s->state[0] = 0x6a09e667f3bcc908ULL; s->state[1] = 0xbb67ae8584caa73bULL;
    s->state[2] = 0x3c6ef372fe94f82bULL; s->state[3] = 0xa54ff53a5f1d36f1ULL;
    s->state[4] = 0x510e527fade682d1ULL; s->state[5] = 0x9b05688c2b3e6c1fULL;
    s->state[6] = 0x1f83d9abfb41bd6bULL; s->state[7] = 0x5be0cd19137e2179ULL;
    s->bitlen = 0;
    s->buflen = 0;
}

static void sha512_update(Sha512* s, const uint8_t* data, size_t len) {
    if (s->buflen) {
        size_t take = 128 - s->buflen;
        if (take > len) take = len;
        std::memcpy(s->buffer + s->buflen, data, take);
        s->buflen += take;
        s->bitlen += static_cast<uint64_t>(take) * 8;
        data += take;
        len -= take;
        if (s->buflen == 128) {
            sha512_transform(s, s->buffer);
            s->buflen = 0;
        }
    }
    while (len >= 128) {
        sha512_transform(s, data);
        data += 128;
        len -= 128;
        s->bitlen += 1024;
    }
    if (len) {
        std::memcpy(s->buffer, data, len);
        s->buflen = len;
        s->bitlen += static_cast<uint64_t>(len) * 8;
    }
}

static void sha512_final(Sha512* s, uint8_t out[64]) {
    const uint64_t bitlen = s->bitlen;
    // 0x80, then zero padding so that the 16-byte length field lands on the
    // second-to-last 128-byte block boundary.
    uint8_t pad[128];
    std::memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    const size_t padlen = (s->buflen < 112) ? (112 - s->buflen) : (240 - s->buflen);
    sha512_update(s, pad, padlen);
    uint8_t len_bytes[16];
    std::memset(len_bytes, 0, sizeof(len_bytes));
    for (int i = 0; i < 8; i++) {
        len_bytes[15 - i] = static_cast<uint8_t>(bitlen >> (i * 8));
    }
    sha512_update(s, len_bytes, sizeof(len_bytes));
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = static_cast<uint8_t>(s->state[i] >> (56 - j * 8));
        }
    }
}

// ---------------------------------------------------------------------------
// Modular exponentiation on 32-bit limbs (Montgomery / CIOS)
//
// Verifying a v2/v3 signature needs exactly one thing from public-key
// arithmetic: signature^e mod n with the public exponent from the pinned
// signing certificate (65537 in practice). Implementing that here keeps the
// check self-contained (no crypto library ships with the NDK) and portable to
// the 32-bit ABIs, where __int128 - the usual shortcut for a textbook
// multiply-reduce - does not exist.
//
// Montgomery multiplication is used because it replaces the division step of
// a naive modular multiply with a multiply-and-shift, leaving only 32x32->64
// bit products, which are exact on every ABI.
// ---------------------------------------------------------------------------
static const size_t kBnMaxLimbs = 256; // 8192-bit ceiling, 128 limbs for the 4096-bit release key

static int bn_cmp(const uint32_t* a, const uint32_t* b, size_t limbs) {
    for (size_t i = limbs; i-- > 0;) {
        if (a[i] != b[i]) return (a[i] > b[i]) ? 1 : -1;
    }
    return 0;
}

static void bn_sub_inplace(uint32_t* a, const uint32_t* b, size_t limbs) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < limbs; i++) {
        const uint64_t d = static_cast<uint64_t>(a[i]) - b[i] - borrow;
        a[i] = static_cast<uint32_t>(d);
        borrow = (d >> 32) ? 1u : 0u;
    }
}

static void bn_double_mod(uint32_t* a, const uint32_t* n, size_t limbs) {
    uint32_t carry = 0;
    for (size_t i = 0; i < limbs; i++) {
        const uint32_t next = a[i] >> 31;
        a[i] = (a[i] << 1) | carry;
        carry = next;
    }
    if (carry || bn_cmp(a, n, limbs) >= 0) bn_sub_inplace(a, n, limbs);
}

// -n^-1 mod 2^32 by Newton iteration on the odd modulus word n0.
static uint32_t bn_mont_n0inv(uint32_t n0) {
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) {
        x = x * (2u - n0 * x);
    }
    return static_cast<uint32_t>(0u - x);
}

static void bn_mont_mul(const uint32_t* a, const uint32_t* b, const uint32_t* n,
                        uint32_t n0, size_t limbs, uint32_t* out) {
    uint32_t t[kBnMaxLimbs + 2];
    std::memset(t, 0, (limbs + 2) * sizeof(uint32_t));
    for (size_t i = 0; i < limbs; i++) {
        uint64_t carry = 0;
        const uint64_t bi = b[i];
        for (size_t j = 0; j < limbs; j++) {
            const uint64_t uv =
                static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(a[j]) * bi + carry;
            t[j] = static_cast<uint32_t>(uv);
            carry = uv >> 32;
        }
        uint64_t uv = static_cast<uint64_t>(t[limbs]) + carry;
        t[limbs] = static_cast<uint32_t>(uv);
        t[limbs + 1] = static_cast<uint32_t>(uv >> 32);

        // Add m*n so that the low word cancels: m = t[0] * (-n^-1) mod 2^32.
        const uint32_t m = static_cast<uint32_t>(t[0] * n0);
        uv = static_cast<uint64_t>(t[0]) + static_cast<uint64_t>(m) * n[0];
        carry = uv >> 32;
        for (size_t j = 1; j < limbs; j++) {
            uv = static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(m) * n[j] + carry;
            t[j - 1] = static_cast<uint32_t>(uv);
            carry = uv >> 32;
        }
        uv = static_cast<uint64_t>(t[limbs]) + carry;
        t[limbs - 1] = static_cast<uint32_t>(uv);
        t[limbs] = t[limbs + 1] + static_cast<uint32_t>(uv >> 32);
    }
    if (t[limbs] != 0 || bn_cmp(t, n, limbs) >= 0) bn_sub_inplace(t, n, limbs);
    std::memcpy(out, t, limbs * sizeof(uint32_t));
}

static bool bn_from_be(const uint8_t* be, size_t len, uint32_t* out, size_t limbs) {
    if (!be || len == 0 || len > limbs * 4) return false;
    std::memset(out, 0, limbs * sizeof(uint32_t));
    for (size_t i = 0; i < len; i++) {
        const size_t bit = (len - 1 - i) * 8;
        out[bit / 32] |= static_cast<uint32_t>(be[i]) << (bit % 32);
    }
    return true;
}

static void bn_to_be(const uint32_t* in, size_t limbs, uint8_t* out) {
    for (size_t i = 0; i < limbs; i++) {
        const uint32_t w = in[limbs - 1 - i];
        out[i * 4]     = static_cast<uint8_t>(w >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(w >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(w >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(w);
    }
}

// DigestInfo prefixes (RFC 8017, EMSA-PKCS1-v1_5) for the two SHA-2 digests
// apksigner pairs with an RSA key.
static const uint8_t kDigestInfoSha256[19] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const uint8_t kDigestInfoSha512[19] = {
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/**
 * RSASSA-PKCS1-v1_5 verification: recovers the encoded message from the
 * signature with the public key and compares it against
 *   0x00 0x01 0xFF..FF 0x00 || DigestInfo || digest
 *
 * @return true when the signature is valid for [expected_digest].
 */
static bool rsa_pkcs1_v15_verify(const uint8_t* sig, size_t sig_len,
                                 const uint8_t* modulus, size_t modulus_len,
                                 uint32_t exponent,
                                 const uint8_t* digest_info, size_t digest_info_len,
                                 const uint8_t* expected_digest, size_t digest_len) {
    if (!sig || !modulus || !expected_digest || modulus_len == 0) return false;
    if (sig_len != modulus_len || modulus_len > kBnMaxLimbs * 4) return false;

    const size_t limbs = (modulus_len + 3) / 4;
    uint32_t n[kBnMaxLimbs], base[kBnMaxLimbs], acc[kBnMaxLimbs];
    uint32_t r[kBnMaxLimbs], tmp[kBnMaxLimbs];
    if (!bn_from_be(modulus, modulus_len, n, limbs)) return false;
    if ((n[0] & 1u) == 0) return false; // Montgomery requires an odd modulus
    if (!bn_from_be(sig, sig_len, base, limbs)) return false;

    const uint32_t n0 = bn_mont_n0inv(n[0]);

    // R^2 mod n, by doubling 1 for two full limb-widths of bits: the first
    // pass yields R mod n, the second R^2 mod n. Doubling with a conditional
    // subtraction needs no division.
    std::memset(r, 0, limbs * sizeof(uint32_t));
    r[0] = 1;
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < 32 * limbs; i++) bn_double_mod(r, n, limbs);
    }

    bn_mont_mul(base, r, n, n0, limbs, tmp);   // signature in Montgomery form
    std::memcpy(base, tmp, limbs * sizeof(uint32_t));
    std::memset(acc, 0, limbs * sizeof(uint32_t));
    acc[0] = 1;
    bn_mont_mul(acc, r, n, n0, limbs, tmp);    // 1 in Montgomery form
    std::memcpy(acc, tmp, limbs * sizeof(uint32_t));

    if (exponent == 0) return false;
    bool started = false;
    for (int bit = 31; bit >= 0; bit--) {
        const bool set = ((exponent >> bit) & 1u) != 0;
        if (!started) {
            if (!set) continue;
            started = true;
        }
        bn_mont_mul(acc, acc, n, n0, limbs, tmp); // square
        std::memcpy(acc, tmp, limbs * sizeof(uint32_t));
        if (set) {
            bn_mont_mul(acc, base, n, n0, limbs, tmp); // multiply
            std::memcpy(acc, tmp, limbs * sizeof(uint32_t));
        }
    }

    std::memset(r, 0, limbs * sizeof(uint32_t));
    r[0] = 1;
    bn_mont_mul(acc, r, n, n0, limbs, tmp); // leave Montgomery form
    std::memcpy(acc, tmp, limbs * sizeof(uint32_t));

    const size_t em_len = limbs * 4;
    std::vector<uint8_t> em(em_len);
    bn_to_be(acc, limbs, em.data());

    const size_t t_len = digest_info_len + digest_len;
    if (em_len < t_len + 11) return false;
    if (em[0] != 0x00 || em[1] != 0x01) return false;
    size_t i = 2;
    while (i < em_len && em[i] == 0xFF) i++;
    if (i - 2 < 8) return false;              // PS must be at least 8 bytes
    if (i >= em_len || em[i] != 0x00) return false;
    if (em_len - (i + 1) != t_len) return false;
    if (std::memcmp(em.data() + i + 1, digest_info, digest_info_len) != 0) return false;
    if (std::memcmp(em.data() + i + 1 + digest_info_len, expected_digest, digest_len) != 0) {
        return false;
    }
    return true;
}

// RSA OID 1.2.840.113549.1.1.1 (rsaEncryption), DER value octets.
static const uint8_t kRsaEncryptionOid[9] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};

/**
 * Extracts (n, e) from a SubjectPublicKeyInfo:
 *   SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { SEQUENCE {
 *     INTEGER modulus, INTEGER publicExponent } } }
 */
static bool spki_to_rsa(const DerNode& spki, std::vector<uint8_t>& out_modulus,
                        uint32_t* out_exponent) {
    if (spki.tag != 0x30 || spki.children.size() < 2) return false;
    const DerNode& alg = spki.children[0];
    const DerNode& bits = spki.children[1];
    if (alg.tag != 0x30 || alg.children.empty()) return false;
    if (alg.children[0].tag != 0x06) return false;
    const std::vector<uint8_t>& oid = alg.children[0].value;
    if (oid.size() != sizeof(kRsaEncryptionOid) ||
        std::memcmp(oid.data(), kRsaEncryptionOid, sizeof(kRsaEncryptionOid)) != 0) {
        return false;
    }
    if (bits.tag != 0x03 || bits.value.size() < 2) return false;
    if (bits.value[0] != 0x00) return false; // no unused bits in a DER key blob

    const DerNode key = parse_der(bits.value.data() + 1, 0, bits.value.size() - 1);
    if (key.tag != 0x30 || key.children.size() < 2) return false;
    if (key.children[0].tag != 0x02 || key.children[1].tag != 0x02) return false;

    // INTEGER values may carry a leading zero octet to stay positive.
    const std::vector<uint8_t>& mod = key.children[0].value;
    const std::vector<uint8_t>& exp = key.children[1].value;
    size_t mod_skip = 0;
    while (mod_skip + 1 < mod.size() && mod[mod_skip] == 0x00) mod_skip++;
    size_t exp_skip = 0;
    while (exp_skip + 1 < exp.size() && exp[exp_skip] == 0x00) exp_skip++;
    if (mod.size() - mod_skip == 0) return false;
    if (exp.size() - exp_skip == 0 || exp.size() - exp_skip > 4) return false;

    out_modulus.assign(mod.begin() + mod_skip, mod.end());
    uint32_t e = 0;
    for (size_t i = exp_skip; i < exp.size(); i++) e = (e << 8) | exp[i];
    *out_exponent = e;
    return true;
}

/**
 * Reads the public key out of an X.509 certificate. The certificate is the
 * object the pin commits to, so its key - not the redundant "public key" field
 * of the signing block - is what the signature is verified against.
 */
static bool cert_to_rsa(const std::vector<uint8_t>& cert, std::vector<uint8_t>& out_modulus,
                        uint32_t* out_exponent) {
    if (cert.size() < 2) return false;
    const DerNode root = parse_der(cert.data(), 0, cert.size());
    if (root.tag != 0x30 || root.children.empty()) return false;
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    for (const auto& child : root.children[0].children) {
        if (child.tag != 0x30) continue;
        if (spki_to_rsa(child, out_modulus, out_exponent)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// APK Signature Scheme v2/v3 — cryptographic verification
//
// WHAT THE EXISTING CHECKS DO NOT COVER
//   Comparing the signing certificate in the v2/v3 block against the pinned
//   digest only proves that the block *names* the release signer. The block is
//   a plain blob: whoever swaps a single byte inside lib/ or classes.dex can
//   leave the original block in place (its signature is then simply stale) and
//   install the result on any device whose own signature verification is
//   bypassed. The certificate comparison still passes, because nothing in it
//   verifies a signature or looks at the file content.
//
// WHAT IS DONE HERE
//   1. The signature in the block is verified with the public key of the
//      pinned certificate, over the exact bytes of the "signed data" field.
//      That proves the digests inside the block were produced by the holder of
//      the release key.
//   2. The APK content digest is recomputed the way google/apksig defines it
//      and compared with the digest recorded in the block. That proves every
//      byte of the file content is the one the release key holder signed.
//
//   Together these make "edit a file, keep the original signature files" fail
//   even when the installer's own verification is bypassed.
// ---------------------------------------------------------------------------
static const uint32_t kSigAlgoRsaPkcs1Sha256 = 0x0103;
static const uint32_t kSigAlgoRsaPkcs1Sha512 = 0x0104;

// google/apksig ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES
static const size_t kContentChunkMaxBytes = 1024 * 1024;

enum : int {
    kBlockOk                = 0,
    kBlockReadFailed        = 1 << 0, // APK unreadable / not a ZIP
    kBlockNotFound          = 1 << 1, // no v2/v3 signing block
    kBlockMalformed         = 1 << 2, // block present but structurally invalid
    kBlockCertMismatch      = 1 << 3, // signer is not the pinned release signer
    kBlockSigAlgoUnsupported = 1 << 4, // signature algorithm not implemented here
    kBlockSigInvalid        = 1 << 5, // signature does not verify (tampering)
    kBlockContentMismatch   = 1 << 6, // content digest mismatch (tampering)
    kBlockDigestUnsupported = 1 << 7, // no digest recorded for that algorithm
};

struct SignerMaterial {
    const uint8_t* signed_data = nullptr;
    size_t signed_data_len = 0;
    uint32_t sig_algo = 0;
    const uint8_t* sig = nullptr;
    size_t sig_len = 0;
    const uint8_t* content_digest = nullptr;
    size_t content_digest_len = 0;
    std::vector<uint8_t> cert;
};

/** Parses the first signer of a v2 (is_v3 == false) or v3 scheme block value. */
static bool parse_scheme_signer(const uint8_t* val, size_t val_len, bool is_v3,
                                SignerMaterial* out) {
    if (!val || val_len == 0 || !out) return false;
    out->signed_data = nullptr;
    out->signed_data_len = 0;
    out->sig_algo = 0;
    out->sig = nullptr;
    out->sig_len = 0;
    out->content_digest = nullptr;
    out->content_digest_len = 0;
    out->cert.clear();

    // Block value := LengthPrefixed( sequence of LengthPrefixed( signer ) )
    uint32_t signers_len = 0;
    if (!read_u32le(val, 0, val_len, &signers_len)) return false;
    const size_t signers = 4;
    if (!in_bounds(signers, signers_len, val_len)) return false;
    const size_t signers_end = signers + signers_len;

    uint32_t signer_len = 0;
    if (!read_u32le(val, signers, signers_end, &signer_len)) return false;
    if (!in_bounds(signers + 4, signer_len, signers_end)) return false;
    const size_t signer = signers + 4;
    const size_t signer_end = signer + signer_len;

    // signer.signedData
    uint32_t sd_len = 0;
    if (!read_u32le(val, signer, signer_end, &sd_len)) return false;
    if (!in_bounds(signer + 4, sd_len, signer_end)) return false;
    const size_t sd = signer + 4;
    const size_t sd_end = sd + sd_len;

    // signedData.digests := sequence of (algo u32, LengthPrefixed digest)
    uint32_t digests_len = 0;
    if (!read_u32le(val, sd, sd_end, &digests_len)) return false;
    if (!in_bounds(sd + 4, digests_len, sd_end)) return false;
    const size_t digests = sd + 4;
    const size_t digests_end = digests + digests_len;

    // signedData.certificates (second field in both v2 and v3)
    uint32_t certs_len = 0;
    if (!read_u32le(val, digests_end, sd_end, &certs_len)) return false;
    if (!in_bounds(digests_end + 4, certs_len, sd_end)) return false;
    const size_t certs = digests_end + 4;
    const size_t certs_end = certs + certs_len;

    uint32_t cert_len = 0;
    if (!read_u32le(val, certs, certs_end, &cert_len)) return false;
    if (!in_bounds(certs + 4, cert_len, certs_end)) return false;
    out->cert.assign(val + certs + 4, val + certs + 4 + cert_len);

    out->signed_data = val + sd;
    out->signed_data_len = sd_len;

    // signer.signatures: directly after the signed data in v2; v3 inserts a
    // minSdk/maxSdk uint32 pair between them.
    const size_t sigs_field = sd_end + (is_v3 ? 8 : 0);
    if (!in_bounds(sigs_field, 4, signer_end)) return false;
    uint32_t sigs_len = 0;
    if (!read_u32le(val, sigs_field, signer_end, &sigs_len)) return false;
    if (!in_bounds(sigs_field + 4, sigs_len, signer_end)) return false;
    const size_t sigs = sigs_field + 4;
    const size_t sigs_end = sigs + sigs_len;

    // first signature record := LengthPrefixed( algo u32, LengthPrefixed sig )
    uint32_t rec_len = 0;
    if (!read_u32le(val, sigs, sigs_end, &rec_len)) return false;
    if (!in_bounds(sigs + 4, rec_len, sigs_end)) return false;
    const size_t rec = sigs + 4;
    const size_t rec_end = rec + rec_len;
    uint32_t algo = 0;
    uint32_t sig_len = 0;
    if (!read_u32le(val, rec, rec_end, &algo)) return false;
    if (!read_u32le(val, rec + 4, rec_end, &sig_len)) return false;
    if (!in_bounds(rec + 8, sig_len, rec_end)) return false;
    out->sig_algo = algo;
    out->sig = val + rec + 8;
    out->sig_len = sig_len;

    // Recorded content digest, keyed by the same algorithm id as the signature.
    size_t pos = digests;
    while (pos + 4 <= digests_end) {
        uint32_t item_len = 0;
        if (!read_u32le(val, pos, digests_end, &item_len)) break;
        if (item_len < 8) break;
        const size_t item = pos + 4;
        const size_t item_end = item + item_len;
        if (!in_bounds(item, item_len, digests_end)) break;
        uint32_t item_algo = 0;
        uint32_t digest_len = 0;
        if (read_u32le(val, item, item_end, &item_algo) &&
            read_u32le(val, item + 4, item_end, &digest_len) &&
            in_bounds(item + 8, digest_len, item_end)) {
            if (item_algo == out->sig_algo && out->content_digest == nullptr) {
                out->content_digest = val + item + 8;
                out->content_digest_len = digest_len;
            }
        }
        pos = item_end;
    }

    return !out->cert.empty() && out->sig != nullptr;
}

/** Finds one signing-block pair by its 4-byte id. */
static bool find_block_pair(const uint8_t* apk, size_t apk_size, size_t block_start,
                            size_t block_end, uint32_t scheme_id,
                            size_t* out_off, size_t* out_len) {
    if (block_start + 8 > block_end) return false;
    size_t p = block_start + 8; // skip the leading uint64 size field
    while (p + 8 <= block_end) {
        uint64_t pair_size = 0;
        if (!read_u64le(apk, p, block_end, &pair_size)) return false;
        if (pair_size < 4) return false;
        const uint64_t value_len = pair_size - 4;
        const size_t value = p + 12;
        if (value > block_end || value_len > block_end - value) return false;
        uint32_t id = 0;
        if (!read_u32le(apk, p + 8, block_end, &id)) return false;
        if (id == scheme_id) {
            *out_off = value;
            *out_len = static_cast<size_t>(value_len);
            return true;
        }
        p = value + static_cast<size_t>(value_len);
    }
    return false;
}

/**
 * Recomputes the APK content digest the way google/apksig defines it
 * (ApkSigningBlockUtils.computeOneMbChunkContentDigests):
 *
 *   - the content is three sections, digested in order: everything before the
 *     APK Signing Block, the ZIP central directory, and the EOCD - the last
 *     with its "offset of central directory" field rewritten to the offset of
 *     the APK Signing Block;
 *   - each section is cut into consecutive 1 MiB chunks;
 *   - a chunk digest is H(0xA5 || uint32_le(chunkSize) || chunkBytes);
 *   - the result is H(0x5A || uint32_le(chunkCount) || all chunk digests).
 *
 * The 0xA5/0x5A chunk framing is what makes this differ from a plain hash of
 * the concatenated bytes, and the rewritten EOCD field is what keeps the
 * signing block itself out of the digest while still covering the whole file.
 */
static bool compute_content_digest(const uint8_t* apk, size_t apk_size,
                                   size_t block_start, uint64_t central_dir_offset,
                                   size_t eocd_pos, bool use_sha512,
                                   std::vector<uint8_t>& out) {
    out.clear();
    if (!apk || apk_size < sizeof(ZipEocd)) return false;
    if (block_start > apk_size) return false;
    if (central_dir_offset > eocd_pos) return false;
    if (sum_exceeds(eocd_pos, sizeof(ZipEocd), apk_size)) return false;

    uint8_t eocd[sizeof(ZipEocd)];
    std::memcpy(eocd, apk + eocd_pos, sizeof(eocd));
    // SetZipEocdCentralDirectoryOffset(modifiedEocd, beforeApkSigningBlock.size())
    const uint32_t block_start32 = static_cast<uint32_t>(block_start);
    eocd[16] = static_cast<uint8_t>(block_start32);
    eocd[17] = static_cast<uint8_t>(block_start32 >> 8);
    eocd[18] = static_cast<uint8_t>(block_start32 >> 16);
    eocd[19] = static_cast<uint8_t>(block_start32 >> 24);

    const uint8_t* sections[3];
    size_t sizes[3];
    sections[0] = apk;
    sizes[0] = block_start;
    sections[1] = apk + central_dir_offset;
    sizes[1] = eocd_pos - static_cast<size_t>(central_dir_offset);
    sections[2] = eocd;
    sizes[2] = sizeof(eocd);

    const size_t digest_len = use_sha512 ? 64 : 32;
    std::vector<uint8_t> chunk_digests;
    uint32_t chunk_count = 0;

    for (int s = 0; s < 3; s++) {
        size_t off = 0;
        while (off < sizes[s]) {
            const size_t take = (sizes[s] - off < kContentChunkMaxBytes)
                                    ? (sizes[s] - off)
                                    : kContentChunkMaxBytes;
            const uint8_t prefix[5] = {
                0xA5,
                static_cast<uint8_t>(take),
                static_cast<uint8_t>(take >> 8),
                static_cast<uint8_t>(take >> 16),
                static_cast<uint8_t>(take >> 24),
            };
            uint8_t dg[64];
            if (use_sha512) {
                Sha512 h;
                sha512_init(&h);
                sha512_update(&h, prefix, sizeof(prefix));
                sha512_update(&h, sections[s] + off, take);
                sha512_final(&h, dg);
            } else {
                Sha256 h;
                sha256_init(&h);
                sha256_update_bulk(&h, prefix, sizeof(prefix));
                sha256_update_bulk(&h, sections[s] + off, take);
                sha256_final(&h, dg);
            }
            chunk_digests.insert(chunk_digests.end(), dg, dg + digest_len);
            if (chunk_count == UINT32_MAX) return false;
            chunk_count++;
            off += take;
        }
    }

    const uint8_t head[5] = {
        0x5A,
        static_cast<uint8_t>(chunk_count),
        static_cast<uint8_t>(chunk_count >> 8),
        static_cast<uint8_t>(chunk_count >> 16),
        static_cast<uint8_t>(chunk_count >> 24),
    };
    out.resize(digest_len);
    if (use_sha512) {
        Sha512 h;
        sha512_init(&h);
        sha512_update(&h, head, sizeof(head));
        sha512_update(&h, chunk_digests.data(), chunk_digests.size());
        sha512_final(&h, out.data());
    } else {
        Sha256 h;
        sha256_init(&h);
        sha256_update_bulk(&h, head, sizeof(head));
        sha256_update_bulk(&h, chunk_digests.data(), chunk_digests.size());
        sha256_final(&h, out.data());
    }
    return true;
}

/** Normalizes a fingerprint/digest string for comparison (hex only, uppercase). */
static std::string normalize_hex(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c >= '0' && c <= '9') {
            out.push_back(c);
        } else if (c >= 'a' && c <= 'f') {
            out.push_back(static_cast<char>(c - 'a' + 'A'));
        } else if (c >= 'A' && c <= 'F') {
            out.push_back(c);
        }
    }
    return out;
}

/**
 * Verifies the v2/v3 signature record of the package at [apk]/[apk_size].
 *
 * @param pinned   pinned SHA-256 of the release signing certificate (hex)
 * @param fatal    set to true only when the result proves tampering: the
 *                 pinned signer is present but the signature or the content
 *                 digest does not match. Any other outcome (absent block,
 *                 unparsable record, algorithm not implemented here) is
 *                 reported but not marked fatal - those states are already
 *                 rejected by the certificate-pin checks in the caller, and a
 *                 future key type must not turn into an unrecoverable startup
 *                 kill.
 * @return a kBlock* bitmask
 */
static int verify_sign_block(const uint8_t* apk, size_t apk_size, size_t eocd_pos,
                             uint64_t central_dir_offset, const std::string& pinned,
                             bool* fatal) {
    *fatal = false;
    if (!apk || apk_size < sizeof(ZipEocd)) return kBlockReadFailed;
    if (pinned.empty()) return kBlockOk; // nothing to verify against
    if (central_dir_offset < 24 || central_dir_offset > apk_size) return kBlockMalformed;

    // Footer of the signing block: uint64 size | "APK Sig Block 42".
    const size_t magic_off = static_cast<size_t>(central_dir_offset) - 16;
    if (std::memcmp(apk + magic_off, kApkSigBlockMagic, sizeof(kApkSigBlockMagic)) != 0) {
        return kBlockNotFound;
    }
    uint64_t block_size = 0;
    if (!read_u64le(apk, magic_off - 8, apk_size, &block_size)) return kBlockMalformed;
    // The declared size counts everything after the leading size field, i.e. the
    // pairs, the trailing size field and the 16-byte magic. The block therefore
    // starts at (central directory offset - block_size - 8).
    if (block_size > static_cast<uint64_t>(magic_off) + 8) return kBlockMalformed;
    const size_t block_start =
        static_cast<size_t>(magic_off) + 8 - static_cast<size_t>(block_size);
    const size_t block_end = magic_off - 8; // end of the ID-value pair region
    if (block_start > block_end) return kBlockMalformed;
    // The content digest covers [0, blockStart), so the leading size field must
    // mirror the footer for the boundary to be well defined.
    uint64_t leading_size = 0;
    if (!read_u64le(apk, block_start, apk_size, &leading_size) ||
        leading_size != block_size) {
        return kBlockMalformed;
    }

    // Prefer v3 over v2, mirroring Android's "strongest scheme wins".
    size_t val = 0;
    size_t val_len = 0;
    bool is_v3 = true;
    if (!find_block_pair(apk, apk_size, block_start, block_end, kApkSigSchemeV3BlockId,
                         &val, &val_len)) {
        is_v3 = false;
        if (!find_block_pair(apk, apk_size, block_start, block_end,
                             kApkSigSchemeV2BlockId, &val, &val_len)) {
            return kBlockNotFound;
        }
    }

    SignerMaterial m;
    if (!parse_scheme_signer(apk + val, val_len, is_v3, &m)) return kBlockMalformed;

    // 1. The signer record must be the pinned release signer.
    const std::string cert_digest = sha256_hex(m.cert.data(), m.cert.size());
    if (cert_digest != pinned) {
        LOGE("v2/v3 signer digest does not match the pinned identity (%s)", is_v3 ? "v3" : "v2");
        return kBlockCertMismatch;
    }

    // 2. Only RSASSA-PKCS1-v1_5 is implemented; anything else is reported so
    //    the caller can log it instead of failing closed on an unknown scheme.
    const uint8_t* digest_info = nullptr;
    size_t digest_len = 0;
    if (m.sig_algo == kSigAlgoRsaPkcs1Sha512) {
        digest_info = kDigestInfoSha512;
        digest_len = 64;
    } else if (m.sig_algo == kSigAlgoRsaPkcs1Sha256) {
        digest_info = kDigestInfoSha256;
        digest_len = 32;
    } else {
        LOGE("v2/v3 signature algorithm 0x%08x is not verifiable here; "
             "signature left unverified", m.sig_algo);
        return kBlockSigAlgoUnsupported;
    }

    // 3. The signature must verify over the signed data with the key inside the
    //    pinned certificate.
    std::vector<uint8_t> modulus;
    uint32_t exponent = 0;
    if (!cert_to_rsa(m.cert, modulus, &exponent)) {
        LOGE("pinned certificate carries no RSA public key; signature left unverified");
        return kBlockSigAlgoUnsupported;
    }
    std::vector<uint8_t> signed_digest(digest_len);
    if (digest_len == 64) {
        Sha512 h;
        sha512_init(&h);
        sha512_update(&h, m.signed_data, m.signed_data_len);
        sha512_final(&h, signed_digest.data());
    } else {
        Sha256 h;
        sha256_init(&h);
        sha256_update_bulk(&h, m.signed_data, m.signed_data_len);
        sha256_final(&h, signed_digest.data());
    }
    if (!rsa_pkcs1_v15_verify(m.sig, m.sig_len, modulus.data(), modulus.size(), exponent,
                              digest_info, 19, signed_digest.data(), digest_len)) {
        LOGE("v2/v3 signature over the signed data does NOT verify with the pinned signer");
        *fatal = true;
        return kBlockSigInvalid;
    }

    // 4. The recorded content digest must match a freshly computed one, so the
    //    signature covers this exact file rather than an older revision of it.
    if (m.content_digest == nullptr || m.content_digest_len != digest_len) {
        LOGE("no content digest recorded for signature algorithm 0x%08x", m.sig_algo);
        return kBlockDigestUnsupported;
    }
    std::vector<uint8_t> actual;
    if (!compute_content_digest(apk, apk_size, block_start, central_dir_offset, eocd_pos,
                                digest_len == 64, actual)) {
        return kBlockMalformed;
    }
    if (actual.size() != m.content_digest_len ||
        std::memcmp(actual.data(), m.content_digest, actual.size()) != 0) {
        LOGE("APK content digest does not match the digest signed by the pinned signer");
        *fatal = true;
        return kBlockContentMismatch;
    }

    LOGI("v2/v3 signature and content digest verified (%s)", is_v3 ? "v3" : "v2");
    return kBlockOk;
}

// ---------------------------------------------------------------------------
// Package name pin
//
// The app's package name ("com.soreverse.mcp") is pinned here, XOR-obfuscated
// with the same key as the signer digest, so a repackaged build that changes
// ---------------------------------------------------------------------------
// Package name pin: "com.soreverse.mcp" encoded with the rotating multi-byte
// XOR cipher defined in key_generated.h (see extern declaration above).
// ---------------------------------------------------------------------------
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
    kProbeOk                = 0,
    kProbeReadFailed        = 1 << 0, // APK unreadable / empty
    kProbeEocdNotFound      = 1 << 1, // not a valid ZIP
    kProbeCentralDirInvalid = 1 << 2, // central directory out of bounds
    kProbeMissingClasses    = 1 << 3, // classes.dex absent
    kProbeMissingManifest   = 1 << 4, // AndroidManifest.xml absent
    kProbeMissingArsc       = 1 << 5, // resources.arsc absent
    kProbeMissingEnvelope  = 1 << 6, // META-INF/ *.{RSA,DSA,EC} absent
    kProbeMissingNative     = 1 << 7, // lib/<abi>/librz_native.so absent
    kProbeCrcMismatch       = 1 << 8, // classes.dex content CRC mismatch
    kProbeMissingBlockV234 = 1 << 9, // no v2/v3 APK Signing Block signer
};

// The bundled native library name is librz_native.so: CMakeLists.txt declares
// "add_library(rz_native SHARED ...)" (which yields librz_native.so), and the
// Kotlin side loads it via System.loadLibrary("rz_native"). The integrity
// check below therefore ensures that this exact library ships inside the APK
// under lib/<abi>/, so a repackaged build that strips the native probe
// code is rejected.

static int probe_archive(const uint8_t* apk, size_t apk_size) {
    if (!apk || apk_size < sizeof(ZipEocd)) return kProbeReadFailed;

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
    if (!found) return kProbeEocdNotFound;

    ZipEocd eocd;
    std::memcpy(&eocd, apk + eocd_pos, sizeof(ZipEocd));
    if (static_cast<uint64_t>(eocd.central_dir_offset) +
            static_cast<uint64_t>(eocd.central_dir_size) > apk_size) {
        return kProbeCentralDirInvalid;
    }

    bool has_classes = false, has_manifest = false, has_arsc = false;
    bool has_signature = false, has_native = false;
    bool crc_fail = false;

    // Detect presence of a v2/v3 APK Signing Block. An official apksigner-
    // signed SOMCP build always carries one; its absence next to a preserved
    // v1 signature is the signature of a scheme-confusion repack and is
    // reported as kProbeMissingBlockV234.
    size_t cd_pos = eocd.central_dir_offset;
    bool has_apk_sign_block = false;
    {
        std::vector<uint8_t> probe_cert;
        int probe = find_apk_sign_block_cert(apk, apk_size,
                                             eocd.central_dir_offset,
                                             /*prefer_v3=*/true, probe_cert);
        has_apk_sign_block = (probe == 1);
    }
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

    int result = kProbeOk;
    if (!has_classes) result |= kProbeMissingClasses;
    if (!has_manifest) result |= kProbeMissingManifest;
    if (!has_arsc) result |= kProbeMissingArsc;
    if (!has_signature) result |= kProbeMissingEnvelope;
    if (!has_native) result |= kProbeMissingNative;
    if (!has_apk_sign_block) result |= kProbeMissingBlockV234;
    if (crc_fail) result |= kProbeCrcMismatch;
    return result;
}

// ---------------------------------------------------------------------------
// JNI entry points
// ---------------------------------------------------------------------------

/**
 * Returns the expected SHA-256 digest of the official release signing
 * certificate. The value is stored XOR-encoded in key_generated.h and decoded
 * at runtime, so it does not appear as a plain-text literal in the .so binary.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeGetPinnedFingerprint(
    JNIEnv* env, jobject thiz) {
    std::string digest = decode_xor_hex(kEncodedExpectedSha256, kEncodedExpectedSha256Len);
    jstring out = env->NewStringUTF(digest.c_str());
    wipe_string(digest);
    return out;
}

/**
 * Returns the log-report-platform reporting API key (sent by the client as the
 * X-API-Key request header). The value is injected into the native layer at
 * build time (see key_generated.h / generate_header.py) and stored encrypted
 * under a SHA-256-CTR keystream stretched from the build secret; it is decoded
 * here into a stack buffer which is wiped right after the jstring is created,
 * so the plaintext never appears in the .so binary, in source, or in any log.
 * Returns an empty string when no key was injected.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeGetReportingKey(
    JNIEnv* env, jobject thiz) {
    if (kRepApiKeyCipherLen == 0 || kRepApiKeyCipherLen > rk::kMaxKeyLen) {
        return env->NewStringUTF("");
    }
    uint8_t buf[rk::kMaxKeyLen + 1];
    size_t n = rk::decode_api_key(buf, rk::kMaxKeyLen);
    if (n == 0) {
        return env->NewStringUTF("");
    }
    buf[n] = 0;
    jstring key = env->NewStringUTF(reinterpret_cast<const char*>(buf));
    rk::secure_zero(buf, n + 1);
    if (!key) env->ExceptionClear();
    return key ? key : env->NewStringUTF("");
}

/**
 * Reads the APK file directly from the filesystem and extracts the first
 * X.509 signing certificate from the META-INF/ *.RSA/.DSA/.EC signature file.
 *
 * This bypasses the Java PackageManager API, which is what kstools and
 * a Binder-level substitution of the package metadata.
 *
 * @param env       JNI environment
 * @param thiz      JNI object
 * @param apkPath   Absolute path to the APK file (e.g., context.packageCodePath)
 * @return          DER-encoded X.509 certificate bytes, or null on failure
 */
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeReadEnvelope(
    JNIEnv* env, jobject thiz, jstring apkPath, jboolean requireRunning) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return nullptr;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    LOGI("Reading APK: %s", path.c_str());

    // Map the APK read-only instead of loading the whole file into the heap
    // (avoids OOM on large APKs). The open goes through the anti-redirect
    // channel: raw syscall + fd/path inode cross-check + (for the running
    // package) /proc/self/maps cross-validation.
    MappedApk apk;
    const MapStatus ms = apk.map_status(path.c_str(), requireRunning == JNI_TRUE);
    if (ms != kMapOk) {
        LOGE("Failed to map APK (anti-redirect status=%d): %s",
             static_cast<int>(ms), path.c_str());
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
                    LOGI("Envelope entry %s is compressed (type %u), decompressing",
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

    LOGI("Envelope entry size: %zu bytes", signature_file_data.size());

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
 * Reads the APK file directly from the filesystem and extracts the signing
 * certificate recorded in the APK Signature Scheme v2/v3 block (the "APK
 * Signing Block" located immediately before the ZIP central directory).
 *
 * WHY (see the WHY comment at the top of the v2/v3 support section): a
 * v1-only (META-INF/ *.RSA) certificate check is vulnerable to scheme-confusion
 * repacking, where an attacker keeps the original v1 signature files and
 * re-signs only with a new key via v2/v3. Because the v2/v3 signature
 * cryptographically covers the entire file, its certificate cannot be
 * preserved while the signing key changes; matching THIS record against
 * the pin therefore closes that bypass.
 *
 * The highest available scheme is preferred (v3 over v2), mirroring Android's
 * "strongest scheme wins" behaviour.
 *
 * @param env       JNI environment
 * @param thiz      JNI object
 * @param apkPath   Absolute path to the APK file (context.packageCodePath)
 * @return          DER-encoded X.509 certificate bytes, or null when the APK
 *                  has no v2/v3 signing block or the block is malformed.
 */
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeReadEnvelopeV234(
    JNIEnv* env, jobject thiz, jstring apkPath, jboolean requireRunning) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return nullptr;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    if (!path_cstr) {
        LOGE("Failed to read apkPath");
        return nullptr;
    }
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    MappedApk apk;
    const MapStatus ms = apk.map_status(path.c_str(), requireRunning == JNI_TRUE);
    if (ms != kMapOk) {
        LOGE("Failed to map APK for v2/v3 check (anti-redirect status=%d): %s",
             static_cast<int>(ms), path.c_str());
        return nullptr;
    }
    const uint8_t* apk_data = apk.data();
    size_t apk_size = apk.size();

    if (apk_size < sizeof(ZipEocd)) {
        LOGE("APK too small");
        return nullptr;
    }

    // Locate EOCD scanning backwards for the central-directory offset.
    size_t eocd_pos = apk_size - sizeof(ZipEocd);
    size_t search_start = (apk_size > 65557) ? apk_size - 65557 : 0;
    bool found_eocd = false;
    for (size_t i = eocd_pos; i >= search_start && i < apk_size; i--) {
        ZipEocd eocd;
        if (sum_exceeds(i, sizeof(ZipEocd), apk_size)) continue;
        std::memcpy(&eocd, apk_data + i, sizeof(ZipEocd));
        if (eocd.signature == 0x06054b50) { eocd_pos = i; found_eocd = true; break; }
        if (i == 0) break;
    }
    if (!found_eocd) {
        LOGI("v2/v3 check: EOCD not found");
        return nullptr;
    }

    ZipEocd eocd;
    std::memcpy(&eocd, apk_data + eocd_pos, sizeof(ZipEocd));

    std::vector<uint8_t> cert;
    int rc = find_apk_sign_block_cert(apk_data, apk_size,
                                      eocd.central_dir_offset,
                                      /*prefer_v3=*/true, cert);
    if (rc != 1 || cert.empty()) {
        LOGI("v2/v3 probe: no record found (rc=%d): %s", rc, path.c_str());
        return nullptr;
    }
    LOGI("Extracted v2/v3 record: %zu bytes", cert.size());

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
 * Matches the running package id against the pinned value
 * ("com.soreverse.mcp"). The expected value is stored XOR-obfuscated in the
 * binary, so a repackaged build with a changed applicationId is rejected here
 * even if the Java context reports a spoofed package name.
 *
 * @return JNI_TRUE if [packageName] matches the pin, JNI_FALSE otherwise.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeMatchPackageId(
    JNIEnv* env, jobject thiz, jstring packageName) {

    if (!packageName) {
        LOGE("nativeMatchPackageId: packageName is null");
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
    const bool ok = (actual == expected);
    wipe_string(expected);
    if (!ok) {
        LOGE("Package name MISMATCH (actual=%s)", actual.c_str());
        return JNI_FALSE;
    }
    LOGI("Package id matched");
    return JNI_TRUE;
}

/**
 * Probes the integrity of the APK at [apkPath] by parsing its ZIP central
 * directory directly from the filesystem:
 *   - structural sanity (EOCD / central directory bounds);
 *   - presence of critical entries (classes.dex, AndroidManifest.xml,
 *     resources.arsc, META-INF signature file, lib/<abi>/librz_native.so);
 *   - CRC32 of the classes.dex payload vs. the central directory value.
 *
 * @return 0 on success, or a bitmask of kProbe* flags on failure.
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeProbeArchive(
    JNIEnv* env, jobject thiz, jstring apkPath, jboolean requireRunning) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return kProbeReadFailed;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    if (!path_cstr) {
        LOGE("Failed to read apkPath");
        return kProbeReadFailed;
    }
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    MappedApk apk;
    const MapStatus ms = apk.map_status(path.c_str(), requireRunning == JNI_TRUE);
    if (ms != kMapOk) {
        LOGE("Failed to map APK for integrity check (anti-redirect status=%d): %s",
             static_cast<int>(ms), path.c_str());
        return kProbeReadFailed;
    }

    int result = probe_archive(apk.data(), apk.size());
    if (result != kProbeOk) {
        LOGE("APK integrity check FAILED (code=0x%X): %s", result, path.c_str());
    }
    return result;
}

/** Locates the ZIP End Of Central Directory record (scanning back over any comment). */
static bool find_eocd_pos(const uint8_t* apk, size_t apk_size, size_t* out_pos) {
    if (!apk || apk_size < sizeof(ZipEocd)) return false;
    size_t pos = apk_size - sizeof(ZipEocd);
    const size_t search_start = (apk_size > 65557) ? apk_size - 65557 : 0;
    for (size_t i = pos; i >= search_start && i < apk_size; i--) {
        ZipEocd e;
        if (sum_exceeds(i, sizeof(ZipEocd), apk_size)) continue;
        std::memcpy(&e, apk + i, sizeof(ZipEocd));
        if (e.signature == 0x06054b50) {
            *out_pos = i;
            return true;
        }
        if (i == 0) break;
    }
    return false;
}

/**
 * Verifies the v2/v3 signature record of the running package.
 *
 * Unlike the certificate comparison in [nativeReadEnvelopeV234], which only
 * proves that the signing block names the pinned signer, this verifies the
 * signature itself and recomputes the signed content digest (see
 * verify_sign_block). A mismatch of either proves tampering and is fatal
 * here, inside the native call: the process is terminated before this
 * function returns, so rewriting the value the call returns cannot turn a
 * mismatch into a pass.
 *
 * Codes other than [kBlockSigInvalid] / [kBlockContentMismatch] are reported
 * for logging only; those states (no signing block, non-RSA signature
 * algorithm, ...) are already covered by the certificate-pin checks.
 *
 * @return a kBlock* bitmask (0 == verified)
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeVerifyBlock(
    JNIEnv* env, jobject thiz, jstring apkPath) {

    if (!apkPath) {
        LOGE("apkPath is null");
        return kBlockReadFailed;
    }

    const char* path_cstr = env->GetStringUTFChars(apkPath, nullptr);
    if (!path_cstr) {
        LOGE("Failed to read apkPath");
        return kBlockReadFailed;
    }
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    // This check always runs against the RUNNING package, so it also acts as
    // the anti-redirect gate: if the file behind [apkPath] is not the APK
    // image the process executes from, or open() was steered to a different
    // inode, the very input of every content check has been substituted.
    // That is definitive tampering, so terminate here (before returning) the
    // same way a fatal signature mismatch does - the caller cannot veto it.
    MappedApk apk;
    const MapStatus ms = apk.map_status(path.c_str(), /*require_running=*/true);
    if (ms == kMapRedirected || ms == kMapNotRunningApk) {
        LOGE("APK path substituted (anti-redirect status=%d): %s",
             static_cast<int>(ms), path.c_str());
        ::_exit(173);
    }
    if (ms != kMapOk) {
        LOGE("Failed to map APK for signature verification: %s", path.c_str());
        return kBlockReadFailed;
    }

    size_t eocd_pos = 0;
    if (!find_eocd_pos(apk.data(), apk.size(), &eocd_pos)) {
        LOGE("EOCD not found while verifying the signature block");
        return kBlockReadFailed;
    }

    ZipEocd eocd;
    std::memcpy(&eocd, apk.data() + eocd_pos, sizeof(eocd));
    if (sum_exceeds(eocd.central_dir_offset, eocd.central_dir_size, apk.size())) {
        return kBlockMalformed;
    }

    std::string pinned =
        normalize_hex(decode_xor_hex(kEncodedExpectedSha256, kEncodedExpectedSha256Len));

    bool fatal = false;
    const int code = verify_sign_block(apk.data(), apk.size(), eocd_pos,
                                       eocd.central_dir_offset, pinned, &fatal);
    wipe_string(pinned);
    if (fatal) {
        LOGE("APK signature verification FAILED (code=0x%X): %s", code, path.c_str());
        ::_exit(173);
    }
    if (code != kBlockOk) {
        LOGE("APK signature verification inconclusive (code=0x%X), not treated as tampering",
             code);
    }
    return code;
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
Java_com_soreverse_mcp_nativecore_NativeProbe_nativeComputeSha256Hex(
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