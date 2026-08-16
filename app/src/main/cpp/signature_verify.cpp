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
 *   central directory, extracts the META-INF/*.RSA/.DSA/.EC signature file,
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
#include <fstream>
#include <android/log.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

#define LOG_TAG "SignatureVerify"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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
// Minimal DER/PKCS7 parser
// ---------------------------------------------------------------------------
struct DerNode {
    // Default-initialized: parse_der has several early-return paths (truncated
    // header, bad length form, depth limit) that return a node without ever
    // assigning these. Callers compare `tag` to decide whether a child parsed,
    // so leaving them indeterminate would make that check read uninitialized
    // memory and the sibling loop terminate unpredictably.
    uint8_t tag = 0;
    bool constructed = false;
    bool parsed = false;          // true once a header was successfully decoded
    std::vector<uint8_t> value;   // raw value bytes (tag+length stripped)
    std::vector<DerNode> children;
};

// Maximum DER nesting depth. A PKCS7 SignedData certificate chain nests ~8
// levels; 16 is generous while bounding recursion so a hostile/corrupt
// signature block cannot drive parse_der into a stack overflow.
static const int kMaxDerDepth = 16;

static DerNode parse_der(const uint8_t* data, size_t offset, size_t end, int depth = 0) {
    DerNode node;
    if (offset + 2 > end) return node;
    if (depth > kMaxDerDepth) return node;

    node.tag = data[offset];
    node.constructed = (node.tag & 0x20) != 0;
    node.parsed = true;
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

    if (pos + length > end) {
        length = end - pos;
    }

    node.value.assign(data + pos, data + pos + length);

    // Parse children for constructed tags. Decode each child's header locally so
    // progress is measured against node.value rather than against a separately
    // allocated child.value vector (subtracting those unrelated pointers was UB).
    if (node.constructed && depth < kMaxDerDepth) {
        size_t child_pos = 0;
        while (child_pos < node.value.size()) {
            if (node.value.size() - child_pos < 2) break;
            uint8_t child_tag = node.value[child_pos];
            size_t len_pos = child_pos + 1;
            size_t child_length = 0;
            size_t length_field_size = 1;
            if (node.value[len_pos] & 0x80) {
                const size_t length_octets = node.value[len_pos] & 0x7f;
                if (length_octets == 0 || length_octets > 4 ||
                    length_octets > node.value.size() - len_pos - 1) break;
                length_field_size += length_octets;
                for (size_t i = 0; i < length_octets; ++i) {
                    child_length = (child_length << 8) | node.value[len_pos + 1 + i];
                }
            } else {
                child_length = node.value[len_pos];
            }
            const size_t header_size = 1 + length_field_size;
            if (child_length > node.value.size() - child_pos - header_size) break;
            const size_t child_end = child_pos + header_size + child_length;
            auto child = parse_der(node.value.data(), child_pos, child_end, depth + 1);
            if (child.tag != child_tag) break;
            node.children.push_back(std::move(child));
            child_pos = child_end;
        }
    }

    return node;
}

// Find a child node by tag at direct children only
static const DerNode* find_direct_child(const DerNode* node, uint8_t tag) {
    if (!node) return nullptr;
    for (const auto& child : node->children) {
        if (child.tag == tag) return &child;
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

    // ContentInfo.SEQUENCE -> first child is the OID (0x06), second is the
    // [0] EXPLICIT wrapper (0xa0) whose single child is the SignedData SEQUENCE.
    const DerNode* signed_data = nullptr;
    if (const DerNode* wrapper = find_direct_child(content_info, 0xa0)) {
        signed_data = find_direct_child(wrapper, 0x30);
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
                    // Re-emit tag + definite length + value so the caller receives
                    // a self-contained DER certificate.
                    const size_t total_len = cert.value.size();
                    // 0x82 is the widest length form emitted below; anything larger
                    // would need 0x83/0x84 and silently truncating the length would
                    // hand Java a corrupt certificate.
                    if (total_len > 0xffff) {
                        LOGE("Certificate too large to re-encode: %zu bytes", total_len);
                        return {};
                    }
                    std::vector<uint8_t> result;
                    result.reserve(total_len + 4);
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
 * Reads the APK at [path] and returns the first X.509 signing certificate found
 * in its META-INF v1 signature block, or an empty vector on any failure.
 *
 * Split out of the JNI entry point so the ZIP/PKCS7 parsing can be exercised
 * directly by a host-side test harness with no JVM present.
 */
static std::vector<uint8_t> read_apk_certificate(const std::string& path) {
    LOGI("Reading APK: %s", path.c_str());

    // Read the entire APK file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOGE("Failed to open APK: %s", path.c_str());
        return {};
    }

    std::streamsize size = file.tellg();
    if (size <= 0) {
        LOGE("APK file is empty");
        return {};
    }

    std::vector<uint8_t> apk_data(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(apk_data.data()), size)) {
        LOGE("Failed to read APK file");
        return {};
    }
    file.close();

    // Find End of Central Directory
    if (apk_data.size() < sizeof(ZipEocd)) {
        LOGE("APK too small");
        return {};
    }

    // Search for EOCD signature from the end (with max comment length)
    size_t eocd_pos = apk_data.size() - sizeof(ZipEocd);
    size_t search_start = (apk_data.size() > 65557) ? apk_data.size() - 65557 : 0;
    bool found_eocd = false;

    for (size_t i = eocd_pos; i >= search_start && i < apk_data.size(); i--) {
        ZipEocd eocd;
        if (i + sizeof(ZipEocd) > apk_data.size()) continue;
        std::memcpy(&eocd, apk_data.data() + i, sizeof(ZipEocd));
        if (eocd.signature == 0x06054b50) {
            eocd_pos = i;
            found_eocd = true;
            break;
        }
        if (i == 0) break;
    }

    if (!found_eocd) {
        LOGE("EOCD not found");
        return {};
    }

    ZipEocd eocd;
    std::memcpy(&eocd, apk_data.data() + eocd_pos, sizeof(ZipEocd));
    LOGI("Central dir: offset=%u, size=%u, entries=%u",
         eocd.central_dir_offset, eocd.central_dir_size, eocd.total_entries);

    const uint64_t central_dir_end = static_cast<uint64_t>(eocd.central_dir_offset) +
                                     static_cast<uint64_t>(eocd.central_dir_size);
    if (central_dir_end > apk_data.size()) {
        LOGE("Central directory exceeds file bounds");
        return {};
    }

    // Scan central directory for META-INF signature files
    const char* signature_prefix = "META-INF/";
    size_t prefix_len = strlen(signature_prefix);
    std::vector<uint8_t> signature_file_data;
    std::string signature_filename;

    size_t cd_pos = eocd.central_dir_offset;
    for (uint16_t i = 0; i < eocd.total_entries; i++) {
        if (cd_pos + sizeof(ZipCentralDirEntry) > apk_data.size()) {
            LOGE("Central directory entry %d out of bounds", i);
            break;
        }

        ZipCentralDirEntry entry;
        std::memcpy(&entry, apk_data.data() + cd_pos, sizeof(ZipCentralDirEntry));

        if (entry.signature != 0x02014b50) {
            LOGE("Invalid central directory signature at entry %d", i);
            break;
        }

        if (cd_pos + sizeof(ZipCentralDirEntry) + entry.filename_length > apk_data.size()) {
            break;
        }

        std::string filename(
            reinterpret_cast<const char*>(apk_data.data() + cd_pos + sizeof(ZipCentralDirEntry)),
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
                if (local_offset + sizeof(ZipLocalFileHeader) > apk_data.size()) {
                    LOGE("Local header offset out of bounds for %s", filename.c_str());
                    continue;
                }

                ZipLocalFileHeader local;
                std::memcpy(&local, apk_data.data() + local_offset, sizeof(ZipLocalFileHeader));

                if (local.signature != 0x04034b50) {
                    LOGE("Invalid local file header signature for %s", filename.c_str());
                    continue;
                }

                const uint64_t data_offset = static_cast<uint64_t>(local_offset) +
                                             sizeof(ZipLocalFileHeader) +
                                             static_cast<uint64_t>(local.filename_length) +
                                             static_cast<uint64_t>(local.extra_length);
                const uint64_t compressed_end = data_offset + static_cast<uint64_t>(entry.compressed_size);
                if (data_offset > apk_data.size() || compressed_end > apk_data.size()) {
                    LOGE("File data out of bounds for %s", filename.c_str());
                    continue;
                }

                // APK v1 signature blocks must be stored: compressed PKCS7 data
                // is not DER, and accepting it would either parse garbage or read
                // a misleading certificate candidate. For stored entries both ZIP
                // sizes must agree before using either one as a range length.
                if (entry.compression != 0 || entry.compressed_size != entry.uncompressed_size) {
                    LOGE("Unsupported signature entry %s (compression=%u, compressed=%u, uncompressed=%u)",
                         filename.c_str(), entry.compression, entry.compressed_size, entry.uncompressed_size);
                    continue;
                }
                signature_file_data.assign(
                    apk_data.data() + static_cast<size_t>(data_offset),
                    apk_data.data() + static_cast<size_t>(compressed_end));
                signature_filename = filename;
                LOGI("Read signature file: %s (%zu bytes)", filename.c_str(), signature_file_data.size());
                break;
            }
        }

        cd_pos += sizeof(ZipCentralDirEntry) + entry.filename_length +
                  entry.extra_length + entry.comment_length;
    }

    if (signature_file_data.empty()) {
        LOGE("No signature file found in META-INF");
        return {};
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
        return {};
    }

    LOGI("Extracted certificate: %zu bytes", cert.size());
    return cert;
}

#ifdef SOMCP_TEST_HARNESS
// Host-side entry point for the parser tests. Never compiled into the APK.
std::vector<uint8_t> somcp_test_read_apk_certificate(const std::string& path) {
    return read_apk_certificate(path);
}
#endif

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
    if (!path_cstr) return nullptr;
    std::string path(path_cstr);
    env->ReleaseStringUTFChars(apkPath, path_cstr);

    const std::vector<uint8_t> cert = read_apk_certificate(path);
    if (cert.empty()) return nullptr;

    jbyteArray result = env->NewByteArray(static_cast<jsize>(cert.size()));
    if (!result) {
        LOGE("Failed to allocate Java byte array");
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(cert.size()),
                            reinterpret_cast<const jbyte*>(cert.data()));
    return result;
}