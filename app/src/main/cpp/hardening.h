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
 * hardening.h
 *
 * Inline anti-tamper primitives shared by signature_verify.cpp and
 * rizin_core.cpp.
 *
 * Design intent (why these live in a header, not a .cpp):
 *   Everything here is `static inline`, so it is compiled INTO each translation
 *   unit that includes it. There is no single exported `check_integrity()` for
 *   a cracker to NOP out: the same logic is inlined at many call sites across
 *   the library, and each result is consumed as a value (see
 *   `HARDEN_CONSUME`) rather than branched on, so a simple "flip the branch"
 *   patch does not produce a working build.
 *
 * This raises the cost of casual patching; it cannot make a purely client-side
 * check unbreakable (nothing can - see the integrity design notes).
 */

#ifndef SOMCP_HARDENING_H
#define SOMCP_HARDENING_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <string>
#include <ctime>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <android/log.h>

#define HARDEN_LOG_TAG "Harden"
#define HLOGE(...) __android_log_print(ANDROID_LOG_ERROR, HARDEN_LOG_TAG, __VA_ARGS__)
#define HLOGW(...) __android_log_print(ANDROID_LOG_WARN, HARDEN_LOG_TAG, __VA_ARGS__)

namespace somcp_harden {

// ===========================================================================
// PRNG
//
// A tiny counter-based PRNG used to derive per-build "poison" values and to
// pick which check runs in which order. It is deliberately NOT the platform
// rand(): the sequence must be stable within one build so that separately
// inlined copies of a check compute the same verifier value, while differing
// between builds (the seed is the build-time XOR key).
// ===========================================================================
static inline uint32_t prng(uint32_t x) {
    // xorshift32. The seed is derived per build from the XOR key (see
    // harden_seed() in signature_verify.cpp), so the sequence is stable within
    // one build and differs between builds.
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

// ===========================================================================
// Checksum / response transform
//
// Each anti-tamper probe returns a small integer "evidence" value. The caller
// folds that evidence together with a build-time PRNG constant into a
// "response" that is then required to equal a value recomputed from the probe
// itself. Because the response is derived (not a constant boolean), patching
// the comparison to "always equal" is not enough: the derived value must ALSO
// feed dependent arithmetic elsewhere (HARDEN_CONSUME) or the app misbehaves.
// ===========================================================================

/** Fold an evidence word into a rolling response. */
static inline uint32_t fold(uint32_t acc, uint32_t evidence) {
    // Mix so that any single changed evidence bit diverges the whole response.
    return prng(acc ^ (evidence * 0x9E3779B1u) ^ 0x85EBCA6Bu);
}

// ===========================================================================
// Debugger / tracer probes
// ===========================================================================

/**
 * Reads TracerPid from /proc/self/status *without* going through libc stdio,
 * so an LD_PRELOAD/frida hook of fopen/fgets cannot hide the tracer. Falls
 * back to a direct read() of the file descriptor.
 *
 * @return tracer pid, or 0 when none / undeterminable.
 */
static inline int tracer_pid_raw() {
    int fd = ::open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    // Locate "TracerPid:" manually (no strstr -> no libc string hooks).
    const char needle[] = "TracerPid:";
    const size_t needle_len = sizeof(needle) - 1;
    for (ssize_t i = 0; i + static_cast<ssize_t>(needle_len) < n; i++) {
        size_t j = 0;
        while (j < needle_len && buf[i + j] == needle[j]) j++;
        if (j != needle_len) continue;
        ssize_t k = i + static_cast<ssize_t>(needle_len);
        while (k < n && (buf[k] == ' ' || buf[k] == '\t')) k++;
        int pid = 0;
        bool any = false;
        while (k < n && buf[k] >= '0' && buf[k] <= '9') {
            pid = pid * 10 + (buf[k] - '0');
            any = true;
            k++;
        }
        return any ? pid : 0;
    }
    return 0;
}

// ===========================================================================
// Self-integrity: in-memory hash of a code region
//
// WHY: a cracker who patches the .so on disk can be defeated by hashing the
// *mapped* code at runtime - the patch is visible in memory. This is not
// unbeatable either (an attacker can restore the page before the probe), but
// combined with randomized timing and multiple probes it costs real effort.
// ===========================================================================

/** FNV-1a over a byte range. */
static inline uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

/**
 * Computes an FNV-1a hash over a range of this library's own mapped .text.
 *
 * The range is derived from dl_iterate_phdr for the executable that contains
 * [probe_addr], so it works under both APK-installed (base.apk!lib/...) and
 * extracted-lib layouts, and survives ASLR.
 *
 * @param probe_addr  address inside the library whose text should be hashed
 * @param out_hash    receives the hash; untouched on failure
 * @return true when a PT_LOAD executable segment covering probe_addr was found.
 */
struct TextRange {
    uintptr_t base = 0;
    size_t size = 0;
    bool found = false;
    uintptr_t anchor = 0; // set by the caller: an address inside our own .text
};

static inline int phdr_cb_for_text(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    TextRange* out = static_cast<TextRange*>(data);
    if (out->found) return 1; // stop: already have our answer

    // Identify our own object by checking whether any executable PT_LOAD
    // contains [anchor] (an address of a function in this library, supplied by
    // the caller). info->dlpi_addr + p_vaddr spans each load segment, so this
    // works under APK-installed (base.apk!lib/...) and extracted layouts and
    // survives ASLR.
    const uintptr_t anchor = out->anchor;

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        if ((ph.p_flags & PF_X) == 0) continue;
        uintptr_t start = static_cast<uintptr_t>(info->dlpi_addr + ph.p_vaddr);
        uintptr_t end = start + ph.p_memsz;
        if (anchor >= start && anchor < end) {
            out->base = start;
            out->size = ph.p_memsz;
            out->found = true;
            return 1;
        }
    }
    return 0;
}

/**
 * Returns a hash over the executable PT_LOAD segment of the library that owns
 * [anchor_addr]. Returns 0 when the segment cannot be located.
 */
static inline uint64_t hash_own_text(const void* anchor_addr) {
    TextRange range;
    range.anchor = reinterpret_cast<uintptr_t>(anchor_addr);
    dl_iterate_phdr(phdr_cb_for_text, &range);
    if (!range.found || range.size == 0) return 0;
    // Hash a bounded window (the first 256 KiB of .text) so the probe stays
    // cheap enough to run periodically; the head of .text holds the majority
    // of inlined checks.
    size_t n = range.size > (256u * 1024u) ? (256u * 1024u) : range.size;
    return fnv1a(reinterpret_cast<const uint8_t*>(range.base), n);
}

// ---------------------------------------------------------------------------
// Load-time text snapshot
//
// The self-integrity check only works if we have something trustworthy to
// compare against. We therefore snapshot the .text hash the first time it is
// needed and keep it in a hidden, process-local variable. A later probe that
// reads a DIFFERENT hash means the code was patched in memory after the
// snapshot was taken (e.g. an in-memory patch that removed a check).
//
// The snapshot itself is taken lazily, at the first probe, which is early in
// Application startup (attachBaseContext) — i.e. before most hooking tools'
// in-memory patching runs. It is deliberately NOT a `const` initialised from
// the ELF, so it cannot be trivially recomputed by re-running the loader.
// ---------------------------------------------------------------------------
struct TextSnapshot {
    uint64_t hash = 0;
    bool valid = false;
    void* anchor = nullptr;
};

static inline TextSnapshot& text_snapshot() {
    static TextSnapshot snap;
    return snap;
}

/**
 * Returns 1 when our own mapped .text still matches the load-time snapshot,
 * 0 otherwise (including when the snapshot could not be taken).
 *
 * @param anchor_addr an address inside our own .text (e.g. &this_function)
 */
static inline uint32_t text_unchanged(const void* anchor_addr) {
    TextSnapshot& snap = text_snapshot();
    const uint64_t current = hash_own_text(anchor_addr);
    if (current == 0) return 0;

    if (!snap.valid) {
        snap.hash = current;
        snap.valid = true;
        snap.anchor = const_cast<void*>(anchor_addr);
        return 1; // first observation: nothing to compare against yet
    }

    // Compare against the snapshot. Using a fold instead of `==` so the result
    // is a derived value, not a flippable branch.
    uint32_t diff = static_cast<uint32_t>((current ^ snap.hash) != 0u);
    return diff ^ 1u;
}
// ===========================================================================
// Environment probes
// ===========================================================================

/**
 * Scans /proc/self/maps for hooking-framework artifacts. Uses raw open/read
 * (not stdio) and a byte-level substring search (not strstr) so libc hooks
 * cannot mask the result.
 *
 * @return bitmask of matched categories (0 = clean).
 */
enum : uint32_t {
    kEnvClean     = 0,
    kEnvFrida     = 1u << 0,
    kEnvXposed    = 1u << 1,
    kEnvInjection = 1u << 2,
    kEnvAddrMap   = 1u << 3,
};

static inline bool buf_contains_ci(const char* hay, size_t hay_len, const char* needle) {
    size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay_len < nlen) return false;
    char lower_needle[32];
    if (nlen >= sizeof(lower_needle)) return false;
    for (size_t i = 0; i < nlen; i++) {
        char c = needle[i];
        lower_needle[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        size_t j = 0;
        while (j < nlen) {
            char c = hay[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            if (c != lower_needle[j]) break;
            j++;
        }
        if (j == nlen) return true;
    }
    return false;
}

static inline uint32_t scan_self_maps() {
    int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return kEnvClean;

    uint32_t flags = kEnvClean;
    char buf[8192];
    ssize_t n;
    // Read the whole file in chunks; a hooking lib is normally near the top.
    size_t total = 0;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0 && total < (8u << 20)) {
        total += static_cast<size_t>(n);
        if (buf_contains_ci(buf, static_cast<size_t>(n), "frida") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "gum-js-loop") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "gadget")) {
            flags |= kEnvFrida;
        }
        if (buf_contains_ci(buf, static_cast<size_t>(n), "xposed") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "lsposed") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "edxp") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "zygisk")) {
            flags |= kEnvXposed;
        }
        if (buf_contains_ci(buf, static_cast<size_t>(n), "apptweak") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "tweakme") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "signaturekill") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "sigkill") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "yc/pm") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "sandhook")) {
            flags |= kEnvInjection;
        }
        if (buf_contains_ci(buf, static_cast<size_t>(n), "libxiaojianbang") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "epic") ||
            buf_contains_ci(buf, static_cast<size_t>(n), "dobby")) {
            flags |= kEnvInjection;
        }
    }
    ::close(fd);
    return flags;
}

/** True when a debugger/tracer is attached, using raw syscalls. */
static inline bool tracer_attached() {
    // ptrace(PTRACE_TRACEME) fails with EPERM when already being traced. Do NOT
    // actually remain traced; PTRACE_TRACEME on an untraced process succeeds and
    // makes us traceable by the parent, which is harmless here but we detach by
    // simply not relying on it further. Use the TracerPid probe as the primary
    // signal and PTRACE_TRACEME only as a secondary hint.
    if (tracer_pid_raw() > 0) return true;
    errno = 0;
    long rc = ::syscall(__NR_ptrace, PTRACE_TRACEME, 0, 0, 0);
    if (rc == -1 && errno == EPERM) return true;
    return false;
}

// ===========================================================================
// Timing probe
//
// A debugger stepping through code, or an emulator, skews a tight loop's
// duration. We measure a short busy loop and compare against a THRESHOLD
// scaled by clock(). Deliberately generous to avoid false positives on slow
// devices; its real value is as one more divergent bit in the response.
// ===========================================================================

static inline uint64_t rdtsc_like() {
    uint64_t v;
    // ARM: read the virtual counter; x86: rdtsc; otherwise use clock_gettime.
#if defined(__aarch64__)
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
#elif defined(__arm__)
    asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(v));
#elif defined(__x86_64__) || defined(__i386__)
    v = __builtin_ia32_rdtsc();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    v = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
#endif
    return v;
}

/** Returns true when the busy-loop timing looks anomalous (slow / stepped). */
static inline bool timing_anomaly() {
    const uint32_t iters = 20000;
    uint64_t t0 = rdtsc_like();
    volatile uint32_t sink = 0;
    for (uint32_t i = 0; i < iters; i++) {
        sink = prng(sink ^ i);
    }
    (void)sink;
    uint64_t t1 = rdtsc_like();
    uint64_t delta = t1 - t0;
    // Threshold: ~40x the per-iteration cost observed on typical hardware.
    // cntvct_el0 / rdtsc both tick fast; 20k iterations stay well under this
    // unless the process is being single-stepped or emulated.
    return delta > static_cast<uint64_t>(iters) * 400ull;
}

/** Reads the pthread name of each thread to spot frida's "gum-js-loop". */
static inline bool suspicious_thread_names() {
    DIR* d = ::opendir("/proc/self/task");
    if (!d) return false;
    bool hit = false;
    struct dirent* e;
    while ((e = ::readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[256];
        // Build "/proc/self/task/<tid>/comm" without snprintf-free assumptions.
        int n = 0;
        const char* prefix = "/proc/self/task/";
        for (const char* p = prefix; *p && n < 200; p++) path[n++] = *p;
        for (const char* p = e->d_name; *p && n < 230; p++) path[n++] = *p;
        const char* suffix = "/comm";
        for (const char* p = suffix; *p && n < 255; p++) path[n++] = *p;
        path[n] = '\0';

        int fd = ::open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char comm[64];
        ssize_t r = ::read(fd, comm, sizeof(comm) - 1);
        ::close(fd);
        if (r <= 0) continue;
        comm[r] = '\0';
        if (buf_contains_ci(comm, static_cast<size_t>(r), "gum-js-loop") ||
            buf_contains_ci(comm, static_cast<size_t>(r), "gmain") ||
            buf_contains_ci(comm, static_cast<size_t>(r), "frida")) {
            hit = true;
            break;
        }
    }
    ::closedir(d);
    return hit;
}

// ===========================================================================
// Aggregated evidence + response
//
// `gather_evidence()` is the single inlined snapshot of all probes. Two
// independently inlined calls with the same seed MUST produce the same value,
// so the build-time seed is passed in by the caller (from kXorKey).
// ===========================================================================

static inline uint32_t gather_evidence(uint32_t seed) {
    uint32_t acc = 0xA5A5A5A5u ^ seed;
    // 1. Tracer present?
    acc = fold(acc, tracer_attached() ? 0x1234u : 0x0000u);
    // 2. Hook framework artifacts in our own maps?
    acc = fold(acc, scan_self_maps());
    // 3. Suspicious thread names?
    acc = fold(acc, suspicious_thread_names() ? 0x0BADC0DEu : 0u);
    // 4. Timing anomaly.
    //
    // NOTE: timing is deliberately kept SEPARATE from the gating evidence. A
    // slow device, a loaded CPU, an emulator, or a GC pause inside the measured
    // window can all skew the loop, and a false positive here would brick a
    // legitimate install. It is therefore only recorded (for diagnostics /
    // potential server-side scoring), never used to deny.
    return acc;
}

/** True when a timing anomaly was observed; advisory only (never gates). */
static inline bool timing_anomaly_advisory() {
    return timing_anomaly();
}

/**
 * The evidence value a pristine environment produces, i.e. gather_evidence()
 * with every probe returning "clean". Kept as its own function (rather than a
 * literal) so it is recomputed from the same seed and can be compared against
 * the live evidence in tamper_gate().
 *
 * Keeping this in lockstep with gather_evidence() is essential: if a new probe
 * is added above, add its clean value here too.
 */
static inline uint32_t clean_evidence_for(uint32_t seed) {
    uint32_t acc = 0xA5A5A5A5u ^ seed;
    acc = fold(acc, 0x0000u); // tracer clean
    acc = fold(acc, kEnvClean); // maps clean
    acc = fold(acc, 0u);      // thread names clean
    return acc;
}

} // namespace somcp_harden

// ===========================================================================
// Consumption primitive
//
// HARDEN_CONSUME folds a "verifier gate" value into a live variable. The
// caller MUST use the variable in real work (return it, index with it, etc.)
// so that defeating the gate requires understanding the data flow rather than
// flipping one branch. The value is 1 when the gate passes, 0 otherwise - but
// it is computed via arithmetic on derived evidence, not stored as a constant.
// ===========================================================================
#define HARDEN_CONSUME(var, gate)                                   \
    do {                                                            \
        uint32_t _hv = static_cast<uint32_t>(gate);                 \
        var = static_cast<decltype(var)>(                           \
            static_cast<uint64_t>(var) ^                            \
            (static_cast<uint64_t>(_hv) * 0x9E3779B97F4A7C15ull));  \
    } while (0)

#endif // SOMCP_HARDENING_H
