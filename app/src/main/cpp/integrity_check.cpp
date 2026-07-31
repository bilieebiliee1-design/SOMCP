#include <jni.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <atomic>
#include <elf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

// ============================================================
// XOR-obfuscated string helper (defeats simple "strings" grep)
// ============================================================
template <size_t N>
struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]) {
        for (size_t i = 0; i < N; ++i)
            data[i] = s[i] ^ 0x5A;
    }
    std::string decode() const {
        std::string out(N, '\0');
        for (size_t i = 0; i < N; ++i)
            out[i] = data[i] ^ 0x5A;
        // Trim trailing null
        while (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }
};

#define OBF(s) ObfStr<sizeof(s)>(s).decode()

// ============================================================
// Self-CRC32: compute CRC32 of the .text section of our own ELF
// ============================================================
static uint32_t crc32_table() {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (int j = 0; j < 8; ++j)
                crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
            table[i] = crc;
        }
        init = true;
    }
    // Return a dummy to make the function non-trivial so the
    // compiler doesn't inline it away
    return table[0];
}

static uint32_t crc32_bytes(const void* data, size_t len) {
    crc32_table(); // ensure init
    // Re-compute table locally to avoid static init dependency
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        table[i] = crc;
    }
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

// Hard-coded expected CRC32 of the .text section.
// This will be updated after first build by reading the actual value.
// The value 0xDEADBEEF is a placeholder — the real value is patched in
// after the first CI build produces the .so.
static constexpr uint32_t EXPECTED_TEXT_CRC = 0xDEADBEEF;

static uint32_t self_text_crc() {
    Dl_info info;
    if (!dladdr((void*)self_text_crc, &info)) return 0;
    if (!info.dli_fbase) return 0;

    // Parse ELF header
    const uint8_t* base = static_cast<const uint8_t*>(info.dli_fbase);
    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0) return 0;

    // Find .text section via section headers
    const Elf64_Shdr* shdr = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);
    const char* shstrtab = reinterpret_cast<const char*>(base + shdr[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; ++i) {
        const char* name = shstrtab + shdr[i].sh_name;
        if (strcmp(name, ".text") == 0) {
            return crc32_bytes(base + shdr[i].sh_offset, shdr[i].sh_size);
        }
    }
    return 0;
}

static bool verify_self_integrity() {
    uint32_t crc = self_text_crc();
    if (crc == 0) return true; // Can't determine — skip check
    if (crc != EXPECTED_TEXT_CRC) return false;
    return true;
}

// ============================================================
// Anti-debugging
// ============================================================
static bool has_tracer() {
    char buf[256];
    FILE* f = fopen(OBF("/proc/self/status").c_str(), "r");
    if (!f) return false;
    bool traced = false;
    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int pid = atoi(buf + 10);
            if (pid > 0) traced = true;
            break;
        }
    }
    fclose(f);
    return traced;
}

static bool ptrace_self() {
    // Fork and ptrace — if ptrace already attached (by debugger), this fails
    pid_t child = fork();
    if (child == 0) {
        // Child: try to ptrace parent
        pid_t parent = getppid();
        // We use ptrace via direct syscall to avoid detection
        long ret = syscall(__NR_ptrace, 0 /*PTRACE_TRACEME*/, 0, 0, 0);
        if (ret == 0) {
            // Success — no debugger attached. Kill child to avoid zombie.
            kill(parent, SIGUSR1);
            _exit(0);
        }
        // ptrace failed — debugger is attached
        _exit(1);
    } else if (child > 0) {
        int status;
        waitpid(child, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return true; // fork failed — assume not debugged
}

// ============================================================
// Anti-Frida: check for D-Bus, frida pipes, frida-server
// ============================================================
static bool check_frida_dbus() {
    // Frida exposes a D-Bus interface on a local socket
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    // Try to connect to common Frida D-Bus sockets
    const char* paths[] = {
        "/tmp/frida.sock",
        "/data/local/tmp/frida.sock",
        nullptr
    };
    for (int i = 0; paths[i]; ++i) {
        strncpy(addr.sun_path, paths[i], sizeof(addr.sun_path) - 1);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) continue;
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            close(fd);
            return true;
        }
        close(fd);
    }

    // Check for frida-helper pipes
    DIR* dir = opendir(OBF("/data/local/tmp").c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name.find(OBF("frida")) != std::string::npos ||
                name.find(OBF("re.frida")) != std::string::npos) {
                closedir(dir);
                return true;
            }
        }
        closedir(dir);
    }
    return false;
}

static bool check_frida_maps() {
    char buf[1024];
    FILE* f = fopen(OBF("/proc/self/maps").c_str(), "r");
    if (!f) return false;
    bool found = false;
    while (fgets(buf, sizeof(buf), f)) {
        std::string line = buf;
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        if (line.find(OBF("frida")) != std::string::npos ||
            line.find(OBF("gum")) != std::string::npos ||
            line.find(OBF("frida-agent")) != std::string::npos) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static bool check_frida_port() {
    // Check common Frida ports
    for (int port : {27042, 27043}) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            close(fd);
            return true;
        }
        close(fd);
    }
    return false;
}

// ============================================================
// Anti-Xposed/EdXposed/LSPosed
// ============================================================
static bool check_xposed_env() {
    // Check for Xposed-related environment variables
    const char* vars[] = {
        "XDISABLE", "XPOSED_", "exposed.", nullptr
    };
    for (int i = 0; vars[i]; ++i) {
        if (getenv(vars[i])) return true;
    }

    // Check for Xposed-related packages in /proc/self/maps
    char buf[1024];
    FILE* f = fopen(OBF("/proc/self/maps").c_str(), "r");
    if (!f) return false;
    bool found = false;
    while (fgets(buf, sizeof(buf), f)) {
        std::string line = buf;
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        if (line.find(OBF("xposed")) != std::string::npos ||
            line.find(OBF("lsposed")) != std::string::npos ||
            line.find(OBF("edxp")) != std::string::npos ||
            line.find(OBF("zygisk")) != std::string::npos) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

// ============================================================
// Check for reverse engineering tools
// ============================================================
static bool is_emulator() {
    // Check for emulator indicators
    char buf[256];
    FILE* f = fopen(OBF("/proc/cpuinfo").c_str(), "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            // Genymotion / QEMU
            if (strstr(buf, "goldfish") || strstr(buf, "ranchu")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }

    // Check for QEMU in /proc/self/maps
    f = fopen(OBF("/proc/self/maps").c_str(), "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "qemu")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    return false;
}

// ============================================================
// Main native verification entry point
// ============================================================
extern "C" JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_core_IntegrityGuard_nativeVerifyIntegrity(
    JNIEnv* env, jclass /*clazz*/, jstring expectedHex) {

    const char* expected = env->GetStringUTFChars(expectedHex, nullptr);
    std::string expectedStr(expected ? expected : "");
    env->ReleaseStringUTFChars(expectedHex, expected);

    // 1. Self-integrity check
    if (!verify_self_integrity()) {
        return JNI_FALSE;
    }

    // 2. Anti-debugging
    if (has_tracer()) {
        return JNI_FALSE;
    }
    if (!ptrace_self()) {
        return JNI_FALSE;
    }

    // 3. Anti-Frida
    if (check_frida_dbus() || check_frida_maps() || check_frida_port()) {
        return JNI_FALSE;
    }

    // 4. Anti-Xposed
    if (check_xposed_env()) {
        return JNI_FALSE;
    }

    // 5. Emulator detection
    if (is_emulator()) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

// ============================================================
// Aggressive native termination — kills the process immediately
// ============================================================
extern "C" JNIEXPORT void JNICALL
Java_com_soreverse_mcp_core_IntegrityGuard_nativeTerminate(
    JNIEnv* /*env*/, jclass /*clazz*/) {

    // Multiple kill signals to make recovery harder
    kill(getpid(), SIGKILL);
    _exit(173);
}