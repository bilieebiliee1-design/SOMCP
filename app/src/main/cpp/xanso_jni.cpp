#include <jni.h>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstring>
#include "fix/section_fix.h"

struct XElf64Ehdr {
    unsigned char ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

struct XElf64Shdr {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
};

struct XElf64Phdr {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};

static std::string jstr(JNIEnv* env, jstring value) {
    if (!value) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string result = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return result;
}

static bool write_bytes(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return out.good();
}

static std::vector<unsigned char> read_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return {};
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size <= 0) return {};
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

static std::vector<unsigned char> recover_elf64_orphan_sections(std::vector<unsigned char> bytes) {
    if (bytes.size() < sizeof(XElf64Ehdr)) return {};
    XElf64Ehdr header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.ident[0] != 0x7f || header.ident[1] != 'E' || header.ident[2] != 'L' || header.ident[3] != 'F' || header.ident[4] != 2 || header.ident[5] != 1) return {};
    if (header.shoff != 0 && header.shnum != 0) return bytes;
    for (size_t offset = (sizeof(XElf64Ehdr) + 7) & ~size_t(7); offset + 2 * sizeof(XElf64Shdr) <= bytes.size(); offset += 8) {
        XElf64Shdr first{};
        std::memcpy(&first, bytes.data() + offset, sizeof(first));
        if (first.name != 0 || first.type != 0 || first.flags != 0 || first.offset != 0 || first.size != 0) continue;
        const size_t count = (bytes.size() - offset) / sizeof(XElf64Shdr);
        if (count < 2 || count > 512 || offset + count * sizeof(XElf64Shdr) != bytes.size()) continue;
        for (size_t strIndex = 1; strIndex < count; ++strIndex) {
            XElf64Shdr strings{};
            std::memcpy(&strings, bytes.data() + offset + strIndex * sizeof(XElf64Shdr), sizeof(strings));
            if (strings.type != 3 || strings.size == 0 || strings.offset > bytes.size() || strings.size > bytes.size() - strings.offset) continue;
            const char* names = reinterpret_cast<const char*>(bytes.data() + strings.offset);
            bool valid = true;
            bool selfNamed = false;
            for (size_t index = 0; index < count; ++index) {
                XElf64Shdr section{};
                std::memcpy(&section, bytes.data() + offset + index * sizeof(XElf64Shdr), sizeof(section));
                if (section.name >= strings.size || std::memchr(names + section.name, '\0', strings.size - section.name) == nullptr) { valid = false; break; }
                if (section.type != 8 && (section.offset > bytes.size() || section.size > bytes.size() - section.offset)) { valid = false; break; }
                if (index == strIndex && std::strcmp(names + section.name, ".shstrtab") == 0) selfNamed = true;
            }
            if (!valid || !selfNamed) continue;
            header.shoff = offset;
            header.shentsize = sizeof(XElf64Shdr);
            header.shnum = static_cast<uint16_t>(count);
            header.shstrndx = static_cast<uint16_t>(strIndex);
            std::memcpy(bytes.data(), &header, sizeof(header));
            return bytes;
        }
    }
    if (header.phentsize != sizeof(XElf64Phdr) || header.phnum == 0 || header.phoff > bytes.size() || static_cast<uint64_t>(header.phnum) * header.phentsize > bytes.size() - header.phoff) return {};
    std::vector<XElf64Shdr> sections(1);
    std::string names(1, '\0');
    auto addName = [&names](const std::string& name) {
        const uint32_t offset = static_cast<uint32_t>(names.size());
        names += name;
        names.push_back('\0');
        return offset;
    };
    for (uint16_t index = 0; index < header.phnum; ++index) {
        XElf64Phdr program{};
        std::memcpy(&program, bytes.data() + header.phoff + static_cast<size_t>(index) * header.phentsize, sizeof(program));
        if (program.filesz == 0 || program.offset > bytes.size() || program.filesz > bytes.size() - program.offset) continue;
        if (program.type != 1 && program.type != 2) continue;
        XElf64Shdr section{};
        section.name = addName(program.type == 2 ? ".dynamic" : ".load" + std::to_string(index));
        section.type = program.type == 2 ? 6 : 1;
        section.flags = 2 | ((program.flags & 2) ? 1 : 0) | ((program.flags & 1) ? 4 : 0);
        section.addr = program.vaddr;
        section.offset = program.offset;
        section.size = program.filesz;
        section.addralign = program.align == 0 ? 1 : program.align;
        section.entsize = program.type == 2 ? 16 : 0;
        sections.push_back(section);
    }
    if (sections.size() < 2) return {};
    XElf64Shdr strings{};
    strings.name = addName(".shstrtab");
    strings.type = 3;
    strings.offset = bytes.size();
    strings.size = names.size();
    strings.addralign = 1;
    const uint16_t stringIndex = static_cast<uint16_t>(sections.size());
    sections.push_back(strings);
    bytes.insert(bytes.end(), names.begin(), names.end());
    while ((bytes.size() & 7) != 0) bytes.push_back(0);
    header.shoff = bytes.size();
    header.shentsize = sizeof(XElf64Shdr);
    header.shnum = static_cast<uint16_t>(sections.size());
    header.shstrndx = stringIndex;
    const auto* table = reinterpret_cast<const unsigned char*>(sections.data());
    bytes.insert(bytes.end(), table, table + sections.size() * sizeof(XElf64Shdr));
    std::memcpy(bytes.data(), &header, sizeof(header));
    return bytes;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_XAnSoEngine_nativeBuildSections(JNIEnv* env, jobject, jbyteArray input, jstring cacheDir) {
    if (!input) return nullptr;
    const jsize size = env->GetArrayLength(input);
    if (size <= 0) return nullptr;
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte*>(bytes.data()));
    const std::string base = jstr(env, cacheDir) + "/xanso-" + std::to_string(getpid()) + "-" + std::to_string(reinterpret_cast<uintptr_t>(input));
    const std::string source = base + ".so";
    const std::string output = base + ".fixed.so";
    if (!write_bytes(source, bytes)) return nullptr;
    section_fix fixer;
    const bool fixed = fixer.fix(source) && fixer.save_as(output);
    std::vector<unsigned char> result = fixed ? read_bytes(output) : std::vector<unsigned char>();
    unlink(source.c_str());
    unlink(output.c_str());
    if (result.empty()) return nullptr;
    jbyteArray array = env->NewByteArray(static_cast<jsize>(result.size()));
    env->SetByteArrayRegion(array, 0, static_cast<jsize>(result.size()), reinterpret_cast<const jbyte*>(result.data()));
    return array;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_engine_XAnSoEngine_nativeAvailable(JNIEnv*, jobject) {
    return JNI_TRUE;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_XAnSoEngine_nativeRecoverElf64Sections(JNIEnv* env, jobject, jbyteArray input) {
    if (!input) return nullptr;
    const jsize size = env->GetArrayLength(input);
    if (size <= 0) return nullptr;
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte*>(bytes.data()));
    auto recovered = recover_elf64_orphan_sections(std::move(bytes));
    if (recovered.empty()) return nullptr;
    jbyteArray array = env->NewByteArray(static_cast<jsize>(recovered.size()));
    env->SetByteArrayRegion(array, 0, static_cast<jsize>(recovered.size()), reinterpret_cast<const jbyte*>(recovered.data()));
    return array;
}
