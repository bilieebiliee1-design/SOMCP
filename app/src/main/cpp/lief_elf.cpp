// LIEF-based ELF parsing and section header reconstruction (xAnSo) JNI bridge.
//
// Replaces the hand-written Kotlin ElfParser with LIEF's production-grade
// C++ ELF parser. LIEF parses sections, symbols, relocations, program headers,
// and dynamic entries — and can rebuild section headers for hardened/stripped
// SO files (the xAnSo algorithm: reconstruct from .dynamic segment).

#include <jni.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#include <LIEF/LIEF.hpp>
#include <LIEF/json.hpp>
#include <LIEF/to_json.hpp>
#include <LIEF/DEX.hpp>
#include <LIEF/DEX/json.hpp>
#include <LIEF/ART.hpp>
#include <LIEF/ART/json.hpp>
#include <LIEF/OAT.hpp>
#include <LIEF/OAT/json.hpp>
#include <LIEF/VDEX.hpp>
#include <LIEF/VDEX/json.hpp>

namespace {

std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

inline void append_num(std::string& out, const char* key, uint64_t val, bool first) {
    if (!first) out += ",";
    out += "\"";
    out += key;
    out += "\":";
    out += std::to_string(val);
}

inline void append_str(std::string& out, const char* key, const std::string& val, bool first) {
    if (!first) out += ",";
    out += "\"";
    out += key;
    out += "\":\"";
    out += esc(val);
    out += "\"";
}

inline void append_bool(std::string& out, const char* key, bool val, bool first) {
    if (!first) out += ",";
    out += "\"";
    out += key;
    out += "\":";
    out += val ? "true" : "false";
}

std::string build_symbol_json(const LIEF::ELF::Symbol& sym) {
    std::string j = "{";
    append_str(j, "name", sym.name(), true);
    append_num(j, "bind", static_cast<uint64_t>(sym.binding()), false);
    append_num(j, "type", static_cast<uint64_t>(sym.type()), false);
    append_num(j, "visibility", static_cast<uint64_t>(sym.visibility()), false);
    append_num(j, "sectionIndex", sym.shndx(), false);
    append_num(j, "value", sym.value(), false);
    append_num(j, "size", sym.size(), false);
    append_bool(j, "imported", sym.is_imported(), false);
    append_bool(j, "exported", sym.is_exported(), false);
    j += "}";
    return j;
}

std::string build_reloc_json(const LIEF::ELF::Relocation& reloc) {
    std::string j = "{";
    append_str(j, "section", "", true);
    append_num(j, "offset", reloc.address(), false);
    append_num(j, "type", static_cast<uint64_t>(reloc.type()), false);
    const auto* sym = reloc.symbol();
    append_str(j, "symbol", sym ? sym->name() : "", false);
    append_num(j, "addend", static_cast<uint64_t>(reloc.addend()), false);
    j += "}";
    return j;
}

std::string build_section_json(const LIEF::ELF::Section& sec) {
    std::string j = "{";
    append_str(j, "name", sec.name(), true);
    append_num(j, "type", static_cast<uint64_t>(sec.type()), false);
    append_num(j, "flags", sec.flags(), false);
    append_num(j, "addr", sec.virtual_address(), false);
    append_num(j, "offset", sec.offset(), false);
    append_num(j, "size", sec.size(), false);
    append_num(j, "link", sec.link(), false);
    append_num(j, "info", sec.information(), false);
    append_num(j, "addralign", sec.alignment(), false);
    append_num(j, "entsize", sec.entry_size(), false);
    j += "}";
    return j;
}

std::string build_segment_json(const LIEF::ELF::Segment& seg) {
    std::string j = "{";
    append_num(j, "type", static_cast<uint64_t>(seg.type()), true);
    append_num(j, "flags", static_cast<uint64_t>(seg.flags()), false);
    append_num(j, "offset", seg.file_offset(), false);
    append_num(j, "vaddr", seg.virtual_address(), false);
    append_num(j, "paddr", seg.physical_address(), false);
    append_num(j, "filesz", seg.physical_size(), false);
    append_num(j, "memsz", seg.virtual_size(), false);
    append_num(j, "align", seg.alignment(), false);
    j += "}";
    return j;
}

std::string build_dynamic_json(const LIEF::ELF::DynamicEntry& entry) {
    std::string j = "{";
    append_num(j, "tag", LIEF::ELF::DynamicEntry::to_value(entry.tag()), true);
    append_num(j, "value", entry.value(), false);
    j += "}";
    return j;
}

} // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeParseAny(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jformat) {
    if (!jbytes) return env->NewStringUTF("{\"error\":\"empty\"}");
    const jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));
    const char* chars = jformat ? env->GetStringUTFChars(jformat, nullptr) : nullptr;
    std::string format = chars ? chars : "auto";
    if (chars) env->ReleaseStringUTFChars(jformat, chars);
    std::string json;
    if (format == "dex" || (format == "auto" && len >= 4 && data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n')) {
        auto parsed = LIEF::DEX::Parser::parse(data, "memory.dex");
        if (parsed) json = LIEF::DEX::to_json(*parsed);
    } else if (format == "art" || (format == "auto" && len >= 4 && data[0] == 'a' && data[1] == 'r' && data[2] == 't' && data[3] == '\n')) {
        auto parsed = LIEF::ART::Parser::parse(data, "memory.art");
        if (parsed) json = LIEF::ART::to_json(*parsed);
    } else if (format == "oat" || (format == "auto" && len >= 4 && data[0] == 'o' && data[1] == 'a' && data[2] == 't' && data[3] == '\n')) {
        auto parsed = LIEF::OAT::Parser::parse(data);
        if (parsed) json = LIEF::OAT::to_json(*parsed);
    } else if (format == "vdex" || (format == "auto" && len >= 4 && data[0] == 'v' && data[1] == 'd' && data[2] == 'e' && data[3] == 'x')) {
        auto parsed = LIEF::VDEX::Parser::parse(data, "memory.vdex");
        if (parsed) json = LIEF::VDEX::to_json(*parsed);
    } else {
        auto parsed = LIEF::Parser::parse(data);
        if (parsed) json = LIEF::to_json(*parsed);
    }
    if (json.empty()) return env->NewStringUTF("{\"error\":\"parse_failed\"}");
    return env->NewStringUTF(json.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeParse(
        JNIEnv* env, jobject thiz, jbyteArray jbytes) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) {
        return env->NewStringUTF("{\"error\":\"empty\"}");
    }

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewStringUTF("{\"error\":\"parse_failed\"}");
    }

    const auto& hdr = binary->header();
    const auto& ident = hdr.identity();
    bool is64 = ident[4] == 2;
    bool little = ident[5] == 1;

    std::string json = "{";
    append_num(json, "bits", is64 ? 64 : 32, true);
    append_bool(json, "littleEndian", little, false);
    append_num(json, "type", static_cast<uint64_t>(hdr.file_type()), false);
    append_num(json, "machine", static_cast<uint64_t>(hdr.machine_type()), false);
    append_num(json, "entry", hdr.entrypoint(), false);

    json += ",\"sections\":[";
    {
        bool first = true;
        for (const auto& sec : binary->sections()) {
            if (!first) json += ",";
            first = false;
            json += build_section_json(sec);
        }
    }
    json += "]";

    json += ",\"symbols\":[";
    {
        bool first = true;
        for (const auto& sym : binary->symtab_symbols()) {
            if (!first) json += ",";
            first = false;
            json += build_symbol_json(sym);
        }
    }
    json += "]";

    json += ",\"dynSymbols\":[";
    {
        bool first = true;
        for (const auto& sym : binary->dynamic_symbols()) {
            if (!first) json += ",";
            first = false;
            json += build_symbol_json(sym);
        }
    }
    json += "]";

    json += ",\"relocations\":[";
    {
        bool first = true;
        for (const auto& reloc : binary->relocations()) {
            if (!first) json += ",";
            first = false;
            json += build_reloc_json(reloc);
        }
    }
    json += "]";

    json += ",\"programHeaders\":[";
    {
        bool first = true;
        for (const auto& seg : binary->segments()) {
            if (!first) json += ",";
            first = false;
            json += build_segment_json(seg);
        }
    }
    json += "]";

    json += ",\"dynamicEntries\":[";
    {
        bool first = true;
        for (const auto& entry : binary->dynamic_entries()) {
            if (!first) json += ",";
            first = false;
            json += build_dynamic_json(entry);
        }
    }
    json += "]";

    json += "}";
    return env->NewStringUTF(json.c_str());
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeFixSections(
        JNIEnv* env, jobject thiz, jbyteArray jbytes) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) {
        return env->NewByteArray(0);
    }

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    LIEF::ELF::Builder builder(*binary);
    builder.build();
    const auto& built = builder.get_build();

    jbyteArray result = env->NewByteArray(static_cast<jsize>(built.size()));
    if (result == nullptr) {
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(built.size()),
                            reinterpret_cast<const jbyte*>(built.data()));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativePatchAddress(
        JNIEnv* env, jobject thiz, jbyteArray jbytes, jlong va, jbyteArray jpatch) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    jsize plen = env->GetArrayLength(jpatch);
    if (len <= 0 || plen <= 0) {
        return env->NewByteArray(0);
    }

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));
    std::vector<uint8_t> patch(static_cast<size_t>(plen));
    env->GetByteArrayRegion(jpatch, 0, plen, reinterpret_cast<jbyte*>(patch.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    binary->patch_address(static_cast<uint64_t>(va), patch);

    LIEF::ELF::Builder builder(*binary);
    builder.build();
    const auto& built = builder.get_build();

    jbyteArray result = env->NewByteArray(static_cast<jsize>(built.size()));
    if (result == nullptr) return nullptr;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(built.size()),
                            reinterpret_cast<const jbyte*>(built.data()));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeGetSectionContent(
        JNIEnv* env, jobject thiz, jbyteArray jbytes, jstring jsectionName) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) {
        return env->NewByteArray(0);
    }

    const char* secCstr = env->GetStringUTFChars(jsectionName, nullptr);
    std::string secName(secCstr);
    env->ReleaseStringUTFChars(jsectionName, secCstr);

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    const auto* sec = binary->get_section(secName);
    if (sec == nullptr) {
        return env->NewByteArray(0);
    }

    auto content = sec->content();
    jsize csize = static_cast<jsize>(content.size());
    jbyteArray result = env->NewByteArray(csize);
    if (result == nullptr) return nullptr;
    if (csize > 0) {
        env->SetByteArrayRegion(result, 0, csize,
                                reinterpret_cast<const jbyte*>(content.data()));
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeSetSectionContent(
        JNIEnv* env, jobject thiz, jbyteArray jbytes, jstring jsectionName, jbyteArray jcontent) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    jsize clen = env->GetArrayLength(jcontent);
    if (len <= 0) {
        return env->NewByteArray(0);
    }

    const char* secCstr = env->GetStringUTFChars(jsectionName, nullptr);
    std::string secName(secCstr);
    env->ReleaseStringUTFChars(jsectionName, secCstr);

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));
    std::vector<uint8_t> content(static_cast<size_t>(std::max(0, clen)));
    if (clen > 0) {
        env->GetByteArrayRegion(jcontent, 0, clen, reinterpret_cast<jbyte*>(content.data()));
    }

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    auto* sec = binary->get_section(secName);
    if (sec == nullptr) {
        return env->NewByteArray(0);
    }

    sec->content(content);

    LIEF::ELF::Builder builder(*binary);
    builder.build();
    const auto& built = builder.get_build();

    jbyteArray result = env->NewByteArray(static_cast<jsize>(built.size()));
    if (result == nullptr) return nullptr;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(built.size()),
                            reinterpret_cast<const jbyte*>(built.data()));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeAddExportedFunction(
        JNIEnv* env, jobject thiz, jbyteArray jbytes, jlong addr, jstring jname) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) {
        return env->NewByteArray(0);
    }

    const char* nameCstr = env->GetStringUTFChars(jname, nullptr);
    std::string funcName(nameCstr);
    env->ReleaseStringUTFChars(jname, nameCstr);

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    binary->add_exported_function(static_cast<uint64_t>(addr), funcName);

    LIEF::ELF::Builder builder(*binary);
    builder.build();
    const auto& built = builder.get_build();

    jbyteArray result = env->NewByteArray(static_cast<jsize>(built.size()));
    if (result == nullptr) return nullptr;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(built.size()),
                            reinterpret_cast<const jbyte*>(built.data()));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeRemoveSymbol(
        JNIEnv* env, jobject thiz, jbyteArray jbytes, jstring jname) {
    (void)thiz;
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) {
        return env->NewByteArray(0);
    }

    const char* nameCstr = env->GetStringUTFChars(jname, nullptr);
    std::string symName(nameCstr);
    env->ReleaseStringUTFChars(jname, nameCstr);

    std::vector<uint8_t> data(static_cast<size_t>(len));
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(data.data()));

    auto binary = LIEF::ELF::Parser::parse(data);
    if (!binary) {
        return env->NewByteArray(0);
    }

    binary->remove_symbol(symName);

    LIEF::ELF::Builder builder(*binary);
    builder.build();
    const auto& built = builder.get_build();

    jbyteArray result = env->NewByteArray(static_cast<jsize>(built.size()));
    if (result == nullptr) return nullptr;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(built.size()),
                            reinterpret_cast<const jbyte*>(built.data()));
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_engine_LiefEngine_nativeAvailable(
        JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    return JNI_TRUE;
}

} // extern "C"
