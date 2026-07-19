// rizin_core.cpp — JNI bridge exposing Rizin (librz) full capabilities to Kotlin.
//
// Rizin is the sole disasm/asm/analysis/search/emulation/diff engine.
// Capstone/Keystone fully removed. This bridge exposes:
//
//   rzDisassemble  — disassemble bytes at address (rz_asm)
//   rzAssemble     — assemble instruction text to bytes (rz_asm)
//   rzXrefs        — cross-references to/from an address (rz_analysis_xrefs)
//   rzAnalyze      — load SO + run auto-analysis, return stats (rz_core)
//   rzFunctions    — list all discovered functions with properties (rz_analysis)
//   rzCfg          — control flow graph for a function: basic blocks + edges
//   rzSearchBytes  — hex pattern search with wildcards (rz_search)
//   rzScanCrypto   — scan for crypto material: AES/RSA/ECC keys (rz_search)
//   rzEsilStep     — ESIL VM emulation: step + register snapshot (rz_core_esil)
//   rzDiff         — byte-level diff between two buffers + similarity (rz_diff)
//
// Built against Rizin 0.8.0 API.
#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#define RZ_NATIVE_LOG(...) __android_log_print(ANDROID_LOG_INFO, "RzNative", __VA_ARGS__)
#include <sys/stat.h>
#include <rz_core.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_bin.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_search.h>
#include <rz_diff.h>
#include <rz_hash.h>
#include <rz_reg.h>

namespace {
    std::mutex ghidraConfigMutex;
    std::string ghidraPluginDir;
    std::string ghidraSleighHome;

    void applyGhidraConfig(RzCore* core) {
        std::lock_guard<std::mutex> lock(ghidraConfigMutex);
        if (!ghidraSleighHome.empty()) {
            setenv("SLEIGHHOME", ghidraSleighHome.c_str(), 1);
        }
        if (!ghidraPluginDir.empty()) {
            setenv("RZ_LIB_PLUGINS", ghidraPluginDir.c_str(), 1);
            rz_config_set_i(core->config, "cfg.plugins", 1);
            std::string pluginFile = ghidraPluginDir + "/libcore_ghidra.so";
            bool openOk = rz_lib_open(core->lib, pluginFile.c_str());
            bool openDirOk = rz_lib_opendir(core->lib, ghidraPluginDir.c_str(), true);
            int loadOk = rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL);
            RZ_NATIVE_LOG("ghidra pluginFile=%s open=%d opendir=%d loadlibs=%d", pluginFile.c_str(), openOk ? 1 : 0, openDirOk ? 1 : 0, loadOk);
        }
        if (!ghidraSleighHome.empty()) {
            rz_config_set(core->config, "sleighhome", ghidraSleighHome.c_str());
            rz_config_set(core->config, "ghidra.sleighhome", ghidraSleighHome.c_str());
            rz_config_set_i(core->config, "ghidra.linelen", 120);
            rz_config_set_i(core->config, "ghidra.indent", 4);
            rz_config_set_i(core->config, "ghidra.cmt.indent", 4);
            rz_config_set_i(core->config, "ghidra.maximplref", 2);
            RZ_NATIVE_LOG("ghidra sleighhome=%s", ghidraSleighHome.c_str());
        }
    }

    std::string jStr(JNIEnv* env, jstring s) {
        if (!s) return {};
        const char* c = env->GetStringUTFChars(s, nullptr);
        std::string r(c ? c : "");
        if (c) env->ReleaseStringUTFChars(s, c);
        return r;
    }

    struct AsmProfile { const char* arch; int bits; };
    AsmProfile profileFor(const std::string& arch) {
        if (arch == "arm64") return { "arm", 64 };
        if (arch == "arm32") return { "arm", 32 };
        if (arch == "x86_64") return { "x86", 64 };
        if (arch == "x86") return { "x86", 32 };
        if (arch == "mips") return { "mips", 32 };
        return { "x86", 32 };
    }

    std::string hexBytes(const uint8_t* d, size_t n) {
        static const char* h = "0123456789ABCDEF";
        std::string s;
        s.reserve(n * 3);
        for (size_t i = 0; i < n; i++) {
            if (i) s += ' ';
            s += h[(d[i] >> 4) & 0xF];
            s += h[d[i] & 0xF];
        }
        return s;
    }

    std::string normalizeBytePattern(const std::string& pattern) {
        std::string out;
        out.reserve(pattern.size());
        for (char c : pattern) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',') continue;
            if (c == '?') out += '.';
            else out += c;
        }
        return out;
    }

    bool isWritableDir(const char* dir) {
        struct stat st{};
        return dir && stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && access(dir, W_OK) == 0;
    }

    // Write bytes to a temp .so file, return the path. Caller must unlink.
    std::string writeTempSo(const uint8_t* data, size_t len, const char* tag) {
        const char* dirs[] = { getenv("TMPDIR"), "/data/user/0/com.soreverse.mcp/cache", "/data/data/com.soreverse.mcp/cache", "/data/local/tmp" };
        char tmpl[512];
        int fd = -1;
        for (const char* dir : dirs) {
            if (!isWritableDir(dir)) continue;
            snprintf(tmpl, sizeof(tmpl), "%s/rz_%s_%d_XXXXXX.so", dir, tag, (int)getpid());
            fd = mkstemps(tmpl, 3);
            if (fd >= 0) break;
        }
        if (fd < 0) return {};
        FILE* f = fdopen(fd, "wb");
        if (!f) { close(fd); unlink(tmpl); return {}; }
        fwrite(data, 1, len, f);
        fclose(f);
        return tmpl;
    }

    // Load a SO into a new RzCore and run auto-analysis. Returns core or nullptr.
    RzCore* loadAndAnalyze(const uint8_t* data, size_t len) {
        std::string path = writeTempSo(data, len, "core");
        if (path.empty()) return nullptr;
        RzCore* core = rz_core_new();
        if (!core) { unlink(path.c_str()); return nullptr; }
        bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
        if (!ok) { rz_core_free(core); unlink(path.c_str()); return nullptr; }
        rz_core_analysis_all(core);
        // Keep the temp file — the core needs it for I/O. Caller must unlink after.
        return core;
    }

    void cleanupCore(RzCore* core, const std::string& path) {
        if (core) rz_core_free(core);
        if (!path.empty()) unlink(path.c_str());
    }

    std::string escJson(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

    std::string stripAnsi(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\x1b' && i + 1 < s.size() && s[i + 1] == '[') {
                i += 2;
                while (i < s.size() && (s[i] < '@' || s[i] > '~')) ++i;
                continue;
            }
            out.push_back(s[i]);
        }
        return out;
    }

    const char* xrefTypeStr(RzAnalysisXRefType t) {
        switch (t) {
            case RZ_ANALYSIS_XREF_TYPE_CODE:   return "code";
            case RZ_ANALYSIS_XREF_TYPE_CALL:   return "call";
            case RZ_ANALYSIS_XREF_TYPE_DATA:   return "data";
            case RZ_ANALYSIS_XREF_TYPE_STRING: return "string";
            default: return "ref";
        }
    }

    uint32_t readU32Le(const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }

    bool isAarch64StrongPrologue(uint32_t insn) {
        // Only high-confidence function starts. Weak stack ops mid-function must not become anchors.
        // STP X29, X30, [SP, #imm]!  (pre-index)
        if ((insn & 0xFFC07FFFu) == 0xA9807BFDu) return true;
        // STP X29, X30, [SP, #imm]   (signed offset)
        if ((insn & 0xFFC07FFFu) == 0xA9007BFDu) return true;
        // PACIASP / PACIBSP
        if (insn == 0xD503233F || insn == 0xD503237F) return true;
        return false;
    }

    bool isAarch64Prologue(uint32_t insn) {
        return isAarch64StrongPrologue(insn);
    }

    bool isAarch64RetLike(uint32_t insn) {
        // RET / RETAA / RETAB / BRK / BLR Xn not included; pure returns:
        if (insn == 0xD65F03C0 || insn == 0xD65F0BFF || insn == 0xD65F0FFF) return true;
        // BLR not return. SVC/HVC ignored.
        return false;
    }

    void collectAarch64Anchors(RzCore* core, ut64 rangeFrom, ut64 rangeTo, std::vector<ut64>& anchors) {
        if (!core || !core->io || rangeTo <= rangeFrom) return;
        const ut64 maxScan = 4ull * 1024ull * 1024ull;
        if (rangeTo - rangeFrom > maxScan) rangeTo = rangeFrom + maxScan;
        std::vector<uint8_t> buf(static_cast<size_t>(rangeTo - rangeFrom));
        const int n = rz_io_read_at(core->io, rangeFrom, buf.data(), static_cast<int>(buf.size()));
        if (n < 8) return;
        const size_t bytes = static_cast<size_t>(n) & ~size_t(3);
        for (size_t off = 0; off + 4 <= bytes; off += 4) {
            const uint32_t insn = readU32Le(buf.data() + off);
            const ut64 va = rangeFrom + off;
            if (isAarch64Prologue(insn)) {
                anchors.push_back(va);
            }
            // BL imm26 — call target is a strong function start candidate
            if ((insn & 0xFC000000u) == 0x94000000u) {
                int64_t imm = static_cast<int64_t>(insn & 0x03FFFFFFu);
                if (imm & 0x02000000) imm |= ~0x03FFFFFFLL;
                const ut64 target = va + (static_cast<ut64>(imm) << 2);
                if (target >= rangeFrom && target < rangeTo && (target % 4) == 0) {
                    anchors.push_back(target);
                }
            }
        }
    }

    ut64 nextAnchorAfter(const std::vector<ut64>& anchors, ut64 va) {
        ut64 next = 0;
        for (ut64 a : anchors) {
            if (a > va && (next == 0 || a < next)) next = a;
        }
        return next;
    }

    ut64 findLinearReturnBoundary(RzCore* core, ut64 start, ut64 hardEnd) {
        if (!core || !core->io || hardEnd <= start) return 0;
        const ut64 maxSpan = 0x10000;
        if (hardEnd - start > maxSpan) hardEnd = start + maxSpan;
        std::vector<uint8_t> buf(static_cast<size_t>(hardEnd - start));
        const int n = rz_io_read_at(core->io, start, buf.data(), static_cast<int>(buf.size()));
        if (n < 8) return 0;
        const size_t bytes = static_cast<size_t>(n) & ~size_t(3);
        bool sawBody = false;
        for (size_t off = 0; off + 4 <= bytes; off += 4) {
            const uint32_t insn = readU32Le(buf.data() + off);
            const ut64 va = start + off;
            if (off > 0 && isAarch64Prologue(insn) && sawBody) {
                return va;
            }
            if (isAarch64RetLike(insn)) {
                // Prefer boundary after ret, unless next insn is another prologue/padding.
                ut64 after = va + 4;
                if (off + 8 <= bytes) {
                    const uint32_t next = readU32Le(buf.data() + off + 4);
                    if (isAarch64Prologue(next) || next == 0xD503201F /* NOP */) {
                        return after;
                    }
                }
                // Keep scanning a little for tail padding / fallthrough; still record candidate.
                if (hardEnd > after) {
                    // If next 4 instructions look like a new function, cut here.
                    size_t look = off + 4;
                    int nops = 0;
                    while (look + 4 <= bytes && look < off + 20) {
                        const uint32_t ninsn = readU32Le(buf.data() + look);
                        if (ninsn == 0xD503201F) { nops++; look += 4; continue; }
                        if (isAarch64Prologue(ninsn)) return after;
                        break;
                    }
                }
            }
            if (!isAarch64Prologue(insn)) sawBody = true;
        }
        return 0;
    }

    struct SymbolSpan {
        ut64 addr = 0;
        ut64 size = 0;
        std::string name;
    };

    void seedSymbolAnchors(RzCore* core, ut64 funcVa, std::vector<ut64>& anchors, std::vector<SymbolSpan>& spans) {
        anchors.push_back(funcVa);
        if (!core || !core->bin) return;
        RzBinFile* bf = rz_bin_cur(core->bin);
        if (!bf || !bf->o) return;
        if (const RzPVector* symbols = rz_bin_object_get_symbols(bf->o)) {
            void** it = nullptr;
            rz_pvector_foreach(symbols, it) {
                auto* sym = static_cast<RzBinSymbol*>(*it);
                if (!sym || sym->is_imported) continue;
                const ut64 addr = sym->vaddr;
                if (!addr || addr == UT64_MAX) continue;
                const char* type = sym->type ? sym->type : "";
                const char* name = sym->name ? sym->name : "";
                const bool isFunc = (type && strstr(type, "FUNC")) || (name && strncmp(name, "Java_", 5) == 0);
                if (!isFunc) continue;
                anchors.push_back(addr);
                SymbolSpan span;
                span.addr = addr;
                span.size = sym->size;
                span.name = name ? name : "";
                spans.push_back(span);
                // Never pre-create an empty shell at the TARGET address.
                // rz_core_analysis_function_add may refuse to fill an existing empty fcn,
                // leaving functionSize=0 and pdg with no object (seen on last-export n0g1a2).
                if (addr == funcVa) continue;
                if (!rz_analysis_get_function_at(core->analysis, addr)) {
                    rz_analysis_create_function(core->analysis, (name && *name) ? name : nullptr, addr, RZ_ANALYSIS_FCN_TYPE_SYM);
                }
            }
        }
        if (const RzPVector* entries = rz_bin_object_get_entries(bf->o)) {
            void** it = nullptr;
            rz_pvector_foreach(entries, it) {
                auto* e = static_cast<RzBinAddr*>(*it);
                if (!e || !e->vaddr || e->vaddr == UT64_MAX) continue;
                anchors.push_back(e->vaddr);
            }
        }
    }

    ut64 selfSymbolSize(const std::vector<SymbolSpan>& spans, ut64 va) {
        for (const auto& sp : spans) {
            if (sp.addr == va) return sp.size;
        }
        return 0;
    }

    // Always re-create target analysis object so we never decompile an empty shell.
    bool analyzeTargetFunction(RzCore* core, ut64 va, ut64 nextBoundary, const char* preferredName) {
        if (!core || !core->analysis) return false;
        if (RzAnalysisFunction* old = rz_analysis_get_function_at(core->analysis, va)) {
            rz_analysis_function_delete(old);
        }
        if (nextBoundary > va) {
            rz_config_set_i(core->config, "analysis.from", va);
            rz_config_set_i(core->config, "analysis.to", nextBoundary);
            rz_config_set(core->config, "analysis.limits", "true");
        } else {
            rz_config_set(core->config, "analysis.limits", "false");
        }
        const bool added = rz_core_analysis_function_add(core, preferredName, va, false);
        if (!rz_analysis_get_function_at(core->analysis, va)) {
            char nm[64];
            if (preferredName && *preferredName) {
                rz_analysis_create_function(core->analysis, preferredName, va, RZ_ANALYSIS_FCN_TYPE_FCN);
            } else {
                snprintf(nm, sizeof(nm), "fcn.0x%llx", static_cast<unsigned long long>(va));
                rz_analysis_create_function(core->analysis, nm, va, RZ_ANALYSIS_FCN_TYPE_FCN);
            }
            rz_core_analysis_function_add(core, nullptr, va, false);
        }
        rz_config_set(core->config, "analysis.limits", "false");
        return added || rz_analysis_get_function_at(core->analysis, va) != nullptr;
    }

    // Frame setup often has SUB SP then STP FP,LR a few instructions later.
    // Those mid-prologue STPs must NOT become "next function" anchors.
    void filterFalsePrologueAnchors(std::vector<ut64>& anchors, const std::vector<SymbolSpan>& spans, ut64 targetVa) {
        if (anchors.empty()) return;
        std::sort(anchors.begin(), anchors.end());
        anchors.erase(std::unique(anchors.begin(), anchors.end()), anchors.end());
        std::vector<ut64> kept;
        kept.reserve(anchors.size());
        for (ut64 a : anchors) {
            if (a == targetVa) {
                kept.push_back(a);
                continue;
            }
            bool insideKnownSymbol = false;
            for (const auto& sp : spans) {
                if (!sp.addr) continue;
                // Always keep true symbol starts.
                if (a == sp.addr) {
                    insideKnownSymbol = false;
                    break;
                }
                // Drop anchors that fall inside a known function body.
                if (sp.size > 0 && a > sp.addr && a < sp.addr + sp.size) {
                    insideKnownSymbol = true;
                    break;
                }
                // Drop near-entry frame setup (common: +4/+8 after SUB SP / PAC).
                if (a > sp.addr && a < sp.addr + 0x20) {
                    insideKnownSymbol = true;
                    break;
                }
            }
            if (insideKnownSymbol) continue;
            // Also drop anchors that are only a few instructions after another kept/symbol start.
            bool nearPrevStart = false;
            for (ut64 k : kept) {
                if (a > k && a < k + 0x20) {
                    nearPrevStart = true;
                    break;
                }
            }
            if (nearPrevStart) continue;
            kept.push_back(a);
        }
        anchors.swap(kept);
    }

    ut64 nextSymbolAfter(const std::vector<SymbolSpan>& spans, ut64 va) {
        ut64 next = 0;
        for (const auto& sp : spans) {
            if (sp.addr > va && (next == 0 || sp.addr < next)) next = sp.addr;
        }
        return next;
    }

    bool markAarch64ExitSyscallNoreturn(RzCore* core, ut64 addr, ut64 limit, ut64* svcAddr) {
        if (!core || !core->io || !core->analysis || !addr) return false;
        ut64 end = limit > addr ? limit : addr + 0x40;
        if (end > addr + 0x80) end = addr + 0x80;
        if (end <= addr || end - addr < 8) return false;
        std::vector<uint8_t> code(static_cast<size_t>(end - addr));
        if (!rz_io_read_at(core->io, addr, code.data(), code.size())) return false;
        const int read = static_cast<int>(code.size());
        int syscallNumber = -1;
        bool hasSvc = false;
        ut64 foundSvc = 0;
        for (int off = 0; off + 4 <= read; off += 4) {
            const uint8_t* p = code.data() + off;
            const uint32_t insn = static_cast<uint32_t>(p[0]) |
                (static_cast<uint32_t>(p[1]) << 8) |
                (static_cast<uint32_t>(p[2]) << 16) |
                (static_cast<uint32_t>(p[3]) << 24);
            if ((insn & 0x7f80001fu) == 0x52800008u) {
                syscallNumber = static_cast<int>((insn >> 5) & 0xffffu);
            }
            if ((insn & 0xffe0001fu) == 0xd4000001u) {
                hasSvc = true;
                foundSvc = addr + static_cast<ut64>(off);
                break;
            }
            if (insn == 0xd65f03c0u) return false;
        }
        if (!hasSvc || (syscallNumber != 93 && syscallNumber != 94)) return false;
        char generatedName[48];
        snprintf(generatedName, sizeof(generatedName), "fcn.0x%llx", static_cast<unsigned long long>(addr));
        rz_analysis_noreturn_add(core->analysis, generatedName, addr);
        RzAnalysisFunction* fcn = rz_analysis_get_function_at(core->analysis, addr);
        if (!fcn) {
            fcn = rz_analysis_create_function(core->analysis, generatedName, addr, RZ_ANALYSIS_FCN_TYPE_FCN);
        }
        if (fcn) {
            fcn->is_noreturn = true;
            rz_analysis_noreturn_add(core->analysis, fcn->name, addr);
        }
        RZ_NATIVE_LOG("noreturn syscall wrapper addr=0x%llx svc=0x%llx nr=%d function=%d",
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(foundSvc),
            syscallNumber,
            fcn ? 1 : 0);
        if (svcAddr) *svcAddr = foundSvc;
        return true;
    }

    bool isLikelyDecompilerError(const std::string& text) {
        if (text.empty()) return true;
        // Only treat short diagnostic replies as failures. Real pseudocode may contain
        // words like "not found" in strings/comments and must not be discarded.
        if (text.size() > 256) return false;
        if (text.find("unknown command") != std::string::npos) return true;
        if (text.find("Cannot find function") != std::string::npos) return true;
        if (text.find("Cannot find") != std::string::npos) return true;
        if (text.find("not found") != std::string::npos) return true;
        if (text.find("No function") != std::string::npos) return true;
        if (text.find("pdg is not") != std::string::npos) return true;
        return false;
    }

    bool enforceFunctionBoundary(RzCore* core, ut64 funcVa, ut64 nextBoundary, ut64* rawSizeOut, ut64* fcnSizeOut, ut64* fcnEndOut, const char** fcnNameOut, bool* resizedOut) {
        if (rawSizeOut) *rawSizeOut = 0;
        if (fcnSizeOut) *fcnSizeOut = 0;
        if (fcnEndOut) *fcnEndOut = 0;
        if (fcnNameOut) *fcnNameOut = "";
        if (resizedOut) *resizedOut = false;
        RzAnalysisFunction* fcn = rz_analysis_get_function_at(core->analysis, funcVa);
        if (!fcn) return false;
        const ut64 rawSize = rz_analysis_function_size_from_entry(fcn);
        if (rawSizeOut) *rawSizeOut = rawSize;
        if (nextBoundary > fcn->addr && rawSize > (nextBoundary - fcn->addr)) {
            rz_analysis_function_resize(fcn, static_cast<int>(nextBoundary - fcn->addr));
            if (resizedOut) *resizedOut = true;
        }
        if (RzList* all = rz_analysis_function_list(core->analysis)) {
            RzListIter* iter = nullptr;
            void* elem = nullptr;
            rz_list_foreach(all, iter, elem) {
                auto* other = static_cast<RzAnalysisFunction*>(elem);
                if (!other || other == fcn || other->addr <= fcn->addr) continue;
                const ut64 curSize = rz_analysis_function_size_from_entry(fcn);
                if (curSize > (other->addr - fcn->addr)) {
                    rz_analysis_function_resize(fcn, static_cast<int>(other->addr - fcn->addr));
                    if (resizedOut) *resizedOut = true;
                }
            }
        }
        // Drop any basic block that starts at/after nextBoundary if resize left stale ranges.
        // bbs is RzPVector in Rizin 0.8, not RzList.
        if (nextBoundary > fcn->addr && fcn->bbs) {
            std::vector<RzAnalysisBlock*> toDel;
            void** it = nullptr;
            rz_pvector_foreach(fcn->bbs, it) {
                auto* bb = static_cast<RzAnalysisBlock*>(*it);
                if (!bb) continue;
                if (bb->addr >= nextBoundary) {
                    toDel.push_back(bb);
                } else if (bb->addr < nextBoundary && bb->addr + bb->size > nextBoundary) {
                    bb->size = static_cast<int>(nextBoundary - bb->addr);
                    if (resizedOut) *resizedOut = true;
                }
            }
            for (RzAnalysisBlock* bb : toDel) {
                rz_analysis_function_remove_block(fcn, bb);
            }
        }
        const ut64 fcnSize = rz_analysis_function_size_from_entry(fcn);
        if (fcnSizeOut) *fcnSizeOut = fcnSize;
        if (fcnEndOut) *fcnEndOut = fcn->addr + fcnSize;
        if (fcnNameOut) *fcnNameOut = fcn->name ? fcn->name : "";
        rz_core_seek(core, fcn->addr, true);
        return true;
    }
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzConfigureGhidra(
        JNIEnv* env, jobject, jstring pluginDir, jstring sleighHome) {
    {
        std::lock_guard<std::mutex> lock(ghidraConfigMutex);
        ghidraPluginDir = jStr(env, pluginDir);
        ghidraSleighHome = jStr(env, sleighHome);
        if (!ghidraPluginDir.empty()) setenv("RZ_LIB_PLUGINS", ghidraPluginDir.c_str(), 1);
        RZ_NATIVE_LOG("configure ghidra pluginDir=%s sleighHome=%s", ghidraPluginDir.c_str(), ghidraSleighHome.c_str());
    }
    bool ok = !ghidraPluginDir.empty() && !ghidraSleighHome.empty();
    if (ok) {
        RzCore* core = rz_core_new();
        if (core) {
            applyGhidraConfig(core);
            char* help = rz_core_cmd_str(core, "pdg?");
            bool hasPdg = help && help[0] && std::string(help).find("unknown command") == std::string::npos;
            RZ_NATIVE_LOG("ghidra selftest pdg=%d help=%s", hasPdg ? 1 : 0, help ? help : "");
            if (help) free(help);
            rz_core_free(core);
            ok = hasPdg;
        } else {
            ok = false;
        }
    }
    return ok;
}

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzDisassemble(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch, jlong jaddr, jboolean jthumb, jint jlimit) {
    std::string arch = jStr(env, jarch);
    AsmProfile p = profileFor(arch);
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    RzAsm* a = rz_asm_new();
    if (!a) return env->NewStringUTF("");
    rz_asm_set_arch(a, p.arch, p.bits);
    if (arch == "arm32" && jthumb) rz_asm_set_bits(a, 16);
    rz_asm_set_pc(a, (ut64)jaddr);

    std::string out;
    ut64 off = 0;
    int count = 0;
    while (off < (ut64)buf.size() && count < jlimit) {
        rz_asm_set_pc(a, (ut64)jaddr + off);
        RzAsmCode* code = rz_asm_mdisassemble(a, buf.data() + off, (int)(buf.size() - off));
        if (!code || code->len <= 0) {
            if (code) rz_asm_code_free(code);
            char line[128];
            snprintf(line, sizeof(line), "0x%llx: %02X    .byte 0x%02X\n",
                     (unsigned long long)((ut64)jaddr + off), buf[off], buf[off]);
            out += line;
            off += (arch == "arm64" || arch == "mips") ? 4 : (arch == "arm32" ? (jthumb ? 2 : 4) : 1);
            count++;
            continue;
        }
        char addr[32];
        snprintf(addr, sizeof(addr), "0x%llx", (unsigned long long)((ut64)jaddr + off));
        std::string bytesHex = hexBytes(buf.data() + off, code->len);
        std::string line = std::string(addr) + ": " + bytesHex + "    " +
                           (code->assembly ? code->assembly : "") + "\n";
        out += line;
        off += code->len;
        count++;
        rz_asm_code_free(code);
    }
    rz_asm_free(a);
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jbyteArray JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzAssemble(
        JNIEnv* env, jobject, jstring jasm, jstring jarch, jlong jaddr, jboolean jthumb) {
    std::string asmText = jStr(env, jasm);
    std::string arch = jStr(env, jarch);
    AsmProfile p = profileFor(arch);
    RzAsm* a = rz_asm_new();
    if (!a) return env->NewByteArray(0);
    rz_asm_set_arch(a, p.arch, p.bits);
    if (arch == "arm32" && jthumb) rz_asm_set_bits(a, 16);
    rz_asm_set_pc(a, (ut64)jaddr);

    RzAsmCode* code = rz_asm_massemble(a, asmText.c_str());
    jbyteArray result = nullptr;
    if (code && code->bytes && code->len > 0) {
        result = env->NewByteArray(code->len);
        env->SetByteArrayRegion(result, 0, code->len, reinterpret_cast<jbyte*>(code->bytes));
    } else {
        result = env->NewByteArray(0);
    }
    if (code) rz_asm_code_free(code);
    rz_asm_free(a);
    return result;
}

// Seed AArch64 BL/B imm26 edges into the analysis xref graph so low-level axt
// and high-level xrefs share the same recovered call sites.
static void seedAarch64BranchXrefs(RzCore* core, ut64 targetVa) {
    if (!core || !core->io || !core->analysis || !targetVa) return;
    if (RzBinFile* bf = rz_bin_cur(core->bin)) {
        if (const RzPVector* sections = rz_bin_object_get_sections_all(bf->o)) {
            void** it = nullptr;
            rz_pvector_foreach(sections, it) {
                auto* sec = static_cast<RzBinSection*>(*it);
                if (!sec || !(sec->perm & RZ_PERM_X) || sec->vsize < 4) continue;
                const ut64 maxScan = 8ull * 1024ull * 1024ull;
                ut64 scanSize = sec->vsize;
                if (scanSize > maxScan) scanSize = maxScan;
                std::vector<uint8_t> buf(static_cast<size_t>(scanSize));
                const int n = rz_io_read_at(core->io, sec->vaddr, buf.data(), static_cast<int>(buf.size()));
                if (n < 4) continue;
                const size_t bytes = static_cast<size_t>(n) & ~size_t(3);
                for (size_t off = 0; off + 4 <= bytes; off += 4) {
                    const uint8_t* p = buf.data() + off;
                    const uint32_t insn = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
                    const bool isBl = (insn & 0xFC000000u) == 0x94000000u;
                    const bool isB = (insn & 0xFC000000u) == 0x14000000u;
                    if (!isBl && !isB) continue;
                    int64_t imm = static_cast<int64_t>(insn & 0x03FFFFFFu);
                    if (imm & 0x02000000) imm |= ~0x03FFFFFFLL;
                    const ut64 from = sec->vaddr + off;
                    const ut64 to = from + (static_cast<ut64>(imm) << 2);
                    if (to != targetVa) continue;
                    rz_analysis_xrefs_set(core->analysis, from, to, isBl ? RZ_ANALYSIS_XREF_TYPE_CALL : RZ_ANALYSIS_XREF_TYPE_CODE);
                }
            }
        }
    }
}

// Enhanced xrefs: direction "to" (incoming) or "from" (outgoing) or "both"
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzXrefs(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch, jlong atVa, jstring jdirection) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"xrefs\":[]}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string direction = jStr(env, jdirection);
    if (direction.empty()) direction = "to";

    std::string path = writeTempSo(buf.data(), buf.size(), "xref");
    if (path.empty()) return env->NewStringUTF("{\"xrefs\":[]}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"xrefs\":[]}"); }
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"xrefs\":[]}"); }
    rz_core_analysis_all(core);
    // Recover direct BL/B to this VA into Rizin graph so axt is not empty for PIC code.
    seedAarch64BranchXrefs(core, static_cast<ut64>(atVa));

    std::string out = "{\"xrefs\":[";
    bool first = true;

    if (direction == "to" || direction == "both") {
        RzList* xrefs = rz_analysis_xrefs_get_to(core->analysis, (ut64)atVa);
        if (xrefs) {
            RzListIter* it;
            void* elem;
            rz_list_foreach(xrefs, it, elem) {
                RzAnalysisXRef* x = (RzAnalysisXRef*)elem;
                if (!first) out += ",";
                first = false;
                char b[220];
                snprintf(b, sizeof(b),
                    "{\"from\":%llu,\"to\":%llu,\"type\":\"%s\",\"sourceType\":\"direct\",\"direction\":\"incoming\"}",
                    (unsigned long long)x->from, (unsigned long long)x->to, xrefTypeStr(x->type));
                out += b;
            }
            rz_list_free(xrefs);
        }
    }

    if (direction == "from" || direction == "both") {
        RzList* xrefs = rz_analysis_xrefs_get_from(core->analysis, (ut64)atVa);
        if (xrefs) {
            RzListIter* it;
            void* elem;
            rz_list_foreach(xrefs, it, elem) {
                RzAnalysisXRef* x = (RzAnalysisXRef*)elem;
                if (!first) out += ",";
                first = false;
                char b[220];
                snprintf(b, sizeof(b),
                    "{\"from\":%llu,\"to\":%llu,\"type\":\"%s\",\"sourceType\":\"direct\",\"direction\":\"outgoing\"}",
                    (unsigned long long)x->from, (unsigned long long)x->to, xrefTypeStr(x->type));
                out += b;
            }
            rz_list_free(xrefs);
        }
    }

    out += "]}";
    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// Load SO + run auto-analysis, return stats
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzAnalyze(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "analyze");
    if (path.empty()) return env->NewStringUTF("{\"error\":\"tempfile\"}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"core\"}"); }
    applyGhidraConfig(core);
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"open\"}"); }
    rz_core_analysis_all(core);

    RzList* funcs = rz_analysis_function_list(core->analysis);
    int funcCount = funcs ? rz_list_length(funcs) : 0;
    rz_list_free(funcs);

    char b[256];
    snprintf(b, sizeof(b), "{\"ok\":true,\"functions\":%d,\"size\":%zu}", funcCount, buf.size());
    std::string out(b);

    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// List all discovered functions with properties
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzFunctions(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("[]");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "funcs");
    if (path.empty()) return env->NewStringUTF("[]");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("[]"); }
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("[]"); }
    rz_core_analysis_all(core);

    RzList* funcs = rz_analysis_function_list(core->analysis);
    std::string out = "[";
    if (funcs) {
        bool first = true;
        RzListIter* it;
        void* elem;
        rz_list_foreach(funcs, it, elem) {
            RzAnalysisFunction* fcn = (RzAnalysisFunction*)elem;
            if (!first) out += ",";
            first = false;
            ut64 fsize = rz_analysis_function_size_from_entry(fcn);
            ut32 complexity = rz_analysis_function_complexity(fcn);
            ut32 loops = rz_analysis_function_loops(fcn);
            char b[512];
            const char* name = fcn->name ? fcn->name : "";
            snprintf(b, sizeof(b),
                     "{\"name\":\"%s\",\"addr\":%llu,\"size\":%llu,\"ninstr\":%d,\"complexity\":%u,\"loops\":%u,\"isPure\":%s}",
                     escJson(name).c_str(),
                     (unsigned long long)fcn->addr,
                     (unsigned long long)fsize,
                     fcn->ninstr,
                     complexity, loops,
                     fcn->is_pure ? "true" : "false");
            out += b;
        }
    }
    out += "]";

    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// Control flow graph for a function at the given address
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzCfg(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch, jlong funcVa) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "cfg");
    if (path.empty()) return env->NewStringUTF("{\"error\":\"tempfile\"}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"core\"}"); }
    applyGhidraConfig(core);
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"open\"}"); }
    rz_core_analysis_all(core);

    RzAnalysisFunction* fcn = rz_analysis_get_function_at(core->analysis, (ut64)funcVa);
    if (!fcn) {
        // Try analyzing the function first
        rz_core_analysis_fcn(core, (ut64)funcVa, (ut64)funcVa, RZ_ANALYSIS_XREF_TYPE_CODE, 1);
        fcn = rz_analysis_get_function_at(core->analysis, (ut64)funcVa);
    }
    if (!fcn) {
        cleanupCore(core, path);
        return env->NewStringUTF("{\"error\":\"function_not_found\"}");
    }

    std::string out = "{\"function\":\"";
    out += escJson(fcn->name ? fcn->name : "");
    out += "\",\"addr\":";
    char nb[32];
    snprintf(nb, sizeof(nb), "%llu", (unsigned long long)fcn->addr);
    out += nb;
    out += ",\"blocks\":[";

    // Iterate basic blocks of the function (bbs is RzPVector, not RzList)
    void **it;
    bool first = true;
    rz_pvector_foreach(fcn->bbs, it) {
        RzAnalysisBlock* bb = (RzAnalysisBlock*)*it;
        if (!first) out += ",";
        first = false;
        char b[256];
        snprintf(b, sizeof(b),
                 "{\"addr\":%llu,\"size\":%llu,\"ninstr\":%d,\"jump\":%llu,\"fail\":%llu}",
                 (unsigned long long)bb->addr,
                 (unsigned long long)bb->size,
                 bb->ninstr,
                 (unsigned long long)bb->jump,
                 (unsigned long long)bb->fail);
        out += b;
    }

    out += "],\"edges\":[";
    // Edges: jump + fail targets
    first = true;
    rz_pvector_foreach(fcn->bbs, it) {
        RzAnalysisBlock* bb = (RzAnalysisBlock*)*it;
        if (bb->jump != UT64_MAX) {
            if (!first) out += ",";
            first = false;
            char b[128];
            snprintf(b, sizeof(b), "{\"from\":%llu,\"to\":%llu,\"type\":\"jump\"}",
                     (unsigned long long)bb->addr, (unsigned long long)bb->jump);
            out += b;
        }
        if (bb->fail != UT64_MAX) {
            if (!first) out += ",";
            first = false;
            char b[128];
            snprintf(b, sizeof(b), "{\"from\":%llu,\"to\":%llu,\"type\":\"fail\"}",
                     (unsigned long long)bb->addr, (unsigned long long)bb->fail);
            out += b;
        }
    }
    out += "]}";

    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// Hex pattern search with Rizin byte pattern syntax. MCP-friendly spaced hex is normalized before parsing.
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzSearchBytes(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch, jstring jpattern, jlong fromVa, jlong toVa) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"hits\":[]}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));
    std::string pattern = jStr(env, jpattern);
    std::string normalizedPattern = normalizeBytePattern(pattern);

    std::string path = writeTempSo(buf.data(), buf.size(), "search");
    if (path.empty()) return env->NewStringUTF("{\"hits\":[]}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"hits\":[]}");
    }
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"hits\":[]}"); }

    RzSearchOpt* opts = rz_search_opt_new();

    RzSearchBytesPattern* bp = rz_search_parse_byte_pattern(normalizedPattern.c_str(), nullptr);
    if (!bp) {
        rz_search_opt_free(opts);
        cleanupCore(core, path);
        std::string out = "{\"hits\":[],\"error\":\"bad_pattern\",\"normalizedPattern\":\"" + escJson(normalizedPattern) + "\"}";
        return env->NewStringUTF(out.c_str());
    }

    RzList* hits = rz_core_search_bytes(core, opts, bp);
    std::string out = "{\"patternSyntax\":\"rizin-byte-pattern\",\"normalizedPattern\":\"" + escJson(normalizedPattern) + "\",\"hits\":[";
    if (hits) {
        bool first = true;
        RzListIter* it;
        void* elem;
        rz_list_foreach(hits, it, elem) {
            RzSearchHit* hit = (RzSearchHit*)elem;
            if (!first) out += ",";
            first = false;
            char b[128];
            snprintf(b, sizeof(b), "{\"addr\":%llu,\"size\":%zu}",
                     (unsigned long long)hit->address, hit->size);
            out += b;
        }
        rz_list_free(hits);
    }
    out += "]}";

    rz_search_opt_free(opts);
    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// Scan for cryptographic material (AES-128/192/256, RSA, ECC, X509)
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzScanCrypto(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"hits\":[]}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "crypto");
    if (path.empty()) return env->NewStringUTF("{\"hits\":[]}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"hits\":[]}"); }
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"hits\":[]}"); }

    std::string out = "{\"hits\":[";
    bool first = true;

    // Scan for each crypto type
    RzSearchCollectionCryptographicType types[] = {
        RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_128,
        RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_192,
        RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_256,
    };
    const char* typeNames[] = { "AES-128", "AES-192", "AES-256" };

    for (int t = 0; t < 3; t++) {
        RzSearchOpt* opts = rz_search_opt_new();
        RzList* hits = rz_core_search_cryptographic_material(core, opts, types[t]);
        if (hits) {
            RzListIter* it;
            void* elem;
            rz_list_foreach(hits, it, elem) {
                RzSearchHit* hit = (RzSearchHit*)elem;
                if (!first) out += ",";
                first = false;
                char b[192];
                snprintf(b, sizeof(b), "{\"addr\":%llu,\"size\":%zu,\"type\":\"%s\"}",
                         (unsigned long long)hit->address, hit->size, typeNames[t]);
                out += b;
            }
            rz_list_free(hits);
        }
        rz_search_opt_free(opts);
    }

    // Entropy scan — find high-entropy regions (packed/encrypted sections)
    {
        RzSearchOpt* opts = rz_search_opt_new();
        RzList* hits = rz_core_search_entropy(core, opts, false, 7.0, 8.0, 256);
        if (hits) {
            RzListIter* it;
            void* elem;
            rz_list_foreach(hits, it, elem) {
                RzSearchHit* hit = (RzSearchHit*)elem;
                if (!first) out += ",";
                first = false;
                char b[192];
                snprintf(b, sizeof(b), "{\"addr\":%llu,\"size\":%zu,\"type\":\"high_entropy\"}",
                         (unsigned long long)hit->address, hit->size);
                out += b;
            }
            rz_list_free(hits);
        }
        rz_search_opt_free(opts);
    }

    out += "]}";
    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// ESIL emulation: step through instructions and return register snapshots
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzEsilStep(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring jarch, jlong startVa, jint stepCount) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "esil");
    if (path.empty()) return env->NewStringUTF("{\"error\":\"tempfile\"}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"core\"}"); }
    applyGhidraConfig(core);
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"open\"}"); }
    rz_core_analysis_all(core);

    rz_core_seek(core, (ut64)startVa, true);
    rz_core_cmd0(core, "aei");
    rz_core_cmd0(core, "aeim");
    rz_core_reg_set_by_role_or_name(core, "PC", (ut64)startVa);

    std::string out = "{\"steps\":[";
    bool first = true;

    for (int i = 0; i < stepCount; i++) {
        ut64 prevAddr = 0;
        int ret = rz_core_esil_step(core, UT64_MAX, nullptr, &prevAddr, false);
        if (!ret) break;

        ut64 pc = rz_core_reg_getv_by_role_or_name(core, "PC");
        ut64 sp = rz_core_reg_getv_by_role_or_name(core, "SP");

        if (!first) out += ",";
        first = false;
        char b[256];
        snprintf(b, sizeof(b), "{\"step\":%d,\"pc\":%llu,\"sp\":%llu}",
                 i, (unsigned long long)pc, (unsigned long long)sp);
        out += b;

        if (pc == 0 || pc == UT64_MAX) break;
    }

    // Final register dump
    out += "],\"registers\":{";
    ut64 finalPc = rz_core_reg_getv_by_role_or_name(core, "PC");
    ut64 finalSp = rz_core_reg_getv_by_role_or_name(core, "SP");
    char regBuf[256];
    snprintf(regBuf, sizeof(regBuf), "\"pc\":%llu,\"sp\":%llu",
             (unsigned long long)finalPc, (unsigned long long)finalSp);
    out += regBuf;
    out += "}}";

    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

// Byte-level diff between two buffers + similarity ratio
JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzDiff(
        JNIEnv* env, jobject, jbyteArray jbytesA, jbyteArray jbytesB) {
    jsize lenA = env->GetArrayLength(jbytesA);
    jsize lenB = env->GetArrayLength(jbytesB);
    if (lenA <= 0 || lenB <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> bufA(lenA), bufB(lenB);
    env->GetByteArrayRegion(jbytesA, 0, lenA, reinterpret_cast<jbyte*>(bufA.data()));
    env->GetByteArrayRegion(jbytesB, 0, lenB, reinterpret_cast<jbyte*>(bufB.data()));

    RzDiff* diff = rz_diff_bytes_new(bufA.data(), (ut32)bufA.size(),
                                      bufB.data(), (ut32)bufB.size(), nullptr);
    if (!diff) return env->NewStringUTF("{\"error\":\"diff\"}");

    double ratio = 0.0;
    rz_diff_ratio(diff, &ratio);

    RzList* ops = rz_diff_opcodes_new(diff);
    std::string out = "{\"similarity\":";
    char rb[32];
    snprintf(rb, sizeof(rb), "%.4f", ratio);
    out += rb;
    out += ",\"ops\":[";
    if (ops) {
        bool first = true;
        RzListIter* it;
        void* elem;
        rz_list_foreach(ops, it, elem) {
            RzDiffOp* op = (RzDiffOp*)elem;
            if (!first) out += ",";
            first = false;
            const char* opStr = "EQUAL";
            if (op->type == RZ_DIFF_OP_DELETE) opStr = "DELETE";
            else if (op->type == RZ_DIFF_OP_INSERT) opStr = "INSERT";
            else if (op->type == RZ_DIFF_OP_REPLACE) opStr = "REPLACE";
            char b[128];
            snprintf(b, sizeof(b), "{\"type\":\"%s\",\"aBeg\":%d,\"aEnd\":%d,\"bBeg\":%d,\"bEnd\":%d}",
                     opStr, op->a_beg, op->a_end, op->b_beg, op->b_end);
            out += b;
        }
        rz_list_free(ops);
    }
    out += "]}";

    rz_diff_free(diff);
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzCommand(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring, jstring jcmd, jboolean unsafe) {
    std::string cmd = jStr(env, jcmd);
    if (cmd.empty()) return env->NewStringUTF("{\"error\":\"empty_command\"}");
    const char* blocked[] = { "!", "!!", "o ", "oo", "w", "wx", "wa", "wc", "rm", "mv", "cp", "cat ", "ls " };
    if (!unsafe) {
        for (const char* b : blocked) {
            if (cmd.rfind(b, 0) == 0) return env->NewStringUTF("{\"error\":\"unsafe_required\",\"message\":\"set unsafe=true for mutating, file, shell, debugger, or external commands\"}");
        }
    }
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "cmd");
    if (path.empty()) return env->NewStringUTF("{\"error\":\"tempfile\"}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"core\"}"); }
    applyGhidraConfig(core);
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, unsafe ? RZ_PERM_RWX : RZ_PERM_RX, unsafe);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"open\"}"); }
    rz_core_analysis_all(core);
    char* result = rz_core_cmd_str(core, cmd.c_str());
    if (unsafe) rz_core_cmd0(core, "wc");
    std::string out = "{\"command\":\"" + escJson(cmd) + "\",\"text\":\"" + escJson(result ? result : "") + "\"";
    rz_core_free(core);
    core = nullptr;
    if (unsafe) {
        std::vector<uint8_t> after(buf.size());
        FILE* file = fopen(path.c_str(), "rb");
        const size_t read = file ? fread(after.data(), 1, after.size(), file) : 0;
        if (file) fclose(file);
        out += ",\"patches\":[";
        bool first = true;
        size_t i = 0;
        while (i < read) {
            if (after[i] == buf[i]) { ++i; continue; }
            const size_t start = i;
            while (i < read && after[i] != buf[i]) ++i;
            if (!first) out += ",";
            first = false;
            out += "{\"offset\":" + std::to_string(start) + ",\"hex\":\"" + hexBytes(after.data() + start, i - start) + "\"}";
        }
        out += "],\"mutated\":";
        out += first ? "false" : "true";
    }
    out += "}";
    if (result) free(result);
    unlink(path.c_str());
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_soreverse_mcp_nativecore_RizinNativeEngine_rzDecompile(
        JNIEnv* env, jobject, jbyteArray jbytes, jstring, jlong funcVa) {
    jsize len = env->GetArrayLength(jbytes);
    if (len <= 0) return env->NewStringUTF("{\"error\":\"empty\"}");
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jbytes, 0, len, reinterpret_cast<jbyte*>(buf.data()));

    std::string path = writeTempSo(buf.data(), buf.size(), "decompile");
    if (path.empty()) return env->NewStringUTF("{\"error\":\"tempfile\"}");
    RzCore* core = rz_core_new();
    if (!core) { unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"core\"}"); }
    applyGhidraConfig(core);
    bool ok = rz_core_file_open_load(core, path.c_str(), 0, RZ_PERM_RX, false);
    if (!ok) { rz_core_free(core); unlink(path.c_str()); return env->NewStringUTF("{\"error\":\"open\"}"); }

    // Root cause of adjacent-function bleed:
    // recursive / global recovery can merge neighboring routines into one
    // RzAnalysisFunction; Ghidra pdg then decompiles that merged object.
    // Never hard-clip pseudocode text. Repair the analysis object BEFORE pdg.
    rz_config_set(core->config, "analysis.vars", "true");
    rz_config_set(core->config, "analysis.vars.stackname", "true");
    rz_config_set(core->config, "analysis.hasnext", "false");
    rz_config_set(core->config, "analysis.jmp.after", "false");
    rz_config_set(core->config, "analysis.nopskip", "false");
    rz_config_set(core->config, "analysis.pushret", "false");
    rz_config_set(core->config, "analysis.jmp.ref", "true");
    rz_config_set(core->config, "analysis.bb.maxsize", "0x2000");
    rz_config_set_i(core->config, "analysis.depth", 64);

    const ut64 va = static_cast<ut64>(funcVa);
    std::vector<ut64> anchors;
    std::vector<SymbolSpan> symbolSpans;
    seedSymbolAnchors(core, va, anchors, symbolSpans);

    // For stripped SO (few symbols), recover additional starts from AArch64
    // prologues and BL targets in a local window around the requested VA.
    ut64 scanFrom = va > 0x4000 ? va - 0x4000 : 0;
    ut64 scanTo = va + 0x10000;
    if (RzBinFile* bf = rz_bin_cur(core->bin)) {
        if (bf->o) {
            // Prefer executable section/segment covering VA when available.
            // Keep a bounded local window so stripped large .text does not explode memory.
            if (const RzPVector* sections = rz_bin_object_get_sections_all(bf->o)) {
                void** it = nullptr;
                rz_pvector_foreach(sections, it) {
                    auto* sec = static_cast<RzBinSection*>(*it);
                    if (!sec || !(sec->perm & RZ_PERM_X) || sec->vsize == 0) continue;
                    if (va >= sec->vaddr && va < sec->vaddr + sec->vsize) {
                        const ut64 localFrom = va > 0x8000 ? va - 0x8000 : sec->vaddr;
                        const ut64 localTo = va + 0x10000;
                        scanFrom = localFrom > sec->vaddr ? localFrom : sec->vaddr;
                        scanTo = localTo < sec->vaddr + sec->vsize ? localTo : sec->vaddr + sec->vsize;
                        break;
                    }
                }
            }
        }
    }
    collectAarch64Anchors(core, scanFrom, scanTo, anchors);
    // Critical: mid-prologue STP after SUB SP must not become nextBoundary.
    filterFalsePrologueAnchors(anchors, symbolSpans, va);

    std::vector<std::pair<ut64, ut64>> inferredNoreturn;
    std::vector<ut64> noreturnCandidates = anchors;
    for (const auto& sp : symbolSpans) noreturnCandidates.push_back(sp.addr);
    std::sort(noreturnCandidates.begin(), noreturnCandidates.end());
    noreturnCandidates.erase(std::unique(noreturnCandidates.begin(), noreturnCandidates.end()), noreturnCandidates.end());
    for (size_t i = 0; i < noreturnCandidates.size(); ++i) {
        const ut64 candidate = noreturnCandidates[i];
        if (candidate < scanFrom || candidate >= scanTo) continue;
        ut64 candidateEnd = (i + 1 < noreturnCandidates.size()) ? noreturnCandidates[i + 1] : candidate + 0x40;
        ut64 svc = 0;
        if (markAarch64ExitSyscallNoreturn(core, candidate, candidateEnd, &svc)) {
            inferredNoreturn.emplace_back(candidate, svc);
        }
    }

    // Prefer next exported/local symbol as hard boundary; fall back to prologue/BL anchors.
    // For last-export functions (no nearby next symbol), use known dynsym size as soft end.
    const ut64 selfSize = selfSymbolSize(symbolSpans, va);
    ut64 nextBoundary = nextSymbolAfter(symbolSpans, va);
    const ut64 nextAnchor = nextAnchorAfter(anchors, va);
    if (nextBoundary == 0) {
        nextBoundary = nextAnchor;
    } else if (nextAnchor > va && nextAnchor < nextBoundary) {
        // Only accept a tighter non-symbol anchor when it is not inside the target's
        // own known symbol size (when size is present).
        if (selfSize == 0 || nextAnchor >= va + selfSize) {
            nextBoundary = nextAnchor;
        }
    }
    if (nextBoundary == 0 && selfSize > 0) {
        nextBoundary = va + selfSize;
    }

    if (nextBoundary > va && nextBoundary - va <= 0x20000) {
        std::vector<uint8_t> targetCode(static_cast<size_t>(nextBoundary - va));
        const int targetRead = rz_io_read_at(core->io, va, targetCode.data(), targetCode.size())
            ? static_cast<int>(targetCode.size()) : 0;
        for (int off = 0; off + 4 <= targetRead; off += 4) {
            const uint8_t* p = targetCode.data() + off;
            const uint32_t insn = static_cast<uint32_t>(p[0]) |
                (static_cast<uint32_t>(p[1]) << 8) |
                (static_cast<uint32_t>(p[2]) << 16) |
                (static_cast<uint32_t>(p[3]) << 24);
            if ((insn & 0xfc000000u) != 0x94000000u) continue;
            int64_t imm26 = static_cast<int64_t>(insn & 0x03ffffffu);
            if (imm26 & 0x02000000) imm26 |= ~0x03ffffffLL;
            const ut64 callSite = va + static_cast<ut64>(off);
            const ut64 target = static_cast<ut64>(static_cast<int64_t>(callSite) + (imm26 << 2));
            ut64 svc = 0;
            if (!markAarch64ExitSyscallNoreturn(core, target, target + 0x40, &svc)) continue;
            bool duplicate = false;
            for (const auto& item : inferredNoreturn) {
                if (item.first == target) { duplicate = true; break; }
            }
            if (!duplicate) inferredNoreturn.emplace_back(target, svc);
        }
    }

    if (scanTo > scanFrom && scanTo - scanFrom <= 0x20000) {
        std::vector<uint8_t> scanCode(static_cast<size_t>(scanTo - scanFrom));
        const int scanRead = rz_io_read_at(core->io, scanFrom, scanCode.data(), scanCode.size())
            ? static_cast<int>(scanCode.size()) : 0;
        for (int off = 0; off + 8 <= scanRead; off += 4) {
            const uint8_t* p = scanCode.data() + off;
            const uint32_t first = static_cast<uint32_t>(p[0]) |
                (static_cast<uint32_t>(p[1]) << 8) |
                (static_cast<uint32_t>(p[2]) << 16) |
                (static_cast<uint32_t>(p[3]) << 24);
            if ((first & 0x7f80001fu) != 0x52800008u) continue;
            const int syscallNumber = static_cast<int>((first >> 5) & 0xffffu);
            if (syscallNumber != 93 && syscallNumber != 94) continue;
            for (int look = 4; look <= 16 && off + look + 4 <= scanRead; look += 4) {
                const uint8_t* q = scanCode.data() + off + look;
                const uint32_t insn = static_cast<uint32_t>(q[0]) |
                    (static_cast<uint32_t>(q[1]) << 8) |
                    (static_cast<uint32_t>(q[2]) << 16) |
                    (static_cast<uint32_t>(q[3]) << 24);
                if (insn == 0xd65f03c0u) break;
                if ((insn & 0xffe0001fu) != 0xd4000001u) continue;
                const ut64 candidate = scanFrom + static_cast<ut64>(off);
                ut64 svc = 0;
                if (markAarch64ExitSyscallNoreturn(core, candidate, candidate + look + 4, &svc)) {
                    bool duplicate = false;
                    for (const auto& item : inferredNoreturn) {
                        if (item.first == candidate) { duplicate = true; break; }
                    }
                    if (!duplicate) inferredNoreturn.emplace_back(candidate, svc);
                }
                break;
            }
        }
    }

    // Seed neighboring anchors as real analysis functions so recovery cannot own them.
    int seededNeighbors = 0;
    for (ut64 a : anchors) {
        if (a == va) continue;
        if (a + 0x8000 < va || a > va + 0x8000) continue;
        if (!rz_analysis_get_function_at(core->analysis, a)) {
            char nm[48];
            snprintf(nm, sizeof(nm), "anchor_0x%llx", static_cast<unsigned long long>(a));
            rz_analysis_create_function(core->analysis, nm, a, RZ_ANALYSIS_FCN_TYPE_FCN);
            seededNeighbors++;
        }
    }
    // Also ensure every known symbol start near VA exists as analysis function.
    std::string preferredName;
    for (const auto& sp : symbolSpans) {
        if (sp.addr == va) {
            preferredName = sp.name;
            continue;
        }
        if (sp.addr + 0x10000 < va || sp.addr > va + 0x10000) continue;
        if (!rz_analysis_get_function_at(core->analysis, sp.addr)) {
            rz_analysis_create_function(
                core->analysis,
                sp.name.empty() ? nullptr : sp.name.c_str(),
                sp.addr,
                RZ_ANALYSIS_FCN_TYPE_SYM);
            seededNeighbors++;
        }
    }

    // Non-recursive only. Do NOT call rz_core_analysis_all here: it re-merges
    // neighbors and undoes the boundary we are trying to protect.
    // Always delete+recreate the TARGET function; never decompile an empty shell.
    analyzeTargetFunction(core, va, nextBoundary, preferredName.empty() ? nullptr : preferredName.c_str());
    if (nextBoundary > va && !rz_analysis_get_function_at(core->analysis, nextBoundary)) {
        rz_core_analysis_function_add(core, nullptr, nextBoundary, false);
    }

    // If analysis still has no tight next boundary, fall back to linear ret/prologue scan.
    {
        ut64 hardEnd = nextBoundary ? nextBoundary : (va + (selfSize > 0 ? selfSize : 0x4000));
        if (hardEnd <= va) hardEnd = va + 0x4000;
        ut64 linear = findLinearReturnBoundary(core, va, hardEnd);
        if (linear > va && (nextBoundary == 0 || linear < nextBoundary)) {
            // Do not accept linear boundary inside known self symbol size.
            if (selfSize == 0 || linear >= va + selfSize) {
                nextBoundary = linear;
                if (!rz_analysis_get_function_at(core->analysis, nextBoundary)) {
                    char nm[48];
                    snprintf(nm, sizeof(nm), "linear_0x%llx", static_cast<unsigned long long>(nextBoundary));
                    rz_analysis_create_function(core->analysis, nm, nextBoundary, RZ_ANALYSIS_FCN_TYPE_FCN);
                }
                // Re-analyze target under the refined boundary.
                analyzeTargetFunction(core, va, nextBoundary, preferredName.empty() ? nullptr : preferredName.c_str());
            }
        }
    }

    ut64 fcnSize = 0;
    ut64 fcnEnd = 0;
    ut64 rawSize = 0;
    bool resized = false;
    const char* fcnName = "";
    if (!enforceFunctionBoundary(core, va, nextBoundary, &rawSize, &fcnSize, &fcnEnd, &fcnName, &resized)) {
        // Last resort: analyze without relying on previous shells.
        analyzeTargetFunction(core, va, nextBoundary ? nextBoundary : (selfSize ? va + selfSize : 0), preferredName.empty() ? nullptr : preferredName.c_str());
        enforceFunctionBoundary(core, va, nextBoundary, &rawSize, &fcnSize, &fcnEnd, &fcnName, &resized);
        if (!fcnSize) rz_core_seek(core, va, true);
    }

    // Never leave a tiny/empty bogus function when known dynsym size is larger
    // (classic failure: empty shell, or SUB SP then STP treated as nextBoundary -> size=4).
    if (selfSize > 0 && (fcnSize == 0 || (fcnSize < 16 && selfSize >= 16))) {
        ut64 recoverTo = nextBoundary ? nextBoundary : (va + selfSize);
        if (recoverTo < va + selfSize) recoverTo = va + selfSize;
        analyzeTargetFunction(core, va, recoverTo, preferredName.empty() ? nullptr : preferredName.c_str());
        enforceFunctionBoundary(core, va, nextBoundary ? nextBoundary : (va + selfSize), &rawSize, &fcnSize, &fcnEnd, &fcnName, &resized);
    }

    RZ_NATIVE_LOG("decompile prep va=0x%llx next=0x%llx raw=%llu size=%llu resized=%d anchors=%zu neighbors=%d",
        static_cast<unsigned long long>(va),
        static_cast<unsigned long long>(nextBoundary),
        static_cast<unsigned long long>(rawSize),
        static_cast<unsigned long long>(fcnSize),
        resized ? 1 : 0,
        anchors.size(),
        seededNeighbors);

    const char* commands[] = { "pdg", "pdd" };
    const char* selected = nullptr;
    char* result = nullptr;
    std::string lastDiag;
    for (const char* cmd : commands) {
        // Seek again immediately before decompile so pdg uses the repaired function.
        if (RzAnalysisFunction* fcn = rz_analysis_get_function_at(core->analysis, va)) {
            enforceFunctionBoundary(core, va, nextBoundary, nullptr, &fcnSize, &fcnEnd, &fcnName, &resized);
            rz_core_seek(core, fcn->addr, true);
        } else {
            rz_core_seek(core, va, true);
        }
        result = rz_core_cmd_str(core, cmd);
        std::string text = stripAnsi(result ? result : "");
        RZ_NATIVE_LOG("ghidra command=%s len=%zu resized=%d size=%llu next=0x%llx output=%.200s",
            cmd, text.size(), resized ? 1 : 0,
            static_cast<unsigned long long>(fcnSize),
            static_cast<unsigned long long>(nextBoundary),
            text.c_str());
        if (result && result[0] != '\0' && !isLikelyDecompilerError(text)) {
            selected = cmd;
            break;
        }
        if (!text.empty()) lastDiag = text.substr(0, 240);
        if (result) { free(result); result = nullptr; }
    }

    std::string out;
    if (selected && result) {
        char addr[32];
        snprintf(addr, sizeof(addr), "0x%llx", static_cast<unsigned long long>(funcVa));
        out = "{\"ok\":true,\"backend\":\"rizin-ghidra\",\"command\":\"";
        out += selected;
        out += "\",\"engine\":\"";
        out += (selected && !strcmp(selected, "pdg")) ? "ghidra" : "pdd";
        out += "\",\"addr\":\"";
        out += addr;
        out += "\",\"functionName\":\"";
        out += escJson(fcnName);
        out += "\",\"functionSize\":";
        out += std::to_string(fcnSize);
        out += ",\"functionEnd\":";
        out += std::to_string(fcnEnd);
        out += ",\"rawFunctionSize\":";
        out += std::to_string(rawSize);
        out += ",\"nextBoundary\":";
        out += std::to_string(nextBoundary);
        out += ",\"resizedToBoundary\":";
        out += resized ? "true" : "false";
        out += ",\"anchorCount\":";
        out += std::to_string(anchors.size());
        out += ",\"seededNeighbors\":";
        out += std::to_string(seededNeighbors);
        out += ",\"inferredNoreturn\":[";
        for (size_t i = 0; i < inferredNoreturn.size(); ++i) {
            if (i) out += ",";
            out += "{\"addr\":\"0x";
            char nrAddr[32];
            snprintf(nrAddr, sizeof(nrAddr), "%llx", static_cast<unsigned long long>(inferredNoreturn[i].first));
            out += nrAddr;
            out += "\",\"evidence\":\"aarch64 exit/exit_group syscall wrapper\",\"svcAddr\":\"0x";
            char svcAddr[32];
            snprintf(svcAddr, sizeof(svcAddr), "%llx", static_cast<unsigned long long>(inferredNoreturn[i].second));
            out += svcAddr;
            out += "\"}";
        }
        out += "]";
        out += ",\"boundaryStrategy\":\"symbol+filtered-prologue+bl-anchors+nonrecursive-af+limit-reanalyze+resize-before-pdg\"";
        out += ",\"pseudocode\":\"";
        out += escJson(stripAnsi(result));
        out += "\"}";
    } else {
        out = "{\"ok\":false,\"error\":\"DECOMPILER_FAILED\",\"backend\":\"rizin-ghidra\",\"message\":\"decompiler produced no usable output for this function after analysis-boundary repair\",\"addr\":\"";
        char addr[32];
        snprintf(addr, sizeof(addr), "0x%llx", static_cast<unsigned long long>(funcVa));
        out += addr;
        out += "\",\"functionSize\":";
        out += std::to_string(fcnSize);
        out += ",\"nextBoundary\":";
        out += std::to_string(nextBoundary);
        out += ",\"anchorCount\":";
        out += std::to_string(anchors.size());
        out += ",\"seededNeighbors\":";
        out += std::to_string(seededNeighbors);
        out += ",\"diagnostic\":\"";
        out += escJson(lastDiag);
        out += "\"}";
    }
    if (result) free(result);
    cleanupCore(core, path);
    return env->NewStringUTF(out.c_str());
}

}  // extern "C"
