#include "pch.h"
#include "CodeAnalyzer.h"
#include "DartApp.h"
#include <cerrno>
#include <exception>
#include <iomanip>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {
bool write_all(int fd, const std::string& value) {
    const char* data = value.data();
    size_t remaining = value.size();
    while (remaining > 0) {
        const ssize_t written = write(fd, data, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        data += written;
        remaining -= static_cast<size_t>(written);
    }
    return true;
}

std::string json_string(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
                else out << static_cast<char>(ch);
        }
    }
    out << '"';
    return out.str();
}

std::string hex_address(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool cancelled(volatile int* value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE) != 0;
}

std::string normalize(DartApp& app, volatile int* cancellation) {
    std::ostringstream libraries;
    std::ostringstream classes;
    std::ostringstream functions;
    size_t library_count = 0;
    size_t class_count = 0;
    size_t function_count = 0;
    bool first_library = true;
    bool first_class = true;
    bool first_function = true;
    for (DartLibrary* library : app.Libraries()) {
        if (cancelled(cancellation)) return {};
        if (library == nullptr) continue;
        const std::string library_id = "library-" + std::to_string(library->id);
        if (!first_library) libraries << ',';
        first_library = false;
        libraries << "{\"id\":" << json_string(library_id) << ",\"kind\":\"library\",\"name\":" << json_string(library->Url()) << '}';
        ++library_count;
    }
    for (const DartClass* cls : app.Classes()) {
        if (cancelled(cancellation)) return {};
        if (cls == nullptr) continue;
        const std::string class_id = "class-" + std::to_string(cls->Id());
        const std::string library_id = "library-" + std::to_string(cls->Library().id);
        if (!first_class) classes << ',';
        first_class = false;
        classes << "{\"id\":" << json_string(class_id) << ",\"kind\":\"class\",\"name\":" << json_string(cls->FullName()) << ",\"libraryId\":" << json_string(library_id) << ",\"size\":" << cls->Size() << '}';
        ++class_count;
        for (DartFunction* function : const_cast<DartClass*>(cls)->Functions()) {
            if (cancelled(cancellation)) return {};
            if (function == nullptr) continue;
            if (!first_function) functions << ',';
            first_function = false;
            functions << "{\"id\":" << json_string("function-" + hex_address(function->Address())) << ",\"kind\":\"function\",\"name\":" << json_string(function->FullName()) << ",\"libraryId\":" << json_string(library_id) << ",\"classId\":" << json_string(class_id) << ",\"address\":" << json_string(hex_address(function->Address())) << ",\"size\":" << function->Size() << '}';
            ++function_count;
        }
    }
    std::ostringstream result;
    result << "{\"schemaVersion\":1,\"jobId\":\"blutter-native\",\"status\":\"succeeded\",\"backend\":\"embedded\",\"createdAt\":\"1970-01-01T00:00:00Z\",\"completedAt\":null,\"input\":{\"displayName\":\"libapp.so\",\"abi\":\"arm64-v8a\",\"libapp\":{\"name\":\"libapp.so\",\"size\":0,\"sha256\":\"" << std::string(64, '0') << "\"},\"libflutter\":{\"name\":\"libflutter.so\",\"size\":0,\"sha256\":\"" << std::string(64, '0') << "\"}},\"flutter\":{\"dartVersion\":null,\"engineRevision\":null,\"compressedPointers\":null,\"nullSafety\":null,\"confidence\":0},\"runner\":{\"runnerId\":\"" RUNNER_ID "\",\"source\":\"embedded\",\"upstreamCommit\":\"" BLUTTER_COMMIT "\",\"sha256\":null},\"summary\":{\"libraries\":" << library_count << ",\"classes\":" << class_count << ",\"functions\":" << function_count << ",\"objects\":0,\"artifacts\":0,\"warnings\":0},\"libraries\":{\"items\":[" << libraries.str() << "],\"total\":" << library_count << ",\"hasMore\":false,\"nextCursor\":null},\"classes\":{\"items\":[" << classes.str() << "],\"total\":" << class_count << ",\"hasMore\":false,\"nextCursor\":null},\"functions\":{\"items\":[" << functions.str() << "],\"total\":" << function_count << ",\"hasMore\":false,\"nextCursor\":null},\"objects\":{\"items\":[],\"total\":0,\"hasMore\":false,\"nextCursor\":null},\"artifacts\":[],\"warnings\":[],\"provenance\":{\"protocolVersion\":1,\"normalizerVersion\":\"native-1\",\"cacheHit\":false,\"durationMillis\":0}}";
    return result.str();
}
}

extern "C" __attribute__((visibility("default"))) int blutter_run_fd(int libapp_fd, int, int result_fd, const char*, volatile int* cancellation) {
    if (libapp_fd < 0 || result_fd < 0 || cancellation == nullptr) return 2;
    try {
        const std::string path = "/proc/self/fd/" + std::to_string(libapp_fd);
        DartApp app(path.c_str());
        if (cancelled(cancellation)) return 3;
        app.EnterScope();
        app.LoadInfo();
        app.ExitScope();
        if (cancelled(cancellation)) return 3;
        app.EnterScope();
#ifndef NO_CODE_ANALYSIS
        CodeAnalyzer analyzer(app);
        analyzer.AnalyzeAll();
#endif
        const std::string output = normalize(app, cancellation);
        app.ExitScope();
        if (output.empty()) return 3;
        return write_all(result_fd, output) ? 0 : 5;
    } catch (const std::exception&) {
        return 6;
    } catch (...) {
        return 6;
    }
}
