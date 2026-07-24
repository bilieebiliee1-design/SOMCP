#include <jni.h>
#include <dlfcn.h>
#include <cctype>
#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>

namespace {
using RunFn = int (*)(int, int, int, const char*, volatile int*);
std::mutex cancel_mutex;
std::unordered_map<long long, std::shared_ptr<int>> cancellations;

void throw_runtime(JNIEnv* env, const std::string& message) {
    jclass type = env->FindClass("java/lang/RuntimeException");
    if (type != nullptr) env->ThrowNew(type, message.c_str());
}

bool valid_library(const std::string& value) {
    if (value.empty() || value.size() > 128 || value.rfind("blutter_", 0) != 0) return false;
    for (char ch : value) if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') return false;
    return true;
}
}

extern "C" JNIEXPORT jint JNICALL
Java_com_soreverse_mcp_blutter_NativeBlutterBridge_nativeRun(JNIEnv* env, jobject, jstring library_name, jint libapp_fd, jint libflutter_fd, jint result_fd, jstring options_json, jlong token) {
    if (library_name == nullptr || options_json == nullptr || libapp_fd < 0 || libflutter_fd < 0 || result_fd < 0) {
        throw_runtime(env, "Invalid Blutter runner arguments");
        return -1;
    }
    const char* raw_library = env->GetStringUTFChars(library_name, nullptr);
    const char* raw_options = env->GetStringUTFChars(options_json, nullptr);
    if (raw_library == nullptr || raw_options == nullptr) return -1;
    std::string library(raw_library);
    env->ReleaseStringUTFChars(library_name, raw_library);
    if (!valid_library(library)) {
        env->ReleaseStringUTFChars(options_json, raw_options);
        throw_runtime(env, "Rejected Blutter runner library name");
        return -1;
    }
    std::string soname = "lib" + library + ".so";
    void* handle = dlopen(soname.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        env->ReleaseStringUTFChars(options_json, raw_options);
        const char* error = dlerror();
        throw_runtime(env, error == nullptr ? "Cannot load Blutter runner" : error);
        return -1;
    }
    auto run = reinterpret_cast<RunFn>(dlsym(handle, "blutter_run_fd"));
    if (run == nullptr) {
        env->ReleaseStringUTFChars(options_json, raw_options);
        dlclose(handle);
        throw_runtime(env, "Blutter runner does not export blutter_run_fd");
        return -1;
    }
    auto cancelled = std::make_shared<int>(0);
    {
        std::lock_guard<std::mutex> lock(cancel_mutex);
        cancellations[token] = cancelled;
    }
    int result = run(libapp_fd, libflutter_fd, result_fd, raw_options, cancelled.get());
    {
        std::lock_guard<std::mutex> lock(cancel_mutex);
        cancellations.erase(token);
    }
    env->ReleaseStringUTFChars(options_json, raw_options);
    dlclose(handle);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_soreverse_mcp_blutter_NativeBlutterBridge_nativeCancel(JNIEnv*, jobject, jlong token) {
    std::lock_guard<std::mutex> lock(cancel_mutex);
    auto found = cancellations.find(token);
    if (found != cancellations.end()) __atomic_store_n(found->second.get(), 1, __ATOMIC_RELEASE);
}
