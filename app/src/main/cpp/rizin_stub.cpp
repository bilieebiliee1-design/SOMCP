// rizin_stub.cpp — placeholder compiled for ABIs where Rizin static libs are
// not yet cross-compiled. Produces an empty librz_native.so so the APK builds
// and loads on every ABI; RizinNativeEngine.available() returns false and the
// Kotlin layer degrades disasm/asm to pseudo/NOP until the meson cross-compile
// is run for that ABI.
extern "C" {
    // Intentionally empty. The JNI symbols RizinNativeEngine declares as
    // `external` are simply absent; calls fall through to runCatching{} which
    // returns "" / ByteArray(0), and available() reports false.
}
