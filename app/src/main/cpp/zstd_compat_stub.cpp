extern "C" int ZSTD_splitBlock(...) {
    return 0;
}

extern "C" void ZSTD_trace_compress_begin(...) {
}

extern "C" void ZSTD_trace_compress_end(...) {
}

extern "C" void ZSTD_trace_decompress_begin(...) {
}

extern "C" void ZSTD_trace_decompress_end(...) {
}

extern "C" unsigned long long rz_debug_get_tls(...) {
    return 0;
}

extern "C" void *rz_debug_native_threads(...) {
    return nullptr;
}
