cmake_minimum_required(VERSION 3.22)

# Rizin + LIEF + Unidbg toolchain — Capstone/Keystone fully removed.
#
# Native backends:
#  1. Rizin (librz): disasm/asm/analysis/xrefs. Cross-compiled by meson per ABI.
#  2. LIEF (libLIEF): ELF parsing + section header reconstruction (xAnSo).
#     Cross-compiled by CMake per ABI into a static archive.
# Both are linked into a single librz_native.so that Kotlin loads.

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY CACHE STRING "" FORCE)
project(rz_native_core LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Map Android ABI to subdirectory names.
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(RZ_ABI_DIR "arm64-v8a")
    set(LIEF_ABI_DIR "arm64-v8a")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(RZ_ABI_DIR "armeabi-v7a")
    set(LIEF_ABI_DIR "armeabi-v7a")
elseif(ANDROID_ABI STREQUAL "x86")
    set(RZ_ABI_DIR "x86")
    set(LIEF_ABI_DIR "x86")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(RZ_ABI_DIR "x86_64")
    set(LIEF_ABI_DIR "x86_64")
else()
    set(RZ_ABI_DIR "")
    set(LIEF_ABI_DIR "")
endif()

# --- Rizin build dir ---
set(RIZIN_BUILD_ROOT "" CACHE PATH "Root containing per-ABI Rizin meson build dirs")
if(NOT RIZIN_BUILD_ROOT)
    set(RIZIN_BUILD_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../rizin-build")
endif()
set(RIZIN_BUILD_DIR "${RIZIN_BUILD_ROOT}/${RZ_ABI_DIR}")
set(RIZIN_SHARED_SDK "${CMAKE_CURRENT_LIST_DIR}/../../../../rizin-sdk/${RZ_ABI_DIR}-wsl")

# --- LIEF build dir ---
set(LIEF_BUILD_ROOT "" CACHE PATH "Root containing per-ABI LIEF cmake build dirs")
if(NOT LIEF_BUILD_ROOT)
    set(LIEF_BUILD_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../third_party/lief-build")
endif()
set(LIEF_BUILD_DIR "${LIEF_BUILD_ROOT}/${LIEF_ABI_DIR}")
set(LIEF_LIB "${LIEF_BUILD_DIR}/lib/libLIEF.a")

# Check which backends are available for this ABI.
set(RIZIN_AVAILABLE FALSE)
set(LIEF_AVAILABLE FALSE)

if(EXISTS "${RIZIN_SHARED_SDK}/lib/librz_core.so")
    set(RIZIN_AVAILABLE TRUE)
elseif(EXISTS "${RIZIN_BUILD_DIR}/librz/util/librz_util.a")
    set(RIZIN_AVAILABLE TRUE)
endif()

if(EXISTS "${LIEF_LIB}")
    set(LIEF_AVAILABLE TRUE)
endif()

# Source files: always include rizin_core.cpp (or stub), plus lief_elf.cpp if LIEF is available.
set(RZ_SOURCES "")
if(RIZIN_AVAILABLE)
    list(APPEND RZ_SOURCES rizin_core.cpp)
else()
    list(APPEND RZ_SOURCES rizin_stub.cpp)
endif()

if(LIEF_AVAILABLE)
    list(APPEND RZ_SOURCES lief_elf.cpp)
endif()

add_library(rz_native SHARED ${RZ_SOURCES})
target_sources(rz_native PRIVATE zstd_compat_stub.cpp)

set(XANSO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../third_party/xAnSo-src")
add_library(xanso_native SHARED
    xanso_jni.cpp
    ${XANSO_ROOT}/log.cpp
    ${XANSO_ROOT}/util/util.cpp
    ${XANSO_ROOT}/Core/dyn_item.cpp
    ${XANSO_ROOT}/Core/dyn_section.cpp
    ${XANSO_ROOT}/Core/elf_header.cpp
    ${XANSO_ROOT}/Core/elf_section.cpp
    ${XANSO_ROOT}/Core/elf_segment.cpp
    ${XANSO_ROOT}/fix/section_fix.cpp
)
target_compile_options(xanso_native PRIVATE "-iquote${XANSO_ROOT}")
target_link_libraries(xanso_native PRIVATE log)

# --- LIEF include dirs and link ---
if(LIEF_AVAILABLE)
    message(STATUS "LIEF: using ${LIEF_LIB}")
    target_include_directories(rz_native PRIVATE "${LIEF_BUILD_DIR}/include")
    target_link_libraries(rz_native PRIVATE ${LIEF_LIB})
else()
    message(WARNING "LIEF not found at '${LIEF_LIB}'. ELF parsing will use Kotlin fallback (ElfParser).")
endif()

# --- Rizin archives ---
if(RIZIN_AVAILABLE)
    set(RIZIN_SRC "C:/Users/15884/Downloads/somcp/rizin-src" CACHE PATH "Rizin source tree")
    if(EXISTS "${RIZIN_SHARED_SDK}/lib/librz_core.so")
        message(STATUS "Rizin: linking shared SDK from ${RIZIN_SHARED_SDK}")
        target_include_directories(rz_native PRIVATE
            ${RIZIN_SHARED_SDK}/include/librz
            ${RIZIN_SHARED_SDK}/include/librz/sdb
        )
        file(GLOB RZ_SHARED_LIBS "${RIZIN_SHARED_SDK}/lib/librz_*.so")
        target_link_libraries(rz_native PRIVATE ${RZ_SHARED_LIBS})
    else()
        file(GLOB_RECURSE RZ_ALL_ARCHIVES_RAW
            "${RIZIN_BUILD_DIR}/librz/*.a"
            "${RIZIN_BUILD_DIR}/subprojects/*.a"
        )
        set(RZ_LINK_ARCHIVES "")
        foreach(archive ${RZ_ALL_ARCHIVES_RAW})
            get_filename_component(fname "${archive}" NAME)
            if(fname MATCHES "_native\.a$" OR fname MATCHES "_cross_native")
                continue()
            endif()
            list(APPEND RZ_LINK_ARCHIVES "${archive}")
        endforeach()

        message(STATUS "Rizin: linking ${RZ_LINK_ARCHIVES} from ${RIZIN_BUILD_DIR}")
        target_include_directories(rz_native PRIVATE
            ${RIZIN_SRC}/librz/include
            ${RIZIN_SRC}/librz/analysis
            ${RIZIN_SRC}/librz/util
            ${RIZIN_SRC}/librz/util/sdb/src
            ${RIZIN_SRC}
            ${RIZIN_SRC}/subprojects/sdb/include
            ${RIZIN_SRC}/subprojects/sdb/include/sdb
            ${RIZIN_SRC}/subprojects/capstone-next/include
            ${RIZIN_SRC}/subprojects/capstone-next/include/capstone
            ${RIZIN_SRC}/subprojects/tree-sitter/lib/include
            ${RIZIN_SRC}/subprojects/tree-sitter/lib/src
            ${RIZIN_SRC}/subprojects/libdemangle/include
            ${RIZIN_BUILD_DIR}
            ${RIZIN_BUILD_DIR}/librz/include
            ${RIZIN_BUILD_DIR}/subprojects/sdb/include
            ${RIZIN_BUILD_DIR}/subprojects
        )
        foreach(archive ${RZ_LINK_ARCHIVES})
            target_link_libraries(rz_native PRIVATE "-Wl,--whole-archive" ${archive} "-Wl,--no-whole-archive")
        endforeach()
    endif()

    target_link_options(rz_native PRIVATE -Wl,--allow-multiple-definition)
    target_link_libraries(rz_native PRIVATE log m z dl c)
else()
    message(WARNING "Rizin static libs not found under '${RIZIN_BUILD_DIR}'. "
                    "Rizin backend will be unavailable at runtime. "
                    "Run the meson cross-compile first.")
    target_link_libraries(rz_native PRIVATE log)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR NOT CMAKE_BUILD_TYPE)
    target_compile_options(rz_native PRIVATE -O2 -ffunction-sections -fdata-sections -fvisibility=hidden)
    target_link_options(rz_native PRIVATE -Wl,--gc-sections -Wl,--icf=safe -Wl,--exclude-libs,ALL)
endif()
