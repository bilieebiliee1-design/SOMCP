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
# REQUIRE_NATIVE_BACKENDS (default OFF for local dev) turns a missing real
# backend into a hard build failure, so release/CI builds can never ship an
# APK that silently degraded to an empty stub .so.
option(REQUIRE_NATIVE_BACKENDS "Fail the build if Rizin/LIEF backends are unavailable" OFF)
set(RZ_SOURCES "")
if(RIZIN_AVAILABLE)
    list(APPEND RZ_SOURCES rizin_core.cpp)
elseif(REQUIRE_NATIVE_BACKENDS)
    message(FATAL_ERROR "Rizin backend not found for ABI ${ANDROID_ABI} but REQUIRE_NATIVE_BACKENDS=ON. Refusing to ship a stub librz_native.so.")
else()
    list(APPEND RZ_SOURCES rizin_stub.cpp)
endif()

if(LIEF_AVAILABLE)
    list(APPEND RZ_SOURCES lief_elf.cpp)
elseif(REQUIRE_NATIVE_BACKENDS)
    message(FATAL_ERROR "LIEF backend not found for ABI ${ANDROID_ABI} but REQUIRE_NATIVE_BACKENDS=ON. Refusing to ship without LIEF.")
endif()

add_library(rz_native SHARED ${RZ_SOURCES})
target_sources(rz_native PRIVATE zstd_compat_stub.cpp)

# Native APK signature verification — reads the APK directly from the
# filesystem to bypass Java-level PackageManager hooks (used by kstools
# and ApkSignatureKiller). Linked into the main rz_native library.
target_sources(rz_native PRIVATE signature_verify.cpp)

add_library(blutter_bridge SHARED blutter_bridge.cpp)
target_link_libraries(blutter_bridge PRIVATE dl log)

set(XANSO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../third_party/xAnSo-src")

# Compatibility header for Windows-specific includes in xAnSo.
set(XANSO_COMPAT_DIR "${CMAKE_CURRENT_BINARY_DIR}/xanso_compat")
file(WRITE "${XANSO_COMPAT_DIR}/strsafe.h" "#include <stdio.h>\n")

# Patch log.cpp: fix invalid va_list dereference.
set(XANSO_PATCHED_DIR "${CMAKE_CURRENT_BINARY_DIR}/xanso_patched")
file(READ "${XANSO_ROOT}/log.cpp" XANSO_LOG_SRC)
string(REPLACE "printf(log_format, *var_arg);" "vprintf(log_format, var_arg);"
       XANSO_LOG_SRC_PATCHED "${XANSO_LOG_SRC}")
file(WRITE "${XANSO_PATCHED_DIR}/log.cpp" "${XANSO_LOG_SRC_PATCHED}")

# Patch util.cpp: replace Windows-only ::_itoa_s() with standard snprintf.
file(READ "${XANSO_ROOT}/util/util.cpp" XANSO_UTIL_SRC)
string(REPLACE "::_itoa_s(i, _rs, rdx)"
       "snprintf(_rs, sizeof(_rs), (rdx==16)?\"%x\":(rdx==8)?\"%o\":\"%d\", i)"
       XANSO_UTIL_SRC_PATCHED "${XANSO_UTIL_SRC}")
file(WRITE "${XANSO_PATCHED_DIR}/util.cpp" "${XANSO_UTIL_SRC_PATCHED}")

add_library(xanso_native SHARED
    xanso_jni.cpp
    ${XANSO_PATCHED_DIR}/log.cpp
    ${XANSO_PATCHED_DIR}/util.cpp
    ${XANSO_ROOT}/Core/dyn_item.cpp
    ${XANSO_ROOT}/Core/dyn_section.cpp
    ${XANSO_ROOT}/Core/elf_header.cpp
    ${XANSO_ROOT}/Core/elf_section.cpp
    ${XANSO_ROOT}/Core/elf_segment.cpp
    ${XANSO_ROOT}/fix/section_fix.cpp
)
target_include_directories(xanso_native PRIVATE
    "${XANSO_COMPAT_DIR}"
    "${XANSO_ROOT}/util"
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
    set(RIZIN_SRC "${CMAKE_CURRENT_LIST_DIR}/../../../../third_party/rizin-src" CACHE PATH "Rizin source tree")
    if(NOT EXISTS "${RIZIN_SRC}/librz/include")
        message(FATAL_ERROR "RIZIN_SRC='${RIZIN_SRC}' does not look like a Rizin source tree "
                            "(missing librz/include). Pass -DRIZIN_SRC=<path> from Gradle "
                            "(or set the RIZIN_SRC env var, see build.gradle.kts) and clean the CMake cache.")
    endif()
    if(EXISTS "${RIZIN_SHARED_SDK}/lib/librz_core.so")
        message(STATUS "Rizin: linking shared SDK from ${RIZIN_SHARED_SDK}")
        target_include_directories(rz_native PRIVATE
            ${RIZIN_SHARED_SDK}/include/librz
            ${RIZIN_SHARED_SDK}/include/librz/sdb
        )
        file(GLOB RZ_SHARED_LIBS "${RIZIN_SHARED_SDK}/lib/librz_*.so")
        target_link_libraries(rz_native PRIVATE ${RZ_SHARED_LIBS} log m z dl c)
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

        # Meson wrap subproject directories may carry a version suffix
        # (e.g. "tree-sitter-0.26.9", "zlib-1.3.1"), so never hardcode the exact
        # folder name — resolve each one by prefix glob and keep only paths that
        # actually exist.
        set(RZ_SUBPROJ_INC "")
        foreach(_root "${RIZIN_SRC}/subprojects" "${RIZIN_BUILD_DIR}/subprojects")
            foreach(_spec
                "sdb|include"
                "sdb|include/sdb"
                "capstone|include"
                "capstone|include/capstone"
                "tree-sitter|lib/include"
                "tree-sitter|lib/src"
                "libdemangle|include"
            )
                string(REPLACE "|" ";" _parts "${_spec}")
                list(GET _parts 0 _prefix)
                list(GET _parts 1 _suffix)
                file(GLOB _cands LIST_DIRECTORIES true "${_root}/${_prefix}*")
                foreach(_cand ${_cands})
                    if(IS_DIRECTORY "${_cand}/${_suffix}")
                        list(APPEND RZ_SUBPROJ_INC "${_cand}/${_suffix}")
                    endif()
                endforeach()
            endforeach()
        endforeach()
        if(RZ_SUBPROJ_INC)
            list(REMOVE_DUPLICATES RZ_SUBPROJ_INC)
        endif()
        message(STATUS "Rizin subproject includes: ${RZ_SUBPROJ_INC}")

        target_include_directories(rz_native PRIVATE
            ${RIZIN_SRC}/librz/include
            ${RIZIN_SRC}/librz/analysis
            ${RIZIN_SRC}/librz/util
            ${RIZIN_SRC}/librz/util/sdb/src
            ${RIZIN_SRC}
            ${RZ_SUBPROJ_INC}
            ${RIZIN_BUILD_DIR}
            ${RIZIN_BUILD_DIR}/librz/include
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
    # Keep the link set in sync with the Rizin branches (m/dl/c kept for
    # forward compatibility; signature_verify/rizin_stub currently only use
    # zlib -> z).
    target_link_libraries(rz_native PRIVATE log m z dl c)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR NOT CMAKE_BUILD_TYPE)
    target_compile_options(rz_native PRIVATE -O2 -ffunction-sections -fdata-sections -fvisibility=hidden)
    target_link_options(rz_native PRIVATE -Wl,--gc-sections -Wl,--icf=safe -Wl,--exclude-libs,ALL)
endif()
