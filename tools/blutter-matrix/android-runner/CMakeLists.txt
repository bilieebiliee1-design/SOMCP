cmake_minimum_required(VERSION 3.22)
project(blutter_android_runner LANGUAGES C CXX)

if(NOT BLUTTER_SOURCE OR NOT DARTLIB OR NOT RUNNER_LIBRARY)
    message(FATAL_ERROR "BLUTTER_SOURCE, DARTLIB and RUNNER_LIBRARY are required")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(${DARTLIB} REQUIRED)
if(NOT CAPSTONE_ROOT)
    message(FATAL_ERROR "CAPSTONE_ROOT is required")
endif()
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES
    IMPORTED_LOCATION "${CAPSTONE_ROOT}/lib/libcapstone.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_ROOT}/include"
)
find_library(LOG_LIBRARY log REQUIRED)
find_library(DL_LIBRARY dl REQUIRED)

set(SRCDIR "${BLUTTER_SOURCE}/src")
include("${BLUTTER_SOURCE}/sourcelist.cmake")
list(FILTER SRCS EXCLUDE REGEX "(^|/)main\\.cpp$")
list(TRANSFORM SRCS PREPEND "${SRCDIR}/")

add_library(${RUNNER_LIBRARY} SHARED ${SRCS} android_runner.cpp)
target_include_directories(${RUNNER_LIBRARY} PRIVATE "${SRCDIR}")
target_include_directories(${RUNNER_LIBRARY} PRIVATE "${CAPSTONE_ROOT}/include/capstone")
target_compile_definitions(${RUNNER_LIBRARY} PRIVATE
    NDEBUG
    RUNNER_ID="${RUNNER_ID}"
    BLUTTER_COMMIT="${BLUTTER_COMMIT}"
    FRIDA_TEMPLATE_DIR="${BLUTTER_SOURCE}/../scripts/"
)
if(NO_METHOD_EXTRACTOR_STUB)
    target_compile_definitions(${RUNNER_LIBRARY} PRIVATE NO_METHOD_EXTRACTOR_STUB)
endif()
if(UNIFORM_INTEGER_ACCESS)
    target_compile_definitions(${RUNNER_LIBRARY} PRIVATE UNIFORM_INTEGER_ACCESS)
endif()
if(NOT COMPRESSED_POINTERS)
    target_compile_definitions(${RUNNER_LIBRARY} PRIVATE NO_CODE_ANALYSIS CSREG_DART_HEAP=ARM64_REG_XZR)
endif()
target_compile_options(${RUNNER_LIBRARY} PRIVATE -O3 -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden -fno-omit-frame-pointer)
target_link_libraries(${RUNNER_LIBRARY} PRIVATE ${DARTLIB} capstone ${LOG_LIBRARY} ${DL_LIBRARY})
target_precompile_headers(${RUNNER_LIBRARY} PRIVATE "${SRCDIR}/pch.h")
