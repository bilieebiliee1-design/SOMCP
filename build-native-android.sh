#!/usr/bin/env bash
# build-native-android.sh — cross-compile the Rizin + LIEF native backends for
# all four Android ABIs on a Linux CI runner (ubuntu-latest).
#
# Linux counterpart of build-rizin.ps1 / build-lief.ps1 (Windows). Differences:
#   * host tools are the system gcc/g++ (no MinGW shim patches needed);
#   * NDK llvm toolchain lives under toolchains/llvm/prebuilt/linux-x86_64/bin
#     with no .cmd/.exe suffixes (the rizin-cross-*.ini templates are Windows
#     templates and are rewritten here).
#
# Output layout matches what app/src/main/cpp/CMakeLists.txt expects:
#   rizin-build/<abi>/librz/...           (meson archives)
#   third_party/lief-build/<abi>/lib/libLIEF.a
#
# Idempotent: if every ABI's archives are already present (e.g. restored from
# the actions/cache step), the script exits immediately without rebuilding.
set -euo pipefail

# --- Locate the Android NDK ---
NDK_ROOT="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK_ROOT" ] && [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    NDK_ROOT="$(ls -1d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "$NDK_ROOT" ] || [ ! -d "$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
    echo "[build-native] ERROR: NDK llvm linux-x86_64 toolchain not found (ANDROID_NDK_HOME=$ANDROID_NDK_HOME, ANDROID_HOME=${ANDROID_HOME:-})." >&2
    exit 1
fi
NDK_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"

RIZIN_SRC="third_party/rizin-src"
LIEF_SRC="third_party/lief-src"
RIZIN_BUILD_ROOT="rizin-build"
LIEF_BUILD_ROOT="third_party/lief-build"

APIS=(arm64-v8a armeabi-v7a x86 x86_64)
CROSS_TEMPLATES=(rizin-cross-aarch64.ini rizin-cross-armv7a.ini rizin-cross-i686.ini rizin-cross-x86_64.ini)

if [ ! -d "$RIZIN_SRC/librz/include" ]; then
    echo "[build-native] ERROR: Rizin source not found at '$RIZIN_SRC' (missing librz/include). Clone it first: git clone --depth 1 --branch v0.10.0 https://github.com/rizinorg/rizin.git $RIZIN_SRC" >&2
    exit 1
fi
if [ ! -d "$LIEF_SRC" ]; then
    echo "[build-native] ERROR: LIEF source not found at '$LIEF_SRC' — run 'git submodule update --init third_party/lief-src'." >&2
    exit 1
fi

# --- Rizin: meson cross-compile per ABI ---
for i in "${!APIS[@]}"; do
    abi="${APIS[$i]}"
    tpl="${CROSS_TEMPLATES[$i]}"
    build_dir="$RIZIN_BUILD_ROOT/$abi"
    if [ -f "$build_dir/librz/util/librz_util.a" ]; then
        echo "[build-native] Rizin $abi: archives already present, skipping."
        continue
    fi
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    # Rewrite the Windows cross template for Linux: linux-x86_64 NDK toolchain,
    # no .cmd/.exe suffixes, concrete NDK root. '|' is the sed delimiter because
    # the NDK path contains '/'. The NDK path is escaped first so characters
    # special to sed (&, \, |) cannot corrupt or inject into the ini.
    NDK_ESC="$(printf '%s' "$NDK_ROOT" | sed 's/[&|\\]/\\&/g')"
    sed -e "s|@NDK_ROOT@|$NDK_ESC|g" \
        -e "s|windows-x86_64|linux-x86_64|g" \
        -e "s|\.cmd||g" \
        -e "s|\.exe||g" \
        "$tpl" > "$build_dir/cross-$abi.ini"
    # Native (host) file: Rizin builds some host tools on the build machine.
    cat > "$build_dir/native-$abi.ini" <<'EOF'
[binaries]
c = 'cc'
cpp = 'c++'
ar = 'ar'
ld = 'ld'
pkg-config = 'false'

[built-in options]
c_args = ['-O2']
cpp_args = ['-O2', '-std=c++17']
c_std = 'c11'
cpp_std = 'c++17'
EOF
    echo "[build-native] Rizin $abi: meson setup + compile (this takes a while)..."
    meson setup "$build_dir" "$RIZIN_SRC" \
        --cross-file "$build_dir/cross-$abi.ini" \
        --native-file "$build_dir/native-$abi.ini" \
        -Dblob=true -Dstatic_runtime=true --default-library static \
        -Duse_sys_capstone=disabled -Ddebugger=false -Dsubprojects_check=false
    meson compile -C "$build_dir"
done

# --- LIEF: CMake cross-compile per ABI ---
for abi in "${APIS[@]}"; do
    build_dir="$LIEF_BUILD_ROOT/$abi"
    if [ -f "$build_dir/lib/libLIEF.a" ]; then
        echo "[build-native] LIEF $abi: libLIEF.a already present, skipping."
        continue
    fi
    rm -rf "$build_dir"
    echo "[build-native] LIEF $abi: cmake configure + build + install..."
    cmake -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM=android-26 \
        -DCMAKE_BUILD_TYPE=Release \
        -DLIEF_TESTS=OFF \
        -DLIEF_EXAMPLES=OFF \
        -DLIEF_DOC=OFF \
        -DLIEF_PYTHON_API=OFF \
        -DLIEF_RUST_API=OFF \
        -DLIEF_C_API=ON \
        -DLIEF_ELF=ON \
        -DLIEF_PE=ON \
        -DLIEF_MACHO=ON \
        -DLIEF_DEX=ON \
        -DLIEF_ART=ON \
        -DLIEF_OAT=ON \
        -DLIEF_VDEX=ON \
        -DLIEF_DEBUG_INFO=OFF \
        -DLIEF_OBJC=OFF \
        -DLIEF_DYLD_SHARED_CACHE=OFF \
        -DLIEF_ASM=OFF \
        -DLIEF_LOGGING=ON \
        -DLIEF_ENABLE_JSON=ON \
        -DLIEF_USE_CCACHE=OFF \
        -DLIEF_DISABLE_FROZEN=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_INSTALL_PREFIX="$build_dir" \
        -B "$build_dir" \
        -S "$LIEF_SRC"
    cmake --build "$build_dir" --parallel 2
    cmake --install "$build_dir"
done

echo "[build-native] All native backends (Rizin + LIEF, 4 ABIs) are ready."
