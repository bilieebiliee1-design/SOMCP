#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# build-rz-ghidra-android.sh — cross-compile the rz-ghidra Ghidra decompiler
# plugin (libcore_ghidra.so) for all four Android ABIs on a Linux CI runner
# (ubuntu-latest) and copy it (plus the shared Rizin SDK it links against) into
# app/src/main/jniLibs/<abi>/ so it is packaged into every APK split.
#
# Without this step the app logs, at runtime (see 25_09-18-04-09_117.log):
#   I RzNative: ghidra plugin missing at .../lib/arm64/libcore_ghidra.so
# and rizin-ghidra pseudocode is unavailable. NativeEngine.configureGhidra()
# passes context.applicationInfo.nativeLibraryDir (i.e. the APK's jniLibs lib
# dir) as the plugin dir, so the .so MUST live in jniLibs to be found.
#
# rz-ghidra's CMake uses find_package(Rizin), which needs a Rizin *SDK install*
# (lib/cmake/Rizin/RizinConfig.cmake). build-native-android.sh only produces
# static Rizin archives (no install), so this script builds & installs its own
# SHARED Rizin SDK per ABI first — mirroring build-rizin-ghidra-wsl.ps1's
# proven Linux recipe, minus the WSL wrapper.
#
# Requires: NDK (ANDROID_NDK_HOME or ANDROID_HOME/ndk), third_party/rizin-src
# (cloned by the workflow's "Clone Rizin source" step), and meson/ninja/cmake/
# git. Network access to github.com is needed for rz-ghidra + its submodules.
set -euo pipefail

# --- NDK resolution (mirrors build-native-android.sh) ---
NDK_ROOT="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK_ROOT" ] && [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    NDK_ROOT="$(ls -1d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "$NDK_ROOT" ] || [ ! -d "$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
    echo "[rz-ghidra] ERROR: Android NDK linux-x86_64 toolchain not found (ANDROID_NDK_HOME=$ANDROID_NDK_HOME, ANDROID_HOME=${ANDROID_HOME:-})." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

RIZIN_SRC="third_party/rizin-src"
RZ_GHIDRA_SRC="third_party/rz-ghidra"
if [ ! -d "$RIZIN_SRC/librz/include" ]; then
    echo "[rz-ghidra] ERROR: Rizin source not found at '$RIZIN_SRC'. Ensure it is cloned before this step." >&2
    exit 1
fi

# Cross-template per ABI (exist in repo; tokens rewritten for Linux below).
ABIS=(arm64-v8a armeabi-v7a x86 x86_64)
TPL=(rizin-cross-aarch64.ini rizin-cross-armv7a.ini rizin-cross-i686.ini rizin-cross-x86_64.ini)

for i in "${!ABIS[@]}"; do
    abi="${ABIS[$i]}"
    tpl="${TPL[$i]}"
    echo "[rz-ghidra] ======================================== ABI: $abi"

    # --- 1) SHARED Rizin SDK install (find_package(Rizin) needs it) ---
    rz_sdk="rizin-sdk/$abi"
    if [ -f "$rz_sdk/lib/cmake/Rizin/RizinConfig.cmake" ]; then
        echo "[rz-ghidra] Rizin SDK for $abi already installed; reusing."
    else
        build_dir="rizin-build/ghidra-$abi"
        rm -rf "$build_dir"
        mkdir -p "$build_dir"
        # Rewrite the Windows cross template for Linux: linux-x86_64 NDK toolchain,
        # no .cmd/.exe suffixes, concrete NDK root (same rewrite build-native-android.sh uses).
        NDK_ESC="$(printf '%s' "$NDK_ROOT" | sed 's/[&|\\]/\\&/g')"
        sed -e "s|@NDK_ROOT@|$NDK_ESC|g" \
            -e "s|windows-x86_64|linux-x86_64|g" \
            -e "s|\.cmd||g" -e "s|\.exe||g" \
            "$tpl" > "$build_dir/cross.ini"
        cat > "$build_dir/native.ini" <<'EOF'
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
        meson setup "$build_dir" "$RIZIN_SRC" \
            --cross-file "$build_dir/cross.ini" \
            --native-file "$build_dir/native.ini" \
            --prefix "$(pwd)/$rz_sdk" \
            --default-library shared -Dblob=true -Dstatic_runtime=false \
            -Duse_sys_capstone=disabled -Ddebugger=false -Dsubprojects_check=false
        meson compile -C "$build_dir"
        meson install -C "$build_dir"
    fi

    # --- 2) rz-ghidra source + submodules (Ghidra decompiler C++ lives in a submodule) ---
    if [ ! -d "$RZ_GHIDRA_SRC/.git" ]; then
        git clone --depth 1 https://github.com/rizinorg/rz-ghidra.git "$RZ_GHIDRA_SRC"
    fi
    git -C "$RZ_GHIDRA_SRC" submodule update --init --recursive --depth 1 || true

    # --- 3) Build + install rz-ghidra plugin ---
    rz_ghidra_build="third_party/rz-ghidra-build-$abi"
    rz_ghidra_install="third_party/rz-ghidra-install-$abi"
    rm -rf "$rz_ghidra_build"
    cmake -S "$RZ_GHIDRA_SRC" -B "$rz_ghidra_build" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM=android-23 \
        -DCMAKE_PREFIX_PATH="$(pwd)/$rz_sdk" \
        -DCMAKE_FIND_ROOT_PATH="$(pwd)/$rz_sdk" \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/$rz_ghidra_install" \
        -DBUILD_CUTTER_PLUGIN=OFF \
        -DBUILD_SLEIGH_PLUGIN=OFF \
        -DUSE_SYSTEM_ZLIB=OFF
    cmake --build "$rz_ghidra_build" --config Release -j "$(nproc)"
    cmake --install "$rz_ghidra_build"

    # --- 4) Locate the core plugin and copy into jniLibs as libcore_ghidra.so ---
    # rizin_core.cpp probes exactly "libcore_ghidra.so", so the packaged name is fixed.
    jni_dir="app/src/main/jniLibs/$abi"
    mkdir -p "$jni_dir"
    core_so="$(find "$rz_ghidra_install" -type f \( \
        -name 'libcore_ghidra.so' -o -name 'librz_core_ghidra.so' -o -name 'librz_ghidra-core.so' \) | head -1)"
    if [ -z "$core_so" ]; then
        core_so="$(find "$rz_ghidra_install" -type f -name '*ghidra*.so*' | head -1)"
    fi
    if [ -z "$core_so" ]; then
        echo "::error::[rz-ghidra] core plugin .so not found under $rz_ghidra_install after build"
        exit 1
    fi
    cp -L "$core_so" "$jni_dir/libcore_ghidra.so"
    echo "[rz-ghidra] copied $(basename "$core_so") -> $jni_dir/libcore_ghidra.so"

    # --- 5) Copy the shared Rizin libs the plugin links against ---
    found_rz=0
    for f in "$rz_sdk"/lib/librz_*.so*; do
        [ -e "$f" ] || continue
        cp -L "$f" "$jni_dir/"
        found_rz=1
    done
    if [ "$found_rz" -eq 0 ]; then
        echo "::error::[rz-ghidra] no shared librz_*.so found under $rz_sdk/lib"
        exit 1
    fi

    # --- 6) Sanity: libcore_ghidra.so must exist in jniLibs ---
    test -f "$jni_dir/libcore_ghidra.so" || {
        echo "::error::[rz-ghidra] libcore_ghidra.so missing from $jni_dir after install"
        exit 1
    }
    echo "[rz-ghidra] $abi: libcore_ghidra.so + shared Rizin libs staged in $jni_dir"
done

echo "[rz-ghidra] Done. libcore_ghidra.so is staged for all four ABIs under app/src/main/jniLibs/."
