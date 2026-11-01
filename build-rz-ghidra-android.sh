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
#
# The rz-ghidra tree itself (incl. its nested submodules) is prepared by
# tools/init-submodules.sh during checkout; section 2 below only re-does it as
# a fallback when this script runs standalone. Both paths share one pin: the
# gitlink SHA in HEAD. Never use `git submodule update` on the nested
# rizinorg/ghidra pins: a pin whose commit was cleaned off that remote turns into
# `upload-pack: not our ref`, and the failure lands inside checkout instead of on
# a named check.
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
# 树的身份只有一个来源：HEAD 里那个 gitlink（见下方 section 2 的兜底 clone）。
# tag 只决定「拉哪条历史」，不决定「编译哪棵树」，两者不会再打架。tag 本身
# 仍与 .gitmodules 的 `branch =` 保持一致，抬版本时两处一起动。
RZ_GHIDRA_REF="${RZ_GHIDRA_REF:-v0.9.0}"
RIZIN_GHIDRA_URL="https://github.com/rizinorg/rz-ghidra.git"
# gitlink 里的 pin 今天恰好是 rizin 分支尖端；分支上取不到时 fetch_pin 会回落
# 按 SHA 取，所以这里只是「先看哪条历史」的提示。
RIZIN_GHIDRA_BRANCH="rizin"
# shellcheck source=tools/submodule-utils.sh
. "$ROOT/tools/submodule-utils.sh"

if [ ! -d "$RIZIN_SRC/librz/include" ]; then
    echo "[rz-ghidra] ERROR: Rizin source not found at '$RIZIN_SRC'. Ensure it is cloned before this step." >&2
    exit 1
fi

# rizin master added ldexpf() in pf_parser.c (half_to_float, 2025-08).
# Bionic does not export the float ldexpf symbol for API < 30, so the
# shared-lib link (-Wl,--no-undefined) fails on android-26.
# Replace with (float)ldexp((double)…), which is available on all API levels.
# sed is idempotent: once applied the ldexpf( pattern is gone.
sed -i 's/float val = ldexpf((float)man, -24);/float val = (float)ldexp((double)man, -24);/' \
    "$RIZIN_SRC/librz/type/pf/pf_parser.c"

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
    # 顶层 checkout 由 tools/init-submodules.sh 置备；本段只在脚本被单独跑、
    # 且目录里没有 checkout 时兜底。兜底也 detach 到 gitlink SHA，绝不留在
    # tag 的工作树：下面 pin 与 marshal.cc 断言算的都是 gitlink 记录的那棵树，
    # 编译的也必须是同一棵。
    #
    # 顺序很重要：先取 pin（pin_of 没有就带名字报错退出），再动目录。反过来会在
    # 没 pin 的顶层 checkout 上把用户手里的 third_party/rz-ghidra 删掉、又不回滚。
    # 而且 clone 本身也可能失败（tag/history 取不到、断网），所以先建到 <src>.tmp.$$，
    # 只有 clone 和 detach 都成了才换名 —— 失败时 third_party/rz-ghidra 原样留着。
    if [ ! -e "$RZ_GHIDRA_SRC/.git" ]; then
        # 显式清理，不用 EXIT trap：fetch_pin 里也做过临时目录，而 EXIT trap 是单槽位，
        # 谁后设谁生效、函数返回不还原 —— 两个都设就会互相覆盖，留下半成品目录。
        ghidra_tmp="$RZ_GHIDRA_SRC.tmp.$$"
        rm -rf "${ghidra_tmp:?}"
        ghidra_fail() {
            rm -rf "${ghidra_tmp:?}" "$ghidra_tmp.pin"
            echo "[rz-ghidra] ERROR: could not clone $RIZIN_GHIDRA_URL at '${RZ_GHIDRA_REF}'" >&2
            echo "  and check out $1; $RZ_GHIDRA_SRC was left untouched." >&2
            exit 1
        }
        # pin_of 用 exit 1 报错，只能直接调用 —— 放进 $( ) 只退子 shell，父进程拿到空串
        # 继续跑，最后死在 `checkout --detach ""` 上。重定向到文件而不是变量：它把 pin
        # 打到 stdout，报错和提示打 stderr。
        pin_of "$ROOT" "$RZ_GHIDRA_SRC" "[rz-ghidra]" >"$ghidra_tmp.pin"
        ghidra_pin="$(cat "$ghidra_tmp.pin")"
        git clone --quiet --no-checkout --filter=blob:none --single-branch \
            --branch "${RZ_GHIDRA_REF}" "$RIZIN_GHIDRA_URL" "$ghidra_tmp" ||
            ghidra_fail "${RZ_GHIDRA_REF}"
        git -C "$ghidra_tmp" checkout --quiet --detach "$ghidra_pin" ||
            ghidra_fail "$ghidra_pin"
        rm -rf "${RZ_GHIDRA_SRC:?}"
        mv "$ghidra_tmp" "$RZ_GHIDRA_SRC"
        rm -f "$ghidra_tmp.pin"
    fi

    # 先核 <repo> 本身在不在父仓钉的提交上。这是 build-rz-ghidra-android.sh 与
    # init-submodules.sh 的关键差别：那边有 check_submodules 从父仓扫 `+`，这边没有，
    # 而下面两处 fetch_pin 读的是 <repo> 自己的 HEAD —— <repo> 停在别的提交上时，它们
    # 读到的就是另一棵树的 pin，然后老老实实把那一棵树的嵌套项置备好、报成功，
    # 编译出来的东西与父仓钉的树毫无关系。
    ghidra_repo_pin="$(git ls-tree HEAD -- "$RZ_GHIDRA_SRC" 2>/dev/null | awk '$1 == "160000" { print $3 }' || true)"
    ghidra_repo_head="$(git -C "$RZ_GHIDRA_SRC" rev-parse HEAD 2>/dev/null || true)"
    if [ -z "$ghidra_repo_pin" ]; then
        echo "[rz-ghidra] ERROR: the superproject records no gitlink for $RZ_GHIDRA_SRC." >&2
        echo "  Run this from the repo root, or restore the submodule entry in .gitmodules." >&2
        exit 1
    fi
    if [ "$ghidra_repo_head" != "$ghidra_repo_pin" ]; then
        echo "[rz-ghidra] ERROR: $RZ_GHIDRA_SRC is at ${ghidra_repo_head:-<nothing>}, but the superproject" >&2
        echo "  pins $ghidra_repo_pin. The nested pins would be read from the wrong tree." >&2
        echo "  Run tools/init-submodules.sh from the repo root first." >&2
        exit 1
    fi

    # 嵌套子模块不用 `git submodule update`：pin 一旦被上游清洗掉，它只会回一句
    # upload-pack: not our ref，并且死在 checkout 里而非某个有名字的检核点。
    # fetch_pin 按分支名 fetch、本地校验并 detach 到 gitlink 记录的 SHA。
    # （与 tools/init-submodules.sh 共用实现，避免两套行为各自腐烂。）
    fetch_pin "$RZ_GHIDRA_SRC" "ghidra/ghidra" "$RIZIN_GHIDRA_BRANCH" "[rz-ghidra]" "$RIZIN_GHIDRA_URL"
    fetch_pin "$RZ_GHIDRA_SRC" "third-party/pugixml" "master" "[rz-ghidra]" "$RIZIN_GHIDRA_URL"
    # 再核一层：<repo> 在 pin 上不等于嵌套项也在（本地手里那份可能停在别的提交）。
    check_gitlinks "[rz-ghidra]" "$RZ_GHIDRA_SRC" "ghidra/ghidra" "third-party/pugixml"
    if [ ! -f "$RZ_GHIDRA_SRC/ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/marshal.cc" ]; then
        echo "[rz-ghidra] ERROR: nested submodule ghidra/ghidra is not populated at" >&2
        echo "  $RZ_GHIDRA_SRC/ghidra/ghidra — the decompiler sources are required." >&2
        exit 1
    fi

    # --- 3) Build + install rz-ghidra plugin ---
    rz_ghidra_build="third_party/rz-ghidra-build-$abi"
    rz_ghidra_install="third_party/rz-ghidra-install-$abi"
    rm -rf "$rz_ghidra_build"
    # android-26 matches the Rizin SDK cross templates and app minSdk 26;
    # on armeabi-v7a, bionic API<24 hides fseeko/ftello and libc++ <fstream> fails.
    cmake -S "$RZ_GHIDRA_SRC" -B "$rz_ghidra_build" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM=android-26 \
        -DCMAKE_PREFIX_PATH="$(pwd)/$rz_sdk" \
        -DCMAKE_FIND_ROOT_PATH="$(pwd)/$rz_sdk" \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/$rz_ghidra_install" \
        -DBUILD_CUTTER_PLUGIN=OFF \
        -DBUILD_SLEIGH_PLUGIN=OFF \
        -DBUILD_SLASPECS=OFF \
        -DUSE_SYSTEM_ZLIB=OFF
    # BUILD_SLASPECS defaults ON and compiles every .slaspec with a just-built
    # (Android-target) sleighc that cannot execute on the x86_64 runner; the
    # runtime .sla/.cspec/.ldefs are already committed under
    # app/src/main/assets/rizin/plugins/rz_ghidra_sleigh and copied to
    # sleighhome by NativeEngine.configureGhidra(), so skip the spec build.
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
