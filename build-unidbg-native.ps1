# build-unidbg-native.ps1 - Cross-compile the Android native libraries required
# by the Unidbg emulation backend using the Android NDK.
#
# Background: unidbg 0.9.9 Maven artifacts only ship Linux natives (the
# libcapstone.so / libkeystone.so / libunicorn.so inside the jars are
# linux_64 / linux_aarch64 only), and there is no reliable Android prebuilt
# download, so the APK does not bundle them by default and emulate_* returns
# EMULATOR_UNAVAILABLE. This script builds the shared libs from the in-repo
# submodules (third_party/*) for a given ABI and copies them into
# app/src/main/jniLibs/<ABI>/; rebuild the APK afterwards to enable Unidbg.
#
# libunicorn.so is special: unidbg's unicorn2 backend is a JNI binding, so the
# library must carry the JNI bridge (Java_com_github_unidbg_arm_backend_unicorn_
# Unicorn_*), not only the raw uc_* engine API. See the unicorn section below
# and tools/verify_unicorn_jni.py.
#
# Usage (PowerShell; requires Android NDK 29 + CMake 3.22, and initialized
# submodules: git submodule update --init --recursive):
#   .\build-unidbg-native.ps1
#   .\build-unidbg-native.ps1 -Abi armeabi-v7a
#
# Notes:
#   - libjnidispatch.so is provided automatically by the JNA AAR
#     (net.java.dev.jna:jna); no need to build it.
#   - libdisassembler.so / libdemumble.so only serve optional diagnostic
#     paths in unidbg 0.9.9 and have no Android prebuilt source;
#     UnidbgEmulator loads them tolerantly (warning only, does not block the
#     emulate main path), so this script does not build them.
#   - libunicorn.so is built as unidbg's unicorn2 JNI bridge (unicorn engine
#     archive + backend/unicorn2/src/main/native/unicorn.c). The script
#     refuses to install a library that does not export that bridge, so an
#     engine-only libunicorn.so can no longer reach the APK (issue #91).
#   - The CMake flags target NDK 29 / CMake 3.22 / unidbg 0.9.9; if you bump
#     the NDK or CMake, adjust the flags per the upstream READMEs.
param(
    [string]$Abi = "arm64-v8a",
    [string]$Ndk = "$env:LOCALAPPDATA/Android/Sdk/ndk/29.0.14206865",
    [string]$CMake = "$env:LOCALAPPDATA/Android/Sdk/cmake/3.22.1/bin/cmake.exe",
    [switch]$SkipCapstone,
    [switch]$SkipKeystone,
    [switch]$SkipUnicorn
)
$ErrorActionPreference = "Stop"
# Whitelist the ABI so the value is never interpolated into filesystem or
# cmake arguments from untrusted input (path-traversal guard).
$ValidAbis = @("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
if ($ValidAbis -notcontains $Abi) { throw "Unsupported ABI '$Abi' - must be one of: $($ValidAbis -join ', ')" }
# Script lives at the repo root, so $PSScriptRoot IS the project root.
# (Sibling scripts build-rizin.ps1 / build-lief.ps1 use the same convention:
#  project dir = script dir, then Join-Path $ProjectDir "third_party/..." etc.
#  Using "$PSScriptRoot/.." would resolve to the parent of the repo and make
#  every third_party/app path wrong, so the build would never populate jniLibs.)
$Project = (Resolve-Path $PSScriptRoot).Path
$JniLibs = Join-Path $Project "app/src/main/jniLibs/$Abi"
New-Item -ItemType Directory -Force -Path $JniLibs | Out-Null
$Toolchain = Join-Path $Ndk "build/cmake/android.toolchain.cmake"
if (-not (Test-Path $Toolchain)) { throw "NDK toolchain not found: $Toolchain" }
if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) { throw "ninja not found on PATH - install it (e.g. winget install ninja) or use the ninja.exe shipped with the Android SDK CMake package" }
$Common = @("-G", "Ninja", "-DCMAKE_TOOLCHAIN_FILE=$Toolchain", "-DANDROID_ABI=$Abi", "-DANDROID_PLATFORM=android-26", "-DCMAKE_BUILD_TYPE=Release")
$BuildRoot = Join-Path $Project "third_party/unidbg-native-build/$Abi"

function Build-One {
    param([string]$Name, [string]$Src, [string[]]$Extra)
    if (-not (Test-Path $Src)) { throw "$Name source missing: $Src - run 'git submodule update --init --recursive' first" }
    $Build = Join-Path $BuildRoot $Name
    Remove-Item -Recurse -Force $Build -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Build | Out-Null
    Write-Host "[unidbg-native] configuring $Name ..."
    & $CMake -S $Src -B $Build @Common @Extra
    if ($LASTEXITCODE -ne 0) { throw "$Name cmake configure failed" }
    Write-Host "[unidbg-native] building $Name ..."
    & $CMake --build $Build --parallel 4
    if ($LASTEXITCODE -ne 0) { throw "$Name build failed" }
}

function Get-PythonRunner {
    foreach ($candidate in @("python", "python3", "py")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

# Refuse to install a libunicorn.so that cannot serve unidbg's unicorn2
# backend. Prefers the python verifier (real .dynsym inspection); falls back to
# a raw symbol scan so the guard also works without python.
function Assert-UnicornJniBridge {
    param([string]$So)
    $verifier = Join-Path $Project "tools/verify_unicorn_jni.py"
    $runner = Get-PythonRunner
    if ($runner -and (Test-Path $verifier)) {
        & $runner $verifier $So
        if ($LASTEXITCODE -ne 0) { throw "$So does not export the unidbg unicorn2 JNI bridge (see $verifier)" }
        return
    }
    Write-Host "[unidbg-native] python not found - falling back to a raw symbol scan"
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString([System.IO.File]::ReadAllBytes($So))
    $hits = ([regex]::Matches($text, "Java_com_github_unidbg_arm_backend_unicorn_Unicorn_")).Count
    if ($hits -lt 20) {
        throw "$So exports only $hits unicorn2 JNI symbols (need >= 20); it looks like the raw unicorn engine instead of unidbg's JNI bridge"
    }
    Write-Host "[unidbg-native] JNI bridge symbol scan passed ($hits symbol references)"
}

if (-not $SkipCapstone) {
    # Prefer the zhkl0228 fork (the unidbg 0.9.9 JNA bindings were written
    # against its API); fall back to the official capstone-4.0.2-src
    # (cs_open/cs_disasm ABI is stable and compatible).
    $cap = Join-Path $Project "third_party/zhkl-capstone-src"
    if (-not (Test-Path $cap)) { $cap = Join-Path $Project "third_party/capstone-4.0.2-src" }
    Build-One "capstone" $cap @("-DCAPSTONE_BUILD_STATIC=OFF", "-DCAPSTONE_BUILD_SHARED=ON", "-DCAPSTONE_BUILD_TESTS=OFF", "-DCAPSTONE_BUILD_CSTOOL=OFF", "-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF", "-DCAPSTONE_ARM_SUPPORT=ON", "-DCAPSTONE_ARM64_SUPPORT=ON")
    Copy-Item (Join-Path $BuildRoot "capstone/libcapstone.so") $JniLibs -Force
    Write-Host "[unidbg-native] copied libcapstone.so -> $JniLibs"
}

if (-not $SkipKeystone) {
    Build-One "keystone" (Join-Path $Project "third_party/keystone-engine-src") @("-DBUILD_LIBS_ONLY=ON", "-DLLVM_BUILD_TOOLS=OFF")
    Copy-Item (Join-Path $BuildRoot "keystone/libkeystone.so") $JniLibs -Force
    Write-Host "[unidbg-native] copied libkeystone.so -> $JniLibs"
}

if (-not $SkipUnicorn) {
    # unicorn's bundled QEMU uses __uint128_t (CONFIG_INT128), which the
    # Android NDK does not provide for 32-bit targets (armeabi-v7a, x86), so
    # the engine only builds for the 64-bit ABIs. The 32-bit APKs keep
    # capstone/keystone and Unidbg degrades gracefully there.
    if ($Abi -ne "arm64-v8a" -and $Abi -ne "x86_64") {
        Write-Warning "[unidbg-native] unicorn cannot compile on 32-bit ABI '$Abi' (needs __uint128_t); skipping libunicorn.so for this ABI"
    } else {
        # -----------------------------------------------------------------
        # libunicorn.so must be unidbg's *unicorn2 JNI bridge*, not the raw
        # engine: the backend the app registers (Unicorn2Factory ->
        # Unicorn2Backend) calls com.github.unidbg.arm.backend.unicorn.Unicorn,
        # whose entry points are JNI `native` methods that Android resolves by
        # symbol name, i.e.
        #     Java_com_github_unidbg_arm_backend_unicorn_Unicorn_*
        # The plain unicorn engine only exports the flat uc_* API. An
        # engine-only library loads fine but makes Unicorn2Backend unbindable;
        # because the app constructs Unicorn2Factory(true),
        # BackendFactory.newBackend swallows the error, falls back to the
        # legacy UnicornBackend and dies with
        # NoClassDefFoundError: unicorn.Unicorn (issue #91).
        #
        # Note the arch list must be a *semicolon* separated CMake list:
        # "-DUNICORN_ARCH=arm,aarch64" is one bogus token, which compiles no
        # arm-softmmu/aarch64-softmmu backend at all (the resulting library
        # exports the whole uc_* surface with no emulation core behind it).
        # The steps mirror unidbg's
        # backend/unicorn2/src/main/native/{Dockerfile,CMakeLists.txt}.
        # -----------------------------------------------------------------
        $uni = Join-Path $Project "third_party/unicorn-engine-unicorn2"
        $uniHeader = Join-Path $uni "include/unicorn/unicorn.h"
        if (-not (Test-Path $uniHeader) -or -not (Select-String -Path $uniHeader -Pattern "uc_ctl_set_cpu_model" -Quiet)) {
            throw "unicorn 2.x engine source not found at $uni - run 'git submodule update --init --recursive'; unidbg's JNI bridge needs the unicorn 2.x API (uc_ctl_*), which the 1.0.x snapshot in third_party/unicorn-zhkl0228 cannot provide"
        }
        $jniDir = Join-Path $Project "third_party/unidbg-zhkl0228/backend/unicorn2/src/main/native"
        if (-not (Test-Path (Join-Path $jniDir "unicorn.c"))) {
            throw "unidbg unicorn2 JNI bridge sources missing: $jniDir/unicorn.c - run 'git submodule update --init --recursive' (needs third_party/unidbg-zhkl0228)"
        }

        # 1) engine: arm + aarch64 back ends plus the all-in-one libunicorn.a
        #    archive the bridge links against.
        Build-One "unicorn" $uni @("-DUNICORN_ARCH=arm;aarch64", "-DBUILD_SHARED_LIBS=ON", "-DUNICORN_LEGACY_STATIC_ARCHIVE=ON", "-DUNICORN_BUILD_TESTS=OFF", "-DUNICORN_INSTALL=OFF", "-DUNICORN_TRACER=OFF")
        $engineDir = Join-Path $BuildRoot "unicorn"
        $engineLib = Join-Path $engineDir "libunicorn.a"
        if (-not (Test-Path $engineLib)) {
            $found = Get-ChildItem $engineDir -Filter "libunicorn*.a" -File | Select-Object -First 1
            if ($found) { $engineLib = $found.FullName }
        }
        if (-not (Test-Path $engineLib)) { throw "unicorn engine archive (libunicorn.a) not found under $engineDir" }
        Write-Host "[unidbg-native] unicorn engine archive: $engineLib"
        # Extra archives are harmless inside --start-group: the linker only
        # pulls the members it still needs.
        $engineExtra = @(Get-ChildItem $engineDir -File | Where-Object { $_.Name -like "lib*-softmmu.a" -or $_.Name -eq "libunicorn-common.a" } | Select-Object -ExpandProperty FullName)

        # 2) JNI bridge -> libunicorn.so, compiled with the NDK toolchain.
        $triple = switch ($Abi) {
            "arm64-v8a" { "aarch64-linux-android" }
            "x86_64" { "x86_64-linux-android" }
            default { throw "unexpected 64-bit ABI '$Abi'" }
        }
        $prebuilt = Join-Path $Ndk "toolchains/llvm/prebuilt/windows-x86_64"
        $bridgeCc = Join-Path $prebuilt "bin/${triple}26-clang.cmd"
        if (-not (Test-Path $bridgeCc)) { throw "NDK clang not found: $bridgeCc" }
        $ndkInclude = Join-Path $prebuilt "sysroot/usr/include"
        if (-not (Test-Path (Join-Path $ndkInclude "jni.h"))) { throw "jni.h not found in the NDK sysroot: $ndkInclude" }

        $bridgeSo = Join-Path $BuildRoot "libunicorn.so"
        Remove-Item -Force $bridgeSo -ErrorAction SilentlyContinue
        Write-Host "[unidbg-native] linking the unicorn2 JNI bridge for $Abi ..."
        $linkArgs = @(
            "-shared", "-fPIC", "-O3", "-DNDEBUG", "-Wall", "-Wno-missing-braces"
            "-I$jniDir", "-I$(Join-Path $uni 'include')", "-I$ndkInclude"
            (Join-Path $jniDir "unicorn.c")
            (Join-Path $jniDir "sample_arm.c")
            (Join-Path $jniDir "sample_arm64.c")
            "-Wl,--start-group"
            $engineLib
        ) + $engineExtra + @("-Wl,--end-group", "-llog", "-lm", "-ldl", "-o", $bridgeSo)
        & $bridgeCc @linkArgs
        if ($LASTEXITCODE -ne 0) { throw "linking the unicorn2 JNI bridge failed" }

        # 3) never install a library that cannot satisfy the backend.
        Assert-UnicornJniBridge -So $bridgeSo
        Copy-Item $bridgeSo (Join-Path $JniLibs "libunicorn.so") -Force
        Write-Host "[unidbg-native] copied libunicorn.so (unicorn2 JNI bridge) -> $JniLibs"
    }
}

Write-Host "[unidbg-native] DONE - rebuild the APK to enable the Unidbg backend (libjnidispatch.so is provided automatically by the JNA AAR)"
