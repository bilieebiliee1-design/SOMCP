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
# This script lives at the repository root, so the project dir IS the script dir.
# Resolving "$PSScriptRoot/.." pointed one level above the checkout, which made
# every third_party/* lookup and the jniLibs output path miss.
$Project = $PSScriptRoot
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
    # unidbg 0.9.9's Unicorn2Factory uses unicorn2 (the zhkl0228 fork).
    $uni = Join-Path $Project "third_party/unicorn-zhkl0228"
    if (-not (Test-Path $uni)) { $uni = Join-Path $Project "third_party/unicorn-engine-unicorn2" }
    Build-One "unicorn" $uni @("-DUNICORN_ARCH=arm,aarch64", "-DUNICORN_BUILD_TESTS=OFF", "-DUNICORN_BUILD_SAMPLES=OFF")
    Copy-Item (Join-Path $BuildRoot "unicorn/libunicorn.so") $JniLibs -Force
    Write-Host "[unidbg-native] copied libunicorn.so -> $JniLibs"
}

Write-Host "[unidbg-native] DONE - rebuild the APK to enable the Unidbg backend (libjnidispatch.so is provided automatically by the JNA AAR)"
