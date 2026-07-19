param(
    [string]$Abi = "arm64-v8a",
    [string]$AndroidPlatform = "android-23",
    [string]$RizinPrefix = "",
    [string]$NdkRoot = "$env:LOCALAPPDATA\Android\Sdk\ndk\29.0.14206865",
    [string]$CMakeExe = "$env:LOCALAPPDATA\Android\Sdk\cmake\3.22.1\bin\cmake.exe"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path $Root "third_party\rz-ghidra"
$Build = Join-Path $Root "third_party\rz-ghidra-build-$Abi"
$Install = Join-Path $Root "third_party\rz-ghidra-install-$Abi"

if (!(Test-Path $Source)) {
    git clone --depth 1 https://github.com/rizinorg/rz-ghidra.git $Source
    git -C $Source submodule update --init --recursive --depth 1
}

if (!$RizinPrefix) {
    $RizinPrefix = Join-Path $Root "rizin-install\$Abi"
}

$RizinConfig = Join-Path $RizinPrefix "lib\cmake\Rizin\RizinConfig.cmake"
if (!(Test-Path $RizinConfig)) {
    throw "Rizin installed SDK not found at $RizinConfig. Build and install Rizin for Android first; the Meson build dir alone is not enough for rz-ghidra find_package(Rizin)."
}

if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
New-Item -ItemType Directory -Force -Path $Build | Out-Null

& $CMakeExe -S $Source -B $Build -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$NdkRoot\build\cmake\android.toolchain.cmake" `
    -DANDROID_ABI=$Abi `
    -DANDROID_PLATFORM=$AndroidPlatform `
    -DCMAKE_PREFIX_PATH=$RizinPrefix `
    -DCMAKE_INSTALL_PREFIX=$Install `
    -DBUILD_CUTTER_PLUGIN=OFF `
    -DBUILD_SLEIGH_PLUGIN=OFF `
    -DUSE_SYSTEM_ZLIB=OFF

& $CMakeExe --build $Build --config Release -j 8
& $CMakeExe --install $Build
