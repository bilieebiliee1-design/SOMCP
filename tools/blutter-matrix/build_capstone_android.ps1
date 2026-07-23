param(
    [string]$Root = "build/blutter-matrix/deps",
    [string]$Ndk = "$env:LOCALAPPDATA/Android/Sdk/ndk/29.0.14206865",
    [string]$CMake = "$env:LOCALAPPDATA/Android/Sdk/cmake/3.22.1/bin/cmake.exe"
)

$ErrorActionPreference = "Stop"
$Project = (Resolve-Path "$PSScriptRoot/../..").Path
$Source = Join-Path $Project "third_party/capstone-4.0.2-src"
$RootPath = Join-Path $Project $Root
$Build = Join-Path $RootPath "capstone-build"
$Install = Join-Path $RootPath "arm64-v8a/capstone"

Remove-Item -Recurse -Force $Build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $Install -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Install | Out-Null

& $CMake -S $Source -B $Build -G Ninja `
    "-DCMAKE_TOOLCHAIN_FILE=$Ndk/build/cmake/android.toolchain.cmake" `
    "-DANDROID_ABI=arm64-v8a" `
    "-DANDROID_PLATFORM=android-26" `
    "-DCMAKE_BUILD_TYPE=Release" `
    "-DCAPSTONE_BUILD_STATIC=ON" `
    "-DCAPSTONE_BUILD_SHARED=OFF" `
    "-DCAPSTONE_BUILD_TESTS=OFF" `
    "-DCAPSTONE_BUILD_CSTOOL=OFF" `
    "-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF" `
    "-DCAPSTONE_ARM64_SUPPORT=ON" `
    "-DCMAKE_INSTALL_PREFIX=$Install"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $CMake --build $Build --target install --parallel 4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not (Test-Path "$Install/lib/libcapstone.a")) { throw "Capstone static library is missing" }
