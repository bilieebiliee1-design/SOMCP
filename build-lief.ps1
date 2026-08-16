param(
    [string]$Abi = "arm64-v8a",
    [string]$CMake = "",
    [string]$Ninja = "",
    [string]$NdkRoot = ""
)
$ErrorActionPreference = "Continue"
# 与 build-rizin.ps1 相同：cmake 正常工作时会向 stderr 写进度信息，
# PowerShell 5.1 下 ErrorActionPreference=Stop 会误报 NativeCommandError。
# 依赖显式 $LASTEXITCODE 判断失败。

# build-lief.ps1 — cross-compile LIEF static archive for one Android ABI with
# CMake. Portability contract: every toolchain path is resolved from
# environment variables or command-line args; nothing machine-specific is
# hardcoded.

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ABI 白名单校验：防止 '..' 等路径穿越（$Abi 会拼进 Remove-Item -Recurse 的
# BuildDir 路径）。
if ($Abi -notmatch '^[a-zA-Z0-9_-]+$') {
    throw "[build-lief] Invalid ABI '$Abi'. Allowed: alphanumeric, '_', '-' (e.g. arm64-v8a, armeabi-v7a, x86, x86_64)."
}

function Get-NdkRoot {
    if ($env:ANDROID_NDK_HOME -and (Test-Path $env:ANDROID_NDK_HOME)) { return $env:ANDROID_NDK_HOME }
    if ($env:ANDROID_HOME) {
        $ndkDir = Join-Path $env:ANDROID_HOME "ndk"
        if (Test-Path $ndkDir) {
            $cand = Get-ChildItem $ndkDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if ($cand) { return $cand.FullName }
        }
    }
    $localNdk = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
    if (Test-Path $localNdk) {
        $cand = Get-ChildItem $localNdk -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { return $cand.FullName }
    }
    throw "[build-lief] Cannot locate Android NDK. Set ANDROID_NDK_HOME / ANDROID_HOME or pass -NdkRoot <path>."
}
function Get-SdkCmakeRoot {
    if ($env:ANDROID_HOME -and (Test-Path (Join-Path $env:ANDROID_HOME "cmake"))) {
        return (Join-Path $env:ANDROID_HOME "cmake")
    }
    $localSdk = Join-Path $env:LOCALAPPDATA "Android\Sdk\cmake"
    if (Test-Path $localSdk) { return $localSdk }
    return ""
}
function Get-CMakeExe {
    if ($env:CMAKE_HOME -and (Test-Path (Join-Path $env:CMAKE_HOME "bin\cmake.exe"))) { return (Join-Path $env:CMAKE_HOME "bin\cmake.exe") }
    $sdkCmake = Get-SdkCmakeRoot
    if ($sdkCmake) {
        $cand = Get-ChildItem $sdkCmake -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($cand -and (Test-Path (Join-Path $cand.FullName "bin\cmake.exe"))) { return (Join-Path $cand.FullName "bin\cmake.exe") }
    }
    $inPath = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    throw "[build-lief] Cannot locate cmake.exe. Set CMAKE_HOME / ANDROID_HOME or pass -CMake <path>."
}
function Get-NinjaExe {
    $sdkCmake = Get-SdkCmakeRoot
    if ($sdkCmake) {
        $cand = Get-ChildItem $sdkCmake -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($cand -and (Test-Path (Join-Path $cand.FullName "bin\ninja.exe"))) { return (Join-Path $cand.FullName "bin\ninja.exe") }
    }
    $inPath = Get-Command ninja.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    throw "[build-lief] Cannot locate ninja.exe. Pass -Ninja <path> or add it to PATH."
}

if (-not $NdkRoot) { $NdkRoot = Get-NdkRoot }
if (-not $CMake) { $CMake = Get-CMakeExe }
if (-not $Ninja) { $Ninja = Get-NinjaExe }

$Toolchain = "$NdkRoot\build\cmake\android.toolchain.cmake"
$SrcDir = "$ProjectDir\third_party\lief-src"
$BuildDir = "$ProjectDir\third_party\lief-build\$Abi"

if (-not (Test-Path $CMake)) { Write-Host "[build-lief] CMake not found at $CMake" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Ninja)) { Write-Host "[build-lief] Ninja not found at $Ninja" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Toolchain)) { Write-Host "[build-lief] NDK toolchain not found at $Toolchain" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $SrcDir)) { Write-Host "[build-lief] LIEF source not found at $SrcDir — run 'git submodule update --init third_party/lief-src'" -ForegroundColor Red; exit 1 }

# LIEF 0.16.1 upstream compile bug: with LIEF_DISABLE_FROZEN=ON, CONST_MAP
# expands to std::unordered_map, but src/OAT/utils.cpp calls lower_bound(),
# which std::unordered_map does not provide. Apply our patch before building.
# Idempotent: skipped once the offending call is gone.
$PatchFile = "$ProjectDir\third_party\patches\lief-0.16.1-oat-lower_bound.patch"
if ((Test-Path $PatchFile) -and (Select-String -Path "$SrcDir\src\OAT\utils.cpp" -Pattern "oat2android\.lower_bound" -Quiet)) {
    Write-Host "[build-lief] Applying LIEF patch: $PatchFile"
    Push-Location $SrcDir
    & git apply $PatchFile 2>&1
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "[build-lief] LIEF patch FAILED" -ForegroundColor Red; exit 1 }
    Pop-Location
}

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

Write-Host "[build-lief] CMake=$CMake"
Write-Host "[build-lief] Ninja=$Ninja"
Write-Host "[build-lief] NdkRoot=$NdkRoot"
Write-Host "[build-lief] CMake configure for $Abi ..."
& $CMake -G "Ninja" `
    -DCMAKE_MAKE_PROGRAM="$Ninja" `
    -DCMAKE_TOOLCHAIN_FILE="$Toolchain" `
    -DANDROID_ABI="$Abi" `
    -DANDROID_PLATFORM=android-26 `
    -DCMAKE_BUILD_TYPE=Release `
    -DLIEF_TESTS=OFF `
    -DLIEF_EXAMPLES=OFF `
    -DLIEF_DOC=OFF `
    -DLIEF_PYTHON_API=OFF `
    -DLIEF_RUST_API=OFF `
    -DLIEF_C_API=ON `
    -DLIEF_ELF=ON `
    -DLIEF_PE=ON `
    -DLIEF_MACHO=ON `
    -DLIEF_DEX=ON `
    -DLIEF_ART=ON `
    -DLIEF_OAT=ON `
    -DLIEF_VDEX=ON `
    -DLIEF_DEBUG_INFO=OFF `
    -DLIEF_OBJC=OFF `
    -DLIEF_DYLD_SHARED_CACHE=OFF `
    -DLIEF_ASM=OFF `
    -DLIEF_LOGGING=ON `
    -DLIEF_ENABLE_JSON=ON `
    -DLIEF_USE_CCACHE=OFF `
    -DLIEF_DISABLE_FROZEN=ON `
    -DBUILD_SHARED_LIBS=OFF `
    -DCMAKE_INSTALL_PREFIX="$BuildDir" `
    -B "$BuildDir" `
    -S "$SrcDir" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] CMake configure FAILED" -ForegroundColor Red; exit 1 }

Write-Host "[build-lief] Building LIEF for $Abi ..."
& $CMake --build "$BuildDir" --parallel 4 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] Build FAILED" -ForegroundColor Red; exit 1 }

Write-Host "[build-lief] Installing LIEF for $Abi ..."
& $CMake --install "$BuildDir" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] Install FAILED" -ForegroundColor Red; exit 1 }

Write-Host "[build-lief] DONE - $Abi"
