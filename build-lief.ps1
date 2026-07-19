param([string]$Abi = "arm64-v8a")
$ErrorActionPreference = "Stop"
$CMake = "C:\Users\15884\AppData\Local\Android\Sdk\cmake\4.1.2\bin\cmake.exe"
$Ninja = "C:\Users\15884\AppData\Local\Programs\Python\Python310\Scripts\ninja.exe"
$NdkRoot = "C:\Users\15884\AppData\Local\Android\Sdk\ndk\29.0.14206865"
$Toolchain = "$NdkRoot\build\cmake\android.toolchain.cmake"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = "$ProjectDir\third_party\lief-src"
$BuildDir = "$ProjectDir\third_party\lief-build\$Abi"

if (-not (Test-Path $CMake)) { Write-Host "[build-lief] CMake not found at $CMake"; exit 1 }
if (-not (Test-Path $Toolchain)) { Write-Host "[build-lief] NDK toolchain not found at $Toolchain"; exit 1 }
if (-not (Test-Path $SrcDir)) { Write-Host "[build-lief] LIEF source not found at $SrcDir"; exit 1 }

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

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
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] CMake configure FAILED"; exit 1 }

Write-Host "[build-lief] Building LIEF for $Abi ..."
& $CMake --build "$BuildDir" --parallel 4 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] Build FAILED"; exit 1 }

Write-Host "[build-lief] Installing LIEF for $Abi ..."
& $CMake --install "$BuildDir" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-lief] Install FAILED"; exit 1 }

Write-Host "[build-lief] DONE — $Abi"
