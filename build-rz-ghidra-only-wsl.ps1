param(
    [string]$Distro = "Ubuntu-22.04",
    [string]$Abi = "arm64-v8a"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootFull = [System.IO.Path]::GetFullPath($Root)
if ($RootFull -notmatch "^([A-Za-z]):\\(.*)$") { throw "Unsupported Windows path: $RootFull" }
$RootWsl = "/mnt/$($Matches[1].ToLower())/$($Matches[2].Replace('\', '/'))"

$Script = @"
set -euo pipefail
export PATH="`$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
cd '$RootWsl'
export ANDROID_NDK_HOME="`$HOME/android-sdk/ndk/29.0.14206865"
test -f "rizin-sdk/${Abi}-wsl/lib/cmake/Rizin/RizinConfig.cmake"
cmake -S third_party/rz-ghidra -B third_party/rz-ghidra-build-${Abi}-wsl -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="`$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=${Abi} \
  -DANDROID_PLATFORM=android-23 \
  -DCMAKE_PREFIX_PATH="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake" \
  -DCMAKE_FIND_ROOT_PATH="$RootWsl/rizin-sdk/${Abi}-wsl" \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH \
  -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH \
  -DRizin_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/Rizin" \
  -Drz_core_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_core" \
  -Drz_analysis_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_analysis" \
  -Drz_arch_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_arch" \
  -Drz_asm_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_asm" \
  -Drz_bin_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_bin" \
  -Drz_config_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_config" \
  -Drz_cons_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_cons" \
  -Drz_flag_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_flag" \
  -Drz_io_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_io" \
  -Drz_util_DIR="$RootWsl/rizin-sdk/${Abi}-wsl/lib/cmake/rz_util" \
  -DCMAKE_INSTALL_PREFIX="$RootWsl/third_party/rz-ghidra-install-${Abi}-wsl" \
  -DBUILD_CUTTER_PLUGIN=OFF \
  -DBUILD_SLEIGH_PLUGIN=OFF \
  -DRZ_GHIDRA_HOST_SLEIGHC="$RootWsl/third_party/rz-ghidra-host-build/ghidra/sleighc" \
  -DUSE_SYSTEM_ZLIB=OFF
cmake --build third_party/rz-ghidra-build-${Abi}-wsl --config Release -j "`$(nproc)"
cmake --install third_party/rz-ghidra-build-${Abi}-wsl
"@

$TempScript = Join-Path $Root ".build-rz-ghidra-only-wsl.tmp.sh"
[System.IO.File]::WriteAllText($TempScript, ($Script -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
wsl -d $Distro bash "$RootWsl/.build-rz-ghidra-only-wsl.tmp.sh"
