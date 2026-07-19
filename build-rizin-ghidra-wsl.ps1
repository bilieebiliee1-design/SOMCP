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
if ! command -v ninja >/dev/null 2>&1 || ! command -v cmake >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1; then
  echo "Missing WSL apt dependencies. Install them first: sudo apt update && sudo apt install -y python3-pip cmake ninja-build git build-essential pkg-config"
  exit 2
fi
if ! command -v meson >/dev/null 2>&1; then
  python3 -m pip install --user meson
  export PATH="`$HOME/.local/bin:`$PATH"
fi
command -v meson >/dev/null 2>&1 || { echo "meson is still unavailable after pip install"; exit 2; }
if [ ! -d third_party/rz-ghidra ]; then
  git clone --depth 1 https://github.com/rizinorg/rz-ghidra.git third_party/rz-ghidra
fi
git -C third_party/rz-ghidra submodule update --init --recursive --depth 1
cat > rizin-cross-aarch64-wsl.ini <<EOF
[binaries]
c = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang'
cpp = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++'
ar = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar'
strip = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip'
ranlib = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib'
ld = '`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld'
pkg-config = 'false'

[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'

[built-in options]
c_args = ['-fPIC', '-O2', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections']
cpp_args = ['-fPIC', '-O2', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-std=c++17', '-fexceptions', '-frtti']
c_link_args = ['-Wl,--gc-sections', '-Wl,--icf=safe']
cpp_link_args = ['-Wl,--gc-sections', '-Wl,--icf=safe']
EOF
rm -rf rizin-build/${Abi}-install-wsl rizin-install/${Abi}-wsl
meson setup rizin-build/${Abi}-install-wsl ../rizin-src \
  --cross-file rizin-cross-aarch64-wsl.ini \
  --prefix "$RootWsl/rizin-install/${Abi}-wsl" \
  --default-library shared \
  -Dblob=true \
  -Dstatic_runtime=false \
  -Duse_sys_capstone=disabled \
  -Ddebugger=true \
  -Denable_tests=false \
  -Denable_rz_test=false
meson compile -C rizin-build/${Abi}-install-wsl
meson install -C rizin-build/${Abi}-install-wsl
cmake -S third_party/rz-ghidra -B third_party/rz-ghidra-build-${Abi}-wsl -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=${Abi} \
  -DANDROID_PLATFORM=android-23 \
  -DCMAKE_PREFIX_PATH="$RootWsl/rizin-install/${Abi}-wsl" \
  -DCMAKE_INSTALL_PREFIX="$RootWsl/third_party/rz-ghidra-install-${Abi}-wsl" \
  -DBUILD_CUTTER_PLUGIN=OFF \
  -DBUILD_SLEIGH_PLUGIN=OFF \
  -DUSE_SYSTEM_ZLIB=OFF
cmake --build third_party/rz-ghidra-build-${Abi}-wsl --config Release -j "`$(nproc)"
cmake --install third_party/rz-ghidra-build-${Abi}-wsl
"@

$TempScript = Join-Path $Root ".build-rizin-ghidra-wsl.tmp.sh"
[System.IO.File]::WriteAllText($TempScript, ($Script -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
$TempScriptWsl = "$RootWsl/.build-rizin-ghidra-wsl.tmp.sh"
wsl -d $Distro bash $TempScriptWsl
