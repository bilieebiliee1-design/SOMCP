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

# rz-ghidra (and everything else under third_party/) is provisioned by
# tools/init-submodules.sh and by nothing else. It is the only entry that knows
# how to take the nested rizinorg/ghidra pins: it fetches them by branch name,
# verifies the gitlink SHA locally (falling back to a bare-SHA fetch), and names
# the fix when the pin is gone. `git submodule update --recursive` reports such a
# pin as `upload-pack: not our ref` with no clue what to do.
#
# There used to be a `git clone --depth 1` here first. It was wrong in an ugly
# way: the script it hands off to resets third_party/rz-ghidra to the
# superproject gitlink, so that clone only decided *which commit that reset
# started from*, and the two fetch_pin calls below read rz-ghidra's own HEAD.
# The net effect was a silent move of third_party/rz-ghidra off its pin before
# building it. Deleting the clone removes that whole class of confusion (and the
# "shallow clone handed to the script" combination with it) - the script builds
# the directory from the gitlink, which is the only authority we have.
#
# Cost of reusing that single entry: it initialises all 10 top-level submodules,
# not just rz-ghidra, so a standalone run here waits minutes longer than the old
# rz-ghidra-only `git submodule update` did.
# Not validated: PowerShell is not available where this was written, so the
# route from here into the bash script has not been executed - see CHANGELOG.
$Bash = Get-Command bash -ErrorAction SilentlyContinue
if (!$Bash) {
    throw "bash is required to initialise submodules (tools/init-submodules.sh). Install Git Bash / WSL and re-run."
}
& $Bash.Source (Join-Path $Root "tools/init-submodules.sh")
if ($LASTEXITCODE -ne 0) { throw "tools/init-submodules.sh failed with exit code $LASTEXITCODE" }

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
