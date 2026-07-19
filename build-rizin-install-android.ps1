param(
    [string]$Abi = "arm64-v8a",
    [string]$CrossFile = "rizin-cross-aarch64.ini",
    [string]$Prefix = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VsShell = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"
& $VsShell -Arch amd64 -HostArch amd64
if ($LASTEXITCODE -ne 0) { throw "Failed to initialize MSVC shell" }

Set-Location $Root
if (!$Prefix) { $Prefix = Join-Path $Root "rizin-install\$Abi" }
$BuildDir = Join-Path $Root "rizin-build\$Abi-install"
$MesonPrefix = $Prefix.Replace("\", "/")
if ($MesonPrefix -match "^([A-Za-z]):/(.*)$") {
    $MesonPrefix = "/$($Matches[1].ToLower())/$($Matches[2])"
}

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

Write-Host "[build-rizin-install] prefix=$MesonPrefix"
meson setup $BuildDir "..\rizin-src" `
    --cross-file $CrossFile `
    --native-file rizin-native.ini `
    --prefix $MesonPrefix `
    --default-library shared `
    -Dblob=true `
    -Dstatic_runtime=false `
    -Duse_sys_capstone=disabled `
    -Ddebugger=true `
    -Denable_tests=false `
    -Denable_rz_test=false
if ($LASTEXITCODE -ne 0) { throw "Rizin meson setup failed" }

meson compile -C $BuildDir
if ($LASTEXITCODE -ne 0) { throw "Rizin compile failed" }

meson install -C $BuildDir
if ($LASTEXITCODE -ne 0) { throw "Rizin install failed" }

$Config = Join-Path $Prefix "lib\cmake\Rizin\RizinConfig.cmake"
if (!(Test-Path $Config)) { throw "RizinConfig.cmake was not installed at $Config" }
Write-Host "Rizin Android install SDK ready: $Prefix"
