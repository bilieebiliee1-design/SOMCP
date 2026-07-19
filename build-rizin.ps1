param([string]$Abi = "arm64-v8a", [string]$CrossFile = "rizin-cross-aarch64.ini")
$ErrorActionPreference = "Stop"
$VsShell = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"
Write-Host "[build-rizin] Setting up MSVC environment for $Abi ..."
& $VsShell -Arch amd64 -HostArch amd64
if ($LASTEXITCODE -ne 0) { Write-Host "[build-rizin] FAILED to init MSVC"; exit 1 }
Set-Location "c:\Users\15884\Downloads\somcp\android-native-mcp"
$buildDir = "rizin-build\$Abi"
if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue }
if (Test-Path $buildDir) { Start-Sleep -Seconds 2; Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue }
if (Test-Path $buildDir) { Rename-Item $buildDir "${buildDir}.old" -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
Write-Host "[build-rizin] meson setup $buildDir ..."
& meson setup $buildDir "../rizin-src" --cross-file $CrossFile --native-file rizin-native.ini -Dblob=true -Dstatic_runtime=true --default-library static -Duse_sys_capstone=disabled -Ddebugger=false 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-rizin] meson setup FAILED"; exit 1 }
Write-Host "[build-rizin] meson compile ..."
& meson compile -C $buildDir 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-rizin] meson compile FAILED"; exit 1 }
Write-Host "[build-rizin] DONE — $Abi"
