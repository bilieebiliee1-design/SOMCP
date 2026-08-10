param(
    [string]$CMake = "",
    [string]$Ninja = "",
    [string]$NdkRoot = ""
)
$ErrorActionPreference = "Stop"
$ScriptPath = Join-Path $PSScriptRoot "build-lief.ps1"
$common = @()
if ($CMake) { $common += @("-CMake", $CMake) }
if ($Ninja) { $common += @("-Ninja", $Ninja) }
if ($NdkRoot) { $common += @("-NdkRoot", $NdkRoot) }
foreach ($abi in @("arm64-v8a", "armeabi-v7a", "x86", "x86_64")) {
    Write-Host "=== Building LIEF for $abi ==="
    & powershell -ExecutionPolicy Bypass -File $ScriptPath -Abi $abi @common
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED for $abi (exit $LASTEXITCODE)" -ForegroundColor Red; exit 1 }
}
Write-Host "=== All LIEF builds done ==="
