param(
    [string]$RizinSrc = "",
    [string]$NdkRoot = "",
    [string]$HostTools = ""
)
$ErrorActionPreference = "Continue"
$ScriptPath = Join-Path $PSScriptRoot "build-rizin.ps1"
$jobs = @(
    @{ Abi = "arm64-v8a"; Cross = "rizin-cross-aarch64.ini" }
    @{ Abi = "armeabi-v7a"; Cross = "rizin-cross-armv7a.ini" }
    @{ Abi = "x86"; Cross = "rizin-cross-i686.ini" }
    @{ Abi = "x86_64"; Cross = "rizin-cross-x86_64.ini" }
)
$common = @()
if ($RizinSrc) { $common += @("-RizinSrc", $RizinSrc) }
if ($NdkRoot) { $common += @("-NdkRoot", $NdkRoot) }
if ($HostTools) { $common += @("-HostTools", $HostTools) }
foreach ($job in $jobs) {
    Write-Host "=== Building Rizin for $($job.Abi) ==="
    & powershell -ExecutionPolicy Bypass -File $ScriptPath -Abi $job.Abi -CrossFile $job.Cross @common
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED for $($job.Abi) (exit $LASTEXITCODE)" -ForegroundColor Red
    } else {
        Write-Host "SUCCESS for $($job.Abi)"
    }
}
Write-Host "=== All Rizin builds done ==="
