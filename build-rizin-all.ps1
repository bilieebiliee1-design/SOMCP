$ErrorActionPreference = "Continue"
$ScriptPath = "c:\Users\15884\Downloads\somcp\android-native-mcp\build-rizin.ps1"
$jobs = @(
    @{ Abi = "armeabi-v7a"; Cross = "rizin-cross-armv7a.ini" }
    @{ Abi = "x86"; Cross = "rizin-cross-i686.ini" }
    @{ Abi = "x86_64"; Cross = "rizin-cross-x86_64.ini" }
)
foreach ($job in $jobs) {
    Write-Host "=== Building Rizin for $($job.Abi) ==="
    & powershell -ExecutionPolicy Bypass -File $ScriptPath -Abi $job.Abi -CrossFile $job.Cross
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED for $($job.Abi) (exit $LASTEXITCODE)"
    } else {
        Write-Host "SUCCESS for $($job.Abi)"
    }
}
Write-Host "=== All Rizin builds done ==="
