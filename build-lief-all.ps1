$ErrorActionPreference = "Stop"
$ScriptPath = "c:\Users\15884\Downloads\somcp\android-native-mcp\build-lief.ps1"
foreach ($abi in @("arm64-v8a", "armeabi-v7a", "x86", "x86_64")) {
    Write-Host "=== Building LIEF for $abi ==="
    & powershell -ExecutionPolicy Bypass -File $ScriptPath -Abi $abi
    if ($LASTEXITCODE -ne 0) {
        throw "FAILED for $abi (exit $LASTEXITCODE)"
    } else {
        Write-Host "SUCCESS for $abi"
    }
}
Write-Host "=== All LIEF builds done ==="
