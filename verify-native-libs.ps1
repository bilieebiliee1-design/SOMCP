param(
    [string]$ReadElf = "$env:ANDROID_HOME\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ReadElf)) {
    $fallback = "$env:LOCALAPPDATA\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
    if (Test-Path $fallback) {
        $ReadElf = $fallback
    } else {
        throw "llvm-readelf.exe not found. Pass -ReadElf <path> or set ANDROID_HOME."
    }
}

$base = Join-Path $PSScriptRoot 'app\build\intermediates\stripped_native_libs\release\stripReleaseDebugSymbols\out\lib'
$abis = @('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')
$pattern = '^(rz_|Rz|ZSTD_|LZ4_|XXH_|sdb_|ht_|PJ_)'
$failed = $false

foreach ($abi in $abis) {
    $so = Join-Path $base "$abi\librz_native.so"
    if (-not (Test-Path $so)) {
        Write-Host "$abi MISSING $so" -ForegroundColor Red
        $failed = $true
        continue
    }

    $undef = & $ReadElf --dyn-syms $so |
        Select-String ' UND ' |
        ForEach-Object { ($_ -split '\s+')[-1] } |
        Sort-Object -Unique
    $bad = @($undef | Where-Object { $_ -match $pattern })

    if ($bad.Count -gt 0) {
        Write-Host "$abi BAD" -ForegroundColor Red
        $bad | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        $failed = $true
    } else {
        $sizeMb = [math]::Round((Get-Item $so).Length / 1MB, 2)
        Write-Host "$abi OK ($sizeMb MB)" -ForegroundColor Green
    }
}

if ($failed) {
    exit 1
}

Write-Host 'All native libraries passed unresolved-symbol checks.' -ForegroundColor Green
