param(
    [string]$Abi = "arm64-v8a",
    [string]$CrossFile = "",
    [string]$RizinSrc = "",
    [string]$NdkRoot = "",
    [string]$HostTools = "",
    [switch]$SkipPatch
)
$ErrorActionPreference = "Continue"
# 注意：不用 "Stop"。meson/ninja 正常工作时会向 stderr 写进度信息
# （例如 wrap 下载的 "From https://..."），在 PowerShell 5.1 下
# ErrorActionPreference=Stop 会把这类输出误报为 NativeCommandError 并
# 中断脚本。这里依赖显式的 $LASTEXITCODE 判断外部命令是否真正失败。

# build-rizin.ps1 — cross-compile Rizin static archives for one Android ABI
# using meson. Portability contract:
#   * Every path is resolved from $PSScriptRoot or from command-line args /
#     environment variables — no machine-specific hardcoded paths.
#   * The cross files in this repo (rizin-cross-*.ini) are TEMPLATES using
#     @NDK_ROOT@ / @HOST_TOOLS@ placeholders; this script substitutes the
#     real paths and writes concrete files into the meson build dir.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# This script lives at the repository root; the project dir IS the script dir.
$ProjectDir = $ScriptDir

function Get-WindowsPath([string]$p) { $p -replace '\\', '/' }
function Get-NdkRoot {
    if ($env:ANDROID_NDK_HOME -and (Test-Path $env:ANDROID_NDK_HOME)) { return $env:ANDROID_NDK_HOME }
    if ($env:ANDROID_HOME) {
        $ndkDir = Join-Path $env:ANDROID_HOME "ndk"
        if (Test-Path $ndkDir) {
            $cand = Get-ChildItem $ndkDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if ($cand) { return $cand.FullName }
        }
    }
    # Android Studio default install location on Windows
    $localNdk = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
    if (Test-Path $localNdk) {
        $cand = Get-ChildItem $localNdk -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { return $cand.FullName }
    }
    throw "[build-rizin] Cannot locate Android NDK. Set ANDROID_NDK_HOME / ANDROID_HOME or pass -NdkRoot <path>."
}
function Get-HostTools {
    if ($env:MINGW_HOME -and (Test-Path $env:MINGW_HOME)) { return $env:MINGW_HOME }
    if (Test-Path "C:\mingw64") { return "C:\mingw64" }
    $gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($gcc) { return (Split-Path -Parent $gcc.Source) -replace '\\bin$', '' }
    throw "[build-rizin] Cannot locate a MinGW-w64 host toolchain (needed to build meson host tools). Set MINGW_HOME or pass -HostTools <path>."
}

# --- Resolve Rizin source tree ---
if (-not $RizinSrc) { $RizinSrc = Join-Path $ProjectDir "third_party\rizin-src" }
if (-not (Test-Path (Join-Path $RizinSrc "librz\include"))) {
    Write-Host "[build-rizin] ERROR: Rizin source not found at '$RizinSrc' (missing librz/include)." -ForegroundColor Red
    Write-Host "[build-rizin] Clone it first:"
    Write-Host "    git clone https://github.com/rizinorg/rizin.git third_party/rizin-src"
    Write-Host "[build-rizin] or pass -RizinSrc <path> to point at an existing checkout."
    exit 1
}

# --- Resolve toolchains ---
if (-not $NdkRoot) { $NdkRoot = Get-NdkRoot }
if (-not (Test-Path "$NdkRoot\toolchains\llvm\prebuilt\windows-x86_64\bin")) {
    throw "[build-rizin] NDK root '$NdkRoot' has no windows-x86_64 llvm toolchain. Pass -NdkRoot <path>."
}
if (-not $HostTools) { $HostTools = Get-HostTools }
if (-not (Test-Path "$HostTools\bin\gcc.exe")) {
    throw "[build-rizin] Host tools '$HostTools' has no bin/gcc.exe. Pass -HostTools <path>."
}
# MinGW 编译的 host 工具运行期依赖 MinGW 的 DLL（libgcc_s_seh-1.dll 等），
# 必须把其 bin 目录前置到 PATH，否则 meson 的 build-machine sanity check
# 会因找不到运行库而失败（WinError 5 拒绝访问）。
$env:PATH = "$HostTools\bin;" + $env:PATH

# --- Rizin 源码 MinGW host 兼容补丁（幂等，逐文件） ---
# Rizin v0.10.0 的 Windows host 代码路径主要为 MSVC（_MSC_VER）设计：
# 若干源文件仅在 _MSC_VER 下包含/启用 Windows API 实现，而 host 编译器是
# MinGW（定义 __WINDOWS__ 而非 _MSC_VER）时这些符号未声明，native(host)
# 工具编译会失败；另有少量 MSVC secure-CRT（_s 系列）调用在 MinGW 下无
# 实现。rz_windows.h 本身支持 MinGW（内部条件为 __WINDOWS__ || _WIN32 ||
# _MSC_VER），因此大多数补丁只需放宽包含条件。所有补丁幂等（已打过则
# 跳过）；用 -SkipPatch 关闭。补丁条目类型：
#   Kind="Regex"       — From（正则）/ To（替换文本）
#   Kind="InsertAfter" — Anchor 行后插入 Insert 文本（Marker 用于幂等判断）
$secureCrtShim = @'

#if defined(__MINGW32__) && !defined(SOMCP_MINGW_SECURE_CRT_SHIM)
#define SOMCP_MINGW_SECURE_CRT_SHIM 1
/* MinGW secure-CRT shim: Rizin's __WINDOWS__ path calls MSVC-only _s functions. */
static int somcp_shim_wdupenv_s(wchar_t **s, size_t *n, const wchar_t *name) {
	DWORD sz = GetEnvironmentVariableW(name, NULL, 0);
	if (sz == 0) { if (s) *s = NULL; if (n) *n = 0; return -1; }
	if (s) { *s = malloc((sz + 1) * sizeof(wchar_t)); if (!*s) return -1; GetEnvironmentVariableW(name, *s, sz + 1); }
	if (n) *n = (size_t)sz;
	return 0;
}
static int somcp_shim_wputenv_s(const wchar_t *name, const wchar_t *value) {
	size_t nl = wcslen(name), vl = wcslen(value);
	wchar_t *buf = malloc((nl + vl + 2) * sizeof(wchar_t));
	if (!buf) return -1;
	swprintf(buf, nl + vl + 2, L"%ls=%ls", name, value);
	int r = _wputenv(buf);
	free(buf);
	return r;
}
#define _wdupenv_s(s, n, name) somcp_shim_wdupenv_s((s), (n), (name))
#define _wputenv_s(name, val) somcp_shim_wputenv_s((name), (val))
#define _chsize_s(fd, len) _chsize((fd), (long)(len))
#define _snwprintf_s(buf, cnt, sz, ...) swprintf((buf), (cnt), __VA_ARGS__)
#endif
'@
$rizinPatches = @(
    @{
        Path = "librz\util\file.c"
        Kind = "Regex"
        From = '(?m)^#if _MSC_VER\r?$'
        To   = '#if defined(_MSC_VER) || defined(__WINDOWS__)'
        Marker = '#if defined(_MSC_VER) || defined(__WINDOWS__)'
    },
    @{
        Path = "librz\util\time.c"
        Kind = "Regex"
        From = '(?m)^#ifdef _MSC_VER\r?$'
        To   = '#if defined(_MSC_VER) || defined(__WINDOWS__)'
        Marker = '#if defined(_MSC_VER) || defined(__WINDOWS__)'
    },
    @{
        # sys.c 有多处 #ifdef _MSC_VER；只放宽"MSVC 头文件包含块"的那一处
        # （psapi/dbghelp/process/direct，其中 process.h 提供 getpid——
        # MinGW 下同样需要），其余 _MSC_VER 分支不动。
        Path = "librz\util\sys.c"
        Kind = "Regex"
        From = '(?m)(#ifdef _MSC_VER\r?\n#include <psapi\.h>)'
        To   = "#if defined(_MSC_VER) || defined(__WINDOWS__)`n#include <psapi.h>"
        Marker = "#if defined(_MSC_VER) || defined(__WINDOWS__)`n#include <psapi.h>"
    },
    @{
        # MinGW 的 Interlocked* 内建要求 PVOID volatile*，Rizin 传入的是
        # RzThreadLock**；加显式 cast（subprocess.c 共 5 处调用）。
        Path = "librz\util\subprocess.c"
        Kind = "Regex"
        From = '(?m)InterlockedCompareExchangePointer\(&subproc_mutex,'
        To   = 'InterlockedCompareExchangePointer((PVOID volatile *)&subproc_mutex,'
        # Marker 含函数名，与下一条 Exchange 补丁的 Marker 互为区分。
        Marker = 'InterlockedCompareExchangePointer((PVOID volatile *)&subproc_mutex'
    },
    @{
        Path = "librz\util\subprocess.c"
        Kind = "Regex"
        From = '(?m)InterlockedExchangePointer\(&subproc_mutex,'
        To   = 'InterlockedExchangePointer((PVOID volatile *)&subproc_mutex,'
        # Marker 必须含函数名，与上一个补丁（CompareExchange）区分开，
        # 否则上一个补丁写入的 "(PVOID volatile *)&subproc_mutex" 会让本
        # 补丁被误判为"已应用"而永久跳过。
        Marker = 'InterlockedExchangePointer((PVOID volatile *)&subproc_mutex'
    },
    @{
        # MSVC secure-CRT（_wdupenv_s / _wputenv_s / _chsize_s / _snwprintf_s）
        # 在 MinGW 无实现；插入兼容 shim。sys.c 需在 rz_windows.h 之后
        # （#if __WINDOWS__ 块内）才可用 DWORD / GetEnvironmentVariableW。
        Path = "librz\util\sys.c"
        Kind = "InsertAfter"
        Anchor = "#include <VersionHelpers.h>"
        Marker = "SOMCP_MINGW_SECURE_CRT_SHIM"
        Insert = $secureCrtShim
    },
    @{
        Path = "librz\util\subprocess.c"
        Kind = "InsertAfter"
        Anchor = "#include <rz_windows.h>"
        Marker = "SOMCP_MINGW_SECURE_CRT_SHIM"
        Insert = $secureCrtShim
    }
)
if (-not $SkipPatch) {
    foreach ($p in $rizinPatches) {
        $target = Join-Path $RizinSrc $p.Path
        if (-not (Test-Path $target)) {
            Write-Host "[build-rizin] WARNING: $($p.Path) not found under $RizinSrc — skipping patch" -ForegroundColor Yellow
            continue
        }
        $orig = [System.IO.File]::ReadAllText($target)
        if ($p.Kind -eq "InsertAfter") {
            if ($orig.Contains($p.Marker)) {
                Write-Host "[build-rizin] $($p.Path) already patched (no-op)"
                continue
            }
            if (-not $orig.Contains($p.Anchor)) {
                Write-Host "[build-rizin] WARNING: anchor '$($p.Anchor)' not found in $($p.Path) — skipping" -ForegroundColor Yellow
                continue
            }
            $patched = $orig.Replace($p.Anchor, $p.Anchor + "`r`n" + $p.Insert)
        } else {
            # 三态：Marker 已存在 = 已应用过；From 能匹配 = 本次应用；
            # 两者都不满足 = 源码版本与 v0.10.0 不符，明确告警。
            if ($p.Marker -and $orig.Contains($p.Marker)) {
                Write-Host "[build-rizin] $($p.Path) already patched (no-op)"
                continue
            }
            $matchCount = [System.Text.RegularExpressions.Regex]::Matches($orig, $p.From).Count
            if ($matchCount -eq 0) {
                Write-Host "[build-rizin] WARNING: patch pattern not found in $($p.Path) — source may differ from Rizin v0.10.0" -ForegroundColor Yellow
                continue
            }
            $patched = [System.Text.RegularExpressions.Regex]::Replace($orig, $p.From, $p.To)
        }
        if ($patched -ne $orig) {
            [System.IO.File]::WriteAllText($target, $patched)
            Write-Host "[build-rizin] Patched $($p.Path) (MinGW host compat)" -ForegroundColor Yellow
        } else {
            Write-Host "[build-rizin] $($p.Path) already patched (no-op)"
        }
    }
}

# --- Map ABI to its cross-file template ---
$abiToCross = @{
    "arm64-v8a" = "rizin-cross-aarch64.ini"
    "armeabi-v7a" = "rizin-cross-armv7a.ini"
    "x86" = "rizin-cross-i686.ini"
    "x86_64" = "rizin-cross-x86_64.ini"
}
# ABI 白名单校验：防止 '..' 等路径穿越。$Abi 会拼进 Rename-Item /
# Join-Path 的构建目录路径；即使显式传入 -CrossFile 绕过下面的查表，
# 也必须先通过本校验。
if ($Abi -notmatch '^[a-zA-Z0-9_-]+$') {
    throw "[build-rizin] Invalid ABI '$Abi'. Allowed: alphanumeric, '_', '-' (e.g. arm64-v8a, armeabi-v7a, x86, x86_64)."
}
if (-not $CrossFile) { $CrossFile = $abiToCross[$Abi] }
if (-not $CrossFile) { throw "[build-rizin] Unknown ABI '$Abi'. Supported: $($abiToCross.Keys -join ', ')" }
$CrossTemplate = Join-Path $ScriptDir $CrossFile
# 防 -CrossFile 含 '..\' 或绝对路径读取仓库外模板喂给 meson：最终路径必须
# 落在 $ScriptDir 下。用规范化目录 + 尾部分隔符比较，防止 C:\SOMCP2\ 等
# 兄弟前缀目录绕过。
$sdFull = [System.IO.Path]::GetFullPath($ScriptDir).TrimEnd('\') + '\'
$crossFull = [System.IO.Path]::GetFullPath($CrossTemplate)
if (-not $crossFull.StartsWith($sdFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "[build-rizin] Cross-file must reside under $ScriptDir (got '$CrossFile')."
}
if (-not (Test-Path $CrossTemplate)) { throw "[build-rizin] Cross-file template not found: $CrossTemplate" }
$NativeTemplate = Join-Path $ScriptDir "rizin-native.ini"
if (-not (Test-Path $NativeTemplate)) { throw "[build-rizin] Native-file template not found: $NativeTemplate" }

# --- Prepare build dir ---
$buildRoot = Join-Path $ProjectDir "rizin-build"
$buildDir = Join-Path $buildRoot $Abi
if (Test-Path $buildDir) {
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    Rename-Item $buildDir "$Abi.old-$stamp"
}
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# --- Generate concrete cross/native files from templates ---
$ndkUnix = Get-WindowsPath $NdkRoot
$hostUnix = Get-WindowsPath $HostTools
# 防 meson ini 注入（CI 环境变量投毒场景）：NDK/MinGW 路径来自环境变量，
# 若含单引号/换行会被注入进 cross/native 文件的 [binaries] 键。
foreach ($v in @($ndkUnix, $hostUnix)) {
    if ($v -match "['`r`n]") {
        throw "[build-rizin] NDK/HostTools path contains characters unsafe for meson ini (' or newline): $v"
    }
}
$genCross = Join-Path $buildDir "cross-$Abi.ini"
$genNative = Join-Path $buildDir "native-$Abi.ini"
# WriteAllText 默认无 BOM 的 UTF-8：PS 5.1 的 Set-Content -Encoding UTF8
# 会写 BOM，meson 的 configparser 不剥离 BOM 会导致 MissingSectionHeaderError。
# 字面替换（非正则）：NDK/MinGW 路径可能包含 '$'（会被 -replace 当组引用）
# 或引号（破坏 meson ini 字符串边界）。
$crossContent = (Get-Content $CrossTemplate -Raw).Replace('@NDK_ROOT@', $ndkUnix)
$nativeContent = (Get-Content $NativeTemplate -Raw).Replace('@HOST_TOOLS@', $hostUnix)
[System.IO.File]::WriteAllText($genCross, $crossContent)
[System.IO.File]::WriteAllText($genNative, $nativeContent)
Write-Host "[build-rizin] NDK=$ndkUnix"
Write-Host "[build-rizin] HostTools=$hostUnix"
Write-Host "[build-rizin] RizinSrc=$RizinSrc"

Write-Host "[build-rizin] meson setup $buildDir ..."
& meson setup $buildDir (Get-WindowsPath $RizinSrc) --cross-file $genCross --native-file $genNative `
    -Dblob=true -Dstatic_runtime=true --default-library static -Duse_sys_capstone=disabled -Ddebugger=false -Dsubprojects_check=false 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-rizin] meson setup FAILED (exit $LASTEXITCODE)" -ForegroundColor Red; exit 1 }

Write-Host "[build-rizin] meson compile ..."
& meson compile -C $buildDir 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[build-rizin] meson compile FAILED (exit $LASTEXITCODE)" -ForegroundColor Red; exit 1 }

Write-Host "[build-rizin] DONE - $Abi archives at $buildDir"
