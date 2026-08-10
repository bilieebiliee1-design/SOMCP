@echo off
rem Incremental meson compile of the Rizin arm64-v8a build directory.
rem Run build-rizin.ps1 first to configure the build dir, then use this to
rem re-run the compile after touching rizin sources (skips meson re-setup).
rem Host toolchain (MinGW or MSVC) must be on PATH or in VS dev environment.
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"
if not exist "rizin-build\arm64-v8a\build.ninja" (
    echo [compile-rizin] rizin-build\arm64-v8a not configured.
    echo [compile-rizin] Run: .\build-rizin.ps1 -Abi arm64-v8a
    exit /b 1
)
meson compile -C "rizin-build\arm64-v8a" -v > rizin-compile-verbose.txt 2>&1
echo Exit code: %ERRORLEVEL%
