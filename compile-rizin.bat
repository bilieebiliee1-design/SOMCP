@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul 2>&1
cd /d "c:\Users\15884\Downloads\somcp\android-native-mcp"
meson compile -C "rizin-build\arm64-v8a" -v > rizin-compile-verbose.txt 2>&1
echo Exit code: %ERRORLEVEL%
