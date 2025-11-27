@echo off
REM Designed for Microsoft Visual C++ Compiler (cl.exe)

setlocal enabledelayedexpansion

echo [*] NCRT v1.0 Build System
echo [*] Checking for Visual C++ compiler...

REM check for environment variables
if defined VCINSTALLDIR goto :compile
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    goto :compile
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
    goto :compile
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    goto :compile
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
    goto :compile
)

echo [!] Visual Studio not found. Attempting direct cl.exe invocation...
where cl.exe >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] ERROR: cl.exe not found. Please install Visual Studio C++ Build Tools.
    exit /b 1
)

:compile
echo [+] Compiler found. Starting compilation...

REM 
if not exist "obj" mkdir obj

echo.
echo [*] Compiling Source Files...

REM Compilation flags:
REM /O2  : Optimize for speed
REM /EHsc: Exception handling
REM /W4  : Warning level 4
REM /Fo  : Output directory for object files
REM /Fe  : Name of the executable
REM /std:c++17 : Use C++17 standard (optional but good practice)

set SOURCE_FILES=cpps\\main.cpp cpps\\utils.cpp cpps\\modules.cpp
set LIBS=ws2_32.lib iphlpapi.lib advapi32.lib shlwapi.lib netapi32.lib shell32.lib

REM Use /MT to statically link the C/C++ runtime into the EXE (no MSVCRT DLL dependency)
cl.exe /nologo /O2 /MT /EHsc /W4 /MP /I"headers" ^
    /Fo".\\obj\\" ^
    /Fe"kamos.exe" ^
    %SOURCE_FILES% ^
    /link %LIBS% /SUBSYSTEM:CONSOLE /MACHINE:X64

if %errorlevel% equ 0 (
    echo.
    echo [+] Compilation successful!
    echo [+] Output: NCRT.exe
    echo.
    REM 
    echo [*] Cleaning up object files...
    del /Q .\obj\*.*
    rmdir .\obj
    exit /b 0
) else (
    echo.
    echo [!] Compilation failed!
    exit /b 1)