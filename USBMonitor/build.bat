@echo off
setlocal

:: ── Find MSVC automatically ──────────────────────────────────────────────────
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set VS_PATH=%%i
)

if not defined VS_PATH (
    echo [ERROR] Visual Studio / Build Tools not found.
    exit /b 1
)

:: Load MSVC environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

:: Load MSVC environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

:: ── Add WiX to PATH ──────────────────────────────────────────────────────────
set WIX_PATH=C:\Program Files (x86)\WiX Toolset v3.14\bin
set PATH=%WIX_PATH%;%PATH%

:: ── Directories ──────────────────────────────────────────────────────────────
set SRC=src
set OUT=build
set INSTALLER=Installer

if not exist %OUT% mkdir %OUT%

:: ── Compile ───────────────────────────────────────────────────────────────────
echo [1/3] Compiling service.cpp...
cl /EHsc /O2 /W3 ^
   /I"%SRC%" ^
   %SRC%\service.cpp ^
   /Fe:%OUT%\USBMonitor.exe ^
   /link setupapi.lib ^
        user32.lib ^
        advapi32.lib ^
        uuid.lib
   
if %errorlevel% neq 0 (
    echo [FAIL] Compilation failed.
    exit /b 1
)
echo [OK] USBMonitor.exe built.

echo [1.5/3] Compiling UI...
cl /EHsc /O2 /W3 ^
   /I"%SRC%" ^
   %SRC%\monitor_ui.cpp ^
   /Fe:%OUT%\USBMonitorUI.exe ^
   /link comctl32.lib user32.lib shell32.lib gdi32.lib
if %errorlevel% neq 0 (
    echo [FAIL] UI compilation failed.
    exit /b 1
)
echo [OK] USBMonitorUI.exe built.

:: ── Build MSI ─────────────────────────────────────────────────────────────────
echo [2/3] Building MSI installer...
candle %INSTALLER%\installer.wxs -o %OUT%\installer.wixobj
if %errorlevel% neq 0 (
    echo [FAIL] candle failed.
    exit /b 1
)

light %OUT%\installer.wixobj -o %OUT%\USBMonitor.msi
if %errorlevel% neq 0 (
    echo [FAIL] light failed.
    exit /b 1
)
echo [OK] USBMonitor.msi built.

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo [3/3] Build complete.
echo   EXE: %OUT%\USBMonitor.exe
echo   MSI: %OUT%\USBMonitor.msi
echo.
echo To install and start the service:
echo   msiexec /i build\USBMonitor.msi /quiet
echo.
echo To test WITHOUT installing (run as admin):
echo   build\USBMonitor.exe
pause