@echo off
:: Run this on each target machine via GPO Startup Script,
:: SCCM, or Intune Win32 App deployment

set MSI_PATH=\\server\share\USBMonitor.msi
set LOG=C:\Windows\Temp\usbmonitor_install.log

echo Installing USB Monitor...
msiexec /i "%MSI_PATH%" /quiet /norestart /log "%LOG%"

if %errorlevel% equ 0 (
    echo [OK] Install succeeded.
) else (
    echo [FAIL] Install failed. Check %LOG%
)