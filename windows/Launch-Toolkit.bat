@echo off
REM CCDC Blue Team Toolkit - Windows panel launcher.
REM Double-click it. It asks for administrator rights, unblocks the scripts
REM (Windows marks downloaded files), then opens the panel.
REM -ExecutionPolicy Bypass applies to THIS process only; the machine policy is not changed.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell.exe -NoProfile -Command "exit $PSVersionTable.PSVersion.Major" >nul 2>&1
if %errorlevel% lss 3 (
    echo.
    echo  This box has PowerShell 2. The toolkit needs PowerShell 3 or newer.
    echo  Install WMF 5.1 ^(KB3191566 for 2008 R2 / 7, needs .NET 4.5^) and reboot,
    echo  or use the manual commands in docs\first-15-minutes-windows.md.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0..' -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-Toolkit.ps1" %*
if %errorlevel% neq 0 pause
