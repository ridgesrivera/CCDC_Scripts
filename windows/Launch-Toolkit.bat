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
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0..' -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-Toolkit.ps1" %*
if %errorlevel% neq 0 pause
