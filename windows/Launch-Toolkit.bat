@echo off
REM Double-click (or right-click > Run as administrator) to open the CCDC Windows panel.
REM -ExecutionPolicy Bypass applies to THIS process only; it does not change the machine policy.
REM If Windows blocks the scripts as "downloaded from the internet", run once in PowerShell:
REM     Get-ChildItem -Recurse "%~dp0.." | Unblock-File
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-Toolkit.ps1" %*
pause
