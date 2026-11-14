#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Print Spooler / Print Server (service: Spooler) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$PrintBrm = "$env:SystemRoot\System32\spool\tools\PrintBrm.exe"

$Def = @{
    Name         = 'PrintSpooler'
    Title        = 'Print Spooler / Print Server'
    ServiceNames = @('Spooler')
    Description  = @"
Manages printers, print queues and printer drivers. A print SERVER shares
printers over SMB (\\server\printer). Drivers live in
C:\Windows\System32\spool\drivers. The spooler runs as SYSTEM and loads
driver DLLs -> PrintNightmare (CVE-2021-34527), SpoolFool, PrinterBug
(coerces the box to authenticate to the attacker - used for NTLM relay /
unconstrained delegation attacks against DCs).
"@
    Ports        = @(
        @{ Port = 445; Proto = 'TCP'; Use = 'SMB (shared printers, MS-RPRN over named pipe)' }
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC' }
        @{ Port = 9100; Proto = 'TCP'; Use = 'Raw / JetDirect (printer side)' }
        @{ Port = 515; Proto = 'TCP'; Use = 'LPD (LPDSVC role)' }
        @{ Port = 631; Proto = 'TCP'; Use = 'IPP' }
    )
    KeyPaths     = @("$env:SystemRoot\System32\spool\drivers", 'HKLM\SYSTEM\CurrentControlSet\Control\Print')
    RedTeam      = @(
        'PrintNightmare: add a malicious "driver" -> SYSTEM code exec (local + remote)'
        'PrinterBug / SpoolSample coercion of DC authentication'
        'Malicious port monitor DLL (HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors) = persistence as SYSTEM'
    )
    Hardening    = @(
        'On DCs and servers that do not print: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled'
        'Point and Print: RestrictDriverInstallationToAdministrators=1 (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint)'
        'Review Print\Monitors and Print\Environments\...\Print Processors for unknown DLLs (Info output)'
    )
    Detect       = { Test-ServiceInstalled 'Spooler' }
}

$Def.InfoExtra = {
    if (Test-IsDomainController) { Write-WARN "This is a DC - Spooler should be DISABLED unless scored" }
    $pp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue
    if ($pp.RestrictDriverInstallationToAdministrators -ne 1) { Write-WARN "RestrictDriverInstallationToAdministrators not set (PrintNightmare)" }
    if ($pp.NoWarningNoElevationOnInstall -eq 1) { Write-CRIT "NoWarningNoElevationOnInstall=1 (PrintNightmare wide open)" }
    Write-STEP "Printers"
    Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain ("{0,-35} shared={1,-5} driver={2} port={3}" -f $_.Name, $_.Shared, $_.DriverName, $_.PortName) }
    Write-STEP "Port monitors (DLLs loaded by the SYSTEM spooler)"
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | ForEach-Object {
        $d = (Get-ItemProperty $_.PSPath).Driver
        $p = "$env:SystemRoot\System32\$d"
        $sig = if ($d -and (Test-Path $p)) { (Get-AuthenticodeSignature $p).Status } else { 'n/a' }
        $l = "{0,-35} {1} [{2}]" -f $_.PSChildName, $d, $sig
        if ($sig -notin 'Valid', 'n/a') { Write-CRIT $l } else { Write-Plain $l }
    }
    Write-STEP "Third-party drivers"
    Get-PrinterDriver -ErrorAction SilentlyContinue | Where-Object { $_.Manufacturer -notmatch 'Microsoft' } | ForEach-Object { Write-WARN "$($_.Name)  ($($_.Manufacturer))" }
}

$Def.Backup = {
    param($Dir)
    if (Test-Path $PrintBrm) {
        & $PrintBrm -B -F "$Dir\printers.printerExport" -O FORCE 2>&1 | Select-Object -Last 2 | ForEach-Object { Write-Plain $_ }
        if (Test-Path "$Dir\printers.printerExport") { Write-OK "PrintBrm export (queues, drivers, ports, settings)" }
    } else { Write-WARN "PrintBrm.exe missing" }
    Get-Printer -ErrorAction SilentlyContinue | Export-Clixml "$Dir\printers.xml"
    Get-PrinterPort -ErrorAction SilentlyContinue | Export-Clixml "$Dir\ports.xml"
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Print' "$Dir\reg\Control_Print.reg" | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' "$Dir\reg\Printers_Policies.reg" | Out-Null
}

$Def.Restore = {
    param($Dir)
    if ((Test-Path $PrintBrm) -and (Test-Path "$Dir\printers.printerExport")) {
        & $PrintBrm -R -F "$Dir\printers.printerExport" -O FORCE
        Write-OK "PrintBrm restore done"
    }
    if (Test-Path "$Dir\reg\Printers_Policies.reg") { & reg.exe import "$Dir\reg\Printers_Policies.reg" 2>&1 | Out-Null; Write-OK "Printer policies restored" }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
