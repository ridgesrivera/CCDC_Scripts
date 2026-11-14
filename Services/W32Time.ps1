#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Windows Time (service: W32Time) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'W32Time'
    Title        = 'Windows Time (NTP)'
    ServiceNames = @('W32Time')
    Description  = @"
Keeps the clock in sync. Kerberos FAILS if a client and the DC differ by more
than 5 minutes - so a red team clock change = nobody can log in, and
"everything is broken" for no obvious reason. Domain members sync from a DC;
the PDC emulator syncs from an external source (or its own clock).
Also matters for log timelines in your incident reports.
"@
    Ports        = @(@{ Port = 123; Proto = 'UDP'; Use = 'NTP' })
    KeyPaths     = @('HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters', 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config')
    RedTeam      = @('Change system time or NtpServer -> Kerberos breaks domain-wide', 'Stop W32Time')
    Hardening    = @('w32tm /resync /force on clients after fixing the DC', 'DCs: w32tm /config /syncfromflags:domhier /update (non-PDC)')
    Detect       = { Test-ServiceInstalled 'W32Time' }
}

$Def.InfoExtra = {
    Write-INFO "Local time: $(Get-Date)  (UTC $((Get-Date).ToUniversalTime()))"
    & w32tm /query /status 2>&1 | ForEach-Object { Write-Plain $_ }
    & w32tm /query /source 2>&1 | ForEach-Object { Write-Plain "source: $_" }
    if (-not (Test-IsDomainController)) {
        $dc = $env:LOGONSERVER -replace '\\', ''
        if ($dc) { & w32tm /stripchart /computer:$dc /samples:1 /dataonly 2>&1 | Select-Object -Last 1 | ForEach-Object { Write-Plain "offset vs $dc : $_" } }
    }
}

$Def.Backup = {
    param($Dir)
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time' "$Dir\reg\W32Time.reg" | Out-Null
    & w32tm /query /configuration > "$Dir\w32tm_configuration.txt" 2>&1
}

$Def.Restore = {
    param($Dir)
    & reg.exe import "$Dir\reg\W32Time.reg" 2>&1 | Out-Null
    Restart-Service W32Time -Force
    & w32tm /resync /force | Out-Null
    Write-OK "W32Time config restored + resynced"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
