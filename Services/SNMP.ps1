#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - SNMP Service (service: SNMP) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$P = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'

$Def = @{
    Name         = 'SNMP'
    Title        = 'SNMP Service'
    ServiceNames = @('SNMP', 'SNMPTRAP', 'SNMPTrap')
    Description  = @"
Simple Network Management Protocol - lets monitoring tools read (and with a
READ-WRITE community, change) system info: users, processes, installed
software, network config, open ports. Windows SNMP is v1/v2c only:
'community strings' are cleartext passwords.
  ValidCommunities : name -> rights (4=READ ONLY, 8=READ WRITE, 16=READ CREATE)
  PermittedManagers: which IPs may query (EMPTY = ANY host!)
Scoring checks usually do an snmpget with a known community.
"@
    Ports        = @(
        @{ Port = 161; Proto = 'UDP'; Use = 'SNMP agent (queries)' }
        @{ Port = 162; Proto = 'UDP'; Use = 'SNMP traps' }
    )
    KeyPaths     = @("$P\ValidCommunities".Replace('HKLM:', 'HKLM'), "$P\PermittedManagers".Replace('HKLM:', 'HKLM'), "$P\TrapConfiguration".Replace('HKLM:', 'HKLM'))
    RedTeam      = @(
        "Community 'public'/'private' -> snmpwalk dumps usernames (1.3.6.1.4.1.77.1.2.25), processes, software"
        'READ-WRITE community -> change config'
        'Empty PermittedManagers = query from anywhere'
    )
    Hardening    = @(
        'Keep the community the scoring engine uses (ask / check the packet), set it READ ONLY (4)'
        'Delete public / private / any RW community not required'
        'Set PermittedManagers to the scoring + monitoring IPs'
        'If SNMP is not scored: Stop-Service SNMP; Set-Service SNMP -StartupType Disabled'
    )
    Detect       = { Test-ServiceInstalled 'SNMP' }
}

$Def.InfoExtra = {
    $vc = Get-ItemProperty "$P\ValidCommunities" -ErrorAction SilentlyContinue
    $rights = @{ 1 = 'NONE'; 2 = 'NOTIFY'; 4 = 'READ ONLY'; 8 = 'READ WRITE'; 16 = 'READ CREATE' }
    Write-STEP "Communities"
    foreach ($c in $vc.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
        $l = "{0,-25} {1}" -f $c.Name, $rights[[int]$c.Value]
        if ($c.Value -ge 8 -or $c.Name -match '^(public|private)$') { Write-CRIT $l } else { Write-Plain $l }
    }
    $pm = Get-ItemProperty "$P\PermittedManagers" -ErrorAction SilentlyContinue
    $mgrs = $pm.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Value }
    if ($mgrs) { Write-OK "PermittedManagers: $($mgrs -join ', ')" } else { Write-CRIT "PermittedManagers EMPTY -> any host can query" }
    $tc = Get-ChildItem "$P\TrapConfiguration" -ErrorAction SilentlyContinue
    foreach ($t in $tc) { Write-Plain "Trap community $($t.PSChildName) -> $((Get-ItemProperty $t.PSPath).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object Value)" }
}

$Def.Backup = {
    param($Dir)
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters' "$Dir\reg\SNMP_Parameters.reg" | Out-Null
}

$Def.Restore = {
    param($Dir)
    # Delete current key first so communities added by red team do not survive the import
    Remove-Item "$P\ValidCommunities" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$P\PermittedManagers" -Recurse -Force -ErrorAction SilentlyContinue
    & reg.exe import "$Dir\reg\SNMP_Parameters.reg" 2>&1 | Out-Null
    Restart-Service SNMP -Force
    Write-OK "SNMP parameters restored exactly + service restarted"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
