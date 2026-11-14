#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Windows Defender Firewall (service: MpsSvc) info / backup / restore.
.DESCRIPTION
    Backup = netsh advfirewall export (.wfw, the native full-fidelity format) + CSV of rules.
    Restore = netsh advfirewall import  (REPLACES all local rules - GPO rules unaffected).
    TIP: take a backup BEFORE running ..\08_Firewall.ps1, so a bad rule is one command to undo.
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
    Name         = 'WindowsFirewall'
    Title        = 'Windows Defender Firewall'
    ServiceNames = @('MpsSvc', 'BFE')
    Description  = @"
Host firewall. Three profiles (Domain / Private / Public); which one applies
depends on the network the NIC is on (Get-NetConnectionProfile). Rules come
from local store + Group Policy (GPO rules win and cannot be removed locally).
BFE (Base Filtering Engine) must be running or the firewall AND IPsec stop.
"@
    Ports        = @()
    KeyPaths     = @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy', 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall')
    RedTeam      = @(
        'netsh advfirewall set allprofiles state off'
        'Allow-any inbound rules with innocent names ("Windows Update", "Core Networking")'
        'Allow rules for their C2 binary / port (e.g. 4444, 8443, 1337)'
        'Stopping BFE/MpsSvc'
    )
    Hardening    = @(
        'All profiles ON, default inbound Block'
        'Delete inbound allow rules for ports you do not serve'
        'Enable logging: Set-NetFirewallProfile -All -LogBlocked True -LogAllowed True -LogFileName %windir%\System32\LogFiles\Firewall\pfirewall.log'
        'Run ..\08_Firewall.ps1 for team-specific lockdown'
    )
    Detect       = { Test-ServiceInstalled 'MpsSvc' }
}

$Def.InfoExtra = {
    foreach ($p in Get-NetFirewallProfile) {
        $l = "{0,-8} Enabled={1,-5} In={2,-6} Out={3,-6} LogBlocked={4} Log={5}" -f $p.Name, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction, $p.LogBlocked, $p.LogFileName
        if (-not $p.Enabled -or $p.DefaultInboundAction -eq 'Allow') { Write-CRIT $l } else { Write-Plain $l }
    }
    Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { Write-INFO "NIC $($_.InterfaceAlias) on '$($_.Name)' uses profile $($_.NetworkCategory)" }
    Write-STEP "Enabled inbound ALLOW rules with a specific local port (what the box exposes)"
    foreach ($r in Get-FwInboundRules | Where-Object { $_.Rule.Action -eq 'Allow' -and $_.LocalPort -and ($_.LocalPort -join '') -notmatch '^(Any|RPC|RPCEPMap|IPHTTPSIn|PlayToDiscovery|Teredo)$' } | Sort-Object { $_.LocalPort[0] }) {
        Write-Plain ("{0,-16} {1,-5} {2}" -f ($r.LocalPort -join ','), $r.Protocol, $r.Rule.DisplayName)
    }
    Write-STEP "Rules created/changed recently are not timestamped - diff against a backup with -Action Restore (shows changes) or compare rules.csv"
    $susp = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.DisplayName -notmatch '@' -and -not $_.Group -and $_.Owner -eq $null }
    foreach ($s in $susp | Select-Object -First 40) {
        $pf = $s | Get-NetFirewallPortFilter; $af = $s | Get-NetFirewallApplicationFilter
        Write-WARN ("Custom rule: {0,-40} port={1} prog={2}" -f $s.DisplayName, ($pf.LocalPort -join ','), $af.Program)
    }
}

$Def.Backup = {
    param($Dir)
    & netsh advfirewall export "$Dir\firewall.wfw" | Out-Null
    if (Test-Path "$Dir\firewall.wfw") { Write-OK "netsh advfirewall export -> firewall.wfw" } else { Write-WARN "netsh export failed" }
    Get-NetFirewallProfile | Export-Clixml "$Dir\profiles.xml"
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
    $pfs = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pfs[$_.InstanceID] = $_ }
    $afs = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $afs[$_.InstanceID] = $_ }
    $apps = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $apps[$_.InstanceID] = $_ }
    $rules | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name; DisplayName = $_.DisplayName; Group = $_.DisplayGroup; Enabled = $_.Enabled; Direction = $_.Direction; Action = $_.Action; Profile = $_.Profile
            Protocol = $pfs[$_.InstanceID].Protocol; LocalPort = ($pfs[$_.InstanceID].LocalPort -join ','); RemotePort = ($pfs[$_.InstanceID].RemotePort -join ',')
            RemoteAddress = ($afs[$_.InstanceID].RemoteAddress -join ','); Program = $apps[$_.InstanceID].Program; PolicyStore = $_.PolicyStoreSourceType
        }
    } | Export-Csv "$Dir\rules.csv" -NoTypeInformation
    Write-OK "rules.csv: $(@($rules).Count) rules"
}

$Def.Restore = {
    param($Dir)
    Write-STEP "Rules that exist now but not in the backup"
    $old = (Import-Csv "$Dir\rules.csv").Name
    Get-NetFirewallRule | Where-Object { $old -notcontains $_.Name } | ForEach-Object { Write-WARN "will be removed: $($_.DisplayName) [$($_.Direction) $($_.Action)]" }
    & netsh advfirewall export "$env:TEMP\pre_restore_$($script:CCDCStamp).wfw" | Out-Null
    Write-INFO "Current policy saved to $env:TEMP\pre_restore_$($script:CCDCStamp).wfw"
    & netsh advfirewall import "$Dir\firewall.wfw"
    if ($LASTEXITCODE -eq 0) { Write-OK "Firewall policy imported" } else { Write-WARN "netsh import exit $LASTEXITCODE" }
    Start-Service BFE, MpsSvc -ErrorAction SilentlyContinue
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
