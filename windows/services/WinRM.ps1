#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Windows Remote Management / PowerShell Remoting (service: WinRM) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'WinRM'
    Title        = 'WinRM / PowerShell Remoting'
    ServiceNames = @('WinRM')
    Description  = @"
Remote command execution over HTTP(S): Enter-PSSession, Invoke-Command,
evil-winrm, Ansible. On by default on Server 2012+. Members of local
Administrators and 'Remote Management Users' can connect.
Config lives in the WSMan: drive / HKLM\SOFTWARE\Microsoft\Windows\
CurrentVersion\WSMAN. PSSession configurations decide who can use which
endpoint (Get-PSSessionConfiguration).
"@
    Ports        = @(
        @{ Port = 5985; Proto = 'TCP'; Use = 'WinRM HTTP' }
        @{ Port = 5986; Proto = 'TCP'; Use = 'WinRM HTTPS' }
        @{ Port = 47001; Proto = 'TCP'; Use = 'WinRM local listener' }
    )
    KeyPaths     = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN')
    RedTeam      = @(
        'evil-winrm with stolen creds / NTLM hash (pass-the-hash)'
        'Adding users to Remote Management Users'
        'AllowUnencrypted=true + Basic auth -> creds in cleartext'
        'TrustedHosts=* on clients'
        'Custom PSSession configuration with RunAs credentials (persistence/privesc)'
    )
    Hardening    = @(
        'If WinRM is NOT scored and you do not use it: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled'
        'Otherwise: AllowUnencrypted=false, Basic=false, restrict 5985 by firewall to your team IPs'
        'Empty Remote Management Users unless needed'
        'Enable PowerShell script block logging (EventID 4104) to see what they run'
    )
    Detect       = { Test-ServiceInstalled 'WinRM' }
}

$Def.InfoExtra = {
    if ((Get-Service WinRM).Status -ne 'Running') { Write-INFO "WinRM not running"; return }
    Write-STEP "Listeners"
    Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue | ForEach-Object {
        $l = $_; $k = @{}; Get-ChildItem $l.PSPath | ForEach-Object { $k[$_.Name] = $_.Value }
        Write-Plain ("{0,-6} port {1,-6} address {2}  enabled {3}" -f $k.Transport, $k.Port, $k.Address, $k.Enabled)
    }
    $svc = @{}; Get-ChildItem WSMan:\localhost\Service -ErrorAction SilentlyContinue | ForEach-Object { $svc[$_.Name] = $_.Value }
    $auth = @{}; Get-ChildItem WSMan:\localhost\Service\Auth -ErrorAction SilentlyContinue | ForEach-Object { $auth[$_.Name] = $_.Value }
    if ($svc.AllowUnencrypted -eq 'true') { Write-CRIT "Service AllowUnencrypted = true" } else { Write-OK "AllowUnencrypted = false" }
    if ($auth.Basic -eq 'true') { Write-WARN "Basic auth enabled" }
    $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ($th) { Write-WARN "Client TrustedHosts = $th" }
    Write-STEP "Remote Management Users"
    Get-LocalGroupMember 'Remote Management Users' -ErrorAction SilentlyContinue | ForEach-Object { Write-WARN $_.Name }
    Write-STEP "PSSession configurations"
    Get-PSSessionConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
        $line = "{0,-40} RunAs:{1}  Perm: {2}" -f $_.Name, $_.RunAsUser, $_.Permission
        if ($_.RunAsUser -or $_.Name -notmatch '^microsoft\.(powershell|powershell32|powershell\.workflow|windows\.servermanagerworkflows)$') { Write-WARN $line } else { Write-Plain $line }
    }
    Show-RecentEvents -LogName 'Microsoft-Windows-WinRM/Operational' -Ids 91, 142, 169 -Max 8
}

$Def.Backup = {
    param($Dir)
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN' "$Dir\reg\WSMAN.reg" | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM' "$Dir\reg\WinRM_Policies.reg" | Out-Null
    & winrm get winrm/config > "$Dir\winrm_config.txt" 2>&1
    & winrm enumerate winrm/config/listener > "$Dir\winrm_listeners.txt" 2>&1
    Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Select-Object Name, Permission, RunAsUser, SecurityDescriptorSddl | Export-Csv "$Dir\pssession_configs.csv" -NoTypeInformation
    Get-LocalGroupMember 'Remote Management Users' -ErrorAction SilentlyContinue | Select-Object Name, @{n = 'SID'; e = { $_.SID.Value } } | Export-Csv "$Dir\remote_management_users.csv" -NoTypeInformation
}

$Def.Restore = {
    param($Dir)
    Stop-Service WinRM -Force
    & reg.exe import "$Dir\reg\WSMAN.reg" 2>&1 | Out-Null
    Start-Service WinRM
    Write-OK "WSMAN registry restored + WinRM restarted"
    $known = (Import-Csv "$Dir\pssession_configs.csv").Name
    Get-PSSessionConfiguration | Where-Object { $known -notcontains $_.Name } | ForEach-Object { Write-CRIT "New PSSession config '$($_.Name)' -> Unregister-PSSessionConfiguration -Name '$($_.Name)'" }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
