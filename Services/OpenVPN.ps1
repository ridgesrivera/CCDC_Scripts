#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - OpenVPN on Windows (OpenVPNService / OpenVPN Access Server client) info / backup / restore.
.DESCRIPTION
    Backup includes keys/certs inside the config folder - sensitive.
    NOTE: do NOT touch the competition's own VPN agent (e.g. NetBird / jump box VPN)
    - it is how the scoring engine and your team reach the box.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$CfgDirs = @("$env:ProgramFiles\OpenVPN\config", "$env:ProgramFiles\OpenVPN\config-auto", "$env:ProgramFiles\OpenVPN\easy-rsa\pki", "$env:USERPROFILE\OpenVPN\config")

$Def = @{
    Name         = 'OpenVPN'
    Title        = 'OpenVPN (Windows)'
    ServiceNames = @('OpenVPNService', 'OpenVPNServiceInteractive', 'OpenVPNServiceLegacy', 'ovpnconnect*')
    Description  = @"
TLS-based VPN. On Windows it is usually a SERVER (config-auto\*.ovpn started
by OpenVPNService) or a client that connects this box to another site.
Config: Program Files\OpenVPN\config(-auto)\*.ovpn  + ca.crt / server.crt /
server.key / ta.key / dh.pem. easy-rsa\pki holds the CA private key if the
CA was built on this box. Server listens UDP 1194 by default (check 'port'
and 'proto' lines).
"@
    Ports        = @(
        @{ Port = 1194; Proto = 'TCP/UDP'; Use = 'OpenVPN default' }
        @{ Port = 443; Proto = 'TCP'; Use = 'OpenVPN over TCP 443 (common)' }
    )
    KeyPaths     = $CfgDirs + @('HKLM\SOFTWARE\OpenVPN')
    RedTeam      = @(
        'Stealing client .ovpn + keys = VPN access to the inside network'
        'Adding a client cert / using an existing one; script-security 2 + up/down scripts = code exec'
        'client-to-client / push "route" changes to pivot'
    )
    Hardening    = @(
        'Remove "script-security 2" / up / down / client-connect lines you did not add'
        'Revoke unknown client certs (easy-rsa revoke + crl-verify)'
        'Keep keys ACL-restricted to Administrators'
    )
    Detect       = { (Test-ServiceInstalled 'OpenVPNService', 'OpenVPNServiceInteractive', 'OpenVPNServiceLegacy') -or (Test-Path "$env:ProgramFiles\OpenVPN") }
}

$Def.InfoExtra = {
    foreach ($d in $CfgDirs) {
        if (-not (Test-Path $d)) { continue }
        foreach ($f in Get-ChildItem $d -Filter *.ovpn -Recurse -ErrorAction SilentlyContinue) {
            Write-STEP $f.FullName
            Get-Content $f.FullName | Where-Object { $_ -match '^\s*(port|proto|dev|server|remote|push|client-to-client|duplicate-cn|script-security|up|down|client-connect|auth-user-pass-verify|crl-verify|tls-auth|tls-crypt|cipher|data-ciphers)\b' } |
                ForEach-Object { if ($_ -match 'script-security\s+[23]|^\s*(up|down|client-connect|auth-user-pass-verify)\b|duplicate-cn') { Write-WARN $_ } else { Write-Plain $_ } }
        }
    }
}

$Def.Backup = {
    param($Dir)
    $i = 0
    foreach ($d in $CfgDirs) { $i++; Copy-Tree $d (Join-Path $Dir "cfg_$i`_$(Split-Path $d -Leaf)") "OpenVPN $d" | Out-Null }
    Export-RegKey 'HKLM\SOFTWARE\OpenVPN' "$Dir\reg\OpenVPN.reg" | Out-Null
}

$Def.Restore = {
    param($Dir)
    foreach ($b in Get-ChildItem $Dir -Directory -Filter 'cfg_*') { Restore-Tree $b.FullName }
    if (Test-Path "$Dir\reg\OpenVPN.reg") { & reg.exe import "$Dir\reg\OpenVPN.reg" 2>&1 | Out-Null }
    foreach ($s in 'OpenVPNService', 'OpenVPNServiceLegacy') { if (Get-Service $s -ErrorAction SilentlyContinue) { Restart-Service $s -Force; Write-OK "Restarted $s" } }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
