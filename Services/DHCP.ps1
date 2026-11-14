#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - DHCP Server (service: DHCPServer) info / backup / restore.
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
    Name         = 'DHCP'
    Title        = 'DHCP Server'
    ServiceNames = @('DHCPServer')
    Description  = @"
Hands out IP addresses, gateway and DNS server settings to clients.
Scopes = address ranges, Options = gateway (003) / DNS (006) / domain (015),
Reservations = fixed IPs for specific MACs (often the servers!).
If red team changes option 006 (DNS) or 003 (router) every client that
renews gets sent to the attacker. Database: %windir%\System32\dhcp\dhcp.mdb
"@
    Ports        = @(
        @{ Port = 67; Proto = 'UDP'; Use = 'DHCP server' }
        @{ Port = 68; Proto = 'UDP'; Use = 'DHCP client' }
        @{ Port = 547; Proto = 'UDP'; Use = 'DHCPv6 server' }
        @{ Port = 647; Proto = 'TCP'; Use = 'DHCP failover' }
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC (management)' }
    )
    KeyPaths     = @("$env:SystemRoot\System32\dhcp", 'HKLM\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters')
    RedTeam      = @(
        'Changing scope/server options 003 (router) or 006 (DNS) to attacker IPs'
        'Deleting reservations so servers get new IPs and scoring breaks'
        'Rogue DHCP server on the subnet (check: Get-DhcpServerInDC, and arp/nmap for other UDP 67 responders)'
        'DnsUpdateProxy / DHCP Administrators group abuse'
    )
    Hardening    = @(
        'Verify options 003/006/015 match the real router/DC'
        'Authorize only your DHCP server in AD'
        'Audit logging is on by default: %windir%\System32\dhcp\DhcpSrvLog-*.log'
    )
    Detect       = { Test-ServiceInstalled 'DHCPServer' }
}

$Def.InfoExtra = {
    if (-not (Get-Module -ListAvailable DhcpServer)) { Write-WARN "DhcpServer module missing"; return }
    Get-DhcpServerInDC -ErrorAction SilentlyContinue | ForEach-Object { Write-INFO "Authorized in AD: $($_.DnsName) $($_.IPAddress)" }
    Write-STEP "Server-level options"
    Get-DhcpServerv4OptionValue -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain ("{0,-4} {1,-20} {2}" -f $_.OptionId, $_.Name, ($_.Value -join ', ')) }
    foreach ($s in Get-DhcpServerv4Scope -ErrorAction SilentlyContinue) {
        Write-STEP "Scope $($s.ScopeId) '$($s.Name)' $($s.StartRange)-$($s.EndRange) State=$($s.State)"
        Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain ("opt {0,-4} {1,-20} {2}" -f $_.OptionId, $_.Name, ($_.Value -join ', ')) }
        $r = Get-DhcpServerv4Reservation -ScopeId $s.ScopeId -ErrorAction SilentlyContinue
        Write-Plain "Reservations: $(@($r).Count)   Leases: $(@(Get-DhcpServerv4Lease -ScopeId $s.ScopeId -ErrorAction SilentlyContinue).Count)"
    }
}

$Def.Backup = {
    param($Dir)
    Export-DhcpServer -File "$Dir\dhcp_export.xml" -Leases -Force -ErrorAction Stop
    Write-OK "Export-DhcpServer (scopes, options, reservations, leases) -> dhcp_export.xml"
    Backup-DhcpServer -Path "$Dir\dhcp_db_backup" -ErrorAction SilentlyContinue
    Write-OK "Backup-DhcpServer (database) -> dhcp_db_backup"
    & netsh dhcp server export "$Dir\netsh_dhcp_export.txt" all 2>&1 | Out-Null
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters' "$Dir\reg\DHCPServer_Parameters.reg" | Out-Null
}

$Def.Restore = {
    param($Dir)
    $bk = Join-Path $Dir 'restore_tmp'
    New-Item -ItemType Directory $bk -Force | Out-Null
    Import-DhcpServer -File "$Dir\dhcp_export.xml" -BackupPath $bk -Leases -ScopeOverwrite -Force -ErrorAction Stop
    Write-OK "Imported scopes/options/reservations/leases (pre-restore copy of current DB saved to $bk)"
    Restart-Service DHCPServer -Force
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
