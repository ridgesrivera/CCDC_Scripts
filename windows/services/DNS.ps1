#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - DNS Server (service: DNS) info / backup / restore.
.EXAMPLE
    .\DNS.ps1                      # info + backup
    .\DNS.ps1 -Action Info
    .\DNS.ps1 -Action Restore      # restore latest backup (asks YES)
    .\DNS.ps1 -Action Restore -RestoreFrom C:\ccdc\backups\services\DNS\20261114_090102
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$DnsDir = "$env:SystemRoot\System32\dns"

$Def = @{
    Name         = 'DNS'
    Title        = 'DNS Server'
    ServiceNames = @('DNS')
    Description  = @"
Resolves names to IPs for the whole network. On a domain controller DNS is
REQUIRED for Active Directory: clients find DCs through SRV records
(_ldap._tcp.dc._msdcs.<domain>), so if DNS dies, logons, GPO, Kerberos and
almost every service that uses a hostname die with it.
Zones are either file-backed (%windir%\System32\dns\*.dns) or AD-integrated
(stored in the DomainDnsZones / ForestDnsZones partitions of AD).
Clients (and monitoring) check DNS by resolving records you own: keep them correct.
"@
    Ports        = @(
        @{ Port = 53; Proto = 'TCP/UDP'; Use = 'DNS queries / zone transfers (TCP)' }
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC endpoint mapper (DNS MMC / dnscmd)' }
    )
    KeyPaths     = @(
        $DnsDir
        'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones'
    )
    RedTeam      = @(
        'Deleting / changing A records for scored hosts (service looks "down" but box is fine)'
        'Adding a wildcard (*) record or rogue record to redirect traffic'
        'Changing forwarders to an attacker resolver'
        'Allowing zone transfers to Any -> full network map for red team'
        'DnsAdmins group member loads a DLL into dns.exe as SYSTEM (ServerLevelPluginDll)'
        'Dynamic update set to Nonsecure -> anyone can register records'
    )
    Hardening    = @(
        'Zone transfers: only to listed servers or none (Set-DnsServerPrimaryZone -SecureSecondaries NoTransfer)'
        'Dynamic updates: Secure only for AD-integrated zones'
        'Check HKLM\...\DNS\Parameters\ServerLevelPluginDll is EMPTY'
        'Keep DnsAdmins group empty'
        'Disable recursion if this server is not a resolver for clients (careful - breaks internet lookups)'
    )
    Detect       = { Test-ServiceInstalled 'DNS' }
}

$Def.InfoExtra = {
    $plugin = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -ErrorAction SilentlyContinue).ServerLevelPluginDll
    if ($plugin) { Write-CRIT "ServerLevelPluginDll is set: $plugin  (DnsAdmins privesc / persistence!)" } else { Write-OK "No ServerLevelPluginDll" }

    try { $dnsAdm = Get-ADGroupMember DnsAdmins -ErrorAction Stop; if ($dnsAdm) { Write-WARN "DnsAdmins members: $($dnsAdm.SamAccountName -join ', ')" } else { Write-OK "DnsAdmins is empty" } } catch {}

    if (-not (Get-Module -ListAvailable DnsServer)) { Write-WARN "DnsServer PowerShell module missing - use dnscmd /enumzones"; & dnscmd /enumzones; return }
    Import-Module DnsServer -ErrorAction SilentlyContinue

    $fw = Get-DnsServerForwarder -ErrorAction SilentlyContinue
    Write-INFO "Forwarders: $(($fw.IPAddress.IPAddressToString) -join ', ')"
    $rec = Get-DnsServerRecursion -ErrorAction SilentlyContinue
    Write-INFO "Recursion enabled: $($rec.Enable)"

    Write-STEP "Zones"
    foreach ($z in Get-DnsServerZone -ErrorAction SilentlyContinue) {
        $xfer = $z.SecureSecondaries
        $line = "{0,-40} {1,-10} AD:{2,-5} DynUpdate:{3,-15} Xfer:{4}" -f $z.ZoneName, $z.ZoneType, $z.IsDsIntegrated, $z.DynamicUpdate, $xfer
        if ($xfer -eq 'TransferAnyServer' -or $z.DynamicUpdate -eq 'NonsecureAndSecure') { Write-WARN $line } else { Write-Plain $line }
        if (-not $z.IsReverseLookupZone -and -not $z.IsAutoCreated -and $z.ZoneName -notmatch '^(_msdcs|TrustAnchors)') {
            $wild = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -Name '*' -ErrorAction SilentlyContinue
            if ($wild) { Write-CRIT "  Wildcard record in $($z.ZoneName): $($wild.RecordData.IPv4Address)" }
            $a = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -RRType A -ErrorAction SilentlyContinue
            Write-Plain "  A records: $(@($a).Count)  e.g. $(($a | Select-Object -First 6 | ForEach-Object { "$($_.HostName)=$($_.RecordData.IPv4Address)" }) -join '  ')"
        }
    }
    Show-RecentEvents -LogName 'DNS Server' -Max 8
}

$Def.Backup = {
    param($Dir)
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $zoneDir = Join-Path $Dir 'zones'
    New-Item -ItemType Directory $zoneDir -Force | Out-Null
    $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }

    $meta = @()
    foreach ($z in $zones) {
        $fn = "ccdc_$($script:CCDCStamp)_$($z.ZoneName).dns"
        # Export-DnsServerZone writes into %windir%\System32\dns - then move it out
        try {
            Export-DnsServerZone -Name $z.ZoneName -FileName $fn -ErrorAction Stop
            Move-Item (Join-Path $DnsDir $fn) (Join-Path $zoneDir "$($z.ZoneName).dns") -Force
            Write-OK "Zone file: $($z.ZoneName)"
        } catch {
            & dnscmd /zoneexport $z.ZoneName $fn 2>&1 | Out-Null
            if (Test-Path (Join-Path $DnsDir $fn)) { Move-Item (Join-Path $DnsDir $fn) (Join-Path $zoneDir "$($z.ZoneName).dns") -Force; Write-OK "Zone file (dnscmd): $($z.ZoneName)" }
            else { Write-WARN "Could not export $($z.ZoneName): $_" }
        }
        Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction SilentlyContinue |
            Select-Object HostName, RecordType, TimeToLive, @{n = 'Data'; e = {
                $d = $_.RecordData; ($d.IPv4Address, $d.IPv6Address, $d.HostNameAlias, $d.NameServer, $d.MailExchange, $d.DomainName, $d.PtrDomainName, ($d.DescriptiveText -join ' ')) | Where-Object { $_ } | Select-Object -First 1 } } |
            Export-Csv (Join-Path $zoneDir "$($z.ZoneName).records.csv") -NoTypeInformation
        $meta += $z | Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsReverseLookupZone, SecureSecondaries, ZoneFile, MasterServers
    }
    $meta | Export-Clixml (Join-Path $Dir 'zones.xml')
    $meta | Format-Table -AutoSize | Out-String -Width 300 | Out-File (Join-Path $Dir 'zones.txt')

    Get-DnsServer -ErrorAction SilentlyContinue | Export-Clixml (Join-Path $Dir 'DnsServerConfig.xml')
    Get-DnsServerForwarder -ErrorAction SilentlyContinue | Export-Clixml (Join-Path $Dir 'forwarders.xml')
    & dnscmd /info > (Join-Path $Dir 'dnscmd_info.txt') 2>&1

    Copy-Tree $DnsDir (Join-Path $Dir 'System32_dns') 'DNS directory (file-backed zones, cache.dns)' | Out-Null
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters' (Join-Path $Dir 'reg\DNS_Parameters.reg') | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server' (Join-Path $Dir 'reg\DNS_Server.reg') | Out-Null
}

$Def.Restore = {
    param($Dir)
    Import-Module DnsServer -ErrorAction Stop
    $meta = Import-Clixml (Join-Path $Dir 'zones.xml')
    foreach ($z in $meta) {
        $src = Join-Path $Dir "zones\$($z.ZoneName).dns"
        if (-not (Test-Path $src)) { Write-WARN "No zone file for $($z.ZoneName)"; continue }
        if ($z.ZoneType -ne 'Primary') { Write-INFO "Skipping non-primary zone $($z.ZoneName) ($($z.ZoneType))"; continue }
        $existing = Get-DnsServerZone -Name $z.ZoneName -ErrorAction SilentlyContinue
        if ($existing) {
            if (-not (Confirm-Action "Zone $($z.ZoneName) exists. DELETE it and reload from backup?")) { continue }
            Remove-DnsServerZone -Name $z.ZoneName -Force -ErrorAction SilentlyContinue
        }
        $fname = "$($z.ZoneName).dns"
        Copy-Item $src (Join-Path $DnsDir $fname) -Force
        try {
            Add-DnsServerPrimaryZone -Name $z.ZoneName -ZoneFile $fname -LoadExisting -ErrorAction Stop
            if ($z.IsDsIntegrated) {
                ConvertTo-DnsServerPrimaryZone -Name $z.ZoneName -ReplicationScope $z.ReplicationScope -Force -ErrorAction Stop
            }
            if ($z.DynamicUpdate) { Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate $z.DynamicUpdate -ErrorAction SilentlyContinue }
            Write-OK "Restored zone $($z.ZoneName) (AD-integrated: $($z.IsDsIntegrated))"
        } catch { Write-WARN "Restore of $($z.ZoneName) failed: $_" }
    }
    $fw = Import-Clixml (Join-Path $Dir 'forwarders.xml') -ErrorAction SilentlyContinue
    if ($fw.IPAddress) { Set-DnsServerForwarder -IPAddress $fw.IPAddress -ErrorAction SilentlyContinue; Write-OK "Forwarders restored" }
    Restart-Service DNS -Force
    Write-INFO "Test: Resolve-DnsName <host>.<zone> -Server 127.0.0.1"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
