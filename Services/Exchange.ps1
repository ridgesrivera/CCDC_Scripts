#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Microsoft Exchange Server info / configuration backup.
.DESCRIPTION
    Exchange is huge; a true mailbox-database backup needs Windows Server Backup
    (VSS, Exchange-aware) or New-MailboxExportRequest to a UNC share.
    This script backs up the CONFIGURATION you'd need to rebuild / diff:
      connectors, accepted domains, virtual directories (OWA/ECP/EWS URLs + auth),
      mailbox list + permissions, transport rules, inbox forwarding, certificates,
      and the web.config files of the Exchange web apps (webshell target #1).
    -ExportMailboxesTo \\server\share  will queue PST exports of every mailbox.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [string]$ExportMailboxesTo
)
. "$PSScriptRoot\_ServiceCommon.ps1"

function Connect-ExchangeShell {
    if (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) { return $true }
    $snap = 'Microsoft.Exchange.Management.PowerShell.SnapIn'
    try { Add-PSSnapin $snap -ErrorAction Stop; return $true } catch {}
    $rs = "$env:ExchangeInstallPath\bin\RemoteExchange.ps1"
    if (Test-Path $rs) { . $rs; Connect-ExchangeServer -auto -ClientApplication:ManagementShell | Out-Null; return [bool](Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) }
    return $false
}

$Def = @{
    Name         = 'Exchange'
    Title        = 'Microsoft Exchange Server'
    ServiceNames = @('MSExchangeIS', 'MSExchangeTransport', 'MSExchangeFrontEndTransport', 'MSExchangeServiceHost', 'MSExchangeADTopology', 'MSExchangeIMAP4', 'MSExchangePOP3', 'MSExchangeRPC')
    Description  = @"
Microsoft's enterprise mail / calendar server. Front end = IIS (OWA /owa,
ECP /ecp, EWS, ActiveSync, MAPI, Autodiscover) + transport (SMTP 25).
Deeply tied to AD (Exchange Windows Permissions group can grant DCSync!).
Install path: `$env:ExchangeInstallPath (usually C:\Program Files\Microsoft\
Exchange Server\V15). Mailbox data: .edb databases (Get-MailboxDatabase).
Historically THE most exploited Windows app (ProxyLogon/ProxyShell).
"@
    Ports        = @(
        @{ Port = 25; Proto = 'TCP'; Use = 'SMTP' }
        @{ Port = 587; Proto = 'TCP'; Use = 'SMTP submission' }
        @{ Port = 80; Proto = 'TCP'; Use = 'HTTP (redirects to OWA)' }
        @{ Port = 443; Proto = 'TCP'; Use = 'OWA/ECP/EWS/ActiveSync/MAPI' }
        @{ Port = 110; Proto = 'TCP'; Use = 'POP3 (if enabled)' }
        @{ Port = 995; Proto = 'TCP'; Use = 'POP3S' }
        @{ Port = 143; Proto = 'TCP'; Use = 'IMAP (if enabled)' }
        @{ Port = 993; Proto = 'TCP'; Use = 'IMAPS' }
        @{ Port = 444; Proto = 'TCP'; Use = 'Exchange Back End site' }
        @{ Port = 2525; Proto = 'TCP'; Use = 'Back-end transport' }
    )
    KeyPaths     = @("$env:ExchangeInstallPath", "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa", "$env:SystemDrive\inetpub\wwwroot\aspnet_client")
    RedTeam      = @(
        'Webshells in FrontEnd\HttpProxy\owa\auth\ , \ecp\ , inetpub\wwwroot\aspnet_client\'
        'Mailbox forwarding / inbox rules / transport rules for exfil'
        'Exchange Windows Permissions / Organization Management membership -> DCSync'
        'New-MailboxExportRequest abuse to steal mailboxes'
    )
    Hardening    = @(
        'Hunt *.aspx newer than install in owa\auth, ecp, aspnet_client'
        'Review Organization Management / Exchange Windows Permissions membership'
        'Remove unknown transport rules, forwarding SMTP addresses, inbox rules'
        'Disable POP/IMAP if not scored'
    )
    Detect       = { Test-ServiceInstalled 'MSExchangeServiceHost', 'MSExchangeIS', 'MSExchangeTransport' }
}

$Def.InfoExtra = {
    if (-not (Connect-ExchangeShell)) { Write-WARN "Could not load Exchange Management Shell"; return }
    Get-ExchangeServer | ForEach-Object { Write-INFO "$($_.Name) $($_.AdminDisplayVersion) roles: $($_.ServerRole)" }
    Get-AcceptedDomain | ForEach-Object { Write-Plain "Accepted domain: $($_.DomainName) ($($_.DomainType))" }
    Get-ReceiveConnector | ForEach-Object { $l = "Receive: $($_.Identity) bindings=$($_.Bindings -join ',') perms=$($_.PermissionGroups)"; if ($_.PermissionGroups -match 'Anonymous' -and $_.Identity -notmatch 'Default Frontend') { Write-WARN $l } else { Write-Plain $l } }
    Get-SendConnector | ForEach-Object { Write-Plain "Send: $($_.Identity) -> $($_.AddressSpaces -join ',') smarthosts=$($_.SmartHosts -join ',')" }
    Get-TransportRule -ErrorAction SilentlyContinue | ForEach-Object { Write-WARN "Transport rule: $($_.Name) state=$($_.State)" }
    Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | ForEach-Object { Write-CRIT "Forwarding: $($_.PrimarySmtpAddress) -> $($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" }
    foreach ($g in 'Organization Management', 'Exchange Windows Permissions', 'Exchange Trusted Subsystem') {
        try { Write-Plain ("{0,-32} {1}" -f $g, ((Get-ADGroupMember $g -ErrorAction Stop).SamAccountName -join ', ')) } catch {}
    }
    Write-STEP "Recent .aspx in common webshell locations"
    foreach ($p in "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth", "$env:ExchangeInstallPath\FrontEnd\HttpProxy\ecp\auth", "$env:SystemDrive\inetpub\wwwroot\aspnet_client") {
        Get-ChildItem $p -Recurse -Filter *.aspx -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-2) | ForEach-Object { Write-CRIT "$($_.LastWriteTime) $($_.FullName)" }
    }
}

$Def.Backup = {
    param($Dir)
    if (-not (Connect-ExchangeShell)) { Write-WARN "No Exchange shell - copying files only" }
    else {
        $c = Join-Path $Dir 'config'; New-Item -ItemType Directory $c -Force | Out-Null
        $exports = [ordered]@{
            ExchangeServer = { Get-ExchangeServer }; AcceptedDomain = { Get-AcceptedDomain }; EmailAddressPolicy = { Get-EmailAddressPolicy }
            ReceiveConnector = { Get-ReceiveConnector }; SendConnector = { Get-SendConnector }; TransportRule = { Get-TransportRule }
            OwaVirtualDirectory = { Get-OwaVirtualDirectory }; EcpVirtualDirectory = { Get-EcpVirtualDirectory }; WebServicesVirtualDirectory = { Get-WebServicesVirtualDirectory }
            ActiveSyncVirtualDirectory = { Get-ActiveSyncVirtualDirectory }; MapiVirtualDirectory = { Get-MapiVirtualDirectory }; OABVirtualDirectory = { Get-OabVirtualDirectory }
            ClientAccessService = { Get-ClientAccessService }; MailboxDatabase = { Get-MailboxDatabase -Status }; ExchangeCertificate = { Get-ExchangeCertificate }
            Mailbox = { Get-Mailbox -ResultSize Unlimited }; DistributionGroup = { Get-DistributionGroup -ResultSize Unlimited }
            RoleGroupMembers = { Get-RoleGroup | ForEach-Object { $g = $_; Get-RoleGroupMember $g | Select-Object @{n = 'RoleGroup'; e = { $g.Name } }, Name } }
            ImapSettings = { Get-ImapSettings }; PopSettings = { Get-PopSettings }
        }
        foreach ($k in $exports.Keys) {
            try { $o = & $exports[$k]; $o | Export-Clixml "$c\$k.xml"; $o | Format-List * | Out-File "$c\$k.txt" -Width 300; Write-OK "$k ($(@($o).Count))" } catch { Write-WARN "$k : $_" }
        }
        $perms = Get-Mailbox -ResultSize Unlimited | ForEach-Object { Get-MailboxPermission $_.Identity | Where-Object { -not $_.IsInherited -and $_.User -notmatch 'NT AUTHORITY\\SELF' } }
        $perms | Select-Object Identity, User, AccessRights | Export-Csv "$c\MailboxPermissions.csv" -NoTypeInformation
        if ($ExportMailboxesTo) {
            Write-INFO "Queuing PST exports to $ExportMailboxesTo (needs 'Mailbox Import Export' role + share writable by Exchange Trusted Subsystem)"
            Get-Mailbox -ResultSize Unlimited | ForEach-Object { New-MailboxExportRequest -Mailbox $_.Identity -FilePath "$ExportMailboxesTo\$($_.Alias).pst" -ErrorAction SilentlyContinue | Out-Null; Write-OK "queued $($_.Alias)" }
            Write-INFO "Track: Get-MailboxExportRequest | Get-MailboxExportRequestStatistics"
        }
    }
    # web.config + front-end files (diff later for webshells)
    foreach ($p in 'FrontEnd\HttpProxy', 'ClientAccess') { Copy-Tree "$env:ExchangeInstallPath\$p" (Join-Path $Dir "files_$($p -replace '\\','_')") "Exchange $p" -ExcludeFiles '*.dll', '*.log' -ExcludeDirs 'Logging', 'bin' | Out-Null }
    Copy-Item "$env:ExchangeInstallPath\Bin\EdgeTransport.exe.config" "$Dir\" -ErrorAction SilentlyContinue
    Write-WARN "Mailbox DATABASES are NOT copied (live .edb). For that: wbadmin start backup -include:<db volume> -vssFull, or -ExportMailboxesTo"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
