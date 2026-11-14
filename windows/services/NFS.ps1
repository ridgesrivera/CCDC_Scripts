#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Server for NFS on Windows (service: NfsService) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force,
    [switch]$SkipContent
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'NFS'
    Title        = 'Server for NFS'
    ServiceNames = @('NfsService', 'NfsServer', 'RpcBind', 'NfsRdr')
    Description  = @"
Network File System - Unix/Linux style file sharing from a Windows server
(role FS-NFS-Service). Linux boxes mount it (mount -t nfs server:/share).
Access is by client IP / host (client groups) and Unix UID/GID mapping, not
Windows passwords - so 'AllowRootAccess' + 'All Machines' = anyone on the
network is root on that share.
"@
    Ports        = @(
        @{ Port = 2049; Proto = 'TCP/UDP'; Use = 'NFS' }
        @{ Port = 111; Proto = 'TCP/UDP'; Use = 'Portmapper / rpcbind' }
        @{ Port = 1048; Proto = 'TCP/UDP'; Use = 'mountd (Windows default)' }
        @{ Port = 1047; Proto = 'TCP/UDP'; Use = 'NSM statd' }
        @{ Port = 1039; Proto = 'TCP/UDP'; Use = 'NLM lockd' }
    )
    KeyPaths     = @('HKLM\SYSTEM\CurrentControlSet\Services\NfsServer\Parameters', 'HKLM\SOFTWARE\Microsoft\ServerForNFS')
    RedTeam      = @(
        'showmount -e server -> mount share read/write from anywhere'
        'AllowRootAccess -> write files as root, plant SSH keys / webshells if share overlaps web root'
        'UnmappedUserAccess / anonymous access'
    )
    Hardening    = @(
        'Restrict each share to specific client IPs (New-NfsClientgroup / Grant-NfsSharePermission)'
        'Disable root access and anonymous access unless scoring needs it'
    )
    Detect       = { Test-ServiceInstalled 'NfsService' }
}

$Def.InfoExtra = {
    if (-not (Get-Command Get-NfsShare -ErrorAction SilentlyContinue)) { Write-WARN "NFS cmdlets missing"; & nfsshare 2>$null; return }
    foreach ($s in Get-NfsShare) {
        $l = "{0,-20} {1,-30} anon={2} unmapped={3} auth={4}" -f $s.Name, $s.Path, $s.AnonymousAccess, $s.UnmappedUserAccess, ($s.Authentication -join ',')
        if ($s.AnonymousAccess -or $s.UnmappedUserAccess) { Write-WARN $l } else { Write-Plain $l }
        foreach ($p in Get-NfsSharePermission -Name $s.Name -ErrorAction SilentlyContinue) {
            $pl = "   {0,-25} {1,-10} perm={2} root={3}" -f $p.ClientName, $p.ClientType, $p.Permission, $p.AllowRootAccess
            if ($p.AllowRootAccess -or $p.ClientName -eq 'All Machines') { Write-WARN $pl } else { Write-Plain $pl }
        }
    }
    Get-NfsMountedClient -ErrorAction SilentlyContinue | ForEach-Object { Write-INFO "Mounted by: $($_.ClientIpAddress)" }
}

$Def.Backup = {
    param($Dir)
    $shares = foreach ($s in Get-NfsShare) {
        [pscustomobject]@{ Share = $s; Perms = @(Get-NfsSharePermission -Name $s.Name -ErrorAction SilentlyContinue) }
    }
    $shares | Export-Clixml "$Dir\nfs_shares.xml" -Depth 5
    Get-NfsServerConfiguration -ErrorAction SilentlyContinue | Export-Clixml "$Dir\nfs_server_config.xml"
    Get-NfsClientgroup -ErrorAction SilentlyContinue | Export-Clixml "$Dir\nfs_clientgroups.xml"
    & nfsshare > "$Dir\nfsshare.txt" 2>&1
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\NfsServer\Parameters' "$Dir\reg\NfsServer.reg" | Out-Null
    Write-OK "NFS share definitions: $(@($shares).Count)"
    if (-not $SkipContent) { foreach ($s in $shares) { Copy-Tree $s.Share.Path (Join-Path $Dir "content\$($s.Share.Name)") "NFS share $($s.Share.Name)" | Out-Null } }
}

$Def.Restore = {
    param($Dir)
    foreach ($s in Import-Clixml "$Dir\nfs_shares.xml") {
        $sh = $s.Share
        if (Test-Path (Join-Path $Dir "content\$($sh.Name)")) { Restore-Tree (Join-Path $Dir "content\$($sh.Name)") $sh.Path }
        if (Get-NfsShare -Name $sh.Name -ErrorAction SilentlyContinue) { Remove-NfsShare -Name $sh.Name -Confirm:$false }
        New-NfsShare -Name $sh.Name -Path $sh.Path -Authentication $sh.Authentication -EnableAnonymousAccess $sh.AnonymousAccess -EnableUnmappedAccess $sh.UnmappedUserAccess -ErrorAction SilentlyContinue | Out-Null
        foreach ($p in $s.Perms) {
            Grant-NfsSharePermission -Name $sh.Name -ClientName $p.ClientName -ClientType $p.ClientType -Permission $p.Permission -AllowRootAccess $p.AllowRootAccess -ErrorAction SilentlyContinue
        }
        Write-OK "Recreated NFS share $($sh.Name) with backed-up permissions"
    }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
