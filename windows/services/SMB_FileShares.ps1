#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - SMB File Server (service: LanmanServer) info / backup / restore.
.DESCRIPTION
    Backs up: share definitions (registry + XML), share permissions, NTFS ACLs,
    SMB server configuration, and the CONTENTS of every non-default share.
.EXAMPLE
    .\SMB_FileShares.ps1
    .\SMB_FileShares.ps1 -Action Backup -SkipContent        # definitions only (fast)
    .\SMB_FileShares.ps1 -Action Restore                    # recreate missing shares + restore files
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force,
    [switch]$SkipContent,
    [switch]$Mirror,
    [int]$MaxShareGB = 20
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'SMB'
    Title        = 'SMB File Sharing (Server service)'
    ServiceNames = @('LanmanServer')
    Description  = @"
Windows file and printer sharing. Users map drives (\\server\share), the DC
serves SYSVOL/NETLOGON over it, and admins use C$/ADMIN$ for remote admin
(PsExec, wmiexec, smbexec all ride on 445). Share definitions live in
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares.
Two permission layers: SHARE permissions AND NTFS permissions - the most
restrictive wins. Scoring usually logs in as a user and reads/writes a file.
"@
    Ports        = @(
        @{ Port = 445; Proto = 'TCP'; Use = 'SMB direct' }
        @{ Port = 139; Proto = 'TCP'; Use = 'SMB over NetBIOS' }
        @{ Port = 137; Proto = 'UDP'; Use = 'NetBIOS name service' }
        @{ Port = 138; Proto = 'UDP'; Use = 'NetBIOS datagram' }
    )
    KeyPaths     = @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares', 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters')
    RedTeam      = @(
        'Lateral movement with stolen creds: PsExec / smbexec / wmiexec via ADMIN$ / C$ / IPC$'
        'Exfil of PII/CSV files from shares (sensitive-file deduction)'
        'Share set to Everyone:Full -> drop malware / ransomware the share'
        'SMBv1 enabled -> EternalBlue (MS17-010) on old boxes'
        'NTLM relay when SMB signing is not required'
        'Null sessions / anonymous share enumeration'
    )
    Hardening    = @(
        'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
        'Require signing: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force  (test scoring!)'
        'Remove Everyone/Guest/Anonymous from share + NTFS perms'
        'RestrictNullSessAccess=1, RestrictAnonymous=1'
        'Firewall 445 to internal subnets only'
    )
    Detect       = { Test-ServiceInstalled 'LanmanServer' }
}

$DefaultShares = '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$'

$Def.InfoExtra = {
    $c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($c) {
        if ($c.EnableSMB1Protocol) { Write-CRIT "SMBv1 ENABLED" } else { Write-OK "SMBv1 disabled" }
        if ($c.RequireSecuritySignature) { Write-OK "SMB signing required" } else { Write-WARN "SMB signing NOT required (NTLM relay risk)" }
        Write-INFO "EncryptData=$($c.EncryptData)  RejectUnencryptedAccess=$($c.RejectUnencryptedAccess)  AutoShareServer=$($c.AutoShareServer)"
    }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    Write-INFO "RestrictAnonymous=$($lsa.RestrictAnonymous)  EveryoneIncludesAnonymous=$($lsa.EveryoneIncludesAnonymous)"
    Write-STEP "Shares"
    foreach ($s in Get-SmbShare -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-18} {1,-35} {2}" -f $s.Name, $s.Path, $s.Description) -ForegroundColor $(if ($s.Name -match $DefaultShares) { 'DarkGray' } else { 'White' })
        foreach ($a in Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue) {
            $line = "share-perm: {0,-35} {1,-6} {2}" -f $a.AccountName, $a.AccessControlType, $a.AccessRight
            if ($a.AccountName -match 'Everyone|Guest|ANONYMOUS|Authenticated Users' -and $a.AccessRight -match 'Full|Change') { Write-WARN "   $line" } else { Write-Plain "   $line" }
        }
    }
    Write-STEP "Open SMB sessions (who is connected right now)"
    Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain ("{0,-22} {1,-30} opens={2} dialect={3}" -f $_.ClientComputerName, $_.ClientUserName, $_.NumOpens, $_.Dialect) }
    Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object { Write-Plain ("open: {0,-25} {1}" -f $_.ClientUserName, $_.Path) }
}

$Def.Backup = {
    param($Dir)
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares' "$Dir\reg\LanmanServer_Shares.reg" | Out-Null
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' "$Dir\reg\LanmanServer_Parameters.reg" | Out-Null
    Get-SmbServerConfiguration | Export-Clixml "$Dir\SmbServerConfiguration.xml"
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch $DefaultShares -and $_.Path }
    $out = foreach ($s in $shares) {
        [pscustomobject]@{
            Name = $s.Name; Path = $s.Path; Description = $s.Description; FolderEnumerationMode = "$($s.FolderEnumerationMode)"
            CachingMode = "$($s.CachingMode)"; EncryptData = $s.EncryptData
            Access = @(Get-SmbShareAccess -Name $s.Name | Select-Object AccountName, AccessControlType, AccessRight)
        }
    }
    $out | Export-Clixml "$Dir\shares.xml" -Depth 5
    $out | Select-Object Name, Path, Description | Export-Csv "$Dir\shares.csv" -NoTypeInformation
    Write-OK "Share definitions: $(@($out).Count) (+ default shares excluded)"

    if ($SkipContent) { Write-INFO "SkipContent: share files not copied"; return }
    foreach ($s in $out) {
        $gb = (Get-ChildItem $s.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1GB
        if ($gb -gt $MaxShareGB) { Write-WARN ("Share {0} is {1:N1} GB > {2} GB - skipped (raise -MaxShareGB)" -f $s.Name, $gb, $MaxShareGB); continue }
        Copy-Tree $s.Path (Join-Path $Dir "content\$($s.Name -replace '[^\w\.-]','_')") "Share $($s.Name) ($($s.Path))" | Out-Null
    }
}

$Def.Restore = {
    param($Dir)
    $shares = Import-Clixml "$Dir\shares.xml"
    foreach ($s in $shares) {
        if (-not (Test-Path $s.Path)) { New-Item -ItemType Directory $s.Path -Force | Out-Null }
        $content = Join-Path $Dir "content\$($s.Name -replace '[^\w\.-]','_')"
        if (Test-Path $content) { Restore-Tree $content $s.Path -Mirror:$Mirror }
        $existing = Get-SmbShare -Name $s.Name -ErrorAction SilentlyContinue
        if ($existing -and $existing.Path -ne $s.Path) { Write-WARN "Share $($s.Name) now points at $($existing.Path) (was $($s.Path)) - recreating"; Remove-SmbShare -Name $s.Name -Force; $existing = $null }
        if (-not $existing) { New-SmbShare -Name $s.Name -Path $s.Path -Description $s.Description | Out-Null; Write-OK "Recreated share $($s.Name)" }
        # Reset share permissions to exactly what was backed up
        foreach ($a in Get-SmbShareAccess -Name $s.Name) {
            if (-not ($s.Access | Where-Object { $_.AccountName -eq $a.AccountName })) { Revoke-SmbShareAccess -Name $s.Name -AccountName $a.AccountName -Force | Out-Null; Write-WARN "Removed extra share perm $($a.AccountName) on $($s.Name)" }
        }
        foreach ($a in $s.Access) {
            if ("$($a.AccessControlType)" -eq 'Deny') { Block-SmbShareAccess -Name $s.Name -AccountName $a.AccountName -Force | Out-Null }
            else { Grant-SmbShareAccess -Name $s.Name -AccountName $a.AccountName -AccessRight "$($a.AccessRight)" -Force | Out-Null }
        }
        Write-OK "Share perms reset on $($s.Name)"
    }
    Write-STEP "Shares that exist now but were NOT in the backup"
    $known = $shares.Name
    Get-SmbShare | Where-Object { $_.Name -notmatch $DefaultShares -and $known -notcontains $_.Name } | ForEach-Object { Write-CRIT "Unknown share: $($_.Name) -> $($_.Path)   (Remove-SmbShare -Name '$($_.Name)')" }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
