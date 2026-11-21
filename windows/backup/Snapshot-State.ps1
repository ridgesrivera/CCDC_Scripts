<#
.SYNOPSIS
    Snapshot-State - save how the box is configured, show what changed since, and put it back.

.DESCRIPTION
    PURPOSE
      "It worked an hour ago." This script answers what changed since then,
      who changed it (the toolkit, or someone else), and puts any of it back.

      Take     saves the security-relevant state of the box. The FIRST snapshot
               on a box is the ORIGINAL: how it was when we got here. The panel
               takes it automatically the first time it opens, and takes another
               one before every script that changes something.
      Compare  lists every difference between a snapshot and right now. Each
               change is marked [toolkit: <script> <time>] when our own change
               log explains it, or NOT BY THE TOOLKIT (a teammate by hand, or
               Red Team).
      Restore  shows the same numbered list; you pick what to put back
               (e.g. 1,4,7 or all). Every restore asks y/N per item, supports
               -WhatIf, backs up first, and takes a "before-restore" snapshot,
               so a restore can itself be undone.

    WHAT IT SAVES (C:\ccdc\snapshots\<HOST>\<time>_<label>\)
      state.xml     registry values in the security catalog (LSA, NTLM, SMB, WDigest,
                    RDP, UAC, Winlogon, Run keys, IFEO, Point and Print, LLMNR, NBT-NS,
                    PowerShell logging, Defender policy, Netlogon, LDAP signing, ...),
                    every service (start mode, state, binary, account), local users and
                    enabled state (domain users on a DC), privileged group members,
                    SMB shares + share permissions, hosts file, Defender settings and
                    exclusions, firewall profiles + rules
      firewall.wfw  full firewall policy (netsh export) for an all-in-one restore
      auditpol.csv  audit policy (auditpol /backup)
      secpol.inf    local security policy: password/lockout policy, user rights,
                    security options (secedit /export)
      No passwords: Winlogon DefaultPassword and similar are recorded as "present" only.

    WHAT RESTORE CAN PUT BACK
      registry values (set back or delete), service start mode / running state /
      binary path, user enabled/disabled, group membership (add back / remove),
      shares (remove new, recreate deleted with saved permissions), hosts file,
      Defender settings and exclusions, firewall rules (disable new, set enabled
      back) or the WHOLE firewall policy, audit policy, local security policy.
      It never deletes a user (new users are DISABLED) and never deletes a service
      (new services are stopped + disabled). It cannot recreate a deleted user
      (no password) or a deleted service: those are reported.

    WHAT IT READS    registry, WMI, net.exe, netsh, auditpol, secedit, Defender
    WHAT IT CHANGES  Take/Compare: nothing (writes snapshot files under C:\ccdc\snapshots).
                     Restore: only the items you pick, each confirmed.
    HOW TO UNDO      a restore takes a "before-restore" snapshot first: restore from that one.

    MANUAL EQUIVALENT
      reg export HKLM\SYSTEM\CurrentControlSet\Control\Lsa lsa.reg ; reg import lsa.reg
      netsh advfirewall export fw.wfw ; netsh advfirewall import fw.wfw
      auditpol /backup /file:audit.csv ; auditpol /restore /file:audit.csv
      secedit /export /cfg secpol.inf ; secedit /configure /db t.sdb /cfg secpol.inf
      sc.exe qc <service> ; sc.exe config <service> start= auto

.PARAMETER Mode
    Take (default), Compare, Restore, List.

.PARAMETER Label
    Short name for a snapshot (Take). Default 'manual'; the first one is always 'ORIGINAL'.

.PARAMETER Against
    Snapshot to compare/restore against: original (default for Compare), latest
    (default for Restore), or a folder name from -Mode List.

.PARAMETER Quiet
    Take without the per-section summary (used by the panel before changes).

.EXAMPLE
    .\Snapshot-State.ps1                         # take a snapshot
.EXAMPLE
    .\Snapshot-State.ps1 -Mode Compare           # what changed since the original
.EXAMPLE
    .\Snapshot-State.ps1 -Mode Restore -Against latest -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Take', 'Compare', 'Restore', 'List')][string]$Mode = 'Take',
    [string]$Label = 'manual',
    [string]$Against = '',
    [switch]$Quiet,
    [switch]$Force,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Snapshot-State' -OutFile $OutFile -ReadOnly:($Mode -ne 'Restore')
$null = Get-CcdcConfig -Path $ConfigPath
$isDC = Test-CcdcIsDC

# ===========================================================================
# CAPTURE
# ===========================================================================
function Get-PrivGroupList {
    # Well-known SIDs, so this works on any display language.
    $g = @(
        @{ Sid = 'S-1-5-32-544'; Name = 'Administrators' }, @{ Sid = 'S-1-5-32-555'; Name = 'Remote Desktop Users' },
        @{ Sid = 'S-1-5-32-580'; Name = 'Remote Management Users' }, @{ Sid = 'S-1-5-32-551'; Name = 'Backup Operators' }
    )
    if ($isDC) {
        $g += @{ Sid = 'S-1-5-32-548'; Name = 'Account Operators' }, @{ Sid = 'S-1-5-32-549'; Name = 'Server Operators' }
        try {
            $de = [ADSI]('LDAP://' + ([ADSI]'LDAP://RootDSE').defaultNamingContext)
            $dom = (New-Object Security.Principal.SecurityIdentifier($de.objectSid[0], 0)).Value
            $g += @{ Sid = "$dom-512"; Name = 'Domain Admins' }, @{ Sid = "$dom-519"; Name = 'Enterprise Admins' },
                  @{ Sid = "$dom-518"; Name = 'Schema Admins' }, @{ Sid = "$dom-520"; Name = 'Group Policy Creator Owners' }
            $s = New-Object DirectoryServices.DirectorySearcher($de, '(&(objectClass=group)(sAMAccountName=DnsAdmins))')
            $r = $s.FindOne()
            if ($r) { $g += @{ Sid = (New-Object Security.Principal.SecurityIdentifier($r.Properties['objectsid'][0], 0)).Value; Name = 'DnsAdmins' } }
        } catch { $null = $_ }
    }
    return $g
}

function Get-GroupMembers($grp) {
    # Returns @{ '<path>' = '<display>' }. Path is what Add/Remove needs later.
    $m = @{}
    if ($isDC) {
        try {
            $de = [ADSI]"LDAP://<SID=$($grp.Sid)>"
            foreach ($dn in @($de.Properties['member'])) { if ($dn) { $m["LDAP://$dn"] = (($dn -split ',')[0] -replace '^CN=', '') } }
        } catch { $null = $_ }
    } else {
        try {
            $name = (New-Object Security.Principal.SecurityIdentifier($grp.Sid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $de = [ADSI]"WinNT://$env:COMPUTERNAME/$name,group"
            foreach ($o in @($de.Invoke('Members'))) {
                $p = $o.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $o, $null)
                $m[$p] = ($p -replace '^WinNT://', '' -replace '/', '\')
            }
        } catch { $null = $_ }
    }
    return $m
}

function Get-State {
    $s = @{}
    $s.Meta = @{
        Host = $env:COMPUTERNAME; Time = (Get-Date); By = "$env:USERDOMAIN\$env:USERNAME"; IsDC = $isDC
        OS = [string](Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        PS = $PSVersionTable.PSVersion.ToString()
    }

    # Registry catalog
    $s.Reg = @{}; $s.RegKeys = @()
    foreach ($c in (Get-CcdcRegCatalog)) {
        $only = if ($c.Only) { [string[]]$c.Only } else { @() }
        $t = Get-CcdcRegTree -KeyId $c.Key -Depth $c.Depth -Only $only
        $s.RegKeys += $t.Keys
        foreach ($e in $t.Values.GetEnumerator()) { $s.Reg[$e.Key] = $e.Value }
    }

    # Facts that are not one registry value (SMBv1 server, SAM hive ACL, shadow copies)
    $s.Extra = Get-CcdcExtraFacts

    # Services
    $s.Services = @{}
    foreach ($v in (Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)) {
        $s.Services[$v.Name] = @{ Display = $v.DisplayName; StartMode = $v.StartMode; State = $v.State; Path = $v.PathName; Account = $v.StartName }
    }

    # Users (local; on a DC, domain users)
    $s.Users = @{}
    if ($isDC) {
        try {
            $se = New-Object DirectoryServices.DirectorySearcher([ADSI]'', '(&(objectCategory=person)(objectClass=user))')
            $se.PageSize = 1000; [void]$se.PropertiesToLoad.Add('samaccountname'); [void]$se.PropertiesToLoad.Add('useraccountcontrol')
            foreach ($r in $se.FindAll()) { $s.Users[[string]$r.Properties['samaccountname'][0]] = @{ Enabled = -not ([int]$r.Properties['useraccountcontrol'][0] -band 2) } }
        } catch { $null = $_ }
    } else {
        foreach ($u in (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) { $s.Users[$u.Name] = @{ Enabled = -not $u.Disabled } }
    }

    # Privileged groups
    $s.Groups = @{}
    foreach ($g in (Get-PrivGroupList)) { $s.Groups[$g.Name] = @{ Sid = $g.Sid; Members = (Get-GroupMembers $g) } }

    # Shares (disk shares; hidden admin shares are noise)
    $s.Shares = @{}
    foreach ($sh in (Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '^[A-Z]\$$|^ADMIN\$$' })) {
        $acc = @()
        if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
            $acc = @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName)|$($_.AccessControlType)|$($_.AccessRight)" })
        }
        $s.Shares[$sh.Name] = @{ Path = $sh.Path; Access = $acc }
    }

    # Hosts file
    $hf = "$env:windir\System32\drivers\etc\hosts"
    $s.Hosts = if (Test-Path $hf) { [IO.File]::ReadAllText($hf) } else { '' }

    # Defender
    $s.Defender = @{}
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $p = Get-MpPreference -ErrorAction Stop
            foreach ($n in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'DisableBlockAtFirstSeen', 'MAPSReporting', 'SubmitSamplesConsent', 'PUAProtection') { $s.Defender[$n] = $p.$n }
            foreach ($n in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') { $s.Defender[$n] = @($p.$n | Where-Object { $_ }) }
        } catch { $null = $_ }
    }

    # Firewall
    $s.FwProfiles = @{}; $s.FwRules = @{}
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { $s.FwProfiles[[string]$p.Name] = "enabled=$($p.Enabled) in=$($p.DefaultInboundAction) out=$($p.DefaultOutboundAction)" }
        foreach ($r in (Get-NetFirewallRule -ErrorAction SilentlyContinue)) { $s.FwRules[[string]$r.Name] = @{ Display = [string]$r.DisplayName; Enabled = [string]$r.Enabled; Dir = [string]$r.Direction; Action = [string]$r.Action } }
    } else {
        # Older Windows: profile state from netsh (rules are covered by firewall.wfw).
        $cur = $null
        foreach ($l in (& netsh.exe advfirewall show allprofiles state 2>$null)) {
            if ($l -match '^(\w+) Profile Settings') { $cur = $Matches[1] }
            elseif ($cur -and $l -match '^State\s+(\S+)') { $s.FwProfiles[$cur] = "state=$($Matches[1])" }
        }
    }
    return $s
}

function Save-Snapshot([string]$label) {
    if (-not (Test-Path $script:CcdcSnapshotRoot)) { New-Item -ItemType Directory -Path $script:CcdcSnapshotRoot -Force -WhatIf:$false | Out-Null }
    $first = ((Get-CcdcSnapshotList).Count -eq 0)
    if ($first) { $label = 'ORIGINAL' }
    $safe = ($label -replace '[^\w\-]', '-'); if ($safe.Length -gt 40) { $safe = $safe.Substring(0, 40) }
    $dir = Join-Path $script:CcdcSnapshotRoot ("{0}_{1}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $safe)
    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
    # Snapshot folders hold configuration only, but keep normal users out anyway (SIDs: Administrators, SYSTEM).
    # Top folder only; children inherit. (/T with (OI)(CI) would strip every file's permissions.)
    $snapTop = Split-Path $script:CcdcSnapshotRoot
    $null = & icacls.exe $snapTop /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /C /Q 2>&1
    $null = & icacls.exe "$snapTop\*" /reset /T /C /Q 2>&1

    $state = Get-State
    $state.Meta.Label = $label
    $state | Export-Clixml -Path (Join-Path $dir 'state.xml') -Depth 6 -WhatIf:$false
    $null = & netsh.exe advfirewall export (Join-Path $dir 'firewall.wfw') 2>&1
    $auditFile = Join-Path $dir 'auditpol.csv'
    $null = & auditpol.exe /backup "/file:$auditFile" 2>&1
    $null = & secedit.exe /export /cfg (Join-Path $dir 'secpol.inf') /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
    Write-CcdcLog "SNAPSHOT $dir"
    return @{ Dir = $dir; State = $state; First = $first }
}

# ===========================================================================
# COMPARE: build a list of change objects. Each one knows how to restore itself.
# ===========================================================================
function Get-IniMap([string]$path) {
    # secedit .inf -> @{ 'Section|Key' = 'value' }
    $m = @{}; $sec = ''
    if (-not (Test-Path $path)) { return $m }
    foreach ($l in (Get-Content $path -ErrorAction SilentlyContinue)) {
        if ($l -match '^\[(.+)\]$') { $sec = $Matches[1]; continue }
        if ($sec -in 'Unicode', 'Version') { continue }
        if ($l -match '^\s*([^=]+?)\s*=\s*(.*)$') { $m["$sec|$($Matches[1])"] = $Matches[2].Trim() }
    }
    return $m
}
function Get-AuditMap([string]$path) {
    # auditpol csv -> @{ 'Subcategory' = 'Inclusion Setting' }
    $m = @{}
    if (-not (Test-Path $path)) { return $m }
    foreach ($r in (Import-Csv $path -ErrorAction SilentlyContinue)) {
        $k = if ($r.Subcategory) { $r.Subcategory } else { $r.'Subcategory GUID' }
        if ($k) { $m[$k] = "$($r.'Inclusion Setting')|$($r.'Setting Value')" }
    }
    return $m
}
function Format-RegData($v) {
    if ($null -eq $v) { return '(not set)' }
    if ($v.Type -eq 'MultiString') { return ('[{0}]' -f (@($v.Data) -join '; ')) }
    if ($v.Type -eq 'Binary') { $d = [string]$v.Data; if ($d.Length -gt 24) { $d = $d.Substring(0, 24) + '...' }; return "bin:$d" }
    return [string]$v.Data
}
function Show-Short([string]$t, [int]$n = 70) { if (-not $t) { return '(empty)' }; $t = $t -replace '\s+', ' '; if ($t.Length -gt $n) { return $t.Substring(0, $n) + '...' }; return $t }

function Get-Changes($base, $now) {
    $ch = New-Object System.Collections.ArrayList
    function Add-Change($cat, $item, $was, $is, $tokens, $restore, $danger) {
        [void]$ch.Add([pscustomobject]@{ Cat = $cat; Item = $item; Was = $was; Is = $is; Tokens = $tokens; Restore = $restore; Danger = [bool]$danger })
    }

    # --- Registry
    $keys = @(@($base.Reg.Keys) + @($now.Reg.Keys) | Sort-Object -Unique)
    foreach ($k in $keys) {
        $b = $base.Reg[$k]; $n = $now.Reg[$k]
        if ($b -and $n -and $b.Type -eq $n.Type -and ((@($b.Data) -join "`n") -ceq (@($n.Data) -join "`n"))) { continue }
        if (-not $b -and -not (Test-CcdcRegKeyCaptured -RegKeys $base.RegKeys -KeyId (($k -split '\|')[0]))) { continue }   # outside what that snapshot read
        if ($b -and $b.Type -eq 'Secret' -and $n -and $n.Type -eq 'Secret') { continue }
        $key, $name = $k -split '\|', 2
        $leaf = Split-Path $key -Leaf
        $danger = $k -match 'Run\||RunOnce\||Image File Execution|Winlogon\|(Shell|Userinit)|WDigest|AppInit|Installer\|AlwaysInstallElevated|Lsa\|(Security Packages|Authentication Packages|Notification Packages)'
        Add-Change 'Registry' "$key  $name" (Format-RegData $b) (Format-RegData $n) @($name, $leaf) @{ T = 'reg'; Key = $key; Name = $name; Old = $b } $danger
    }

    # --- Services
    foreach ($name in @(@($base.Services.Keys) + @($now.Services.Keys) | Sort-Object -Unique)) {
        $b = $base.Services[$name]; $n = $now.Services[$name]
        if (-not $b) { Add-Change 'Service' "$name ($($n.Display))" '(did not exist)' "NEW: $($n.StartMode), $($n.State), $(Show-Short $n.Path 60)" @($name) @{ T = 'svc-new'; Name = $name } $true; continue }
        if (-not $n) { Add-Change 'Service' "$name ($($b.Display))" "$($b.StartMode), $($b.State)" 'DELETED' @($name) @{ T = 'none'; Why = 'service was deleted: reinstall it or restore from services\<Service>.ps1 -Action Restore' } $true; continue }
        if ($b.Path -ne $n.Path) { Add-Change 'Service' "$name binary path" (Show-Short $b.Path) (Show-Short $n.Path) @($name) @{ T = 'svc-path'; Name = $name; Old = $b.Path } $true }
        if ($b.StartMode -ne $n.StartMode) { Add-Change 'Service' "$name start mode" $b.StartMode $n.StartMode @($name) @{ T = 'svc-start'; Name = $name; Old = $b.StartMode } ($n.StartMode -eq 'Disabled') }
        if ($b.State -ne $n.State) { Add-Change 'Service' "$name state" $b.State $n.State @($name) @{ T = 'svc-state'; Name = $name; Old = $b.State } $false }
        if ($b.Account -ne $n.Account) { Add-Change 'Service' "$name runs as" $b.Account $n.Account @($name) @{ T = 'none'; Why = 'changing the service account back needs its password: services.msc > Log On' } $true }
    }

    # --- Users
    foreach ($u in @(@($base.Users.Keys) + @($now.Users.Keys) | Sort-Object -Unique)) {
        $b = $base.Users[$u]; $n = $now.Users[$u]
        if (-not $b) { Add-Change 'User' $u '(did not exist)' ("NEW user, enabled=$($n.Enabled)") @($u) @{ T = 'user-new'; Name = $u } $true; continue }
        if (-not $n) { Add-Change 'User' $u "enabled=$($b.Enabled)" 'DELETED' @($u) @{ T = 'none'; Why = 'a deleted user cannot be recreated with its old SID/password' } $true; continue }
        if ($b.Enabled -ne $n.Enabled) { Add-Change 'User' $u "enabled=$($b.Enabled)" "enabled=$($n.Enabled)" @($u) @{ T = 'user-enable'; Name = $u; Old = $b.Enabled } ($n.Enabled) }
    }

    # --- Privileged groups
    foreach ($g in @(@($base.Groups.Keys) + @($now.Groups.Keys) | Sort-Object -Unique)) {
        $bm = @{}; $nm = @{}; $sid = $null
        if ($base.Groups[$g]) { $bm = $base.Groups[$g].Members; $sid = $base.Groups[$g].Sid }
        if ($now.Groups[$g]) { $nm = $now.Groups[$g].Members; $sid = $now.Groups[$g].Sid }
        foreach ($p in $nm.Keys) { if (-not $bm.ContainsKey($p)) { Add-Change 'Group' "$g  +$($nm[$p])" '(not a member)' 'ADDED' @($nm[$p].Split('\')[-1], $g) @{ T = 'grp-remove'; Sid = $sid; Group = $g; Path = $p } $true } }
        foreach ($p in $bm.Keys) { if (-not $nm.ContainsKey($p)) { Add-Change 'Group' "$g  -$($bm[$p])" 'member' 'REMOVED' @($bm[$p].Split('\')[-1], $g) @{ T = 'grp-add'; Sid = $sid; Group = $g; Path = $p } $false } }
    }

    # --- Shares
    foreach ($sh in @(@($base.Shares.Keys) + @($now.Shares.Keys) | Sort-Object -Unique)) {
        $b = $base.Shares[$sh]; $n = $now.Shares[$sh]
        if (-not $b) { Add-Change 'Share' $sh '(did not exist)' "NEW -> $($n.Path)" @($sh) @{ T = 'share-del'; Name = $sh } $true; continue }
        if (-not $n) { Add-Change 'Share' $sh $b.Path 'DELETED' @($sh) @{ T = 'share-add'; Name = $sh; Path = $b.Path; Access = $b.Access } $false; continue }
        if ($b.Path -ne $n.Path -or ((@($b.Access) -join ';') -ne (@($n.Access) -join ';'))) {
            Add-Change 'Share' "$sh permissions/path" ("{0} {1}" -f $b.Path, (@($b.Access) -join ', ')) ("{0} {1}" -f $n.Path, (@($n.Access) -join ', ')) @($sh) @{ T = 'share-reset'; Name = $sh; Path = $b.Path; Access = $b.Access } $true
        }
    }

    # --- Hosts file
    if (($base.Hosts -replace '\s+', ' ').Trim() -ne ($now.Hosts -replace '\s+', ' ').Trim()) {
        Add-Change 'Hosts' 'hosts file' (Show-Short (($base.Hosts -split "`n" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }) -join ' | ')) (Show-Short (($now.Hosts -split "`n" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }) -join ' | ')) @('hosts') @{ T = 'hosts'; Old = $base.Hosts } $true
    }

    # --- Defender
    foreach ($n in @(@($base.Defender.Keys) + @($now.Defender.Keys) | Sort-Object -Unique)) {
        $b = @($base.Defender[$n]) -join ', '; $c = @($now.Defender[$n]) -join ', '
        if ($b -ne $c) { Add-Change 'Defender' $n $(if ($b) { $b } else { '(none)' }) $(if ($c) { $c } else { '(none)' }) @($n, 'Defender', 'MpPreference') @{ T = 'def'; Name = $n; Old = $base.Defender[$n]; New = $now.Defender[$n] } ($n -like 'Exclusion*' -or $n -like 'Disable*') }
    }

    # --- Firewall
    foreach ($p in @(@($base.FwProfiles.Keys) + @($now.FwProfiles.Keys) | Sort-Object -Unique)) {
        if ($base.FwProfiles[$p] -ne $now.FwProfiles[$p]) { Add-Change 'Firewall' "profile $p" $base.FwProfiles[$p] $now.FwProfiles[$p] @('firewall', 'profile', $p) @{ T = 'fw-all' } $true }
    }
    foreach ($r in @(@($base.FwRules.Keys) + @($now.FwRules.Keys) | Sort-Object -Unique)) {
        $b = $base.FwRules[$r]; $n = $now.FwRules[$r]
        if (-not $b) { if ($n.Enabled -eq 'True') { Add-Change 'Firewall' "rule $($n.Display)" '(did not exist)' "NEW $($n.Dir) $($n.Action)" @($n.Display, $r) @{ T = 'fw-disable'; Name = $r } ($n.Action -eq 'Block' -or $n.Dir -eq 'Inbound') }; continue }
        if (-not $n) { Add-Change 'Firewall' "rule $($b.Display)" "$($b.Dir) $($b.Action) enabled=$($b.Enabled)" 'DELETED' @($b.Display, $r) @{ T = 'fw-all' } $false; continue }
        if ($b.Enabled -ne $n.Enabled -or $b.Action -ne $n.Action) { Add-Change 'Firewall' "rule $($n.Display)" "enabled=$($b.Enabled) $($b.Action)" "enabled=$($n.Enabled) $($n.Action)" @($n.Display, $r) @{ T = 'fw-rule'; Name = $r; Enabled = $b.Enabled; Action = $b.Action } $false }
    }

    # --- Audit policy and local security policy (files)
    if ($base.Dir) {
        $nowAudit = Join-Path $env:TEMP "ccdc_auditpol_$($script:CcdcStamp).csv"
        $null = & auditpol.exe /backup "/file:$nowAudit" 2>&1
        $ba = Get-AuditMap (Join-Path $base.Dir 'auditpol.csv'); $na = Get-AuditMap $nowAudit
        $auditChanged = @(@($ba.Keys) + @($na.Keys) | Sort-Object -Unique | Where-Object { $ba[$_] -ne $na[$_] })
        foreach ($k in $auditChanged) { Add-Change 'AuditPolicy' $k (($ba[$k] -split '\|')[0]) (($na[$k] -split '\|')[0]) @($k, 'audit') @{ T = 'audit'; File = (Join-Path $base.Dir 'auditpol.csv') } ($na[$k] -match 'No Auditing') }
        Remove-Item $nowAudit -ErrorAction SilentlyContinue

        $nowSec = Join-Path $env:TEMP "ccdc_secpol_$($script:CcdcStamp).inf"
        $null = & secedit.exe /export /cfg $nowSec /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        $bs = Get-IniMap (Join-Path $base.Dir 'secpol.inf'); $ns = Get-IniMap $nowSec
        foreach ($k in @(@($bs.Keys) + @($ns.Keys) | Sort-Object -Unique | Where-Object { $bs[$_] -ne $ns[$_] })) {
            $sec, $name = $k -split '\|', 2
            Add-Change 'SecPolicy' "$sec  $name" (Show-Short $bs[$k] 50) (Show-Short $ns[$k] 50) @(($name -split '\\')[-1], $name) @{ T = 'secpol'; File = (Join-Path $base.Dir 'secpol.inf') } ($sec -eq 'Privilege Rights')
        }
        Remove-Item $nowSec -ErrorAction SilentlyContinue
    }
    return $ch
}

function Set-Attribution($changes, [datetime]$since) {
    # Match each change against the toolkit's own CHANGED log lines.
    $log = Get-CcdcToolkitChanges -Since $since
    foreach ($c in $changes) {
        $hit = $null
        foreach ($l in $log) {
            $ok = $true
            foreach ($t in @($c.Tokens | Where-Object { $_ })) { if ($l.Text.IndexOf([string]$t, [StringComparison]::OrdinalIgnoreCase) -lt 0) { $ok = $false; break } }
            if ($ok -and @($c.Tokens | Where-Object { $_ }).Count) { $hit = $l }
        }
        $c | Add-Member -NotePropertyName By -NotePropertyValue $(if ($hit) { "toolkit: $($hit.Script) $($hit.Time.ToString('HH:mm'))" } else { '' }) -Force
    }
}

function Show-Changes($changes, $base) {
    $bt = $base.Meta.Time
    Write-Section ("Changes since snapshot '{0}' ({1})" -f $base.Meta.Label, $bt.ToString('yyyy-MM-dd HH:mm'))
    if ($changes.Count -eq 0) { Write-Finding -Level GREEN -Category 'Snapshot' -Message 'Nothing changed.'; return }
    $i = 0
    foreach ($cat in @($changes | ForEach-Object { $_.Cat } | Select-Object -Unique)) {
        Write-Host ''
        Write-Host ("  {0}" -f $cat.ToUpper()) -ForegroundColor Cyan
        foreach ($c in @($changes | Where-Object { $_.Cat -eq $cat })) {
            $i++
            $c | Add-Member -NotePropertyName No -NotePropertyValue $i -Force
            $lvl = if ($c.By) { 'INFO' } elseif ($c.Danger) { 'RED' } else { 'YELLOW' }
            $who = if ($c.By) { "[$($c.By)]" } else { '[NOT BY THE TOOLKIT]' }
            Write-Finding -Level $lvl -Category $cat -Message ("{0,3}. {1}" -f $i, $c.Item) -Detail ("was: {0}`nnow: {1}   {2}" -f $c.Was, $c.Is, $who)
        }
    }
    $mine = @($changes | Where-Object { $_.By }).Count
    Write-Host ''
    Write-Host ("  {0} change(s): {1} made by the toolkit, {2} NOT by the toolkit (a teammate by hand, or Red Team)." -f $changes.Count, $mine, ($changes.Count - $mine)) -ForegroundColor White
}

# ===========================================================================
# RESTORE one change
# ===========================================================================
function Restore-One($c) {
    $r = $c.Restore
    switch ($r.T) {
        'reg' {
            $old = $r.Old; $key = $r.Key; $name = $r.Name
            if ($old -and $old.Type -eq 'Secret') { Write-Host '     skipped: secret value, not saved in the snapshot' -ForegroundColor DarkGray; return }
            $regExe = $key -replace '^HKLM', 'HKEY_LOCAL_MACHINE'
            $undo = if ($c.Is -eq '(not set)') { "reg delete `"$regExe`" /v `"$name`" /f" } else { "re-run restore from the before-restore snapshot" }
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target "$key\$name" -Action $(if ($old) { "Set back to $(Format-RegData $old)" } else { 'Delete value (did not exist before)' }) -Force:$Force -Undo $undo -ScriptBlock {
                $null = Backup-CcdcRegistry -Key $regExe
                $wk = Open-CcdcRegKey -KeyId $key -Writable
                if (-not $wk) { throw "cannot open $key for writing" }
                try {
                    $vn = if ($name -eq '(default)') { '' } else { $name }
                    if ($old) {
                        $data = switch ($old.Type) { 'Binary' { [Convert]::FromBase64String($old.Data) } 'MultiString' { [string[]]@($old.Data) } 'DWord' { [int]$old.Data } 'QWord' { [long]$old.Data } default { [string]$old.Data } }
                        $wk.SetValue($vn, $data, [Microsoft.Win32.RegistryValueKind]$old.Type)
                    } else { $wk.DeleteValue($vn, $false) }
                } finally { $wk.Close() }
            }
        }
        'svc-start' {
            $map = @{ Auto = 'auto'; Manual = 'demand'; Disabled = 'disabled'; Boot = 'boot'; System = 'system' }
            $svcName = $r.Name; $mode = $map[[string]$r.Old]
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $svcName -Action "Set start mode back to $($r.Old)" -Force:$Force -Undo "sc.exe config $svcName start= <previous>" -ScriptBlock {
                $o = & sc.exe config $svcName start= $mode 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'svc-state' {
            $svcName = $r.Name; $want = $r.Old
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $svcName -Action $(if ($want -eq 'Running') { 'Start service' } else { 'Stop service' }) -Force:$Force -ScriptBlock {
                if ($want -eq 'Running') { Start-Service -Name $svcName -ErrorAction Stop } else { Stop-Service -Name $svcName -Force -ErrorAction Stop }
            }
        }
        'svc-path' {
            $svcName = $r.Name; $p = $r.Old
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $svcName -Action "Set binary path back to $p" -Force:$Force -ScriptBlock {
                $o = & sc.exe config $svcName binPath= $p 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'svc-new' {
            $svcName = $r.Name
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $svcName -Action 'Stop + DISABLE new service (not deleted: evidence)' -Force:$Force -Undo "sc.exe config $svcName start= demand" -ScriptBlock {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                $o = & sc.exe config $svcName start= disabled 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'user-enable' {
            $u = $r.Name; $flag = if ($r.Old) { 'yes' } else { 'no' }
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $u -Action $(if ($r.Old) { 'Enable account' } else { 'Disable account' }) -Force:$Force -Undo "net user $u /active:<previous>" -ScriptBlock {
                $o = & net.exe user $u /active:$flag 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'user-new' {
            $u = $r.Name
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $u -Action 'DISABLE new account (not deleted: evidence)' -Force:$Force -Undo "net user $u /active:yes" -ScriptBlock {
                $o = & net.exe user $u /active:no 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        { $_ -in 'grp-add', 'grp-remove' } {
            $grpSid = $r.Sid; $member = $r.Path; $add = ($r.T -eq 'grp-add')
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $r.Group -Action $(if ($add) { "Add back $member" } else { "Remove $member" }) -Force:$Force -Undo "re-run restore from the before-restore snapshot" -ScriptBlock {
                if ($member -like 'LDAP://*') { $grp = [ADSI]"LDAP://<SID=$grpSid>" }
                else {
                    $gname = (New-Object Security.Principal.SecurityIdentifier($grpSid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
                    $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$gname,group"
                }
                if ($add) { $grp.Add($member) } else { $grp.Remove($member) }
            }
        }
        'share-del' {
            $sh = $r.Name
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $sh -Action 'Remove new share (folder is kept)' -Force:$Force -ScriptBlock {
                $o = & net.exe share $sh /delete /y 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        { $_ -in 'share-add', 'share-reset' } {
            $sh = $r.Name; $p = $r.Path; $acc = @($r.Access); $reset = ($r.T -eq 'share-reset')
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $sh -Action "Recreate share -> $p with saved permissions" -Force:$Force -ScriptBlock {
                if ($reset) { $null = & net.exe share $sh /delete /y 2>&1 }
                if (Get-Command New-SmbShare -ErrorAction SilentlyContinue) {
                    $full = @(); $chg = @(); $read = @()
                    foreach ($a in $acc) { $f = $a -split '\|'; if ($f[1] -ne 'Allow') { continue }; switch ($f[2]) { 'Full' { $full += $f[0] } 'Change' { $chg += $f[0] } default { $read += $f[0] } } }
                    $sp = @{ Name = $sh; Path = $p; ErrorAction = 'Stop' }
                    if ($full) { $sp.FullAccess = $full }; if ($chg) { $sp.ChangeAccess = $chg }; if ($read) { $sp.ReadAccess = $read }
                    $null = New-SmbShare @sp
                } else { $o = & net.exe share "$sh=$p" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') } }
            }
        }
        'hosts' {
            $old = $r.Old; $hf = "$env:windir\System32\drivers\etc\hosts"
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $hf -Action 'Write the hosts file back' -Force:$Force -Undo 'copy the backup in C:\ccdc\backups back' -ScriptBlock {
                $null = Backup-CcdcFile -Path $hf
                [IO.File]::WriteAllText($hf, $old)
            }
        }
        'def' {
            $n = $r.Name; $old = $r.Old; $new = $r.New
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target "Defender $n" -Action "Set back to: $(@($old) -join ', ')" -Force:$Force -ScriptBlock {
                if ($n -like 'Exclusion*') {
                    $add = @($old | Where-Object { @($new) -notcontains $_ }); $rem = @($new | Where-Object { @($old) -notcontains $_ })
                    if ($rem) { $p = @{ $n = $rem }; Remove-MpPreference @p -ErrorAction Stop }
                    if ($add) { $p = @{ $n = $add }; Add-MpPreference @p -ErrorAction Stop }
                } else { $p = @{ $n = $old }; Set-MpPreference @p -ErrorAction Stop }
            }
        }
        'fw-disable' {
            $rn = $r.Name
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $c.Item -Action 'Disable new firewall rule (not deleted)' -Force:$Force -Undo "Enable-NetFirewallRule -Name '$rn'" -ScriptBlock { Disable-NetFirewallRule -Name $rn -ErrorAction Stop }
        }
        'fw-rule' {
            $rn = $r.Name; $en = $r.Enabled; $act = $r.Action
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $c.Item -Action "Set back to enabled=$en action=$act" -Force:$Force -ScriptBlock { Set-NetFirewallRule -Name $rn -Enabled $en -Action $act -ErrorAction Stop }
        }
        'fw-all' { Write-Host '     part of the firewall policy: use the WHOLE-FIREWALL restore item (F) instead' -ForegroundColor DarkGray }
        { $_ -in 'audit', 'secpol' } { Write-Host '     restored as a whole: use the AUDIT (P) or SECURITY POLICY (S) restore item' -ForegroundColor DarkGray }
        default { Write-Host ("     cannot restore automatically: {0}" -f $r.Why) -ForegroundColor Yellow }
    }
}

function Restore-Whole([string]$what, $base) {
    switch ($what) {
        'F' {
            $f = Join-Path $base.Dir 'firewall.wfw'
            if (-not (Test-Path $f)) { Write-Host '  No firewall export in that snapshot.' -ForegroundColor Red; return }
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target 'Windows Firewall (all rules + profiles)' -Action "Import $f" -Force:$Force -Undo 'restore the before-restore snapshot (F)' -ScriptBlock {
                $o = & netsh.exe advfirewall import $f 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'P' {
            $f = Join-Path $base.Dir 'auditpol.csv'
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target 'Audit policy' -Action "auditpol /restore $f" -Force:$Force -ScriptBlock {
                $o = & auditpol.exe /restore "/file:$f" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
        'S' {
            $f = Join-Path $base.Dir 'secpol.inf'
            if ($isDC) { Write-Host '  DC: Group Policy re-applies its settings within minutes. Fix the GPO (gpmc.msc) instead if the change came from there.' -ForegroundColor Yellow }
            $db = Join-Path $env:TEMP "ccdc_secedit_$($script:CcdcStamp).sdb"
            $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target 'Local security policy (password/lockout policy, user rights, security options)' -Action "secedit /configure from $f" -Force:$Force -ScriptBlock {
                $o = & secedit.exe /configure /db $db /cfg $f /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
            }
        }
    }
}

# ===========================================================================
# MAIN
# ===========================================================================
switch ($Mode) {
    'List' {
        Write-Section 'Snapshots on this box'
        $list = Get-CcdcSnapshotList
        if (-not $list) { Write-Finding -Level YELLOW -Category 'Snapshot' -Message 'No snapshots yet. Take one: .\Snapshot-State.ps1' }
        $i = 0; foreach ($s in $list) { $i++; Write-Finding -Level INFO -Category 'Snapshot' -Message ("{0,2}. {1}   {2}" -f $i, $s.Time.ToString('yyyy-MM-dd HH:mm:ss'), $s.Label) -Detail $s.Path }
    }
    'Take' {
        Write-Section 'Taking snapshot'
        $r = Save-Snapshot $Label
        $st = $r.State
        if ($r.First) { Write-Finding -Level GREEN -Category 'Snapshot' -Message 'ORIGINAL snapshot saved: this is how the box looked before we changed anything.' }
        else { Write-Finding -Level GREEN -Category 'Snapshot' -Message "Snapshot '$($st.Meta.Label)' saved." }
        Write-Finding -Level INFO -Category 'Snapshot' -Message $r.Dir
        if (-not $Quiet) {
            Write-Finding -Level INFO -Category 'Snapshot' -Message ("{0} registry values, {1} services, {2} users, {3} privileged groups, {4} shares, {5} firewall rules" -f $st.Reg.Count, $st.Services.Count, $st.Users.Count, $st.Groups.Count, $st.Shares.Count, $st.FwRules.Count)
            Write-Finding -Level INFO -Category 'Snapshot' -Message 'Next: -Mode Compare shows what changed since; -Mode Restore puts things back.'
        }
    }
    { $_ -in 'Compare', 'Restore' } {
        $which = if ($Against) { $Against } elseif ($Mode -eq 'Compare') { 'original' } else { 'latest' }
        $base = Import-CcdcSnapshot -Which $which
        if (-not $base) { Write-Finding -Level RED -Category 'Snapshot' -Message "No snapshot '$which' found. Take one first (or -Mode List)."; break }
        Write-Host '  Reading current state...' -ForegroundColor DarkGray
        $now = Get-State
        $changes = Get-Changes $base $now
        Set-Attribution $changes $base.Meta.Time
        Show-Changes $changes $base
        if ($Mode -eq 'Compare') { break }

        Write-Section 'Restore'
        Write-Host '  Pick changes to put back: numbers (1,4,7), a range (3-9), "all", or a category name (Registry, Service, User...).' -ForegroundColor White
        Write-Host '  Whole-area restores:  F = entire firewall policy   P = audit policy   S = local security policy' -ForegroundColor White
        $pick = (Read-Host '  Restore which (Enter = nothing)').Trim()
        if (-not $pick) { Write-Host '  Nothing restored.' -ForegroundColor DarkGray; break }
        if (-not $WhatIfPreference) {
            Write-Host '  Taking a before-restore snapshot first (so this can be undone)...' -ForegroundColor DarkGray
            $null = Save-Snapshot 'before-restore'
        }
        $sel = @()
        foreach ($tok in ($pick -split '[,\s]+' | Where-Object { $_ })) {
            if ($tok -match '^(?i)all$') { $sel += $changes }
            elseif ($tok -match '^(\d+)-(\d+)$') { $a = [int]$Matches[1]; $b = [int]$Matches[2]; $sel += @($changes | Where-Object { $_.No -ge $a -and $_.No -le $b }) }
            elseif ($tok -match '^\d+$') { $sel += @($changes | Where-Object { $_.No -eq [int]$tok }) }
            elseif ($tok -match '^(?i)[FPS]$') { Restore-Whole $tok.ToUpper() $base }
            else { $sel += @($changes | Where-Object { $_.Cat -ieq $tok }) }
        }
        foreach ($c in ($sel | Sort-Object No -Unique)) {
            Write-Host ("  {0,3}. {1}  ({2} -> {3})" -f $c.No, $c.Item, (Show-Short $c.Is 30), (Show-Short $c.Was 30)) -ForegroundColor Cyan
            Restore-One $c
        }
        Write-Host ''
        Write-Host '  Done. Run -Mode Compare again to confirm; restore from the "before-restore" snapshot to undo.' -ForegroundColor Green
    }
}
Complete-Ccdc
