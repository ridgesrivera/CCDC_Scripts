<#
.SYNOPSIS
    Launch-Toolkit - the menu "panel" for every Windows script (same idea as legacy\00_LAUNCH.ps1).

.DESCRIPTION
    PURPOSE
      One window, numbered options, no need to remember parameters under
      pressure. Read-only scripts run straight away. Scripts that CHANGE the
      box always offer a dry run (-WhatIf) first, then ask before running for real.

    WHAT IT READS    nothing itself - it starts the other scripts
    WHAT IT CHANGES  nothing itself - see each script's header
    HOW TO UNDO      n/a

    START IT
      Right-click Launch-Toolkit.bat -> Run as administrator
      or:  powershell -ExecutionPolicy Bypass -File .\windows\Launch-Toolkit.ps1

    MANUAL EQUIVALENT
      Run any script directly, e.g.  .\audit\Audit-Users.ps1 -OutFile C:\ccdc\reports\users.txt
      Read any script's header:      Get-Help .\audit\Audit-Users.ps1 -Full
#>
[CmdletBinding()]
param([string]$ConfigPath)

$here = $PSScriptRoot
. "$here\lib\CCDC-Common.ps1"

# key, label, relative path, read-only?, short description
$menu = @(
    @{ Key = '1';  Name = 'Box overview';            File = 'recon\Get-BoxOverview.ps1';     RO = $true;  Desc = 'OS, role, IPs, listeners->process, roles, patches, likely scored services' }
    @{ Key = '2';  Name = 'Users & admins';          File = 'audit\Audit-Users.ps1';         RO = $true;  Desc = 'Admin groups, roastable accounts, passwords in descriptions, new accounts' }
    @{ Key = '3';  Name = 'Persistence hunt';        File = 'audit\Audit-Persistence.ps1';   RO = $true;  Desc = 'Tasks, services, Run keys, WMI, IFEO/sticky keys, SSH keys, web shells' }
    @{ Key = '4';  Name = 'Network exposure';        File = 'audit\Audit-Network.ps1';       RO = $true;  Desc = 'Connections, firewall, SMBv1/signing, shares, RDP NLA, WinRM' }
    @{ Key = '5';  Name = 'Vulnerability check';     File = 'audit\Audit-Vulns.ps1';         RO = $true;  Desc = 'Zerologon, PrintNightmare, MS17-010, NoPAC, LLMNR, WDigest, LSA, Defender' }
    @{ Key = '6';  Name = 'AD + GPO (DC only)';      File = 'audit\Audit-AD-GPO.ps1';        RO = $true;  Desc = 'GPO changes, DCSync rights, root ACL, delegation, krbtgt age' }
    @{ Key = '7';  Name = 'Rotate passwords';        File = 'harden\Rotate-Passwords.ps1';   RO = $false; Desc = 'Random passwords, shown once, never saved. Scored accounts excluded' }
    @{ Key = '8';  Name = 'Disable accounts';        File = 'harden\Disable-Accounts.ps1';   RO = $false; Desc = 'Disable (not delete) rogue accounts, with rollback file' }
    @{ Key = '9';  Name = 'Firewall allowlist';      File = 'harden\Set-Firewall.ps1';       RO = $false; Desc = 'Default-deny inbound, allow scored ports, keep your session, auto-rollback' }
    @{ Key = '10'; Name = 'Baseline hardening';      File = 'harden\Harden-Baseline.ps1';    RO = $false; Desc = 'SMBv1, signing, LLMNR/NBT-NS, WDigest, LSA, spooler, auditing, IFEO' }
    @{ Key = '11'; Name = 'IIS / PHP hardening';     File = 'harden\Harden-IIS-PHP.ps1';     RO = $false; Desc = 'Backup web roots, WP DISALLOW_FILE_EDIT, config perms, WP admins/plugins' }
    @{ Key = 'B';  Name = 'Backup this box';         File = 'backup\Backup-Box.ps1';         RO = $false; Desc = 'Registry, tasks, firewall, AD/GPO/DNS (DC), IIS -> C:\ccdc\backups' }
    @{ Key = 'L';  Name = 'Setup logging';           File = 'logging\Setup-Logging.ps1';     RO = $false; Desc = 'Audit policy, PS logging, Sysmon (if staged), forward to Graylog' }
    @{ Key = 'W';  Name = 'Watch for changes';       File = 'hunt\Watch-Changes.ps1';        RO = $true;  Desc = 'Baseline once, then diff every 15 min' }
)

function Read-YesNo([string]$q, [bool]$default) {
    $hint = if ($default) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host "  $q $hint"
    if (-not $a) { return $default }
    return ($a -match '^(y|yes)$')
}
function Read-List([string]$q) {
    $a = Read-Host "  $q"
    if (-not $a) { return @() }
    return @($a -split '[,\s]+' | Where-Object { $_ })
}

function Get-ScriptParams([string]$key) {
    # Ask for the parameters a script needs, so nobody has to remember them.
    $p = @{}
    if ($ConfigPath) { $p.ConfigPath = $ConfigPath }
    switch ($key) {
        '7' {
            $scope = Read-Host '  Scope: [L]ocal or [D]omain (Enter = auto)'
            if ($scope -match '^l') { $p.Scope = 'Local' } elseif ($scope -match '^d') { $p.Scope = 'Domain' }
            $how = Read-Host '  Rotate: [1] specific users  [2] members of a group  [3] ALL enabled accounts'
            switch ($how) {
                '1' { $p.Users = Read-List 'User names (comma separated)' }
                '2' { $p.Group = Read-Host '  Group name (e.g. Administrators or Domain Admins)' }
                '3' { $p.AllEnabled = $true }
                default { return $null }
            }
            Write-Host '  Scored accounts need a Password Change Request first! List them to exclude.' -ForegroundColor Yellow
            $ex = Read-List 'Exclude (comma separated, Enter = none)'
            if ($ex) { $p.Exclude = $ex }
            if (Read-YesNo 'Prompt for ONE password instead of generating random ones?' $false) { $p.Prompt = $true }
        }
        '8' {
            $p.Users = Read-List 'Accounts to DISABLE (comma separated)'
            if (-not $p.Users) { return $null }
            $scope = Read-Host '  Scope: [L]ocal or [D]omain (Enter = auto)'
            if ($scope -match '^l') { $p.Scope = 'Local' } elseif ($scope -match '^d') { $p.Scope = 'Domain' }
        }
        '9' {
            $tcp = Read-List 'TCP ports to allow (Enter = scored ports from config)'
            if ($tcp) { $p.AllowTcp = [int[]]$tcp }
            $udp = Read-List 'UDP ports to allow (Enter = from config / none)'
            if ($udp) { $p.AllowUdp = [int[]]$udp }
            $adm = Read-List 'Admin source CIDRs for RDP/WinRM (Enter = config adminSources)'
            if ($adm) { $p.AdminSources = $adm }
            if (Read-YesNo 'ALSO disable all other inbound allow rules (true allowlist)?' $false) { $p.DisableOtherInboundRules = $true }
        }
        '10' {
            $skip = Read-List 'Modules to SKIP (Enter = none; e.g. EnableLSAProtection,RequireSMBSigning)'
            if ($skip) { $p.Skip = $skip }
        }
        'W' {
            $m = Read-Host '  [1] take/replace BASELINE  [2] diff once  [3] diff every 15 min (loop)'
            switch ($m) { '1' { $p.Mode = 'Baseline' } '2' { $p.Mode = 'Diff' } '3' { $p.Mode = 'Diff'; $p.Loop = $true } default { return $null } }
        }
    }
    return $p
}

function Show-Menu {
    Clear-Host
    $cfg = Get-CcdcConfig -Path $ConfigPath
    $hc  = Get-CcdcHostConfig -Config $cfg
    Write-Host ('=' * 76) -ForegroundColor Cyan
    Write-Host '   CCDC BLUE TEAM TOOLKIT v2  -  Windows panel' -ForegroundColor Cyan
    Write-Host ('=' * 76) -ForegroundColor Cyan
    $adminTxt = if (Test-CcdcIsAdmin) { 'elevated' } else { 'NOT ELEVATED - right-click > Run as administrator' }
    Write-Host ("   Host: {0}   ({1})" -f $env:COMPUTERNAME, $adminTxt) -ForegroundColor $(if (Test-CcdcIsAdmin) { 'DarkGray' } else { 'Red' })
    Write-Host ("   Config: {0}" -f $(if ($hc) { "$($hc.name) - $($hc.role)" } elseif ($cfg) { 'loaded (this host not listed)' } else { 'none' })) -ForegroundColor DarkGray
    Write-Host '   Logs: C:\ccdc\logs   Reports: C:\ccdc\reports   Backups: C:\ccdc\backups' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host '  READ-ONLY (safe any time)' -ForegroundColor Green
    foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6' }) { Write-MenuLine $m 'White' }
    Write-Host '  [A]  ' -NoNewline -ForegroundColor Yellow; Write-Host 'Run ALL read-only audits' -NoNewline -ForegroundColor Cyan; Write-Host '  - 1-6, reports saved to C:\ccdc\reports\' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host '  CHANGES THE BOX (dry run offered first)' -ForegroundColor Yellow
    foreach ($m in $menu | Where-Object { $_.Key -in '7', '8', '9', '10', '11' }) { Write-MenuLine $m 'White' }
    Write-Host ""
    Write-Host '  BACKUP / LOGGING / HUNT' -ForegroundColor Magenta
    foreach ($m in $menu | Where-Object { $_.Key -in 'B', 'L', 'W' }) { Write-MenuLine $m 'White' }
    Write-Host ""
    Write-Host '  [H]  Explain a script (show its header)     [Q]  Quit' -ForegroundColor DarkGray
    Write-Host ""
}
function Write-MenuLine($m, $color) {
    Write-Host (("  [{0}]" -f $m.Key).PadRight(7)) -NoNewline -ForegroundColor $color
    Write-Host $m.Name.PadRight(22) -NoNewline -ForegroundColor Cyan
    Write-Host ("- {0}" -f $m.Desc) -ForegroundColor DarkGray
}

function Invoke-Entry($m) {
    $path = Join-Path $here $m.File
    if (-not (Test-Path $path)) { Write-Host "  Not found: $path" -ForegroundColor Red; return }
    $params = Get-ScriptParams $m.Key
    if ($null -eq $params) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
    if ($m.RO) {
        if ($m.Key -ne 'W' -and (Read-YesNo 'Save a report to C:\ccdc\reports\?' $true)) {
            $params.OutFile = 'C:\ccdc\reports\{0}_{1}_{2}.txt' -f ([IO.Path]::GetFileNameWithoutExtension($m.File)), $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        }
        & $path @params
        return
    }
    # State-changing: dry run first, then the real thing.
    if (Read-YesNo 'Dry run first (-WhatIf, changes nothing)?' $true) {
        & $path @params -WhatIf
        Write-Host ""
        if (-not (Read-YesNo 'Run it FOR REAL now? (you will confirm each action)' $false)) { return }
    }
    & $path @params
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
while ($true) {
    Show-Menu
    $choice = (Read-Host 'Select option').Trim().ToUpper()
    if ($choice -eq 'Q') { break }
    if ($choice -eq 'H') {
        $k = (Read-Host '  Which option? (1-11, B, L, W)').Trim().ToUpper()
        $m = $menu | Where-Object { $_.Key -eq $k }
        if ($m) { Get-Help (Join-Path $here $m.File) -Full | Out-Host -Paging }
    } elseif ($choice -eq 'A') {
        $dir = 'C:\ccdc\reports\{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6' }) {
            if ($m.Key -eq '6' -and -not (Test-CcdcIsDC)) { continue }
            $p = @{ OutFile = (Join-Path $dir (([IO.Path]::GetFileNameWithoutExtension($m.File)) + '.txt')) }
            if ($ConfigPath) { $p.ConfigPath = $ConfigPath }
            & (Join-Path $here $m.File) @p
        }
        Write-Host "`n  All reports: $dir" -ForegroundColor Green
    } else {
        $m = $menu | Where-Object { $_.Key -eq $choice }
        if ($m) { Invoke-Entry $m } else { Write-Host '  Unknown option.' -ForegroundColor Red }
    }
    Write-Host "`n  Press Enter to return to the menu..." -ForegroundColor DarkGray
    [void](Read-Host)
}
