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
    @{ Key = 'P';  Name = 'Security policy (GPO)';   File = 'audit\Audit-SecurityPolicy.ps1'; RO = $true; Desc = 'GPO/AD/DNS settings safe to turn on, with GPO path + check/fix commands' }
    @{ Key = 'T';  Name = 'Vendor tool audits';      File = 'audit\Invoke-AuditTools.ps1';  RO = $true;  Desc = 'Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith' }
    @{ Key = 'F';  Name = 'Sensitive files (PII)';   File = 'audit\Audit-SensitiveFiles.ps1'; RO = $true; Desc = 'SSNs, card numbers, passwords, keys in files + who can read them' }
    @{ Key = 'X';  Name = 'Software audit';          File = 'audit\Audit-Software.ps1';      RO = $true;  Desc = 'Remote-access tools, attack tools, junk -> inventory CSV for injects' }
    @{ Key = '7';  Name = 'Rotate passwords';        File = 'harden\Rotate-Passwords.ps1';   RO = $false; Desc = 'Random passwords, shown once, never saved. Scored accounts excluded' }
    @{ Key = '8';  Name = 'Disable accounts';        File = 'harden\Disable-Accounts.ps1';   RO = $false; Desc = 'Disable (not delete) rogue accounts, with rollback file' }
    @{ Key = '9';  Name = 'Firewall allowlist';      File = 'harden\Set-Firewall.ps1';       RO = $false; Desc = 'Default-deny inbound, allow scored ports, keep your session, auto-rollback' }
    @{ Key = '10'; Name = 'Baseline hardening';      File = 'harden\Harden-Baseline.ps1';    RO = $false; Desc = 'SMBv1, signing, LLMNR/NBT-NS, WDigest, LSA, spooler, auditing, IFEO' }
    @{ Key = '11'; Name = 'IIS / PHP hardening';     File = 'harden\Harden-IIS-PHP.ps1';     RO = $false; Desc = 'Backup web roots, WP DISALLOW_FILE_EDIT, config perms, WP admins/plugins' }
    @{ Key = '12'; Name = 'AD account hardening';    File = 'harden\Harden-AD.ps1';          RO = $false; Desc = 'DC: pre-auth, reversible encryption, blank-password flag; lists roastable' }
    @{ Key = '13'; Name = 'SQL Server hardening';    File = 'harden\Harden-MSSQL.ps1';       RO = $false; Desc = 'Audit sa / sysadmins / weak logins, turn off xp_cmdshell and friends' }
    @{ Key = 'K';  Name = 'Reset krbtgt';            File = 'harden\Reset-Krbtgt.ps1';       RO = $false; Desc = 'DC: kill golden tickets after a domain compromise (run twice, with a pause)' }
    @{ Key = 'D';  Name = 'Disconnect sessions';     File = 'harden\Disconnect-Sessions.ps1'; RO = $false; Desc = 'List / log off RDP, SMB, WinRM, SSH sessions after a password change' }
    @{ Key = 'R';  Name = 'Remove persistence';      File = 'hunt\Remove-Persistence.ps1';   RO = $false; Desc = 'Numbered list: preserve evidence, then disable / quarantine what you pick' }
    @{ Key = 'B';  Name = 'Backup this box';         File = 'backup\Backup-Box.ps1';         RO = $false; Desc = 'Registry, tasks, firewall, AD/GPO/DNS (DC), IIS -> C:\ccdc\backups' }
    @{ Key = 'L';  Name = 'Setup logging';           File = 'logging\Setup-Logging.ps1';     RO = $false; Desc = 'Audit policy, PS logging, Sysmon (if staged), forward to Graylog' }
    @{ Key = 'S';  Name = 'Per-service backup';      File = 'services\Invoke-AllServices.ps1'; RO = $false; Desc = 'Detect every service (DNS, IIS, SQL, SMB...), back up / info / verify each -> C:\ccdc\backups\services' }
    @{ Key = 'W';  Name = 'Watch for changes';       File = 'hunt\Watch-Changes.ps1';        RO = $true;  Desc = 'Baseline once, then diff every 15 min (or install as a scheduled task)' }
    @{ Key = 'E';  Name = 'Watch events (live)';     File = 'hunt\Watch-Events.ps1';         RO = $true;  Desc = 'Event-log alerts with source IP: new users, tasks, services, logons, tampering' }
    @{ Key = 'C';  Name = 'Check scored services';   File = 'hunt\Test-ScoredServices.ps1';  RO = $true;  Desc = 'Listener -> service -> firewall -> answer for every scored port; says WHY it is down' }
    @{ Key = 'I';  Name = 'Incident worksheet';      File = 'hunt\New-IncidentReport.ps1';   RO = $true;  Desc = 'Candidate source IPs + timeline + what was removed, for the incident portal' }
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
        'T' {
            if (Read-YesNo 'Also run winPEAS? (Defender may quarantine it; output can contain credentials)' $false) { $p.IncludeWinPEAS = $true }
        }
        '10' {
            $skip = Read-List 'Modules to SKIP (Enter = none; e.g. EnableLSAProtection,RequireSMBSigning)'
            if ($skip) { $p.Skip = $skip }
        }
        'W' {
            $m = Read-Host '  [1] take/replace BASELINE  [2] diff once  [3] diff every 15 min (loop)  [4] INSTALL scheduled task  [5] remove scheduled task'
            switch ($m) { '1' { $p.Mode = 'Baseline' } '2' { $p.Mode = 'Diff' } '3' { $p.Mode = 'Diff'; $p.Loop = $true } '4' { $p.InstallTask = $true } '5' { $p.UninstallTask = $true } default { return $null } }
        }
        'E' {
            $m = Read-Host '  [1] look back (one pass)  [2] LIVE loop (Ctrl+C stops)'
            if ($m -eq '2') { $p.Loop = $true; $p.Beep = $true }
            $lb = Read-Host '  Minutes to look back first (Enter = 60 one-pass / 10 live)'
            if ($lb -match '^\d+$') { $p.LookbackMinutes = [int]$lb }
        }
        'C' {
            $m = Read-Host '  [1] check once  [2] LOOP every 60 s  [3] check once and SAVE BASELINE (scoreboard must be green)'
            switch ($m) { '2' { $p.Loop = $true; $p.Beep = $true } '3' { $p.SaveBaseline = $true } }
            $tcp = Read-List 'TCP ports (Enter = scored ports from config)'
            if ($tcp) { $p.Tcp = [int[]]$tcp }
        }
        'I' {
            $t = Read-Host '  Short title (e.g. rogue admin hacker)'; if ($t) { $p.Title = $t }
            $mins = Read-Host '  Minutes to look back (Enter = 120)'; if ($mins -match '^\d+$') { $p.SinceMinutes = [int]$mins }
            $ips = Read-List 'Known attacker IPs (Enter = none)'; if ($ips) { $p.SourceIp = $ips }
            $ind = Read-Host '  Text to search the IIS logs for, e.g. shell file name (Enter = none)'; if ($ind) { $p.Indicator = $ind }
        }
        'R' {
            if (Read-YesNo 'Also list lower-confidence (YELLOW) items?' $false) { $p.MinLevel = 'YELLOW' }
            if (Read-YesNo 'DELETE tasks/services instead of disabling them?' $false) { $p.Delete = $true }
        }
        'D' {
            $u = Read-List 'Users to log off (Enter = just list sessions; type ALL for everyone but you)'
            if ($u -and $u[0] -ieq 'ALL') { $p.AllOthers = $true } elseif ($u) { $p.User = $u }
        }
        '13' {
            $su = Read-Host '  SQL login to connect with (Enter = Windows authentication)'; if ($su) { $p.SqlUser = $su }
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
    foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6', 'P', 'T', 'F', 'X' }) { Write-MenuLine $m 'White' }
    Write-Host '  [A]  ' -NoNewline -ForegroundColor Yellow; Write-Host 'Run ALL read-only audits' -NoNewline -ForegroundColor Cyan; Write-Host '  - 1-6 + P, reports saved to C:\ccdc\reports\' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host '  CHANGES THE BOX (dry run offered first)' -ForegroundColor Yellow
    foreach ($m in $menu | Where-Object { $_.Key -in '7', '8', '9', '10', '11', '12', '13', 'K', 'D' }) { Write-MenuLine $m 'White' }
    Write-Host ""
    Write-Host '  BACKUP / LOGGING' -ForegroundColor Magenta
    foreach ($m in $menu | Where-Object { $_.Key -in 'B', 'S', 'L' }) { Write-MenuLine $m 'White' }
    Write-Host ""
    Write-Host '  HUNT / RESPOND (keep E and C running in their own windows)' -ForegroundColor Magenta
    foreach ($m in $menu | Where-Object { $_.Key -in 'W', 'E', 'C', 'R', 'I' }) { Write-MenuLine $m 'White' }
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
    if ($m.Key -eq 'S') {
        # services\*.ps1 have their own -Action switch (no -WhatIf / -ConfigPath), so ask directly.
        $a = Read-Host '  [1] detect what is installed  [2] back up everything present  [3] full info write-up  [4] verify backups'
        $act = switch ($a) { '1' { 'Detect' } '2' { 'Backup' } '3' { 'Info' } '4' { 'Verify' } default { $null } }
        if (-not $act) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
        $sp = @{ Action = $act }
        if ($act -eq 'Backup') {
            $off = Read-Host '  Also copy backups off-box to (UNC path, Enter = skip)'
            if ($off) { $sp.OffboxPath = $off }
        }
        & $path @sp
        Write-Host '  Restore is per service: .\services\<Service>.ps1 -Action Restore' -ForegroundColor DarkGray
        return
    }
    $params = Get-ScriptParams $m.Key
    if ($null -eq $params) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
    if ($m.RO) {
        if ($m.Key -notin 'W', 'E', 'C', 'I' -and (Read-YesNo 'Save a report to C:\ccdc\reports\?' $true)) {
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
        $k = (Read-Host '  Which option? (1-13, P, T, F, X, K, D, B, S, L, W, E, C, R, I)').Trim().ToUpper()
        $m = $menu | Where-Object { $_.Key -eq $k }
        if ($m) { Get-Help (Join-Path $here $m.File) -Full | Out-Host -Paging }
    } elseif ($choice -eq 'A') {
        $dir = 'C:\ccdc\reports\{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6', 'P' }) {
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
