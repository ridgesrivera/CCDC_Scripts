<#
.SYNOPSIS
    Launch-Toolkit - the one panel for every Windows script: monitor, audit, harden, respond, back up.

.DESCRIPTION
    PURPOSE
      One window, short keys, no parameters to remember under pressure.
      The header is a live status board for this box (role, IPs, whether
      LIVE ALERTS are on, the newest alert). Read-only scripts run straight
      away. Scripts that CHANGE the box always offer a dry run (-WhatIf)
      first, then ask before running for real. Long-running monitors open
      in their own window so the panel stays free.

    WHAT IT READS    OS / role / IPs for the header; C:\bt\alerts.log (newest alert)
    WHAT IT CHANGES  nothing itself - see each script's header ([H] shows it)
    HOW TO UNDO      n/a

    START IT
      Double-click CCDC-Toolkit.bat in the repo root (it asks for admin rights)
      or:  powershell -ExecutionPolicy Bypass -File .\windows\Launch-Toolkit.ps1

    KEYS
      0   guided "first 15 minutes" run (does the safe things in order)
      D   LIVE ALERTS menu         ?<key>  explain an option, e.g. ?7
      H   full help for a script   Q       quit

    MANUAL EQUIVALENT
      Run any script directly, e.g.  .\audit\Audit-Users.ps1 -OutFile C:\ccdc\reports\users.txt
      Read any script's header:      Get-Help .\audit\Audit-Users.ps1 -Full
#>
[CmdletBinding()]
param([string]$ConfigPath)

$here = $PSScriptRoot
. "$here\lib\CCDC-Common.ps1"
$ToolkitVersion = '3.0'
$BtDir = 'C:\bt'
$ReportDir = 'C:\ccdc\reports'

# ---------------------------------------------------------------------------
# Menu table. Sec = section on screen. RO = read-only. Win = opens own window.
# ---------------------------------------------------------------------------
$menu = @(
    # MONITOR
    @{ Key = 'D';  Sec = 'MON'; Name = 'LIVE ALERTS';           File = 'alerts\bt-alerts.ps1';            RO = $false; Desc = 'Instant popup when Red Team acts: who, from which IP, how they got in, what that IP did before, and the undo commands. Install, watch, trust/block an IP, story of an IP, self-test.' }
    @{ Key = 'C';  Sec = 'MON'; Name = 'Scored services';       File = 'hunt\Test-ScoredServices.ps1';    RO = $true;  Desc = 'Listener -> service -> firewall -> real answer for every scored port, and WHY it is down. Loop mode beeps on a change.' }
    @{ Key = 'W';  Sec = 'MON'; Name = 'Change watch';          File = 'hunt\Watch-Changes.ps1';          RO = $true;  Desc = 'Baseline once, then diff users, admins, tasks, services, Run keys, listeners, shares every 15 min.' }
    @{ Key = 'N';  Sec = 'MON'; Name = 'Who is on this box';    File = 'alerts\whoshere.ps1';             RO = $true;  Desc = 'One screen: sessions, remote connections, recent logons, new users/tasks/services, diff vs baseline.' }
    # AUDIT
    @{ Key = '1';  Sec = 'AUD'; Name = 'Box overview';          File = 'recon\Get-BoxOverview.ps1';       RO = $true;  Desc = 'OS, role, IPs, listeners -> process, roles, patches, likely scored services.' }
    @{ Key = '2';  Sec = 'AUD'; Name = 'Users & admins';        File = 'audit\Audit-Users.ps1';           RO = $true;  Desc = 'Admin groups, roastable accounts, passwords in descriptions, new accounts.' }
    @{ Key = '3';  Sec = 'AUD'; Name = 'Persistence hunt';      File = 'audit\Audit-Persistence.ps1';     RO = $true;  Desc = 'Tasks, services, Run keys, WMI, IFEO/sticky keys, SSH keys, web shells.' }
    @{ Key = '4';  Sec = 'AUD'; Name = 'Network exposure';      File = 'audit\Audit-Network.ps1';         RO = $true;  Desc = 'Connections, firewall, SMBv1/signing, shares, RDP NLA, WinRM.' }
    @{ Key = '5';  Sec = 'AUD'; Name = 'Vulnerability check';   File = 'audit\Audit-Vulns.ps1';           RO = $true;  Desc = 'Zerologon, PrintNightmare, MS17-010, NoPAC, LLMNR, WDigest, LSA, Defender.' }
    @{ Key = '6';  Sec = 'AUD'; Name = 'AD + GPO (DC)';         File = 'audit\Audit-AD-GPO.ps1';          RO = $true;  Desc = 'GPO changes, DCSync rights, root ACL, delegation, krbtgt age.' }
    @{ Key = 'P';  Sec = 'AUD'; Name = 'Security policy';       File = 'audit\Audit-SecurityPolicy.ps1';  RO = $true;  Desc = 'GPO/AD/DNS settings safe to turn on, with the GPO path and check/fix commands.' }
    @{ Key = 'F';  Sec = 'AUD'; Name = 'PII / sensitive files'; File = 'audit\Audit-SensitiveFiles.ps1';  RO = $true;  Desc = 'SSNs, card numbers, passwords, keys in files (and SQL Server) + who can read them. PII loss is -200 points.' }
    @{ Key = 'X';  Sec = 'AUD'; Name = 'Software audit';        File = 'audit\Audit-Software.ps1';        RO = $true;  Desc = 'Remote-access tools, attack tools, junk -> inventory CSV for injects.' }
    @{ Key = 'T';  Sec = 'AUD'; Name = 'Vendor tool audits';    File = 'audit\Invoke-AuditTools.ps1';     RO = $true;  Desc = 'Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith (stage with tools\Get-CcdcTools.ps1).' }
    # HARDEN
    @{ Key = '7';  Sec = 'HAR'; Name = 'Rotate passwords';      File = 'harden\Rotate-Passwords.ps1';     RO = $false; Desc = 'Random passwords, shown once, never saved. Scored accounts excluded (they need a Password Change Request).' }
    @{ Key = '8';  Sec = 'HAR'; Name = 'Disable accounts';      File = 'harden\Disable-Accounts.ps1';     RO = $false; Desc = 'Disable (not delete) rogue accounts, with a rollback file.' }
    @{ Key = '9';  Sec = 'HAR'; Name = 'Firewall allowlist';    File = 'harden\Set-Firewall.ps1';         RO = $false; Desc = 'Default-deny inbound, scored ports open to any source, keeps your session, auto-rollback in 5 min.' }
    @{ Key = '10'; Sec = 'HAR'; Name = 'Baseline hardening';    File = 'harden\Harden-Baseline.ps1';      RO = $false; Desc = 'SMBv1, signing, LLMNR/NBT-NS, WDigest, LSA, spooler on DC, auditing, IFEO (each skippable).' }
    @{ Key = '11'; Sec = 'HAR'; Name = 'IIS / PHP hardening';   File = 'harden\Harden-IIS-PHP.ps1';       RO = $false; Desc = 'Back up web roots, WP DISALLOW_FILE_EDIT, config perms, WP admins/plugins.' }
    @{ Key = '12'; Sec = 'HAR'; Name = 'AD account hardening';  File = 'harden\Harden-AD.ps1';            RO = $false; Desc = 'DC: Kerberos pre-auth, reversible encryption, blank-password flag; lists roastable accounts.' }
    @{ Key = '13'; Sec = 'HAR'; Name = 'SQL Server hardening';  File = 'harden\Harden-MSSQL.ps1';         RO = $false; Desc = 'Audit sa / sysadmins / weak logins, turn off xp_cmdshell and friends.' }
    @{ Key = 'K';  Sec = 'HAR'; Name = 'Reset krbtgt';          File = 'harden\Reset-Krbtgt.ps1';         RO = $false; Desc = 'DC: kill golden tickets after a domain compromise (run twice, with a pause).' }
    # RESPOND
    @{ Key = 'R';  Sec = 'RES'; Name = 'Remove persistence';    File = 'hunt\Remove-Persistence.ps1';     RO = $false; Desc = 'Numbered list: preserve evidence first, then disable / quarantine what you pick.' }
    @{ Key = 'O';  Sec = 'RES'; Name = 'Log off sessions';      File = 'harden\Disconnect-Sessions.ps1';  RO = $false; Desc = 'List / log off RDP, SMB, WinRM, SSH sessions (do it right after a password change).' }
    @{ Key = 'E';  Sec = 'RES'; Name = 'Event-log sweep';       File = 'hunt\Watch-Events.ps1';           RO = $true;  Desc = 'Look back N minutes: new users, tasks, services, logons, tampering, DCSync, roasting, each with source IP.' }
    @{ Key = 'I';  Sec = 'RES'; Name = 'Incident worksheet';    File = 'hunt\New-IncidentReport.ps1';     RO = $true;  Desc = 'Candidate attacker IPs + timeline + what was removed: facts for the incident report ticket.' }
    # BACKUP / LOGGING
    @{ Key = 'B';  Sec = 'BAK'; Name = 'Backup this box';       File = 'backup\Backup-Box.ps1';           RO = $false; Desc = 'Registry, tasks, firewall, AD/GPO/DNS (DC), IIS -> C:\ccdc\backups.' }
    @{ Key = 'S';  Sec = 'BAK'; Name = 'Per-service backup';    File = 'services\Invoke-AllServices.ps1'; RO = $false; Desc = 'Detect every service (DNS, IIS, SQL, SMB, FTP, VNC...), back up / info / verify each.' }
    @{ Key = 'L';  Sec = 'BAK'; Name = 'Setup logging';         File = 'logging\Setup-Logging.ps1';       RO = $false; Desc = 'Audit policy, PowerShell logging, Sysmon (if staged), forward to a syslog/Graylog server.' }
)
$sections = @(
    @{ Id = 'MON'; Title = 'MONITOR   keep these running in their own windows'; Color = 'Red' }
    @{ Id = 'AUD'; Title = 'AUDIT     read-only, safe any time';                Color = 'Green' }
    @{ Id = 'HAR'; Title = 'HARDEN    dry run first, you confirm each change';  Color = 'Yellow' }
    @{ Id = 'RES'; Title = 'RESPOND   an alert fired, now what';                Color = 'Magenta' }
    @{ Id = 'BAK'; Title = 'BACKUP & LOGGING';                                   Color = 'Cyan' }
)

# ---------------------------------------------------------------------------
# Small prompts
# ---------------------------------------------------------------------------
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
function Get-ReportPath([string]$file) {
    return ('{0}\{1}_{2}_{3}.txt' -f $ReportDir, ([IO.Path]::GetFileNameWithoutExtension($file)), $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
function Start-InNewWindow([string]$path, [string]$argLine, [string]$title) {
    # Monitors run in their own console so the panel stays usable.
    $cmd = "`$host.UI.RawUI.WindowTitle = '$title'; & '$path' $argLine"
    Start-Process powershell.exe -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd) | Out-Null
    Write-Host "  Opened in a new window: $title" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Status header (cheap queries only; it is redrawn after every action)
# ---------------------------------------------------------------------------
$script:osCaption = $null
function Get-AlertStatus {
    $s = @{ Tasks = 0; Disabled = 0; Watch = $false; Last = $null }
    try {
        $t = @(Get-ScheduledTask -TaskName 'BT-Alert-*' -ErrorAction SilentlyContinue)
        $s.Tasks = $t.Count
        $s.Disabled = @($t | Where-Object { $_.State -eq 'Disabled' }).Count
    } catch { $null = $_ }
    $pidFile = Join-Path $BtDir 'watch.pid'
    if (Test-Path $pidFile) {
        $wp = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($wp -match '^\d+$' -and (Get-Process -Id ([int]$wp) -ErrorAction SilentlyContinue)) { $s.Watch = $true }
    }
    $log = Join-Path $BtDir 'alerts.log'
    if (Test-Path $log) { $s.Last = Get-Content $log -Tail 1 -ErrorAction SilentlyContinue }
    return $s
}
function Show-Header {
    if (-not $script:osCaption) {
        try { $script:osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption -replace 'Microsoft ', '' } catch { $script:osCaption = 'Windows' }
    }
    $role = switch (Get-CcdcDomainRole) { 0 { 'Standalone workstation' } 1 { 'Domain workstation' } 2 { 'Standalone server' } 3 { 'Member server' } 4 { 'DOMAIN CONTROLLER' } 5 { 'DOMAIN CONTROLLER (PDC)' } default { 'unknown role' } }
    $isAdmin = Test-CcdcIsAdmin
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | ForEach-Object { $_.IPAddress })
    $cfg = Get-CcdcConfig -Path $ConfigPath
    $hc  = Get-CcdcHostConfig -Config $cfg
    $al  = Get-AlertStatus

    $bar = '=' * 78
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host '  CCDC BLUE TEAM TOOLKIT ' -NoNewline -ForegroundColor Cyan
    Write-Host ("v{0}" -f $ToolkitVersion) -NoNewline -ForegroundColor DarkGray
    Write-Host ((Get-Date -Format 'HH:mm').PadLeft(49)) -ForegroundColor DarkGray
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host '  HOST    ' -NoNewline -ForegroundColor DarkGray
    Write-Host ('{0}  ' -f $env:COMPUTERNAME) -NoNewline -ForegroundColor White
    Write-Host ('{0}  |  {1}' -f $script:osCaption, $role) -ForegroundColor Gray
    Write-Host '  IP      ' -NoNewline -ForegroundColor DarkGray
    Write-Host $(if ($ips) { $ips -join ', ' } else { '(none)' }) -ForegroundColor Gray
    Write-Host '  RIGHTS  ' -NoNewline -ForegroundColor DarkGray
    if ($isAdmin) { Write-Host 'Administrator' -ForegroundColor Green }
    else { Write-Host 'NOT ELEVATED - close this and use CCDC-Toolkit.bat (it asks for admin)' -ForegroundColor Red }
    Write-Host '  ALERTS  ' -NoNewline -ForegroundColor DarkGray
    if ($al.Tasks -eq 0) {
        Write-Host 'OFF - press D then 1 to turn on LIVE ALERTS' -ForegroundColor Yellow
    } else {
        $txt = '{0} detections armed' -f $al.Tasks
        if ($al.Disabled) { $txt += (', {0} DISABLED (tampering?)' -f $al.Disabled) }
        $txt += $(if ($al.Watch) { ', watch window open' } else { ', watch window CLOSED (D then 2)' })
        Write-Host $txt -ForegroundColor $(if ($al.Disabled -or -not $al.Watch) { 'Yellow' } else { 'Green' })
    }
    if ($al.Last) {
        $last = $al.Last; if ($last.Length -gt 68) { $last = $last.Substring(0, 68) + '...' }
        Write-Host '  LAST    ' -NoNewline -ForegroundColor DarkGray
        Write-Host $last -ForegroundColor Gray
    }
    Write-Host '  CONFIG  ' -NoNewline -ForegroundColor DarkGray
    Write-Host $(if ($hc) { "$($hc.name) - $($hc.role)" } elseif ($cfg) { 'loaded (this host not listed)' } else { 'none - generic mode (fine)' }) -ForegroundColor DarkGray
    Write-Host ('-' * 78) -ForegroundColor DarkCyan
}

function Show-Menu {
    Clear-Host
    Show-Header
    Write-Host '  START  ' -NoNewline -ForegroundColor White
    Write-Host '[0] ' -NoNewline -ForegroundColor Yellow
    Write-Host 'First 15 minutes (guided)' -NoNewline -ForegroundColor Cyan
    Write-Host '  overview, backup, alerts, audits, baselines' -ForegroundColor DarkGray
    foreach ($sec in $sections) {
        Write-Host ''
        Write-Host ("  {0}" -f $sec.Title) -ForegroundColor $sec.Color
        $items = @($menu | Where-Object { $_.Sec -eq $sec.Id })
        for ($i = 0; $i -lt $items.Count; $i += 2) {
            Write-MenuCell $items[$i] $true
            if ($i + 1 -lt $items.Count) { Write-MenuCell $items[$i + 1] $false } else { Write-Host '' }
        }
        if ($sec.Id -eq 'AUD') {
            Write-Host '   [A]  ' -NoNewline -ForegroundColor Yellow
            Write-Host 'Run ALL quick audits' -NoNewline -ForegroundColor Cyan
            Write-Host ' (1-6 + P) -> one report folder' -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host '  [H] full help for a script   [?7] explain an option   [Q] quit' -ForegroundColor DarkGray
    Write-Host ''
}
function Write-MenuCell($m, [bool]$left) {
    Write-Host (('   [{0}]' -f $m.Key).PadRight(8)) -NoNewline -ForegroundColor Yellow
    if ($left) { Write-Host $m.Name.PadRight(30) -NoNewline -ForegroundColor White }
    else { Write-Host $m.Name -ForegroundColor White }
}

# ---------------------------------------------------------------------------
# Per-script questions, so nobody has to remember parameters.
# Return $null to cancel.
# ---------------------------------------------------------------------------
function Get-ScriptParams([string]$key) {
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
            Write-Host '  Scored accounts need a Password Change Request in the scoring portal FIRST. List them to exclude.' -ForegroundColor Yellow
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
            $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' -and [int]$_.LocalPort -lt 49152 } | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique)
            if ($listen) { Write-Host ("  Listening now (TCP): {0}" -f ($listen -join ', ')) -ForegroundColor DarkGray }
            $tcp = Read-List 'TCP ports to allow (Enter = scored ports from config)'
            if ($tcp) { $p.AllowTcp = [int[]]$tcp }
            $udp = Read-List 'UDP ports to allow (Enter = from config / none; e.g. 53,123,161)'
            if ($udp) { $p.AllowUdp = [int[]]$udp }
            $adm = Read-List 'Admin source CIDRs for RDP/WinRM (Enter = config adminSources / this subnet + your live session)'
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
            $m = Read-Host '  [1] take/replace BASELINE  [2] diff once  [3] diff every 15 min (new window)  [4] INSTALL scheduled task  [5] remove task'
            switch ($m) { '1' { $p.Mode = 'Baseline' } '2' { $p.Mode = 'Diff' } '3' { $p.Mode = 'Diff'; $p.Loop = $true } '4' { $p.InstallTask = $true } '5' { $p.UninstallTask = $true } default { return $null } }
        }
        'N' {
            if (Read-YesNo 'Save this as the BASELINE (do it early, while the box is clean)?' $false) { $p.SaveBaseline = $true }
            $mins = Read-Host '  Minutes of logon history (Enter = 60)'; if ($mins -match '^\d+$') { $p.Minutes = [int]$mins }
        }
        'E' {
            $lb = Read-Host '  Minutes to look back (Enter = 60)'
            if ($lb -match '^\d+$') { $p.LookbackMinutes = [int]$lb }
        }
        'C' {
            $m = Read-Host '  [1] check once  [2] LOOP every 60 s (new window)  [3] check once and SAVE BASELINE (scoreboard must be green)'
            switch ($m) { '2' { $p.Loop = $true; $p.Beep = $true } '3' { $p.SaveBaseline = $true } }
            $tcp = Read-List 'TCP ports (Enter = config, else what is listening now)'
            if ($tcp) { $p.Tcp = [int[]]$tcp }
        }
        'I' {
            $t = Read-Host '  Short title (e.g. rogue admin account)'; if ($t) { $p.Title = $t }
            $mins = Read-Host '  Minutes to look back (Enter = 120)'; if ($mins -match '^\d+$') { $p.SinceMinutes = [int]$mins }
            $ips = Read-List 'Known attacker IPs (Enter = none)'; if ($ips) { $p.SourceIp = $ips }
            $ind = Read-Host '  Text to search the IIS logs for, e.g. shell file name (Enter = none)'; if ($ind) { $p.Indicator = $ind }
        }
        'R' {
            if (Read-YesNo 'Also list lower-confidence (YELLOW) items?' $false) { $p.MinLevel = 'YELLOW' }
            if (Read-YesNo 'DELETE tasks/services instead of disabling them?' $false) { $p.Delete = $true }
        }
        'O' {
            $u = Read-List 'Users to log off (Enter = just list sessions; type ALL for everyone but you)'
            if ($u -and $u[0] -ieq 'ALL') { $p.AllOthers = $true } elseif ($u) { $p.User = $u }
        }
        '13' {
            $su = Read-Host '  SQL login to connect with (Enter = Windows authentication)'; if ($su) { $p.SqlUser = $su }
        }
    }
    return $p
}

# ---------------------------------------------------------------------------
# LIVE ALERTS submenu. The bundle is standalone (paste-deployable) so it is
# installed to C:\bt and run from there, not from the repo folder.
# ---------------------------------------------------------------------------
function Install-LiveAlerts {
    $src = Join-Path $here 'alerts'
    New-Item $BtDir -ItemType Directory -Force | Out-Null
    foreach ($f in 'bt-alerts.ps1', 'bt-selftest.ps1', 'whoshere.ps1', 'pii-hunt.ps1') { Copy-Item (Join-Path $src $f) (Join-Path $BtDir $f) -Force }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $BtDir 'bt-alerts.ps1') -Install
}
function Invoke-LiveAlerts {
    $bt = Join-Path $BtDir 'bt-alerts.ps1'
    $st = Get-AlertStatus
    Write-Host ''
    if ($st.Tasks) { Write-Host ("  LIVE ALERTS: ON ({0} detections){1}" -f $st.Tasks, $(if ($st.Watch) { ', watch window open' } else { ', watch window CLOSED' })) -ForegroundColor Green }
    else { Write-Host '  LIVE ALERTS: OFF on this box' -ForegroundColor Yellow }
    Write-Host ''
    Write-Host '   [1] Install / reinstall      turn alerts on, 24 h backfill, open the watch window' -ForegroundColor White
    Write-Host '   [2] Reopen watch window      [3] Trust an IP (scorer / teammate)' -ForegroundColor White
    Write-Host '   [4] Block an IP (firewall)   [5] Story of an IP (attack chain)' -ForegroundColor White
    Write-Host '   [6] Snooze popups            [7] Backfill: what already happened' -ForegroundColor White
    Write-Host '   [8] Self-test (fires every detection, PASS/FAIL)' -ForegroundColor White
    Write-Host '   [9] Remove alerts from this box' -ForegroundColor DarkGray
    $a = (Read-Host '  Choice').Trim()
    if ($a -eq '1') { Install-LiveAlerts; return }
    if (-not (Test-Path $bt)) { Write-Host '  Not installed yet: choose [1] first.' -ForegroundColor Red; return }
    switch ($a) {
        '2' { Start-Process powershell.exe -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $bt, '-Watch') | Out-Null }
        '3' { $ip = Read-Host '  IP to trust (scoring engine / teammate)'; if ($ip) { & $bt -Trust $ip } }
        '4' { $ip = Read-Host '  IP to BLOCK (in + out)'; if ($ip -and (Read-YesNo "Block $ip on this box's firewall? (never the scoring engine)" $false)) { & $bt -Block $ip } }
        '5' { $ip = Read-Host '  IP'; $h = Read-Host '  Hours back (Enter = 24)'; if ($ip) { if ($h -match '^\d+$') { & $bt -Chain $ip -Hours ([int]$h) } else { & $bt -Chain $ip } } }
        '6' { $n = Read-Host '  Minutes (Enter = 10)'; if ($n -notmatch '^\d+$') { $n = 10 }; & $bt -Snooze ([int]$n) }
        '7' { $h = Read-Host '  Hours back (Enter = 24)'; if ($h -match '^\d+$') { & $bt -Backfill -Hours ([int]$h) } else { & $bt -Backfill } }
        '8' { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $BtDir 'bt-selftest.ps1') }
        '9' { if (Read-YesNo 'Remove all BT-Alert tasks from this box?' $false) { & $bt -Remove } }
        default { Write-Host '  Cancelled.' -ForegroundColor DarkGray }
    }
}

# ---------------------------------------------------------------------------
# Run one menu entry
# ---------------------------------------------------------------------------
function Invoke-Entry($m) {
    $path = Join-Path $here $m.File
    if (-not (Test-Path $path)) { Write-Host "  Not found: $path" -ForegroundColor Red; return }
    Write-Host ''
    Write-Host ("  {0}: " -f $m.Name) -NoNewline -ForegroundColor Cyan
    Write-Host $m.Desc -ForegroundColor DarkGray
    if ($m.Key -eq 'D') { Invoke-LiveAlerts; return }
    if ($m.Key -eq 'F') {
        $a = Read-Host '  [1] deep file scan + who can read it  [2] quick PII hunt incl. SQL Server databases'
        if ($a -eq '2') { & $path.Replace('audit\Audit-SensitiveFiles.ps1', 'alerts\pii-hunt.ps1'); return }
        if ($a -ne '1') { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
    }
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
    if ($m.Key -eq 'N') { $params.Remove('ConfigPath') }   # standalone bundle script, no config

    # Loops go to their own window so the panel stays free.
    if ($params.Loop) {
        $argLine = ($params.GetEnumerator() | ForEach-Object {
            if ($_.Value -is [bool]) { "-$($_.Key)" }
            elseif ($_.Value -is [array]) { "-$($_.Key) " + (($_.Value | ForEach-Object { "'$_'" }) -join ',') }
            else { "-$($_.Key) '$($_.Value)'" }
        }) -join ' '
        Start-InNewWindow $path $argLine ("CCDC {0} - {1}" -f $m.Name, $env:COMPUTERNAME)
        return
    }
    if ($m.RO) {
        if ($m.Key -notin 'W', 'C', 'I', 'N', 'E' -and (Read-YesNo "Save a report to $ReportDir?" $true)) {
            $params.OutFile = Get-ReportPath $m.File
        }
        & $path @params
        return
    }
    # State-changing: dry run first, then the real thing.
    if (Read-YesNo 'Dry run first (-WhatIf, changes nothing)?' $true) {
        & $path @params -WhatIf
        Write-Host ''
        if (-not (Read-YesNo 'Run it FOR REAL now? (you will confirm each action)' $false)) { return }
    }
    & $path @params
}

# ---------------------------------------------------------------------------
# [0] Guided first 15 minutes. Only safe steps; each one can be skipped.
# ---------------------------------------------------------------------------
function Invoke-FirstSteps {
    $dir = '{0}\first15_{1}_{2}' -f $ReportDir, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm')
    $cp = @{}; if ($ConfigPath) { $cp.ConfigPath = $ConfigPath }
    $steps = @(
        @{ T = 'Box overview: what is this box, what is listening';               Do = { & (Join-Path $here 'recon\Get-BoxOverview.ps1') @cp -OutFile (Join-Path $dir 'overview.txt') } }
        @{ T = 'Backup: registry, tasks, firewall, AD/DNS/GPO, IIS (writes only C:\ccdc\backups)'; Do = { & (Join-Path $here 'backup\Backup-Box.ps1') @cp } }
        @{ T = 'LIVE ALERTS: turn on instant alerts (opens the watch window)';    Do = { Install-LiveAlerts } }
        @{ T = 'Users & admins audit: who has admin, roastable, odd accounts';    Do = { & (Join-Path $here 'audit\Audit-Users.ps1') @cp -OutFile (Join-Path $dir 'users.txt') } }
        @{ T = 'Persistence hunt: tasks, services, Run keys, web shells';         Do = { & (Join-Path $here 'audit\Audit-Persistence.ps1') @cp -OutFile (Join-Path $dir 'persistence.txt') } }
        @{ T = 'Who is on this box + save baseline';                               Do = { & (Join-Path $here 'alerts\whoshere.ps1') -SaveBaseline } }
        @{ T = 'Change-watch baseline (diff later with W)';                        Do = { & (Join-Path $here 'hunt\Watch-Changes.ps1') @cp -Mode Baseline } }
        @{ T = 'Scored services: check + save baseline (only if the scoreboard is green)'; Do = { & (Join-Path $here 'hunt\Test-ScoredServices.ps1') @cp -SaveBaseline } }
    )
    Write-Host ''
    Write-Host '  FIRST 15 MINUTES - each step asks first; Enter = yes, n = skip.' -ForegroundColor Cyan
    Write-Host "  Reports: $dir" -ForegroundColor DarkGray
    $n = 0
    foreach ($s in $steps) {
        $n++
        Write-Host ''
        Write-Host ("  ---- Step {0}/{1}: {2}" -f $n, $steps.Count, $s.T) -ForegroundColor Yellow
        if (-not (Read-YesNo 'Run this step?' $true)) { continue }
        try { & $s.Do } catch { Write-Host "  Step failed: $_" -ForegroundColor Red }
    }
    Write-Host ''
    Write-Host '  Done. Next, by hand (each needs a decision):' -ForegroundColor Green
    Write-Host '    [7] rotate passwords  (scored accounts: Password Change Request first)' -ForegroundColor Gray
    Write-Host '    [O] log off old sessions right after rotating' -ForegroundColor Gray
    Write-Host '    [9] firewall allowlist (scored ports stay open to any source)' -ForegroundColor Gray
    Write-Host '    [10] baseline hardening, [L] logging, then keep [C] looping in its own window' -ForegroundColor Gray
    Write-Host '    D -> 3 trust the scoring engine IP as soon as you see it in an alert' -ForegroundColor Gray
}

function Show-Explain([string]$k) {
    $m = $menu | Where-Object { $_.Key -eq $k }
    if (-not $m) { Write-Host '  Unknown option.' -ForegroundColor Red; return }
    Write-Host ''
    Write-Host ("  [{0}] {1}  ({2})" -f $m.Key, $m.Name, $(if ($m.RO) { 'read-only' } else { 'CHANGES THE BOX or installs something' })) -ForegroundColor Cyan
    Write-Host ("  {0}" -f $m.Desc) -ForegroundColor Gray
    Write-Host ("  Script: windows\{0}   (H for the full header)" -f $m.File) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
try { $host.UI.RawUI.WindowTitle = "CCDC Toolkit - $env:COMPUTERNAME" } catch { $null = $_ }
while ($true) {
    Show-Menu
    $choice = (Read-Host '  Select').Trim().ToUpper()
    if (-not $choice) { continue }
    if ($choice -eq 'Q') { break }
    if ($choice -eq '0') {
        Invoke-FirstSteps
    } elseif ($choice -match '^\?\s*(\w+)$') {
        Show-Explain $Matches[1]
    } elseif ($choice -eq 'H') {
        $k = (Read-Host '  Which option? (e.g. 7, D, C)').Trim().ToUpper()
        $m = $menu | Where-Object { $_.Key -eq $k }
        if ($m) { Get-Help (Join-Path $here $m.File) -Full | Out-Host -Paging }
    } elseif ($choice -eq 'A') {
        $dir = '{0}\{1}_{2}' -f $ReportDir, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6', 'P' }) {
            if ($m.Key -eq '6' -and -not (Test-CcdcIsDC)) { continue }
            $p = @{ OutFile = (Join-Path $dir (([IO.Path]::GetFileNameWithoutExtension($m.File)) + '.txt')) }
            if ($ConfigPath) { $p.ConfigPath = $ConfigPath }
            try { & (Join-Path $here $m.File) @p } catch { Write-Host "  $($m.Name) failed: $_" -ForegroundColor Red }
        }
        Write-Host "`n  All reports: $dir" -ForegroundColor Green
    } else {
        $m = $menu | Where-Object { $_.Key -eq $choice }
        if ($m) { try { Invoke-Entry $m } catch { Write-Host "  Error: $_" -ForegroundColor Red } }
        else { Write-Host '  Unknown option.' -ForegroundColor Red }
    }
    Write-Host "`n  Press Enter to return to the menu..." -ForegroundColor DarkGray
    [void](Read-Host)
}
