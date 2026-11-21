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

    SNAPSHOTS
      The first time the panel opens on a box it saves an ORIGINAL snapshot
      (how the box was when we got here). Before any script that changes the
      box runs for real, it saves another one. W shows what changed since,
      and who did it; U puts any of it back.

    KEYS
      0   guided "first 15 minutes" run (does the safe things in order)
      S / W / U  snapshot / what changed / undo     D  LIVE ALERTS
      ?<key>  explain an option, e.g. ?13           H  full help   Q quit

    MANUAL EQUIVALENT
      Run any script directly, e.g.  .\audit\Audit-Users.ps1 -OutFile C:\ccdc\reports\users.txt
      Read any script's header:      Get-Help .\audit\Audit-Users.ps1 -Full
#>
[CmdletBinding()]
param([string]$ConfigPath)

$here = $PSScriptRoot
. "$here\lib\CCDC-Common.ps1"
$ToolkitVersion = '3.2'
$BtDir = 'C:\bt'
$ReportDir = 'C:\ccdc\reports'

# ---------------------------------------------------------------------------
# Menu table. Sec = section on screen. RO = read-only. Win = opens own window.
# ---------------------------------------------------------------------------
$menu = @(
    # MONITOR
    @{ Key = 'D';  Sec = 'MON'; Name = 'LIVE ALERTS';           File = 'alerts\bt-alerts.ps1';            RO = $false; Desc = 'Instant popup when Red Team acts: who, from which IP, how they got in, what that IP did before. Install, watch, trust/block an IP, story of an IP, self-test.' }
    @{ Key = 'N';  Sec = 'MON'; Name = 'Who is on this box';    File = 'alerts\whoshere.ps1';             RO = $true;  Desc = 'Every way in (RDP, SSH, SMB, WinRM, WMI, VNC, Telnet, FTP, web, SQL): is it on, and who is connected right now from where.' }
    # RED TEAM RESPONSE
    @{ Key = 'E';  Sec = 'RES'; Name = 'Find attacks (what to do)'; File = 'hunt\Find-Attacks.ps1';       RO = $true;  Desc = 'Reads the logs and names the attack: password guessing on any service, Kerberoasting, AS-REP roasting, DCSync, new admin, PsExec, web shell, credential dumping... with step-by-step response.' }
    @{ Key = 'X';  Sec = 'RES'; Name = 'Kick user / block IP';  File = 'hunt\Kick-Block.ps1';             RO = $false; Desc = 'Log a user off everywhere + disable the account, and/or block an IP in + out. Every action can be undone.' }
    @{ Key = 'R';  Sec = 'RES'; Name = 'Remove persistence';    File = 'hunt\Remove-Persistence.ps1';     RO = $false; Desc = 'Numbered list of tasks, services, Run keys, web shells...: keeps evidence, then disables / quarantines what you pick.' }
    @{ Key = 'F';  Sec = 'RES'; Name = 'Fix DNS outage';        File = 'hunt\Repair-DNS.ps1';             RO = $false; Desc = 'DNS down? Finds out if it was just turned off or something bigger, tries the standard fixes (each asks first), verifies, and tells you what is left.' }
    @{ Key = 'I';  Sec = 'RES'; Name = 'Incident worksheet';    File = 'hunt\New-IncidentReport.ps1';     RO = $true;  Desc = 'Candidate attacker IPs + timeline + what was removed: the facts for an incident report.' }
    # SNAPSHOT & ROLLBACK
    @{ Key = 'S';  Sec = 'SNP'; Name = 'Take snapshot';         File = 'backup\Snapshot-State.ps1';       RO = $true;  Desc = 'Save the security state now: registry security settings, services, users, admin groups, shares, hosts, Defender, firewall, audit + security policy. The first one is the ORIGINAL.' }
    @{ Key = 'W';  Sec = 'SNP'; Name = 'What changed?';         File = 'backup\Snapshot-State.ps1';       RO = $true;  Desc = 'Every setting that changed since a snapshot, marked [toolkit] or NOT BY THE TOOLKIT; plus new users/tasks/services/keys since the change baseline.' }
    @{ Key = 'U';  Sec = 'SNP'; Name = 'Undo changes';          File = 'backup\Snapshot-State.ps1';       RO = $false; Desc = 'Something broke? Pick a snapshot, pick the changes, put them back (each confirmed, backed up, and undoable).' }
    # AUDIT
    @{ Key = '1';  Sec = 'AUD'; Name = 'Box overview';          File = 'recon\Get-BoxOverview.ps1';       RO = $true;  Desc = 'OS, role, IPs, listeners -> process, roles, installed services, patches.' }
    @{ Key = '2';  Sec = 'AUD'; Name = 'Users & admins';        File = 'audit\Audit-Users.ps1';           RO = $true;  Desc = 'Who is in admin groups, roastable accounts, passwords in descriptions, accounts created after setup. Grouped, one line per problem.' }
    @{ Key = '3';  Sec = 'AUD'; Name = 'Persistence hunt';      File = 'audit\Audit-Persistence.ps1';     RO = $true;  Desc = 'Tasks, services, Run keys, WMI, IFEO/sticky keys, SSH keys, web shells.' }
    @{ Key = '4';  Sec = 'AUD'; Name = 'Network exposure';      File = 'audit\Audit-Network.ps1';         RO = $true;  Desc = 'Connections, firewall, SMBv1/signing, shares, RDP NLA, WinRM.' }
    @{ Key = '5';  Sec = 'AUD'; Name = 'Vulns (CVE check)';     File = 'audit\Audit-Vulns.ps1';           RO = $true;  Desc = 'Zerologon, PrintNightmare, EternalBlue, noPac, PetitPotam, Certifried, SIGRed, HiveNightmare, relay, cleartext creds... NOW vs ORIGINAL snapshot: what you fixed, what regressed.' }
    @{ Key = '6';  Sec = 'AUD'; Name = 'AD + GPO (DC)';         File = 'audit\Audit-AD-GPO.ps1';          RO = $true;  Desc = 'GPO changes, DCSync rights, root ACL, delegation, krbtgt age.' }
    @{ Key = '7';  Sec = 'AUD'; Name = 'PII / sensitive files'; File = 'audit\Audit-SensitiveFiles.ps1';  RO = $true;  Desc = 'SSNs, card numbers, passwords, keys in files (and SQL Server) + who can read them.' }
    @{ Key = '8';  Sec = 'AUD'; Name = 'C2 beacon scan';        File = 'hunt\Find-Beacons.ps1';           RO = $true;  Desc = 'Watches outbound connections for a minute: implants calling home, odd processes talking out, C2 pipes, DNS tunnelling.' }
    # HARDEN
    @{ Key = '10'; Sec = 'HAR'; Name = 'Rotate passwords';      File = 'harden\Rotate-Passwords.ps1';     RO = $false; Desc = 'Random passwords, shown once, never saved. Scored accounts excluded (they need a Password Change Request).' }
    @{ Key = '11'; Sec = 'HAR'; Name = 'Firewall (basic)';      File = 'harden\Set-Firewall.ps1';         RO = $false; Desc = 'Step by step: keep everything that is listening open, block other inbound, safety timer, one-key revert.' }
    @{ Key = '12'; Sec = 'HAR'; Name = 'Hardening walkthrough'; File = 'harden\Harden-Walkthrough.ps1';   RO = $false; Desc = 'Step by step: each change explained (what it stops, SAFE/CAUTION/DANGER). On a DC it goes into one GPO. Undo any step.' }
    @{ Key = '13'; Sec = 'HAR'; Name = 'IIS / PHP hardening';   File = 'harden\Harden-IIS-PHP.ps1';       RO = $false; Desc = 'Back up web roots, WP DISALLOW_FILE_EDIT, config perms, WP admins/plugins.' }
    @{ Key = '14'; Sec = 'HAR'; Name = 'SQL Server hardening';  File = 'harden\Harden-MSSQL.ps1';         RO = $false; Desc = 'Audit sa / sysadmins / weak logins, turn off xp_cmdshell and friends.' }
    @{ Key = '16'; Sec = 'HAR'; Name = 'Defender on';           File = 'harden\Repair-Defender.ps1';      RO = $false; Desc = 'Bring Defender back: reinstall if removed, start the service, remove policy switches that turn it off, real-time on, review exclusions, verify.' }
    @{ Key = '15'; Sec = 'HAR'; Name = 'Reset krbtgt (DC)';     File = 'harden\Reset-Krbtgt.ps1';         RO = $false; Desc = 'DC, after a domain compromise (DCSync, ntds.dit stolen): kills golden tickets. Run twice, with a pause.' }
    # BACKUP / LOGGING
    @{ Key = 'B';  Sec = 'BAK'; Name = 'Backup AD / IIS';       File = 'backup\Backup-Box.ps1';           RO = $false; Desc = 'On a DC: GPOs, DNS zones, AD objects. On a web server: IIS config + web roots. -> C:\ccdc\backups. Other services: P.' }
    @{ Key = 'P';  Sec = 'BAK'; Name = 'Per-service backup';    File = 'services\Invoke-AllServices.ps1'; RO = $false; Desc = 'Detect every service (DNS, IIS, SQL, SMB, FTP, VNC...), back up / verify / restore one service.' }
    @{ Key = 'L';  Sec = 'BAK'; Name = 'Setup logging';         File = 'logging\Setup-Logging.ps1';       RO = $false; Desc = 'Audit policy, PowerShell logging, Sysmon (if staged), forward to a syslog/Graylog server.' }
)
# Changing scripts that do NOT get an automatic snapshot first (they do not change settings, or handle it themselves).
$noAutoSnapshot = @('D', 'U', 'X', 'B', 'P', 'F')
$sections = @(
    @{ Id = 'MON'; Title = 'MONITOR   keep LIVE ALERTS open in its own window';  Color = 'Red' }
    @{ Id = 'RES'; Title = 'RED TEAM RESPONSE   something is happening';         Color = 'Magenta' }
    @{ Id = 'SNP'; Title = 'SNAPSHOT  what changed, and put it back';           Color = 'Cyan' }
    @{ Id = 'AUD'; Title = 'AUDIT     read-only, safe any time';                Color = 'Green' }
    @{ Id = 'HAR'; Title = 'HARDEN    step by step, every change reversible';   Color = 'Yellow' }
    @{ Id = 'BAK'; Title = 'BACKUP & LOGGING';                                   Color = 'DarkCyan' }
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
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $t = @(Get-ScheduledTask -TaskName 'BT-Alert-*' -ErrorAction SilentlyContinue)
            $s.Tasks = $t.Count
            $s.Disabled = @($t | Where-Object { $_.State -eq 'Disabled' }).Count
        } else {
            # Older Windows: schtasks.exe (CSV: TaskName, Next Run Time, Status)
            $rows = @(& schtasks.exe /query /fo csv /nh 2>$null | Where-Object { $_ -match '"\\?BT-Alert-' })
            $s.Tasks = $rows.Count
            $s.Disabled = @($rows | Where-Object { $_ -match '"Disabled"' }).Count
        }
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
    $snaps = @(Get-CcdcSnapshotList)
    Write-Host '  SNAPS   ' -NoNewline -ForegroundColor DarkGray
    if ($snaps.Count -eq 0) { Write-Host 'none yet - press S (ORIGINAL is taken automatically when elevated)' -ForegroundColor Yellow }
    else { Write-Host ("ORIGINAL {0}, {1} total, latest {2} {3}" -f $snaps[0].Time.ToString('HH:mm'), $snaps.Count, $snaps[-1].Time.ToString('HH:mm'), $snaps[-1].Label) -ForegroundColor Gray }
    Write-Host '  CONFIG  ' -NoNewline -ForegroundColor DarkGray
    Write-Host $(if ($hc) { "$($hc.name) - $($hc.role)" } elseif ($cfg) { 'loaded (this host not listed)' } else { 'none - generic mode (fine)' }) -ForegroundColor DarkGray
    Write-Host ('-' * 78) -ForegroundColor DarkCyan
}

function Show-Menu {
    Clear-Host
    Show-Header
    Write-Host '  START  ' -NoNewline -ForegroundColor White
    Write-Host '[0] ' -NoNewline -ForegroundColor Yellow
    Write-Host 'First 15 minutes (guided, zero)' -NoNewline -ForegroundColor Cyan
    Write-Host '  snapshot, backup, alerts, ports + SSH keys, admins, PII, vulns' -ForegroundColor DarkGray
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
            Write-Host ' (1-6) -> one report folder' -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host '  [H] full help for a script   [?13] explain an option   [Q] quit' -ForegroundColor DarkGray
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
        '10' {
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
        'N' {
            if (Read-YesNo 'Save this as the BASELINE (do it early, while the box is clean)?' $false) { $p.SaveBaseline = $true }
            $mins = Read-Host '  Minutes of logon history (Enter = 60)'; if ($mins -match '^\d+$') { $p.Minutes = [int]$mins }
        }
        'E' {
            $lb = Read-Host '  Hours of logs to check for attacks (Enter = 24)'
            if ($lb -match '^\d+$') { $p.Hours = [int]$lb }
        }
        '8' {
            $sec = Read-Host '  Seconds to watch connections (Enter = 60; slow beacons: 300)'
            if ($sec -match '^\d+$') { $p.Seconds = [int]$sec }
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
        '14' {
            $su = Read-Host '  SQL login to connect with (Enter = Windows authentication)'; if ($su) { $p.SqlUser = $su }
        }
    }
    return $p
}

# ---------------------------------------------------------------------------
# LIVE ALERTS submenu. The bundle is standalone (paste-deployable) so it is
# installed to C:\bt and run from there, not from the repo folder.
# ---------------------------------------------------------------------------
function Install-LiveAlerts([switch]$Quiet) {
    $src = Join-Path $here 'alerts'
    New-Item $BtDir -ItemType Directory -Force | Out-Null
    foreach ($f in 'bt-alerts.ps1', 'bt-selftest.ps1', 'whoshere.ps1', 'pii-hunt.ps1') { Copy-Item (Join-Path $src $f) (Join-Path $BtDir $f) -Force }
    $alertArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $BtDir 'bt-alerts.ps1'), '-Install')
    if ($Quiet) { $alertArgs += '-NoBackfill' }   # first 15: the users audit covers the same ground
    & powershell.exe @alertArgs
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
    if ($m.Key -eq '7') {
        $a = Read-Host '  [1] deep file scan + who can read it  [2] quick PII hunt incl. SQL Server databases'
        if ($a -eq '2') { & $path.Replace('audit\Audit-SensitiveFiles.ps1', 'alerts\pii-hunt.ps1'); return }
        if ($a -ne '1') { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
    }
    if ($m.Key -eq 'P') {
        # services\*.ps1 have their own -Action switch (no -WhatIf / -ConfigPath), so ask directly.
        $a = Read-Host '  [1] detect what is installed  [2] back up everything present  [3] full info write-up  [4] verify backups  [5] restore (pick)'
        $act = switch ($a) { '1' { 'Detect' } '2' { 'Backup' } '3' { 'Info' } '4' { 'Verify' } '5' { 'Restore' } default { $null } }
        if (-not $act) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
        if ($act -eq 'Restore') {
            $svcs = @(Get-ChildItem (Join-Path $here 'services') -Filter '*.ps1' | Where-Object { $_.Name -notmatch '^(_|Invoke-)' } | Sort-Object Name)
            for ($i = 0; $i -lt $svcs.Count; $i++) { Write-Host ("   [{0,2}] {1}" -f ($i + 1), $svcs[$i].BaseName) }
            $n = Read-Host '  Restore which service (number)'
            if ($n -notmatch '^\d+$' -or [int]$n -lt 1 -or [int]$n -gt $svcs.Count) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
            Save-AutoSnapshot "before-restore-$($svcs[[int]$n - 1].BaseName)"
            & $svcs[[int]$n - 1].FullName -Action Restore
            return
        }
        $sp = @{ Action = $act }
        if ($act -eq 'Backup') {
            $off = Read-Host '  Also copy backups off-box to (UNC path, Enter = skip)'
            if ($off) { $sp.OffboxPath = $off }
        }
        & $path @sp
        return
    }
    if ($m.Key -in 'S', 'W', 'U') { Invoke-Snapshot $m.Key; return }
    if ($m.Key -eq 'X') { Invoke-KickMenu $path; return }
    if ($m.Key -in 'F', '16') { & $path; return }   # every fix asks y/N itself: no separate dry run
    if ($m.Key -eq '11') { Invoke-FirewallMenu $path; return }
    if ($m.Key -eq '12') { Invoke-WalkthroughMenu $path; return }
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
        if ($m.Key -notin 'I', 'N' -and (Read-YesNo "Save a report to $ReportDir?" $true)) {
            $params.OutFile = Get-ReportPath $m.File
        }
        & $path @params
        return
    }
    # State-changing: dry run first, then snapshot, then the real thing.
    if (Read-YesNo 'Dry run first (-WhatIf, changes nothing)?' $true) {
        & $path @params -WhatIf
        Write-Host ''
        if (-not (Read-YesNo 'Run it FOR REAL now? (you will confirm each action)' $false)) { return }
    }
    if ($noAutoSnapshot -notcontains $m.Key) { Save-AutoSnapshot ('before-' + [IO.Path]::GetFileNameWithoutExtension($m.File)) }
    & $path @params
}

# ---------------------------------------------------------------------------
# Snapshots: automatic ones, and the S / W / U menus
# ---------------------------------------------------------------------------
function Save-AutoSnapshot([string]$label) {
    # Quiet snapshot so any change can be compared and undone later (panel U).
    if (-not (Test-CcdcIsAdmin)) { return }
    Write-Host ("  Snapshot before the change ({0})..." -f $label) -ForegroundColor DarkGray
    try { $null = & (Join-Path $here 'backup\Snapshot-State.ps1') -Mode Take -Label $label -Quiet *>&1 } catch { Write-Host "  Snapshot failed: $_" -ForegroundColor Yellow }
}
function Select-Snapshot([string]$prompt, [string]$default) {
    $list = @(Get-CcdcSnapshotList)
    if ($list.Count -eq 0) { Write-Host '  No snapshots yet: press S first.' -ForegroundColor Red; return $null }
    for ($i = 0; $i -lt $list.Count; $i++) {
        $tag = if ($i -eq 0) { '  <- ORIGINAL' } elseif ($i -eq $list.Count - 1) { '  <- latest' } else { '' }
        Write-Host ("   [{0,2}] {1}  {2}{3}" -f ($i + 1), $list[$i].Time.ToString('MM-dd HH:mm:ss'), $list[$i].Label, $tag)
    }
    $a = Read-Host "  $prompt (Enter = $default)"
    if (-not $a) { return $(if ($default -eq 'ORIGINAL') { $list[0].Name } else { $list[-1].Name }) }
    if ($a -match '^\d+$' -and [int]$a -ge 1 -and [int]$a -le $list.Count) { return $list[[int]$a - 1].Name }
    return $null
}
function Invoke-Snapshot([string]$key) {
    $snapScript = Join-Path $here 'backup\Snapshot-State.ps1'
    $cp = @{}; if ($ConfigPath) { $cp.ConfigPath = $ConfigPath }
    switch ($key) {
        'S' {
            $l = Read-Host '  Label (Enter = manual, e.g. after-hardening)'
            if (-not $l) { $l = 'manual' }
            & $snapScript -Mode Take -Label $l @cp
        }
        'W' {
            Write-Host '   [1] Settings changed since the ORIGINAL snapshot (and who changed them)'
            Write-Host '   [2] Settings changed since a snapshot you pick'
            Write-Host '   [3] New users / tasks / services / Run keys / listeners since the change baseline'
            Write-Host '   [4] Same as 3, every 15 min in a new window'
            Write-Host '   [5] Accept the current state as the new change baseline (only when the box is clean)'
            $a = Read-Host '  Choice'
            switch ($a) {
                '1' { & $snapScript -Mode Compare -Against original @cp }
                '2' { $n = Select-Snapshot 'Compare against' 'latest'; if ($n) { & $snapScript -Mode Compare -Against $n @cp } }
                '3' { & (Join-Path $here 'hunt\Watch-Changes.ps1') -Mode Diff @cp }
                '4' { Start-InNewWindow (Join-Path $here 'hunt\Watch-Changes.ps1') '-Mode Diff -Loop' "CCDC Change watch - $env:COMPUTERNAME" }
                '5' { & (Join-Path $here 'hunt\Watch-Changes.ps1') -Mode Baseline @cp }
                default { Write-Host '  Cancelled.' -ForegroundColor DarkGray }
            }
        }
        'U' {
            $n = Select-Snapshot 'Put things back to which snapshot' 'latest'
            if (-not $n) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
            if (Read-YesNo 'Dry run first (-WhatIf, changes nothing)?' $false) { & $snapScript -Mode Restore -Against $n -WhatIf @cp; Write-Host '' }
            if (Read-YesNo "Restore from '$n' for real? (you pick the items, each one is confirmed)" $true) { & $snapScript -Mode Restore -Against $n @cp }
        }
    }
}

# ---------------------------------------------------------------------------
# [0] Guided first 15 minutes. Only safe steps; each one can be skipped.
# ---------------------------------------------------------------------------
function Invoke-KickMenu([string]$path) {
    & $path -List | Out-Host
    Write-Host ''
    Write-Host '   [1] Kick a user: log off everywhere + disable the account'
    Write-Host '   [2] Block an IP: firewall in + out, close its sessions, show who logged on from it'
    Write-Host '   [3] Both: kick a user AND block an IP'
    Write-Host '   [4] Undo: unblock an IP / re-enable an account'
    $a = Read-Host '  Choice'
    $p = @{}; if ($ConfigPath) { $p.ConfigPath = $ConfigPath }
    if ($a -in '1', '3') { $u = Read-List 'User name(s) to kick (comma separated)'; if ($u) { $p.User = $u; $p.DisableAccount = (Read-YesNo 'Also DISABLE the account(s) so they cannot log back in?' $true) } }
    if ($a -in '2', '3') { $ip = Read-List 'IP address(es) to block'; if ($ip) { $p.BlockIp = $ip } }
    if ($a -eq '4') {
        $ip = Read-List 'IP(s) to UNBLOCK (Enter = none)'; if ($ip) { $p.Unblock = $ip }
        $u = Read-List 'Account(s) to RE-ENABLE (Enter = none)'; if ($u) { $p.Enable = $u }
    }
    if ($p.Count -le 1 -and -not ($p.User -or $p.BlockIp -or $p.Unblock -or $p.Enable)) { Write-Host '  Nothing chosen.' -ForegroundColor DarkGray; return }
    & $path @p
}
function Invoke-FirewallMenu([string]$path) {
    Write-Host '   [1] Turn on the basic firewall (step by step, safety timer)'
    Write-Host '   [2] REVERT: remove the toolkit''s rules, every profile back exactly as recorded'
    Write-Host '   [3] Status'
    Write-Host '   [4] Full restore from the saved policy file (only if 2 was not enough)' -ForegroundColor DarkGray
    Write-Host '   Locked out of the panel? Run C:\ccdc\firewall\revert.cmd as administrator.' -ForegroundColor DarkGray
    switch (Read-Host '  Choice') {
        '1' { Save-AutoSnapshot 'before-Set-Firewall'; & $path }
        '2' { & $path -Revert }
        '3' { & $path -Status }
        '4' { & $path -RestoreFull }
        default { Write-Host '  Cancelled.' -ForegroundColor DarkGray }
    }
}
function Invoke-WalkthroughMenu([string]$path) {
    Write-Host '   [1] Walk through the hardening steps (explained, apply or skip each)'
    Write-Host '   [2] Show what has been changed'
    Write-Host '   [3] UNDO: one step or everything'
    switch (Read-Host '  Choice') {
        '1' { Save-AutoSnapshot 'before-Harden-Walkthrough'; & $path -Mode Walk }
        '2' { & $path -Mode List }
        '3' {
            & $path -Mode List
            $st = Read-List 'Step id(s) to undo (Enter = ALL, newest first)'
            if ($st) { & $path -Mode Undo -Step $st } else { & $path -Mode Undo }
        }
        default { Write-Host '  Cancelled.' -ForegroundColor DarkGray }
    }
}

# ---------------------------------------------------------------------------
# [0] First 15 minutes: ONLY what belongs at the very start. Each step asks.
# ---------------------------------------------------------------------------
function Invoke-FirstSteps {
    $dir = '{0}\first15_{1}_{2}' -f $ReportDir, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm')
    $cp = @{}; if ($ConfigPath) { $cp.ConfigPath = $ConfigPath }
    $role = if (Test-CcdcIsDC) { 'Active Directory: GPOs, DNS zones, AD objects' } elseif (Test-Path "$env:windir\System32\inetsrv\appcmd.exe") { 'IIS: config + web roots' } else { 'no AD or IIS here: nothing to back up' }
    $steps = @(
        @{ T = 'Snapshot: record how the box is before anyone changes it';              Do = { & (Join-Path $here 'backup\Snapshot-State.ps1') -Mode Take -Label 'first15' -Quiet @cp } }
        @{ T = "Backup ($role)";                                                         Do = { & (Join-Path $here 'backup\Backup-Box.ps1') @cp } }
        @{ T = 'LIVE ALERTS on (opens the watch window; keep it open)';                  Do = { Install-LiveAlerts -Quiet } }
        @{ T = 'Ways in, every open port (odd ones flagged), SSH keys, who is on';       Do = { & (Join-Path $here 'alerts\whoshere.ps1') } }
        @{ T = 'Admin users and risky accounts';                                         Do = { & (Join-Path $here 'audit\Audit-Users.ps1') @cp -OutFile (Join-Path $dir 'users.txt') } }
        @{ T = 'PII: card numbers, SSNs, passwords in files and SQL Server';             Do = { & (Join-Path $here 'alerts\pii-hunt.ps1') } }
        @{ T = 'Vulnerability check: what Red Team can walk straight into';              Do = { & (Join-Path $here 'audit\Audit-Vulns.ps1') @cp -OutFile (Join-Path $dir 'vulns.txt') } }
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
    Write-Host '  Done. Now, in this order (each one asks before changing anything):' -ForegroundColor Green
    Write-Host '    [10] rotate admin passwords (scored accounts: Password Change Request first)' -ForegroundColor Gray
    Write-Host '    [X]  kick + disable any admin account step 5 flagged that is not your team' -ForegroundColor Gray
    Write-Host '    [12] hardening walkthrough: apply the SAFE steps' -ForegroundColor Gray
    Write-Host '    [11] basic firewall' -ForegroundColor Gray
    Write-Host '  Then: [3] persistence hunt, [E] find attacks. Broke something? W shows what changed, U puts it back.' -ForegroundColor Gray
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
if ((Test-CcdcIsAdmin) -and @(Get-CcdcSnapshotList).Count -eq 0) {
    # First time on this box: record how it looked before anyone touched it.
    Write-Host ''
    Write-Host '  First run on this box: saving the ORIGINAL snapshot (how it looks before we change anything)...' -ForegroundColor Cyan
    try { & (Join-Path $here 'backup\Snapshot-State.ps1') -Mode Take -Quiet | Out-Null } catch { Write-Host "  Snapshot failed: $_" -ForegroundColor Yellow }
}
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
        $k = (Read-Host '  Which option? (e.g. 13, D, C)').Trim().ToUpper()
        $m = $menu | Where-Object { $_.Key -eq $k }
        if ($m) { Get-Help (Join-Path $here $m.File) -Full | Out-Host -Paging }
    } elseif ($choice -eq 'A') {
        $dir = '{0}\{1}_{2}' -f $ReportDir, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        foreach ($m in $menu | Where-Object { $_.Key -in '1', '2', '3', '4', '5', '6' }) {
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
