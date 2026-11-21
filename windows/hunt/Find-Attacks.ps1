<#
.SYNOPSIS
    Find-Attacks - Red Team response: finds the attacks in the logs, says what each one is and exactly what to do. READ-ONLY.

.DESCRIPTION
    PURPOSE
      You do not need to know which attack happened. This reads the event logs
      (and web / FTP logs) and checks for the attacks Red Team commonly uses.
      For each one it finds, it prints:
        What it is   one or two plain sentences
        Evidence     who, from which IP, when, against what
        Do this now  numbered steps, with the panel key for each
      Nothing found for an attack = one green line.

    PART 1  LOGON ATTEMPTS ON EVERY SERVICE (default: last 2 hours)
      Windows logons (RDP, SMB / WinRM / WMI = "network", IIS basic / FTP = "cleartext"),
      Kerberos and NTLM on a DC, SSH (OpenSSH log), SQL Server (failed logins),
      IIS web logins (HTTP 401), IIS FTP logins (530). Per source IP: failures,
      successes, accounts tried, and a verdict: BRUTE FORCE, SPRAY, or
      LOGGED IN AFTER FAILING (the dangerous one).

    PART 2  ATTACK CHECKS (default: last 24 hours)
      Kerberoasting, AS-REP roasting, DCSync, pass-the-hash (logon type 9),
      someone added to an admin group, new service (PsExec-style), new scheduled task,
      web shell / xp_cmdshell, credential dumping (LSASS, ntds.dit), log cleared,
      Defender tampering, Zerologon.

    WHAT IT NEEDS
      The audit policy on (panel 12 step "audit events", or LIVE ALERTS install).
      Web shell / dumping checks need "command line in process events" (panel 12).

    WHAT IT READS    Security, System, Application, Directory Service, Defender, OpenSSH, RDP logs;
                     IIS W3SVC / FTPSVC log files
    WHAT IT CHANGES  nothing
    HOW TO UNDO      nothing to undo

    MANUAL EQUIVALENT
      Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-2)}
      Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} | ? { $_.Properties[5].Value -eq '0x17' }

.PARAMETER LogonMinutes
    Window for part 1. Default 120.

.PARAMETER Hours
    Window for part 2. Default 24.

.EXAMPLE
    .\Find-Attacks.ps1
.EXAMPLE
    .\Find-Attacks.ps1 -LogonMinutes 30 -Hours 4
#>
[CmdletBinding()]
param(
    [int]$LogonMinutes = 120,
    [int]$Hours = 24,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Find-Attacks' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath
$isDC = Test-CcdcIsDC
$t1 = (Get-Date).AddMinutes(-$LogonMinutes)
$t2 = (Get-Date).AddHours(-$Hours)
$mine = @(Get-CcdcLocalIps)

function Get-Ev([string]$log, [int[]]$ids, [datetime]$since, [int]$max = 5000) {
    $r = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = $since } -MaxEvents $max -ErrorAction SilentlyContinue)
    foreach ($e in $r) { $d = Get-CcdcEventData -Record $e; $d['_Time'] = $e.TimeCreated; $d['_Id'] = $e.Id; $d['_Msg'] = $null; $d['_Rec'] = $e; [pscustomobject]$d }
}
function Show-Attack([string]$name, [string]$what, [string[]]$evidence, [string[]]$todo) {
    Write-Finding -Level RED -Category $name -Message ("{0}" -f $name.ToUpper())
    Write-Host "       What it is: $what" -ForegroundColor Gray
    Write-Host '       Evidence:' -ForegroundColor Gray
    foreach ($e in ($evidence | Select-Object -First 12)) { Write-Host "         $e" -ForegroundColor Yellow }
    if (@($evidence).Count -gt 12) { Write-Host "         ... and $(@($evidence).Count - 12) more" -ForegroundColor Yellow }
    Write-Host '       Do this now:' -ForegroundColor Gray
    $n = 0; foreach ($t in $todo) { $n++; Write-Host "         $n. $t" -ForegroundColor White }
    Write-CcdcLog ("ATTACK {0}: {1}" -f $name, ($evidence -join ' | '))
}
function Show-Clear([string]$name, [string]$note = '') { Write-Finding -Level GREEN -Category $name -Message ("No signs of {0}{1}" -f $name, $(if ($note) { " ($note)" } else { '' })) }
function Test-Outside([string]$ip) { $c = ConvertTo-CcdcIp $ip; return ($c -and $mine -notcontains $c) }

# ===========================================================================
Write-Section "PART 1: logon attempts on every service (last $LogonMinutes min)"
# ===========================================================================
$att = @{}   # key "ip|service" -> stats
function Add-Att([string]$ip, [string]$svc, [string]$user, [bool]$ok, [datetime]$t) {
    $ip = ConvertTo-CcdcIp $ip; if (-not $ip) { $ip = '(local)' }
    if ($mine -contains $ip) { return }
    if ($user -match '\$$') { return }   # computer accounts
    $k = "$ip|$svc"
    if (-not $att.ContainsKey($k)) { $att[$k] = @{ Ip = $ip; Svc = $svc; Fail = 0; Ok = 0; Users = @{}; Last = $t; FirstOkAfterFail = $null } }
    $a = $att[$k]
    if ($ok) { $a.Ok++; if ($a.Fail -gt 0 -and -not $a.FirstOkAfterFail) { $a.FirstOkAfterFail = "$user at $($t.ToString('HH:mm'))" } } else { $a.Fail++ }
    if ($user) { $a.Users[$user] = 1 }
    if ($t -gt $a.Last) { $a.Last = $t }
}
$typeName = @{ '2' = 'console'; '3' = 'network (SMB/WinRM/WMI)'; '8' = 'cleartext (IIS/FTP)'; '10' = 'RDP'; '7' = 'unlock'; '11' = 'cached' }
foreach ($e in (Get-Ev 'Security' @(4625, 4624) $t1 20000 | Sort-Object _Time)) {
    $lt = [string]$e.LogonType
    if ($lt -notin '2', '3', '8', '10') { continue }
    if ($e._Id -eq 4624 -and $lt -eq '3' -and -not (Test-Outside $e.IpAddress)) { continue }
    Add-Att $e.IpAddress $typeName[$lt] $e.TargetUserName ($e._Id -eq 4624) $e._Time
}
if ($isDC) {
    foreach ($e in (Get-Ev 'Security' @(4771) $t1)) { Add-Att $e.IpAddress 'Kerberos' $e.TargetUserName $false $e._Time }
    foreach ($e in (Get-Ev 'Security' @(4768) $t1 | Where-Object { $_.Status -eq '0x6' })) { Add-Att $e.IpAddress 'Kerberos (unknown user)' $e.TargetUserName $false $e._Time }
    foreach ($e in (Get-Ev 'Security' @(4776) $t1 | Where-Object { $_.Status -and $_.Status -ne '0x0' })) { Add-Att $e.Workstation 'NTLM' $e.TargetUserName $false $e._Time }
}
foreach ($e in @(Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $t1 })) {
    if ($e.Message -match '(Accepted|Failed) \S+ for (invalid user )?(\S+) from (\S+)') { Add-Att $Matches[4] 'SSH' $Matches[3] ($Matches[1] -eq 'Accepted') $e.TimeCreated }
}
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 18456; StartTime = $t1 } -MaxEvents 2000 -ErrorAction SilentlyContinue)) {
    $u = if ($e.Message -match "user '([^']*)'") { $Matches[1] } else { '?' }
    $ip = if ($e.Message -match 'CLIENT: ([^\]]+)\]') { $Matches[1] } else { '' }
    Add-Att $ip 'SQL Server' $u $false $e.TimeCreated
}
# IIS web (401) and IIS FTP (530) logs: newest file per site, times are UTC.
$utcFrom = $t1.ToUniversalTime()
foreach ($kind in @(@{ Glob = 'W3SVC*'; Svc = 'web login (IIS 401)'; Code = '401' }, @{ Glob = 'FTPSVC*'; Svc = 'FTP'; Code = '530' })) {
    foreach ($dir in @(Get-ChildItem "$env:SystemDrive\inetpub\logs\LogFiles" -Directory -Filter $kind.Glob -ErrorAction SilentlyContinue)) {
        $f = Get-ChildItem $dir.FullName -Filter '*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if (-not $f -or $f.LastWriteTime -lt $t1) { continue }
        $fields = @()
        foreach ($line in (Get-Content $f.FullName -Tail 20000 -ErrorAction SilentlyContinue)) {
            if ($line -like '#Fields:*') { $fields = @($line.Substring(9).Trim() -split ' '); continue }
            if ($line.StartsWith('#') -or -not $fields) { continue }
            $v = $line -split ' '
            $row = @{}; for ($i = 0; $i -lt $fields.Count -and $i -lt $v.Count; $i++) { $row[$fields[$i]] = $v[$i] }
            if ($row['sc-status'] -ne $kind.Code -and -not ($kind.Code -eq '401' -and $row['sc-status'] -eq '200' -and $row['cs-username'] -and $row['cs-username'] -ne '-')) { continue }
            $t = $null; try { $t = [datetime]::ParseExact("$($row['date']) $($row['time'])", 'yyyy-MM-dd HH:mm:ss', $null) } catch { continue }
            if ($t -lt $utcFrom) { continue }
            Add-Att $row['c-ip'] $kind.Svc $row['cs-username'] ($row['sc-status'] -ne $kind.Code) $t.ToLocalTime()
        }
    }
}

$rows = @($att.Values | Sort-Object { $_.Fail } -Descending)
$bad = @($rows | Where-Object { $_.Fail -ge 5 -or $_.FirstOkAfterFail })
foreach ($a in $rows) {
    $nu = $a.Users.Count
    $verdict = if ($a.FirstOkAfterFail -and $a.Fail -ge 3) { "LOGGED IN AFTER FAILING ($($a.FirstOkAfterFail))" } elseif ($a.Fail -ge 5 -and $nu -ge 4) { 'PASSWORD SPRAY (many accounts)' } elseif ($a.Fail -ge 5) { 'BRUTE FORCE (one account, many tries)' } else { '' }
    $lvl = if ($verdict -like 'LOGGED IN*') { 'RED' } elseif ($verdict) { 'YELLOW' } elseif ($a.Ok -gt 0 -and $a.Fail -eq 0) { 'INFO' } else { 'INFO' }
    $users = (@($a.Users.Keys) | Select-Object -First 6) -join ', '; if ($nu -gt 6) { $users += " +$($nu - 6)" }
    Write-Finding -Level $lvl -Category 'Logons' -Message ("{0,-16} {1,-24} fail {2,4}  ok {3,3}  last {4}  {5}" -f $a.Ip, $a.Svc, $a.Fail, $a.Ok, $a.Last.ToString('HH:mm'), $verdict) -Detail $(if ($users) { "accounts: $users" } else { '' })
}
if (-not $rows) { Write-Finding -Level GREEN -Category 'Logons' -Message 'No logon attempts from other machines in this window.' }
if ($bad) {
    Show-Attack 'Password guessing' 'Someone is trying passwords against your services. A success after many failures means they probably got in.' `
        @($bad | ForEach-Object { "{0} on {1}: {2} failed, {3} ok{4}" -f $_.Ip, $_.Svc, $_.Fail, $_.Ok, $(if ($_.FirstOkAfterFail) { "  SUCCESS: $($_.FirstOkAfterFail)" } else { '' }) }) `
        @('Block the IP: panel X -> 2 (not the scoring engine: check that it is not the IP your services are checked from).',
          'Any account that LOGGED IN AFTER FAILING: change its password now (panel 10; scored account = Password Change Request), then kick it: panel X -> 1.',
          'Check what that account did after logging in: panel D -> 5 (story of the IP), panel W (what changed).',
          'Weak passwords everywhere? Rotate the rest (panel 10).')
}

# ===========================================================================
Write-Section "PART 2: attack checks (last $Hours h)"
# ===========================================================================
$admSids = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551')

if ($isDC) {
    # Kerberoasting: RC4 service tickets for USER accounts (services run by people-type accounts).
    $tgs = @(Get-Ev 'Security' @(4769) $t2 20000 | Where-Object { $_.TicketEncryptionType -eq '0x17' -and $_.ServiceName -notmatch '\$$' -and $_.ServiceName -ne 'krbtgt' -and $_.Status -eq '0x0' })
    if ($tgs) {
        Show-Attack 'Kerberoasting' 'They asked the DC for service tickets they can crack OFFLINE to learn the password of service accounts (often admins). No failed logons happen.' `
            @($tgs | Group-Object { "$(ConvertTo-CcdcIp $_.IpAddress) as $($_.TargetUserName)" } | ForEach-Object { "{0} requested tickets for: {1}  (last {2})" -f $_.Name, ((@($_.Group | ForEach-Object { $_.ServiceName } | Sort-Object -Unique)) -join ', '), ($_.Group | Sort-Object _Time | Select-Object -Last 1)._Time.ToString('HH:mm') }) `
            @('Change the password of every service account named above to a long random one (25+ chars): panel 10. If a service uses it, update the service too, or use a Password Change Request if it is scored.',
              'The account that REQUESTED the tickets is compromised: change its password and kick it (panel X -> 1).',
              'Block the source IP if it is not one of yours (panel X -> 2).',
              'Take service accounts out of admin groups where you can (panel 2 shows them).')
    } else { Show-Clear 'Kerberoasting' }

    # AS-REP roasting: TGTs issued without pre-authentication.
    $asrep = @(Get-Ev 'Security' @(4768) $t2 20000 | Where-Object { $_.PreAuthType -eq '0' -and $_.Status -eq '0x0' })
    if ($asrep) {
        Show-Attack 'AS-REP roasting' 'Accounts with "Kerberos pre-auth not required" hand out a crackable hash to ANYONE, no password needed.' `
            @($asrep | Group-Object TargetUserName | ForEach-Object { "{0} (from {1})" -f $_.Name, ((@($_.Group | ForEach-Object { ConvertTo-CcdcIp $_.IpAddress } | Sort-Object -Unique)) -join ', ') }) `
            @('Turn pre-auth back on for those accounts: panel 12, step "Fix risky account flags".',
              'Change their passwords (the hash may already be cracked): panel 10.',
              'Block the source IP (panel X -> 2).')
    } else { Show-Clear 'AS-REP roasting' }

    # DCSync: directory replication requested by something that is not a DC.
    $repl = @(Get-Ev 'Security' @(4662) $t2 20000 | Where-Object { $_.Properties -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' -and $_.SubjectUserName -notmatch '\$$' })
    if ($repl) {
        Show-Attack 'DCSync' 'Someone used replication rights to pull EVERY password hash from AD (mimikatz lsadump::dcsync). Assume all accounts are compromised.' `
            @($repl | Group-Object SubjectUserName | ForEach-Object { "{0} ({1} times, last {2}, logon from {3})" -f $_.Name, $_.Count, ($_.Group | Sort-Object _Time | Select-Object -Last 1)._Time.ToString('HH:mm'), (Get-CcdcLogonSource $_.Group[0].SubjectLogonId) }) `
            @('Kick and disable that account (panel X -> 1) and block its source IP (panel X -> 2).',
              'Reset krbtgt TWICE with the wait in between (panel 15): kills golden tickets made from the stolen hash.',
              'Rotate all admin and service account passwords (panel 10).',
              'Remove replication rights from anything that is not a DC: panel 6 lists "DCSync holders".',
              'File an incident report with the evidence above (panel I).')
    } else { Show-Clear 'DCSync' 'needs Directory Service Access auditing' }

    # Zerologon exploitation attempts (Netlogon).
    $zl = @(Get-Ev 'System' @(5827, 5828, 5829) $t2)
    if ($zl) {
        Show-Attack 'Zerologon' 'Someone tried the Netlogon bug that resets the DC''s own password and takes over the domain.' `
            @($zl | ForEach-Object { "{0} event {1}" -f $_._Time.ToString('HH:mm'), $_._Id }) `
            @('Make sure enforcement is on: panel 12 step "Zerologon" (and panel 5 shows patch status).', 'Treat the domain as compromised if the DC machine password changed: panel 15 (krbtgt), rotate admin passwords.')
    } else { Show-Clear 'Zerologon' }
}

# Pass-the-hash / runas /netonly (logon type 9 = new credentials).
$pth = @(Get-Ev 'Security' @(4624) $t2 20000 | Where-Object { [string]$_.LogonType -eq '9' -and $_.LogonProcessName -match 'seclogo' })
if ($pth) {
    Show-Attack 'Pass-the-hash' 'A process was started with someone else''s credentials (mimikatz sekurlsa::pth or runas /netonly). Often used to move to other boxes.' `
        @($pth | ForEach-Object { "{0}  {1} started as {2}\{3}" -f $_._Time.ToString('HH:mm'), $_.SubjectUserName, $_.TargetOutboundDomainName, $_.TargetOutboundUserName }) `
        @('If you or a teammate did not run "runas /netonly": the account that ran it is compromised. Kick it (panel X -> 1).', 'Change the password of the account it impersonated (panel 10).', 'Check the other boxes for logons by that account (panel N on each).')
} else { Show-Clear 'pass-the-hash (logon type 9)' }

# Someone added to an admin group.
$adds = @(Get-Ev 'Security' @(4728, 4732, 4756) $t2 | Where-Object { $admSids -contains $_.TargetSid -or $_.TargetSid -match '-(512|518|519|520)$' -or $_.TargetUserName -eq 'DnsAdmins' })
if ($adds) {
    Show-Attack 'New admin' 'An account was added to an admin-level group. Unless your team did it, this is Red Team giving themselves a way back in.' `
        @($adds | ForEach-Object { "{0}  {1} -> {2}  by {3} (from {4})" -f $_._Time.ToString('MM-dd HH:mm'), ($_.MemberName -replace '^CN=([^,]+),.*$', '$1'), $_.TargetUserName, $_.SubjectUserName, $(if (($s = Get-CcdcLogonSource $_.SubjectLogonId)) { $s } else { '?' }) }) `
        @('Remove the member from the group (Active Directory Users and Computers, or panel W -> 1 then U to put the group back).',
          'Kick and disable the added account if it is not yours (panel X -> 1).',
          'The account that ADDED it is compromised too: change its password (panel 10).')
} else { Show-Clear 'accounts added to admin groups' }

# New services (PsExec and friends install a service to run their command).
$svc = @(Get-Ev 'System' @(7045) $t2)
if ($svc) {
    Show-Attack 'New service' 'A service was installed. Remote-command tools (PsExec, Impacket, Cobalt Strike) do this to run as SYSTEM; malware does it to survive reboots.' `
        @($svc | ForEach-Object { "{0}  {1} -> {2}" -f $_._Time.ToString('MM-dd HH:mm'), $_.ServiceName, $_.ImagePath }) `
        @('Anything you do not recognise: panel R (removes it, keeps evidence).', 'Random names, cmd.exe / powershell in the path, or files in Temp / ProgramData = attacker.', 'Then find how they got admin: Part 1 above, panel D -> 5.')
} else { Show-Clear 'new services' }

# New scheduled tasks.
$tasks = @(Get-Ev 'Security' @(4698) $t2)
if ($tasks) {
    Show-Attack 'New scheduled task' 'A scheduled task was created: the most common way to get back in after being kicked.' `
        @($tasks | ForEach-Object { "{0}  {1}  by {2}" -f $_._Time.ToString('MM-dd HH:mm'), $_.TaskName, $_.SubjectUserName }) `
        @('Not yours? Remove it with panel R (evidence is kept).', 'Look at what it runs before deleting (panel R shows the command).')
} else { Show-Clear 'new scheduled tasks' }

# Process-based checks (need command-line auditing): web shell, xp_cmdshell, credential dumping.
$procEv = @(Get-Ev 'Security' @(4688) $t2 20000)
$web = @($procEv | Where-Object { $_.ParentProcessName -match '\\(w3wp|httpd|php-cgi|sqlservr|tomcat\d*|java)\.exe$' -and $_.NewProcessName -match '\\(cmd|powershell|pwsh|whoami|net1?|certutil|rundll32|bitsadmin)\.exe$' })
if ($web) {
    Show-Attack 'Web shell / xp_cmdshell' 'Your web server or SQL Server started a command shell. That means someone is running commands through a web page or the database.' `
        @($web | ForEach-Object { "{0}  {1} -> {2}  {3}" -f $_._Time.ToString('MM-dd HH:mm'), (Split-Path $_.ParentProcessName -Leaf), (Split-Path $_.NewProcessName -Leaf), $_.CommandLine }) `
        @('Web server: find the shell file (panel 3 "web shells", or newest .aspx/.php/.jsp in the web root) and remove it with panel R.',
          'SQL Server: turn off xp_cmdshell and check sysadmin logins (panel 14).',
          'Block the attacker IP from the web logs / Part 1 (panel X -> 2).')
} else { Show-Clear 'web shells / xp_cmdshell' $(if (-not $procEv) { 'process auditing off: turn on in panel 12' } else { '' }) }
$dump = @($procEv | Where-Object { $_.CommandLine -match '(?i)lsass|comsvcs.*minidump|procdump|sekurlsa|mimikatz|ntdsutil|vssadmin\s+create\s+shadow|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|ifm' })
if ($dump) {
    Show-Attack 'Credential dumping' 'Someone tried to copy passwords out of memory (LSASS) or out of the AD / SAM database files.' `
        @($dump | ForEach-Object { "{0}  {1}: {2}" -f $_._Time.ToString('MM-dd HH:mm'), $_.SubjectUserName, $_.CommandLine }) `
        @('Assume every account that was logged on to this box is compromised: rotate those passwords (panel 10).',
          'Turn on LSA protection (panel 12) and kick the account that ran it (panel X -> 1).',
          'On a DC (ntds.dit / ntdsutil): reset krbtgt twice (panel 15) and rotate ALL admin passwords.')
} else { Show-Clear 'credential dumping' $(if (-not $procEv) { 'process auditing off' } else { '' }) }

# Logs cleared.
$clr = @(Get-Ev 'Security' @(1102) $t2) + @(Get-Ev 'System' @(104) $t2)
if ($clr) {
    Show-Attack 'Log cleared' 'Someone wiped an event log to hide what they did. Assume they had admin.' `
        @($clr | ForEach-Object { "{0}  event {1} by {2}" -f $_._Time.ToString('MM-dd HH:mm'), $_._Id, $(if ($_.SubjectUserName) { $_.SubjectUserName } else { $_.Channel }) }) `
        @('Check what changed instead: panel W -> 1 (settings), W -> 3 (new users / tasks / services).', 'Rotate the admin account that cleared it (panel 10) and kick it (panel X -> 1).', 'LIVE ALERTS keeps its own copy in C:\bt\alerts.log: read it for what happened before the wipe.')
} else { Show-Clear 'log clearing' }

# Defender tampering.
$def = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5007; StartTime = $t2 } -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 5001 -or $_.Message -match 'Exclusions' })
if ($def) {
    Show-Attack 'Defender tampering' 'Real-time protection was turned off or an exclusion was added: attackers do this before dropping tools.' `
        @($def | ForEach-Object { "{0}  {1}" -f $_.TimeCreated.ToString('MM-dd HH:mm'), (($_.Message -split "`n" | Where-Object { $_ -match 'Exclusions|Real-time|New value' } | Select-Object -First 1) -replace '\s+', ' ') }) `
        @('Turn real-time back on and remove unknown exclusions: panel 12 step "Defender", or W -> 1 then U.', 'Scan the excluded folder: files there are probably attacker tools (panel R).')
} else { Show-Clear 'Defender tampering' }

Write-Host ''
Write-Host '  Not sure what to do with a finding? Each one lists its steps. For an incident report: panel I.' -ForegroundColor DarkGray
Complete-Ccdc
