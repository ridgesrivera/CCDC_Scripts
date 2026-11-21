<#
.SYNOPSIS
    New-IncidentReport - gather the FACTS for an incident report (source IPs, timeline, what was removed). READ-ONLY.

.DESCRIPTION
    PURPOSE
      A useful incident report names the source address the attack came from
      and is filed quickly. Under pressure nobody has time to dig through event logs, so
      this script does the digging for a time window and writes a worksheet:

        1. Candidate SOURCE ADDRESSES, ranked, each with the reasons it is
           suspicious (RDP logon as an admin, 40 failed logons, created a user...).
        2. One merged TIMELINE: alerts from LIVE ALERTS / the toolkit alert file,
           logons from outside, account and group changes, new tasks and services,
           log clearing, and everything Remove-Persistence took out.
        3. What we REMOVED (with file hashes and creation times) and what we CHANGED.
        4. What is live right now: sessions and connections from those addresses.
        5. A fill-in template with the factual fields already filled.

      It collects facts only. The description of what happened, the impact
      and the prevention steps are yours to write, in your own words: the
      competition packet zeroes inject responses that read as AI-generated.

    REMEMBER
      * Customers, Orange Team and the scoring engine see the PUBLIC address
        (10.100.1XX.Y). Report your box by that address, not 192.168.x.x.
      * 'outside team ranges' is a hint, not proof: the scoring engine is
        outside too. An ADMIN logon, a new account or a web shell request from
        an outside address is the proof.

    WHAT IT READS    Security / System / RDP / OpenSSH event logs, C:\ccdc\alerts,
                     C:\ccdc\evidence, C:\ccdc\logs, IIS logs, current sessions and connections
    WHAT IT CHANGES  nothing. Writes one text file under C:\ccdc\reports\incidents\.
    HOW TO UNDO      delete the file.

    MANUAL EQUIVALENT
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-2)} |
        ? { $_.Properties[8].Value -eq 10 } | select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}
      Select-String -Path C:\inetpub\logs\LogFiles\W3SVC*\*.log -Pattern 'shell.php'
      quser ; Get-NetTCPConnection -State Established | sort RemoteAddress

.PARAMETER SinceMinutes
    How far back to look. Default 120.

.PARAMETER SourceIp
    Focus on these addresses (they are always listed, and their web requests are pulled from the IIS logs).

.PARAMETER User
    Also list every logon of these accounts in the window (e.g. the rogue account you found).

.PARAMETER Indicator
    Text to search the IIS logs for (a web shell file name, an odd URL). Shows who requested it.

.PARAMETER Title
    Short name for the incident, used in the file name and header.

.EXAMPLE
    .\New-IncidentReport.ps1 -Title 'rogue admin hacker' -User hacker
.EXAMPLE
    .\New-IncidentReport.ps1 -SinceMinutes 240 -Indicator 'x.php' -SourceIp 10.100.50.7
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 10080)][int]$SinceMinutes = 120,
    [string[]]$SourceIp = @(),
    [string[]]$User = @(),
    [string]$Indicator,
    [string]$Title = 'incident',
    [string[]]$TrustedRanges = @(),
    [string]$OutDir = 'C:\ccdc\reports\incidents',
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'New-IncidentReport' -ReadOnly
$config   = Get-CcdcConfig -Path $ConfigPath
$hostCfg  = Get-CcdcHostConfig -Config $config
$ranges   = Get-CcdcTrustedRanges -Config $config -Extra $TrustedRanges
$localIps = Get-CcdcLocalIps
$start    = (Get-Date).AddMinutes(-$SinceMinutes)
$startUtc = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')

$ipFacts  = @{}                                             # ip -> @{ First; Last; Score; Reasons }
$timeline = New-Object System.Collections.ArrayList

function Add-IpFact([string]$ip, $when, [string]$reason, [int]$weight = 1) {
    $ip = ConvertTo-CcdcIp $ip
    if (-not $ip) { return }
    $class = Get-CcdcIpClass -Ip $ip -Ranges $ranges -LocalIps $localIps
    if ($class -eq 'local') { return }
    if (-not $ipFacts.ContainsKey($ip)) { $ipFacts[$ip] = @{ First = $when; Last = $when; Score = 0; Class = $class; Reasons = @{} } }
    $f = $ipFacts[$ip]
    if ($when -and $when -lt $f.First) { $f.First = $when }
    if ($when -and $when -gt $f.Last)  { $f.Last = $when }
    $f.Score += $weight
    $f.Reasons[$reason] = 1 + [int]$f.Reasons[$reason]
}
function Add-Timeline($when, [string]$source, [string]$text, [string]$ip = '') {
    [void]$timeline.Add([pscustomobject]@{ Time = [datetime]$when; Source = $source; Text = ($text -replace '\s+', ' ').Trim(); Ip = (ConvertTo-CcdcIp $ip) })
}
function Get-Events([string]$log, [string]$xpath, [int]$max = 3000) {
    try { return @(Get-WinEvent -LogName $log -FilterXPath $xpath -MaxEvents $max -ErrorAction Stop) } catch { return @() }
}
$timeFilter = "TimeCreated[@SystemTime>='$startUtc']"

# ---------------------------------------------------------------------------
Write-Section "Collecting since $($start.ToString('HH:mm')) ($SinceMinutes min)"
# ---------------------------------------------------------------------------
# 1. Remote interactive logons (RDP) - always interesting.
foreach ($e in (Get-Events 'Security' "*[System[EventID=4624 and $timeFilter] and EventData[Data[@Name='LogonType']='10']]")) {
    $d = Get-CcdcEventData -Record $e
    $who = "{0}\{1}" -f $d['TargetDomainName'], $d['TargetUserName']
    Add-IpFact $d['IpAddress'] $e.TimeCreated "RDP logon as $who" 5
    Add-Timeline $e.TimeCreated 'Logon' "RDP logon as $who" $d['IpAddress']
}
# 2. Network logons from OUTSIDE the team ranges by real users (not machine accounts).
foreach ($e in (Get-Events 'Security' "*[System[EventID=4624 and $timeFilter] and EventData[Data[@Name='LogonType']='3']]" 5000)) {
    $d = Get-CcdcEventData -Record $e
    if ($d['TargetUserName'] -match '\$$|^ANONYMOUS LOGON$') { continue }
    $class = Get-CcdcIpClass -Ip $d['IpAddress'] -Ranges $ranges -LocalIps $localIps
    $named = $User -contains $d['TargetUserName']
    if ($class -ne 'outside' -and -not $named) { continue }
    $who = "{0}\{1}" -f $d['TargetDomainName'], $d['TargetUserName']
    $priv = ($d['ElevatedToken'] -eq '%%1842')          # the session got an admin token
    Add-IpFact $d['IpAddress'] $e.TimeCreated ("network logon as {0}{1}" -f $who, $(if ($priv) { ' (ADMIN token)' } else { '' })) $(if ($priv) { 4 } else { 1 })
    if ($priv -or $named) { Add-Timeline $e.TimeCreated 'Logon' ("network logon as {0} ({1}){2}" -f $who, $d['AuthenticationPackageName'], $(if ($priv) { ' ADMIN' } else { '' })) $d['IpAddress'] }
}
# 3. Failed logons, counted per address.
$fails = @{}
foreach ($e in (Get-Events 'Security' "*[System[(EventID=4625 or EventID=4771) and $timeFilter]]" 10000)) {
    $d = Get-CcdcEventData -Record $e
    $ip = ConvertTo-CcdcIp $d['IpAddress']
    if (-not $ip) { continue }
    if (-not $fails.ContainsKey($ip)) { $fails[$ip] = @{ Count = 0; Users = @{}; First = $e.TimeCreated; Last = $e.TimeCreated } }
    $fails[$ip].Count++; $fails[$ip].Users[[string]$d['TargetUserName']] = 1
    if ($e.TimeCreated -lt $fails[$ip].First) { $fails[$ip].First = $e.TimeCreated }
    if ($e.TimeCreated -gt $fails[$ip].Last)  { $fails[$ip].Last = $e.TimeCreated }
}
foreach ($ip in $fails.Keys) {
    $f = $fails[$ip]
    if ($f.Count -lt 5) { continue }
    Add-IpFact $ip $f.First ("{0} failed logons against {1} account(s)" -f $f.Count, $f.Users.Count) ([math]::Min(6, [int]($f.Count / 10) + 1))
    if ($ipFacts.ContainsKey($ip)) { $ipFacts[$ip].Last = $f.Last }
    Add-Timeline $f.First 'Logon' ("password guessing starts: {0} failures against {1} account(s) until {2}" -f $f.Count, $f.Users.Count, $f.Last.ToString('HH:mm:ss')) $ip
}
# 4. Account / group / task / service / log-clearing events, each tied back to the session's source address.
$idText = @{ 4720 = 'user CREATED'; 4722 = 'user enabled'; 4724 = 'password reset'; 4725 = 'user disabled'; 4726 = 'user DELETED'
             4728 = 'added to global group'; 4732 = 'added to local group'; 4756 = 'added to universal group'
             4698 = 'scheduled task CREATED'; 4697 = 'service INSTALLED'; 1102 = 'Security log CLEARED'; 4719 = 'audit policy changed' }
$idQuery = ($idText.Keys | ForEach-Object { "EventID=$_" }) -join ' or '
foreach ($e in (Get-Events 'Security' "*[System[($idQuery) and $timeFilter]]")) {
    $d = Get-CcdcEventData -Record $e
    $by = "{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']
    $src = Get-CcdcLogonSource -LogonId $d['SubjectLogonId']
    $obj = switch ([int]$e.Id) {
        { $_ -in 4728, 4732, 4756 } { $m = if ($d['MemberName'] -and $d['MemberName'] -ne '-') { ($d['MemberName'] -split ',')[0] -replace '^CN=' } else { $d['MemberSid'] }; "'$m' -> '$($d['TargetUserName'])'"; break }
        4698 { "'$($d['TaskName'])'"; break }
        4697 { "'$($d['ServiceName'])' = $($d['ServiceFileName'])"; break }
        default { if ($d['TargetUserName']) { "'$($d['TargetUserName'])'" } else { '' } }
    }
    $text = "{0}: {1} by {2}" -f $idText[[int]$e.Id], $obj, $by
    Add-Timeline $e.TimeCreated 'Change' $text $(if ($src -notmatch '^console') { $src } else { '' })
    if ($src -and $src -notmatch '^console') { Add-IpFact $src $e.TimeCreated $text 4 }
}
foreach ($e in (Get-Events 'System' "*[System[(EventID=7045 or EventID=104) and $timeFilter]]")) {
    $d = Get-CcdcEventData -Record $e
    if ($e.Id -eq 7045) { Add-Timeline $e.TimeCreated 'Change' ("service INSTALLED: '{0}' = {1} (as {2})" -f $d['ServiceName'], $d['ImagePath'], $d['AccountName']) }
    else { Add-Timeline $e.TimeCreated 'Change' ("event log '{0}' CLEARED by {1}" -f $d['Channel'], $d['SubjectUserName']) }
}
# 5. RDP connection log and OpenSSH (these keep the address even when Security auditing is off).
foreach ($e in (Get-Events 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' "*[System[EventID=1149 and $timeFilter]]")) {
    $d = Get-CcdcEventData -Record $e
    Add-IpFact $d['Param3'] $e.TimeCreated ("RDP connection as {0}\{1}" -f $d['Param2'], $d['Param1']) 3
}
foreach ($e in (Get-Events 'OpenSSH/Operational' "*[System[EventID=4 and $timeFilter]]")) {
    $d = Get-CcdcEventData -Record $e
    $p = [string]$d['payload']; if (-not $p) { $p = [string]$e.Message }
    if ($p -match 'Accepted (\S+) for (\S+) from (\S+)') {
        Add-IpFact $Matches[3] $e.TimeCreated ("SSH login as {0} ({1})" -f $Matches[2], $Matches[1]) $(if ($Matches[1] -eq 'publickey') { 5 } else { 2 })
        Add-Timeline $e.TimeCreated 'Logon' ("SSH login as {0} using {1}" -f $Matches[2], $Matches[1]) $Matches[3]
    }
}
# 6. Our own alert file (scheduled Watch-Changes and other toolkit alerts).
$alertFile = Join-Path $script:CcdcAlertRoot ("alerts_{0}.csv" -f $env:COMPUTERNAME)
$alerts = @()
if (Test-Path $alertFile) {
    $alerts = @(Import-Csv $alertFile | Where-Object { try { [datetime]$_.Time -ge $start } catch { $false } })
    foreach ($a in $alerts) {
        Add-Timeline ([datetime]$a.Time) "Alert/$($a.Source)" ("[{0}] {1}: {2}" -f $a.Level, $a.Rule, $a.Detail) $a.SourceIp
        if ($a.SourceIp -and $a.Level -eq 'RED') { Add-IpFact $a.SourceIp ([datetime]$a.Time) "alert $($a.Rule)" 3 }
    }
}
# 7. Evidence written by Remove-Persistence.
$evidenceFile = Join-Path $script:CcdcEvidenceRoot ("evidence_{0}.jsonl" -f $env:COMPUTERNAME)
$evidence = @()
if (Test-Path $evidenceFile) {
    foreach ($line in (Get-Content $evidenceFile)) {
        try { $o = $line | ConvertFrom-Json; if ([datetime]$o.RecordedAt -ge $start) { $evidence += $o } } catch { $null = $_ }
    }
    foreach ($o in $evidence) {
        Add-Timeline ([datetime]$o.RecordedAt) 'Removed' ("{0} '{1}' -> {2}" -f $o.Type, $o.Name, $o.ActionTaken) $(if ($o.SourceIp -notmatch '^console') { $o.SourceIp } else { '' })
        if ($o.CreatedAt -and $o.CreatedAt -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$') { Add-Timeline ([datetime]$o.CreatedAt) 'Planted' ("{0} '{1}' was created by {2}" -f $o.Type, $o.Name, $o.CreatedBy) $(if ($o.SourceIp -notmatch '^console') { $o.SourceIp } else { '' }) }
        if ($o.SourceIp -and $o.SourceIp -notmatch '^console') { Add-IpFact $o.SourceIp ([datetime]$o.RecordedAt) "created $($o.Type) '$($o.Name)'" 6 }
        foreach ($wr in @($o.WebRequests)) { if ($wr -match '^(\S+) x(\d+)') { Add-IpFact $Matches[1] ([datetime]$o.RecordedAt) "requested web shell $(Split-Path ([string]$o.Name) -Leaf) x$($Matches[2])" 5 } }
    }
}
# 8. Toolkit change log: every state change our scripts made in the window.
$changes = @()
foreach ($log in (Get-ChildItem $script:CcdcLogRoot -Filter *.log -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $start })) {
    foreach ($m in (Select-String -LiteralPath $log.FullName -Pattern '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[CHANGE\] (.*)$' -ErrorAction SilentlyContinue)) {
        $when = [datetime]$m.Matches[0].Groups[1].Value
        if ($when -ge $start) { $changes += [pscustomobject]@{ Time = $when; Script = ($log.BaseName -replace '_.*$', ''); Text = $m.Matches[0].Groups[2].Value } }
    }
}
# 9. IIS logs: who requested the indicator, and what did the focus addresses request?
$webHits = @()
$needles = @(); if ($Indicator) { $needles += $Indicator }; $needles += $SourceIp
if ($needles.Count -gt 0) {
    $logs = Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $start.AddHours(-1) }
    foreach ($log in $logs) {
        $fieldsLine = Select-String -LiteralPath $log.FullName -Pattern '^#Fields:' -ErrorAction SilentlyContinue | Select-Object -Last 1
        if (-not $fieldsLine) { continue }
        $fields = @(($fieldsLine.Line -replace '^#Fields:\s*', '') -split '\s+')
        $ix = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $ix[$fields[$i]] = $i }
        if (-not $ix.ContainsKey('c-ip')) { continue }
        foreach ($m in (Select-String -LiteralPath $log.FullName -SimpleMatch -Pattern $needles -ErrorAction SilentlyContinue | Select-Object -First 400)) {
            $c = @($m.Line -split '\s+')
            if ($c.Count -lt $fields.Count -or $m.Line -like '#*') { continue }
            $hit = [pscustomobject]@{
                TimeUtc = "$($c[$ix['date']]) $($c[$ix['time']])"; Ip = $c[$ix['c-ip']]; Method = $c[$ix['cs-method']]
                Uri = $c[$ix['cs-uri-stem']]; Status = $c[$ix['sc-status']]
            }
            $webHits += $hit
            if ($Indicator -and $m.Line -like "*$Indicator*") { Add-IpFact $hit.Ip $start ("requested '{0}' ({1})" -f $Indicator, $hit.Method) 2 }
        }
    }
}
foreach ($ip in $SourceIp) { Add-IpFact $ip $start 'named by you (-SourceIp)' 0 }

# ---------------------------------------------------------------------------
# Live state
# ---------------------------------------------------------------------------
$suspectIps = @($ipFacts.Keys)
$liveConns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $suspectIps -contains $_.RemoteAddress } | ForEach-Object {
    $pn = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { "pid$($_.OwningProcess)" }
    "{0}:{1} -> local port {2} ({3})" -f $_.RemoteAddress, $_.RemotePort, $_.LocalPort, $pn
})
$sessions = @(& quser.exe 2>$null)

# ---------------------------------------------------------------------------
# Write the worksheet
# ---------------------------------------------------------------------------
$ranked = @($ipFacts.GetEnumerator() | Sort-Object @{ Expression = { if ($_.Value.Class -eq 'outside') { 0 } else { 1 } } }, @{ Expression = { $_.Value.Score }; Descending = $true })
$sb = New-Object System.Text.StringBuilder
function Out-Line([string]$s = '') { [void]$sb.AppendLine($s) }

$myIps = @($localIps | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -ne '127.0.0.1' })
Out-Line ('=' * 78)
Out-Line (" INCIDENT WORKSHEET: {0}" -f $Title)
Out-Line ('=' * 78)
Out-Line (" Box        : {0}   internal IP {1}{2}" -f $env:COMPUTERNAME, ($myIps -join ', '), $(if ($hostCfg -and $hostCfg.role) { "   ($($hostCfg.role))" } else { '' }))
Out-Line ' Public IP  : 10.100.1XX.Y  <- report THIS address (same last octet as the internal one, XX = team number)'
Out-Line (" Window     : {0}  to  {1}   (local time; IIS log times are UTC)" -f $start.ToString('yyyy-MM-dd HH:mm'), (Get-Date).ToString('HH:mm'))
Out-Line (" Team ranges: {0}" -f $(if ($ranges) { $ranges -join ', ' } else { 'NOT CONFIGURED - every address shows as unknown' }))
Out-Line ' Submit at  : the incident portal named in the team packet, as soon as possible after detection.'
Out-Line ' Wording    : this file is facts only. Write the description, impact and prevention yourselves.'
Out-Line
Out-Line '--- 1. CANDIDATE SOURCE ADDRESSES (most suspicious first) ---------------------'
if ($ranked.Count -eq 0) { Out-Line '  none found in the logs for this window. Widen it (-SinceMinutes) or check that auditing is on (logging\Setup-Logging.ps1).' }
foreach ($r in $ranked) {
    $v = $r.Value
    Out-Line ("  {0,-16} {1,-8} first {2}  last {3}" -f $r.Key, $v.Class.ToUpper(), ([datetime]$v.First).ToString('HH:mm:ss'), ([datetime]$v.Last).ToString('HH:mm:ss'))
    foreach ($reason in ($v.Reasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)) {
        Out-Line ("      - {0}{1}" -f $reason.Key, $(if ($reason.Value -gt 1) { "  (x$($reason.Value))" } else { '' }))
    }
}
Out-Line
Out-Line '--- 2. TIMELINE ---------------------------------------------------------------'
foreach ($t in ($timeline | Sort-Object Time)) {
    $text = if ($t.Text.Length -gt 230) { $t.Text.Substring(0, 230) + '...' } else { $t.Text }
    Out-Line ("  {0}  {1,-22} {2}{3}" -f $t.Time.ToString('HH:mm:ss'), $t.Source, $text, $(if ($t.Ip) { "  [from $($t.Ip)]" } else { '' }))
}
if ($timeline.Count -eq 0) { Out-Line '  (nothing recorded)' }
Out-Line
Out-Line '--- 3. WHAT WE REMOVED (evidence kept in C:\ccdc\quarantine) -------------------'
foreach ($o in $evidence) {
    Out-Line ("  {0}  {1}: {2}" -f $o.RecordedAt, $o.Type, $o.Name)
    if ($o.Detail)        { Out-Line ("      what      : {0}" -f $o.Detail) }
    if ($o.CreatedAt)     { Out-Line ("      created   : {0} by {1}{2}" -f $o.CreatedAt, $o.CreatedBy, $(if ($o.SourceIp) { " from $($o.SourceIp)" } else { '' })) }
    if ($o.PayloadPath)   { Out-Line ("      file      : {0}  created {1}  modified {2}  owner {3}" -f $o.PayloadPath, $o.PayloadCreated, $o.PayloadModified, $o.PayloadOwner) }
    if ($o.PayloadSha256) { Out-Line ("      sha256    : {0}" -f $o.PayloadSha256) }
    if ($o.WebRequests)   { Out-Line ("      requested by: {0}" -f (@($o.WebRequests) -join '; ')) }
    Out-Line ("      action    : {0}" -f $o.ActionTaken)
}
if ($evidence.Count -eq 0) { Out-Line '  nothing removed with hunt\Remove-Persistence.ps1 in this window.' }
Out-Line
Out-Line '--- 4. WHAT WE CHANGED (toolkit change log) -----------------------------------'
foreach ($c in ($changes | Sort-Object Time)) { Out-Line ("  {0}  {1,-20} {2}" -f $c.Time.ToString('HH:mm:ss'), $c.Script, ($c.Text -replace ' \| UNDO:.*$', '')) }
if ($changes.Count -eq 0) { Out-Line '  (no toolkit changes logged in this window)' }
Out-Line
Out-Line '--- 5. LIVE RIGHT NOW ---------------------------------------------------------'
Out-Line '  Connections from the candidate addresses:'
if ($liveConns.Count -gt 0) { foreach ($l in $liveConns) { Out-Line "    $l" } } else { Out-Line '    none' }
Out-Line '  Logged-on sessions (quser):'
foreach ($s in $sessions) { Out-Line "    $s" }
if ($webHits.Count -gt 0) {
    Out-Line
    Out-Line '--- 6. WEB REQUESTS (IIS logs, times in UTC) ----------------------------------'
    foreach ($g in ($webHits | Group-Object Ip | Sort-Object Count -Descending | Select-Object -First 10)) {
        Out-Line ("  {0}  {1} request(s)" -f $g.Name, $g.Count)
        foreach ($h in ($g.Group | Select-Object -First 12)) { Out-Line ("      {0}  {1,-5} {2}  -> {3}" -f $h.TimeUtc, $h.Method, $h.Uri, $h.Status) }
    }
}
Out-Line
Out-Line '--- FILL IN AND SUBMIT --------------------------------------------------------'
$top = if ($ranked.Count -gt 0) { $ranked[0].Key } else { '<address>' }
$firstRed = $alerts | Where-Object { $_.Level -eq 'RED' } | Select-Object -First 1
Out-Line (" Time detected : {0}" -f $(if ($firstRed) { $firstRed.Time } else { '<HH:MM>' }))
Out-Line (" System        : {0} (10.100.1XX.<last octet>), {1}" -f $env:COMPUTERNAME, $(if ($hostCfg) { $hostCfg.role } else { '<role>' }))
Out-Line (" Source address: {0}   <- confirm against section 1" -f $top)
Out-Line (" How detected  : {0}" -f $(if ($firstRed) { "$($firstRed.Source) rule $($firstRed.Rule)" } else { '<script / log / who noticed>' }))
Out-Line ' What happened : <your words: what the attacker did, in order, using the timeline>'
Out-Line ' Actions taken : <your words: section 3 and 4, with times>'
Out-Line ' Impact        : <which scored services / data were affected, or "none">'
Out-Line ' Prevention    : <what you changed so it cannot happen again>'
Out-Line ' Evidence      : quarantine folder, SHA256 above, screenshots of the alert and of the removal'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$safeTitle = ($Title -replace '[^\w-]+', '_')
$outPath = Join-Path $OutDir ("incident_{0}_{1}_{2}.txt" -f $env:COMPUTERNAME, $script:CcdcStamp, $safeTitle)
$sb.ToString() | Out-File -FilePath $outPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
Write-Section 'Candidate source addresses'
if ($ranked.Count -eq 0) { Write-Finding -Level YELLOW -Category 'Source' -Message 'No candidate addresses found in this window.' -Detail 'Widen with -SinceMinutes, name one with -SourceIp, or check auditing: logging\Setup-Logging.ps1' }
foreach ($r in ($ranked | Select-Object -First 8)) {
    $v = $r.Value
    $lvl = if ($v.Class -eq 'outside' -and $v.Score -ge 4) { 'RED' } elseif ($v.Score -ge 4) { 'YELLOW' } else { 'INFO' }
    Write-Finding -Level $lvl -Category 'Source' -Message ("{0}  ({1}, {2} - {3})" -f $r.Key, $v.Class, ([datetime]$v.First).ToString('HH:mm'), ([datetime]$v.Last).ToString('HH:mm')) `
        -Detail (($v.Reasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Key)$(if ($_.Value -gt 1) { " x$($_.Value)" })" }) -join "`n")
}
Write-Finding -Level INFO -Category 'Report' -Message ("Timeline entries: {0}   removed items: {1}   toolkit changes: {2}" -f $timeline.Count, $evidence.Count, $changes.Count)
Write-Finding -Level GREEN -Category 'Report' -Message "Worksheet: $outPath" -Detail 'Open it, write the description in your own words, submit to the incident portal with the PUBLIC address of this box.'
Complete-Ccdc
