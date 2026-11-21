<#
.SYNOPSIS
    bt-alerts v6 - instant alerts with WHO, FROM WHERE, HOW, WHAT TO DO, and the ATTACK CHAIN.

.DESCRIPTION
    PURPOSE
      Pops up the moment someone logs in over RDP or the network from an untrusted IP,
      sprays passwords, Kerberoasts (DC), creates/enables/resets a user, adds someone to
      a group, installs a service, creates a task, clears the Security log, touches
      Defender, or tampers with the alerting itself. Each alert traces the action back
      to the original logon (source IP, PC name, logon type, NTLM/Kerberos), links it to
      what the same IP already did in the last hour (CHAIN + LIKELY pattern), and prints
      copy-paste response commands that fit the box's role (DC / member / standalone).
      Generic: no hard-coded IPs, names or domains. Any Windows language (audit GUIDs,
      well-known SIDs). Windows Server 2012 R2+ / Windows 8.1+ (PowerShell 4+).

    HOW IT WORKS
      Task Scheduler "On an event" triggers: one task per detection runs this script as
      SYSTEM with -Key <name> within ~1 s of the event. The script reads the event, follows
      SubjectLogonId -> the 4624 logon (IP/PC/type/auth), writes C:\bt\alerts.log (one line)
      and C:\bt\alerts-full.log (full block), and shows a msg.exe popup. The -Watch window
      tails alerts-full.log and runs a 30 s heartbeat (tasks present/enabled/pointing here,
      script hash, EventLog + Schedule services, audit policy every 5 min).

    WHAT IT READS    Security, System and Defender event logs; scheduled tasks; audit policy
    WHAT IT CHANGES  (-Install) audit subcategories ON (7, by GUID); Security log max 512 MB
                     if smaller; registers BT-Alert-* tasks (SYSTEM); locks C:\bt to
                     Administrators + SYSTEM; writes C:\bt\trusted.txt with your RDP IP.
                     (-Block) adds 'BT block <ip>' firewall rules. Nothing else, ever: no
                     passwords, no scored services, no automatic blocking.
    HOW TO UNDO      .\bt-alerts.ps1 -Remove                      (tasks)
                     Get-NetFirewallRule -DisplayName 'BT block*' | Remove-NetFirewallRule
                     icacls C:\bt /reset /T                       (folder permissions)
                     audit policy: harmless to leave on

    COMMANDS (Admin PowerShell, from C:\bt)
      .\bt-alerts.ps1 -Install            alerts on + 24 h backfill + opens the watch window (-NoBackfill: skip the report)
      .\bt-alerts.ps1 -Watch              reopen the watch window (one per box)
      .\bt-alerts.ps1 -Trust 10.1.2.3     stop network-logon alerts from an IP (scorer / teammate)
      .\bt-alerts.ps1 -Block 10.66.6.6    firewall an attacker IP (in + out; refuses trusted IPs)
      .\bt-alerts.ps1 -Chain 10.66.6.6    full story of one IP: first seen, logons, kerberoast, alerts
      .\bt-alerts.ps1 -Snooze 10          no popups for 10 min (still logged) during inject work
      .\bt-alerts.ps1 -Backfill -Hours 48 re-run the "what already happened" report
      .\bt-alerts.ps1 -Test | -Remove

    MANUAL EQUIVALENT
      Event Viewer > Security, filter 4624/4720/4728/4732/4697/4698/1102; find the action's
      Logon ID, then search 4624 for TargetLogonId = that ID to get the source IP.
      Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 5 | fl

    FILES (C:\bt)  alerts.log  alerts-full.log  alert-state.json  trusted.txt  watch.pid
    See dev/docs/live-alerts.md in the repo for the full design, limits and test results.

.EXAMPLE
    .\bt-alerts.ps1 -Install
.EXAMPLE
    .\bt-alerts.ps1 -Chain 10.66.6.6 -Hours 6
#>
param([switch]$Install, [switch]$Remove, [switch]$Test, [switch]$Watch, [switch]$Backfill, [switch]$NoBackfill,
      [string]$Block, [string]$Trust, [string]$Chain, [int]$Snooze = 0, [int]$Hours = 24,
      [string]$Key = '', [string]$Log = 'Security')

$Webhook = ''      # optional Discord webhook URL for phone pings (check the rules first)

$Dir = 'C:\bt'; $Self = "$Dir\bt-alerts.ps1"; $Short = "$Dir\alerts.log"; $Full = "$Dir\alerts-full.log"
$State = "$Dir\alert-state.json"; $TrustFile = "$Dir\trusted.txt"; $Flag = "$Dir\installing.flag"
New-Item $Dir -ItemType Directory -Force | Out-Null

# ---------------- helpers ----------------
function EvData($e) {
  $x = [xml]$e.ToXml(); $h = @{}
  foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $h[$n.Name] = [string]$n.'#text' } }
  if ($x.Event.UserData) { foreach ($c in $x.Event.UserData.FirstChild.ChildNodes) { $h[$c.LocalName] = [string]$c.InnerText } }
  $h
}
function CleanIP([string]$ip) { if (-not $ip) { return '-' }; $ip -replace '^::ffff:', '' }
function Get-MyIPs { @(Get-NetIPAddress -EA 0 | ForEach-Object { $_.IPAddress -replace '%.*$', '' }) + @('-', '::1', '127.0.0.1') }
function Get-Trusted { $t = @(Get-MyIPs); if (Test-Path $TrustFile) { $t += Get-Content $TrustFile | Where-Object { $_.Trim() } }; $t | Select-Object -Unique }
function Get-State { $s = @{}; if (Test-Path $State) { try { (Get-Content $State -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $s[$_.Name] = $_.Value } } catch {} }; $s }
function Save-State($s) { ($s | ConvertTo-Json) | Set-Content $State }
function Throttle([string]$k, [int]$minutes) {
  $s = Get-State; $now = Get-Date
  if ($s[$k] -and ($now - [datetime]$s[$k]).TotalMinutes -lt $minutes) { return $true }
  $s[$k] = $now.ToString('o'); Save-State $s; return $false
}
# audit subcategories we depend on (all GUIDs end in -69AE-11D9-BED3-505054503030; GUIDs work in any Windows language)
$AuditMap = @{ '0CCE9215' = 'Logon'; '0CCE9235' = 'User Account Management'; '0CCE9237' = 'Security Group Management'
               '0CCE9227' = 'Other Object Access (tasks)'; '0CCE9211' = 'Security System Extension (services)'
               '0CCE9240' = 'Kerberos Service Ticket Ops'; '0CCE922F' = 'Audit Policy Change' }
function Installing { (Test-Path $Flag) -and ((Get-Date) - (Get-Item $Flag).LastWriteTime).TotalSeconds -lt 90 }

# ----- role-aware response commands (DC / member server / standalone) -----
$Role = (Get-CimInstance Win32_ComputerSystem).DomainRole      # 0 standalone wks, 1 member wks, 2 standalone srv, 3 member srv, 4/5 DC
function CmdDisable([string]$user, [string]$dom) {
  if ($dom -and $dom -eq $env:COMPUTERNAME) { return "net user '$user' /active:no      # local account" }
  if ($Role -ge 4) { return "Disable-ADAccount -Identity '$user'" }
  return "net user '$user' /domain /active:no      # domain account: or run Disable-ADAccount on the DC"
}
function CmdResetPw([string]$user, [string]$dom) {
  if ($dom -and $dom -eq $env:COMPUTERNAME) { return "net user '$user' *      # prompts for a new password" }
  if ($Role -ge 4) { return "Set-ADAccountPassword -Identity '$user' -Reset -NewPassword (Read-Host -AsSecureString)" }
  return "net user '$user' * /domain      # or reset it on the DC"
}
function CmdRemoveMember([string]$group, [string]$member, [int]$eventId) {
  if ($Role -ge 4) { return "Remove-ADGroupMember -Identity '$group' -Members '$member' -Confirm:`$false" }
  if ($eventId -eq 4732) { return "net localgroup '$group' '$member' /delete" }
  return "# domain group: on the DC run  Remove-ADGroupMember '$group' -Members '$member'"
}

function JustCreated($evt, [string]$name) {
  Start-Sleep -Seconds 1
  $c = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4720] and EventData[Data[@Name='TargetUserName']='$name']]" -MaxEvents 1 -EA 0
  $c -and [math]::Abs(($evt.TimeCreated - $c.TimeCreated).TotalSeconds) -lt 5
}

function Get-How([string]$type, [string]$auth) {
  switch ($type) {
    '2'  { 'at the keyboard/console' }
    '3'  { if ($auth -match 'NTLM') { 'network logon with NTLM = password OR stolen hash (pass-the-hash). Typical of SMB/PsExec/WinRM/secretsdump tools' } else { 'network logon with Kerberos = valid password or a stolen/forged ticket' } }
    '4'  { 'a scheduled task (persistence already running)' }
    '5'  { 'a service (persistence already running)' }
    '8'  { 'cleartext network logon (IIS basic auth / LDAP simple bind)' }
    '9'  { 'runas /netonly (explicit stolen credentials used from this box)' }
    '10' { 'RDP with a valid password' }
    default { "logon type $type" }
  }
}

function Get-Origin([string]$lid) {
  $o = [ordered]@{ IP = '-'; Host = '-'; Type = '-'; Auth = '-'; Proc = '-'; How = 'unknown'; Line = 'origin unknown' }
  if (-not $lid) { return $o }
  if ($lid -eq '0x3e7') { $o.How = 'code running as SYSTEM on THIS box: a service, task, webshell on a LocalSystem app pool, or an exploit'; $o.Line = 'SYSTEM on this box'; return $o }
  $e = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='TargetLogonId']='$lid']]" -MaxEvents 1 -EA 0
  if (-not $e) { $o.Line = "logon $lid not in log (rolled over or cleared)"; return $o }
  $d = EvData $e
  $o.IP = CleanIP $d.IpAddress; $o.Host = $d.WorkstationName; $o.Type = $d.LogonType; $o.Auth = $d.AuthenticationPackageName
  $o.Proc = if ($d.ProcessName -and $d.ProcessName -ne '-') { [IO.Path]::GetFileName($d.ProcessName) } else { '-' }
  $o.How = Get-How $d.LogonType $d.AuthenticationPackageName
  $o.Line = "from $($o.IP) (PC: $($o.Host)) type $($o.Type) $($o.Auth)"
  $o
}

# ----- attack chain: what else did this same IP do in the last hour? -----
function ChainLine([string]$l) { $x = $l -replace '^(\S+)\s+\S+\s+', '$1  '; if ($x.Length -gt 110) { $x = $x.Substring(0, 107) + '...' }; $x }
function Get-Chain([string]$title, $origin, [string]$who) {
  $out = @()
  try {
    if (-not $origin -or $origin.IP -eq '-' -or -not (Test-Path $Short)) { return $out }
    $now = Get-Date; $ipRx = '\| from ' + [regex]::Escape($origin.IP) + '(\s|$)'
    $recent = @(Get-Content $Short -Tail 400 -EA 0)
    $prev = @()
    foreach ($l in $recent) {
      if ($l -notmatch $ipRx) { continue }
      try { $age = ($now - [datetime]::ParseExact($l.Substring(0, 8), 'HH:mm:ss', $null)).TotalMinutes } catch { continue }
      if ($age -lt 0) { $age += 1440 }
      if ($age -le 60) { $prev += $l }
    }
    $u = ($who -split '\\')[-1]
    $roasted = @()
    if ($title -match 'LOGON' -and $u) { $roasted = @($recent | Where-Object { $_ -match ("KERBEROASTING.*for '" + [regex]::Escape($u) + "'") }) }
    if (-not $prev -and -not $roasted) { return $out }
    if ($prev) {
      $out += "    CHAIN: this IP did $($prev.Count) earlier thing(s) in the last hour. FIRST line = where it started:"
      $sel = if ($prev.Count -gt 6) { @($prev[0]) + @($prev[($prev.Count - 5)..($prev.Count - 1)]) } else { $prev }
      $i = 0
      foreach ($l in $sel) { $out += '      > ' + (ChainLine $l); if ($i -eq 0 -and $prev.Count -gt 6) { $out += '      > ...' }; $i++ }
      $out += "      > $(Get-Date -f HH:mm:ss)  $title   <- this alert"
    }
    $all = (@($prev | ForEach-Object { ($_ -split '\|')[0] }) + $title) -join ' ; '
    $why = @()
    if ($roasted) { $why += "'$u' was Kerberoasted earlier and just logged in: its password was cracked. Reset it (25+ chars)." }
    if ($all -match 'SPRAYING' -and $title -match 'LOGON') { $why += "failed logons, then a SUCCESSFUL one from the same IP: a guessed password worked. Change it." }
    if ($all -match 'NETWORK LOGON' -and $title -match 'SERVICE INSTALLED') { $why += 'network logon, then a new service: PsExec-style remote code execution as SYSTEM.' }
    if ($all -match 'NETWORK LOGON' -and $title -match 'TASK CREATED') { $why += 'network logon, then a new task: remote execution / persistence (atexec style).' }
    if ($all -match 'NEW USER' -and $title -match 'ADDED TO GROUP') { $why += 'new account, then a group add: they are building a backdoor admin.' }
    if (@($prev | Where-Object { $_ -match 'KERBEROASTING' }).Count -and $title -match 'KERBEROAST') { $why += 'several service tickets from one IP: a Kerberoasting sweep. Reset every listed service account.' }
    if ($prev -and $title -match 'LOG CLEARED|TAMPERED|AUDITING') { $why += 'they are now hiding their tracks: treat this box as compromised.' }
    $why | Select-Object -Unique | ForEach-Object { $out += "    LIKELY: $_" }
  } catch { }
  $out
}

function Send-Alert([string]$title, [string]$what, $origin, [string]$who, [string[]]$todo) {
  $stamp = Get-Date -Format 'HH:mm:ss'
  $from = if ($origin) { $origin.Line } else { '' }
  $untrusted = $origin -and -not ($origin.IP -in (Get-Trusted) -or $origin.Line -eq 'SYSTEM on this box')
  $chain = @(); if ($untrusted) { $chain = @(Get-Chain $title $origin $who) }
  $likely = @($chain | Where-Object { $_ -like '    LIKELY*' } | Select-Object -First 1)
  $s = Get-State
  $snoozed = $s['snooze'] -and ((Get-Date) -lt [datetime]$s['snooze'])
  if (-not $snoozed -and (Get-Command msg.exe -EA 0)) {
    $pop = "!!! $env:COMPUTERNAME $title !!!`n"
    if ($likely) { $pop += "$($likely[0].Trim())`n" }
    $pop += "$what`nBy: $who`n$from`n$stamp - see the BT ALERTS window"
    if ($pop.Length -gt 254) { $pop = $pop.Substring(0, 251) + '...' }   # msg.exe limit
    msg * /TIME:60 $pop
  }
  $tag = if ($snoozed) { ' [snoozed]' } else { '' }
  "$stamp  $env:COMPUTERNAME  $title | $what | by $who | $from$tag" | Add-Content $Short
  $block = @("", "!!! [$stamp] $env:COMPUTERNAME  $title$tag", "    WHAT : $what", "    WHO  : $who")
  if ($origin) {
    $block += "    FROM : $($origin.IP)   computer: $($origin.Host)"
    $block += "    LOGON: type $($origin.Type) via $($origin.Auth)   process: $($origin.Proc)"
    $block += "    HOW  : $($origin.How)"
    if (-not $untrusted) {
      $todo = @($todo | Where-Object { $_ -notmatch "if it isn't yours|if this wasn't your team" })   # don't tell you to disable yourself
    } else {
      $todo = @(".\bt-alerts.ps1 -Block $($origin.IP)      # attacker? cut them off",
                ".\bt-alerts.ps1 -Trust $($origin.IP)      # scorer/teammate? stop alerting on it",
                ".\bt-alerts.ps1 -Chain $($origin.IP)      # full story of this IP") + $todo
    }
  }
  if ($chain) { $block += $chain }
  if ($todo) { $block += "    DO NOW:"; $todo | ForEach-Object { $block += "      $_" } }
  $block | Add-Content $Full
  if ($Webhook) { try { Invoke-RestMethod -Uri $Webhook -Method Post -ContentType 'application/json' -Body (@{ content = ('```' + "`n" + ($block -join "`n") + "`n" + '```') } | ConvertTo-Json) | Out-Null } catch {} }
}

# ---------------- trigger definitions ----------------
$isDC = $Role -ge 4
$notMine = (Get-MyIPs | ForEach-Object { "EventData[Data[@Name='IpAddress']!='$_']" }) -join ' and '
# Key = @(log, xpath, noisy)   noisy = drop new events while one is still being processed
$Triggers = [ordered]@{
  'rdp'        = @('Security', "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10']]", $false)
  'netlogon'   = @('Security', "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM' or Data[@Name='AuthenticationPackageName']='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'] and $notMine]", $true)   # NTLM only: what PtH/PsExec/spray tools use; normal domain traffic is Kerberos
  'failed'     = @('Security', '*[System[EventID=4625]]', $true)
  'usernew'    = @('Security', '*[System[EventID=4720]]', $false)
  'userenable' = @('Security', '*[System[EventID=4722]]', $false)
  'pwreset'    = @('Security', '*[System[EventID=4724]]', $false)
  'groupadd'   = @('Security', '*[System[(EventID=4728 or EventID=4732 or EventID=4756)]]', $false)
  'svc4697'    = @('Security', '*[System[EventID=4697]]', $false)
  'svc7045'    = @('System',   '*[System[EventID=7045]]', $false)
  'logclear'   = @('Security', '*[System[EventID=1102]]', $false)
  'defender'   = @('Microsoft-Windows-Windows Defender/Operational', '*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007)]]', $false)
  'taskdel'    = @('Security', '*[System[(EventID=4699 or EventID=4702)]]', $false)   # our alert tasks deleted or changed/disabled
  'auditoff'   = @('Security', '*[System[EventID=4719]]', $true)                        # audit policy changed
  'task'       = @('Security', '*[System[EventID=4698]]', $false)
}
if ($isDC) { $Triggers.Insert(3, 'kerberoast', @('Security', "*[System[EventID=4769] and EventData[Data[@Name='TicketEncryptionType']='0x17']]", $true)) }

# ---------------- backfill: what already happened ----------------
function Show-Backfill([int]$h) {
  $since = (Get-Date).AddHours(-$h); $trusted = Get-Trusted; $out = @()
  $priv = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Remote Desktop Users','Remote Management Users','Pre-Windows 2000 Compatible Access'
  $noise = 'ANONYMOUS LOGON','SYSTEM','LOCAL SERVICE','NETWORK SERVICE','-',''
  $rows = foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720,4722,4724,4728,4732,4756,4697,4698,1102; StartTime = $since } -EA 0) +
                        @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -EA 0)) {
    $d = EvData $e; $by = $d.SubjectUserName
    if ($e.Id -notin 7045, 1102 -and ($by -like '*$' -or $by -in $noise)) { continue }   # Windows setup / machine noise
    if ($d.TargetUserName -like '*$' -and $e.Id -in 4720,4722,4724) { continue }        # computer accounts
    [pscustomobject]@{ T = $e.TimeCreated; Id = $e.Id; D = $d; By = $by }
  }
  $rows = @($rows | Sort-Object T)
  $created = @{}; $rows | Where-Object Id -eq 4720 | ForEach-Object { $created[$_.D.TargetUserName] = $_.T }

  $out += "", "==================== BACKFILL: last $h h on $env:COMPUTERNAME ($(Get-Date -f 'HH:mm')) ===================="
  $out += "** PRIVILEGED GROUP CHANGES (check every one of these) **"
  # well-known SIDs: Administrators, Account/Server/Print/Backup Operators, Pre-Win2000, RDP Users, Remote Mgmt Users
  $privSid = 'S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-554','S-1-5-32-555','S-1-5-32-580'
  # domain RIDs: 512 Domain Admins, 518 Schema Admins, 519 Enterprise Admins, 520 Group Policy Creator Owners
  $pg = @($rows | Where-Object { $_.Id -in 4728,4732,4756 -and ($_.D.TargetUserName -in $priv -or $_.D.TargetSid -in $privSid -or $_.D.TargetSid -match '-(512|518|519|520)$') })
  if ($pg) { $pg | ForEach-Object { $sid = $_.D.MemberSid; $m = if ($_.D.MemberName -and $_.D.MemberName -ne '-') { (($_.D.MemberName -split ',')[0]) -replace '^CN=','' } else { switch ($sid) { 'S-1-1-0' { 'Everyone' } 'S-1-5-7' { 'ANONYMOUS LOGON' } 'S-1-5-11' { 'Authenticated Users' } default { $sid } } }
                                    $out += "  {0}  {1,-22} -> {2,-26} by {3}" -f $_.T.ToString('MM/dd HH:mm'), $m, $_.D.TargetUserName, $_.By } }
  else { $out += "  none" }

  $out += "** ACCOUNTS CREATED **"
  $uc = @($rows | Where-Object Id -eq 4720)
  if ($uc) {
    $uc | Group-Object { "{0} by {1}" -f $_.T.ToString('MM/dd HH:mm'), $_.By } | ForEach-Object {
      $names = @($_.Group | ForEach-Object { $_.D.TargetUserName }); $hdr = "  $($_.Name) ($($names.Count)): "; $line = $hdr
      foreach ($nm in $names) { if (($line + $nm).Length -gt 118) { $out += $line.TrimEnd(', '); $line = ' ' * $hdr.Length }; $line += "$nm, " }
      $out += $line.TrimEnd(', ')
    }
  } else { $out += "  none" }

  $out += "** RE-ENABLED / PASSWORD RESET (not part of creating the account) **"
  $re = @($rows | Where-Object { $_.Id -in 4722,4724 -and -not ($created[$_.D.TargetUserName] -and [math]::Abs(($_.T - $created[$_.D.TargetUserName]).TotalMinutes) -lt 2) })
  if ($re) { $re | ForEach-Object { $out += "  {0}  {1,-15} {2,-22} by {3}" -f $_.T.ToString('MM/dd HH:mm'), $(if ($_.Id -eq 4722) { 'ENABLED' } else { 'PASSWORD RESET' }), $_.D.TargetUserName, $_.By } }
  else { $out += "  none" }

  $out += "** SERVICES / TASKS / LOG CLEARING **"
  $other = @($rows | Where-Object {
    ($_.Id -eq 7045 -and $_.D.ImagePath -notmatch '\\System32\\|\\SysWOW64\\|\\Program Files( \(x86\))?\\(Microsoft|Windows Defender|Common Files\\Microsoft)') -or
    ($_.Id -eq 4697 -and $_.D.ServiceFileName -notmatch '\\System32\\|\\SysWOW64\\') -or
    ($_.Id -eq 4698 -and $_.D.TaskName -notlike '\BT-Alert-*') -or $_.Id -eq 1102 })
  if ($other) { foreach ($r in $other) { $t = $r.T.ToString('MM/dd HH:mm')    # ($_ inside switch = the switch value, so use $r)
    $out += switch ($r.Id) {
      7045 { "  $t  SERVICE  $($r.D.ServiceName) -> $($r.D.ImagePath)" }
      4697 { "  $t  SERVICE  $($r.D.ServiceName) -> $($r.D.ServiceFileName)  by $($r.By)" }
      4698 { "  $t  TASK     $($r.D.TaskName)  by $($r.By)" }
      1102 { "  $t  !! SECURITY LOG CLEARED  by $($r.D.SubjectUserName)" } } } }
  else { $out += "  none" }

  $out += "** LOGONS FROM OUTSIDE THIS BOX (machine accounts + trusted IPs hidden) **"
  $lg = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $since } -EA 0 | ForEach-Object {
    $d = EvData $_
    if ($d.LogonType -in '3','10' -and $d.TargetUserName -notlike '*$' -and $d.TargetUserName -ne 'ANONYMOUS LOGON' -and (CleanIP $d.IpAddress) -notin $trusted) {
      [pscustomobject]@{ K = "{0,-18} type {1,-2} from {2,-16} {3}" -f $d.TargetUserName, $d.LogonType, (CleanIP $d.IpAddress), $d.AuthenticationPackageName; T = $_.TimeCreated } } })
  if ($lg) { $lg | Group-Object K | Sort-Object Count -Descending | ForEach-Object { $out += "  {0,4}x  {1}   (last {2})" -f $_.Count, $_.Name, ($_.Group | Sort-Object T | Select-Object -Last 1).T.ToString('MM/dd HH:mm') } }
  else { $out += "  none" }
  $out += "Anything above you can't explain = investigate it NOW (whoshere.ps1, persistence sweep)."
  $out | Add-Content $Full
  foreach ($l in $out) { if ($l -like '[*][*] PRIV*' -or $l -like '*LOG CLEARED*') { Write-Host $l -ForegroundColor Red } elseif ($l -like '[*][*]*' -or $l -like '====*') { Write-Host $l -ForegroundColor Cyan } else { Write-Host $l } }
}

# ---------------- modes ----------------
if ($Trust) { Add-Content $TrustFile $Trust; Write-Host "Trusted $Trust (no more network-logon alerts for it)." -ForegroundColor Green; return }

if ($Snooze -gt 0) { $s = Get-State; $s['snooze'] = (Get-Date).AddMinutes($Snooze).ToString('o'); Save-State $s; Write-Host "Popups snoozed for $Snooze min (alerts still logged and shown in the watch window)." -ForegroundColor Yellow; return }

if ($Block) {
  if ($Block -in (Get-Trusted)) { Write-Host "$Block is trusted (scorer/teammate/this box?). Not blocking. Remove it from $TrustFile if you're sure." -ForegroundColor Yellow; return }
  New-NetFirewallRule -DisplayName "BT block $Block (in)"  -Direction Inbound  -RemoteAddress $Block -Action Block | Out-Null
  New-NetFirewallRule -DisplayName "BT block $Block (out)" -Direction Outbound -RemoteAddress $Block -Action Block | Out-Null
  Set-NetFirewallProfile -All -Enabled True
  Write-Host "Blocked $Block in + out. Undo: Get-NetFirewallRule -DisplayName 'BT block $Block*' | Remove-NetFirewallRule" -ForegroundColor Green
  "$(Get-Date -f HH:mm:ss)  $env:COMPUTERNAME  BLOCKED $Block" | Add-Content $Short
  return
}

if ($Backfill) { Show-Backfill $Hours; return }

if ($Chain) {
  $ip = $Chain.Trim(); $ms = [int64]$Hours * 3600000
  Write-Host "`n=== STORY OF $ip on $env:COMPUTERNAME (last $Hours h) ===" -ForegroundColor Cyan
  $xp = "*[System[(EventID=4624 or EventID=4625 or EventID=4769) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='IpAddress']='$ip' or Data[@Name='IpAddress']='::ffff:$ip']]"
  $ev = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 5000 -EA 0); [array]::Reverse($ev)   # oldest first
  if (-not $ev) { Write-Host "No logons or tickets from $ip in the Security log." -ForegroundColor DarkGray }
  else {
    $rows = foreach ($x in $ev) { $q = EvData $x; [pscustomobject]@{ T = $x.TimeCreated; Id = $x.Id; U = $q.TargetUserName; Type = $q.LogonType; Auth = $q.AuthenticationPackageName; Svc = $q.ServiceName; Enc = $q.TicketEncryptionType } }
    $rows = @($rows)
    $fl = @($rows | Where-Object { $_.Id -eq 4625 }); $ok = @($rows | Where-Object { $_.Id -eq 4624 -and $_.U -notlike '*$' })
    $kr = @($rows | Where-Object { $_.Id -eq 4769 -and $_.Enc -eq '0x17' -and $_.Svc -notlike '*$' -and $_.Svc -ne 'krbtgt' })
    $kind = @{ 4624 = 'successful logon'; 4625 = 'failed logon'; 4769 = 'Kerberos ticket request' }
    Write-Host ("FIRST SEEN  : {0:HH:mm:ss}  ({1})   <- the attack started here" -f $rows[0].T, $kind[[int]$rows[0].Id]) -ForegroundColor Red
    if ($fl) { Write-Host ("FAILED      : {0} from {1:HH:mm:ss} to {2:HH:mm:ss}, users tried: {3}" -f $fl.Count, $fl[0].T, $fl[-1].T, (($fl | Group-Object U | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ' ')) -ForegroundColor Yellow }
    if ($kr) { Write-Host ("KERBEROAST  : {0} RC4 tickets, first {1:HH:mm:ss}, accounts: {2}" -f $kr.Count, $kr[0].T, (($kr | ForEach-Object { $_.Svc } | Select-Object -Unique) -join ', ')) -ForegroundColor Red }
    if ($ok) {
      $f1 = $ok[0]
      Write-Host ("FIRST LOGIN : {0:HH:mm:ss} as {1} (type {2}, {3}): {4}" -f $f1.T, $f1.U, $f1.Type, $f1.Auth, (Get-How $f1.Type $f1.Auth)) -ForegroundColor Red
      Write-Host ("ALL LOGINS  : {0}, accounts: {1}" -f $ok.Count, (($ok | Group-Object U | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ' '))
    }
    if ($fl -and $ok -and $ok[0].T -gt $fl[0].T) { Write-Host "PATTERN     : failed logons first, then a success = password guessing worked" -ForegroundColor Magenta }
    if ($kr -and $ok -and @($ok | Where-Object { $kr.Svc -contains $_.U }).Count) { Write-Host "PATTERN     : a Kerberoasted account later logged in = its password was cracked" -ForegroundColor Magenta }
  }
  Write-Host "`nALERTS FROM THIS IP:" -ForegroundColor Cyan
  $al = @(Get-Content $Short -EA 0 | Where-Object { $_ -match ('\| from ' + [regex]::Escape($ip) + '(\s|$)') })
  if ($al) { $al | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  none' -ForegroundColor DarkGray }
  Write-Host "`nUse FIRST SEEN as the start time in your incident report." -ForegroundColor Cyan
  return
}

if ($Watch) {
  if (-not (Test-Path $Full)) { New-Item $Full -ItemType File | Out-Null }
  function SetTitle([string]$t) { try { $host.UI.RawUI.WindowTitle = $t } catch {} }
  SetTitle "BT ALERTS - $env:COMPUTERNAME"
  # turn OFF QuickEdit for this window: otherwise one mouse click pauses it ("Select" in the title) until a key is pressed
  try {
    Add-Type -Namespace BT -Name Con -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int h); [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m); [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);' -EA Stop
    $ch = [BT.Con]::GetStdHandle(-10); [uint32]$cm = 0
    if ([BT.Con]::GetConsoleMode($ch, [ref]$cm)) { $nm = $cm -bor 0x80; if ($nm -band 0x40) { $nm = $nm - 0x40 }; [void][BT.Con]::SetConsoleMode($ch, [uint32]$nm) }
  } catch { }
  $pos = (Get-Item $Full).Length; $expected = [int](Get-State)['expected']; if (-not $expected) { $expected = $Triggers.Count }; $tick = 0
  $myHash = try { (Get-FileHash $Self -EA Stop).Hash } catch { '' }      # kept in memory: editing the file on disk can't fool it
  Set-Content "$Dir\watch.pid" $PID                                    # newest watch window owns the job; older ones step aside
  Write-Host "Watching for alerts on $env:COMPUTERNAME (Ctrl+C to stop). If the title ever says 'Select', press Esc." -ForegroundColor Cyan
  try {
    while ($true) {
      $len = (Get-Item $Full).Length
      if ($len -lt $pos) { $pos = 0 }
      if ($len -gt $pos) {
        $fs = [IO.File]::Open($Full, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek($pos, 'Begin')
        $sr = New-Object IO.StreamReader($fs); $txt = $sr.ReadToEnd(); $sr.Close(); $pos = $len
        # print the WHOLE alert block first (WHAT/WHO/FROM/HOW/DO NOW), THEN sound the alarm
        $heads = @()
        foreach ($line in ($txt -split "`r?`n")) {
          if ($line -like '!!!*') { Write-Host $line -ForegroundColor Red; $heads += ($line -replace '^!!! \[[^\]]*\]\s*', '') }
          elseif ($line -like '    CHAIN*' -or $line -like '    LIKELY*' -or $line -like '      > *') { Write-Host $line -ForegroundColor Magenta }
          elseif ($line -like '*DO NOW*' -or $line -like '      *') { Write-Host $line -ForegroundColor Yellow }
          elseif ($line) { Write-Host $line }
        }
        if ($heads) { SetTitle "BT ALERTS - $env:COMPUTERNAME  (last alert $(Get-Date -f HH:mm:ss))" }
      }
      if (($tick++ % 30) -eq 0) {
        # HEARTBEAT every 30 s: is the alerting itself still intact?
        $issues = @()
        $owner = try { (Get-Content "$Dir\watch.pid" -EA Stop | Select-Object -First 1).Trim() } catch { "$PID" }
        if ($owner -and $owner -ne "$PID" -and (Get-Process -Id $owner -EA 0)) {
          Write-Host "`nA newer BT ALERTS window (PID $owner) has taken over. This old one is closing in 5 s." -ForegroundColor Yellow
          Start-Sleep -Seconds 5; [Environment]::Exit(0)
        }
        try {
          $bt = @(Get-ScheduledTask -TaskName 'BT-Alert-*' -EA 0)
          $n = @($bt | Where-Object { $_.State -ne 'Disabled' }).Count
          if ($n -lt $expected) { $issues += "only $n of $expected alert tasks active (deleted or disabled)" }
          $bad = @($bt | Where-Object { "$($_.Actions[0].Arguments)" -notlike "*$Self*" } | ForEach-Object { $_.TaskName })
          if ($bad) { $issues += "alert task(s) changed to run something else: $($bad -join ', ')" }
          if ($myHash) { $now = try { (Get-FileHash $Self -EA Stop).Hash } catch { 'missing' }; if ($now -ne $myHash) { $issues += 'bt-alerts.ps1 was EDITED or DELETED since this window opened (ignore if you just re-deployed)' } }
          foreach ($sn in 'EventLog', 'Schedule') { $sv = Get-Service $sn -EA 0; if ($sv -and $sv.Status -ne 'Running') { $issues += "$sn service is $($sv.Status): NO alerts can fire" } }
          if ((($tick - 1) % 300) -eq 0) {     # every 5 min: is auditing still on?
            $csv = "$env:TEMP\bt-audit.csv"; Remove-Item $csv -EA 0; auditpol /backup /file:"$csv" | Out-Null
            $offs = @()
            foreach ($r in @(Get-Content $csv -EA 0 | Select-Object -Skip 1)) {
              $c = $r -split ','
              if ($c.Count -lt 7 -or $c[3].Length -lt 9) { continue }
              $g = $c[3].Trim('{}').Substring(0, 8); $v = 0; [void][int]::TryParse($c[6].Trim(), [ref]$v)
              if ($AuditMap.ContainsKey($g) -and -not ($v -band 1)) { $offs += $AuditMap[$g] }
            }
            Remove-Item $csv -EA 0
            if ($offs) { $issues += "auditing is OFF for: $(($offs | Select-Object -Unique) -join ', ')" }
          }
        } catch { }
        foreach ($i in $issues) {
          if (Throttle "tamper|$i" 10) { Write-Host "!!! HEARTBEAT $(Get-Date -f HH:mm:ss): $i" -ForegroundColor Red }
          else { Send-Alert 'ALERTING TAMPERED' $i $null 'unknown (found by the watch window self-check)' @('.\bt-alerts.ps1 -Install      # restores tasks, auditing, script and folder lock') }
        }
      }
      Start-Sleep -Seconds 1
    }
  } finally { }
}

if ($Install) {
  Set-Content $Flag (Get-Date)
  if ($PSCommandPath -ne $Self) { Copy-Item $PSCommandPath $Self -Force }
  # turn on every audit subcategory the alerts depend on (by GUID: works in any Windows language)
  foreach ($g in $AuditMap.Keys) { auditpol /set /subcategory:"{$($g)-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null }
  # lock C:\bt to Administrators + SYSTEM only: the alert tasks run this script AS SYSTEM, so nobody else may edit it
  icacls $Dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
  if ($LASTEXITCODE -eq 0) { Write-Host 'Locked C:\bt: only Administrators + SYSTEM can change it' -ForegroundColor DarkGray } else { Write-Host 'Could not lock C:\bt permissions (icacls failed)' -ForegroundColor Yellow }
  # bigger Security log so "who/from where" lookups still work hours later
  $maxSize = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
  if ($maxSize -lt 512MB) { wevtutil sl Security /ms:536870912 }
  # auto-trust the IP you are RDP'd in from
  $me = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='10'] and EventData[Data[@Name='TargetUserName']='$env:USERNAME']]" -MaxEvents 1 -EA 0
  if ($me) { $myRdp = CleanIP (EvData $me).IpAddress; if ($myRdp -notin (Get-Trusted)) { Add-Content $TrustFile $myRdp }; Write-Host "Auto-trusted your RDP source: $myRdp" -ForegroundColor DarkGray }
  else { Write-Host "Couldn't find your RDP logon to auto-trust. Use: .\bt-alerts.ps1 -Trust <your IP>" -ForegroundColor Yellow }

  Get-ScheduledTask -TaskName 'BT-Alert-*' -EA 0 | Unregister-ScheduledTask -Confirm:$false
  $cls = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
  $installed = 0; $okNames = @()
  foreach ($k in $Triggers.Keys) {
    $logName, $xpath, $noisy = $Triggers[$k]
    if (-not (Get-WinEvent -ListLog $logName -EA 0)) { Write-Host "[skip] $k (no '$logName' log on this box)" -ForegroundColor DarkGray; continue }
    $t = New-CimInstance -CimClass $cls -ClientOnly; $t.Enabled = $true
    $t.Subscription = "<QueryList><Query Id='0' Path='$logName'><Select Path='$logName'>$xpath</Select></Query></QueryList>"
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-w hidden -nop -ep bypass -File $Self -Key $k -Log `"$logName`""
    $set = New-ScheduledTaskSettingsSet -MultipleInstances $(if ($noisy) { 'IgnoreNew' } else { 'Queue' }) -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    try { Register-ScheduledTask -TaskName "BT-Alert-$k" -Action $a -Trigger $t -Settings $set -User 'SYSTEM' -RunLevel Highest -Force -EA Stop | Out-Null; $okNames += $k; $installed++ }
    catch { Write-Host "[!!] $k : $($_.Exception.Message)" -ForegroundColor Red }
  }
  Write-Host ("Armed {0} detections: {1}" -f $installed, ($okNames -join ', ')) -ForegroundColor Green
  $st = Get-State; $st['expected'] = $installed; Save-State $st
  if (-not $NoBackfill) { Show-Backfill $Hours } else { Write-Host 'What already happened (last 24 h): panel D -> 7, or .\bt-alerts.ps1 -Backfill' -ForegroundColor DarkGray }
  $interactive = [Environment]::UserInteractive -and $host.Name -eq 'ConsoleHost' -and -not $env:SSH_CLIENT -and -not $PSSenderInfo
  if ($interactive) {
    # close any older watch window first (one per box; an old one would also flag the new script as 'edited')
    try { Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA Stop | Where-Object { $_.CommandLine -like '*bt-alerts.ps1*-Watch*' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA 0 } } catch {}
    Start-Process powershell.exe -ArgumentList "-NoExit -ep bypass -File `"$Self`" -Watch"
  }
  else { Write-Host "Remote/SSH session: no window to open. Run  C:\bt\bt-alerts.ps1 -Watch  in this session (or set `$Webhook for phone pings)." -ForegroundColor Yellow }
  Write-Host "`nInstalled $installed alerts on a $(@('standalone workstation','domain member workstation','standalone server','domain member server','domain controller','domain controller (PDC)')[$Role]). Every alert shows in the watch window + a popup. Trusted: $((Get-Trusted) -join ', ')" -ForegroundColor Cyan
  Write-Host "When the scorer/teammates show up as NETWORK LOGON alerts: .\bt-alerts.ps1 -Trust <ip>" -ForegroundColor Cyan
  return
}

if ($Remove) { Set-Content $Flag (Get-Date); Get-ScheduledTask -TaskName 'BT-Alert-*' -EA 0 | Unregister-ScheduledTask -Confirm:$false; Write-Host 'Alerts removed.' -ForegroundColor Yellow; return }

if ($Test) {
  $fake = [ordered]@{ IP = '10.66.6.6'; Host = 'KALI'; Type = '3'; Auth = 'NTLM'; Proc = '-'; How = (Get-How '3' 'NTLM'); Line = 'from 10.66.6.6 (PC: KALI) type 3 NTLM' }
  Send-Alert 'TEST ALERT' 'testuser added to Domain Admins (this is a test)' $fake "$env:USERDOMAIN\testuser" @((CmdRemoveMember 'Domain Admins' 'testuser' 4728))
  return
}

# ---------------- called by a trigger ----------------
if (-not $Key) { Get-Help $PSCommandPath; return }
$e = Get-WinEvent -LogName $Log -FilterXPath $Triggers[$Key][1] -MaxEvents 1 -EA 0
if (-not $e) { return }
$d = EvData $e
$subj = "$($d.SubjectDomainName)\$($d.SubjectUserName)"

switch ($Key) {
  'rdp' {
    $o = Get-Origin $d.TargetLogonId
    if (Throttle "rdp|$($d.TargetUserName)|$($o.IP)" 5) { return }
    Send-Alert 'RDP LOGON' "$($d.TargetDomainName)\$($d.TargetUserName) logged in over RDP" $o "$($d.TargetDomainName)\$($d.TargetUserName)" @(
      'query user                          # find their session ID', 'logoff <ID>',
      "$(CmdDisable $d.TargetUserName $d.TargetDomainName)     # if this isn't you/a teammate")
  }
  'netlogon' {
    if ($d.TargetUserName -like '*$' -or $d.TargetUserName -in 'ANONYMOUS LOGON', '-') { return }
    $ip = CleanIP $d.IpAddress
    if ($ip -in (Get-Trusted)) { return }
    if (Throttle "net|$($d.TargetUserName)|$ip" 10) { return }
    $o = Get-Origin $d.TargetLogonId
    Send-Alert 'NETWORK LOGON FROM UNTRUSTED IP' "$($d.TargetDomainName)\$($d.TargetUserName) authenticated over the network" $o "$($d.TargetDomainName)\$($d.TargetUserName)" @(
      "$(CmdDisable $d.TargetUserName $d.TargetDomainName)     # if unexpected, then change its password")
  }
  'failed' {
    $ip = CleanIP $d.IpAddress
    $n = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddMinutes(-2) } -EA 0 | Where-Object { (CleanIP (EvData $_).IpAddress) -eq $ip }).Count
    if ($n -lt 5 -or (Throttle "fail|$ip" 5)) { return }
    $o = [ordered]@{ IP = $ip; Host = $d.WorkstationName; Type = $d.LogonType; Auth = $d.AuthenticationPackageName; Proc = '-'; How = 'password guessing / spraying'; Line = "from $ip (PC: $($d.WorkstationName))" }
    Send-Alert 'PASSWORD SPRAYING / BRUTE FORCE' "$n failed logons in 2 min (latest user: $($d.TargetUserName))" $o 'unknown (failed logons)' @(
      '# Watch for a SUCCESSFUL logon from this IP next; make sure passwords are strong')
  }
  'kerberoast' {
    if ($d.ServiceName -like '*$' -or $d.ServiceName -eq 'krbtgt') { return }
    $ip = CleanIP $d.IpAddress
    if (Throttle "roast|$ip|$($d.ServiceName)" 10) { return }
    $o = [ordered]@{ IP = $ip; Host = '-'; Type = '-'; Auth = 'Kerberos RC4'; Proc = '-'; How = 'Kerberoasting: asked for an RC4 ticket for a service account to crack its password offline'; Line = "from $ip" }
    Send-Alert 'KERBEROASTING SUSPECTED' "RC4 service ticket for '$($d.ServiceName)' requested by $($d.TargetUserName)" $o $d.TargetUserName @(
      "$(CmdResetPw $d.ServiceName '')   # 25+ chars; update wherever it's used",
      "Get-ADPrincipalGroupMembership '$($d.ServiceName)' | Select Name    # make sure it isn't an admin")
  }
  'usernew' {
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'NEW USER CREATED' "account '$($d.TargetUserName)' was created" $o $subj @(
      "$(CmdDisable $d.TargetUserName $d.TargetDomainName)",
      "$(CmdDisable $d.SubjectUserName $d.SubjectDomainName)    # the account that created it, if it isn't yours")
  }
  'userenable' {
    if (JustCreated $e $d.TargetUserName) { return }      # part of creating the account, already alerted
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'ACCOUNT RE-ENABLED' "'$($d.TargetUserName)' was enabled (a backdoor you disabled coming back?)" $o $subj @(
      "$(CmdDisable $d.TargetUserName $d.TargetDomainName)", "$(CmdDisable $d.SubjectUserName $d.SubjectDomainName)    # if this wasn't your team")
  }
  'pwreset' {
    if (JustCreated $e $d.TargetUserName) { return }      # part of creating the account, already alerted
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'PASSWORD RESET' "password of '$($d.TargetUserName)' was reset" $o $subj @(
      "$(CmdResetPw $d.TargetUserName $d.TargetDomainName)   # take it back",
      "$(CmdDisable $d.SubjectUserName $d.SubjectDomainName)    # if this wasn't your team")
  }
  'groupadd' {
    $o = Get-Origin $d.SubjectLogonId
    $member = if ($d.MemberName -and $d.MemberName -ne '-') { ($d.MemberName -split ',')[0] -replace '^CN=', '' } else { $d.MemberSid }
    Send-Alert "ADDED TO GROUP: $($d.TargetUserName)" "$member was added to '$($d.TargetUserName)'" $o $subj @(
      "$(CmdRemoveMember $d.TargetUserName $member $e.Id)",
      "$(CmdDisable $member $d.MemberDomain)")
  }
  'svc4697' {
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'SERVICE INSTALLED' "service '$($d.ServiceName)' -> $($d.ServiceFileName)" $o $subj @(
      "Stop-Service '$($d.ServiceName)' -Force; sc.exe delete '$($d.ServiceName)'",
      '# A random-named service right after a network logon = PsExec-style remote execution')
  }
  'svc7045' {
    Start-Sleep -Seconds 3                                 # the detailed 4697 version (with who/where) usually lands too
    $m = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4697] and EventData[Data[@Name='ServiceName']='$($d.ServiceName)']]" -MaxEvents 1 -EA 0
    if ($m -and [math]::Abs(($e.TimeCreated - $m.TimeCreated).TotalSeconds) -lt 30) { return }
    Send-Alert 'SERVICE INSTALLED' "service '$($d.ServiceName)' -> $($d.ImagePath) (runs as $($d.AccountName))" $null 'unknown (enable Security System Extension auditing for who/where)' @(
      "Stop-Service '$($d.ServiceName)' -Force; sc.exe delete '$($d.ServiceName)'")
  }
  'logclear' {
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'SECURITY LOG CLEARED' 'the Security event log was wiped: someone is covering their tracks' $o $subj @(
      '# Assume compromise: run whoshere.ps1, hunt persistence, rotate admin passwords',
      "$(CmdDisable $d.SubjectUserName $d.SubjectDomainName)    # if this wasn't your team")
  }
  'defender' {
    $what = switch ($e.Id) {
      1116 { "MALWARE DETECTED: $($d.'Threat Name') at $($d.Path)" }
      1117 { "Defender acted on: $($d.'Threat Name') ($($d.'Action Name'))" }
      5001 { 'Defender REAL-TIME PROTECTION WAS TURNED OFF' }
      5007 { "Defender settings changed: $($d.'New Value')" }
    }
    if ($e.Id -eq 5007 -and (Throttle 'def5007' 2)) { return }
    Send-Alert 'DEFENDER' $what $null ($d.'Detection User') @(
      'Set-MpPreference -DisableRealtimeMonitoring $false',
      '(Get-MpPreference).ExclusionPath     # remove anything you did not add: Remove-MpPreference -ExclusionPath <path>')
  }
  'taskdel' {
    if ($d.TaskName -notlike '\BT-Alert-*' -or (Installing)) { return }
    $verb = 'DELETED'
    if ($e.Id -eq 4702) {
      $bt = Get-ScheduledTask -TaskName ($d.TaskName.TrimStart('\')) -EA 0
      if (-not $bt) { return }
      $okAct = "$($bt.Actions[0].Arguments)" -like "*$Self*"
      if ($bt.State -ne 'Disabled' -and $okAct) { return }          # harmless update (e.g. you re-enabled it)
      $verb = if ($bt.State -eq 'Disabled') { 'DISABLED' } else { "CHANGED to run: $($bt.Actions[0].Execute) $($bt.Actions[0].Arguments)" }
    }
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'ALERTING TAMPERED' "alert task $($d.TaskName) was $verb" $o $subj @('.\bt-alerts.ps1 -Install      # put the alerts back', "$(CmdDisable $d.SubjectUserName $d.SubjectDomainName)    # if this wasn't your team")
  }
  'auditoff' {
    if (Installing) { return }
    Start-Sleep -Seconds 2                                   # 'auditpol /clear' writes a burst: look at the whole burst
    $off = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4719; StartTime = (Get-Date).AddMinutes(-2) } -EA 0 | ForEach-Object { EvData $_ } |
      Where-Object { $_.AuditPolicyChanges -match '8448|8450' -and "$($_.SubcategoryGuid)".Length -ge 9 -and $AuditMap.ContainsKey("$($_.SubcategoryGuid)".Trim('{}').Substring(0, 8)) })
    if (-not $off -or (Throttle 'audit|off' 10)) { return }
    $names = ($off | ForEach-Object { $AuditMap["$($_.SubcategoryGuid)".Trim('{}').Substring(0, 8)] } | Select-Object -Unique) -join ', '
    $o = Get-Origin $off[0].SubjectLogonId
    Send-Alert 'AUDITING TURNED OFF' "auditing disabled for: $names (alerts that need it go blind)" $o "$($off[0].SubjectDomainName)\$($off[0].SubjectUserName)" @(
      '.\bt-alerts.ps1 -Install      # turns auditing back on',
      '# Keeps coming back every few minutes? A GPO is doing it: gpresult /h C:\bt\gp.html, then fix the GPO')
  }
  'task' {
    if ($d.TaskName -like '\BT-Alert-*') { return }
    $cmd = ''; try { $tx = [xml]$d.TaskContent; $cmd = "$($tx.Task.Actions.Exec.Command) $($tx.Task.Actions.Exec.Arguments)" } catch {}
    $o = Get-Origin $d.SubjectLogonId
    Send-Alert 'SCHEDULED TASK CREATED' "$($d.TaskName) runs: $cmd" $o $subj @("Unregister-ScheduledTask -TaskName '$(Split-Path $d.TaskName -Leaf)' -Confirm:`$false")
  }
}
