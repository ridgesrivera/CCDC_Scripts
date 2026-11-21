<#
.SYNOPSIS
    bt-selftest - end-to-end test of bt-alerts on THIS box. Safe and self-cleaning.

.DESCRIPTION
    PURPOSE
      For each detection it performs the real action (throwaway user, task, service,
      audit-policy toggle, task disable/delete...), waits for the alert to land in
      C:\bt\alerts.log, and prints PASS/FAIL. On FAIL it says WHICH link broke: Windows
      didn't log the event (audit policy / GPO), the alert task didn't fire, or the
      script ran but wrote nothing (with the exact debug command).
      Also checks: scripts parse, tasks Ready, attack-chain linking, C:\bt locked down,
      Guest disabled (health finding, not a tool failure).

    WHAT IT READS    C:\bt\*, event logs, scheduled tasks
    WHAT IT CHANGES  temporarily: user/task/service tagged btstNNNN (all removed at the end),
                     Kerberos ticket auditing off for a few seconds (turned back on),
                     BT-Alert-rdp disabled then deleted (restored). Mutes popups for 10 min
                     while it runs, un-mutes at the end.
    HOW TO UNDO      nothing left behind; if interrupted: C:\bt\bt-alerts.ps1 -Install

    NEEDS            bt-alerts installed (-Install) and the BT ALERTS watch window open
                     (the heartbeat check uses it). Takes about 2 minutes.
    EXPECTED         DC: all PASS except 'guest account' if Guest is enabled (a real finding).
                     Defender SKIPs if Defender isn't running (also a finding).

    MANUAL EQUIVALENT
      net user t1 P@ssw0rd123! /add  -> watch for NEW USER CREATED -> net user t1 /delete

.EXAMPLE
    C:\bt\bt-selftest.ps1
#>
param([int]$Timeout = 25)
$ErrorActionPreference = 'Continue'
$Dir = 'C:\bt'; $Short = "$Dir\alerts.log"; $Full = "$Dir\alerts-full.log"; $StateFile = "$Dir\alert-state.json"
$Role = (Get-CimInstance Win32_ComputerSystem).DomainRole; $isDC = $Role -ge 4
$roleName = @('standalone workstation','domain member workstation','standalone server','domain member server','domain controller','domain controller (PDC)')[$Role]
$tag = 'btst' + (Get-Random -Minimum 1000 -Maximum 9999)
$user = $tag; $task = "$tag-task"; $svc = "$tag-svc"
$pw  = 'Bt!' + [guid]::NewGuid().ToString('N').Substring(0, 8) + 'aA1'    # 14 chars: longer makes 'net user' stop and ask Y/N
$pw2 = 'Rs!' + [guid]::NewGuid().ToString('N').Substring(0, 8) + 'bB2'
$results = New-Object System.Collections.ArrayList
$guests = ([Security.Principal.SecurityIdentifier]'S-1-5-32-546').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]   # 'Guests' in any language

function Result($name, $status, $detail) {
  [void]$results.Add([pscustomobject]@{ Test = $name; Result = $status; Detail = $detail })
  $c = @{ PASS = 'Green'; FAIL = 'Red'; SKIP = 'DarkGray'; MANUAL = 'Yellow' }[$status]
  Write-Host ("[{0,-6}] {1,-30} {2}" -f $status, $name, $detail) -ForegroundColor $c
}
function LineCount { if (Test-Path $Short) { @(Get-Content $Short).Count } else { 0 } }
function WaitFor([int]$before, [string]$pattern) {
  $deadline = (Get-Date).AddSeconds($Timeout)
  do { Start-Sleep -Milliseconds 700; $hit = @(Get-Content $Short -EA 0 | Select-Object -Skip $before | Where-Object { $_ -match $pattern }) }
  until ($hit -or (Get-Date) -gt $deadline)
  if ($hit) { $hit[0] } else { $null }
}
function Diagnose([datetime]$start, [string]$taskKey, [int[]]$ids, [string]$log) {
  if ($taskKey -eq 'none') { return "no alert arrived in time (is the BT ALERTS watch window open? reopen: C:\bt\bt-alerts.ps1 -Watch)" }
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = $start } -EA 0).Count
  $ti = Get-ScheduledTaskInfo -TaskName "BT-Alert-$taskKey" -EA 0
  if ($ev -eq 0) { return "Windows never logged event $($ids -join '/'): audit policy (a GPO may override it; check: auditpol /get /category:*)" }
  if (-not $ti)  { return "event logged, but task BT-Alert-$taskKey is missing: re-run -Install" }
  if ($ti.LastRunTime -lt $start) { return "event logged, but the task didn't fire (last run $($ti.LastRunTime))" }
  return ("task ran (result 0x{0:X}) but wrote no alert. Debug: powershell -ep bypass -File $Dir\bt-alerts.ps1 -Key $taskKey -Log '$log'" -f $ti.LastTaskResult)
}
function Expect([string]$name, [string]$pattern, [scriptblock]$action, [string]$taskKey, [int[]]$ids, [string]$log = 'Security') {
  $start = Get-Date; $before = LineCount
  try { & $action | Out-Null } catch { Result $name 'FAIL' "couldn't perform the test action: $($_.Exception.Message)"; return $null }
  $hit = WaitFor $before $pattern
  if ($hit) { Result $name 'PASS' ("{0}s  {1}" -f [math]::Round(((Get-Date) - $start).TotalSeconds, 1), (($hit -replace '^\S+\s+\S+\s+', '') -replace '\s+', ' ')) }
  else { Result $name 'FAIL' (Diagnose $start $taskKey $ids $log) }
  $hit
}

Write-Host "`nbt-alerts self-test on $env:COMPUTERNAME ($roleName), throwaway objects tagged '$tag'" -ForegroundColor Cyan
Write-Host "(Each test alert will also show in the watch window.)`n" -ForegroundColor DarkGray

# ---------- 0. static checks ----------
foreach ($f in 'bt-alerts.ps1', 'whoshere.ps1', 'pii-hunt.ps1') {
  $p = "$Dir\$f"
  if (-not (Test-Path $p)) { Result "syntax: $f" 'FAIL' 'file missing (re-paste the deploy block)'; continue }
  $errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
  if ($errs) { Result "syntax: $f" 'FAIL' ("{0} (line {1})" -f $errs[0].Message, $errs[0].Extent.StartLineNumber) } else { Result "syntax: $f" 'PASS' 'no syntax errors' }
}
$tasks = @(Get-ScheduledTask -TaskName 'BT-Alert-*' -EA 0)
$exp = try { [int](Get-Content $StateFile -Raw | ConvertFrom-Json).expected } catch { 0 }
$ready = @($tasks | Where-Object { $_.State -in 'Ready', 'Running' }).Count
if (-not $tasks) { Result 'alert tasks installed' 'FAIL' 'none found: run C:\bt\bt-alerts.ps1 -Install first'; $results | Format-Table -AutoSize; return }
if ($ready -eq $tasks.Count -and (-not $exp -or $tasks.Count -eq $exp)) { Result 'alert tasks installed' 'PASS' "$($tasks.Count) tasks, all Ready" }
else { Result 'alert tasks installed' 'FAIL' "$($tasks.Count) found, $ready Ready, $exp expected" }

# reset throttles + install flag so repeat runs don't get suppressed; mute popups during the test
Remove-Item "$Dir\installing.flag" -EA 0
$st = @{}; if (Test-Path $StateFile) { try { (Get-Content $StateFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { if ($_.Name -notmatch '^(fail|rdp|net|roast|audit|tamper)\||^def5007$') { $st[$_.Name] = $_.Value } } } catch {} }
$st['snooze'] = (Get-Date).AddMinutes(10).ToString('o'); ($st | ConvertTo-Json) | Set-Content $StateFile

try { & "$Dir\whoshere.ps1" -Minutes 5 *> $null; Result 'whoshere.ps1 runs' 'PASS' 'completed' } catch { Result 'whoshere.ps1 runs' 'FAIL' $_.Exception.Message }
try { & "$Dir\pii-hunt.ps1" -Paths $Dir *> $null; if ((Get-Item "$Dir\pii-report.txt" -EA 0).LastWriteTime -gt (Get-Date).AddMinutes(-2)) { Result 'pii-hunt.ps1 runs' 'PASS' 'report written' } else { Result 'pii-hunt.ps1 runs' 'FAIL' 'no fresh report' } } catch { Result 'pii-hunt.ps1 runs' 'FAIL' $_.Exception.Message }

# ---------- 1. alert pipeline ----------
[void](Expect 'test alert (pipeline)' 'TEST ALERT' { & "$Dir\bt-alerts.ps1" -Test } 'none' @(0) 'Security')
# attack chain: a second alert from the same (fake) IP must list the first one
& "$Dir\bt-alerts.ps1" -Test | Out-Null; Start-Sleep -Milliseconds 500
$tailF = @(Get-Content $Full -Tail 30 -EA 0)
if ($tailF -match 'CHAIN: this IP') { Result 'attack chain linking' 'PASS' 'second alert from 10.66.6.6 listed the first one' }
else { Result 'attack chain linking' 'FAIL' 'second alert from the same IP had no CHAIN section' }
# folder lock: no low-privilege group may change the scripts that SYSTEM runs
$lowSids = 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-3-0'
$weak = @((Get-Acl "$Dir\bt-alerts.ps1").Access | Where-Object {
  $sid = try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
  $_.AccessControlType -eq 'Allow' -and $lowSids -contains $sid -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership|^\d+$' })
if ($weak) { Result 'C:\bt locked down' 'FAIL' "$(($weak | ForEach-Object { $_.IdentityReference }) -join ', ') can edit it: re-run -Install" }
else { Result 'C:\bt locked down' 'PASS' 'only Administrators + SYSTEM can edit' }

# ---------- 2. account detections ----------
$mk = if ($isDC) { { New-ADUser -Name $user -SamAccountName $user -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true -EA Stop } }
      else { { $o = cmd /c "net user $user $pw /add 2>&1"; if ($LASTEXITCODE) { throw "$o" } } }
$hit = Expect 'new user created' "NEW USER CREATED \| account '$user'" $mk 'usernew' @(4720)
if ($hit) {
  if ($hit -match '\| (from \S+.*|SYSTEM on this box)$' -and $hit -notmatch 'origin unknown|not in log') { Result 'who/where traced' 'PASS' ($hit -replace '^.*\| ', '') }
  else { Result 'who/where traced' 'FAIL' "origin not traced: $($hit -replace '^.*\| ', '')" }
  Start-Sleep 1
  $txt = Get-Content $Full -Raw; $i = $txt.LastIndexOf("account '$user' was created")
  $want = if ($isDC) { 'Disable-ADAccount' } else { '/active:no' }
  if ($i -ge 0 -and $txt.Substring($i, [math]::Min(900, $txt.Length - $i)) -match [regex]::Escape($want)) { Result 'role-correct DO NOW cmd' 'PASS' "suggests $want ($roleName)" }
  else { Result 'role-correct DO NOW cmd' 'FAIL' "expected $want in the DO NOW section" }
}
Start-Sleep 4
$dups = @(Get-Content $Short -EA 0 | Where-Object { $_ -match "(PASSWORD RESET|ACCOUNT RE-ENABLED) .*'$user'" }).Count
if ($dups) { Result 'creation noise suppressed' 'FAIL' "$dups extra reset/enable alerts for the new account" } else { Result 'creation noise suppressed' 'PASS' '1 alert for creating 1 user' }
$rp = if ($isDC) { { Set-ADAccountPassword $user -Reset -NewPassword (ConvertTo-SecureString $pw2 -AsPlainText -Force) -EA Stop } } else { { cmd /c "net user $user $pw2" | Out-Null } }
[void](Expect 'password reset' "PASSWORD RESET \| password of '$user'" $rp 'pwreset' @(4724))
$en = if ($isDC) { { Disable-ADAccount $user; Start-Sleep 1; Enable-ADAccount $user } } else { { cmd /c "net user $user /active:no" | Out-Null; Start-Sleep 1; cmd /c "net user $user /active:yes" | Out-Null } }
[void](Expect 'account re-enabled' "ACCOUNT RE-ENABLED \| '$user'" $en 'userenable' @(4722))
$ga = if ($isDC) { { Add-ADGroupMember -Identity 'S-1-5-32-546' -Members $user -EA Stop } } else { { cmd /c "net localgroup `"$guests`" $user /add" | Out-Null } }
[void](Expect 'added to group' "ADDED TO GROUP: $([regex]::Escape($guests)) .*$user" $ga 'groupadd' @(4728, 4732, 4756))

# a REAL account with a WRONG password (a made-up username can silently log in as Guest when Guest is enabled)
$fl = { 1..12 | ForEach-Object { cmd /c "net use \\127.0.0.1\IPC$ WrongPass1 /user:$user >nul 2>&1"; Start-Sleep -Milliseconds 300 }; cmd /c "net use \\127.0.0.1\IPC$ /delete >nul 2>&1" }
[void](Expect 'failed logons (spraying)' 'PASSWORD SPRAYING' $fl 'failed' @(4625))
$guest = if ($isDC) { (Get-ADUser -Identity "$((Get-ADDomain).DomainSID.Value)-501" -EA 0).Enabled }
         else { $g = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -EA 0 | Where-Object { $_.SID -like '*-501' }; $g -and -not $g.Disabled }   # built-in Guest = RID 501
if ($guest) { Result 'guest account' 'FAIL' 'Guest is ENABLED: spraying with fake usernames leaves no failed-logon trail. Disable it.' } else { Result 'guest account' 'PASS' 'disabled' }

# ---------- 3. persistence detections ----------
$tk = { Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit') -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)) -EA Stop }
$hit = Expect 'scheduled task created' "SCHEDULED TASK CREATED \| .*$task" $tk 'task' @(4698)
if ($hit -and $hit -notmatch 'cmd\.exe') { Result 'task command captured' 'FAIL' 'alert did not include the command (cmd.exe)' } elseif ($hit) { Result 'task command captured' 'PASS' 'shows: cmd.exe /c exit' }

$start = Get-Date; $before = LineCount
try { New-Service -Name $svc -BinaryPathName 'C:\Windows\System32\cmd.exe /c exit' -StartupType Manual -EA Stop | Out-Null
  $deadline = (Get-Date).AddSeconds($Timeout); do { Start-Sleep -Milliseconds 700; $h = @(Get-Content $Short -EA 0 | Select-Object -Skip $before | Where-Object { $_ -match "SERVICE INSTALLED \| service '$svc'" }) } until ((Get-Date) -gt $deadline -or ($h.Count -ge 1 -and ((Get-Date) - $start).TotalSeconds -gt 8))
  if ($h | Where-Object { $_ -notmatch 'runs as' }) { Result 'service (4697, who/where)' 'PASS' 'with source' } else { Result 'service (4697, who/where)' 'FAIL' (Diagnose $start 'svc4697' @(4697) 'Security') }
  if ($h | Where-Object { $_ -match 'runs as' })    { Result 'service duplicate suppressed' 'FAIL' 'got both 7045 + 4697 alerts for one service' }
  elseif (@(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $start } -EA 0).Count) { Result 'service duplicate suppressed' 'PASS' '7045 logged, duplicate alert skipped' }
  else { Result 'service duplicate suppressed' 'FAIL' 'Windows never logged 7045' }
} catch { Result 'service installed' 'FAIL' "couldn't create the test service: $($_.Exception.Message)" }

# ---------- 4. defender + tamper ----------
$mp = if (Get-Command Get-MpComputerStatus -EA 0) { Get-MpComputerStatus -EA 0 } else { $null }
if (-not (Get-Command Add-MpPreference -EA 0) -or -not (Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -EA 0)) { Result 'defender settings changed' 'SKIP' 'no Defender on this box' }
elseif (-not $mp -or -not $mp.AMServiceEnabled -or -not $mp.AntivirusEnabled) { Result 'defender settings changed' 'SKIP' 'Defender is NOT running here: that is itself a finding (check GPOs / Set-MpPreference -DisableRealtimeMonitoring $false)' }
else {
  [void](Expect 'defender settings changed' 'DEFENDER \|' { Add-MpPreference -ExclusionPath "$Dir\$tag-excl" -EA Stop } 'defender' @(5007) 'Microsoft-Windows-Windows Defender/Operational')
  Remove-MpPreference -ExclusionPath "$Dir\$tag-excl" -EA 0
}

# auditing switched off (uses Kerberos ticket auditing, then turns it straight back on)
$kguid = '{0CCE9240-69AE-11D9-BED3-505054503030}'
[void](Expect 'tamper: auditing turned off' 'AUDITING TURNED OFF' { auditpol /set /subcategory:"$kguid" /success:disable /failure:disable | Out-Null } 'auditoff' @(4719))
auditpol /set /subcategory:"$kguid" /success:enable /failure:enable | Out-Null

if (Get-ScheduledTask -TaskName 'BT-Alert-rdp' -EA 0) {
  # Windows usually logs nothing when a task is disabled, so the watch window heartbeat (every 30 s) is what catches it
  $saveT = $Timeout; $Timeout = 45
  $hit = Expect 'tamper: alert task disabled' 'ALERTING TAMPERED \| (alert task .*BT-Alert-rdp was DISABLED|only \d+ of \d+ alert tasks active)' { Disable-ScheduledTask -TaskName 'BT-Alert-rdp' -EA Stop } 'none' @(0)
  if (-not $hit) { Write-Host '         (this check needs the BT ALERTS watch window open: its heartbeat catches disabled tasks)' -ForegroundColor Yellow }
  $Timeout = $saveT
  Enable-ScheduledTask -TaskName 'BT-Alert-rdp' -EA 0 | Out-Null
}
$xml = (Export-ScheduledTask -TaskName 'BT-Alert-rdp' -EA 0)
if ($xml) {
  [void](Expect 'tamper: alert task deleted' 'ALERTING TAMPERED' { Unregister-ScheduledTask -TaskName 'BT-Alert-rdp' -Confirm:$false -EA Stop } 'taskdel' @(4699))
  try { Register-ScheduledTask -TaskName 'BT-Alert-rdp' -Xml $xml -Force -EA Stop | Out-Null; Result 'restore deleted alert task' 'PASS' 'BT-Alert-rdp back' }
  catch { Result 'restore deleted alert task' 'FAIL' "re-run C:\bt\bt-alerts.ps1 -Install ($($_.Exception.Message))" }
} else { Result 'tamper: alert task deleted' 'SKIP' 'BT-Alert-rdp not found' }

# ---------- 5. needs another machine / destructive ----------
Result 'RDP logon' 'MANUAL' 'disconnect + reconnect your RDP session -> expect RDP LOGON'
Result 'network logon (untrusted IP)' 'MANUAL' 'from a machine NOT in trusted.txt: smbclient -L //<this-ip> -U <user> (or nxc smb <ip> -u x -p y)'
if ($isDC) { Result 'kerberoasting' 'MANUAL' 'from Kali: impacket-GetUserSPNs <domain>/<user>:<pw> -dc-ip <this-ip> -request' }
Result 'security log cleared' 'MANUAL' 'not auto-tested (it would wipe real evidence)'

# ---------- cleanup ----------
if ($isDC) { Remove-ADUser -Identity $user -Confirm:$false -EA 0 } else { cmd /c "net user $user /delete" 2>&1 | Out-Null }
Unregister-ScheduledTask -TaskName $task -Confirm:$false -EA 0
cmd /c "sc.exe delete $svc" 2>&1 | Out-Null
$st = @{}; try { (Get-Content $StateFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { if ($_.Name -ne 'snooze') { $st[$_.Name] = $_.Value } } } catch {}; ($st | ConvertTo-Json) | Set-Content $StateFile

$p = @($results | Where-Object Result -eq 'PASS').Count; $f = @($results | Where-Object Result -eq 'FAIL').Count
Write-Host ("`nSUMMARY on {0}: {1} PASS, {2} FAIL, {3} manual/skip. Test objects removed, popups un-muted." -f $env:COMPUTERNAME, $p, $f, ($results.Count - $p - $f)) -ForegroundColor $(if ($f) { 'Red' } else { 'Green' })
