<#
.SYNOPSIS
    Set-Firewall - a very basic Windows Firewall, step by step, that keeps every service working. CHANGES STATE, guaranteed revert.

.DESCRIPTION
    PURPOSE
      Turn the firewall on without taking down your own services or locking
      yourself out. Keep it simple:
        * Everything this box is serving RIGHT NOW stays reachable from anywhere
          (an allow rule for every listening port, so nothing on the board breaks).
        * Windows' own built-in allow rules stay as they are (AD, DNS, file sharing...).
        * Everything else coming IN is blocked. Outbound is left open.
        * Dropped connections are logged, so you can see what is being blocked.

    HOW THE REVERT WORKS (it does NOT depend on importing a file)
      Before anything changes, the exact settings of each profile (Domain, Private,
      Public: on/off, inbound and outbound default, logging) are written to
      C:\ccdc\firewall\before_<time>.json, and a revert file C:\ccdc\firewall\revert.cmd
      is written with plain netsh commands for those exact settings.
      Revert = delete ONLY the toolkit's own "CCDC Allow" rules + set every profile
      back exactly as recorded. Nothing else is touched. Each part runs on its own,
      so one failing part cannot stop the others, and the result is checked.
      The full netsh export (.wfw) is also kept, as an extra (-RestoreFull).

    STEPS (each one asks first)
      1. Record the current settings (json + revert.cmd) and export the policy (.wfw).
      2. Show every listening port + process; you can leave any of them closed.
      3. Add "CCDC Allow" rules for them (+ RDP / WinRM / SSH for your own access).
      4. SAFETY TIMER: if you do not confirm within -RevertMinutes (3), revert.cmd runs
         as SYSTEM and puts everything back. Protects you from locking yourself out.
      5. Turn the firewall on (all profiles): inbound = block, outbound = allow.
      6. You open a NEW RDP/SSH window to test. It works? Type YES: the timer is cancelled.

    WHAT IT READS    listening ports, firewall rules and profiles
    WHAT IT CHANGES  firewall profiles + "CCDC Allow" rules + one temporary task (CCDC-Firewall-Revert)
    HOW TO UNDO      .\Set-Firewall.ps1 -Revert        (panel 11 -> 2)
                     or double-click C:\ccdc\firewall\revert.cmd as admin (works without the toolkit)

    MANUAL EQUIVALENT
      netsh advfirewall show allprofiles
      netsh advfirewall firewall add rule name="CCDC Allow TCP 80" dir=in action=allow protocol=TCP localport=80
      netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
      netsh advfirewall set allprofiles state on
      Undo:  netsh advfirewall firewall delete rule name="CCDC Allow TCP 80"
             netsh advfirewall set publicprofile state off   (whatever it was before)

.PARAMETER Revert
    Put the firewall back exactly as recorded before the last run.

.PARAMETER RestoreFull
    Extra: import the full saved policy (.wfw). Use only if -Revert is not enough.

.PARAMETER Status
    Show profiles, CCDC rules and the saved records. Changes nothing.

.PARAMETER RevertMinutes
    Safety timer length. Default 3.

.EXAMPLE
    .\Set-Firewall.ps1            # guided
.EXAMPLE
    .\Set-Firewall.ps1 -Revert
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Revert,
    [switch]$RestoreFull,
    [switch]$Status,
    [ValidateRange(1, 30)][int]$RevertMinutes = 3,
    [switch]$Force,
    [string]$ConfigPath
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Set-Firewall' -ReadOnly:$Status
$saveDir = 'C:\ccdc\firewall'
$revertCmd = Join-Path $saveDir 'revert.cmd'
$task = 'CCDC-Firewall-Revert'
$group = 'CCDC Allow'
$hasNetSec = [bool](Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$netshName = @{ Domain = 'domainprofile'; Private = 'privateprofile'; Public = 'publicprofile' }

# ---------------------------------------------------------------------------
# Record / restore profile settings
# ---------------------------------------------------------------------------
function Get-FwProfiles {
    # One object per profile: Name, Enabled (True/False), In (Block/Allow), Out (Block/Allow), LogBlocked (True/False)
    $out = @()
    if ($hasNetSec) {
        foreach ($p in (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
            $out += [pscustomobject]@{ Name = [string]$p.Name; Enabled = [string]$p.Enabled; In = [string]$p.DefaultInboundAction; Out = [string]$p.DefaultOutboundAction; LogBlocked = [string]$p.LogBlocked }
        }
    } else {
        foreach ($n in 'Domain', 'Private', 'Public') {
            $txt = (& netsh.exe advfirewall show ($netshName[$n]) 2>$null) -join "`n"
            $en = if ($txt -match '(?m)^State\s+ON') { 'True' } else { 'False' }
            $pol = if ($txt -match '(?m)^Firewall Policy\s+(\w+),(\w+)') { $Matches[1], $Matches[2] } else { 'BlockInbound', 'AllowOutbound' }
            $out += [pscustomobject]@{ Name = $n; Enabled = $en; In = ($pol[0] -replace 'Inbound(Always)?', ''); Out = ($pol[1] -replace 'Outbound', ''); LogBlocked = 'NotConfigured' }
        }
    }
    return $out
}
function ConvertTo-NetshPolicy($p) {
    # NotConfigured means "Windows default": block inbound, allow outbound.
    $in = if ($p.In -eq 'Allow') { 'allowinbound' } else { 'blockinbound' }
    $outp = if ($p.Out -eq 'Block') { 'blockoutbound' } else { 'allowoutbound' }
    return "$in,$outp"
}
function Show-FwState {
    foreach ($p in (Get-FwProfiles)) { Write-Host ("    {0,-8} firewall {1,-5}  inbound {2,-13} outbound {3}" -f $p.Name, $(if ($p.Enabled -eq 'True') { 'ON' } else { 'OFF' }), $p.In, $p.Out) }
    $n = if ($hasNetSec) { @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count } else { '?' }
    Write-Host "    CCDC Allow rules: $n" -ForegroundColor DarkGray
}
function Write-RevertCmd($profiles, [string[]]$ruleNames) {
    # A plain .cmd that puts the recorded settings back with netsh only. Runs even if PowerShell or the toolkit is broken.
    $lines = @('@echo off', 'REM Puts the Windows Firewall back exactly as it was before Set-Firewall ran. Run as administrator.', "REM Written $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    foreach ($r in $ruleNames) { $lines += "netsh advfirewall firewall delete rule name=""$r"" >nul 2>&1" }
    foreach ($p in $profiles) {
        $np = $netshName[$p.Name]; if (-not $np) { continue }
        $lines += "netsh advfirewall set $np firewallpolicy $(ConvertTo-NetshPolicy $p)"
        $lines += "netsh advfirewall set $np state $(if ($p.Enabled -eq 'True') { 'on' } else { 'off' })"
    }
    $lines += "schtasks /Delete /TN $task /F >nul 2>&1"
    $lines += "echo %date% %time% revert.cmd ran >> ""$saveDir\revert.log"""
    [IO.File]::WriteAllLines($revertCmd, $lines)
}
function Restore-Fw {
    # The real revert. Every part is separate: one failure does not stop the others.
    $rec = Get-ChildItem $saveDir -Filter 'before_*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $rec) { Write-Finding -Level RED -Category 'Revert' -Message "No recorded settings in $saveDir. Run C:\ccdc\firewall\revert.cmd if it exists, or set profiles by hand (netsh advfirewall set allprofiles state off)."; return $false }
    $saved = Get-Content $rec.FullName -Raw | ConvertFrom-Json
    Write-Finding -Level INFO -Category 'Revert' -Message "Putting back the settings recorded in $($rec.Name)"
    $allOk = $true
    # 1. Remove only the toolkit's own rules.
    try {
        if ($hasNetSec) { Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop }
        else { foreach ($r in @($saved.Rules)) { $null = & netsh.exe advfirewall firewall delete rule name="$r" 2>&1 } }
        Write-Finding -Level GREEN -Category 'Revert' -Message 'Removed the CCDC Allow rules (no other rule touched).'
    } catch { $allOk = $false; Write-Finding -Level RED -Category 'Revert' -Message "Could not remove CCDC Allow rules: $($_.Exception.Message)" }
    # 2. Each profile back exactly as recorded.
    foreach ($p in @($saved.Profiles)) {
        try {
            if ($hasNetSec) {
                $sp = @{ Name = $p.Name; Enabled = $p.Enabled; DefaultInboundAction = $p.In; DefaultOutboundAction = $p.Out; ErrorAction = 'Stop' }
                if ($p.LogBlocked -and $p.LogBlocked -ne 'NotConfigured') { $sp.LogBlocked = $p.LogBlocked }
                Set-NetFirewallProfile @sp
            } else {
                $np = $netshName[$p.Name]
                $o1 = & netsh.exe advfirewall set $np firewallpolicy (ConvertTo-NetshPolicy $p) 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o1 -join ' ') }
                $o2 = & netsh.exe advfirewall set $np state $(if ($p.Enabled -eq 'True') { 'on' } else { 'off' }) 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o2 -join ' ') }
            }
        } catch { $allOk = $false; Write-Finding -Level RED -Category 'Revert' -Message "Profile $($p.Name): $($_.Exception.Message)" }
    }
    # 3. Timer no longer needed.
    $null = & schtasks.exe /Delete /TN $task /F 2>&1
    # 4. Check it really matches.
    $now = Get-FwProfiles
    foreach ($p in @($saved.Profiles)) {
        $c = $now | Where-Object { $_.Name -eq $p.Name } | Select-Object -First 1
        $same = $c -and $c.Enabled -eq $p.Enabled -and ($c.In -eq $p.In -or $p.In -eq 'NotConfigured') -and ($c.Out -eq $p.Out -or $p.Out -eq 'NotConfigured')
        if (-not $same) { $allOk = $false }
        Write-Finding -Level $(if ($same) { 'GREEN' } else { 'RED' }) -Category 'Revert' -Message ("{0}: now {1} / in {2} / out {3}  (recorded: {4} / {5} / {6})" -f $p.Name, $c.Enabled, $c.In, $c.Out, $p.Enabled, $p.In, $p.Out)
    }
    if ($allOk) { Write-Finding -Level GREEN -Category 'Revert' -Message 'Firewall is back exactly as it was.' }
    else { Write-Finding -Level RED -Category 'Revert' -Message "Not everything matched. Run $revertCmd as administrator, or -RestoreFull." }
    return $allOk
}

# ---------------------------------------------------------------------------
if ($Status) {
    Write-Section 'Firewall status'
    Show-FwState
    foreach ($f in (Get-ChildItem $saveDir -Filter 'before_*' -ErrorAction SilentlyContinue | Sort-Object Name)) { Write-Finding -Level INFO -Category 'Saved' -Message $f.FullName }
    Complete-Ccdc; return
}
if ($Revert) {
    Write-Section 'Revert the firewall'
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Windows Firewall' -Action 'Remove the CCDC Allow rules and set every profile back as recorded' -ScriptBlock { $null = Restore-Fw }
    Show-FwState
    Complete-Ccdc; return
}
if ($RestoreFull) {
    Write-Section 'Full restore from the saved policy (.wfw)'
    $f = Get-ChildItem $saveDir -Filter 'before_*.wfw' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if (-not $f) { Write-Finding -Level RED -Category 'Restore' -Message 'No .wfw saved.'; Complete-Ccdc; return }
    # The import is done by the firewall service, which may not be able to read C:\ccdc: copy to Windows\Temp first.
    $tmp = Join-Path "$env:windir\Temp" $f.Name
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Windows Firewall' -Action "Import every rule and setting from $($f.Name)" -ScriptBlock {
        Copy-Item $f.FullName $tmp -Force
        $o = & netsh.exe advfirewall import "$tmp" 2>&1
        Remove-Item $tmp -ErrorAction SilentlyContinue
        if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
    }
    Show-FwState
    Complete-Ccdc; return
}

# ---------------------------------------------------------------------------
Write-Section 'Step 1: record the current settings (this is what revert puts back)'
if (-not (Test-Path $saveDir)) { New-Item -ItemType Directory -Path $saveDir -Force -WhatIf:$false | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$profilesBefore = @(Get-FwProfiles)
if (-not $profilesBefore) { Write-Finding -Level RED -Category 'Record' -Message 'Could not read the current firewall settings: stopping (nothing changed).'; Complete-Ccdc; return }
$recordFile = Join-Path $saveDir "before_$stamp.json"
if (-not $WhatIfPreference) {
    [pscustomobject]@{ Time = (Get-Date).ToString('s'); Profiles = $profilesBefore; Rules = @() } | ConvertTo-Json -Depth 4 | Set-Content -Path $recordFile -Encoding UTF8
    Write-RevertCmd $profilesBefore @()
    $null = & netsh.exe advfirewall export (Join-Path $saveDir "before_$stamp.wfw") 2>&1   # extra full copy; not needed for revert
    Write-Finding -Level GREEN -Category 'Record' -Message "Recorded. Undo any time: panel 11 -> 2, or run $revertCmd as admin."
}
Write-Host '  Now:' -ForegroundColor White; Show-FwState

# ---------------------------------------------------------------------------
Write-Section 'Step 2: what this box is serving right now'
$procName = @{}; foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procName[$p.Id] = $p.ProcessName }
$tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' -and [int]$_.LocalPort -lt 49152 } | Sort-Object LocalPort -Unique)
$udp = @()
if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' -and [int]$_.LocalPort -lt 49152 -and $_.LocalPort -notin 5353, 5355, 1900, 3702 } | Sort-Object LocalPort -Unique)
}
$allowTcp = @(); $allowUdp = @()
foreach ($l in $tcp) { $allowTcp += [int]$l.LocalPort; Write-Host ("    TCP {0,-6} {1}" -f $l.LocalPort, $procName[[int]$l.OwningProcess]) }
foreach ($l in $udp) { $allowUdp += [int]$l.LocalPort; Write-Host ("    UDP {0,-6} {1}" -f $l.LocalPort, $procName[[int]$l.OwningProcess]) -ForegroundColor DarkGray }
# Your own way back in, even if it is not listening right now.
foreach ($p in 3389, 5985, 22) { if ($allowTcp -notcontains $p -and (Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue)) { $allowTcp += $p } }
if (-not $Force) {
    $drop = Read-Host '  All of these stay open. Type ports to LEAVE CLOSED (comma separated), or Enter to keep all'
    if ($drop) {
        $d = @($drop -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
        if ($d -contains 3389 -or $d -contains 22 -or $d -contains 5985) { Write-Host '  You are closing a remote-access port. If that is how YOU are connected, you will be cut off (the timer will put it back).' -ForegroundColor Yellow }
        $allowTcp = @($allowTcp | Where-Object { $d -notcontains $_ }); $allowUdp = @($allowUdp | Where-Object { $d -notcontains $_ })
    }
}
$allowTcp = @($allowTcp | Sort-Object -Unique); $allowUdp = @($allowUdp | Sort-Object -Unique)

# ---------------------------------------------------------------------------
Write-Section 'Step 3: allow rules for those ports (from anywhere)'
$added = @()
foreach ($spec in @($allowTcp | ForEach-Object { @{ P = 'TCP'; N = $_ } }) + @($allowUdp | ForEach-Object { @{ P = 'UDP'; N = $_ } })) {
    $ruleName = "CCDC Allow $($spec.P) $($spec.N)"; $proto = $spec.P; $pt = $spec.N
    if ($hasNetSec -and (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) { continue }
    $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$true -Target "$proto $pt" -Action 'Allow inbound' -Undo "netsh advfirewall firewall delete rule name=""$ruleName""" -ScriptBlock {
        if ($hasNetSec) { $null = New-NetFirewallRule -DisplayName $ruleName -Group $group -Direction Inbound -Protocol $proto -LocalPort $pt -Action Allow -ErrorAction Stop }
        else { $o = & netsh.exe advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=$proto localport=$pt 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') } }
    }
    if ($ok) { $added += $ruleName }
}
if (-not $WhatIfPreference) {
    # Keep the record and the revert file in step with the rules actually added.
    [pscustomobject]@{ Time = (Get-Date).ToString('s'); Profiles = $profilesBefore; Rules = $added } | ConvertTo-Json -Depth 4 | Set-Content -Path $recordFile -Encoding UTF8
    Write-RevertCmd $profilesBefore $added
}
Write-Finding -Level INFO -Category 'Rules' -Message ("Allowed TCP {0}; UDP {1}. Windows' built-in rules (AD, DNS, file sharing) are untouched." -f ($allowTcp -join ','), $(if ($allowUdp) { $allowUdp -join ',' } else { '-' }))

# ---------------------------------------------------------------------------
Write-Section "Step 4: safety timer ($RevertMinutes min)"
$timerOk = $false
if (-not $WhatIfPreference) {
    $when = (Get-Date).AddMinutes($RevertMinutes)
    # Runs revert.cmd (plain netsh) as SYSTEM at an exact date + time (safe across midnight).
    $o = ''
    if (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            $act = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $revertCmd"
            $trg = New-ScheduledTaskTrigger -Once -At $when
            $null = Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop
            $timerOk = $true
        } catch { $o = $_.Exception.Message }
    }
    if (-not $timerOk) {
        # Older Windows: schtasks (the path has no spaces, so no quotes are needed inside /TR).
        $o = & schtasks.exe /Create /TN $task /TR $revertCmd /SC ONCE /ST $when.ToString('HH:mm') /SD $when.ToString('MM/dd/yyyy') /RU SYSTEM /RL HIGHEST /F 2>&1
        $timerOk = ($LASTEXITCODE -eq 0)
    }
    if ($timerOk) { Write-Finding -Level GREEN -Category 'Timer' -Message "If you do not type YES, the firewall is put back at $($when.ToString('HH:mm')) automatically." }
    else { Write-Finding -Level RED -Category 'Timer' -Message "Could not create the safety timer ($o). Stopping BEFORE turning the firewall on: nothing that could lock you out has been changed." ; $null = Restore-Fw; Complete-Ccdc; return }
}

# ---------------------------------------------------------------------------
Write-Section 'Step 5: turn the firewall on (inbound block, outbound allow, log drops)'
$ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'all profiles' -Action 'Firewall ON, block inbound, allow outbound' -Undo '.\Set-Firewall.ps1 -Revert' -ScriptBlock {
    $o1 = & netsh.exe advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o1 -join ' ') }
    $null = & netsh.exe advfirewall set allprofiles logging droppedconnections enable 2>&1
    $o2 = & netsh.exe advfirewall set allprofiles state on 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o2 -join ' ') }
}
Show-FwState

# ---------------------------------------------------------------------------
Write-Section 'Step 6: test, then confirm'
if ($WhatIfPreference) { Complete-Ccdc; return }
if (-not $ok) {
    Write-Host '  The firewall was not turned on: putting the rules back as they were.' -ForegroundColor Yellow
    $null = Restore-Fw
} else {
    Write-Host '  Open a NEW RDP / SSH connection to this box now (keep this window open).' -ForegroundColor Yellow
    Write-Host '  Check your services / the scoreboard too.' -ForegroundColor Yellow
    $a = Read-Host '  Did the new connection work and are services fine? Type YES to keep the firewall'
    if ($a -ceq 'YES') {
        $null = & schtasks.exe /Delete /TN $task /F 2>&1
        Write-Finding -Level GREEN -Category 'Done' -Message 'Kept. Safety timer cancelled. Undo any time: panel 11 -> 2, or run C:\ccdc\firewall\revert.cmd as admin.'
        Write-Finding -Level INFO -Category 'Done' -Message 'Dropped connections are logged in %windir%\System32\LogFiles\Firewall\pfirewall.log'
    } else {
        Write-Host '  Not confirmed: reverting now.' -ForegroundColor Yellow
        $null = Restore-Fw
    }
}
Show-FwState
Complete-Ccdc
