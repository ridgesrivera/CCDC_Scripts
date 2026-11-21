<#
.SYNOPSIS
    Set-Firewall - a very basic Windows Firewall, step by step, that keeps every service working. CHANGES STATE, one-step revert.

.DESCRIPTION
    PURPOSE
      Turn the firewall on without taking down your own services or locking
      yourself out. Keep it simple:
        * Everything this box is serving RIGHT NOW stays reachable from anywhere
          (an allow rule for every listening port, so nothing on the board breaks).
        * Windows' own built-in allow rules stay as they are (AD, DNS, file sharing...).
        * Everything else coming IN is blocked. Outbound is left open.
        * Dropped connections are logged, so you can see what is being blocked.

    STEPS (each one asks first)
      1. Save the current firewall (netsh export) so it can be put back exactly.
      2. Show every listening port + process; you can untick any you do not want open.
      3. Add "CCDC Allow" rules for them (+ RDP/WinRM/SSH for your own access).
      4. Start a SAFETY TIMER: if you do not confirm within -RevertMinutes (3),
         the firewall is put back automatically. Protects you from locking yourself out.
      5. Turn the firewall on (all profiles): inbound = block, outbound = allow.
      6. You open a NEW RDP/SSH window to test. It works? Confirm: the timer is cancelled.

    WHAT IT READS    listening ports, firewall rules and profiles
    WHAT IT CHANGES  firewall profiles + "CCDC Allow" rules + one temporary task (CCDC-Firewall-Revert)
    HOW TO UNDO      .\Set-Firewall.ps1 -Revert           (puts back the firewall exactly as it was)
                     panel 11 -> 2 does the same.

    MANUAL EQUIVALENT
      netsh advfirewall export C:\ccdc\fw-before.wfw
      netsh advfirewall firewall add rule name="CCDC Allow TCP 80" dir=in action=allow protocol=TCP localport=80
      netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
      netsh advfirewall set allprofiles state on
      Undo:  netsh advfirewall import C:\ccdc\fw-before.wfw

.PARAMETER Revert
    Put the firewall back to the newest saved copy (from step 1).

.PARAMETER Status
    Show profiles, CCDC rules and the saved copies. Changes nothing.

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
    [switch]$Status,
    [ValidateRange(1, 30)][int]$RevertMinutes = 3,
    [switch]$Force,
    [string]$ConfigPath
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Set-Firewall' -ReadOnly:$Status
$saveDir = 'C:\ccdc\firewall'
$task = 'CCDC-Firewall-Revert'
$group = 'CCDC Allow'

function Get-Saved { @(Get-ChildItem $saveDir -Filter 'before_*.wfw' -ErrorAction SilentlyContinue | Sort-Object Name) }
function Show-FwState {
    foreach ($l in (& netsh.exe advfirewall show allprofiles state 2>$null | Where-Object { $_ -match 'Profile Settings|^State' })) { Write-Host "    $l" }
    $n = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count
    Write-Host "    CCDC Allow rules: $n" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
if ($Status) {
    Write-Section 'Firewall status'
    Show-FwState
    foreach ($f in (Get-Saved)) { Write-Finding -Level INFO -Category 'Saved' -Message $f.FullName }
    Complete-Ccdc; return
}

# ---------------------------------------------------------------------------
if ($Revert) {
    Write-Section 'Revert the firewall'
    $f = (Get-Saved | Select-Object -Last 1)
    if (-not $f) { Write-Finding -Level RED -Category 'Revert' -Message "No saved firewall in $saveDir. Turn it off by hand if needed: netsh advfirewall set allprofiles state off"; Complete-Ccdc; return }
    $file = $f.FullName
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Windows Firewall' -Action "Put back exactly as saved in $file" -ScriptBlock {
        $o = & netsh.exe advfirewall import "$file" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
        $null = & schtasks.exe /Delete /TN $task /F 2>&1
    }
    Show-FwState
    Complete-Ccdc; return
}

# ---------------------------------------------------------------------------
Write-Section 'Step 1: save the current firewall'
if (-not (Test-Path $saveDir)) { New-Item -ItemType Directory -Path $saveDir -Force -WhatIf:$false | Out-Null }
$backup = Join-Path $saveDir ("before_{0}.wfw" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
if (-not $WhatIfPreference) {
    $o = & netsh.exe advfirewall export "$backup" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Finding -Level RED -Category 'Backup' -Message "Could not save the firewall, stopping: $o"; Complete-Ccdc; return }
    Write-Finding -Level GREEN -Category 'Backup' -Message "Saved: $backup   (undo any time: .\Set-Firewall.ps1 -Revert)"
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
foreach ($port in $allowTcp) {
    $pt = $port
    if (Get-NetFirewallRule -DisplayName "CCDC Allow TCP $pt" -ErrorAction SilentlyContinue) { continue }
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$true -Target "TCP $pt" -Action 'Allow inbound' -ScriptBlock {
        $null = New-NetFirewallRule -DisplayName "CCDC Allow TCP $pt" -Group $group -Direction Inbound -Protocol TCP -LocalPort $pt -Action Allow -ErrorAction Stop
    }
}
foreach ($port in $allowUdp) {
    $pt = $port
    if (Get-NetFirewallRule -DisplayName "CCDC Allow UDP $pt" -ErrorAction SilentlyContinue) { continue }
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$true -Target "UDP $pt" -Action 'Allow inbound' -ScriptBlock {
        $null = New-NetFirewallRule -DisplayName "CCDC Allow UDP $pt" -Group $group -Direction Inbound -Protocol UDP -LocalPort $pt -Action Allow -ErrorAction Stop
    }
}
Write-Finding -Level INFO -Category 'Rules' -Message ("Allowed TCP {0}; UDP {1}. Windows' built-in rules (AD, DNS, file sharing) are untouched." -f ($allowTcp -join ','), $(if ($allowUdp) { $allowUdp -join ',' } else { '-' }))

# ---------------------------------------------------------------------------
Write-Section "Step 4: safety timer ($RevertMinutes min)"
if (-not $WhatIfPreference) {
    $when = (Get-Date).AddMinutes($RevertMinutes).ToString('HH:mm')
    # No quotes inside /TR (Windows PowerShell mangles embedded quotes); the path has no spaces.
    $cmd = "netsh advfirewall import $backup"
    $o = & schtasks.exe /Create /TN $task /TR "cmd.exe /c $cmd & schtasks /Delete /TN $task /F" /SC ONCE /ST $when /RU SYSTEM /RL HIGHEST /F 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Finding -Level GREEN -Category 'Timer' -Message "If you do not confirm, the firewall is put back at $when." }
    else { Write-Finding -Level YELLOW -Category 'Timer' -Message "Could not create the safety timer ($o). Keep a console session open in case." }
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
if ($ok -and -not $WhatIfPreference) {
    Write-Host '  Open a NEW RDP / SSH connection to this box now (keep this window open).' -ForegroundColor Yellow
    Write-Host '  Check the scoreboard / your services too.' -ForegroundColor Yellow
    $a = Read-Host '  Did the new connection work and are services fine? Type YES to keep the firewall'
    if ($a -ceq 'YES') {
        $null = & schtasks.exe /Delete /TN $task /F 2>&1
        Write-Finding -Level GREEN -Category 'Done' -Message 'Kept. Safety timer cancelled. Undo any time: panel 11 -> 2 (or .\Set-Firewall.ps1 -Revert).'
        Write-Finding -Level INFO -Category 'Done' -Message 'Dropped connections are logged in %windir%\System32\LogFiles\Firewall\pfirewall.log'
    } else {
        Write-Host '  Not confirmed: reverting now.' -ForegroundColor Yellow
        $o = & netsh.exe advfirewall import "$backup" 2>&1
        $null = & schtasks.exe /Delete /TN $task /F 2>&1
        Write-Finding -Level YELLOW -Category 'Done' -Message "Firewall put back as it was. $o"
    }
}
Complete-Ccdc
