<#
.SYNOPSIS
    Set-Firewall - all profiles on, default-deny inbound, allowlist scored ports, never lock yourself out. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      Make the Windows Firewall actually enforce something without breaking
      scored services or your own RDP/WinRM session.

    STEPS (each one asks y/N unless -Force; -WhatIf shows them all)
      1. Export the current firewall policy (backup) with netsh.
      2. Add "CCDC Allowlist" rules for every -AllowTcp / -AllowUdp port
         (default: this host's scoredPorts from config). -Preset DC adds the
         ports Active Directory needs.
      3. Add a "CCDC Admin" rule for RDP/WinRM (+SSH if sshd exists) from
         -AdminSources PLUS the IP of every currently connected admin session.
      4. Schedule a ONE-TIME rollback task (-RollbackMinutes, default 5) that
         re-imports the backup. If you get locked out, wait and it undoes itself.
      5. Turn on all profiles, inbound default = Block, outbound = Allow, log drops.
      6. Optional -DisableOtherInboundRules: DISABLE (not delete) every other
         enabled inbound allow rule, so only the allowlist remains.
      7. Ask you to test a NEW connection; on "yes" the rollback task is removed.

    IMPORTANT CONCEPT FOR STUDENTS
      "Default inbound = Block" only blocks traffic that NO allow rule matches.
      Windows ships allow rules for every role you install (AD, DNS, IIS...),
      so step 5 alone rarely breaks a service - and is also NOT a true allowlist.
      Step 6 is what makes it an allowlist; that is where things break, so it
      is opt-in and fully reversible.

    WHAT IT READS    current sessions (Get-NetTCPConnection), firewall rules, config\ccdc.json
    WHAT IT CHANGES  firewall profiles + rules, one temporary scheduled task (CCDC-Firewall-Rollback)
    HOW TO UNDO      netsh advfirewall import "C:\ccdc\backups\<stamp>\firewall.wfw"
                     (the path is printed and logged), or wait for the rollback task.

    MANUAL EQUIVALENT
      netsh advfirewall export C:\ccdc\fw-before.wfw
      netsh advfirewall set allprofiles state on
      netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
      netsh advfirewall firewall add rule name="CCDC Allow TCP 80" dir=in action=allow protocol=TCP localport=80
      netsh advfirewall firewall add rule name="CCDC Admin" dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.100.0/24

.EXAMPLE
    .\Set-Firewall.ps1 -AllowTcp 80,443 -WhatIf
.EXAMPLE
    .\Set-Firewall.ps1 -Preset DC -AdminSources 192.168.100.0/24
.EXAMPLE
    .\Set-Firewall.ps1 -AllowTcp 80,443 -DisableOtherInboundRules
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [int[]]$AllowTcp = @(),
    [int[]]$AllowUdp = @(),
    [ValidateSet('None', 'DC')][string]$Preset = 'None',
    [string[]]$AdminSources = @(),
    [int[]]$AdminPorts = @(3389, 5985, 5986),
    [switch]$DisableOtherInboundRules,
    [ValidateRange(2, 60)][int]$RollbackMinutes = 5,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Set-Firewall'
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config
$group   = 'CCDC Allowlist'

# ---------------------------------------------------------------------------
# Work out what to allow
# ---------------------------------------------------------------------------
if (-not $AllowTcp -and -not $AllowUdp -and $hostCfg) {
    $AllowTcp = @($hostCfg.scoredPorts.tcp | Where-Object { $_ }); $AllowUdp = @($hostCfg.scoredPorts.udp | Where-Object { $_ })
    Write-Finding -Level INFO -Category 'Plan' -Message "Using scored ports from config for '$($hostCfg.name)'"
}
if ($Preset -eq 'DC' -or (Test-CcdcIsDC)) {
    if ($Preset -ne 'DC') { Write-Finding -Level YELLOW -Category 'Plan' -Message 'This is a DC - adding AD ports automatically (same as -Preset DC).' }
    # DNS, Kerberos, RPC EPM, LDAP, SMB, kpasswd, LDAPS, GC, ADWS, + RPC dynamic range (AD replication/logons need it)
    $AllowTcp += 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 9389
    $AllowUdp += 53, 88, 123, 389, 464
    $dcRpcRange = '49152-65535'
} else { $dcRpcRange = $null }
if (Get-Service sshd -ErrorAction SilentlyContinue) { $AdminPorts += 22 }
$AllowTcp   = @($AllowTcp | Where-Object { $AdminPorts -notcontains $_ } | Sort-Object -Unique)  # admin ports get their own restricted rule
$AllowUdp   = @($AllowUdp | Sort-Object -Unique)
$AdminPorts = @($AdminPorts | Sort-Object -Unique)
if (-not $AllowTcp -and -not $AllowUdp) {
    Write-Finding -Level RED -Category 'Plan' -Message 'No ports to allow. Pass -AllowTcp/-AllowUdp or add this host to config. Refusing to default-deny blind.'
    Complete-Ccdc; return
}

# Who is connected right now? Their IPs are ALWAYS allowed on admin ports.
$liveAdmins = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $AdminPorts -contains [int]$_.LocalPort -and $_.RemoteAddress -notmatch '^(127\.|::1$)' } |
    ForEach-Object { $_.RemoteAddress } | Sort-Object -Unique)
if (-not $AdminSources -and $config -and $config.adminSources) { $AdminSources = @($config.adminSources) }
if (-not $AdminSources) { $AdminSources = @('LocalSubnet') }   # firewall keyword = this box's own subnet(s)
$adminRemote = @($AdminSources + $liveAdmins | Sort-Object -Unique)

Write-Finding -Level INFO -Category 'Plan' -Message ("Allow TCP: {0}" -f ($AllowTcp -join ', '))
Write-Finding -Level INFO -Category 'Plan' -Message ("Allow UDP: {0}" -f $(if ($AllowUdp) { $AllowUdp -join ', ' } else { '(none)' }))
if ($dcRpcRange) { Write-Finding -Level INFO -Category 'Plan' -Message "Allow TCP RPC dynamic: $dcRpcRange (needed by AD)" }
Write-Finding -Level INFO -Category 'Plan' -Message ("Admin ports {0} from: {1}" -f ($AdminPorts -join ','), ($adminRemote -join ', '))
if ($liveAdmins) { Write-Finding -Level GREEN -Category 'Plan' -Message ("Your live session(s) from {0} will stay allowed" -f ($liveAdmins -join ', ')) }
else { Write-Finding -Level YELLOW -Category 'Plan' -Message 'No live RDP/WinRM/SSH session detected (console?). Admin access limited to the sources above.' }

# ---------------------------------------------------------------------------
# 1. Backup
# ---------------------------------------------------------------------------
$backup = $null
if (-not $WhatIfPreference) {
    $backup = Join-Path (Get-CcdcBackupDir) 'firewall.wfw'
    $null = & netsh advfirewall export "$backup" 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Finding -Level GREEN -Category 'Backup' -Message "Firewall policy exported to $backup" -Detail "Undo: netsh advfirewall import `"$backup`"" ; Write-CcdcLog "UNDO: netsh advfirewall import `"$backup`"" 'CHANGE' }
    else { Write-Finding -Level RED -Category 'Backup' -Message 'Firewall export FAILED - stopping (no backup, no changes).'; Complete-Ccdc; return }
}

# ---------------------------------------------------------------------------
# 2-3. Allow rules (added BEFORE default-deny so nothing drops in between)
# ---------------------------------------------------------------------------
function Add-AllowRule([string]$DisplayName, [string]$Proto, [string[]]$Ports, [string[]]$Remote = @('Any')) {
    if (Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue) {
        Write-Finding -Level INFO -Category 'Rule' -Message "exists: $DisplayName"; return
    }
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $DisplayName -Action 'Add inbound allow rule' `
        -Undo "Remove-NetFirewallRule -DisplayName '$DisplayName'" -ScriptBlock {
            New-NetFirewallRule -DisplayName $DisplayName -Group $group -Direction Inbound -Action Allow `
                -Protocol $Proto -LocalPort $Ports -RemoteAddress $Remote -Profile Any | Out-Null
        })
}
foreach ($p in $AllowTcp) { Add-AllowRule "CCDC Allow TCP $p" 'TCP' @("$p") }
foreach ($p in $AllowUdp) { Add-AllowRule "CCDC Allow UDP $p" 'UDP' @("$p") }
if ($dcRpcRange) { Add-AllowRule "CCDC Allow TCP RPC $dcRpcRange" 'TCP' @($dcRpcRange) }
Add-AllowRule ("CCDC Admin TCP {0}" -f ($AdminPorts -join ',')) 'TCP' ($AdminPorts | ForEach-Object { "$_" }) $adminRemote

# ---------------------------------------------------------------------------
# 4. Safety net: scheduled rollback (interactive runs only)
# ---------------------------------------------------------------------------
$taskName = 'CCDC-Firewall-Rollback'
$rollbackSet = $false
if ($backup -and -not $Force) {
    $rollbackSet = Invoke-CcdcChange -Cmdlet $PSCmdlet -Target $taskName -Action "Schedule automatic rollback in $RollbackMinutes min" `
        -Undo "Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false" -ScriptBlock {
            $act  = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument "advfirewall import `"$backup`""
            $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RollbackMinutes)
            Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trig -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        }
} elseif ($Force) {
    Write-Finding -Level YELLOW -Category 'Safety' -Message '-Force: no automatic rollback scheduled. Keep the console/another session open.'
}

# ---------------------------------------------------------------------------
# 5. Profiles: on, block inbound by default, log drops
# ---------------------------------------------------------------------------
[void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Domain,Private,Public profiles' -Action 'Enable firewall, inbound=Block, outbound=Allow, log blocked' `
    -Undo "netsh advfirewall import <backup>" -ScriptBlock {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384
    })

# ---------------------------------------------------------------------------
# 6. Optional: disable everything else (true allowlist)
# ---------------------------------------------------------------------------
if ($DisableOtherInboundRules) {
    $others = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object { $_.Group -ne $group })
    Write-Finding -Level YELLOW -Category 'Rule' -Message "$($others.Count) other enabled inbound allow rules would be DISABLED (not deleted)."
    $others | Select-Object -First 15 | ForEach-Object { Write-Host "       $($_.DisplayName)" -ForegroundColor DarkGray }
    if ($others.Count -gt 15) { Write-Host "       ... and $($others.Count - 15) more" -ForegroundColor DarkGray }
    $rbFile = $script:CcdcLogFile -replace '\.log$', '_reenable.ps1'
    $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($others.Count) inbound rules" -Action 'Disable all non-CCDC inbound allow rules' `
        -Undo "run $rbFile" -ScriptBlock {
            # Write the re-enable list FIRST, so a failure halfway is still recoverable.
            $others | ForEach-Object { "Enable-NetFirewallRule -Name '$($_.Name)'" } | Set-Content -Path $rbFile -Encoding UTF8
            $others | Disable-NetFirewallRule
        }
    if ($ok) { Write-Finding -Level INFO -Category 'Rule' -Message "Re-enable script: $rbFile" }
}

# ---------------------------------------------------------------------------
# 7. Confirm connectivity, then cancel the rollback
# ---------------------------------------------------------------------------
if ($rollbackSet) {
    Write-Host ""
    Write-Host "  TEST NOW: open a NEW RDP/WinRM/SSH connection from your admin box AND check the scoreboard." -ForegroundColor Yellow
    Write-Host "  If you do nothing, the firewall reverts automatically in $RollbackMinutes minutes." -ForegroundColor Yellow
    $keep = Read-Host '  Type YES to keep the new rules'
    if ($keep -ceq 'YES') {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Finding -Level GREEN -Category 'Safety' -Message 'Rollback task removed - new rules kept.'
        Write-CcdcLog "Rollback task $taskName removed by operator" 'CHANGE'
    } else {
        Write-Finding -Level YELLOW -Category 'Safety' -Message "Rollback still scheduled. To revert now: netsh advfirewall import `"$backup`""
    }
}
Complete-Ccdc
