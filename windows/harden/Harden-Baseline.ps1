<#
.SYNOPSIS
    Harden-Baseline - modular Windows hardening; every module skippable. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      The fixes for most of what audit\Audit-Vulns.ps1 and Audit-Network.ps1
      flag. Each module: checks current state -> GREEN and skips if already
      fine -> otherwise backs up the registry key / setting -> asks y/N -> applies.

    MODULES (names for -Only / -Skip)
      DisableSMBv1            SMBv1 server off                     (EternalBlue)
      RequireSMBSigning       server+client require signing        (NTLM relay)   * may break very old clients
      DisableLLMNR            policy EnableMulticast=0             (Responder)
      DisableNBTNS            NetbiosOptions=2 on every interface  (Responder)
      DisableWDigest          UseLogonCredential=0                 (cleartext creds in LSASS)
      EnableLSAProtection     RunAsPPL=1                           * needs REBOOT; can break 3rd-party LSA plugins
      DisableSpoolerOnDC      stop + disable Spooler on DCs only   (PrintNightmare)
      EnableAuditPolicy       advanced audit subcategories on      (see lib Get-CcdcAuditPolicyPlan)
      EnableScriptBlockLogging PowerShell 4104 events + command line in 4688
      EnableDefenderRealtime  Defender real-time protection on
      RemoveIfeoDebuggers     delete IFEO "Debugger" values        (sticky-keys backdoors) - asks per entry
      RequireRdpNla           RDP UserAuthentication=1 (NLA)       (pre-auth RDP bugs, sticky keys at login screen)
      DisableGuest            disable the built-in Guest account   (local, or domain Guest on a DC)
      MachineAccountQuotaZero DC: ms-DS-MachineAccountQuota=0      (NoPAC / RBCD need a user-created computer)

    WHAT IT READS    registry, services, SMB config, auditpol, Defender
    WHAT IT CHANGES  only the settings above
    HOW TO UNDO      every registry change is exported first to C:\ccdc\backups\<stamp>\reg_*.reg
                     -> "reg import <file>". Audit policy -> "auditpol /restore /file:<backup csv>".
                     The log lists the exact undo for each change.

    MANUAL EQUIVALENT (one example per module)
      Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
      Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
      wmic nicconfig where IPEnabled=true call SetTcpipNetbios 2
      reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
      reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
      Stop-Service Spooler; Set-Service Spooler -StartupType Disabled
      auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
      Set-MpPreference -DisableRealtimeMonitoring $false
      reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f

.PARAMETER Only
    Run just these modules.
.PARAMETER Skip
    Run everything except these modules.

.EXAMPLE
    .\Harden-Baseline.ps1 -WhatIf
.EXAMPLE
    .\Harden-Baseline.ps1 -Skip EnableLSAProtection,RequireSMBSigning
.EXAMPLE
    .\Harden-Baseline.ps1 -Only RemoveIfeoDebuggers
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('DisableSMBv1', 'RequireSMBSigning', 'DisableLLMNR', 'DisableNBTNS', 'DisableWDigest', 'EnableLSAProtection',
                 'DisableSpoolerOnDC', 'EnableAuditPolicy', 'EnableScriptBlockLogging', 'EnableDefenderRealtime', 'RemoveIfeoDebuggers',
                 'RequireRdpNla', 'DisableGuest', 'MachineAccountQuotaZero')]
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Harden-Baseline'
$null = Get-CcdcConfig -Path $ConfigPath
$isDC = Test-CcdcIsDC

function Test-Run([string]$module) {
    if ($Only -and $Only -notcontains $module) { return $false }
    if ($Skip -contains $module) { Write-Finding -Level INFO -Category $module -Message 'skipped (-Skip)'; return $false }
    Write-Section $module
    return $true
}

function Set-CcdcRegValue {
    <#
      Idempotent registry setter: shows GREEN if already correct, otherwise
      exports the key (backup) and sets the value via Invoke-CcdcChange.
    #>
    param([string]$Path, [string]$Name, [int]$Value, [string]$Category)
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -ne $current -and [int]$current -eq $Value) {
        Write-Finding -Level GREEN -Category $Category -Message "$Name already $Value"; return
    }
    $regPath = $Path -replace '^HKLM:\\', 'HKLM\'
    $undo = if ($null -eq $current) { "reg delete `"$regPath`" /v $Name /f" } else { "reg add `"$regPath`" /v $Name /t REG_DWORD /d $current /f" }
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$regPath\$Name" -Action "Set to $Value (was $(if ($null -eq $current) { 'unset' } else { $current }))" -Undo $undo -ScriptBlock {
        $null = Backup-CcdcRegistry -Key $regPath
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    })
}

# ---------------------------------------------------------------------------
if (Test-Run 'DisableSMBv1') {
    $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($cfg -and -not $cfg.EnableSMB1Protocol) { Write-Finding -Level GREEN -Category 'DisableSMBv1' -Message 'SMBv1 already off' }
    elseif ($cfg) {
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'SMB server' -Action 'Disable SMBv1' -Undo 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force' -ScriptBlock {
            $null = Backup-CcdcRegistry -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        })
    } else { Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 'DisableSMBv1' }
}

if (Test-Run 'RequireSMBSigning') {
    Write-Finding -Level INFO -Category 'RequireSMBSigning' -Message 'All supported Windows/Samba clients sign fine; only ancient devices break.'
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1 'RequireSMBSigning'
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 1 'RequireSMBSigning'
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 'RequireSMBSigning'
}

if (Test-Run 'DisableLLMNR') {
    Set-CcdcRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'DisableLLMNR'
}

if (Test-Run 'DisableNBTNS') {
    # NetbiosOptions per interface: 0 = from DHCP, 1 = on, 2 = off.
    foreach ($if in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$($if.PSChildName)"
        Set-CcdcRegValue $p 'NetbiosOptions' 2 'DisableNBTNS'
    }
}

if (Test-Run 'DisableWDigest') {
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'DisableWDigest'
    Write-Finding -Level INFO -Category 'DisableWDigest' -Message 'Already-cached cleartext creds stay in LSASS until those users log off (or reboot).'
}

if (Test-Run 'EnableLSAProtection') {
    Write-Finding -Level YELLOW -Category 'EnableLSAProtection' -Message 'Takes effect after REBOOT. Do not reboot a scored box mid-round without a plan.'
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 'EnableLSAProtection'
}

if (Test-Run 'DisableSpoolerOnDC') {
    $sp = Get-Service Spooler -ErrorAction SilentlyContinue
    if (-not $isDC) { Write-Finding -Level INFO -Category 'DisableSpoolerOnDC' -Message 'Not a DC - leaving Spooler alone (disable by hand if nothing prints).' }
    elseif (-not $sp -or ($sp.Status -eq 'Stopped' -and $sp.StartType -eq 'Disabled')) { Write-Finding -Level GREEN -Category 'DisableSpoolerOnDC' -Message 'Spooler already stopped+disabled' }
    else {
        $oldStart = $sp.StartType
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Spooler (DC)' -Action 'Stop and disable' -Undo "Set-Service Spooler -StartupType $oldStart; Start-Service Spooler" -ScriptBlock {
            Stop-Service Spooler -Force
            Set-Service Spooler -StartupType Disabled
        })
    }
}

if (Test-Run 'EnableAuditPolicy') {
    $auditBackup = Join-Path (Get-CcdcBackupDir) 'auditpol_before.csv'
    if (-not $WhatIfPreference) { $null = & auditpol.exe /backup /file:"$auditBackup" 2>&1; Write-CcdcLog "BACKUP auditpol -> $auditBackup (undo: auditpol /restore /file:`"$auditBackup`")" 'BACKUP' }
    # Make subcategory ("advanced") settings win over legacy category settings.
    Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 'EnableAuditPolicy'
    $plan = Get-CcdcAuditPolicyPlan
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($plan.Count) audit subcategories" -Action 'Enable success+failure auditing' -Undo "auditpol /restore /file:`"$auditBackup`"" -ScriptBlock {
        foreach ($sub in $plan) {
            $null = & auditpol.exe /set /subcategory:"$($sub.Guid)" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($sub.Name)" }
        }
    })
    # Bigger Security log so events are not overwritten in minutes.
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Security event log' -Action 'Set max size 1 GB' -Undo 'wevtutil sl Security /ms:20971520' -ScriptBlock {
        $null = & wevtutil.exe sl Security /ms:1073741824
        if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }
    })
}

if (Test-Run 'EnableScriptBlockLogging') {
    Set-CcdcRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'EnableScriptBlockLogging'
    # Include the full command line in 4688 process-creation events. (Another
    # reason our scripts never put passwords on a command line.)
    Set-CcdcRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 'EnableScriptBlockLogging'
}

if (Test-Run 'EnableDefenderRealtime') {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mp -and -not $mp.DisableRealtimeMonitoring) { Write-Finding -Level GREEN -Category 'EnableDefenderRealtime' -Message 'Real-time already on' }
        else {
            [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Defender' -Action 'Enable real-time monitoring' -Undo 'Set-MpPreference -DisableRealtimeMonitoring $true' -ScriptBlock {
                Set-MpPreference -DisableRealtimeMonitoring $false
            })
        }
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
        if ($pol.DisableAntiSpyware -eq 1) { Write-Finding -Level RED -Category 'EnableDefenderRealtime' -Message 'Policy DisableAntiSpyware=1 is set (Red Team trick) - check GPO / local policy' }
    } else { Write-Finding -Level INFO -Category 'EnableDefenderRealtime' -Message 'Defender cmdlets not available on this OS.' }
}

if (Test-Run 'RemoveIfeoDebuggers') {
    $found = $false
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
            $dbg = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).Debugger
            if (-not $dbg) { continue }
            $found = $true
            $regKey = ($k.Name)   # already "HKEY_LOCAL_MACHINE\..." form, accepted by reg.exe
            $keyPath = $k.PSPath
            [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($k.PSChildName) Debugger=$dbg" -Action 'Remove IFEO Debugger value' `
                -Undo "reg add `"$regKey`" /v Debugger /t REG_SZ /d `"$dbg`" /f" -ScriptBlock {
                    $null = Backup-CcdcRegistry -Key $regKey
                    Remove-ItemProperty -Path $keyPath -Name Debugger
                })
        }
    }
    if (-not $found) { Write-Finding -Level GREEN -Category 'RemoveIfeoDebuggers' -Message 'No IFEO debuggers present' }
}

if (Test-Run 'RequireRdpNla') {
    # NLA = the user must authenticate BEFORE the RDP login screen appears. Stops
    # pre-auth exploits and makes sticky-keys / utilman backdoors unreachable.
    # Every current RDP client (mstsc, xfreerdp, Remmina) supports it.
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    if ($ts -and $ts.fDenyTSConnections -eq 0) {
        Set-CcdcRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 'RequireRdpNla'
        Write-Finding -Level INFO -Category 'RequireRdpNla' -Message 'Applies to NEW RDP connections. Test a fresh login (and the scoreboard) right after.'
    } else { Write-Finding -Level INFO -Category 'RequireRdpNla' -Message 'RDP is disabled on this box - nothing to do.' }
}

if (Test-Run 'DisableGuest') {
    $guest = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction SilentlyContinue
    if ($isDC) {
        # The domain Guest is always <domain SID>-501; bind to it directly by SID.
        $domRoot = [ADSI]('LDAP://' + ([ADSI]'LDAP://RootDSE').defaultNamingContext)
        $domSid  = (New-Object System.Security.Principal.SecurityIdentifier($domRoot.Properties['objectSid'][0], 0)).Value
        $guestDe = $null
        try { $guestDe = [ADSI]"LDAP://<SID=$domSid-501>"; $null = $guestDe.Properties['sAMAccountName'].Value } catch { $guestDe = $null }
        if ($guestDe -and $guestDe.Properties['sAMAccountName'].Value) {
            $uacNow = [int]$guestDe.Properties['userAccountControl'].Value
            if ($uacNow -band 2) { Write-Finding -Level GREEN -Category 'DisableGuest' -Message 'Domain Guest already disabled' }
            else {
                [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "Domain\$($guestDe.Properties['sAMAccountName'].Value)" -Action 'Disable built-in Guest' -Undo "Enable-ADAccount -Identity $($guestDe.Properties['sAMAccountName'].Value)" -ScriptBlock {
                    $guestDe.Properties['userAccountControl'].Value = $uacNow -bor 2
                    $guestDe.CommitChanges()
                })
            }
        }
    } elseif ($guest) {
        if ($guest.Disabled) { Write-Finding -Level GREEN -Category 'DisableGuest' -Message "Guest ($($guest.Name)) already disabled" }
        else {
            $gName = $guest.Name
            [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "Local\$gName" -Action 'Disable built-in Guest' -Undo "net user `"$gName`" /active:yes" -ScriptBlock {
                $null = & net.exe user $gName /active:no 2>&1
                if ($LASTEXITCODE -ne 0) { throw "net user exit $LASTEXITCODE" }
            })
        }
    }
}

if (Test-Run 'MachineAccountQuotaZero') {
    # ms-DS-MachineAccountQuota (default 10) lets ANY domain user create computer
    # accounts - the first step of NoPAC and RBCD attacks. Admins can still join machines.
    if (-not $isDC) { Write-Finding -Level INFO -Category 'MachineAccountQuotaZero' -Message 'Not a DC - n/a' }
    else {
        $root = [ADSI]('LDAP://' + ([ADSI]'LDAP://RootDSE').defaultNamingContext)
        $maq = [int]$root.Properties['ms-DS-MachineAccountQuota'].Value
        if ($maq -eq 0) { Write-Finding -Level GREEN -Category 'MachineAccountQuotaZero' -Message 'ms-DS-MachineAccountQuota already 0' }
        else {
            [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'domain root' -Action "Set ms-DS-MachineAccountQuota 0 (was $maq)" -Undo "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=$maq}" -ScriptBlock {
                $root.Properties['ms-DS-MachineAccountQuota'].Value = 0
                $root.CommitChanges()
            })
        }
    }
}

Complete-Ccdc
