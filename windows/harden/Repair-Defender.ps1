<#
.SYNOPSIS
    Repair-Defender - bring Microsoft Defender back online and prove it is working. CHANGES STATE (each fix confirmed, reversible).

.DESCRIPTION
    PURPOSE
      Attackers turn Defender off (or exclude their folder) before dropping tools.
      This checks every common way it gets switched off and puts it back:
        1. Defender feature removed (Server)          -> offers to reinstall it (needs a reboot)
        2. WinDefend service stopped                   -> start it
        3. Group Policy "turn off Defender" switches   -> removed (registry key backed up first)
        4. Real-time / behaviour / download / script scanning off -> turned back on
        5. Exclusions (folders, programs, extensions)  -> listed; you choose which to remove
        6. Old signatures                              -> tries an update (needs internet; fine if it fails)
        7. Verify: real-time protection really ON. Optional quick scan.
      Third-party antivirus installed? Defender steps back on purpose: the script says so and stops.

    WHAT IT READS    Defender status + settings, WinDefend service, Defender policy registry keys
    WHAT IT CHANGES  only what you confirm; every change is logged with its undo
    HOW TO UNDO      policy keys: reg import the .reg file it prints (C:\ccdc\backups\<time>\)
                     settings: Set-MpPreference -DisableRealtimeMonitoring $true (etc.)
                     exclusions: Add-MpPreference -ExclusionPath <path>

    MANUAL EQUIVALENT
      Get-MpComputerStatus | fl AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge
      reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s
      Set-MpPreference -DisableRealtimeMonitoring $false ; Get-MpPreference | select Exclusion*
      Start-MpScan -ScanType QuickScan

.EXAMPLE
    .\Repair-Defender.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force,
    [string]$ConfigPath
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Repair-Defender'
$polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'

# ---------------------------------------------------------------------------
Write-Section '1. Is Defender installed?'
# ---------------------------------------------------------------------------
$other = @(Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -notmatch 'Defender' })
if ($other) { Write-Finding -Level YELLOW -Category 'Other AV' -Message ("Another antivirus is installed: {0}. Defender turns itself off when another AV is active; check that one instead." -f (($other | ForEach-Object { $_.displayName }) -join ', ')); Complete-Ccdc; return }
$svc = Get-WmiObject Win32_Service -Filter "Name='WinDefend'" -ErrorAction SilentlyContinue
if (-not $svc -or -not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    $feat = if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue } else { $null }
    if ($feat -and -not $feat.Installed) {
        Write-Finding -Level RED -Category 'Installed' -Message 'Defender was REMOVED from this server.'
        $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Windows-Defender feature' -Action 'Reinstall (a reboot is needed to finish)' -Undo 'Uninstall-WindowsFeature Windows-Defender' -ScriptBlock { $null = Install-WindowsFeature -Name Windows-Defender -ErrorAction Stop }
        Write-Finding -Level YELLOW -Category 'Installed' -Message 'Reboot when the captain agrees, then run this again.'
    } else { Write-Finding -Level RED -Category 'Installed' -Message 'Defender is not available on this Windows version / edition. Use another AV.' }
    Complete-Ccdc; return
}
Write-Finding -Level GREEN -Category 'Installed' -Message 'Defender is installed.'

# ---------------------------------------------------------------------------
Write-Section '2. Service'
# ---------------------------------------------------------------------------
if ($svc.State -ne 'Running') {
    Write-Finding -Level RED -Category 'Service' -Message "WinDefend is $($svc.State) ($($svc.StartMode))"
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'WinDefend' -Action 'Start the Defender service' -ScriptBlock { Start-Service -Name WinDefend -ErrorAction Stop }
} else { Write-Finding -Level GREEN -Category 'Service' -Message 'WinDefend running.' }

# ---------------------------------------------------------------------------
Write-Section '3. Group Policy switches that turn Defender off'
# ---------------------------------------------------------------------------
$offValues = @(
    @{ Key = $polKey; Name = 'DisableAntiSpyware' }, @{ Key = $polKey; Name = 'DisableAntiVirus' },
    @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableRealtimeMonitoring' }, @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableBehaviorMonitoring' },
    @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableOnAccessProtection' }, @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableIOAVProtection' },
    @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableScriptScanning' }, @{ Key = "$polKey\Real-Time Protection"; Name = 'DisableScanOnRealtimeEnable' }
)
$found = @($offValues | Where-Object { (Get-ItemProperty -Path $_.Key -Name $_.Name -ErrorAction SilentlyContinue).($_.Name) -eq 1 })
if ($found) {
    foreach ($v in $found) { Write-Finding -Level RED -Category 'Policy' -Message "$($v.Name) = 1  ($($v.Key -replace '^HKLM:\\', 'HKLM\'))" }
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Defender policy' -Action ("Remove {0} 'turn off' value(s) (key backed up first)" -f $found.Count) -Undo 'reg import the .reg backup printed in the log' -ScriptBlock {
        $bk = Backup-CcdcRegistry -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
        if ($bk) { Write-Host "     backup: $bk" -ForegroundColor DarkGray }
        foreach ($v in $found) { Remove-ItemProperty -Path $v.Key -Name $v.Name -ErrorAction Stop }
    }
    Write-Finding -Level INFO -Category 'Policy' -Message 'If a domain GPO sets these, it will put them back: on the DC check gpmc.msc (Computer > Admin Templates > Windows Components > Microsoft Defender Antivirus).'
} else { Write-Finding -Level GREEN -Category 'Policy' -Message 'No policy switches turning Defender off.' }

# ---------------------------------------------------------------------------
Write-Section '4. Protection settings'
# ---------------------------------------------------------------------------
$pref = Get-MpPreference -ErrorAction SilentlyContinue
$offPrefs = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning' | Where-Object { $pref -and $pref.$_ })
if ($offPrefs) {
    Write-Finding -Level RED -Category 'Settings' -Message ("Turned off: {0}" -f ($offPrefs -join ', '))
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Defender settings' -Action ("Turn back on: {0}" -f ($offPrefs -join ', ')) -Undo ("Set-MpPreference " + (($offPrefs | ForEach-Object { "-$_ `$true" }) -join ' ')) -ScriptBlock {
        $sp = @{}; foreach ($n in $offPrefs) { $sp[$n] = $false }
        Set-MpPreference @sp -ErrorAction Stop
    }
} else { Write-Finding -Level GREEN -Category 'Settings' -Message 'Real-time, behaviour, download and script scanning are on.' }

# ---------------------------------------------------------------------------
Write-Section '5. Exclusions (Defender does not look here)'
# ---------------------------------------------------------------------------
$excl = @()
if ($pref) {
    foreach ($t in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') { foreach ($v in @($pref.$t | Where-Object { $_ })) { $excl += @{ Type = $t; Value = $v } } }
}
if (-not $excl) { Write-Finding -Level GREEN -Category 'Exclusions' -Message 'No exclusions.' }
foreach ($e in $excl) {
    Write-Finding -Level YELLOW -Category 'Exclusions' -Message ("{0}: {1}" -f ($e.Type -replace 'Exclusion', ''), $e.Value)
    $et = $e.Type; $ev = $e.Value
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$et $ev" -Action 'Remove exclusion (keep it only if a service you run needs it)' -Undo "Add-MpPreference -$et '$ev'" -ScriptBlock { $p = @{ $et = $ev }; Remove-MpPreference @p -ErrorAction Stop }
}
if ($excl) { Write-Finding -Level INFO -Category 'Exclusions' -Message 'Removed a folder exclusion? Scan it now (step 7): tools hidden there get caught.' }

# ---------------------------------------------------------------------------
Write-Section '6. Signatures'
# ---------------------------------------------------------------------------
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($st -and $st.AntivirusSignatureAge -gt 3) {
    Write-Finding -Level YELLOW -Category 'Signatures' -Message "Signatures are $($st.AntivirusSignatureAge) days old."
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Defender signatures' -Action 'Try to update (needs internet; skipping is fine)' -ScriptBlock { Update-MpSignature -ErrorAction Stop }
} elseif ($st) { Write-Finding -Level GREEN -Category 'Signatures' -Message "Signatures are $($st.AntivirusSignatureAge) day(s) old." }

# ---------------------------------------------------------------------------
Write-Section '7. Verify'
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 2
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
$ok = $st -and $st.AMServiceEnabled -and $st.AntivirusEnabled -and $st.RealTimeProtectionEnabled
if ($ok) {
    Write-Finding -Level GREEN -Category 'Verify' -Message ("Defender is ON: real-time protection enabled{0}." -f $(if ($st.IsTamperProtected) { ', tamper protection on' } else { '' }))
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'this box' -Action 'Start a quick scan in the background (a few minutes)' -ScriptBlock { Start-MpScan -ScanType QuickScan -AsJob | Out-Null }
    Write-Finding -Level INFO -Category 'Verify' -Message 'Detections: Get-MpThreatDetection, or Event Viewer > Windows Defender > Operational (event 1116).'
} else {
    Write-Finding -Level RED -Category 'Verify' -Message ("Defender is still NOT fully on (service={0}, antivirus={1}, real-time={2})." -f $st.AMServiceEnabled, $st.AntivirusEnabled, $st.RealTimeProtectionEnabled)
    Write-Finding -Level INFO -Category 'Verify' -Message 'Common causes: a domain GPO turning it off (check gpmc.msc), a pending reboot after reinstall, or another AV. Run this again after fixing.'
}
Complete-Ccdc
