<#
.SYNOPSIS
    Audit-Vulns - CHECK (never exploit) for the big-name Windows vulns. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Quick yes/no on the vulnerabilities Red Team reaches for first. Each
      check reads registry values, service state and patch level only.

    CHECKS
      Zerologon (CVE-2020-1472)      DC: patch level + FullSecureChannelProtection
      PrintNightmare (CVE-2021-34527) Spooler running on a DC; Point-and-Print no-warning policy
      MS17-010 / EternalBlue          SMBv1 on + no patch since March 2017
      NoPAC (CVE-2021-42278/42287)   DC: patch level + ms-DS-MachineAccountQuota
      LLMNR / NBT-NS                  name-poisoning (Responder) exposure
      WDigest                         cleartext creds in LSASS memory
      LSA protection (RunAsPPL)       makes mimikatz-style LSASS dumping harder
      LAPS                            legacy or Windows LAPS present?
      Defender                        real-time on, signatures fresh
      Bonus: AlwaysInstallElevated, UAC disabled

    LIMITATION - patch checks use "date of newest installed update". Windows
    updates are cumulative on 2016+/Win10+, so a CU newer than the fix date
    almost certainly includes it. On 2012 R2 (monthly rollups vs security-only)
    treat GREEN as "probably" and confirm the specific KB.

    WHAT IT READS   registry, services, Get-HotFix, Get-MpComputerStatus, LDAP (domain root)
    WHAT IT CHANGES nothing
    HOW TO UNDO     nothing to undo. Fixes: harden\Harden-Baseline.ps1

    MANUAL EQUIVALENT
      Get-HotFix | sort InstalledOn | select -Last 3
      reg query HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v FullSecureChannelProtection
      Get-Service Spooler
      reg query "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast
      reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
      reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
      Get-MpComputerStatus | select RealTimeProtectionEnabled,AntivirusSignatureAge

.EXAMPLE
    .\Audit-Vulns.ps1
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Vulns' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath
$isDC = Test-CcdcIsDC

function Get-RegValue([string]$Path, [string]$Name) {
    $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($v) { return $v.$Name } else { return $null }
}

# Newest update install date = rough patch level.
$newestPatch = (Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn
if ($newestPatch) { Write-Finding -Level INFO -Category 'Patch' -Message "Newest installed update: $($newestPatch.ToString('yyyy-MM-dd'))" }
else { Write-Finding -Level YELLOW -Category 'Patch' -Message 'Could not determine patch level (Get-HotFix empty).' }
function Test-PatchedAfter([datetime]$date) { return ($newestPatch -and $newestPatch -ge $date) }

# ---------------------------------------------------------------------------
Write-Section 'Zerologon (CVE-2020-1472)'
# ---------------------------------------------------------------------------
if ($isDC) {
    $fscp  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'FullSecureChannelProtection'
    $allow = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'vulnerablechannelallowlist'
    if (-not (Test-PatchedAfter ([datetime]'2020-08-11'))) {
        Write-Finding -Level RED -Category 'Zerologon' -Message 'DC has no update since Aug 2020 - Zerologon LIKELY EXPLOITABLE (domain takeover in seconds)'
    } elseif (-not (Test-PatchedAfter ([datetime]'2021-02-09')) -and $fscp -ne 1) {
        Write-Finding -Level YELLOW -Category 'Zerologon' -Message 'Patched but enforcement mode not on (set FullSecureChannelProtection=1)'
    } else { Write-Finding -Level GREEN -Category 'Zerologon' -Message 'Patched and enforcement in effect' }
    if ($allow) { Write-Finding -Level RED -Category 'Zerologon' -Message "vulnerablechannelallowlist is set: $allow" }
} else { Write-Finding -Level INFO -Category 'Zerologon' -Message 'Not a DC - n/a' }

# ---------------------------------------------------------------------------
Write-Section 'PrintNightmare (CVE-2021-34527)'
# ---------------------------------------------------------------------------
$spool = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spool -and $spool.Status -eq 'Running') {
    $lvl = if ($isDC) { 'RED' } else { 'YELLOW' }
    Write-Finding -Level $lvl -Category 'PrintNightmare' -Message ("Print Spooler RUNNING{0}" -f $(if ($isDC) { ' on a DOMAIN CONTROLLER - disable it' } else { ' - disable if nothing prints' }))
} else { Write-Finding -Level GREEN -Category 'PrintNightmare' -Message 'Print Spooler not running' }
$pnp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if ((Get-RegValue $pnp 'NoWarningNoElevationOnInstall') -eq 1) { Write-Finding -Level RED -Category 'PrintNightmare' -Message 'Point and Print NoWarningNoElevationOnInstall=1 (exploitable even when patched)' }
if ((Get-RegValue $pnp 'RestrictDriverInstallationToAdministrators') -eq 0) { Write-Finding -Level RED -Category 'PrintNightmare' -Message 'RestrictDriverInstallationToAdministrators=0' }

# ---------------------------------------------------------------------------
Write-Section 'MS17-010 / EternalBlue'
# ---------------------------------------------------------------------------
$smb1 = $null
$smbCfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbCfg) { $smb1 = $smbCfg.EnableSMB1Protocol } else { $smb1 = ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -ne 0) }
if ($smb1 -and -not (Test-PatchedAfter ([datetime]'2017-03-14'))) {
    Write-Finding -Level RED -Category 'MS17-010' -Message 'SMBv1 ON and no update since March 2017 - EternalBlue LIKELY'
} elseif ($smb1) {
    Write-Finding -Level YELLOW -Category 'MS17-010' -Message 'SMBv1 ON (patched by date, but disable it anyway)'
} else { Write-Finding -Level GREEN -Category 'MS17-010' -Message 'SMBv1 off' }

# ---------------------------------------------------------------------------
Write-Section 'NoPAC / sAMAccountName spoofing (CVE-2021-42278/42287)'
# ---------------------------------------------------------------------------
if ($isDC) {
    if (Test-PatchedAfter ([datetime]'2021-11-09')) { Write-Finding -Level GREEN -Category 'NoPAC' -Message 'DC patched (Nov 2021+)' }
    else { Write-Finding -Level RED -Category 'NoPAC' -Message 'DC not patched since Nov 2021 - any domain user -> Domain Admin' }
    try {
        $root = [ADSI]('LDAP://' + ([ADSI]'LDAP://RootDSE').defaultNamingContext)
        $maq = [int]$root.Properties['ms-DS-MachineAccountQuota'].Value
        $lvl = if ($maq -gt 0) { 'YELLOW' } else { 'GREEN' }
        Write-Finding -Level $lvl -Category 'NoPAC' -Message "ms-DS-MachineAccountQuota = $maq $(if ($maq -gt 0) { '(any user can add computers; set to 0 to blunt NoPAC/RBCD)' })"
    } catch { Write-Finding -Level INFO -Category 'NoPAC' -Message 'Could not read MachineAccountQuota' }
} else { Write-Finding -Level INFO -Category 'NoPAC' -Message 'Not a DC - n/a' }

# ---------------------------------------------------------------------------
Write-Section 'LLMNR / NBT-NS (Responder poisoning)'
# ---------------------------------------------------------------------------
$llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
if ($llmnr -eq 0) { Write-Finding -Level GREEN -Category 'LLMNR' -Message 'LLMNR disabled by policy' }
else { Write-Finding -Level YELLOW -Category 'LLMNR' -Message 'LLMNR enabled (default) - poisonable' }
# NetbiosOptions: 0 = use DHCP setting, 1 = enabled, 2 = disabled. Per interface.
$nbt = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions }
if ($nbt -and -not ($nbt | Where-Object { $_ -ne 2 })) { Write-Finding -Level GREEN -Category 'NBT-NS' -Message 'NetBIOS over TCP/IP disabled on all interfaces' }
else { Write-Finding -Level YELLOW -Category 'NBT-NS' -Message ("NetBIOS over TCP/IP enabled on some interfaces (values: {0})" -f (($nbt | Sort-Object -Unique) -join ',')) }

# ---------------------------------------------------------------------------
Write-Section 'Credential exposure: WDigest / LSA protection'
# ---------------------------------------------------------------------------
$wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
if ($wd -eq 1) { Write-Finding -Level RED -Category 'WDigest' -Message 'UseLogonCredential=1 - CLEARTEXT passwords in LSASS (Red Team sets this on purpose)' }
else { Write-Finding -Level GREEN -Category 'WDigest' -Message ("WDigest cleartext caching off (value: {0})" -f $(if ($null -eq $wd) { 'not set = off on 2012R2+' } else { $wd })) }
$ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
if ($ppl -ge 1) { Write-Finding -Level GREEN -Category 'LSA' -Message "LSA protection on (RunAsPPL=$ppl; takes effect after reboot)" }
else { Write-Finding -Level YELLOW -Category 'LSA' -Message 'LSA protection (RunAsPPL) off' }

# ---------------------------------------------------------------------------
Write-Section 'LAPS'
# ---------------------------------------------------------------------------
$legacyLaps  = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"
$windowsLaps = Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
if ($legacyLaps -or $windowsLaps) { Write-Finding -Level GREEN -Category 'LAPS' -Message ("LAPS present (legacy={0}, Windows LAPS policy={1})" -f $legacyLaps, $windowsLaps) }
else { Write-Finding -Level YELLOW -Category 'LAPS' -Message 'No LAPS - local admin passwords are probably identical across boxes' }

# ---------------------------------------------------------------------------
Write-Section 'Defender'
# ---------------------------------------------------------------------------
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $lvl = if ($mp.RealTimeProtectionEnabled -and $mp.AntivirusEnabled) { 'GREEN' } else { 'RED' }
        Write-Finding -Level $lvl -Category 'Defender' -Message ("AV enabled={0} real-time={1} tamper={2}" -f $mp.AntivirusEnabled, $mp.RealTimeProtectionEnabled, $mp.IsTamperProtected)
        if ($mp.AntivirusSignatureAge -gt 30) { Write-Finding -Level YELLOW -Category 'Defender' -Message "Signatures $($mp.AntivirusSignatureAge) days old (no internet = expected; still detects known tools)" }
    } else { Write-Finding -Level RED -Category 'Defender' -Message 'Defender cmdlets present but status unavailable (service stopped/removed?)' }
} else { Write-Finding -Level YELLOW -Category 'Defender' -Message 'Defender cmdlets not present (2012 R2 or removed) - check for other AV' }

# ---------------------------------------------------------------------------
Write-Section 'Bonus quick wins'
# ---------------------------------------------------------------------------
$aieM = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if ($aieM -eq 1) { Write-Finding -Level RED -Category 'Privesc' -Message 'AlwaysInstallElevated=1 (any user can install MSI as SYSTEM)' }
$lua = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
if ($lua -eq 0) { Write-Finding -Level RED -Category 'UAC' -Message 'UAC disabled (EnableLUA=0)' } else { Write-Finding -Level GREEN -Category 'UAC' -Message 'UAC enabled' }

Complete-Ccdc
