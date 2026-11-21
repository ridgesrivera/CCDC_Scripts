<#
.SYNOPSIS
    Audit-Vulns - check (never exploit) the Windows vulns Red Team uses first, and show which ones you closed. READ-ONLY.

.DESCRIPTION
    PURPOSE
      One table that answers three questions for every big-name Windows vuln:
        NOW       is this box exposed right now?          VULNERABLE / AT RISK / OK
        BEFORE    was it exposed in the ORIGINAL snapshot? (how the box was when we got here)
        CHANGE    FIXED since then (and by which toolkit script), or REGRESSED
                  (it was fixed, now it is open again: someone turned it back on)
      The BEFORE column needs a snapshot (backup\Snapshot-State.ps1; the panel takes
      the ORIGINAL automatically). Without one you still get the NOW column.

    CHECKS (remote code execution, domain takeover, credential theft)
      Zerologon CVE-2020-1472 (DC)          PrintNightmare CVE-2021-1675/34527 + Point and Print
      EternalBlue MS17-010 (SMBv1)          SMBGhost CVE-2020-0796
      BlueKeep CVE-2019-0708 (2008 R2/7)    SIGRed CVE-2020-1350 (DNS server)
      noPac CVE-2021-42278/42287 (DC)       PetitPotam CVE-2021-36942 + AD CS web enrollment (ESC8)
      Certifried CVE-2022-26923 (DC)        MS14-068 Kerberos (old DCs)
      HiveNightmare CVE-2021-36934          Follina CVE-2022-30190
      ProxyLogon / ProxyShell (Exchange)    IPv6 RCE CVE-2024-38063
      LDAPNightmare CVE-2024-49112 (DC)     SMB NTLM reflection CVE-2025-33073
      LDAP signing + channel binding (DC)   SMB signing (relay)
      NTLMv1 / LM hashes                    LLMNR / NBT-NS poisoning
      WDigest cleartext passwords           LSA protection (RunAsPPL)
      Anonymous / null sessions / Guest     AlwaysInstallElevated, UAC, remote local-admin token
      RDP without NLA                       Defender real-time off / exclusions
      Patch age (anything newer than the last update)
      AD CS ESC1 templates (live only)

    HOW PATCH CHECKS WORK (limitation)
      "Patched" = the newest installed update is newer than the fix date. Updates are
      cumulative on 2016 / Windows 10 and newer, so this is reliable there. On 2012 R2
      and older (security-only updates exist) treat OK as "probably" and confirm the KB.
      Zero-days by definition have no check: keep LIVE ALERTS running for those.

    WHAT IT READS    registry, services, Get-HotFix, SAM file ACL, Defender, LDAP, the ORIGINAL snapshot
    WHAT IT CHANGES  nothing
    HOW TO UNDO      nothing to undo. Fixes: each finding names the panel option / command.

    MANUAL EQUIVALENT
      Get-HotFix | sort InstalledOn | select -Last 3
      reg query HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
      Get-Service Spooler ; Get-SmbServerConfiguration | select EnableSMB1Protocol,RequireSecuritySignature
      icacls C:\Windows\System32\config\SAM

.PARAMETER Against
    Snapshot for the BEFORE column: original (default), latest, or a folder name.

.EXAMPLE
    .\Audit-Vulns.ps1 -OutFile C:\ccdc\reports\vulns.txt
#>
[CmdletBinding()]
param(
    [string]$Against = 'original',
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Vulns' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath

# ---------------------------------------------------------------------------
# Facts about this box (same for NOW and BEFORE: patch level, OS, roles)
# ---------------------------------------------------------------------------
$os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
$X = @{
    Build = [int]$os.BuildNumber; Caption = [string]$os.Caption; IsDC = (Test-CcdcIsDC)
    Patch = (Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn
}
$liveSvc = @{}
foreach ($v in (Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)) { $liveSvc[$v.Name] = @{ StartMode = $v.StartMode; State = $v.State } }
$X.Dns      = $liveSvc.ContainsKey('DNS')
$X.Adcs     = $liveSvc.ContainsKey('CertSvc')
$X.AdcsWeb  = Test-Path "$env:windir\System32\CertSrv\en-US" -ErrorAction SilentlyContinue
$X.Exchange = [bool]($liveSvc.Keys | Where-Object { $_ -like 'MSExchange*' } | Select-Object -First 1)
$X.AdcsInForest = $false
try {
    $cfgNc = [string]([ADSI]'LDAP://RootDSE').configurationNamingContext
    if ($cfgNc) { $X.AdcsInForest = [bool]([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNc").Children.GetEnumerator().MoveNext() }
} catch { $null = $_ }
$X.Maq = $null
if ($X.IsDC) { try { $X.Maq = [int]([ADSI]('LDAP://' + ([ADSI]'LDAP://RootDSE').defaultNamingContext)).Properties['ms-DS-MachineAccountQuota'].Value } catch { $null = $_ } }
$guest = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction SilentlyContinue | Select-Object -First 1
$X.GuestName = if ($guest) { $guest.Name } else { $null }

function Test-Patched([datetime]$fixDate) { return ($X.Patch -and $X.Patch -ge $fixDate) }
$patchTxt = if ($X.Patch) { $X.Patch.ToString('yyyy-MM-dd') } else { 'unknown' }

# ---------------------------------------------------------------------------
# State accessors: the same check code runs against NOW and against a snapshot.
# ---------------------------------------------------------------------------
$Live = @{ Kind = 'live'; Services = $liveSvc; Extra = (Get-CcdcExtraFacts); Defender = @{}; Users = @{} }
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    try { $mp = Get-MpPreference -ErrorAction Stop; $Live.Defender.DisableRealtimeMonitoring = $mp.DisableRealtimeMonitoring; $Live.Defender.ExclusionPath = @($mp.ExclusionPath | Where-Object { $_ }); $Live.Defender.ExclusionProcess = @($mp.ExclusionProcess | Where-Object { $_ }) } catch { $null = $_ }
}
if ($guest) { $Live.Users[$guest.Name] = @{ Enabled = -not $guest.Disabled } }

$script:Unknown = $false
function Get-SReg($S, [string]$key, [string]$name) {
    # Registry value data (or $null). Flags 'unknown' if the snapshot never captured that key.
    if ($S.Kind -eq 'live') { $v = Read-CcdcRegValue -KeyId $key -Name $name }
    else {
        if (-not (Test-CcdcRegKeyCaptured -RegKeys $S.RegKeys -KeyId $key)) { $script:Unknown = $true; return $null }
        $v = $S.Reg["$key|$name"]
    }
    if ($v) { return $v.Data } else { return $null }
}
function Get-SSvc($S, [string]$name) { if ($S.Services) { return $S.Services[$name] } else { $script:Unknown = $true; return $null } }
function Get-SFact($S, [string]$name) { if ($S.Extra -and $S.Extra.ContainsKey($name)) { return $S.Extra[$name] } $script:Unknown = $true; return $null }
function Test-SvcOn($svc) { return ($svc -and ($svc.State -eq 'Running' -or $svc.StartMode -eq 'Auto')) }
function New-Vuln([string]$why) { return @{ S = 'VULN'; Why = $why } }
function New-Risk([string]$why) { return @{ S = 'RISK'; Why = $why } }
function New-Ok([string]$why) { return @{ S = 'OK'; Why = $why } }

$P_LSA   = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$P_SRV   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$P_NETL  = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$P_NTDS  = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$P_TS    = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
$P_RDP   = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$P_PNP   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$P_SYS   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

# ---------------------------------------------------------------------------
# The checks. Applies = does it apply to this box at all. Eval = param($S) -> V/K/G.
# Tokens = words that appear in the toolkit's change log when it fixes this.
# ---------------------------------------------------------------------------
$checks = @(
    @{ Id = 'Zerologon'; Cve = 'CVE-2020-1472'; Name = 'Zerologon (domain takeover)'; Applies = { $X.IsDC }; Tokens = @('FullSecureChannelProtection', 'vulnerablechannelallowlist')
       Fix = 'Patch. Delete Netlogon\Parameters vulnerablechannelallowlist; set FullSecureChannelProtection=1'
       Eval = { param($S)
           $allow = Get-SReg $S $P_NETL 'vulnerablechannelallowlist'; $fscp = Get-SReg $S $P_NETL 'FullSecureChannelProtection'
           if (-not (Test-Patched '2020-08-11')) { return (New-Vuln "no update since Aug 2020 (newest: $patchTxt)") }
           if ($allow) { return (New-Vuln "vulnerablechannelallowlist is set ($allow): those accounts bypass the fix") }
           if (-not (Test-Patched '2021-02-09') -and $fscp -ne 1) { return (New-Risk 'patched, but enforcement mode is off (FullSecureChannelProtection != 1)') }
           New-Ok 'patched and enforced' } }
    @{ Id = 'PrintNightmare'; Cve = 'CVE-2021-34527'; Name = 'PrintNightmare / Spooler coercion'; Applies = { $true }; Tokens = @('Spooler')
       Fix = 'Panel 12 (walkthrough step SpoolerDC) or: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled'
       Eval = { param($S)
           $sp = Get-SSvc $S 'Spooler'
           if ((Get-SReg $S $P_PNP 'NoWarningNoElevationOnInstall') -eq 1) { return (New-Vuln 'Point and Print NoWarningNoElevationOnInstall=1: exploitable even when patched') }
           if ((Get-SReg $S $P_PNP 'RestrictDriverInstallationToAdministrators') -eq 0) { return (New-Vuln 'RestrictDriverInstallationToAdministrators=0: non-admins can install drivers') }
           if ((Test-SvcOn $sp) -and -not (Test-Patched '2021-08-10')) { return (New-Vuln "Spooler $($sp.State)/$($sp.StartMode) and no update since Aug 2021") }
           if ((Test-SvcOn $sp) -and $X.IsDC) { return (New-Vuln "Spooler $($sp.State) on a DOMAIN CONTROLLER: PrinterBug coercion -> relay -> domain takeover") }
           if (Test-SvcOn $sp) { return (New-Risk "Spooler $($sp.State)/$($sp.StartMode): disable it if nothing on this box prints") }
           New-Ok 'Spooler stopped and not automatic' } }
    @{ Id = 'EternalBlue'; Cve = 'MS17-010'; Name = 'EternalBlue (SMBv1 RCE)'; Applies = { $true }; Tokens = @('SMB1')
       Fix = 'Panel 12 (walkthrough step SMBv1) or: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
       Eval = { param($S)
           $smb1 = Get-SFact $S 'Smb1Server'
           if ($smb1 -and -not (Test-Patched '2017-03-14')) { return (New-Vuln 'SMBv1 ON and no update since March 2017: remote SYSTEM') }
           if ($smb1) { return (New-Risk 'SMBv1 server ON (patched by date, but turn it off: nothing modern needs it)') }
           New-Ok 'SMBv1 server off' } }
    @{ Id = 'SMBGhost'; Cve = 'CVE-2020-0796'; Name = 'SMBGhost (SMBv3 compression RCE)'; Applies = { $X.Build -in 18362, 18363 }; Tokens = @('DisableCompression')
       Fix = 'Patch, or set LanmanServer\Parameters DisableCompression=1'
       Eval = { param($S)
           if (Test-Patched '2020-03-12') { return (New-Ok 'patched') }
           if ((Get-SReg $S $P_SRV 'DisableCompression') -eq 1) { return (New-Risk 'unpatched, but compression disabled (workaround)') }
           New-Vuln 'build 1903/1909, unpatched, SMBv3 compression on: remote SYSTEM' } }
    @{ Id = 'BlueKeep'; Cve = 'CVE-2019-0708'; Name = 'BlueKeep (RDP RCE, 2008 R2 / 7)'; Applies = { $X.Build -le 7601 }; Tokens = @('UserAuthentication', 'fDenyTSConnections')
       Fix = 'Patch (KB4499175), or require NLA (panel 12 step RdpNla), or disable RDP'
       Eval = { param($S)
           if ((Get-SReg $S $P_TS 'fDenyTSConnections') -eq 1) { return (New-Ok 'RDP disabled') }
           if (Test-Patched '2019-05-14') { return (New-Ok 'patched') }
           if ((Get-SReg $S $P_RDP 'UserAuthentication') -eq 1) { return (New-Risk 'unpatched, NLA on (attacker needs a valid login first)') }
           New-Vuln 'RDP on, unpatched, no NLA: wormable remote SYSTEM' } }
    @{ Id = 'SIGRed'; Cve = 'CVE-2020-1350'; Name = 'SIGRed (DNS server RCE)'; Applies = { $X.Dns }; Tokens = @('TcpReceivePacketSize')
       Fix = 'Patch, or: reg add HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 /f ; net stop dns ; net start dns'
       Eval = { param($S)
           if (Test-Patched '2020-07-14') { return (New-Ok 'patched') }
           $t = Get-SReg $S 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'TcpReceivePacketSize'
           if ($t -and [int]$t -le 0xFF00) { return (New-Risk 'unpatched, TcpReceivePacketSize workaround in place') }
           New-Vuln 'DNS server unpatched since July 2020: wormable remote SYSTEM on the DC' } }
    @{ Id = 'noPac'; Cve = 'CVE-2021-42278/42287'; Name = 'noPac (any user -> Domain Admin)'; Applies = { $X.IsDC }; Tokens = @('MachineAccountQuota')
       Fix = 'Patch. Panel 12 step MAQ blunts it'
       Eval = { param($S)
           if (-not (Test-Patched '2021-11-09')) { return (New-Vuln "DC not patched since Nov 2021 (MachineAccountQuota=$($X.Maq))") }
           if ($X.Maq -gt 0) { return (New-Risk "patched; MachineAccountQuota=$($X.Maq) still lets any user add computers (RBCD / KrbRelayUp)") }
           New-Ok 'patched, MachineAccountQuota=0' } }
    @{ Id = 'PetitPotam'; Cve = 'CVE-2021-36942'; Name = 'PetitPotam / NTLM relay to AD CS (ESC8)'; Applies = { $X.IsDC -or $X.Adcs }; Tokens = @('CertSrv')
       Fix = 'Patch. Remove AD CS Web Enrollment if unused, or require HTTPS + Extended Protection (IIS)'
       Eval = { param($S)
           if ($X.IsDC -and -not (Test-Patched '2021-08-10')) { return (New-Vuln 'DC unpatched since Aug 2021: anonymous coercion of the DC') }
           if ($X.AdcsWeb) { return (New-Risk 'AD CS Web Enrollment installed here: NTLM relay target (DC certificate -> domain takeover)') }
           New-Ok 'patched, no web enrollment on this box' } }
    @{ Id = 'Certifried'; Cve = 'CVE-2022-26923'; Name = 'Certifried (AD CS machine cert -> DA)'; Applies = { $X.IsDC }; Tokens = @('StrongCertificateBindingEnforcement')
       Fix = 'Patch. Kdc StrongCertificateBindingEnforcement=2 once clients are patched'
       Eval = { param($S)
           if (-not $X.AdcsInForest) { return (New-Ok 'no enterprise CA in the forest') }
           if (-not (Test-Patched '2022-05-10')) { return (New-Vuln 'enterprise CA exists and the DC is unpatched since May 2022') }
           if ((Get-SReg $S 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement') -eq 0) { return (New-Risk 'patched but StrongCertificateBindingEnforcement=0 (binding checks off)') }
           New-Ok 'patched' } }
    @{ Id = 'MS14-068'; Cve = 'MS14-068'; Name = 'MS14-068 (forged Kerberos PAC)'; Applies = { $X.IsDC -and $X.Build -le 9600 }; Tokens = @()
       Fix = 'Patch (KB3011780)'
       Eval = { param($S) if (Test-Patched '2014-11-18') { New-Ok 'patched' } else { New-Vuln 'DC on 2012 R2 or older, unpatched since Nov 2014: any user -> Domain Admin' } } }
    @{ Id = 'HiveNightmare'; Cve = 'CVE-2021-36934'; Name = 'HiveNightmare (users read SAM)'; Applies = { $X.Build -ge 17763 }; Tokens = @('SAM', 'config')
       Fix = 'icacls %windir%\system32\config\*.* /inheritance:e ; then delete old shadow copies (vssadmin delete shadows /all) AFTER your backups'
       Eval = { param($S)
           $r = Get-SFact $S 'SamUsersRead'
           if ($null -eq $r) { return (New-Risk 'could not read the SAM file ACL') }
           if ($r -and (Get-SFact $S 'ShadowCopies') -gt 0) { return (New-Vuln 'BUILTIN\Users can read SAM and shadow copies exist: any user dumps local hashes') }
           if ($r) { return (New-Risk 'BUILTIN\Users can read SAM (exploitable once a shadow copy exists)') }
           New-Ok 'SAM not readable by users' } }
    @{ Id = 'Follina'; Cve = 'CVE-2022-30190'; Name = 'Follina (ms-msdt from documents)'; Applies = { $true }; Tokens = @('ms-msdt')
       Fix = 'Patch, or: reg export HKCR\ms-msdt C:\ccdc\backups\ms-msdt.reg ; reg delete HKCR\ms-msdt /f'
       Eval = { param($S)
           if (Test-Patched '2022-06-14') { return (New-Ok 'patched') }
           $h = Get-SReg $S 'HKLM\SOFTWARE\Classes\ms-msdt' '(default)'
           if ($null -ne $h -or $null -ne (Get-SReg $S 'HKLM\SOFTWARE\Classes\ms-msdt' 'URL Protocol')) { return (New-Risk 'ms-msdt handler registered and unpatched (needs someone to open a document)') }
           New-Ok 'ms-msdt handler removed' } }
    @{ Id = 'ProxyShell'; Cve = 'CVE-2021-26855/34473'; Name = 'ProxyLogon / ProxyShell (Exchange)'; Applies = { $X.Exchange }; Tokens = @()
       Fix = 'Install the latest Exchange CU + SU. Meanwhile watch IIS logs for /autodiscover/autodiscover.json?@ and /ecp/ requests'
       Eval = { param($S)
           $inst = Get-SReg $S 'HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' 'MsiInstallPath'
           if (-not $inst) { $inst = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction SilentlyContinue).MsiInstallPath }
           $ex = if ($inst) { Get-Item (Join-Path $inst 'Bin\ExSetup.exe') -ErrorAction SilentlyContinue }
           if (-not $ex) { return (New-Risk 'Exchange present but version unknown: check the CU/SU level by hand') }
           $ver = $ex.VersionInfo.ProductVersion
           if ($ex.LastWriteTime -lt [datetime]'2021-03-02') { return (New-Vuln "Exchange build $ver predates March 2021: ProxyLogon + ProxyShell (pre-auth SYSTEM)") }
           if ($ex.LastWriteTime -lt [datetime]'2021-07-13') { return (New-Vuln "Exchange build $ver predates July 2021: ProxyShell (pre-auth SYSTEM)") }
           New-Risk "Exchange build ${ver}: confirm it is the latest SU (ProxyNotShell and later)" } }
    @{ Id = 'IPv6RCE'; Cve = 'CVE-2024-38063'; Name = 'IPv6 TCP/IP remote code execution'; Applies = { $X.Build -ge 7601 }; Tokens = @('DisabledComponents')
       Fix = 'Patch (Aug 2024+). Workaround: unbind IPv6 on the NIC if nothing scored uses it'
       Eval = { param($S)
           if (Test-Patched '2024-08-13') { return (New-Ok 'patched') }
           $dc = Get-SReg $S 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents'
           if ($dc -and ([int]$dc -band 0xFF) -eq 0xFF) { return (New-Ok 'unpatched, IPv6 disabled') }
           New-Vuln "unpatched since Aug 2024 with IPv6 on: wormable pre-auth RCE (newest update $patchTxt)" } }
    @{ Id = 'LDAPNightmare'; Cve = 'CVE-2024-49112'; Name = 'LDAPNightmare (crash / RCE on DCs)'; Applies = { $X.IsDC }; Tokens = @()
       Fix = 'Patch (Dec 2024+). Watch for DCs rebooting: the public exploit crashes LSASS'
       Eval = { param($S) if (Test-Patched '2024-12-10') { New-Ok 'patched' } else { New-Vuln 'DC unpatched since Dec 2024: unauthenticated LSASS crash (DC reboots) / RCE' } } }
    @{ Id = 'SMBReflect'; Cve = 'CVE-2025-33073'; Name = 'SMB NTLM reflection (user -> SYSTEM)'; Applies = { $true }; Tokens = @('RequireSecuritySignature')
       Fix = 'Patch (June 2025+), or require SMB signing (panel 12 step SMBSigning)'
       Eval = { param($S)
           if (Test-Patched '2025-06-10') { return (New-Ok 'patched') }
           if ((Get-SReg $S $P_SRV 'RequireSecuritySignature') -eq 1) { return (New-Risk 'unpatched, but SMB signing is required (blocks the reflection)') }
           New-Vuln 'unpatched since June 2025 and SMB signing not required: any domain user -> SYSTEM via coerced NTLM' } }
    @{ Id = 'LDAPSign'; Cve = 'relay'; Name = 'LDAP signing + channel binding (DC)'; Applies = { $X.IsDC }; Tokens = @('LDAPServerIntegrity', 'LdapEnforceChannelBinding')
       Fix = 'GPO: Domain controller: LDAP server signing requirements = Require signing; LdapEnforceChannelBinding=2. CAUTION: test scored LDAP binds'
       Eval = { param($S)
           $i = Get-SReg $S $P_NTDS 'LDAPServerIntegrity'; $cb = Get-SReg $S $P_NTDS 'LdapEnforceChannelBinding'
           if ($i -ne 2 -and $cb -ne 2) { return (New-Risk ("LDAP signing not required (LDAPServerIntegrity={0}) and no channel binding: NTLM relay to LDAP (KrbRelayUp, ntlmrelayx)" -f $(if ($null -eq $i) { 'unset' } else { $i }))) }
           if ($i -ne 2) { return (New-Risk 'channel binding on, signing not required') }
           New-Ok 'LDAP signing required' } }
    @{ Id = 'SMBSign'; Cve = 'relay'; Name = 'SMB signing (relay)'; Applies = { $true }; Tokens = @('RequireSecuritySignature', 'SMB')
       Fix = 'Panel 12 step SMBSigning. CAUTION on old clients'
       Eval = { param($S)
           if ((Get-SReg $S $P_SRV 'RequireSecuritySignature') -eq 1) { return (New-Ok 'SMB signing required') }
           if ($X.IsDC) { return (New-Vuln 'DC does not require SMB signing (default is required: someone turned it off)') }
           New-Risk 'SMB signing not required: NTLM relay to this box' } }
    @{ Id = 'NTLMv1'; Cve = 'creds'; Name = 'NTLMv1 / LM hashes'; Applies = { $true }; Tokens = @('LmCompatibilityLevel', 'NoLMHash')
       Fix = 'Set Lsa LmCompatibilityLevel=5 (3 minimum) and NoLMHash=1'
       Eval = { param($S)
           $l = Get-SReg $S $P_LSA 'LmCompatibilityLevel'; $n = Get-SReg $S $P_LSA 'NoLMHash'
           if ($null -ne $l -and [int]$l -lt 3) { return (New-Vuln "LmCompatibilityLevel=${l}: LM/NTLMv1 accepted (hashes cracked in minutes)") }
           if ($n -eq 0) { return (New-Vuln 'NoLMHash=0: LM hashes stored for new passwords') }
           New-Ok ("NTLMv2 only (LmCompatibilityLevel={0})" -f $(if ($null -eq $l) { 'default 3' } else { $l })) } }
    @{ Id = 'Poisoning'; Cve = 'creds'; Name = 'LLMNR / NBT-NS poisoning (Responder)'; Applies = { $true }; Tokens = @('EnableMulticast', 'NetbiosOptions')
       Fix = 'Panel 12 steps LLMNR + NBTNS'
       Eval = { param($S)
           $llmnr = Get-SReg $S 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
           $nbtOn = $false
           if ($S.Kind -eq 'live') { foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) { if ((Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).NetbiosOptions -ne 2) { $nbtOn = $true } } }
           else { foreach ($kk in @($S.RegKeys | Where-Object { $_ -like 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*' })) { if ($S.Reg["$kk|NetbiosOptions"].Data -ne 2) { $nbtOn = $true } } }
           $bad = @(); if ($llmnr -ne 0) { $bad += 'LLMNR on' }; if ($nbtOn) { $bad += 'NBT-NS on' }
           if ($bad) { return (New-Risk (($bad -join ', ') + ': attackers on the LAN capture NTLM hashes')) }
           New-Ok 'LLMNR and NBT-NS off' } }
    @{ Id = 'WDigest'; Cve = 'creds'; Name = 'WDigest cleartext passwords in LSASS'; Applies = { $true }; Tokens = @('UseLogonCredential')
       Fix = 'Panel 12 step WDigest (UseLogonCredential=0)'
       Eval = { param($S)
           $w = Get-SReg $S 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
           if ($w -eq 1) { return (New-Vuln 'UseLogonCredential=1: cleartext passwords in memory (Red Team sets this on purpose)') }
           if ($null -eq $w -and $X.Build -lt 9600) { return (New-Vuln 'not set on 2012/2008 R2 = cleartext caching ON by default') }
           New-Ok 'off' } }
    @{ Id = 'LsaPPL'; Cve = 'creds'; Name = 'LSA protection (RunAsPPL)'; Applies = { $X.Build -ge 9600 }; Tokens = @('RunAsPPL')
       Fix = 'Panel 12 step LsaPPL (needs a reboot to take effect)'
       Eval = { param($S) if ([int](Get-SReg $S $P_LSA 'RunAsPPL') -ge 1) { New-Ok 'on (after reboot)' } else { New-Risk 'off: mimikatz reads LSASS directly' } } }
    @{ Id = 'Anonymous'; Cve = 'enum'; Name = 'Anonymous / null sessions / Guest'; Applies = { $true }; Tokens = @('RestrictAnonymous', 'EveryoneIncludesAnonymous', 'NullSession', 'Guest')
       Fix = 'Lsa RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0, clear NullSessionShares/Pipes; panel 12 steps AnonSAM, EveryoneAnon, Guest'
       Eval = { param($S)
           $bad = @()
           if ((Get-SReg $S $P_LSA 'RestrictAnonymousSAM') -eq 0) { $bad += 'RestrictAnonymousSAM=0' }
           if ((Get-SReg $S $P_LSA 'EveryoneIncludesAnonymous') -eq 1) { $bad += 'EveryoneIncludesAnonymous=1' }
           $ns = @(Get-SReg $S $P_SRV 'NullSessionShares') | Where-Object { $_ }; if ($ns) { $bad += "NullSessionShares=$($ns -join ',')" }
           $np = @(Get-SReg $S $P_SRV 'NullSessionPipes') | Where-Object { $_ }; if ($np -and -not $X.IsDC) { $bad += "NullSessionPipes=$($np -join ',')" }
           if ($X.GuestName -and $S.Users -and $S.Users[$X.GuestName] -and $S.Users[$X.GuestName].Enabled) { $bad += "Guest '$($X.GuestName)' enabled" }
           if ($bad) { return (New-Vuln ($bad -join '; ')) }
           New-Ok 'no anonymous access, Guest off' } }
    @{ Id = 'LocalPrivesc'; Cve = 'privesc'; Name = 'AlwaysInstallElevated / UAC / remote local-admin'; Applies = { $true }; Tokens = @('AlwaysInstallElevated', 'EnableLUA', 'LocalAccountTokenFilterPolicy')
       Fix = 'Delete Installer AlwaysInstallElevated; EnableLUA=1; LocalAccountTokenFilterPolicy=0'
       Eval = { param($S)
           if ((Get-SReg $S 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1) { return (New-Vuln 'AlwaysInstallElevated=1: any user installs an MSI as SYSTEM') }
           if ((Get-SReg $S $P_SYS 'EnableLUA') -eq 0) { return (New-Vuln 'UAC disabled (EnableLUA=0)') }
           if ((Get-SReg $S $P_SYS 'LocalAccountTokenFilterPolicy') -eq 1) { return (New-Risk 'LocalAccountTokenFilterPolicy=1: local admin hashes work remotely (pass-the-hash)') }
           New-Ok 'ok' } }
    @{ Id = 'RdpNla'; Cve = 'access'; Name = 'RDP without NLA'; Applies = { $true }; Tokens = @('UserAuthentication')
       Fix = 'Panel 12 step RdpNla'
       Eval = { param($S)
           if ((Get-SReg $S $P_TS 'fDenyTSConnections') -eq 1) { return (New-Ok 'RDP disabled') }
           if ((Get-SReg $S $P_RDP 'UserAuthentication') -eq 0) { return (New-Risk 'RDP on without NLA: login screen exposed to anyone, BlueKeep-class bugs pre-auth') }
           New-Ok 'NLA required' } }
    @{ Id = 'Defender'; Cve = 'av'; Name = 'Defender real-time + exclusions'; Applies = { [bool](Get-Command Get-MpPreference -ErrorAction SilentlyContinue) }; Tokens = @('Defender', 'DisableRealtimeMonitoring', 'Exclusion')
       Fix = 'Set-MpPreference -DisableRealtimeMonitoring $false ; Remove-MpPreference -ExclusionPath <path>'
       Eval = { param($S)
           if (-not $S.Defender -or $S.Defender.Count -eq 0) { $script:Unknown = $true; return (New-Risk 'Defender settings not readable') }
           if ($S.Defender.DisableRealtimeMonitoring) { return (New-Vuln 'real-time protection OFF') }
           $ex = @($S.Defender.ExclusionPath) + @($S.Defender.ExclusionProcess) | Where-Object { $_ }
           if ($ex) { return (New-Risk ("exclusions: {0} (Red Team hides tools here)" -f ($ex -join ', '))) }
           New-Ok 'real-time on, no exclusions' } }
    @{ Id = 'PatchAge'; Cve = 'all'; Name = 'Patch age (newer CVEs)'; Applies = { $true }; Tokens = @()
       Fix = 'Apply the latest cumulative update if the rules and time allow (snapshot + backup first; it reboots)'
       Eval = { param($S)
           if (-not $X.Patch) { return (New-Risk 'patch level unknown (Get-HotFix empty)') }
           $age = [int]((Get-Date) - $X.Patch).TotalDays
           if ($age -gt 120) { return (New-Vuln "newest update is $age days old ($patchTxt): every CVE fixed since then applies") }
           if ($age -gt 45) { return (New-Risk "newest update is $age days old ($patchTxt)") }
           New-Ok "updated $patchTxt" } }
)

# ---------------------------------------------------------------------------
# Run every check against NOW and BEFORE
# ---------------------------------------------------------------------------
$snap = Import-CcdcSnapshot -Which $Against
if ($snap) { $snap.Kind = 'snap'; Write-Finding -Level INFO -Category 'Snapshot' -Message ("BEFORE column = snapshot '{0}' taken {1}" -f $snap.Meta.Label, $snap.Meta.Time.ToString('yyyy-MM-dd HH:mm')) }
else { Write-Finding -Level YELLOW -Category 'Snapshot' -Message 'No snapshot yet: only the NOW column. Take one (panel S) to track what you fix.' }
Write-Finding -Level INFO -Category 'Patch' -Message ("{0} build {1}, newest installed update: {2}" -f $X.Caption, $X.Build, $patchTxt)
$toolLog = if ($snap) { Get-CcdcToolkitChanges -Since $snap.Meta.Time } else { @() }

$rows = @()
foreach ($c in $checks) {
    if (-not (& $c.Applies)) { continue }
    $script:Unknown = $false
    try { $now = & $c.Eval $Live } catch { $now = @{ S = 'RISK'; Why = "check failed: $($_.Exception.Message)" } }
    $before = $null
    if ($snap) {
        $script:Unknown = $false
        try { $before = & $c.Eval $snap } catch { $before = $null }
        if ($script:Unknown) { $before = @{ S = '?'; Why = 'not in that snapshot' } }
    }
    $change = ''
    if ($before -and $before.S -ne '?') {
        if ($before.S -ne 'OK' -and $now.S -eq 'OK') {
            $by = $null
            foreach ($l in $toolLog) { foreach ($t in $c.Tokens) { if ($l.Text.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $by = $l } } }
            $change = if ($by) { "FIXED by $($by.Script) $($by.Time.ToString('HH:mm'))" } else { 'FIXED (not by the toolkit)' }
        } elseif ($before.S -eq 'OK' -and $now.S -ne 'OK') { $change = 'REGRESSED: was fixed, open again' }
        elseif ($before.S -eq 'VULN' -and $now.S -eq 'RISK') { $change = 'improved' }
    }
    $rows += [pscustomobject]@{ Check = $c.Name; Cve = $c.Cve; Now = $now.S; Before = $(if ($before) { $before.S } else { '-' }); Change = $change; Why = $now.Why; Fix = $c.Fix }

    $lvl = switch ($now.S) { 'VULN' { 'RED' } 'RISK' { 'YELLOW' } default { 'GREEN' } }
    if ($change -like 'REGRESSED*') { $lvl = 'RED' }
    $msg = "{0} [{1}]: {2}" -f $c.Name, $c.Cve, $now.Why
    if ($change) { $msg += "   <- $change" }
    Write-Finding -Level $lvl -Category $c.Id -Message $msg -Detail $(if ($now.S -ne 'OK') { "Fix: $($c.Fix)" } else { '' })
}

# ---------------------------------------------------------------------------
# AD CS ESC1 (live only: lives in AD, not on this box)
# ---------------------------------------------------------------------------
if ($X.AdcsInForest) {
    Write-Section 'AD CS ESC1 templates (any user -> certificate as Domain Admin)'
    try {
        $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfgNc", '(objectClass=pKICertificateTemplate)')
        foreach ($p in 'name', 'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature') { [void]$s.PropertiesToLoad.Add($p) }
        $authEku = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
        $n = 0
        foreach ($t in @($s.FindAll())) {
            $nameFlag = [int]($t.Properties['mspki-certificate-name-flag'] | Select-Object -First 1)
            $ekus = @($t.Properties['pkiextendedkeyusage'])
            $approval = [int]($t.Properties['mspki-enrollment-flag'] | Select-Object -First 1) -band 0x2
            $raSig = [int]($t.Properties['mspki-ra-signature'] | Select-Object -First 1)
            $canAuth = ($ekus.Count -eq 0) -or ($ekus | Where-Object { $authEku -contains $_ })
            if (-not (($nameFlag -band 0x1) -and $canAuth -and -not $approval -and $raSig -eq 0)) { continue }
            $lowPriv = @()
            try {
                foreach ($ace in $t.GetDirectoryEntry().ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $ot = ([string]$ace.ObjectType).ToLower()
                    $enroll = ([string]$ace.ActiveDirectoryRights -match 'GenericAll') -or (([string]$ace.ActiveDirectoryRights -match 'ExtendedRight') -and $ot -in @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2', '00000000-0000-0000-0000-000000000000'))
                    $sid = $ace.IdentityReference.Value
                    if ($enroll -and ($sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') -or $sid -match '-(513|515)$')) {
                        try { $lowPriv += $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $lowPriv += $sid }
                    }
                }
            } catch { $lowPriv = @('(could not read template ACL)') }
            $n++
            $tn = $t.Properties['name'][0]
            if ($lowPriv) { Write-Finding -Level RED -Category 'ESC1' -Message ("Template '{0}': requester supplies the subject, usable for logon, no approval, enrollable by {1}" -f $tn, (($lowPriv | Sort-Object -Unique) -join ', ')) -Detail 'Fix (certtmpl.msc): untick "Supply in the request", require CA manager approval, or remove their Enroll right. PingCastle / Locksmith list ESC1-ESC16 if you have them.' }
            else { Write-Finding -Level YELLOW -Category 'ESC1' -Message "Template '$tn' is ESC1-shaped but only privileged groups can enroll" }
        }
        if ($n -eq 0) { Write-Finding -Level GREEN -Category 'ESC1' -Message 'No ESC1-shaped templates' }
    } catch { Write-Finding -Level INFO -Category 'ESC1' -Message "Could not read templates: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
Write-Section 'Summary'
$fmt = '  {0,-10} {1,-7} {2,-40} {3}'
Write-Host ($fmt -f 'NOW', 'BEFORE', 'CHECK', 'CHANGE') -ForegroundColor White
foreach ($r in ($rows | Sort-Object @{ e = { switch ($_.Now) { 'VULN' { 0 } 'RISK' { 1 } default { 2 } } } }, Check)) {
    $label = switch ($r.Now) { 'VULN' { 'VULNERABLE' } 'RISK' { 'AT RISK' } default { 'OK' } }
    $col = switch ($r.Now) { 'VULN' { 'Red' } 'RISK' { 'Yellow' } default { 'Green' } }
    if ($r.Change -like 'REGRESSED*') { $col = 'Red' }
    Write-Host ($fmt -f $label, $r.Before, $r.Check, $r.Change) -ForegroundColor $col
}
$fixed = @($rows | Where-Object { $_.Change -like 'FIXED*' })
$regr  = @($rows | Where-Object { $_.Change -like 'REGRESSED*' })
$open  = @($rows | Where-Object { $_.Now -ne 'OK' })
Write-Host ''
Write-Host ("  Open now: {0}   Fixed since snapshot: {1}   Regressed: {2}" -f $open.Count, $fixed.Count, $regr.Count) -ForegroundColor White
if ($regr) { Write-Host '  REGRESSED items were fixed and are open again: check LIVE ALERTS / panel W for who changed them.' -ForegroundColor Red }

Complete-Ccdc
