<#
.SYNOPSIS
    Harden-Walkthrough - step-by-step hardening: what each change does, how risky it is, apply or skip, undo any time. CHANGES STATE, reversible.

.DESCRIPTION
    PURPOSE
      Walks through the security changes that matter most on a Windows box
      (and on a domain controller, the Group Policy / AD ones). For each step:
        Now      the current setting
        Change   what it would become
        Why      what attack it stops, in plain English
        Risk     SAFE     no effect on normal services
                 CAUTION  good change, but it CAN break something specific (named)
                 DANGER   evidence on THIS box says it will break something: skip unless you know
      You answer A (apply) or Enter (skip). Settings that are already fine are skipped.

    HOW CHANGES ARE MADE (and undone)
      * Every change records the value it replaced in C:\ccdc\hardening-undo.csv.
      * On a domain controller, registry settings are ALSO written to one GPO named
        "CCDC Hardening" linked to the Domain Controllers OU, so Red Team cannot just
        flip the registry back: Group Policy re-applies it. All our GPO changes live
        in that one GPO and nowhere else.
      * Undo one step or all of them: panel 12 -> 3, or  -Mode Undo [-Step <id>].
        Undo removes the value from the GPO and puts the old local value back.

    WHAT IT READS    registry, services, Directory Service log, AD (Guest, Pre-Windows 2000 group,
                     machine account quota), DNS server zones, audit policy, Defender
    WHAT IT CHANGES  only the steps you apply (each listed with its undo)
    HOW TO UNDO      .\Harden-Walkthrough.ps1 -Mode Undo            (all, newest first)
                     .\Harden-Walkthrough.ps1 -Mode Undo -Step WDigest

    MANUAL EQUIVALENT
      gpmc.msc -> New GPO "CCDC Hardening" -> link to Domain Controllers -> edit the settings named per step
      reg add <key> /v <name> /t REG_DWORD /d <value> /f

.PARAMETER Mode
    Walk (default), List (what was changed), Undo.

.PARAMETER Step
    With -Mode Undo: only these step ids. With -Mode Walk: only these steps.

.EXAMPLE
    .\Harden-Walkthrough.ps1
.EXAMPLE
    .\Harden-Walkthrough.ps1 -Mode Undo -Step LdapSigning
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Walk', 'List', 'Undo')][string]$Mode = 'Walk',
    [string[]]$Step = @(),
    [switch]$Force,
    [string]$ConfigPath
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Harden-Walkthrough' -ReadOnly:($Mode -eq 'List')
$isDC = Test-CcdcIsDC
$journal = 'C:\ccdc\hardening-undo.csv'
$GpoName = 'CCDC Hardening'
$guestFilter = if ($isDC) { "SID LIKE '%-501' AND Domain='$env:USERDOMAIN'" } else { "SID LIKE '%-501' AND LocalAccount=True" }
$script:useGpo = $null
$domainDN = $null; if ($isDC) { try { $domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext } catch { $null = $_ } }

# ---------------------------------------------------------------------------
# Journal (structured: no code is ever read back and executed)
# ---------------------------------------------------------------------------
function Add-Undo([string]$id, [string]$kind, [hashtable]$data) {
    [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Step = $id; Kind = $kind; Data = ($data | ConvertTo-Json -Compress) } |
        Export-Csv -Path $journal -Append -NoTypeInformation -WhatIf:$false
}
function Get-Undo { if (Test-Path $journal) { return @(Import-Csv $journal) } return @() }

# ---------------------------------------------------------------------------
# GPO (DC only): one GPO, linked to the Domain Controllers OU
# ---------------------------------------------------------------------------
function Test-UseGpo {
    if ($null -ne $script:useGpo) { return $script:useGpo }
    $script:useGpo = $false
    if (-not $isDC -or -not (Test-CcdcModule GroupPolicy)) { return $false }
    $a = if ($Force) { 'y' } else { Read-Host "  Also put registry settings in a GPO '$GpoName' linked to Domain Controllers (recommended: it re-applies if someone reverts it) [Y/n]" }
    if ($a -match '^(n|no)$') { return $false }
    try {
        if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) { $null = New-GPO -Name $GpoName -Comment 'Created by the CCDC toolkit hardening walkthrough. Every value here can be undone with Harden-Walkthrough.ps1 -Mode Undo.' -ErrorAction Stop }
        $target = "OU=Domain Controllers,$domainDN"
        $linked = @((Get-GPInheritance -Target $target -ErrorAction SilentlyContinue).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })
        if (-not $linked) { $null = New-GPLink -Name $GpoName -Target $target -LinkEnabled Yes -ErrorAction Stop }
        Write-CcdcLog "GPO $GpoName ready and linked to $target"
        $script:useGpo = $true
    } catch { Write-Host "  GPO not available ($($_.Exception.Message)): applying locally only." -ForegroundColor Yellow }
    return $script:useGpo
}

# ---------------------------------------------------------------------------
# AD permission helpers (DCSync rights, AdminSDHolder). SIDs only: works in any language.
# ---------------------------------------------------------------------------
$script:domSid = $null
if ($isDC -and $domainDN) { try { $script:domSid = (New-Object Security.Principal.SecurityIdentifier(([ADSI]"LDAP://$domainDN").objectSid[0], 0)).Value } catch { $null = $_ } }
$replGuids = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c')
function Test-AdminSid([string]$sid) {
    # SYSTEM, Enterprise DCs, Administrators, and the domain's DCs / RODCs / Domain Admins / Enterprise Admins.
    if ($sid -in 'S-1-5-18', 'S-1-5-9', 'S-1-5-32-544') { return $true }
    return ($script:domSid -and $sid -match ("^{0}-(498|512|516|519|521)$" -f [regex]::Escape($script:domSid)))
}
function Get-BadAces([string]$dn, [string]$mode) {
    # mode 'repl': replication (DCSync) rights or all extended rights held by a non-admin.
    # mode 'write': GenericAll / WriteDacl / WriteOwner / GenericWrite held by a non-admin.
    $de = [ADSI]"LDAP://$dn"
    $out = @()
    foreach ($r in $de.ObjectSecurity.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow' -or (Test-AdminSid $r.IdentityReference.Value)) { continue }
        $g = ([string]$r.ObjectType).ToLower(); $rights = [string]$r.ActiveDirectoryRights
        $bad = if ($mode -eq 'repl') { ($replGuids -contains $g) -or ($rights -match 'ExtendedRight' -and $g -eq '00000000-0000-0000-0000-000000000000') } else { $rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite' }
        if ($bad) { $out += $r }
    }
    return $out
}
function Get-SidName([string]$sid) { try { return (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $sid } }
function Remove-BadAces([string]$id, [string]$dn, [string]$mode) {
    $de = [ADSI]"LDAP://$dn"
    $de.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
    $sec = $de.ObjectSecurity
    foreach ($r in (Get-BadAces $dn $mode)) {
        $sec.RemoveAccessRuleSpecific($r)
        Add-Undo $id 'ace' @{ Dn = $dn; Sid = $r.IdentityReference.Value; Rights = [string]$r.ActiveDirectoryRights; ObjectType = [string]$r.ObjectType; Inheritance = [string]$r.InheritanceType; InheritedObjectType = [string]$r.InheritedObjectType }
    }
    $de.ObjectSecurity = $sec
    $de.CommitChanges()
}
function Get-GppPasswordFiles {
    $dns = try { ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name } catch { $env:USERDNSDOMAIN }
    $root = "\\$dns\SYSVOL\$dns\Policies"
    return @(Get-ChildItem $root -Recurse -Include Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml -ErrorAction SilentlyContinue | Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match 'cpassword="[^"]+' })
}

# ---------------------------------------------------------------------------
# Generic registry step helpers
# ---------------------------------------------------------------------------
function Get-RegNow($s) {
    # A Group Policy value (GpoKey) wins over the local one, so check it first.
    if ($s.GpoKey) { $p = Read-CcdcRegValue -KeyId $s.GpoKey -Name $s.Name; if ($p) { return $p.Data } }
    $v = Read-CcdcRegValue -KeyId $s.Key -Name $s.Name
    if ($s.AltKey -and -not $v) { $v = Read-CcdcRegValue -KeyId $s.AltKey -Name $s.Name }
    if ($v) { return $v.Data } return $null
}
function Set-RegStep($s) {
    $old = Read-CcdcRegValue -KeyId $s.Key -Name $s.Name
    $k = Open-CcdcRegKey -KeyId $s.Key -Writable
    if (-not $k) { throw "cannot open $($s.Key)" }
    try { $k.SetValue($s.Name, [int]$s.Value, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $k.Close() }
    $inGpo = $false
    if (Test-UseGpo) {
        $gk = if ($s.GpoKey) { $s.GpoKey } else { $s.Key }
        Set-GPRegistryValue -Name $GpoName -Key $gk -ValueName $s.Name -Type DWord -Value ([int]$s.Value) -ErrorAction Stop | Out-Null
        if ($s.GpoKey) { $k2 = Open-CcdcRegKey -KeyId $s.GpoKey -Writable; if ($k2) { $k2.SetValue($s.Name, [int]$s.Value, [Microsoft.Win32.RegistryValueKind]::DWord); $k2.Close() } }
        $inGpo = $true
    }
    Add-Undo $s.Id 'reg' @{ Key = $s.Key; Name = $s.Name; OldType = $(if ($old) { $old.Type } else { '' }); OldData = $(if ($old) { $old.Data } else { $null }); GpoKey = $(if ($inGpo) { if ($s.GpoKey) { $s.GpoKey } else { $s.Key } } else { '' }) }
}

# ---------------------------------------------------------------------------
# The steps. Reg steps: Key/Name/Value(+Default = meaning when not set).
# Custom steps: Check -> @{ Ok = bool; Now = 'text' }, Apply -> does it AND calls Add-Undo.
# ---------------------------------------------------------------------------
$LSA = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$SRV = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$steps = @(
    @{ Id = 'WDigest'; Title = 'Stop Windows keeping plain-text passwords in memory (WDigest)'; Risk = 'SAFE'
       Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0; Default = 0
       Why = 'With it on, mimikatz reads logged-on users'' passwords in clear text. Red Team turns it on deliberately.'; RiskText = 'Nothing modern uses it.' }
    @{ Id = 'NoLMHash'; Title = 'Do not store LM password hashes'; Risk = 'SAFE'; Key = $LSA; Name = 'NoLMHash'; Value = 1; Default = 1
       Why = 'LM hashes crack in seconds.'; RiskText = 'None. Takes effect at the next password change.' }
    @{ Id = 'NTLMv2'; Title = 'This box uses only NTLMv2 (never LM / NTLMv1)'; Risk = 'SAFE'; Key = $LSA; Name = 'LmCompatibilityLevel'; Value = 3; Default = 3
       Why = 'LM / NTLMv1 responses captured on the network (Responder) are cracked in minutes. 3 is the Windows default; values below 3 were set on purpose to weaken the box.'
       RiskText = 'Level 3 only changes what THIS box sends, so nothing that logs on to it breaks. (Level 5 would also refuse NTLMv1 from others: stronger, but can lock out old clients, so it is not offered here.)' }
    @{ Id = 'AnonSAM'; Title = 'No anonymous listing of accounts'; Risk = 'SAFE'; Key = $LSA; Name = 'RestrictAnonymousSAM'; Value = 1; Default = 1
       Why = 'Stops anyone enumerating user names without logging in (first step of password spraying).'; RiskText = 'None on modern systems.' }
    @{ Id = 'AnonShares'; Title = 'No anonymous listing of shares'; Risk = 'SAFE'; Key = $LSA; Name = 'RestrictAnonymous'; Value = 1; Default = 0
       Why = 'Null sessions can list shares and accounts.'; RiskText = 'Only NT4-era trusts care.' }
    @{ Id = 'EveryoneAnon'; Title = 'Anonymous users do not get Everyone permissions'; Risk = 'SAFE'; Key = $LSA; Name = 'EveryoneIncludesAnonymous'; Value = 0; Default = 0
       Why = 'With it on, anything shared to Everyone is open without a password.'; RiskText = 'None.' }
    @{ Id = 'LLMNR'; Title = 'Turn off LLMNR name broadcasts'; Risk = 'SAFE'; Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0; Default = 1
       Why = 'Responder answers these broadcasts and captures password hashes from anyone who mistypes a name.'; RiskText = 'Name lookups still use DNS. Nothing in a normal domain needs LLMNR.' }
    @{ Id = 'SMBSigning'; Title = 'Require SMB signing (this box as a file server)'; Risk = 'CAUTION'; Key = $SRV; Name = 'RequireSecuritySignature'; Value = 1; Default = 0
       Why = 'Blocks NTLM relay to this box (attacker forwards a captured login to get in).'; RiskText = 'Very old clients (XP, old Samba, some printers / scanners) cannot connect to shares.'
       RiskDC = 'SAFE'; RiskTextDC = 'Domain controllers require SMB signing by default; every domain member already signs. This only puts the default back.' }
    @{ Id = 'LsaPPL'; Title = 'Protect LSASS (RunAsPPL)'; Risk = 'CAUTION'; Key = $LSA; Name = 'RunAsPPL'; Value = 1; Default = 0
       Why = 'Makes dumping passwords from LSASS memory (mimikatz) much harder.'; RiskText = 'Takes effect after a REBOOT. Rare third-party security / smart-card plugins can fail to load.' }
    @{ Id = 'ScriptBlockLog'; Title = 'Log every PowerShell script that runs'; Risk = 'SAFE'; Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Default = 0
       Why = 'Records what attackers run in PowerShell (event 4104), even obfuscated.'; RiskText = 'None (more log volume).' }
    @{ Id = 'CmdLineLog'; Title = 'Record the command line of every new process'; Risk = 'SAFE'; Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Default = 0
       Why = 'Event 4688 then shows exactly what was run, not just the program name.'; RiskText = 'A password typed on a command line would be logged: never type passwords as arguments.' }
    @{ Id = 'AlwaysElevated'; Title = 'Turn off AlwaysInstallElevated'; Risk = 'SAFE'; Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Value = 0; Default = 0
       Why = 'With it on, any user installs a malicious MSI as SYSTEM.'; RiskText = 'None.' }
    @{ Id = 'RemoteLocalAdmin'; Title = 'Local admin accounts get a filtered token over the network'; Risk = 'CAUTION'; Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LocalAccountTokenFilterPolicy'; Value = 0; Default = 0
       Why = 'Stops pass-the-hash with a LOCAL admin account (same password on many boxes = one hash opens them all).'; RiskText = 'Remote admin tools that log in with a local (not domain) admin account stop working. Domain accounts are unaffected.' }
    @{ Id = 'RdpNla'; Title = 'Require Network Level Authentication for RDP'; Risk = 'CAUTION'; Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'UserAuthentication'; Value = 1; Default = 1
       GpoKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
       Why = 'Users must prove who they are BEFORE the login screen appears: blocks pre-login RDP bugs and slows guessing.'; RiskText = 'Very old RDP clients, and RDP checks that cannot do NLA, fail. Test a new RDP connection after.' }
    @{ Id = 'Zerologon'; Title = 'Enforce secure Netlogon channel (Zerologon)'; Risk = 'SAFE'; DCOnly = $true; Key = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'FullSecureChannelProtection'; Value = 1; Default = 0
       Why = 'Zerologon takes over a domain in seconds from the network.'; RiskText = 'Only matters on an unpatched DC; modern clients are fine.' }
    @{ Id = 'LdapSigning'; Title = 'Require LDAP signing on the DC'; Risk = 'DANGER'; DCOnly = $true; Key = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerIntegrity'; Value = 2; Default = 1
       Why = 'Blocks NTLM relay to LDAP (an attacker turns a captured login into AD changes, e.g. KrbRelayUp).'
       RiskText = 'In our own lab this STOPPED authentication: Linux and web apps that log in through LDAP on port 389 (Gitea, help desks, ticketing) failed immediately. Leave it OFF during a competition.'
       Evidence = {
           # Event 2887 (Directory Service log, once a day): how many unsigned binds the DC accepted.
           $e = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2887 } -MaxEvents 1 -ErrorAction SilentlyContinue
           if ($e -and [int]$e.Properties[0].Value -gt 0) { return "DC logged $($e.Properties[0].Value) unsigned LDAP bind(s) (event 2887, $($e.TimeCreated.ToString('MM-dd HH:mm'))): something on the network WILL break." }
           return $null } }
    @{ Id = 'LdapCB'; Title = 'LDAP channel binding (LDAPS)'; Risk = 'CAUTION'; Recommend = 'skip'; DCOnly = $true; Key = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LdapEnforceChannelBinding'; Value = 1; Default = 0
       Why = 'Blocks relay to LDAPS (636).'; RiskText = 'Same family as LDAP signing: apps using LDAPS with old libraries can fail. Recommended: skip during a competition.' }
)

# Custom steps (services, AD objects, DNS, audit policy, Defender)
$steps += @(
    @{ Id = 'SMBv1'; Title = 'Turn off the SMBv1 server'; Risk = 'CAUTION'
       Why = 'SMBv1 is what EternalBlue / WannaCry exploit for remote SYSTEM.'; RiskText = 'Windows XP / 2003 and very old Linux / printers that only speak SMBv1 lose access to shares.'
       Check = { $on = (Get-CcdcExtraFacts).Smb1Server; @{ Ok = -not $on; Now = $(if ($on) { 'SMBv1 server ON' } else { 'off' }) } }
       Apply = { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Add-Undo 'SMBv1' 'smb1' @{ Old = $true } } }
    @{ Id = 'NBTNS'; Title = 'Turn off NetBIOS name broadcasts on every network card'; Risk = 'CAUTION'
       Why = 'Same as LLMNR: Responder answers NetBIOS broadcasts and captures hashes.'; RiskText = 'Only very old name resolution (WINS, NT4-style browsing) needs it.'
       Check = {
           $on = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions -ne 2 })
           @{ Ok = ($on.Count -eq 0); Now = "$($on.Count) interface(s) with NetBIOS on" } }
       Apply = {
           foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
               $kid = 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $k.PSChildName
               $old = Read-CcdcRegValue -KeyId $kid -Name 'NetbiosOptions'
               if ($old -and [int]$old.Data -eq 2) { continue }
               Set-ItemProperty -Path $k.PSPath -Name NetbiosOptions -Value 2 -Type DWord -ErrorAction Stop
               Add-Undo 'NBTNS' 'reg' @{ Key = $kid; Name = 'NetbiosOptions'; OldType = $(if ($old) { $old.Type } else { '' }); OldData = $(if ($old) { $old.Data } else { $null }); GpoKey = '' }
           } } }
    @{ Id = 'SpoolerDC'; Title = 'Stop and disable the Print Spooler on the DC'; Risk = 'SAFE'; DCOnly = $true
       Why = 'PrintNightmare (SYSTEM on the DC) and PrinterBug (forces the DC to authenticate to an attacker).'; RiskText = 'Nobody should print from a domain controller. Skip only if printing on THIS box is a service you must keep.'
       Check = { $s = Get-WmiObject Win32_Service -Filter "Name='Spooler'" -ErrorAction SilentlyContinue; @{ Ok = (-not $s -or ($s.StartMode -eq 'Disabled' -and $s.State -ne 'Running')); Now = $(if ($s) { "$($s.State), $($s.StartMode)" } else { 'not installed' }) } }
       Apply = {
           $s = Get-WmiObject Win32_Service -Filter "Name='Spooler'"
           Add-Undo 'SpoolerDC' 'svc' @{ Name = 'Spooler'; StartMode = $s.StartMode; State = $s.State }
           Stop-Service Spooler -Force -ErrorAction Stop; Set-Service Spooler -StartupType Disabled -ErrorAction Stop } }
    @{ Id = 'Guest'; Title = 'Disable the built-in Guest account'; Risk = 'SAFE'
       Why = 'Guest lets anyone log on without a password, and wrong user names silently become Guest.'; RiskText = 'None.'
       Check = {
           $g = Get-WmiObject Win32_UserAccount -Filter $guestFilter -ErrorAction SilentlyContinue | Select-Object -First 1
           @{ Ok = (-not $g -or $g.Disabled); Now = $(if ($g) { "$($g.Name) $(if ($g.Disabled) { 'disabled' } else { 'ENABLED' })" } else { 'n/a' }) } }
       Apply = {
           $g = Get-WmiObject Win32_UserAccount -Filter $guestFilter | Select-Object -First 1
           $o = & net.exe user $g.Name /active:no 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
           Add-Undo 'Guest' 'user' @{ Name = $g.Name } } }
    @{ Id = 'PreWin2000'; Title = 'Remove Everyone / Anonymous from "Pre-Windows 2000 Compatible Access"'; Risk = 'CAUTION'; DCOnly = $true
       Why = 'With Everyone or Anonymous in this group, anyone can read most of AD without logging in.'; RiskText = 'Only NT4-era systems and very old apps need anonymous AD reads.'
       Check = {
           $g = [ADSI]'LDAP://<SID=S-1-5-32-554>'
           $bad = @($g.Properties['member'] | Where-Object { $_ -match 'S-1-1-0|S-1-5-7' })
           @{ Ok = ($bad.Count -eq 0); Now = "$($bad.Count) anonymous member(s)" } }
       Apply = {
           $g = [ADSI]'LDAP://<SID=S-1-5-32-554>'
           foreach ($m in @($g.Properties['member'] | Where-Object { $_ -match 'S-1-1-0|S-1-5-7' })) {
               $g.Remove("LDAP://$m"); Add-Undo 'PreWin2000' 'grpmember' @{ Group = 'S-1-5-32-554'; Member = $m }
           } } }
    @{ Id = 'MAQ'; Title = 'Stop normal users adding computers to the domain (MachineAccountQuota = 0)'; Risk = 'SAFE'; DCOnly = $true
       Why = 'Attackers add a computer account to run noPac / RBCD / KrbRelayUp attacks.'; RiskText = 'Joining new machines needs an admin (normal anyway).'
       Check = { $q = [int]([ADSI]"LDAP://$domainDN").Properties['ms-DS-MachineAccountQuota'].Value; @{ Ok = ($q -eq 0); Now = "$q" } }
       Apply = {
           $d = [ADSI]"LDAP://$domainDN"; $old = [int]$d.Properties['ms-DS-MachineAccountQuota'].Value
           $d.Properties['ms-DS-MachineAccountQuota'].Value = 0; $d.CommitChanges()
           Add-Undo 'MAQ' 'maq' @{ Old = $old } } }
    @{ Id = 'DnsPlugin'; Title = 'Remove a DNS ServerLevelPluginDll (DnsAdmins backdoor)'; Risk = 'SAFE'
       Why = 'A plugin DLL here is loaded by the DNS service as SYSTEM on every start: a known DnsAdmins-to-Domain-Admin trick.'; RiskText = 'Legit DNS servers do not use one.'
       Check = { $v = Read-CcdcRegValue -KeyId 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name 'ServerLevelPluginDll'; @{ Ok = (-not $v); Now = $(if ($v) { [string]$v.Data } else { 'none' }) } }
       Apply = {
           $old = Read-CcdcRegValue -KeyId 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name 'ServerLevelPluginDll'
           Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll -ErrorAction Stop
           Add-Undo 'DnsPlugin' 'reg' @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters'; Name = 'ServerLevelPluginDll'; OldType = $old.Type; OldData = $old.Data; GpoKey = '' }
           Write-Host '     Restart DNS when convenient (net stop dns & net start dns) to unload it.' -ForegroundColor Yellow } }
    @{ Id = 'DnsZones'; Title = 'DNS: zone transfers only to the zone''s own name servers, secure dynamic updates only'; Risk = 'CAUTION'
       Why = 'A zone transfer hands an attacker your whole network map; insecure updates let anyone repoint names (e.g. wpad) at themselves.'
       RiskText = 'Real secondary DNS servers keep working (they are listed as name servers). Non-domain machines that register their OWN name dynamically (DHCP clients) stop updating; static records are unaffected.'
       Check = {
           if (-not (Test-CcdcModule DnsServer)) { return @{ Ok = $true; Now = 'no DNS server here' } }
           $z = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })
           $bad = @($z | Where-Object { $_.SecureSecondaries -eq 'TransferAnyServer' -or ($_.IsDsIntegrated -and $_.DynamicUpdate -eq 'NonsecureAndSecure') })
           @{ Ok = ($bad.Count -eq 0); Now = $(if ($bad) { ($bad | ForEach-Object { "$($_.ZoneName) (transfer=$($_.SecureSecondaries), update=$($_.DynamicUpdate))" }) -join '; ' } else { 'ok' }) } }
       Apply = {
           foreach ($z in @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })) {
               $changed = $false
               if ($z.SecureSecondaries -eq 'TransferAnyServer') { Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries TransferToZoneNameServer -ErrorAction Stop; $changed = $true }
               if ($z.IsDsIntegrated -and $z.DynamicUpdate -eq 'NonsecureAndSecure') { Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure -ErrorAction Stop; $changed = $true }
               if ($changed) { Add-Undo 'DnsZones' 'dnszone' @{ Zone = $z.ZoneName; Secondaries = [string]$z.SecureSecondaries; Update = [string]$z.DynamicUpdate } }
           } } }
    @{ Id = 'AuditPolicy'; Title = 'Turn on the audit events that show attacks (logons, accounts, services, tasks)'; Risk = 'SAFE'
       Why = 'Without these, Windows never writes the events that LIVE ALERTS and the Red Team response check read.'; RiskText = 'None (more log volume).'
       Check = {
           $bk = Join-Path $env:TEMP 'ccdc_ap.csv'; $null = & auditpol.exe /backup "/file:$bk" 2>&1
           $rows = @(Import-Csv $bk -ErrorAction SilentlyContinue); Remove-Item $bk -ErrorAction SilentlyContinue
           $off = @(Get-CcdcAuditPolicyPlan | Where-Object { $g = $_.Guid; -not ($rows | Where-Object { $_.'Subcategory GUID' -eq $g -and $_.'Setting Value' -eq '3' }) })
           @{ Ok = ($off.Count -eq 0); Now = "$($off.Count) important subcategories not fully on" } }
       Apply = {
           $bk = Join-Path 'C:\ccdc' ("auditpol_before_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
           $null = & auditpol.exe /backup "/file:$bk" 2>&1
           foreach ($p in (Get-CcdcAuditPolicyPlan)) { $null = & auditpol.exe /set "/subcategory:$($p.Guid)" /success:enable /failure:enable 2>&1 }
           $k = Open-CcdcRegKey -KeyId $LSA -Writable; if ($k) { $k.SetValue('SCENoApplyLegacyAuditPolicy', 1, [Microsoft.Win32.RegistryValueKind]::DWord); $k.Close() }
           Add-Undo 'AuditPolicy' 'auditpol' @{ File = $bk } } }
    @{ Id = 'Defender'; Title = 'Defender on and working (service, policy switches, real-time, exclusions)'; Risk = 'SAFE'
       Why = 'Catches known attack tools (mimikatz, common C2) the moment they land. Attackers turn it off or exclude their folder first.'
       RiskText = 'Opens Repair-Defender: it asks before each fix (and before removing each exclusion). Keep an exclusion only if a service you run needs it.'
       Check = {
           $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
           $p = Get-MpPreference -ErrorAction SilentlyContinue
           $ex = @(@($p.ExclusionPath) + @($p.ExclusionProcess) | Where-Object { $_ })
           $ok = $st -and $st.AMServiceEnabled -and $st.AntivirusEnabled -and $st.RealTimeProtectionEnabled -and -not $ex
           @{ Ok = [bool]$ok; Now = $(if (-not $st) { 'Defender not running / not installed' } elseif (-not $st.RealTimeProtectionEnabled) { 'real-time protection OFF' } elseif ($ex) { "exclusions: $($ex -join ', ')" } else { 'on' }) } }
       Apply = { & (Join-Path $PSScriptRoot 'Repair-Defender.ps1') } }
    @{ Id = 'DCSyncRights'; Title = 'Remove DCSync (replication) rights from accounts that are not DCs or admins'; Risk = 'SAFE'; DCOnly = $true
       Why = 'An account with these rights can download EVERY password hash in the domain (DCSync), including krbtgt.'; RiskText = 'Only domain controllers need them. Exception: a real sync tool (Azure AD Connect "MSOL_" account): skip if you see one.'
       Check = { $b = @(Get-BadAces $domainDN 'repl'); @{ Ok = ($b.Count -eq 0); Now = $(if ($b) { (($b | ForEach-Object { Get-SidName $_.IdentityReference.Value } | Sort-Object -Unique) -join ', ') + ' can DCSync' } else { 'none' }) } }
       Apply = { Remove-BadAces 'DCSyncRights' $domainDN 'repl' } }
    @{ Id = 'AdminSDHolderAcl'; Title = 'Remove extra control rights on AdminSDHolder'; Risk = 'SAFE'; DCOnly = $true
       Why = 'AdminSDHolder''s permissions are copied onto every admin account every hour: control of it = control of every admin.'; RiskText = 'Only admin groups should hold these rights. Fixed admin accounts get the clean permissions at the next hourly refresh.'
       Check = { $b = @(Get-BadAces "CN=AdminSDHolder,CN=System,$domainDN" 'write'); @{ Ok = ($b.Count -eq 0); Now = $(if ($b) { (($b | ForEach-Object { '{0} ({1})' -f (Get-SidName $_.IdentityReference.Value), $_.ActiveDirectoryRights } | Sort-Object -Unique) -join ', ') } else { 'none' }) } }
       Apply = { Remove-BadAces 'AdminSDHolderAcl' "CN=AdminSDHolder,CN=System,$domainDN" 'write' } }
    @{ Id = 'GppPasswords'; Title = 'Blank out passwords stored in Group Policy Preferences (cpassword)'; Risk = 'SAFE'; DCOnly = $true
       Why = 'Any domain user can read SYSVOL and decrypt these passwords instantly (the key is public).'; RiskText = 'The policy keeps doing everything else (group membership etc.); it just stops setting that password. Each file is backed up first. Rotate the accounts listed: their passwords are already exposed.'
       Check = { $f = @(Get-GppPasswordFiles); @{ Ok = ($f.Count -eq 0); Now = $(if ($f) { "$($f.Count) file(s): " + (($f | ForEach-Object { $_.Directory.Parent.Parent.Parent.Name + '\' + $_.Name }) -join ', ') } else { 'none' }) } }
       Apply = {
           $bdir = Join-Path 'C:\ccdc\backups' ("gpp_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')); New-Item -ItemType Directory -Path $bdir -Force | Out-Null
           $i = 0
           foreach ($f in (Get-GppPasswordFiles)) {
               $i++; $bk = Join-Path $bdir ("{0}_{1}" -f $i, $f.Name); Copy-Item $f.FullName $bk -Force
               $txt = Get-Content $f.FullName -Raw
               foreach ($m in [regex]::Matches($txt, '(?i)(userName|accountName|runAs)="([^"]+)"[^>]*cpassword="[^"]+')) { Write-Host "     password exposed for: $($m.Groups[2].Value)  -> rotate it (panel 10)" -ForegroundColor Yellow }
               [IO.File]::WriteAllText($f.FullName, ($txt -replace 'cpassword="[^"]*"', 'cpassword=""'))
               Add-Undo 'GppPasswords' 'file' @{ Path = $f.FullName; Backup = $bk }
           } } }
    @{ Id = 'AccountFlags'; Title = 'Fix risky account flags (AS-REP roastable, password not required, reversible encryption)'; Risk = 'SAFE'; DCOnly = $true
       Why = 'AS-REP roastable accounts hand anyone a crackable hash with no password; "password not required" can mean an empty password.'
       RiskText = 'Opens Harden-AD: it lists each account and asks y/N for each one. It only flips account flags (never passwords); every modern client already does pre-authentication. Undo: the rollback file it prints (C:\ccdc\logs\Harden-AD_*_rollback.ps1).'
       Check = { @{ Ok = $false; Now = 'opens Harden-AD (it lists what it finds)' } }
       Apply = { & (Join-Path $PSScriptRoot 'Harden-AD.ps1') } }
)

# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------
function Undo-Entry($e) {
    $d = $e.Data | ConvertFrom-Json
    switch ($e.Kind) {
        'reg' {
            if ($d.GpoKey -and (Test-CcdcModule GroupPolicy)) { Remove-GPRegistryValue -Name $GpoName -Key $d.GpoKey -ValueName $d.Name -ErrorAction SilentlyContinue | Out-Null }
            $k = Open-CcdcRegKey -KeyId $d.Key -Writable
            if (-not $k) { throw "cannot open $($d.Key)" }
            try {
                if ($d.OldType) {
                    $val = switch ($d.OldType) { 'DWord' { [int]$d.OldData } 'QWord' { [long]$d.OldData } 'MultiString' { [string[]]@($d.OldData) } 'Binary' { [Convert]::FromBase64String($d.OldData) } default { [string]$d.OldData } }
                    $k.SetValue($d.Name, $val, [Microsoft.Win32.RegistryValueKind]$d.OldType)
                } else { $k.DeleteValue($d.Name, $false) }
            } finally { $k.Close() }
        }
        'smb1' { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop }
        'svc' {
            $map = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }
            Set-Service -Name $d.Name -StartupType $map[[string]$d.StartMode] -ErrorAction Stop
            if ($d.State -eq 'Running') { Start-Service -Name $d.Name -ErrorAction Stop }
        }
        'user' { $o = & net.exe user $d.Name /active:yes 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') } }
        'grpmember' { ([ADSI]"LDAP://<SID=$($d.Group)>").Add("LDAP://$($d.Member)") }
        'maq' { $dd = [ADSI]"LDAP://$domainDN"; $dd.Properties['ms-DS-MachineAccountQuota'].Value = [int]$d.Old; $dd.CommitChanges() }
        'dnszone' { Set-DnsServerPrimaryZone -Name $d.Zone -SecureSecondaries $d.Secondaries -ErrorAction Stop; Set-DnsServerPrimaryZone -Name $d.Zone -DynamicUpdate $d.Update -ErrorAction Stop }
        'auditpol' { $o = & auditpol.exe /restore "/file:$($d.File)" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') } }
        'mp' { Set-MpPreference -DisableRealtimeMonitoring ([bool]$d.Old) -ErrorAction Stop }
        'ace' {
            $de = [ADSI]"LDAP://$($d.Dn)"; $de.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
            $sec = $de.ObjectSecurity
            $rule = New-Object DirectoryServices.ActiveDirectoryAccessRule((New-Object Security.Principal.SecurityIdentifier($d.Sid)), [DirectoryServices.ActiveDirectoryRights]$d.Rights, [Security.AccessControl.AccessControlType]::Allow, [guid]$d.ObjectType, [DirectoryServices.ActiveDirectorySecurityInheritance]$d.Inheritance, [guid]$d.InheritedObjectType)
            $sec.AddAccessRule($rule); $de.ObjectSecurity = $sec; $de.CommitChanges()
        }
        'file' { Copy-Item $d.Backup $d.Path -Force -ErrorAction Stop }
        default { throw "unknown undo kind $($e.Kind)" }
    }
}

switch ($Mode) {
    'List' {
        Write-Section 'What the walkthrough changed (newest last)'
        $u = Get-Undo
        if (-not $u) { Write-Finding -Level INFO -Category 'Undo' -Message 'Nothing changed yet.' }
        foreach ($e in $u) { Write-Finding -Level INFO -Category $e.Step -Message ("{0}  {1,-14} {2}" -f $e.Time, $e.Step, $e.Data) }
        if ($isDC -and (Test-CcdcModule GroupPolicy) -and (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) { Write-Finding -Level INFO -Category 'GPO' -Message "GPO '$GpoName' exists (linked to Domain Controllers). gpmc.msc shows its settings." }
    }
    'Undo' {
        Write-Section 'Undo hardening changes (newest first)'
        $u = @(Get-Undo)
        $todo = @($u | Where-Object { -not $Step -or $Step -contains $_.Step })
        [array]::Reverse($todo)
        if (-not $todo) { Write-Finding -Level INFO -Category 'Undo' -Message 'Nothing to undo.' }
        $done = @()
        foreach ($e in $todo) {
            $entry = $e
            if (Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $e.Step -Action "Undo ($($e.Kind)) $($e.Data)" -ScriptBlock { Undo-Entry $entry }) { $done += $e }
        }
        if ($done -and -not $WhatIfPreference) {
            $keep = @($u | Where-Object { $done -notcontains $_ })
            if ($keep) { $keep | Export-Csv $journal -NoTypeInformation -WhatIf:$false } else { Remove-Item $journal -ErrorAction SilentlyContinue -WhatIf:$false }
        }
        Write-Finding -Level INFO -Category 'Undo' -Message 'LSA protection / SMB changes may need a reboot or service restart to fully revert.'
    }
    'Walk' {
        $list = @($steps | Where-Object { (-not $_.DCOnly -or $isDC) -and (-not $Step -or $Step -contains $_.Id) })
        Write-Host ''
        Write-Host ("  HARDENING WALKTHROUGH: {0} steps{1}. A = apply, Enter = skip, Q = stop. Everything here can be undone (panel 12 -> 3)." -f $list.Count, $(if ($isDC) { ' (domain controller)' } else { '' })) -ForegroundColor Cyan
        $i = 0; $applied = 0
        foreach ($s in $list) {
            $i++
            if ($s.Check) { $c = & $s.Check; $ok = $c.Ok; $nowTxt = $c.Now }
            else {
                $cur = Get-RegNow $s
                $eff = if ($null -eq $cur) { $s.Default } else { $cur }
                $ok = ([int]$eff -eq [int]$s.Value)
                $nowTxt = if ($null -eq $cur) { "$($s.Name) not set (= $($s.Default))" } else { "$($s.Name) = $cur" }
            }
            Write-Host ''
            Write-Host ("  STEP {0}/{1}  {2}" -f $i, $list.Count, $s.Title) -ForegroundColor White
            if ($ok) { Write-Host "    Already fine: $nowTxt" -ForegroundColor Green; continue }
            $risk = if ($isDC -and $s.RiskDC) { $s.RiskDC } else { $s.Risk }
            $riskText = if ($isDC -and $s.RiskTextDC) { $s.RiskTextDC } else { $s.RiskText }
            $evidence = if ($s.Evidence) { & $s.Evidence } else { $null }
            if ($evidence) { $risk = 'DANGER' }
            $col = @{ SAFE = 'Green'; CAUTION = 'Yellow'; DANGER = 'Red' }[$risk]
            Write-Host "    Now:    $nowTxt"
            if (-not $s.Check) { Write-Host ("    Change: {0} = {1}  ({2})" -f $s.Name, $s.Value, $s.Key) }
            Write-Host "    Why:    $($s.Why)"
            Write-Host "    Risk:   $risk - $riskText" -ForegroundColor $col
            if ($evidence) { Write-Host "    !! $evidence" -ForegroundColor Red }
            if ($risk -eq 'DANGER') {
                # Never by accident: type YES in capitals.
                $a = Read-Host '    Recommended: SKIP.  Type YES to apply anyway, Enter to skip, Q to stop'
                if ($a -match '^(?i)q$') { break }
                if ($a -cne 'YES') { Write-Host '    skipped' -ForegroundColor DarkGray; continue }
            } else {
                if ($s.Recommend -eq 'skip') { Write-Host '    Recommended: skip.' -ForegroundColor Yellow }
                $a = if ($Force -and $risk -eq 'SAFE') { 'a' } else { Read-Host '    [A]pply  [Enter] skip  [Q]uit' }
                if ($a -match '^(?i)q') { break }
                if ($a -notmatch '^(?i)a') { Write-Host '    skipped' -ForegroundColor DarkGray; continue }
            }
            $st = $s
            $done = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$true -Target $s.Id -Action $s.Title -Undo "Harden-Walkthrough.ps1 -Mode Undo -Step $($s.Id)" -ScriptBlock { if ($st.Apply) { & $st.Apply } else { Set-RegStep $st } }
            if ($done) { $applied++ }
        }
        Write-Host ''
        Write-Finding -Level INFO -Category 'Done' -Message "$applied change(s) applied. Undo: panel 12 -> 3. Re-check: panel 5 (vulns) shows what is now FIXED."
        if ($script:useGpo) { Write-Finding -Level INFO -Category 'GPO' -Message "Registry settings are also in GPO '$GpoName' (Domain Controllers OU). Other DCs pick them up at the next Group Policy refresh (gpupdate /force)." }
    }
}
Complete-Ccdc
