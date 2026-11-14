<#
.SYNOPSIS
    Audit-SecurityPolicy - Group Policy / AD / DNS settings you can turn on WITHOUT breaking scoring. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Checks the security settings that Group Policy (and DNS Manager) control,
      shows the current value, and for every one that is not hardened says:
        SAFE      turn it on now - no effect on scored services in a normal pod
        CAUTION   good setting, but it CAN break something specific; the reason is printed. Test first.
        LEAVE     do not change mid-competition (e.g. account lockout, password expiry)
      plus WHERE to change it yourself:
        GPO   the Group Policy Management Editor path (gpmc.msc on the DC)
        Check a command that shows the current value
        Fix   a command that sets it on this box only (a GPO is better: it re-applies if Red Team reverts it)

    AREAS
      Passwords      reversible encryption (passwords stored decryptable to plain text), complexity,
                     length, LM hashes, WDigest (plain-text passwords in memory), LSA protection
      Anonymous      anonymous enumeration / SID lookups / null sessions, Guest
      Network auth   NTLM level, SMBv1, SMB signing, LLMNR/NetBIOS, WinRM Basic, RDP NLA + encryption,
                     Netlogon secure channel, LDAP signing + channel binding (DC; with a check of who
                     would break), DSRM logon
      Logging        PowerShell script block logging, command line in 4688, audit subcategories
      AD objects     Protected Users, MachineAccountQuota
      DNS server     zone transfers, insecure dynamic updates, query block list (wpad), cache locking,
                     socket pool, ServerLevelPluginDll (DnsAdmins backdoor), rate limiting, audit log

    WHICH GPO DO I EDIT?  (open gpmc.msc on the DC)
      Password / lockout policy for DOMAIN accounts -> only works in a GPO linked at the DOMAIN root
                                                       ("Default Domain Policy")
      DC-only settings (LDAP signing, Netlogon...)    -> "Default Domain Controllers Policy"
      Member servers / workstations                    -> a GPO linked to their OU (or gpedit.msc / secpol.msc on the box)
      After editing:  gpupdate /force  on the target, then re-run this script.
      Settings under "MS Security Guide" need SecGuide.admx (Microsoft Security Compliance Toolkit)
      in the PolicyDefinitions folder; without it, set the registry value with
      GPO > Preferences > Windows Settings > Registry.

    WHAT IT READS    registry, secedit export (deleted right after), LDAP (domain policy, users, FGPPs),
                     DNS server settings, Directory Service event log
    WHAT IT CHANGES  nothing (own log + optional -OutFile report)
    HOW TO UNDO      nothing to undo

    MANUAL EQUIVALENT
      secedit /export /cfg C:\ccdc\secpol.inf /areas SECURITYPOLICY   (then read it)
      gpresult /h C:\ccdc\gpresult.html                                (which GPO set what)
      Get-ADDefaultDomainPasswordPolicy
      Get-DnsServerZone | select ZoneName,SecureSecondaries,DynamicUpdate

.PARAMETER Reference
    Do not scan. Write every check (setting, safety, GPO path, check + fix commands) as a Markdown
    table to -Reference <path>. Works on any OS. docs\security-policy-reference.md is made this way.

.EXAMPLE
    .\Audit-SecurityPolicy.ps1 -OutFile C:\ccdc\reports\secpolicy.txt
.EXAMPLE
    .\Audit-SecurityPolicy.ps1 -Reference .\docs\security-policy-reference.md
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$ConfigPath,
    [string]$Reference
)

# GPO path prefixes (Group Policy Management Editor), kept short so lines fit.
$SO  = 'Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > '
$PP  = 'Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > '
$LP  = 'Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > '
$AT  = 'Computer Configuration > Policies > Administrative Templates > '
$SG  = 'Computer Configuration > Policies > Administrative Templates > MS Security Guide > '
$RDS = 'Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > '
$LSA = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$LMS = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$LMW = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$POL = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$RDP = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$NTDS = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$NETL = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$DNSP = 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters'

# ---------------------------------------------------------------------------
# The catalog. One entry per setting.
#   Area/Title  what it is            Applies  'All' | 'DC' | 'Member' (non-DC) | 'MemberServer' | 'DNS' | 'Domain'
#   Reg/Name    registry value read (Default = effective value when unset)
#   Get         scriptblock returning the value (used instead of Reg)
#   Multi       Get returns objects {Target; Value; Ok} - one finding each
#   Test        scriptblock param($v) -> $true when hardened
#   Want        the hardened value, in words
#   Safety      SAFE | CAUTION | LEAVE        Bad  RED | YELLOW (level when not hardened)
#   Why         what it protects          Breaks   what it can break (CAUTION/LEAVE)
#   Gpo         where to set it           Check/Fix  manual commands
# ---------------------------------------------------------------------------
$catalog = @(
    # ===== Passwords: how they are stored =====
    @{ Area = 'Passwords'; Title = 'Domain policy: store passwords using reversible encryption'; Applies = 'Domain'; Bad = 'RED'; Safety = 'SAFE'
       Get = { if ($null -eq $dom) { $null } elseif ($dom.PwdProperties -band 16) { 'Enabled' } else { 'Disabled' } }; Test = { param($v) $v -eq 'Disabled' }; Want = 'Disabled'
       Why = 'Enabled = the DC keeps every password in a form that decrypts to PLAIN TEXT. A DCSync or ntds.dit theft then hands Red Team the real passwords, not just hashes.'
       Breaks = 'Only CHAP / Digest authentication (RRAS, IAS) - not used in a normal pod. Passwords already stored reversibly stay that way until each is changed: rotate them after fixing.'
       Gpo = 'Default Domain Policy: ' + $PP + 'Store passwords using reversible encryption = Disabled'
       Check = 'Get-ADDefaultDomainPasswordPolicy | fl ReversibleEncryptionEnabled'
       Fix = 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -ReversibleEncryptionEnabled $false' }
    @{ Area = 'Passwords'; Title = 'Accounts flagged "store password using reversible encryption"'; Applies = 'Domain'; Bad = 'RED'; Safety = 'SAFE'; Multi = $true
       Get = { Get-LdapList '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' | ForEach-Object { [pscustomobject]@{ Target = $_; Value = 'reversible encryption ON'; Ok = $false } } }
       Want = 'none'
       Why = 'Same as above but per account: these users'' passwords are recoverable in plain text from AD.'
       Breaks = 'Nothing. The flag only takes effect at the next password change, so reset the password after clearing it.'
       Gpo = 'Not a GPO: Active Directory Users and Computers > user > Account tab > Account options > untick "Store password using reversible encryption"'
       Check = "Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq `$true'"
       Fix = 'Set-ADUser <user> -AllowReversiblePasswordEncryption $false   (then reset its password)' }
    @{ Area = 'Passwords'; Title = 'Fine-grained password policies with reversible encryption'; Applies = 'Domain'; Bad = 'RED'; Safety = 'SAFE'; Multi = $true
       Get = { Get-LdapList '(&(objectClass=msDS-PasswordSettings)(msDS-PasswordReversibleEncryptionEnabled=TRUE))' 'name' | ForEach-Object { [pscustomobject]@{ Target = $_; Value = 'reversible encryption ON'; Ok = $false } } }
       Want = 'none'
       Why = 'A fine-grained policy (PSO) overrides the domain policy for its members - Red Team can add one quietly.'
       Breaks = 'Nothing in a normal pod.'
       Gpo = 'Not a GPO: Active Directory Administrative Center (dsac.exe) > <domain> > System > Password Settings Container'
       Check = 'Get-ADFineGrainedPasswordPolicy -Filter * | fl Name,ReversibleEncryptionEnabled,AppliesTo'
       Fix = 'Set-ADFineGrainedPasswordPolicy <name> -ReversibleEncryptionEnabled $false' }
    @{ Area = 'Passwords'; Title = 'Domain policy: password complexity'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { if ($null -eq $dom) { $null } elseif ($dom.PwdProperties -band 1) { 'Enabled' } else { 'Disabled' } }; Test = { param($v) $v -eq 'Enabled' }; Want = 'Enabled'
       Why = 'Blocks trivial passwords on every future change.'
       Breaks = 'Nothing existing - applies only to NEW passwords. Your PCR passwords for scored users must then be complex.'
       Gpo = 'Default Domain Policy: ' + $PP + 'Password must meet complexity requirements = Enabled'
       Check = 'Get-ADDefaultDomainPasswordPolicy | fl ComplexityEnabled'
       Fix = 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -ComplexityEnabled $true' }
    @{ Area = 'Passwords'; Title = 'Domain policy: minimum password length'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { if ($null -eq $dom) { $null } else { $dom.MinPwdLength } }; Test = { param($v) [int]$v -ge 12 }; Want = '12 or more'
       Why = 'Short passwords fall to spraying and offline cracking of roasted tickets.'
       Breaks = 'Nothing existing - applies at the next change. Rotate-Passwords generates 16 characters.'
       Gpo = 'Default Domain Policy: ' + $PP + 'Minimum password length = 12'
       Check = 'net accounts /domain'
       Fix = 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -MinPasswordLength 12' }
    @{ Area = 'Passwords'; Title = 'Domain policy: account lockout threshold'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'LEAVE'
       Get = { if ($null -eq $dom) { $null } else { $dom.LockoutThreshold } }; Test = { param($v) [int]$v -eq 0 -or [int]$v -ge 10 }; Want = '0 (off) or 10+'
       Why = 'A low threshold sounds safe, but Red Team can spray wrong passwords at SCORED accounts and lock them out - taking your service checks down.'
       Breaks = 'A threshold below 10 lets Red Team lock out scored users at will.'
       Gpo = 'Default Domain Policy: ' + $LP + 'Account lockout threshold (0, or 10+ with a 5-15 minute duration)'
       Check = 'net accounts /domain'
       Fix = 'Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -LockoutThreshold 0' }
    @{ Area = 'Passwords'; Title = 'Domain policy: maximum password age'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'LEAVE'
       Get = { if ($null -eq $dom) { $null } elseif ($dom.MaxPwdAgeDays -eq 0) { 'never' } else { "$($dom.MaxPwdAgeDays) days" } }; Test = { param($v) $v -eq 'never' -or [int]($v -replace '\D') -ge 30 }; Want = 'never, or 30+ days'
       Why = 'A short max age can expire scored accounts DURING the event, and the scoring engine cannot answer "password expired".'
       Breaks = 'Do not shorten it mid-competition.'
       Gpo = 'Default Domain Policy: ' + $PP + 'Maximum password age'
       Check = 'net accounts /domain'
       Fix = '(leave as is)' }
    @{ Area = 'Passwords'; Title = 'Local policy: store passwords using reversible encryption'; Applies = 'Member'; Bad = 'RED'; Safety = 'SAFE'
       Get = { Get-Sec 'ClearTextPassword' }; Test = { param($v) [int]$v -eq 0 }; Want = '0 (Disabled)'
       Why = 'Same as the domain setting, for LOCAL accounts (Administrator on fernbank/fossil).'
       Breaks = 'Nothing.'
       Gpo = $PP + 'Store passwords using reversible encryption = Disabled   (or secpol.msc on the box)'
       Check = 'secedit /export /cfg C:\ccdc\sec.inf /areas SECURITYPOLICY ; findstr ClearTextPassword C:\ccdc\sec.inf'
       Fix = 'secpol.msc > Account Policies > Password Policy > Store passwords using reversible encryption > Disabled' }
    @{ Area = 'Passwords'; Title = 'Local policy: password complexity'; Applies = 'Member'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { Get-Sec 'PasswordComplexity' }; Test = { param($v) [int]$v -eq 1 }; Want = '1 (Enabled)'
       Why = 'Local accounts get trivial passwords otherwise.'; Breaks = 'Nothing existing.'
       Gpo = $PP + 'Password must meet complexity requirements = Enabled'
       Check = 'findstr PasswordComplexity C:\ccdc\sec.inf (after secedit /export)'
       Fix = 'secpol.msc > Account Policies > Password Policy > Password must meet complexity requirements > Enabled' }
    @{ Area = 'Passwords'; Title = 'Local policy: minimum password length'; Applies = 'Member'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { Get-Sec 'MinimumPasswordLength' }; Test = { param($v) [int]$v -ge 12 }; Want = '12 or more'
       Why = 'Short local admin passwords get sprayed / cracked.'; Breaks = 'Nothing existing.'
       Gpo = $PP + 'Minimum password length = 12'
       Check = 'net accounts'
       Fix = 'net accounts /minpwlen:12' }
    @{ Area = 'Passwords'; Title = 'LM hashes not stored'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'NoLMHash'; Default = 1; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'LM hashes crack in seconds. Off by default since 2008 - a 0 here was set on purpose.'
       Breaks = 'Nothing modern. Existing LM hashes disappear as passwords change.'
       Gpo = $SO + 'Network security: Do not store LAN Manager hash value on next password change = Enabled'
       Check = "reg query $LSA /v NoLMHash"
       Fix = "reg add $LSA /v NoLMHash /t REG_DWORD /d 1 /f" }
    @{ Area = 'Passwords'; Title = 'WDigest: no plain-text passwords in LSASS memory'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = '1 = every logged-on user''s password sits in memory in CLEAR TEXT for mimikatz. Red Team flips this to 1 and waits for you to log in.'
       Breaks = 'Nothing (only ancient Digest-auth web apps).'
       Gpo = $SG + 'WDigest Authentication = Disabled   (needs SecGuide.admx; or GPO Preferences > Registry)'
       Check = 'reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential'
       Fix = 'reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f' }
    @{ Area = 'Passwords'; Title = 'LSA protection (RunAsPPL)'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'CAUTION'
       Reg = $LSA; Name = 'RunAsPPL'; Default = 0; Test = { param($v) [int]$v -ge 1 }; Want = '1'
       Why = 'Stops most tools from reading LSASS memory (credential dumping).'
       Breaks = 'Needs a REBOOT to take effect. Can stop third-party LSA plugins / some AV from loading. Plan the reboot with the captain.'
       Gpo = $AT + 'System > Local Security Authority > Configure LSASS to run as a protected process (2022/Win11 ADMX; older: registry)'
       Check = "reg query $LSA /v RunAsPPL"
       Fix = "reg add $LSA /v RunAsPPL /t REG_DWORD /d 1 /f   (then reboot when allowed)" }
    @{ Area = 'Passwords'; Title = 'Domain credentials cached for offline logon (member servers)'; Applies = 'MemberServer'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'CachedLogonsCount'; Default = 10; Test = { param($v) [int]$v -le 2 }; Want = '2 or less'
       Why = 'Cached hashes (DCC2) of every admin who ever logged on can be dumped and cracked.'
       Breaks = 'Domain logons fail if the DC is down. Fine on servers; DO NOT lower it on workstations (fossil) - scored RDP logins rely on it when trex is unreachable.'
       Gpo = $SO + 'Interactive logon: Number of previous logons to cache = 2'
       Check = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount'
       Fix = 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 2 /f' }
    @{ Area = 'Passwords'; Title = 'No stored credentials for network authentication'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'CAUTION'
       Reg = $LSA; Name = 'DisableDomainCreds'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Credential Manager cannot keep domain passwords Red Team could harvest.'
       Breaks = 'Saved RDP / mapped-drive credentials, and creating scheduled tasks that "run whether user is logged on or not" with a domain account. Check scored tasks first.'
       Gpo = $SO + 'Network access: Do not allow storage of passwords and credentials for network authentication = Enabled'
       Check = "reg query $LSA /v DisableDomainCreds"
       Fix = "reg add $LSA /v DisableDomainCreds /t REG_DWORD /d 1 /f" }
    @{ Area = 'Passwords'; Title = 'Blank-password accounts limited to console'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'LimitBlankPasswordUse'; Default = 1; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'With 0, an account with an empty password can log on over the network.'
       Breaks = 'Nothing.'
       Gpo = $SO + 'Accounts: Limit local account use of blank passwords to console logon only = Enabled'
       Check = "reg query $LSA /v LimitBlankPasswordUse"
       Fix = "reg add $LSA /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f" }
    @{ Area = 'Passwords'; Title = 'UAC remote restrictions for local accounts (pass-the-hash)'; Applies = 'Member'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $POL; Name = 'LocalAccountTokenFilterPolicy'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = '1 = a stolen LOCAL Administrator hash gives full admin over SMB/WinRM on every box with the same password.'
       Breaks = 'Remote admin (PsExec / WinRM / C$) with a LOCAL account. Domain accounts are unaffected.'
       Gpo = $SG + 'Apply UAC restrictions to local accounts on network logons = Enabled   (needs SecGuide.admx)'
       Check = "reg query $POL /v LocalAccountTokenFilterPolicy"
       Fix = "reg delete $POL /v LocalAccountTokenFilterPolicy /f" }
    @{ Area = 'Passwords'; Title = 'UAC enabled'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $POL; Name = 'EnableLUA'; Default = 1; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'UAC off = every admin process runs fully elevated, and remote local-admin restrictions are gone.'
       Breaks = 'Nothing (turning it back on needs a reboot).'
       Gpo = $SO + 'User Account Control: Run all administrators in Admin Approval Mode = Enabled'
       Check = "reg query $POL /v EnableLUA"
       Fix = "reg add $POL /v EnableLUA /t REG_DWORD /d 1 /f   (reboot)" }
    @{ Area = 'Passwords'; Title = 'AlwaysInstallElevated off'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = '1 = any user can install an .msi as SYSTEM (instant privilege escalation).'
       Breaks = 'Nothing.'
       Gpo = $AT + 'Windows Components > Windows Installer > Always install with elevated privileges = Disabled'
       Check = 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated'
       Fix = 'reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f' }

    # ===== Anonymous access =====
    @{ Area = 'Anonymous'; Title = 'No anonymous enumeration of SAM accounts'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'RestrictAnonymousSAM'; Default = 1; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Stops anyone listing user names without logging in (first step of password spraying).'; Breaks = 'Nothing modern.'
       Gpo = $SO + 'Network access: Do not allow anonymous enumeration of SAM accounts = Enabled'
       Check = "reg query $LSA /v RestrictAnonymousSAM"; Fix = "reg add $LSA /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f" }
    @{ Area = 'Anonymous'; Title = 'No anonymous enumeration of accounts AND shares'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $LSA; Name = 'RestrictAnonymous'; Default = 0; Test = { param($v) [int]$v -ge 1 }; Want = '1'
       Why = 'Also hides share names and more from anonymous (null session) users.'; Breaks = 'Only pre-2000 trusts / NT4-era tools.'
       Gpo = $SO + 'Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled'
       Check = "reg query $LSA /v RestrictAnonymous"; Fix = "reg add $LSA /v RestrictAnonymous /t REG_DWORD /d 1 /f" }
    @{ Area = 'Anonymous'; Title = 'Everyone permissions do not apply to anonymous'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'EveryoneIncludesAnonymous'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = '1 = anything shared to Everyone is readable without logging in.'; Breaks = 'Nothing.'
       Gpo = $SO + 'Network access: Let Everyone permissions apply to anonymous users = Disabled'
       Check = "reg query $LSA /v EveryoneIncludesAnonymous"; Fix = "reg add $LSA /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f" }
    @{ Area = 'Anonymous'; Title = 'No anonymous SID/name translation'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { Get-Sec 'LSAAnonymousNameLookup' }; Test = { param($v) [int]$v -eq 0 }; Want = '0 (Disabled)'
       Why = 'Anonymous users can turn SIDs into names (finds the renamed Administrator, RID 500).'; Breaks = 'Nothing modern.'
       Gpo = $SO + 'Network access: Allow anonymous SID/Name translation = Disabled'
       Check = 'findstr LSAAnonymousNameLookup C:\ccdc\sec.inf (after secedit /export)'
       Fix = 'secpol.msc > Local Policies > Security Options > Network access: Allow anonymous SID/Name translation > Disabled' }
    @{ Area = 'Anonymous'; Title = 'No LocalSystem NULL session fallback'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = "$LSA\MSV1_0"; Name = 'allownullsessionfallback'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'Prevents services falling back to unauthenticated NULL sessions.'; Breaks = 'Nothing modern.'
       Gpo = $SO + 'Network security: Allow LocalSystem NULL session fallback = Disabled'
       Check = "reg query $LSA\MSV1_0 /v allownullsessionfallback"; Fix = "reg add $LSA\MSV1_0 /v allownullsessionfallback /t REG_DWORD /d 0 /f" }
    @{ Area = 'Anonymous'; Title = 'Guest account disabled'; Applies = 'Member'; Bad = 'RED'; Safety = 'SAFE'
       Get = { Get-Sec 'EnableGuestAccount' }; Test = { param($v) [int]$v -eq 0 }; Want = '0 (Disabled)'
       Why = 'Guest = a passwordless way in.'; Breaks = 'Nothing.'
       Gpo = $SO + 'Accounts: Guest account status = Disabled'
       Check = 'net user guest'; Fix = 'net user guest /active:no' }

    # ===== Network authentication =====
    @{ Area = 'Network'; Title = 'NTLM level: NTLMv2 only'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'LmCompatibilityLevel'; Default = 3; Test = { param($v) [int]$v -ge 3 }; Want = '3 (5 = refuse LM/NTLMv1 too: CAUTION, test old clients)'
       Why = 'Below 3 the box sends LM/NTLMv1 responses, which are cracked or relayed trivially.'; Breaks = 'Nothing modern at 3.'
       Gpo = $SO + 'Network security: LAN Manager authentication level = Send NTLMv2 response only'
       Check = "reg query $LSA /v LmCompatibilityLevel"; Fix = "reg add $LSA /v LmCompatibilityLevel /t REG_DWORD /d 3 /f" }
    @{ Area = 'Network'; Title = 'SMBv1 server disabled'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LMS; Name = 'SMB1'; Default = 1; Get = { $c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; if ($c) { [int][bool]$c.EnableSMB1Protocol } else { Get-RegEffective $LMS 'SMB1' 1 } }
       Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'SMBv1 = EternalBlue / WannaCry class attacks.'; Breaks = 'Only XP/2003-era clients and very old printers/NAS.'
       Gpo = $SG + 'Configure SMB v1 server = Disabled   (needs SecGuide.admx)'
       Check = 'Get-SmbServerConfiguration | fl EnableSMB1Protocol'; Fix = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    @{ Area = 'Network'; Title = 'SMB server signing required'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $LMS; Name = 'RequireSecuritySignature'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Blocks NTLM relay to this box''s SMB (a top Red Team move with Responder).'; Breaks = 'Only clients that cannot sign (none modern; Samba signs).'
       Gpo = $SO + 'Microsoft network server: Digitally sign communications (always) = Enabled'
       Check = 'Get-SmbServerConfiguration | fl RequireSecuritySignature'; Fix = 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' }
    @{ Area = 'Network'; Title = 'SMB client signing required'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'CAUTION'
       Reg = $LMW; Name = 'RequireSecuritySignature'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'This box refuses unsigned SMB servers (stops relay/spoofed shares).'
       Breaks = 'Connections FROM this box to SMB servers that do not sign (old NAS / misconfigured Samba). Check what this box mounts.'
       Gpo = $SO + 'Microsoft network client: Digitally sign communications (always) = Enabled'
       Check = "reg query $LMW /v RequireSecuritySignature"; Fix = 'Set-SmbClientConfiguration -RequireSecuritySignature $true -Force' }
    @{ Area = 'Network'; Title = 'LLMNR off'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Default = 1; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'Responder answers LLMNR broadcasts and collects password hashes.'; Breaks = 'Nothing when DNS works (it does: trex).'
       Gpo = $AT + 'Network > DNS Client > Turn off multicast name resolution = Enabled'
       Check = 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast'
       Fix = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f' }
    @{ Area = 'Network'; Title = 'NetBIOS name resolution off (all interfaces)'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { $v = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty $_.PSPath).NetbiosOptions }); if (-not $v) { $null } elseif (-not ($v | Where-Object { $_ -ne 2 })) { 'off everywhere' } else { 'on (values: ' + (($v | Sort-Object -Unique) -join ',') + ')' } }
       Test = { param($v) $v -eq 'off everywhere' }; Want = 'off everywhere (NetbiosOptions=2)'
       Why = 'NBT-NS is the other protocol Responder poisons.'; Breaks = 'Only apps that resolve names via NetBIOS instead of DNS (rare).'
       Gpo = $AT + 'Network > DNS Client > Configure NetBIOS settings = Disable NetBIOS name resolution (2022/Win11 ADMX); older: NIC > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP'
       Check = 'wmic nicconfig get Description,TcpipNetbiosOptions'; Fix = 'harden\Harden-Baseline.ps1 -Only DisableNBTNS' }
    @{ Area = 'Network'; Title = 'WinRM: Basic auth off'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service'; Name = 'auth_basic'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'Basic auth sends passwords base64-encoded (plain text) over HTTP 5985.'; Breaks = 'Only scripts that log in with -Authentication Basic.'
       Gpo = $AT + 'Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow Basic authentication = Disabled'
       Check = 'winrm get winrm/config/service/auth'; Fix = 'winrm set winrm/config/service/auth @{Basic="false"}' }
    @{ Area = 'Network'; Title = 'WinRM: unencrypted traffic off'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service'; Name = 'allow_unencrypted'; Default = 0; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'Unencrypted WinRM exposes commands and credentials on the wire.'; Breaks = 'Nothing (Kerberos/NTLM WinRM encrypts by itself).'
       Gpo = $AT + 'Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow unencrypted traffic = Disabled'
       Check = 'winrm get winrm/config/service'; Fix = 'winrm set winrm/config/service @{AllowUnencrypted="false"}' }
    @{ Area = 'Network'; Title = 'RDP: Network Level Authentication required'; Applies = 'RDP'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $RDP; Name = 'UserAuthentication'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Users must authenticate BEFORE the login screen: blocks pre-auth RDP bugs and sticky-keys backdoors.'; Breaks = 'Only pre-2008 RDP clients. Test a fresh login + the scoreboard after.'
       Gpo = $RDS + 'Require user authentication for remote connections by using Network Level Authentication = Enabled'
       Check = "reg query `"$RDP`" /v UserAuthentication"; Fix = 'harden\Harden-Baseline.ps1 -Only RequireRdpNla' }
    @{ Area = 'Network'; Title = 'RDP: encryption level High'; Applies = 'RDP'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { $p = Get-RegEffective 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel' $null; if ($null -ne $p) { $p } else { Get-RegEffective $RDP 'MinEncryptionLevel' 2 } }
       Test = { param($v) [int]$v -ge 3 }; Want = '3 (High)'
       Why = 'Forces 128-bit encryption for RDP sessions.'; Breaks = 'Nothing modern.'
       Gpo = $RDS + 'Set client connection encryption level = High Level'
       Check = "reg query `"$RDP`" /v MinEncryptionLevel"; Fix = "reg add `"$RDP`" /v MinEncryptionLevel /t REG_DWORD /d 3 /f" }
    @{ Area = 'Network'; Title = 'Netlogon secure channel always signed/sealed'; Applies = 'All'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $NETL; Name = 'RequireSignOrSeal'; Default = 1; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Protects the machine <-> DC channel from tampering.'; Breaks = 'Nothing (default is 1).'
       Gpo = $SO + 'Domain member: Digitally encrypt or sign secure channel data (always) = Enabled'
       Check = "reg query $NETL /v RequireSignOrSeal"; Fix = "reg add $NETL /v RequireSignOrSeal /t REG_DWORD /d 1 /f" }
    @{ Area = 'Network'; Title = 'DC: Zerologon enforcement (FullSecureChannelProtection)'; Applies = 'DC'; Bad = 'RED'; Safety = 'SAFE'
       Get = { $f = Get-RegEffective $NETL 'FullSecureChannelProtection' 0
               $hf = (Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn
               if ([int]$f -eq 1) { '1' } elseif ($hf -and $hf -ge [datetime]'2021-02-09') { "enforced by updates (newest patch $($hf.ToString('yyyy-MM-dd')))" } else { "0 and no update since Feb 2021" } }
       Test = { param($v) $v -notmatch '^0' }; Want = '1 (or any update from Feb 2021 on, which enforces it)'
       Why = 'Refuses vulnerable Netlogon connections (CVE-2020-1472: domain takeover in seconds).'; Breaks = 'Only unpatched non-Windows devices using Netlogon. Patched Samba is fine.'
       Gpo = 'Default Domain Controllers Policy: ' + $SO + 'Domain controller: Allow vulnerable Netlogon secure channel connections = (leave Not Defined / empty)'
       Check = "reg query $NETL /v FullSecureChannelProtection"; Fix = "reg add $NETL /v FullSecureChannelProtection /t REG_DWORD /d 1 /f" }
    @{ Area = 'Network'; Title = 'DC: LDAP signing required'; Applies = 'DC'; Bad = 'YELLOW'; Safety = 'CAUTION'
       Get = { $v = Get-RegEffective $NTDS 'LDAPServerIntegrity' 1; $u = Get-UnsignedBindInfo; "$v  ($u)" }
       Test = { param($v) $v -match '^2\b' }; Want = '2 (Require signing)'
       Why = 'Unsigned LDAP binds can be relayed / tampered with (NTLM relay to LDAP = create admin, set RBCD).'
       Breaks = 'Any app doing a SIMPLE bind on ldap://389 without StartTLS - e.g. Keycloak federation on hellcreek. Only switch if the unsigned-bind count in brackets is 0, or move Keycloak to ldaps://636 first.'
       Gpo = 'Default Domain Controllers Policy: ' + $SO + 'Domain controller: LDAP server signing requirements = Require signing'
       Check = "Get-WinEvent -LogName 'Directory Service' -FilterXPath '*[System[EventID=2887]]' -MaxEvents 1 | fl Message   (count of unsigned binds per 24h)"
       Fix = "reg add $NTDS /v LDAPServerIntegrity /t REG_DWORD /d 2 /f" }
    @{ Area = 'Network'; Title = 'DC: LDAP channel binding'; Applies = 'DC'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $NTDS; Name = 'LdapEnforceChannelBinding'; Default = 0; Test = { param($v) [int]$v -ge 1 }; Want = '1 (when supported)'
       Why = 'Ties LDAPS sessions to the TLS channel so they cannot be relayed.'
       Breaks = '1 = nothing (only clients that support it are checked). 2 (Always) breaks Java/Keycloak LDAPS - do NOT use 2 here.'
       Gpo = 'Default Domain Controllers Policy: ' + $SO + 'Domain controller: LDAP server channel binding token requirements = When supported'
       Check = "reg query $NTDS /v LdapEnforceChannelBinding"; Fix = "reg add $NTDS /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f" }
    @{ Area = 'Network'; Title = 'DC: DSRM administrator cannot log on over the network'; Applies = 'DC'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $LSA; Name = 'DsrmAdminLogonBehavior'; Default = 0; Test = { param($v) [int]$v -ne 2 }; Want = '0 or unset'
       Why = '2 lets the DSRM (directory restore) admin log on normally - a known persistence trick: its password survives every domain password reset.'
       Breaks = 'Nothing.'
       Gpo = 'Not a GPO setting - registry only'
       Check = "reg query $LSA /v DsrmAdminLogonBehavior"; Fix = "reg delete $LSA /v DsrmAdminLogonBehavior /f   (and reset it: ntdsutil `"set dsrm password`")" }

    # ===== Logging =====
    @{ Area = 'Logging'; Title = 'PowerShell script block logging'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Event 4104 records the actual code Red Team runs, even when obfuscated or encoded.'; Breaks = 'Nothing (log volume only).'
       Gpo = $AT + 'Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled'
       Check = 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Fix = 'logging\Setup-Logging.ps1' }
    @{ Area = 'Logging'; Title = 'Command line in process creation events (4688)'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = "$POL\Audit"; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Shows exactly what was run. (Never put passwords on a command line - they get logged.)'; Breaks = 'Nothing.'
       Gpo = $AT + 'System > Audit Process Creation > Include command line in process creation events = Enabled'
       Check = "reg query $POL\Audit /v ProcessCreationIncludeCmdLine_Enabled"; Fix = 'logging\Setup-Logging.ps1' }
    @{ Area = 'Logging'; Title = 'Advanced audit policy overrides legacy categories'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $LSA; Name = 'SCENoApplyLegacyAuditPolicy'; Default = 0; Test = { param($v) [int]$v -eq 1 }; Want = '1'
       Why = 'Without it, old-style audit settings can silently override the detailed subcategories.'; Breaks = 'Nothing.'
       Gpo = $SO + 'Audit: Force audit policy subcategory settings to override audit policy category settings = Enabled'
       Check = "reg query $LSA /v SCENoApplyLegacyAuditPolicy"; Fix = 'logging\Setup-Logging.ps1 (also sets the subcategories)' }
    @{ Area = 'Logging'; Title = 'Audit: logons, account + group changes, process creation'; Applies = 'All'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { Get-AuditSummary }; Test = { param($v) $v -eq 'all on' }; Want = 'all on'
       Why = 'Without these, 4624/4625/4720/4728/4688 events never happen - you cannot see or report what Red Team did.'; Breaks = 'Nothing (log size: raise Security log to 1 GB).'
       Gpo = 'Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > (Logon/Logoff, Account Management, Detailed Tracking...)'
       Check = 'auditpol /get /category:*'; Fix = 'logging\Setup-Logging.ps1' }

    # ===== Services / AD objects =====
    @{ Area = 'Services'; Title = 'DC: Print Spooler disabled'; Applies = 'DC'; Bad = 'RED'; Safety = 'SAFE'
       Get = { $s = Get-Service Spooler -ErrorAction SilentlyContinue; if (-not $s) { 'not installed' } else { "$($s.Status)/$($s.StartType)" } }
       Test = { param($v) $v -eq 'not installed' -or $v -eq 'Stopped/Disabled' }; Want = 'Stopped/Disabled'
       Why = 'PrintNightmare and "printer bug" coercion (forces the DC to authenticate to Red Team).'; Breaks = 'Printing from the DC (nobody prints from a DC).'
       Gpo = 'Default Domain Controllers Policy: Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Print Spooler = Disabled'
       Check = 'Get-Service Spooler'; Fix = 'harden\Harden-Baseline.ps1 -Only DisableSpoolerOnDC' }
    @{ Area = 'AD'; Title = 'ms-DS-MachineAccountQuota = 0'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { if ($null -eq $dom) { $null } else { $dom.MachineAccountQuota } }; Test = { param($v) [int]$v -eq 0 }; Want = '0'
       Why = 'Default 10 lets ANY domain user create computer accounts - step one of NoPAC and RBCD attacks.'; Breaks = 'Non-admins joining machines to the domain (admins still can).'
       Gpo = 'Not a GPO: ADSI Edit > domain root > Properties > ms-DS-MachineAccountQuota'
       Check = "Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota"; Fix = 'harden\Harden-Baseline.ps1 -Only MachineAccountQuotaZero' }
    @{ Area = 'AD'; Title = 'Human Domain Admins in "Protected Users"'; Applies = 'Domain'; Bad = 'YELLOW'; Safety = 'CAUTION'; Multi = $true
       Get = { Get-ProtectedUsersGap }; Want = 'every human admin account a member'
       Why = 'Protected Users: no NTLM, no cached credentials, no delegation, short Kerberos tickets - stolen admin creds are worth far less.'
       Breaks = 'That account can no longer use NTLM (logons by IP address), delegation or offline logon. NEVER add service, bind (Keycloak) or scored accounts. Add one human admin first and test RDP/WinRM to each box.'
       Gpo = 'Not a GPO: Active Directory Users and Computers > Users > Protected Users > Members'
       Check = 'Get-ADGroupMember "Protected Users"'; Fix = 'Add-ADGroupMember "Protected Users" -Members <human admin>' }

    # ===== DNS server =====
    @{ Area = 'DNS'; Title = 'Zone transfers restricted'; Applies = 'DNS'; Bad = 'RED'; Safety = 'SAFE'; Multi = $true
       Get = { foreach ($z in (Get-DnsZones)) { [pscustomobject]@{ Target = $z.ZoneName; Value = [string]$z.SecureSecondaries; Ok = ([string]$z.SecureSecondaries -ne 'TransferAnyServer') } } }
       Want = 'NoTransfer (or name servers only)'
       Why = 'TransferAnyServer = anyone can download the whole zone: a full map of every host and service.'; Breaks = 'Secondary DNS servers - a pod normally has none.'
       Gpo = 'Not a GPO: DNS Manager (dnsmgmt.msc) > zone > Properties > Zone Transfers'
       Check = 'Get-DnsServerZone | select ZoneName,SecureSecondaries'; Fix = 'Set-DnsServerPrimaryZone -Name <zone> -SecureSecondaries NoTransfer' }
    @{ Area = 'DNS'; Title = 'Dynamic updates secure only'; Applies = 'DNS'; Bad = 'RED'; Safety = 'SAFE'; Multi = $true
       Get = { foreach ($z in (Get-DnsZones)) { [pscustomobject]@{ Target = $z.ZoneName; Value = [string]$z.DynamicUpdate; Ok = ([string]$z.DynamicUpdate -ne 'NonsecureAndSecure') } } }
       Want = 'Secure (AD-integrated zones) or None'
       Why = 'Nonsecure updates let ANYONE register or overwrite records - e.g. point wpad or a scored hostname at Red Team.'
       Breaks = 'Non-domain hosts that register themselves via DDNS. Linux boxes normally have static records - check they still resolve.'
       Gpo = 'Not a GPO: DNS Manager > zone > Properties > General > Dynamic updates = Secure only'
       Check = 'Get-DnsServerZone | select ZoneName,IsDsIntegrated,DynamicUpdate'; Fix = 'Set-DnsServerPrimaryZone -Name <zone> -DynamicUpdate Secure' }
    @{ Area = 'DNS'; Title = 'Global query block list (wpad, isatap) enabled'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { $b = Get-DnsServerGlobalQueryBlockList -ErrorAction SilentlyContinue; if (-not $b) { 'unknown' } elseif ($b.Enable -and ($b.List -contains 'wpad')) { 'on (' + ($b.List -join ',') + ')' } else { 'off or wpad missing' } }
       Test = { param($v) $v -like 'on*' }; Want = 'on, includes wpad'
       Why = 'Stops anyone registering "wpad" to hijack every browser''s proxy settings.'; Breaks = 'Only a real WPAD setup (none in a pod).'
       Gpo = 'Not a GPO: dnscmd / PowerShell only'
       Check = 'Get-DnsServerGlobalQueryBlockList'; Fix = 'Set-DnsServerGlobalQueryBlockList -Enable $true -List wpad,isatap' }
    @{ Area = 'DNS'; Title = 'Cache locking'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { (Get-DnsServerCache -ErrorAction SilentlyContinue).LockingPercent }; Test = { param($v) [int]$v -ge 90 }; Want = '100'
       Why = 'Cached answers cannot be overwritten before their TTL - blunts cache poisoning.'; Breaks = 'Nothing.'
       Gpo = 'Not a GPO: PowerShell / dnscmd'
       Check = 'Get-DnsServerCache | fl LockingPercent'; Fix = 'Set-DnsServerCache -LockingPercent 100' }
    @{ Area = 'DNS'; Title = 'Socket pool size (source-port randomisation)'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'SAFE'
       Reg = $DNSP; Name = 'SocketPoolSize'; Default = 2500; Test = { param($v) [int]$v -ge 2500 }; Want = '2500+ (10000 is fine)'
       Why = 'More random source ports = harder to spoof replies.'; Breaks = 'Nothing. Needs a DNS service restart (brief).'
       Gpo = 'Not a GPO: dnscmd'
       Check = 'dnscmd /info /socketpoolsize'; Fix = 'dnscmd /config /socketpoolsize 10000 ; Restart-Service DNS' }
    @{ Area = 'DNS'; Title = 'No ServerLevelPluginDll (DnsAdmins backdoor)'; Applies = 'DNS'; Bad = 'RED'; Safety = 'SAFE'
       Reg = $DNSP; Name = 'ServerLevelPluginDll'; Default = ''; Test = { param($v) -not $v }; Want = 'not set'
       Why = 'Any DnsAdmins member can make the DNS service load a DLL as SYSTEM on the DC. Set = assume compromise.'; Breaks = 'Nothing - nothing legitimate uses it in a pod.'
       Gpo = 'Not a GPO: registry only. Also audit DnsAdmins membership (audit\Audit-Users.ps1)'
       Check = "reg query $DNSP /v ServerLevelPluginDll"; Fix = "reg delete $DNSP /v ServerLevelPluginDll /f ; Restart-Service DNS  (preserve the DLL first!)" }
    @{ Area = 'DNS'; Title = 'Response rate limiting'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'CAUTION'
       Get = { $r = Get-DnsServerResponseRateLimiting -ErrorAction SilentlyContinue; if ($r) { [string]$r.Mode } else { 'n/a (pre-2016)' } }
       Test = { param($v) $v -in @('LogOnly', 'Enable', 'n/a (pre-2016)') }; Want = 'LogOnly'
       Why = 'Limits DNS amplification/flood abuse; LogOnly shows what WOULD be limited.'
       Breaks = '"Enable" could throttle the scoring engine if it queries in bursts. Use LogOnly.'
       Gpo = 'Not a GPO: PowerShell only'
       Check = 'Get-DnsServerResponseRateLimiting'; Fix = 'Set-DnsServerResponseRateLimiting -Mode LogOnly' }
    @{ Area = 'DNS'; Title = 'DNS server audit log enabled'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { $l = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Audit' -ErrorAction SilentlyContinue; if ($l) { [string]$l.IsEnabled } else { 'missing' } }
       Test = { param($v) $v -eq 'True' }; Want = 'True'
       Why = 'Records zone / record changes (event 515-516 add/delete) - shows a Red Team record hijack.'; Breaks = 'Nothing.'
       Gpo = 'Not a GPO: Event Viewer > Applications and Services Logs > Microsoft > Windows > DNS-Server > Audit > Enable Log'
       Check = "Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Audit'"; Fix = "wevtutil sl Microsoft-Windows-DNSServer/Audit /e:true" }
    @{ Area = 'DNS'; Title = 'Forwarders (review - did Red Team redirect lookups?)'; Applies = 'DNS'; Bad = 'YELLOW'; Safety = 'SAFE'
       Get = { $f = Get-DnsServerForwarder -ErrorAction SilentlyContinue; if ($f -and $f.IPAddress) { 'review: ' + (($f.IPAddress | ForEach-Object { $_.IPAddressToString }) -join ', ') } else { 'none' } }
       Test = { param($v) $v -eq 'none' }; Want = 'only forwarders from the team packet'
       Why = 'A changed forwarder silently sends every external lookup to Red Team.'; Breaks = 'Removing a forwarder the pod needs breaks external name resolution - compare with the packet first.'
       Gpo = 'Not a GPO: DNS Manager > server > Properties > Forwarders'
       Check = 'Get-DnsServerForwarder'; Fix = 'Set-DnsServerForwarder -IPAddress <packet value>' }
)

# ---------------------------------------------------------------------------
# -Reference: write the catalog as Markdown and stop (no scanning, any OS).
# ---------------------------------------------------------------------------
if ($Reference) {
    $md = New-Object System.Collections.Generic.List[string]
    $md.Add('# Security policy reference: AD, DNS and Windows hardening settings')
    $md.Add('')
    $md.Add('Generated from `windows\audit\Audit-SecurityPolicy.ps1 -Reference` - edit the script, not this file.')
    $md.Add('Run the script (panel `[P]`) to see the CURRENT value of each setting on a box.')
    $md.Add('')
    $md.Add('**Safety:** `SAFE` = turn it on now, no effect on scored services in a normal pod. `CAUTION` = can break the thing named in "Breaks"; test first. `LEAVE` = do not change mid-competition.')
    $md.Add('')
    $md.Add('**Which GPO?** Domain password/lockout policy only works in a GPO linked at the domain root (*Default Domain Policy*). DC-only settings go in *Default Domain Controllers Policy*. Member servers/workstations: a GPO on their OU, or `gpedit.msc`/`secpol.msc` on the box. Then `gpupdate /force`. "MS Security Guide" settings need `SecGuide.admx` from the Microsoft Security Compliance Toolkit; without it, use GPO Preferences > Registry with the value from "Fix".')
    $md.Add('')
    foreach ($area in ($catalog | ForEach-Object { $_.Area } | Select-Object -Unique)) {
        $md.Add("## $area")
        $md.Add('')
        $md.Add('| Setting | Applies to | Want | Safety | Why | Breaks | Where (GPO / console) | Check | Fix |')
        $md.Add('|---|---|---|---|---|---|---|---|---|')
        foreach ($c in ($catalog | Where-Object Area -eq $area)) {
            $cells = @($c.Title, $c.Applies, $c.Want, $c.Safety, $c.Why, $c.Breaks, $c.Gpo, ('`' + $c.Check + '`'), ('`' + $c.Fix + '`')) | ForEach-Object { ([string]$_) -replace '\|', '\|' }
            $md.Add('| ' + ($cells -join ' | ') + ' |')
        }
        $md.Add('')
    }
    $dir = Split-Path -Parent $Reference
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllLines($Reference, $md, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Reference written: $Reference ($(@($catalog).Count) settings)"
    return
}

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-SecurityPolicy' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath
$role = Get-CcdcDomainRole
$isDC = $role -ge 4

function Get-RegEffective([string]$Key, [string]$Name, $Default) {
    $v = Get-ItemProperty -Path ("Registry::" + $Key) -Name $Name -ErrorAction SilentlyContinue
    if ($v -and $null -ne $v.$Name) { return $v.$Name }
    return $Default
}

# secedit export: the effective local security policy (on a DC: the domain policy).
$sec = @{}
$secFile = Join-Path $env:TEMP ("ccdc_secpol_{0}.inf" -f $script:CcdcStamp)
try {
    $null = & secedit.exe /export /cfg $secFile /areas SECURITYPOLICY /quiet 2>&1
    if (Test-Path $secFile) {
        foreach ($line in (Get-Content $secFile)) { if ($line -match '^\s*([^=;\[]+?)\s*=\s*(.*)$') { $sec[$Matches[1]] = $Matches[2].Trim() } }
    }
} finally { Remove-Item $secFile -Force -ErrorAction SilentlyContinue }
function Get-Sec([string]$k) { if ($sec.ContainsKey($k)) { return $sec[$k] } return $null }

# Domain password policy straight from the domain object (works from any member).
$dom = $null; $domainDN = $null
try {
    $domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
    if ($domainDN) {
        $d = [ADSI]"LDAP://$domainDN"
        $maxAge = $d.ConvertLargeIntegerToInt64($d.Properties['maxPwdAge'].Value)
        $dom = @{
            PwdProperties = [int]$d.Properties['pwdProperties'].Value
            MinPwdLength = [int]$d.Properties['minPwdLength'].Value
            LockoutThreshold = [int]$d.Properties['lockoutThreshold'].Value
            # maxPwdAge is negative 100-ns ticks; Int64.MinValue (or 0) = never expires.
            MaxPwdAgeDays = if ($maxAge -eq [Int64]::MinValue -or $maxAge -eq 0) { 0 } else { [int]([TimeSpan]::FromTicks(-$maxAge).TotalDays) }
            MachineAccountQuota = [int]$d.Properties['ms-DS-MachineAccountQuota'].Value
        }
    }
} catch { $dom = $null; $domainDN = $null }

function Get-LdapList([string]$Filter, [string]$Prop = 'sAMAccountName') {
    if (-not $domainDN) { return @() }
    $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN", $Filter)
    $s.PageSize = 1000; [void]$s.PropertiesToLoad.Add($Prop)
    @($s.FindAll() | ForEach-Object { [string]$_.Properties[$Prop.ToLower()][0] })
}
function Get-ProtectedUsersGap {
    if (-not $domainDN) { return @() }
    $da = Get-LdapList '(&(objectClass=group)(sAMAccountName=Domain Admins))' 'distinguishedName'
    $pu = Get-LdapList '(&(objectClass=group)(sAMAccountName=Protected Users))' 'distinguishedName'
    if (-not $da -or -not $pu) { return @() }
    $members = Get-LdapList "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=$($da[0])))"
    $inPu = Get-LdapList "(memberOf:1.2.840.113556.1.4.1941:=$($pu[0]))"
    foreach ($m in $members) {
        $svcLike = $m -match '(?i)^(svc|sa|srv)[-_.]|bind|ldap|keycloak|sql|backup|score'
        [pscustomobject]@{ Target = $m; Value = $(if ($inPu -contains $m) { 'member' } elseif ($svcLike) { 'not a member (looks like a service account - leave it out)' } else { 'not a member' }); Ok = ($inPu -contains $m -or $svcLike) }
    }
}
function Get-UnsignedBindInfo {
    # Event 2887 (once a day): how many unsigned / cleartext binds this DC accepted in the last 24h.
    $e = $null
    try { $e = Get-WinEvent -LogName 'Directory Service' -FilterXPath '*[System[EventID=2887]]' -MaxEvents 1 -ErrorAction Stop } catch { $e = $null }
    if (-not $e) { return 'no 2887 event yet = no unsigned binds seen, or the DC has not logged a summary' }
    $nums = [regex]::Matches($e.Message, '\b\d+\b') | ForEach-Object { [int]$_.Value }
    return ("unsigned/cleartext binds in 24h before {0:MM-dd HH:mm}: {1}" -f $e.TimeCreated, ($nums -join '/'))
}
$dnsZones = $null
function Get-DnsZones {
    if ($null -eq $script:dnsZones) {
        $script:dnsZones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })
    }
    return $script:dnsZones
}
function Get-AuditSummary {
    $plan = @{ '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'; '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management'
               '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'; '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation' }
    $off = @()
    foreach ($g in $plan.Keys) {
        # /r = CSV; the last column is "Inclusion Setting" (No Auditing / Success / Failure / Success and Failure)
        $row = (& auditpol.exe /get /subcategory:"$g" /r 2>$null) | Select-Object -Skip 1 | Where-Object { $_ } | Select-Object -First 1
        if (-not $row -or ($row -split ',')[4] -match 'No Auditing') { $off += $plan[$g] }
    }
    if ($off) { return 'off: ' + ($off -join ', ') } else { return 'all on' }
}

$hasDns = $isDC -and (Get-Service DNS -ErrorAction SilentlyContinue) -and (Test-CcdcModule DnsServer)
if ($isDC -and (Get-Service DNS -ErrorAction SilentlyContinue) -and -not $hasDns) {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'DNS role present but the DnsServer PowerShell module is missing - DNS checks skipped. Use DNS Manager (dnsmgmt.msc).'
}
$rdpOn = (Get-RegEffective 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1) -eq 0

function Test-Applies([string]$a) {
    switch ($a) {
        'All'          { return $true }
        'DC'           { return $isDC }
        'Member'       { return -not $isDC }
        'MemberServer' { return $role -eq 3 }
        'Domain'       { return [bool]$dom }
        'DNS'          { return [bool]$hasDns }
        'RDP'          { return $rdpOn }
    }
    return $false
}

$safeTodo = New-Object System.Collections.ArrayList
$cautionTodo = New-Object System.Collections.ArrayList
function Write-Check($c, [string]$target, $value, [bool]$ok) {
    $name = if ($target) { "$($c.Title): $target" } else { $c.Title }
    $shown = if ($null -eq $value -or "$value" -eq '') { '(not set)' } else { "$value" }
    if ($ok) {
        Write-Finding -Level GREEN -Category $c.Area -Message ("{0} = {1}" -f $name, $shown) -Detail ("GPO: " + $c.Gpo)
        return
    }
    $lvl = $c.Bad
    $tag = switch ($c.Safety) { 'SAFE' { '[SAFE to turn on]' } 'CAUTION' { '[CAUTION - read Breaks]' } default { '[LEAVE as is mid-competition]' } }
    $detail = @(
        "Want : $($c.Want)    $tag"
        "Why  : $($c.Why)"
    )
    if ($c.Safety -ne 'SAFE' -or $c.Breaks -notmatch '^Nothing') { $detail += "Breaks: $($c.Breaks)" }
    $detail += "GPO  : $($c.Gpo)"
    $detail += "Check: $($c.Check)"
    $detail += "Fix  : $($c.Fix)"
    Write-Finding -Level $lvl -Category $c.Area -Message ("{0} = {1}" -f $name, $shown) -Detail ($detail -join "`n")
    if ($c.Safety -eq 'SAFE') { [void]$safeTodo.Add($name) } elseif ($c.Safety -eq 'CAUTION') { [void]$cautionTodo.Add($name) }
}

foreach ($area in ($catalog | ForEach-Object { $_.Area } | Select-Object -Unique)) {
    $items = @($catalog | Where-Object { $_.Area -eq $area -and (Test-Applies $_.Applies) })
    if (-not $items) { continue }
    Write-Section $area
    foreach ($c in $items) {
        try {
            if ($c.Multi) {
                $rows = @(& $c.Get)
                if (-not $rows) { Write-Check $c '' 'none' $true; continue }
                foreach ($r in $rows) { Write-Check $c $r.Target $r.Value ([bool]$r.Ok) }
                continue
            }
            $v = if ($c.Get) { & $c.Get } else { Get-RegEffective $c.Reg $c.Name $c.Default }
            if ($null -eq $v) { Write-Finding -Level INFO -Category $c.Area -Message "$($c.Title): could not read" -Detail ("Check by hand: " + $c.Check); continue }
            Write-Check $c '' $v ([bool](& $c.Test $v))
        } catch {
            Write-Finding -Level INFO -Category $c.Area -Message "$($c.Title): check failed ($($_.Exception.Message))" -Detail ("Check by hand: " + $c.Check)
        }
    }
}

Write-Section 'To do'
if ($safeTodo.Count) {
    Write-Finding -Level YELLOW -Category 'Summary' -Message ("{0} SAFE setting(s) to turn on now:" -f $safeTodo.Count) -Detail (($safeTodo | ForEach-Object { "- $_" }) -join "`n")
} else { Write-Finding -Level GREEN -Category 'Summary' -Message 'Every SAFE setting is already on.' }
if ($cautionTodo.Count) {
    Write-Finding -Level INFO -Category 'Summary' -Message ("{0} CAUTION setting(s) - read the Breaks line and test before changing:" -f $cautionTodo.Count) -Detail (($cautionTodo | ForEach-Object { "- $_" }) -join "`n")
}
Write-Finding -Level INFO -Category 'Summary' -Message 'Prefer setting these in a GPO (see each GPO line) so they re-apply if Red Team reverts them. Then: gpupdate /force, and re-run this script.'

Complete-Ccdc
