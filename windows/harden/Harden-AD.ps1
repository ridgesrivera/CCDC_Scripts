<#
.SYNOPSIS
    Harden-AD - fix the per-account Active Directory findings PingCastle keeps reporting. CHANGES STATE. DC only.

.DESCRIPTION
    PURPOSE
      The Qualifiers PingCastle scan put these at the top, and Red Team uses
      every one of them. They are single flags on user accounts, so they are
      quick to fix and almost never break a scored service:

      MODULE                       WHAT IT FIXES                                  RISK
      RequirePreAuth               "Do not require Kerberos pre-authentication"    none
                                   -> AS-REP roasting without any credentials
      ClearReversibleEncryption    "Store password using reversible encryption"   none (legacy CHAP/Digest apps only)
                                   -> password recoverable in clear text
      ClearPasswordNotRequired     PASSWD_NOTREQD: account may have a BLANK        fails harmlessly if the password is blank
                                   password                                        (set one first)
      ClearDesOnly                 "Use only Kerberos DES encryption"             none on anything from this century
      ProtectAdmins                "Account is sensitive and cannot be            breaks an admin account ONLY if a service
                                   delegated" on members of admin groups           delegates as it (rare). Not run by default.

      And it REPORTS (does not change) what needs a human decision:
        * Kerberoastable accounts (users with an SPN): rotate to a 25+ char random password
        * Unconstrained delegation on non-DC accounts
        * Members of Domain Admins / Enterprise Admins / Schema Admins / Administrators
        * ms-DS-MachineAccountQuota (fix: harden\Harden-Baseline.ps1 -Only MachineAccountQuotaZero)

    WHAT IT READS    user objects in the domain (LDAP, no module needed)
    WHAT IT CHANGES  userAccountControl bits on the accounts it lists; each one is
                     confirmed (y/N) unless -Force. Passwords are NOT touched.
    HOW TO UNDO      C:\ccdc\logs\Harden-AD_*_rollback.ps1 restores each account's
                     original userAccountControl value.

    MANUAL EQUIVALENT
      Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
      Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | Set-ADUser -AllowReversiblePasswordEncryption $false
      Get-ADUser -Filter {PasswordNotRequired -eq $true} | Set-ADUser -PasswordNotRequired $false
      Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet

.PARAMETER Only
    Run only these modules.

.PARAMETER Skip
    Run the default modules except these.

.EXAMPLE
    .\Harden-AD.ps1 -WhatIf
.EXAMPLE
    .\Harden-AD.ps1 -Only RequirePreAuth -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('RequirePreAuth', 'ClearReversibleEncryption', 'ClearPasswordNotRequired', 'ClearDesOnly', 'ProtectAdmins')][string[]]$Only = @(),
    [string[]]$Skip = @(),
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Harden-AD'
$null = Get-CcdcConfig -Path $ConfigPath
if (-not (Test-CcdcIsDC)) {
    Write-Finding -Level RED -Category 'Setup' -Message 'This is not a domain controller. Run it on the DC.'
    Complete-Ccdc; return
}
$domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext

# userAccountControl bits (https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
$UF = @{ PasswdNotReqd = 0x20; ReversibleEnc = 0x80; NotDelegated = 0x100000; DesOnly = 0x200000; NoPreAuth = 0x400000; TrustedForDelegation = 0x80000; Disabled = 0x2 }

function Find-Users([string]$filter) {
    $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN", $filter)
    $s.PageSize = 1000
    foreach ($p in 'sAMAccountName', 'userAccountControl', 'distinguishedName', 'servicePrincipalName', 'pwdLastSet', 'objectClass') { [void]$s.PropertiesToLoad.Add($p) }
    return @($s.FindAll())
}
# LDAP "bitwise AND" matching rule: finds accounts where that bit is set.
function Get-BitFilter([int]$bit) { return "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$bit))" }

$rollback = $script:CcdcLogFile -replace '\.log$', '_rollback.ps1'
$rollbackLines = New-Object System.Collections.ArrayList
[void]$rollbackLines.Add("# Rollback for Harden-AD run $($script:CcdcStamp): restores original userAccountControl values. Review before running.")

function Set-UacBit {
    # Clears (or sets) one userAccountControl bit on every account the filter returns.
    param([string]$Module, [string]$Filter, [int]$Bit, [switch]$SetBit, [string]$Why)
    Write-Section $Module
    $found = Find-Users $Filter
    if ($found.Count -eq 0) { Write-Finding -Level GREEN -Category $Module -Message 'No accounts need this.'; return }
    foreach ($r in $found) {
        $sam = [string]$r.Properties['samaccountname'][0]
        $uac = [int]$r.Properties['useraccountcontrol'][0]
        $dn  = [string]$r.Properties['distinguishedname'][0]
        $new = if ($SetBit) { $uac -bor $Bit } else { $uac -band (-bnot $Bit) }
        if ($new -eq $uac) { continue }
        $state = if ($uac -band $UF.Disabled) { ' (disabled account)' } else { '' }
        Write-Finding -Level RED -Category $Module -Message "$sam$state" -Detail $Why
        $entry = $r.GetDirectoryEntry()
        $undo = "`$e = [ADSI]'LDAP://$dn'; `$e.Properties['userAccountControl'].Value = $uac; `$e.CommitChanges()   # $sam"
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $sam -Action $Module -Undo $undo -ScriptBlock {
            $entry.Properties['userAccountControl'].Value = $new
            $entry.CommitChanges()
        }
        if ($ok) { [void]$rollbackLines.Add($undo) }
    }
}

$default = @('RequirePreAuth', 'ClearReversibleEncryption', 'ClearPasswordNotRequired', 'ClearDesOnly')
$run = if ($Only.Count -gt 0) { $Only } else { $default | Where-Object { $Skip -notcontains $_ } }

if ($run -contains 'RequirePreAuth') {
    Set-UacBit -Module 'RequirePreAuth' -Filter (Get-BitFilter $UF.NoPreAuth) -Bit $UF.NoPreAuth -Why 'Anyone on the network can request an AS-REP for this account and crack its password offline, without logging in.'
}
if ($run -contains 'ClearReversibleEncryption') {
    Set-UacBit -Module 'ClearReversibleEncryption' -Filter (Get-BitFilter $UF.ReversibleEnc) -Bit $UF.ReversibleEnc -Why 'The password is stored so it can be decrypted to clear text. (Takes full effect at the next password change: rotate it.)'
}
if ($run -contains 'ClearPasswordNotRequired') {
    Set-UacBit -Module 'ClearPasswordNotRequired' -Filter (Get-BitFilter $UF.PasswdNotReqd) -Bit $UF.PasswdNotReqd -Why 'This account is allowed to have an EMPTY password regardless of the domain policy.'
}
if ($run -contains 'ClearDesOnly') {
    Set-UacBit -Module 'ClearDesOnly' -Filter (Get-BitFilter $UF.DesOnly) -Bit $UF.DesOnly -Why 'Kerberos tickets for this account use DES, which is crackable in hours.'
}
if ($run -contains 'ProtectAdmins') {
    # Members (direct or nested) of Domain Admins that are not yet marked "sensitive, cannot be delegated".
    $da = (Find-Users '(&(objectClass=group)(sAMAccountName=Domain Admins))' | Select-Object -First 1)
    if ($da) {
        $daDn = [string]$da.Properties['distinguishedname'][0]
        $f = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$daDn)(!(userAccountControl:1.2.840.113556.1.4.803:=$($UF.NotDelegated))))"
        Set-UacBit -Module 'ProtectAdmins' -Filter $f -Bit $UF.NotDelegated -SetBit -Why 'Domain Admin whose identity can be delegated: a server trusted for delegation can act as this admin.'
    }
}

# ---------------------------------------------------------------------------
Write-Section 'Report only: needs your decision'
# ---------------------------------------------------------------------------
$spn = @(Find-Users '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))')
if ($spn.Count -eq 0) { Write-Finding -Level GREEN -Category 'Kerberoast' -Message 'No user accounts have an SPN.' }
foreach ($r in $spn) {
    $sam = [string]$r.Properties['samaccountname'][0]
    $set = if ($r.Properties['pwdlastset'].Count -gt 0 -and [int64]$r.Properties['pwdlastset'][0] -gt 0) { [datetime]::FromFileTime([int64]$r.Properties['pwdlastset'][0]).ToString('yyyy-MM-dd') } else { 'never' }
    $spnText = (@($r.Properties['serviceprincipalname']) | Select-Object -First 2) -join ', '
    Write-Finding -Level YELLOW -Category 'Kerberoast' -Message ("{0}: has SPN {1}; password last set {2}" -f $sam, $spnText, $set) `
        -Detail "Any domain user can request a ticket for it and crack the password offline. Give it a 25+ character random password:`nharden\Rotate-Passwords.ps1 -Scope Domain -Users $sam   (then update whatever service logs on with it!)"
}
# Unconstrained delegation on anything that is not a DC (DCs have primaryGroupID 516).
$s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN", "(&(userAccountControl:1.2.840.113556.1.4.803:=$($UF.TrustedForDelegation))(!(primaryGroupID=516))(!(primaryGroupID=521)))")
[void]$s.PropertiesToLoad.Add('sAMAccountName')
$deleg = @($s.FindAll())
foreach ($r in $deleg) {
    Write-Finding -Level RED -Category 'Delegation' -Message ("{0} is trusted for UNCONSTRAINED delegation" -f $r.Properties['samaccountname'][0]) -Detail "Whoever controls it can impersonate any user who connects to it, including Domain Admins.`nFix (if no app needs it): Set-ADAccountControl '$($r.Properties['samaccountname'][0])' -TrustedForDelegation `$false"
}
if ($deleg.Count -eq 0) { Write-Finding -Level GREEN -Category 'Delegation' -Message 'No non-DC account has unconstrained delegation.' }

foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') {
    $grp = Find-Users "(&(objectClass=group)(sAMAccountName=$g))" | Select-Object -First 1
    if (-not $grp) { continue }
    $members = @(Find-Users "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$($grp.Properties['distinguishedname'][0])))" | ForEach-Object { [string]$_.Properties['samaccountname'][0] } | Sort-Object)
    $lvl = if ($members.Count -gt 5 -or ($g -eq 'Schema Admins' -and $members.Count -gt 1)) { 'YELLOW' } else { 'INFO' }
    Write-Finding -Level $lvl -Category 'Admins' -Message ("{0}: {1} member(s): {2}" -f $g, $members.Count, ($members -join ', ')) -Detail $(if ($lvl -eq 'YELLOW') { "Shrink to the minimum. Remove: Remove-ADGroupMember '$g' <user>   Disable unknown ones: harden\Disable-Accounts.ps1" } else { '' })
}
$maq = ([ADSI]"LDAP://$domainDN").Properties['ms-DS-MachineAccountQuota'].Value
if ($null -ne $maq -and [int]$maq -gt 0) { Write-Finding -Level YELLOW -Category 'Quota' -Message "ms-DS-MachineAccountQuota = ${maq}: any user can join that many computers to the domain." -Detail 'Fix: harden\Harden-Baseline.ps1 -Only MachineAccountQuotaZero' }

if ($rollbackLines.Count -gt 1) {
    $rollbackLines | Set-Content -Path $rollback -Encoding UTF8 -WhatIf:$false
    Write-Finding -Level INFO -Category 'Rollback' -Message "Rollback commands written to $rollback"
}
Complete-Ccdc
