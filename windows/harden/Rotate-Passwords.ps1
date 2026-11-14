<#
.SYNOPSIS
    Rotate-Passwords - give local/domain accounts new strong random passwords. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      The Red Team already has every password from the team packet. Rotating
      them is the single most valuable thing you do in the first 15 minutes.

    HOW IT WORKS
      1. Builds a target list (-Users, -Group, or -AllEnabled) for -Scope Local or Domain.
      2. REMOVES from that list: built-ins (krbtgt, Guest, ...), anything in
         -Exclude, every scoredAccounts entry in the config, and accounts that
         look like service accounts (svc_, ldap, bind, keycloak, sql ...)
         unless -IncludeServiceAccounts.
      3. For each remaining account: asks y/N (unless -Force), generates a
         random password with the OS crypto RNG, sets it.
      4. Shows ALL new passwords ONCE in a table. Write them on paper / give
         them to the captain, press Enter, and the screen is cleared.

    !! SCORED ACCOUNTS !!
      Accounts the scoring engine logs in with need an approved Password
      Change Request (PCR) submitted to the White/Black team BEFORE you change
      them, or you lose SLA points. Put them in config scoredAccounts or -Exclude.
      Service/bind accounts (e.g. Keycloak's LDAP bind user on the DC, the
      MySQL user in wp-config.php) break their app when changed - change the
      app config at the same time or leave them alone.

    PASSWORD SAFETY (hard rule: never write passwords to disk)
      * Passwords live only in memory and on screen. They are NOT in the log,
        NOT in -OutFile, NOT in a transcript (the script warns if PowerShell
        transcription is forced on by GPO).
      * We set passwords through ADSI (SetPassword) - NOT "net user name pass"
        - because a command line shows up in process listings and in 4688
        process-creation events with command-line logging on.

    WHAT IT READS    local SAM (WinNT provider) or AD (LDAP), config\ccdc.json
    WHAT IT CHANGES  account passwords. Log: C:\ccdc\logs\Rotate-Passwords_*.log (names only)
    HOW TO UNDO      there is no "undo" for a password. Re-run for the account, or
                     reset it by hand. The log tells you which accounts changed and when.

    MANUAL EQUIVALENT
      Local :  net user Administrator *          (the * makes it PROMPT - nothing on the command line)
      Domain:  Set-ADAccountPassword -Identity jdoe -Reset      (prompts for the new password)
      GUI   :  lusrmgr.msc  /  dsa.msc -> right-click user -> Reset Password

.PARAMETER Scope
    Local or Domain. Default: Domain on a DC, Local everywhere else.

.PARAMETER Users
    Explicit account names to rotate.

.PARAMETER Group
    Rotate every enabled member of this group (recursive for domain groups), e.g. 'Domain Admins'.

.PARAMETER AllEnabled
    Rotate every enabled account in scope (minus exclusions).

.PARAMETER Exclude
    Accounts to never touch (scored accounts, service accounts...).

.PARAMETER Length
    Generated password length. Default 16.

.PARAMETER Prompt
    Instead of generating, prompt ONCE for a password (hidden input) and use it for all targets.

.PARAMETER IncludeServiceAccounts
    Do not auto-skip accounts whose names look like service/bind accounts.

.PARAMETER Force
    Do not ask y/N per account.

.EXAMPLE
    .\Rotate-Passwords.ps1 -Scope Local -Users Administrator -WhatIf
.EXAMPLE
    .\Rotate-Passwords.ps1 -Scope Domain -Group 'Domain Admins' -Exclude svc_keycloak
.EXAMPLE
    .\Rotate-Passwords.ps1 -Scope Domain -AllEnabled -Exclude scoreuser1,scoreuser2
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Local', 'Domain')][string]$Scope,
    [string[]]$Users = @(),
    [string]$Group,
    [switch]$AllEnabled,
    [string[]]$Exclude = @(),
    [ValidateRange(12, 64)][int]$Length = 16,
    [switch]$Prompt,
    [switch]$IncludeServiceAccounts,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Rotate-Passwords'
$config = Get-CcdcConfig -Path $ConfigPath
$isDC = Test-CcdcIsDC
if (-not $Scope) { $Scope = if ($isDC) { 'Domain' } else { 'Local' } }
if ($Scope -eq 'Local' -and $isDC) {
    Write-Finding -Level RED -Category 'Setup' -Message 'Domain controllers have no local accounts - use -Scope Domain.'
    Complete-Ccdc; return
}
if (-not $Users -and -not $Group -and -not $AllEnabled) {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'Nothing selected. Use -Users a,b  or  -Group "Domain Admins"  or  -AllEnabled.'
    Complete-Ccdc; return
}

# ---------------------------------------------------------------------------
# Safety banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  !! SCORED ACCOUNTS NEED A PASSWORD CHANGE REQUEST (PCR) FIRST !!" -ForegroundColor Red
Write-Host "  !! Service/bind accounts (Keycloak LDAP bind, wp-config DB user) break their app if changed !!" -ForegroundColor Red
Write-Host ""
if (Test-CcdcTranscriptionOn) {
    Write-Finding -Level RED -Category 'Safety' -Message 'PowerShell TRANSCRIPTION is enabled by policy - passwords shown on screen would be written to disk.' -Detail 'Disable transcription for this session or use -Prompt with a password you already know.'
    $go = Read-Host '  Continue anyway? (y/N)'
    if ($go -notmatch '^(y|yes)$') { Complete-Ccdc; return }
}

# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
$builtinSkip = @('krbtgt', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')   # krbtgt has its own procedure (reset twice) - see docs
$scored      = Get-CcdcScoredAccounts -Config $config
$skip        = @($builtinSkip + $Exclude + $scored) | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
# Names that usually belong to an application, not a person.
$serviceRegex = '(?i)^(svc|sa|srv)[-_.]|[-_.](svc|service)$|bind|ldap|keycloak|sql|mysql|iis|apppool|backup|scan|score|graylog|minio|wp_?|wiki'
if ($scored) { Write-Finding -Level INFO -Category 'Exclude' -Message ('Scored accounts from config (skipped): {0}' -f ($scored -join ', ')) }

# ---------------------------------------------------------------------------
# Build the target list
# ---------------------------------------------------------------------------
$targets = New-Object System.Collections.ArrayList    # objects: Name, Id (DN or WinNT path)

if ($Scope -eq 'Local') {
    $all = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True"
    $pick = @()
    if ($AllEnabled) { $pick += $all | Where-Object { -not $_.Disabled } }
    if ($Users)      { $pick += $all | Where-Object { $Users -contains $_.Name } }
    if ($Group) {
        $members = @(([ADSI]"WinNT://./$Group,group").psbase.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
        $pick += $all | Where-Object { $members -contains $_.Name -and -not $_.Disabled }
    }
    foreach ($u in ($pick | Sort-Object Name -Unique)) {
        [void]$targets.Add([pscustomobject]@{ Name = $u.Name; Id = "WinNT://$env:COMPUTERNAME/$($u.Name),user" })
    }
    foreach ($n in $Users) { if (-not ($all | Where-Object Name -eq $n)) { Write-Finding -Level YELLOW -Category 'Target' -Message "Local user '$n' not found" } }
} else {
    $domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
    function Find-DomainUsers([string]$filter) {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.SearchRoot = [ADSI]"LDAP://$domainDN"; $s.PageSize = 1000
        # objectCategory=person + not disabled (UAC bit 2) - computers/disabled users never rotate
        $s.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))$filter)"
        [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('distinguishedName')
        return $s.FindAll()
    }
    $found = @()
    if ($AllEnabled) { $found += Find-DomainUsers '' }
    foreach ($n in $Users) {
        $r = @(Find-DomainUsers "(sAMAccountName=$n)")
        if ($r.Count -eq 0) { Write-Finding -Level YELLOW -Category 'Target' -Message "Domain user '$n' not found or disabled" }
        $found += $r
    }
    if ($Group) {
        $g = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN", "(&(objectClass=group)(sAMAccountName=$Group))")
        $gr = $g.FindOne()
        if ($gr) { $found += Find-DomainUsers "(memberOf:1.2.840.113556.1.4.1941:=$($gr.Properties['distinguishedname'][0]))" }
        else { Write-Finding -Level YELLOW -Category 'Target' -Message "Group '$Group' not found" }
    }
    $seen = @{}
    foreach ($r in $found) {
        $sam = [string]$r.Properties['samaccountname'][0]
        if ($seen.ContainsKey($sam)) { continue }; $seen[$sam] = 1
        [void]$targets.Add([pscustomobject]@{ Name = $sam; Id = [string]$r.Properties['distinguishedname'][0] })
    }
}

# Apply exclusions with a visible reason for each skip (students should see WHY).
$final = @()
foreach ($t in $targets) {
    if ($skip -contains $t.Name.ToLower()) { Write-Finding -Level INFO -Category 'Exclude' -Message "skip $($t.Name) (excluded / built-in / scored)"; continue }
    if (-not $IncludeServiceAccounts -and $t.Name -match $serviceRegex) {
        Write-Finding -Level YELLOW -Category 'Exclude' -Message "skip $($t.Name) - looks like a SERVICE account (use -IncludeServiceAccounts after updating its app config)"
        continue
    }
    $final += $t
}
if (-not $final) { Write-Finding -Level YELLOW -Category 'Target' -Message 'No accounts left to rotate after exclusions.'; Complete-Ccdc; return }
Write-Finding -Level INFO -Category 'Target' -Message ("{0} account(s) to rotate ({1}): {2}" -f $final.Count, $Scope, (($final | ForEach-Object Name) -join ', '))
if ($final.Name -contains $env:USERNAME) { Write-Finding -Level YELLOW -Category 'Target' -Message "You are rotating YOUR OWN account ($env:USERNAME). Your current session stays up; new logins need the new password." }

# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------
function New-CcdcPassword([int]$Len) {
    <#
      Uses RNGCryptoServiceProvider (crypto-grade randomness; Get-Random is NOT).
      Alphabet avoids look-alikes (0 O 1 l I) and characters that break
      shells/configs when a teammate has to type or paste it: quotes, backtick,
      $, %, ^, &, |, <, >, \, spaces.
      Rejection sampling avoids "modulo bias" (some chars appearing more often).
    #>
    $lower = 'abcdefghijkmnopqrstuvwxyz'; $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digit = '23456789';                  $sym   = '!@#*-_=+?.'
    $all   = $lower + $upper + $digit + $sym
    $rng   = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $byte  = New-Object byte[] 1
    function Get-RandomChar([string]$set) {
        $limit = 256 - (256 % $set.Length)
        do { $rng.GetBytes($byte) } while ($byte[0] -ge $limit)
        return $set[$byte[0] % $set.Length]
    }
    do {
        $chars = for ($i = 0; $i -lt $Len; $i++) { Get-RandomChar $all }
        $pw = -join $chars
        # Re-roll until every character class is present (complexity policy).
    } until ($pw -cmatch '[a-z]' -and $pw -cmatch '[A-Z]' -and $pw -match '\d' -and $pw -match '[^a-zA-Z0-9]')
    $rng.Dispose()
    return $pw
}

$shared = $null
if ($Prompt -and -not $WhatIfPreference) {
    do {
        $s1 = Read-Host '  New password for ALL selected accounts' -AsSecureString
        $s2 = Read-Host '  Confirm' -AsSecureString
        # Convert to plain only in memory, only to compare/set. Never logged.
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
        $ok = ($p1 -ceq $p2) -and $p1.Length -ge 12
        if (-not $ok) { Write-Host '  Mismatch or shorter than 12 characters - try again.' -ForegroundColor Red }
    } until ($ok)
    $shared = $p1; $p1 = $null; $p2 = $null
}

# ---------------------------------------------------------------------------
# Rotate
# ---------------------------------------------------------------------------
$results = New-Object System.Collections.ArrayList   # in memory ONLY
foreach ($acct in $final) {
    $newPw = if ($shared) { $shared } else { New-CcdcPassword $Length }
    $acctId = $acct.Id
    $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$Scope\$($acct.Name)" -Action 'Set new password' `
        -Undo 'no undo for passwords; re-run or reset manually' -ScriptBlock {
            if ($acctId -like 'WinNT://*') {
                $obj = [ADSI]$acctId               # local account via WinNT provider
                $obj.SetPassword($newPw)
            } else {
                $obj = [ADSI]"LDAP://$acctId"      # domain account via LDAP (needs LDAPS/Kerberos - fine on a DC)
                $obj.Invoke('SetPassword', $newPw)
                # Make sure the account is not forced to change at next logon (would break scoring logins).
                $obj.Properties['pwdLastSet'].Value = -1
                $obj.CommitChanges()
            }
        }
    if ($ok) { [void]$results.Add([pscustomobject]@{ Account = "$Scope\$($acct.Name)"; Password = $newPw }) }
}
$newPw = $null; $shared = $null

# ---------------------------------------------------------------------------
# Display ONCE, then clear
# ---------------------------------------------------------------------------
if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host ('#' * 72) -ForegroundColor Yellow
    Write-Host '  NEW PASSWORDS - shown ONCE. Write them down / hand to the captain NOW.' -ForegroundColor Yellow
    Write-Host '  They are NOT saved anywhere. Screen clears when you press Enter.' -ForegroundColor Yellow
    Write-Host ('#' * 72) -ForegroundColor Yellow
    foreach ($r in $results) { Write-Host ("  {0,-35} {1}" -f $r.Account, $r.Password) -ForegroundColor White }
    Write-Host ('#' * 72) -ForegroundColor Yellow
    [void](Read-Host '  Press Enter when recorded')
    Clear-Host
    # Best effort: drop the plaintext from memory. (.NET strings are immutable,
    # so this removes references; the GC reclaims them.)
    $results.Clear(); [GC]::Collect()
    Write-Finding -Level GREEN -Category 'Rotate' -Message 'Passwords rotated. Update the team password sheet (paper). Log lists account names only.'
} elseif ($WhatIfPreference) {
    Write-Finding -Level INFO -Category 'Rotate' -Message 'Dry run complete - no passwords changed.'
}
Complete-Ccdc
