<#
.SYNOPSIS
    Audit-Users - who can log in, who is an admin, who is roastable. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Find rogue/unexpected admins and risky account settings that the Red
      Team abuses: Kerberoastable SPN accounts, AS-REP roastable accounts,
      passwords sitting in description fields, accounts created in the last
      few days, and AdminSDHolder-protected (adminCount=1) leftovers.

    WHAT IT READS
      * Local users + local groups (ADSI WinNT provider - works on 2012 R2+)
      * Domain users/groups over LDAP (System.DirectoryServices). This works
        on ANY domain-joined box, even without the ActiveDirectory module.
      * Security event log: 4720 (user created), 4728/4732/4756 (added to a
        security group) for the last -RecentDays days.

    WHAT IT CHANGES
      Nothing. Writes only its own log in C:\ccdc\logs\ and the optional report.
      NOTE: if a description field contains what looks like a password, it is
      shown on SCREEN ONLY and never written to the log or report.

    HOW TO UNDO
      Nothing to undo. To act on findings use hunt\Kick-Block.ps1 (panel X) and
      harden\Rotate-Passwords.ps1.

    MANUAL EQUIVALENT
      net user                      ; net localgroup Administrators
      net group "Domain Admins" /domain
      Get-ADGroupMember "Domain Admins" -Recursive
      Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
      Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
      Get-ADUser -Filter * -Properties Description | ? Description -match 'pass'
      Get-ADUser -Filter {adminCount -eq 1}
      Get-ADUser -Filter * -Properties whenCreated | ? whenCreated -gt (Get-Date).AddDays(-7)

.PARAMETER ExpectedAdmins
    Account names you EXPECT in admin groups (shown GREEN). Everyone else is RED.

.PARAMETER RecentDays
    How far back counts as "recently created/modified". Default 7.

.EXAMPLE
    .\Audit-Users.ps1 -ExpectedAdmins Administrator,jdoe -OutFile C:\ccdc\reports\users.csv
#>
[CmdletBinding()]
param(
    [string[]]$ExpectedAdmins = @('Administrator'),
    [int]$RecentDays = 7,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Users' -OutFile $OutFile -ReadOnly
$null    = Get-CcdcConfig -Path $ConfigPath
$isDC    = Test-CcdcIsDC
$cutoff  = (Get-Date).AddDays(-$RecentDays)
# Words that suggest a password was left in a description/info field.
$pwRegex = '(?i)(pass(word)?|pwd|pw\s*[:=]|cred|secret|p@ss)'

# userAccountControl flag values (bit masks). See: "UserAccountControl flags" on Microsoft Learn.
$UAC_DISABLED          = 0x0002
$UAC_PASSWD_NOTREQD    = 0x0020
$UAC_DONT_EXPIRE_PASSWD= 0x10000
$UAC_TRUSTED_FOR_DELEG = 0x80000
$UAC_DONT_REQ_PREAUTH  = 0x400000

function Test-Expected([string]$name) {
    $short = $name -replace '^.*[\\/]', ''   # strip DOMAIN\ or WinNT://DOMAIN/
    return ($ExpectedAdmins -contains $short)
}

# ---------------------------------------------------------------------------
# Local accounts (skipped on DCs - a DC has no local SAM users)
# ---------------------------------------------------------------------------
if (-not $isDC) {
    Write-Section 'Local users'
    # Win32_UserAccount works everywhere; LocalAccount=True excludes domain users.
    $locals = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    foreach ($u in $locals) {
        $level = if ($u.Disabled) { 'INFO' } else { 'YELLOW' }
        if (-not $u.Disabled -and $u.Name -eq 'Guest') { $level = 'RED' }
        $flags = @()
        if (-not $u.Disabled) { $flags += 'ENABLED' } else { $flags += 'disabled' }
        if (-not $u.PasswordExpires) { $flags += 'pw-never-expires' }
        if (-not $u.PasswordRequired) { $flags += 'NO-PASSWORD-REQUIRED'; $level = 'RED' }
        Write-Finding -Level $level -Category 'LocalUser' -Message ("{0,-22} {1}" -f $u.Name, ($flags -join ' '))
        if ($u.Description -match $pwRegex) {
            Write-Finding -Level RED -Category 'LocalUser' -Message "Description of local user '$($u.Name)' may contain a password (shown on screen only)"
            Write-Host "       description: $($u.Description)" -ForegroundColor DarkYellow   # screen only, never logged
        }
    }
}

# ---------------------------------------------------------------------------
# Local / builtin group membership (on a DC these ARE the domain builtin groups)
# ---------------------------------------------------------------------------
# On a DC these groups ARE the domain builtin groups: the domain section below covers them.
if (-not $isDC) { Write-Section 'Privileged local/builtin groups' }
foreach ($g in @(if (-not $isDC) { 'Administrators', 'Remote Desktop Users', 'Backup Operators', 'Remote Management Users' })) {
    try {
        # The WinNT provider lists members, including orphaned SIDs that break Get-LocalGroupMember.
        $grp = [ADSI]"WinNT://./$g,group"
        $members = @($grp.psbase.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null) })
    } catch { continue }
    if ($members.Count -eq 0) { Write-Finding -Level GREEN -Category 'LocalGroup' -Message "$g : (empty)"; continue }
    foreach ($m in $members) {
        $name = ($m -replace '^WinNT://', '') -replace '/', '\'
        if ($g -eq 'Administrators') {
            $lvl = if ((Test-Expected $name) -or $name -match '\\(Domain Admins|Enterprise Admins)$') { 'GREEN' } else { 'RED' }
        } else { $lvl = 'YELLOW' }
        Write-Finding -Level $lvl -Category 'LocalGroup' -Message ("{0,-24} <- {1}" -f $g, $name)
    }
}

# ---------------------------------------------------------------------------
# Domain checks over LDAP
# ---------------------------------------------------------------------------
$rootDse = $null
try { $rootDse = [ADSI]'LDAP://RootDSE'; $null = $rootDse.defaultNamingContext } catch { $rootDse = $null }

function Search-Ldap {
    # Tiny wrapper around DirectorySearcher. -Filter is an LDAP filter string.
    param([string]$Filter, [string[]]$Properties = @('sAMAccountName'))
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]("LDAP://" + $rootDse.defaultNamingContext)
    $s.Filter     = $Filter
    $s.PageSize   = 1000          # without paging AD stops at 1000 results
    foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p) }
    return $s.FindAll()
}
function Get-Prop($r, $name) { if ($r.Properties[$name].Count -gt 0) { return $r.Properties[$name][0] } return $null }

if (-not $rootDse -or -not $rootDse.defaultNamingContext) {
    Write-Section 'Domain'
    Write-Finding -Level INFO -Category 'Domain' -Message 'Not domain-joined (or DC unreachable) - domain checks skipped.'
} else {
    $domainDN = [string]$rootDse.defaultNamingContext
    Write-Section "Domain privileged groups ($domainDN)"
    $userProps = @('sAMAccountName', 'userAccountControl', 'whenCreated', 'whenChanged', 'description', 'info', 'servicePrincipalName', 'adminCount', 'pwdLastSet', 'distinguishedName')

    # One line per group. '!' = not a default/expected member. Recursive (nested groups count).
    $privGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'DnsAdmins',
                    'Backup Operators', 'Account Operators', 'Server Operators', 'Print Operators',
                    'Remote Desktop Users', 'Group Policy Creator Owners')
    $topGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    $privMembers = @{}   # sAMAccountName -> list of groups
    $empty = @()
    foreach ($gName in $privGroups) {
        $g = Search-Ldap -Filter "(&(objectClass=group)(sAMAccountName=$gName))" -Properties @('distinguishedName')
        if ($g.Count -eq 0) { continue }
        $gDN = Get-Prop $g[0] 'distinguishedname'
        # 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN -> RECURSIVE membership (nested groups too).
        $members = @(Search-Ldap -Filter "(&(|(objectClass=user)(objectClass=computer))(memberOf:1.2.840.113556.1.4.1941:=$gDN))" -Properties $userProps)
        if ($members.Count -eq 0) { $empty += $gName; continue }
        $names = @(); $unexpected = 0
        foreach ($m in $members) {
            $sam = [string](Get-Prop $m 'samaccountname')
            $off = ([int](Get-Prop $m 'useraccountcontrol')) -band $UAC_DISABLED
            if (-not $privMembers.ContainsKey($sam)) { $privMembers[$sam] = @() }
            $privMembers[$sam] += $gName
            $odd = -not (Test-Expected $sam)
            if ($odd -and -not $off) { $unexpected++ }
            $names += ('{0}{1}{2}' -f $sam, $(if ($odd) { ' !' } else { '' }), $(if ($off) { ' (disabled)' } else { '' }))
        }
        $lvl = if ($unexpected -eq 0) { 'GREEN' } elseif ($gName -in $topGroups -or $gName -eq 'DnsAdmins') { 'RED' } else { 'YELLOW' }
        Write-Finding -Level $lvl -Category 'DomainGroup' -Message ("{0} ({1}): {2}" -f $gName, $members.Count, ($names -join ', '))
    }
    if ($empty) { Write-Finding -Level GREEN -Category 'DomainGroup' -Message ("Empty (good): {0}" -f ($empty -join ', ')) }
    Write-Host '       ! = not a default member. Admin-level groups should hold only the accounts your team uses. Remove the rest (panel 10/X) after checking nothing scored depends on them.' -ForegroundColor DarkGray

    # One pass over all users, collected into buckets so each problem prints ONCE with its list.
    Write-Section 'Domain account risks (grouped)'
    $users = @(Search-Ldap -Filter '(&(objectCategory=person)(objectClass=user))' -Properties $userProps)
    $b = @{ NoPw = @(); AsRep = @(); Kerb = @(); KerbPriv = @(); Deleg = @(); PwDesc = @(); Orphan = @(); Never = 0 }
    $created = @()
    $enabled = 0
    $buildTime = $null
    foreach ($u in $users) {
        $sam = [string](Get-Prop $u 'samaccountname')
        $uac = [int](Get-Prop $u 'useraccountcontrol')
        $isEnabled = -not ($uac -band $UAC_DISABLED)
        if ($isEnabled) { $enabled++ }
        $wc = Get-Prop $u 'whencreated'; if ($wc) { $created += [pscustomobject]@{ Sam = $sam; Time = [datetime]$wc } }
        if ($sam -eq 'krbtgt' -and $wc) { $buildTime = [datetime]$wc }   # krbtgt is created when the domain is built
        if (-not $isEnabled) { continue }
        if ($uac -band $UAC_PASSWD_NOTREQD) { $b.NoPw += $sam }
        if ($uac -band $UAC_DONT_REQ_PREAUTH) { $b.AsRep += $sam }
        if ($uac -band $UAC_DONT_EXPIRE_PASSWD) { $b.Never++ }
        if (($uac -band $UAC_TRUSTED_FOR_DELEG) -and $sam -notmatch '\$$') { $b.Deleg += $sam }
        if ($u.Properties['serviceprincipalname'].Count -gt 0 -and $sam -ne 'krbtgt') { if ($privMembers.ContainsKey($sam)) { $b.KerbPriv += $sam } else { $b.Kerb += $sam } }
        foreach ($field in @('description', 'info')) {
            $val = [string](Get-Prop $u $field)
            if ($val -and $val -match $pwRegex) { $b.PwDesc += "$sam ($field)"; Write-Host "       ${sam} ${field}: $val" -ForegroundColor DarkYellow }   # screen only - never logged
        }
        if ([int](Get-Prop $u 'admincount') -eq 1 -and -not $privMembers.ContainsKey($sam) -and $sam -ne 'krbtgt') { $b.Orphan += $sam }
    }
    function Show-Bucket([string]$lvl, [string]$cat, [string]$title, $list, [string]$why) {
        if (@($list).Count -eq 0) { return }
        Write-Finding -Level $lvl -Category $cat -Message ("{0} ({1}): {2}" -f $title, @($list).Count, (@($list) -join ', ')) -Detail $why
    }
    Show-Bucket RED 'Kerberoast' 'Kerberoastable AND privileged' $b.KerbPriv 'Any domain user can request a ticket for these and crack the password offline, then they are admin. Fix: long random password (panel 10), take it out of admin groups if you can.'
    Show-Bucket RED 'ASREPRoast' 'AS-REP roastable (no Kerberos pre-auth)' $b.AsRep 'Anyone can get a crackable hash for these WITHOUT a password. Fix: panel 12 (hardening walkthrough) or Set-ADAccountControl <user> -DoesNotRequirePreAuth $false'
    Show-Bucket RED 'NoPassword' 'Password not required (PASSWD_NOTREQD)' $b.NoPw 'These may have an EMPTY password. Fix: panel 12, or set a password and clear the flag.'
    Show-Bucket RED 'PwInDescription' 'Password written in the description' $b.PwDesc 'Anyone in the domain can read descriptions. Change that password and clear the field.'
    Show-Bucket RED 'Delegation' 'Unconstrained delegation on a user' $b.Deleg 'Their tickets can be used to impersonate anyone. Remove "Trust this user for delegation".'
    Show-Bucket YELLOW 'Kerberoast' 'Kerberoastable (service accounts with an SPN)' $b.Kerb 'Crackable offline if the password is weak. Give them long random passwords (check what service uses them first).'
    Show-Bucket YELLOW 'AdminSDHolder' 'adminCount=1 but not in an admin group now' $b.Orphan 'A former admin, or a sign someone was briefly made admin. Check who changed it.'
    if ($b.Never) { Write-Finding -Level INFO -Category 'PwNeverExpires' -Message ("{0} enabled accounts have 'password never expires' (normal in labs; not a priority mid-competition)" -f $b.Never) }

    # Account creation: bulk batches = environment setup; accounts made alone AFTER setup = look at these.
    Write-Section 'When accounts were created'
    $batches = @($created | Group-Object { $_.Time.ToString('yyyy-MM-dd HH:mm') } | Sort-Object Name)
    $bulk = @($batches | Where-Object { $_.Count -ge 5 })
    if ($bulk) { Write-Finding -Level INFO -Category 'Created' -Message ("Created in bulk (environment setup): {0}" -f (($bulk | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')) }
    $setupEnd = if ($bulk) { [datetime]::ParseExact($bulk[-1].Name, 'yyyy-MM-dd HH:mm', $null).AddMinutes(1) } elseif ($buildTime) { $buildTime.AddMinutes(30) } else { [datetime]::MinValue }
    $late = @($created | Where-Object { $_.Time -gt $setupEnd } | Sort-Object Time)
    if ($late) { Write-Finding -Level RED -Category 'Created' -Message ("Created on their own AFTER setup ({0}): {1}" -f $late.Count, (($late | ForEach-Object { '{0} {1}' -f $_.Sam, $_.Time.ToString('MM-dd HH:mm') }) -join ', ')) -Detail 'Nobody on your team made these? Treat them as Red Team: panel X (kick + disable).' }
    else { Write-Finding -Level GREEN -Category 'Created' -Message 'No accounts created after the setup batches.' }
    Write-Finding -Level INFO -Category 'Account' -Message ("{0} domain user accounts, {1} enabled" -f $users.Count, $enabled)
}

# ---------------------------------------------------------------------------
# Security log: privileged group adds listed one by one; everything else summarized
# ---------------------------------------------------------------------------
Write-Section "Security log: accounts created / added to groups (last $RecentDays days)"
$privNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'DnsAdmins', 'Backup Operators', 'Account Operators', 'Server Operators', 'Group Policy Creator Owners', 'Remote Desktop Users', 'Remote Management Users', 'Pre-Windows 2000 Compatible Access')
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4728, 4732, 4756; StartTime = $cutoff } -MaxEvents 2000 -ErrorAction Stop)
    $made = @(); $other = 0
    foreach ($e in ($events | Sort-Object TimeCreated)) {
        $d = Get-CcdcEventData -Record $e
        $who = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
        if ($d['SubjectUserName'] -match '\$$|^ANONYMOUS LOGON$|^-$') { continue }   # Windows itself (domain build, machine setup)
        if ($e.Id -eq 4720) { $made += [pscustomobject]@{ T = $e.TimeCreated.ToString('MM-dd HH:mm'); Who = $who; Name = $d['TargetUserName'] }; continue }
        if ($privNames -contains $d['TargetUserName']) {
            $member = ($d['MemberName'] -replace '^CN=([^,]+),.*$', '$1'); if (-not $member -or $member -eq '-') { $member = $d['MemberSid'] }
            Write-Finding -Level RED -Category 'SecLog' -Message ("{0}  {1} -> {2}  (by {3})" -f $e.TimeCreated.ToString('MM-dd HH:mm'), $member, $d['TargetUserName'], $who)
        } else { $other++ }
    }
    foreach ($g in ($made | Group-Object T, Who)) {
        $lvl = if ($g.Count -ge 5) { 'INFO' } else { 'YELLOW' }
        $first = $g.Group[0]
        $list = ($g.Group | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', '
        if ($g.Count -gt 8) { $list += ", ... +$($g.Count - 8) more" }
        Write-Finding -Level $lvl -Category 'SecLog' -Message ("{0}  {1} account(s) created by {2}: {3}" -f $first.T, $g.Count, $first.Who, $list)
    }
    if ($other) { Write-Finding -Level INFO -Category 'SecLog' -Message "$other add(s) to non-admin groups (not listed)." }
    if (-not $events) { Write-Finding -Level INFO -Category 'SecLog' -Message 'No matching events.' }
} catch {
    Write-Finding -Level INFO -Category 'SecLog' -Message 'No matching events (or Security log not readable / auditing off).'
}

Complete-Ccdc
