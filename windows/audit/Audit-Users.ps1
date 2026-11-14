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
      Nothing to undo. To act on findings use harden\Disable-Accounts.ps1 and
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
Write-Section 'Privileged local/builtin groups'
foreach ($g in @('Administrators', 'Remote Desktop Users', 'Backup Operators', 'Remote Management Users')) {
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

    $privGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'DnsAdmins',
                    'Backup Operators', 'Account Operators', 'Server Operators', 'Print Operators',
                    'Remote Desktop Users', 'Group Policy Creator Owners')
    $privMembers = @{}   # sAMAccountName -> list of groups (used for adminCount check below)
    foreach ($gName in $privGroups) {
        $g = Search-Ldap -Filter "(&(objectClass=group)(sAMAccountName=$gName))" -Properties @('distinguishedName')
        if ($g.Count -eq 0) { continue }
        $gDN = Get-Prop $g[0] 'distinguishedname'
        # 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN -> RECURSIVE membership (nested groups too).
        $members = Search-Ldap -Filter "(&(|(objectClass=user)(objectClass=computer))(memberOf:1.2.840.113556.1.4.1941:=$gDN))" -Properties $userProps
        if ($members.Count -eq 0) { Write-Finding -Level GREEN -Category 'DomainGroup' -Message "$gName : (empty)"; continue }
        foreach ($m in $members) {
            $sam = [string](Get-Prop $m 'samaccountname')
            $uac = [int](Get-Prop $m 'useraccountcontrol')
            if (-not $privMembers.ContainsKey($sam)) { $privMembers[$sam] = @() }
            $privMembers[$sam] += $gName
            $state = if ($uac -band $UAC_DISABLED) { 'disabled' } else { 'ENABLED' }
            $lvl = 'YELLOW'
            if ($gName -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')) {
                $lvl = if (Test-Expected $sam) { 'GREEN' } else { 'RED' }
            }
            if ($gName -eq 'DnsAdmins' -or $gName -eq 'Schema Admins' -or $gName -eq 'Enterprise Admins') {
                if (-not (Test-Expected $sam)) { $lvl = 'RED' }   # these should be (nearly) empty
            }
            if ($uac -band $UAC_DISABLED) { $lvl = 'INFO' }
            Write-Finding -Level $lvl -Category 'DomainGroup' -Message ("{0,-22} <- {1,-20} {2}" -f $gName, $sam, $state)
        }
    }

    # One pass over all users for the per-account checks.
    Write-Section 'Domain account risk checks'
    $users = Search-Ldap -Filter '(&(objectCategory=person)(objectClass=user))' -Properties $userProps
    $enabled = 0
    foreach ($u in $users) {
        $sam = [string](Get-Prop $u 'samaccountname')
        $uac = [int](Get-Prop $u 'useraccountcontrol')
        $isEnabled = -not ($uac -band $UAC_DISABLED)
        if ($isEnabled) { $enabled++ }

        if ($uac -band $UAC_PASSWD_NOTREQD) {
            Write-Finding -Level RED -Category 'Account' -Message "$sam : PASSWD_NOTREQD set (account may have an empty password)"
        }
        if ($uac -band $UAC_DONT_REQ_PREAUTH) {
            Write-Finding -Level RED -Category 'ASREPRoast' -Message "$sam : Kerberos pre-auth NOT required -> AS-REP roastable" -Detail 'Fix: Set-ADAccountControl <user> -DoesNotRequirePreAuth $false'
        }
        if ($isEnabled -and ($uac -band $UAC_DONT_EXPIRE_PASSWD)) {
            Write-Finding -Level YELLOW -Category 'PwNeverExpires' -Message "$sam : password never expires"
        }
        if (($uac -band $UAC_TRUSTED_FOR_DELEG) -and $sam -notmatch '\$$') {
            Write-Finding -Level RED -Category 'Delegation' -Message "$sam : user trusted for UNCONSTRAINED delegation"
        }
        $spns = $u.Properties['serviceprincipalname']
        if ($spns.Count -gt 0 -and $sam -ne 'krbtgt') {
            $lvl = if ($privMembers.ContainsKey($sam)) { 'RED' } else { 'YELLOW' }
            Write-Finding -Level $lvl -Category 'Kerberoast' -Message "$sam : has SPN -> Kerberoastable$(if ($lvl -eq 'RED') { ' AND privileged' })" -Detail (($spns | Select-Object -First 3) -join '; ')
        }
        foreach ($field in @('description', 'info')) {
            $val = [string](Get-Prop $u $field)
            if ($val -and $val -match $pwRegex) {
                Write-Finding -Level RED -Category 'PwInDescription' -Message "$sam : '$field' field may contain a password (shown on screen only)"
                Write-Host "       ${field}: $val" -ForegroundColor DarkYellow   # screen only - never logged/reported
            }
        }
        $created = Get-Prop $u 'whencreated'
        $changed = Get-Prop $u 'whenchanged'
        if ($created -and [datetime]$created -gt $cutoff) {
            Write-Finding -Level RED -Category 'Recent' -Message "$sam : CREATED $created (within $RecentDays days)"
        } elseif ($changed -and [datetime]$changed -gt $cutoff -and $isEnabled) {
            Write-Finding -Level INFO -Category 'Recent' -Message "$sam : modified $changed"
        }
        if ([int](Get-Prop $u 'admincount') -eq 1) {
            if ($privMembers.ContainsKey($sam)) {
                Write-Finding -Level INFO -Category 'AdminSDHolder' -Message "$sam : adminCount=1 (protected; in $($privMembers[$sam] -join ', '))"
            } else {
                Write-Finding -Level YELLOW -Category 'AdminSDHolder' -Message "$sam : adminCount=1 but NOT in a privileged group now (former admin? check its ACL)"
            }
        }
    }
    Write-Finding -Level INFO -Category 'Account' -Message ("{0} domain user accounts, {1} enabled" -f $users.Count, $enabled)
}

# ---------------------------------------------------------------------------
# Security log: recent account creation / group adds (works local + domain)
# ---------------------------------------------------------------------------
Write-Section "Security log: account created / added to group (last $RecentDays days)"
$evIds = @{ 4720 = 'user created'; 4728 = 'added to global group'; 4732 = 'added to local group'; 4756 = 'added to universal group' }
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @($evIds.Keys); StartTime = $cutoff } -MaxEvents 200 -ErrorAction Stop
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $who  = "$($data['SubjectDomainName'])\$($data['SubjectUserName'])"
        $what = if ($e.Id -eq 4720) { $data['TargetUserName'] } else { "$($data['MemberName']) -> $($data['TargetUserName'])" }
        Write-Finding -Level YELLOW -Category 'SecLog' -Message ("{0}  {1}: {2}  (by {3})" -f $e.TimeCreated, $evIds[$e.Id], $what, $who)
    }
} catch {
    Write-Finding -Level INFO -Category 'SecLog' -Message 'No matching events (or Security log not readable / auditing off).'
}

Complete-Ccdc
