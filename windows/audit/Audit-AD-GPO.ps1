<#
.SYNOPSIS
    Audit-AD-GPO - domain-level backdoors: GPOs, root ACLs, DCSync, delegation, krbtgt. READ-ONLY. DC ONLY.

.DESCRIPTION
    PURPOSE
      Red Team with Domain Admin creds rarely stops at adding a user. They
      leave domain-level persistence that survives password resets:
        * a new or edited GPO that pushes a scheduled task / startup script
        * an extra ACE on the domain root (GenericAll / WriteDacl)
        * DCSync rights granted to a normal user (dump every hash any time)
        * unconstrained delegation on a box they control
        * an old krbtgt password (golden tickets keep working until it is reset twice)

    WHAT IT READS
      LDAP (domain root ACL, AdminSDHolder ACL, groupPolicyContainer objects,
      computers/users with delegation flags, krbtgt pwdLastSet), SYSVOL file
      timestamps, and Get-GPO if the GroupPolicy module exists.

    WHAT IT CHANGES nothing
    HOW TO UNDO     nothing to undo. See docs\incident-response.md for fixing findings.

    MANUAL EQUIVALENT
      Get-GPO -All | sort ModificationTime -Descending | select -First 10 DisplayName,ModificationTime
      (Get-Acl "AD:\DC=great,DC=local").Access | ? { $_.ObjectType -match '1131f6a' }   # DCSync
      Get-ADComputer -Filter {TrustedForDelegation -eq $true}
      Get-ADUser krbtgt -Properties PasswordLastSet
      dir \\great.local\SYSVOL\great.local\Policies -Recurse | sort LastWriteTime | select -Last 20

.PARAMETER RecentDays
    GPO/SYSVOL changes newer than this are flagged. Default 7.

.EXAMPLE
    .\Audit-AD-GPO.ps1 -OutFile C:\ccdc\reports\ad.csv
#>
[CmdletBinding()]
param(
    [int]$RecentDays = 7,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-AD-GPO' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath
$cutoff = (Get-Date).AddDays(-$RecentDays)

if (-not (Test-CcdcIsDC)) {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'This is not a domain controller. Run this on the DC (trex in Great Cretaceous).'
    Complete-Ccdc
    return
}

$rootDse  = [ADSI]'LDAP://RootDSE'
$domainDN = [string]$rootDse.defaultNamingContext
$dnsName  = ($domainDN -replace ',DC=', '.') -replace '^DC=', ''

function Search-Ldap([string]$Filter, [string[]]$Props, [string]$Base = $domainDN) {
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = [ADSI]"LDAP://$Base"; $s.Filter = $Filter; $s.PageSize = 1000
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s.FindAll()
}
function Get-Prop($r, $n) { if ($r.Properties[$n].Count) { return $r.Properties[$n][0] } return $null }
function Resolve-Sid($ref) {
    # ACL entries come back as SIDs; turn them into DOMAIN\name when possible.
    try { return $ref.Translate([System.Security.Principal.NTAccount]).Value } catch { return $ref.Value }
}

# Principals that legitimately hold powerful rights on the domain root.
$expectedPrincipals = '(?i)(\\Domain Admins|\\Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|\\Domain Controllers|\\Enterprise Domain Controllers|ENTERPRISE DOMAIN CONTROLLERS|\\Read-only Domain Controllers|\\Enterprise Read-only Domain Controllers|\\Key Admins|\\Enterprise Key Admins|NT AUTHORITY\\SELF|CREATOR OWNER|\\Cloneable Domain Controllers|NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS)$'
# NOTE: Everyone / Authenticated Users are deliberately NOT here - they normally
# only have read rights, so if they hold GenericAll/WriteDacl we WANT a RED.

# ---------------------------------------------------------------------------
Write-Section 'GPOs (newest first)'
# ---------------------------------------------------------------------------
$gpos = Search-Ldap '(objectClass=groupPolicyContainer)' @('displayName', 'whenChanged', 'whenCreated', 'name', 'gPCFileSysPath')
foreach ($g in ($gpos | Sort-Object { [datetime](Get-Prop $_ 'whenchanged') } -Descending)) {
    $name = Get-Prop $g 'displayname'; $changed = [datetime](Get-Prop $g 'whenchanged'); $created = [datetime](Get-Prop $g 'whencreated')
    $lvl = 'INFO'
    if ($created -gt $cutoff) { $lvl = 'RED' } elseif ($changed -gt $cutoff) { $lvl = 'YELLOW' }
    Write-Finding -Level $lvl -Category 'GPO' -Message ("{0,-40} changed {1:yyyy-MM-dd HH:mm}  created {2:yyyy-MM-dd}" -f $name, $changed, $created) -Detail (Get-Prop $g 'name')
}
# Where GPOs are linked (gPLink on domain root and OUs).
foreach ($ou in (Search-Ldap '(gPLink=*)' @('distinguishedName', 'gPLink'))) {
    Write-Finding -Level INFO -Category 'GPOLink' -Message ("{0} links {1}" -f (Get-Prop $ou 'distinguishedname'), ((Get-Prop $ou 'gplink') -replace '\[LDAP://cn=|,cn=policies[^\]]*\]', ' ').Trim())
}

Write-Section "SYSVOL files changed in the last $RecentDays days"
# GPO payloads (ScheduledTasks.xml, scripts.ini, .ps1/.bat, Groups.xml) live here.
$sysvol = "\\$dnsName\SYSVOL\$dnsName\Policies"
$hits = Get-ChildItem $sysvol -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object LastWriteTime -Descending | Select-Object -First 40
foreach ($f in $hits) {
    $lvl = if ($f.Name -match '(?i)^(ScheduledTasks\.xml|scripts\.ini|psscripts\.ini|Groups\.xml|Services\.xml)$|\.(ps1|bat|cmd|vbs|exe|dll)$') { 'RED' } else { 'YELLOW' }
    Write-Finding -Level $lvl -Category 'SYSVOL' -Message ("{0:yyyy-MM-dd HH:mm}  {1}" -f $f.LastWriteTime, $f.FullName.Replace($sysvol, '...'))
}
if (-not $hits) { Write-Finding -Level GREEN -Category 'SYSVOL' -Message 'No recent SYSVOL changes.' }
# Groups.xml with cpassword = GPP password (MS14-025) - anyone can decrypt it.
Get-ChildItem $sysvol -Recurse -Include Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml -ErrorAction SilentlyContinue |
    Select-String -Pattern 'cpassword="[^"]+' -List | ForEach-Object {
        Write-Finding -Level RED -Category 'GPP' -Message "GPP cpassword found (decryptable by any user): $($_.Path)"
    }

# ---------------------------------------------------------------------------
Write-Section 'Domain root ACL: DCSync and dangerous delegated rights'
# ---------------------------------------------------------------------------
$replGuids = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
}
$dangerous = 'GenericAll|WriteDacl|WriteOwner|GenericWrite'
function Test-Acl([string]$dn, [string]$label) {
    $obj = [ADSI]"LDAP://$dn"
    $rules = $obj.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
    $found = 0
    foreach ($r in $rules) {
        if ($r.AccessControlType -ne 'Allow') { continue }
        $who = Resolve-Sid $r.IdentityReference
        $rights = [string]$r.ActiveDirectoryRights
        $guid = ([string]$r.ObjectType).ToLower()
        if ($replGuids.ContainsKey($guid)) {
            $ok = $who -match '(?i)\\Domain Controllers$|ENTERPRISE DOMAIN CONTROLLERS|BUILTIN\\Administrators|\\Read-only Domain Controllers|\\Enterprise Read-only Domain Controllers'
            if (-not $ok) { $found++; Write-Finding -Level RED -Category 'DCSync' -Message "$who has $($replGuids[$guid]) on $label - can DCSync (dump all hashes)" }
            continue
        }
        if ($rights -match $dangerous -and $who -notmatch $expectedPrincipals) {
            $found++
            Write-Finding -Level RED -Category 'RootACL' -Message ("{0} has {1} on {2}" -f $who, $rights, $label) -Detail ("inherit={0} objectType={1}" -f $r.InheritanceType, $guid)
        }
    }
    if ($found -eq 0) { Write-Finding -Level GREEN -Category 'RootACL' -Message "No unexpected DCSync/GenericAll/WriteDacl holders on $label" }
}
Test-Acl $domainDN 'domain root'
Write-Section 'AdminSDHolder ACL (copied onto every protected admin account hourly)'
Test-Acl "CN=AdminSDHolder,CN=System,$domainDN" 'AdminSDHolder'

# ---------------------------------------------------------------------------
Write-Section 'Unconstrained delegation'
# ---------------------------------------------------------------------------
# UAC 0x80000 TRUSTED_FOR_DELEGATION. DCs (primaryGroupID 516) have it by design.
$deleg = Search-Ldap '(userAccountControl:1.2.840.113556.1.4.803:=524288)' @('sAMAccountName', 'primaryGroupID', 'objectClass')
$n = 0
foreach ($d in $deleg) {
    if ([int](Get-Prop $d 'primarygroupid') -eq 516) { continue }
    $n++
    Write-Finding -Level RED -Category 'Delegation' -Message ("{0} trusted for UNCONSTRAINED delegation" -f (Get-Prop $d 'samaccountname')) -Detail 'Any admin who connects to it leaves a reusable TGT.'
}
if ($n -eq 0) { Write-Finding -Level GREEN -Category 'Delegation' -Message 'Only DCs have unconstrained delegation.' }
foreach ($d in (Search-Ldap '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' @('sAMAccountName'))) {
    Write-Finding -Level YELLOW -Category 'Delegation' -Message ("{0} has resource-based constrained delegation configured (RBCD) - verify" -f (Get-Prop $d 'samaccountname'))
}

# ---------------------------------------------------------------------------
Write-Section 'krbtgt password age'
# ---------------------------------------------------------------------------
$k = Search-Ldap '(sAMAccountName=krbtgt)' @('pwdLastSet')
if ($k.Count) {
    $set = [datetime]::FromFileTime([int64](Get-Prop $k[0] 'pwdlastset'))
    $age = [int]((Get-Date) - $set).TotalDays
    $lvl = if ($age -gt 180) { 'YELLOW' } else { 'GREEN' }
    Write-Finding -Level $lvl -Category 'krbtgt' -Message "krbtgt password last set $($set.ToString('yyyy-MM-dd')) ($age days ago)" -Detail 'If Red Team had DA, golden tickets work until krbtgt is reset TWICE (wait for replication between resets). Coordinate - see docs\incident-response.md.'
}

Complete-Ccdc
