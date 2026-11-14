#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Active Directory Domain Services (service: NTDS) info / backup / restore.
.DESCRIPTION
    Backup (default, safe):
      - Users, groups, group membership, OUs, computers, GPO links -> CSV/XML
      - LDIF export of OUs/users/groups (ldifde)  - re-importable
      - SYSVOL copy, domain/forest info, trusts, FSMO, password policy
      - AD Recycle Bin status (enable it! it is the best "undo" for deletes)
    Optional (SENSITIVE - contain every password hash in the domain):
      -IncludeNTDS         ntdsutil IFM copy of ntds.dit + SYSTEM hive
      -SystemStateTarget   wbadmin system state backup to a volume / share (E: or \\host\share)

    The packets score "-50: recovery of AD with hashes". Only use the optional
    switches if you store the result off-box / encrypted, and delete it after.
.EXAMPLE
    .\ActiveDirectory.ps1
    .\ActiveDirectory.ps1 -Action Backup -SystemStateTarget E:
    .\ActiveDirectory.ps1 -Action Restore      # recreates deleted users/groups/OUs + memberships
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force,
    [switch]$IncludeNTDS,
    [string]$SystemStateTarget
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'ActiveDirectory'
    Title        = 'Active Directory Domain Services (Domain Controller)'
    ServiceNames = @('NTDS', 'Kdc', 'Netlogon', 'DFSR', 'IsmServ', 'ADWS')
    Description  = @"
The identity system for the whole Windows network: users, groups, computers,
passwords, Kerberos tickets and Group Policy. Every domain-joined box trusts
this server. NTDS = the directory database (C:\Windows\NTDS\ntds.dit),
Kdc = Kerberos, Netlogon = DC locator / secure channel, DFSR = SYSVOL
replication, ADWS = what the PowerShell AD module talks to (9389).
If red team owns the DC they own every box. Protect it first.
"@
    Ports        = @(
        @{ Port = 53; Proto = 'TCP/UDP'; Use = 'DNS (required by AD)' }
        @{ Port = 88; Proto = 'TCP/UDP'; Use = 'Kerberos' }
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC endpoint mapper' }
        @{ Port = 137; Proto = 'UDP'; Use = 'NetBIOS name' }
        @{ Port = 138; Proto = 'UDP'; Use = 'NetBIOS datagram' }
        @{ Port = 139; Proto = 'TCP'; Use = 'NetBIOS session' }
        @{ Port = 389; Proto = 'TCP/UDP'; Use = 'LDAP' }
        @{ Port = 445; Proto = 'TCP'; Use = 'SMB (SYSVOL/NETLOGON, DRSUAPI)' }
        @{ Port = 464; Proto = 'TCP/UDP'; Use = 'Kerberos password change' }
        @{ Port = 636; Proto = 'TCP'; Use = 'LDAPS' }
        @{ Port = 3268; Proto = 'TCP'; Use = 'Global Catalog' }
        @{ Port = 3269; Proto = 'TCP'; Use = 'Global Catalog SSL' }
        @{ Port = 9389; Proto = 'TCP'; Use = 'AD Web Services (PowerShell AD module)' }
        @{ Port = '49152-65535'; Proto = 'TCP'; Use = 'RPC dynamic (replication, NTDS)' }
    )
    KeyPaths     = @(
        "$env:SystemRoot\NTDS\ntds.dit"
        "$env:SystemRoot\SYSVOL\domain"
        'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    )
    RedTeam      = @(
        'DCSync (Replicating Directory Changes rights) / ntdsutil IFM / shadow copy -> every hash'
        'New hidden admin users, users added to Domain Admins / Enterprise Admins / Administrators / Backup Operators'
        'AdminSDHolder ACL backdoor, SIDHistory injection, golden tickets (krbtgt)'
        'Kerberoasting (users with SPNs) and AS-REP roasting (DONT_REQ_PREAUTH)'
        'GPO edits to push scheduled tasks / startup scripts to every box'
        'Deleting users/OUs that scored services log in with'
    )
    Hardening    = @(
        'Change every privileged password; reset krbtgt TWICE (wait for replication in between)'
        'Enable AD Recycle Bin: Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target <forest>'
        'Remove unknown members of privileged groups (see Info output)'
        'Disable Print Spooler on DCs; require SMB signing; enforce LDAP signing'
        'Run ..\audit\Audit-AD-GPO.ps1 and ..\audit\Audit-Users.ps1 for delegation / roasting / ACL checks'
    )
    Detect       = { (Test-IsDomainController) -and (Test-ServiceInstalled 'NTDS') }
}

$PrivGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Remote Desktop Users'

$Def.InfoExtra = {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    if (-not (Get-Module ActiveDirectory)) { Write-WARN "ActiveDirectory module not available"; return }
    $d = Get-ADDomain; $f = Get-ADForest
    Write-INFO "Domain: $($d.DNSRoot)  NetBIOS: $($d.NetBIOSName)  Mode: $($d.DomainMode)"
    Write-INFO "Forest: $($f.Name)  Mode: $($f.ForestMode)"
    Write-INFO "FSMO: PDC=$($d.PDCEmulator) RID=$($d.RIDMaster) Infra=$($d.InfrastructureMaster) Schema=$($f.SchemaMaster) Naming=$($f.DomainNamingMaster)"
    Write-INFO "DCs: $((Get-ADDomainController -Filter *).HostName -join ', ')"
    $rb = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"'
    if ($rb.EnabledScopes) { Write-OK "AD Recycle Bin enabled" } else { Write-WARN "AD Recycle Bin DISABLED - deleted users cannot be undeleted easily" }
    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
    if ($trusts) { foreach ($t in $trusts) { Write-WARN "Trust: $($t.Name) Direction=$($t.Direction)" } }

    Write-STEP "Privileged group membership"
    foreach ($g in $PrivGroups) {
        $m = Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue
        if ($m) { Write-Plain ("{0,-28} {1}" -f $g, (($m.SamAccountName) -join ', ')) }
    }
    $u = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, whenCreated, PasswordNeverExpires, DoesNotRequirePreAuth, ServicePrincipalName
    Write-INFO "Users: $(@($u).Count) total, $(@($u | Where-Object Enabled).Count) enabled"
    $new = $u | Where-Object { $_.whenCreated -gt (Get-Date).AddHours(-24) }
    foreach ($n in $new) { Write-WARN "Created in last 24h: $($n.SamAccountName) at $($n.whenCreated)" }
    foreach ($n in $u | Where-Object DoesNotRequirePreAuth) { Write-WARN "AS-REP roastable: $($n.SamAccountName)" }
    foreach ($n in $u | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' }) { Write-WARN "Kerberoastable (has SPN): $($n.SamAccountName)" }
    $krb = Get-ADUser krbtgt -Properties PasswordLastSet
    Write-INFO "krbtgt password last set: $($krb.PasswordLastSet)"
    & repadmin /replsummary 2>$null | Select-Object -First 12 | ForEach-Object { Write-Plain $_ }
}

$Def.Backup = {
    param($Dir)
    Import-Module ActiveDirectory -ErrorAction Stop
    $d = Get-ADDomain
    $Dir_obj = Join-Path $Dir 'objects'; New-Item -ItemType Directory $Dir_obj -Force | Out-Null

    $d | Export-Clixml "$Dir\domain.xml"
    Get-ADForest | Export-Clixml "$Dir\forest.xml"
    Get-ADDefaultDomainPasswordPolicy | Export-Clixml "$Dir\passwordpolicy.xml"
    Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | Export-Clixml "$Dir\fgpp.xml"
    Get-ADTrust -Filter * -ErrorAction SilentlyContinue | Export-Clixml "$Dir\trusts.xml"

    Get-ADOrganizationalUnit -Filter * -Properties Description, gPLink, ProtectedFromAccidentalDeletion |
        Select-Object Name, DistinguishedName, Description, gPLink, ProtectedFromAccidentalDeletion | Export-Csv "$Dir_obj\OUs.csv" -NoTypeInformation
    $userProps = 'SamAccountName', 'UserPrincipalName', 'GivenName', 'Surname', 'DisplayName', 'Name', 'Description', 'EmailAddress', 'Title', 'Department', 'Enabled', 'PasswordNeverExpires', 'CannotChangePassword', 'DoesNotRequirePreAuth', 'ServicePrincipalName', 'DistinguishedName', 'whenCreated', 'LastLogonDate', 'MemberOf', 'SID'
    $users = Get-ADUser -Filter * -Properties $userProps
    $users | Select-Object SamAccountName, UserPrincipalName, GivenName, Surname, DisplayName, Name, Description, EmailAddress, Title, Department, Enabled, PasswordNeverExpires, CannotChangePassword, DoesNotRequirePreAuth,
        @{n = 'SPNs'; e = { $_.ServicePrincipalName -join ';' } }, DistinguishedName, whenCreated, LastLogonDate, @{n = 'SID'; e = { $_.SID.Value } } |
        Export-Csv "$Dir_obj\Users.csv" -NoTypeInformation
    Write-OK "Users: $(@($users).Count)"
    $groups = Get-ADGroup -Filter * -Properties Description, ManagedBy
    $groups | Select-Object Name, SamAccountName, GroupScope, GroupCategory, Description, DistinguishedName, @{n = 'SID'; e = { $_.SID.Value } } | Export-Csv "$Dir_obj\Groups.csv" -NoTypeInformation
    $mem = foreach ($g in $groups) {
        foreach ($m in (Get-ADGroupMember $g -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Group = $g.SamAccountName; Member = $m.SamAccountName; MemberClass = $m.objectClass; MemberDN = $m.distinguishedName }
        }
    }
    $mem | Export-Csv "$Dir_obj\GroupMembership.csv" -NoTypeInformation
    Write-OK "Groups: $(@($groups).Count), memberships: $(@($mem).Count)"
    Get-ADComputer -Filter * -Properties OperatingSystem, IPv4Address, whenCreated, ServicePrincipalName |
        Select-Object Name, DNSHostName, OperatingSystem, IPv4Address, Enabled, DistinguishedName, whenCreated | Export-Csv "$Dir_obj\Computers.csv" -NoTypeInformation

    # LDIF (re-importable with ldifde -i). No passwords are included.
    if (Test-CommandExists ldifde) {
        & ldifde -f "$Dir\ldif_OUs.ldf" -d $d.DistinguishedName -r "(objectClass=organizationalUnit)" -l "objectClass,ou,description" 2>&1 | Out-Null
        & ldifde -f "$Dir\ldif_users.ldf" -d $d.DistinguishedName -r "(&(objectCategory=person)(objectClass=user))" -l "objectClass,sAMAccountName,userPrincipalName,givenName,sn,displayName,description,mail,title,department" 2>&1 | Out-Null
        & ldifde -f "$Dir\ldif_groups.ldf" -d $d.DistinguishedName -r "(objectClass=group)" -l "objectClass,sAMAccountName,description,groupType,member" 2>&1 | Out-Null
        Write-OK "LDIF exports (OUs, users, groups)"
    }

    # ACL baseline of critical objects (AdminSDHolder + domain root) to diff later
    $acl = foreach ($dn in @($d.DistinguishedName, "CN=AdminSDHolder,CN=System,$($d.DistinguishedName)")) {
        (Get-Acl "AD:\$dn").Access | Select-Object @{n = 'Object'; e = { $dn } }, IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType, InheritanceType
    }
    $acl | Export-Csv "$Dir\ACL_baseline_domainroot_adminsdholder.csv" -NoTypeInformation

    Copy-Tree "$env:SystemRoot\SYSVOL\domain" (Join-Path $Dir 'SYSVOL_domain') 'SYSVOL (policies + scripts)' | Out-Null
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' (Join-Path $Dir 'reg\NTDS_Parameters.reg') | Out-Null
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' (Join-Path $Dir 'reg\Netlogon_Parameters.reg') | Out-Null

    if ($IncludeNTDS) {
        Write-WARN "Creating IFM copy of ntds.dit - this file contains EVERY password hash. Move it off-box and delete it."
        $ifm = Join-Path $Dir 'IFM_SENSITIVE'
        & ntdsutil "activate instance ntds" "ifm" "create full `"$ifm`"" quit quit 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Plain $_ }
    }
    if ($SystemStateTarget) {
        if (Test-CommandExists wbadmin) {
            Write-INFO "Running wbadmin system state backup to $SystemStateTarget (takes 10-30 min)..."
            & wbadmin start systemstatebackup "-backupTarget:$SystemStateTarget" -quiet
        } else { Write-WARN "wbadmin missing: Install-WindowsFeature Windows-Server-Backup" }
    }
}

$Def.Restore = {
    param($Dir)
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-INFO "Step 1: try the AD Recycle Bin first (keeps SIDs, passwords, memberships)"
    $deleted = Get-ADObject -Filter 'isDeleted -eq $true -and (objectClass -eq "user" -or objectClass -eq "group" -or objectClass -eq "organizationalUnit")' -IncludeDeletedObjects -Properties whenChanged, lastKnownParent, samAccountName -ErrorAction SilentlyContinue |
        Where-Object { $_.whenChanged -gt (Get-Date).AddDays(-2) }
    foreach ($o in $deleted) {
        if (Confirm-Action "Undelete $($o.samAccountName) ($($o.ObjectClass)) deleted $($o.whenChanged)?") {
            try { Restore-ADObject -Identity $o.ObjectGUID -ErrorAction Stop; Write-OK "Undeleted $($o.samAccountName)" } catch { Write-WARN "$_" }
        }
    }

    Write-INFO "Step 2: recreate anything still missing from the CSV backup (new SIDs, random password, DISABLED until you set one)"
    $ous = Import-Csv "$Dir\objects\OUs.csv" | Sort-Object { ($_.DistinguishedName -split ',').Count }
    foreach ($ou in $ous) {
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($ou.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
            $parent = $ou.DistinguishedName.Substring($ou.DistinguishedName.IndexOf(',') + 1)
            try { New-ADOrganizationalUnit -Name $ou.Name -Path $parent -Description $ou.Description -ErrorAction Stop; Write-OK "Recreated OU $($ou.DistinguishedName)" } catch { Write-WARN "OU $($ou.Name): $_" }
        }
    }
    foreach ($g in Import-Csv "$Dir\objects\Groups.csv") {
        if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($g.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            $path = $g.DistinguishedName.Substring($g.DistinguishedName.IndexOf(',') + 1)
            try { New-ADGroup -Name $g.Name -SamAccountName $g.SamAccountName -GroupScope $g.GroupScope -GroupCategory $g.GroupCategory -Path $path -Description $g.Description -ErrorAction Stop; Write-OK "Recreated group $($g.SamAccountName)" } catch { Write-WARN "$($g.SamAccountName): $_" }
        }
    }
    $recreated = @()
    foreach ($u in Import-Csv "$Dir\objects\Users.csv") {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            $path = $u.DistinguishedName.Substring($u.DistinguishedName.IndexOf(',') + 1)
            $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
            $p = @{ Name = $u.Name; SamAccountName = $u.SamAccountName; Path = $path; AccountPassword = $pw; Enabled = $false }
            if ($u.UserPrincipalName) { $p.UserPrincipalName = $u.UserPrincipalName }
            if ($u.GivenName) { $p.GivenName = $u.GivenName }; if ($u.Surname) { $p.Surname = $u.Surname }
            if ($u.DisplayName) { $p.DisplayName = $u.DisplayName }; if ($u.Description) { $p.Description = $u.Description }
            if ($u.EmailAddress) { $p.EmailAddress = $u.EmailAddress }
            try { New-ADUser @p -ErrorAction Stop; $recreated += $u.SamAccountName; Write-OK "Recreated user $($u.SamAccountName) (DISABLED)" } catch { Write-WARN "$($u.SamAccountName): $_" }
        }
    }
    Write-INFO "Step 3: re-add missing group memberships (does NOT remove extra members - review those by hand)"
    foreach ($m in Import-Csv "$Dir\objects\GroupMembership.csv") {
        try {
            $cur = Get-ADGroupMember $m.Group -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
            if ($cur -notcontains $m.Member) { Add-ADGroupMember $m.Group -Members $m.Member -ErrorAction Stop; Write-OK "Re-added $($m.Member) -> $($m.Group)" }
        } catch {}
    }
    Write-STEP "Members that are in privileged groups NOW but were NOT in the backup"
    $bk = Import-Csv "$Dir\objects\GroupMembership.csv"
    foreach ($g in $PrivGroups) {
        $now = Get-ADGroupMember $g -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        $was = $bk | Where-Object Group -eq $g | Select-Object -ExpandProperty Member
        foreach ($x in $now | Where-Object { $was -notcontains $_ }) { Write-CRIT "$g has NEW member '$x' - remove with: Remove-ADGroupMember '$g' '$x'" }
    }
    if ($recreated) { Write-WARN "Set passwords + enable: $($recreated -join ', ')  (Set-ADAccountPassword / Enable-ADAccount)" }
    Write-INFO "SYSVOL / GPO restore: use GroupPolicy.ps1 -Action Restore"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
