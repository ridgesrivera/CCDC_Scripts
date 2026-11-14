#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Group Policy (GPOs in SYSVOL + AD) info / backup / restore. Run on a DC.
.EXAMPLE
    .\GroupPolicy.ps1 -Action Restore                       # restore ALL GPOs from latest backup
    .\GroupPolicy.ps1 -Action Restore -GpoName "Default Domain Policy"
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [string]$GpoName
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'GroupPolicy'
    Title        = 'Group Policy (GPOs)'
    ServiceNames = @('gpsvc')
    Description  = @"
Group Policy pushes settings from the DC to every domain machine:
password policy, firewall rules, scheduled tasks, startup scripts, software,
local admin membership, etc. A GPO = an AD object (CN={GUID},CN=Policies,
CN=System) + files in SYSVOL\<domain>\Policies\{GUID}. Clients pull them
over SMB (445) + LDAP (389) every ~90 min (gpupdate /force to do it now).
Red team LOVES GPOs: one edit = code execution on every box.
"@
    Ports        = @(
        @{ Port = 445; Proto = 'TCP'; Use = 'SMB - clients read SYSVOL' }
        @{ Port = 389; Proto = 'TCP/UDP'; Use = 'LDAP - clients find GPO links' }
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC (remote gpupdate / GPMC)' }
    )
    KeyPaths     = @("$env:SystemRoot\SYSVOL\domain\Policies", "$env:SystemRoot\SYSVOL\domain\scripts")
    RedTeam      = @(
        'Immediate Scheduled Task in a GPO (Preferences\ScheduledTasks\ScheduledTasks.xml)'
        'Startup/logon scripts in Machine\Scripts or User\Scripts'
        'Restricted Groups / Groups.xml adding attacker to local Administrators'
        'GPP passwords (cpassword in Groups.xml etc - decryptable)'
        'Disabling Defender / firewall / audit via policy'
        'New GPO linked at domain root with high link order'
    )
    Hardening    = @(
        'Diff GPO modification times against competition start (Info output)'
        'grep SYSVOL for cpassword, ScheduledTasks.xml, .bat/.ps1/.exe'
        'Only Domain Admins / Group Policy Creator Owners should edit GPOs'
    )
    Detect       = { (Test-IsDomainController) -and (Get-Module -ListAvailable GroupPolicy) }
}

$Def.InfoExtra = {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $start = (Get-Date).AddHours(-12)
    foreach ($g in Get-GPO -All | Sort-Object ModificationTime -Descending) {
        $line = "{0,-45} modified {1}  status {2}" -f $g.DisplayName, $g.ModificationTime, $g.GpoStatus
        if ($g.ModificationTime -gt $start) { Write-WARN $line } else { Write-Plain $line }
    }
    $sysvol = "$env:SystemRoot\SYSVOL\domain\Policies"
    Write-STEP "Suspicious content in SYSVOL"
    Get-ChildItem $sysvol -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ScheduledTasks\.xml|Groups\.xml|scripts\.ini|psscripts\.ini|\.(bat|cmd|ps1|vbs|exe|dll)$' } |
        ForEach-Object { Write-WARN $_.FullName.Replace($sysvol, '') }
    Get-ChildItem $sysvol -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword="[^"]+' -List | ForEach-Object { Write-CRIT "GPP cpassword in $($_.Path)" }
}

$Def.Backup = {
    param($Dir)
    Import-Module GroupPolicy -ErrorAction Stop
    $gpoDir = Join-Path $Dir 'GPOs'; New-Item -ItemType Directory $gpoDir -Force | Out-Null
    $r = Backup-GPO -All -Path $gpoDir -Comment "CCDC $($script:CCDCStamp)" -ErrorAction Stop
    Write-OK "Backup-GPO: $(@($r).Count) GPOs -> GPOs\"
    $r | Select-Object DisplayName, GpoId, Id | Export-Csv "$Dir\gpo_backup_index.csv" -NoTypeInformation
    Get-GPOReport -All -ReportType Html -Path "$Dir\AllGPOs_report.html" -ErrorAction SilentlyContinue
    # Links (Backup-GPO does NOT save links)
    $links = foreach ($ou in (@((Get-ADDomain).DistinguishedName) + @((Get-ADOrganizationalUnit -Filter *).DistinguishedName))) {
        $inh = Get-GPInheritance -Target $ou -ErrorAction SilentlyContinue
        foreach ($l in $inh.GpoLinks) { [pscustomobject]@{ Target = $ou; DisplayName = $l.DisplayName; GpoId = $l.GpoId; Enabled = $l.Enabled; Enforced = $l.Enforced; Order = $l.Order } }
    }
    $links | Export-Csv "$Dir\gpo_links.csv" -NoTypeInformation
    Write-OK "GPO links: $(@($links).Count)"
    # WMI filters + permissions
    Get-GPO -All | ForEach-Object { $g = $_; Get-GPPermission -Guid $g.Id -All | Select-Object @{n = 'GPO'; e = { $g.DisplayName } }, @{n = 'Trustee'; e = { $_.Trustee.Name } }, Permission } |
        Export-Csv "$Dir\gpo_permissions.csv" -NoTypeInformation
    Copy-Tree "$env:SystemRoot\SYSVOL\domain\scripts" (Join-Path $Dir 'SYSVOL_scripts') 'NETLOGON scripts' | Out-Null
}

$Def.Restore = {
    param($Dir)
    Import-Module GroupPolicy -ErrorAction Stop
    $gpoDir = Join-Path $Dir 'GPOs'
    $idx = Import-Csv "$Dir\gpo_backup_index.csv"
    if ($GpoName) { $idx = $idx | Where-Object DisplayName -eq $GpoName }
    foreach ($g in $idx) {
        try {
            if (Get-GPO -Guid $g.GpoId -ErrorAction SilentlyContinue) {
                Restore-GPO -BackupId $g.Id -Path $gpoDir -ErrorAction Stop | Out-Null
            } else {
                Import-GPO -BackupId $g.Id -Path $gpoDir -TargetName $g.DisplayName -CreateIfNeeded -ErrorAction Stop | Out-Null
            }
            Write-OK "Restored GPO $($g.DisplayName)"
        } catch { Write-WARN "$($g.DisplayName): $_" }
    }
    # Re-create links that are missing
    foreach ($l in Import-Csv "$Dir\gpo_links.csv") {
        if ($GpoName -and $l.DisplayName -ne $GpoName) { continue }
        $have = (Get-GPInheritance -Target $l.Target -ErrorAction SilentlyContinue).GpoLinks | Where-Object DisplayName -eq $l.DisplayName
        if (-not $have) {
            try { New-GPLink -Name $l.DisplayName -Target $l.Target -LinkEnabled $(if ($l.Enabled -eq 'True') { 'Yes' } else { 'No' }) -ErrorAction Stop | Out-Null; Write-OK "Relinked $($l.DisplayName) -> $($l.Target)" } catch { Write-WARN "$_" }
        }
    }
    Write-STEP "GPOs that exist NOW but were not in the backup (possible red team GPOs)"
    $known = (Import-Csv "$Dir\gpo_backup_index.csv").GpoId
    Get-GPO -All | Where-Object { $known -notcontains $_.Id.ToString() } | ForEach-Object { Write-CRIT "NEW GPO: $($_.DisplayName) {$($_.Id)} created $($_.CreationTime)  -> Remove-GPO -Guid $($_.Id)" }
    Write-INFO "Then: gpupdate /force on clients (or Invoke-GPUpdate -Computer X -Force)"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
