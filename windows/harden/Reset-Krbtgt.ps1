<#
.SYNOPSIS
    Reset-Krbtgt - reset the krbtgt password (run it TWICE, with a pause) to kill golden tickets. CHANGES STATE. DC only.

.DESCRIPTION
    PURPOSE
      Every Kerberos ticket in the domain is signed with the krbtgt account's
      key. An attacker who dumped the domain hashes (DCSync, ntds.dit copy,
      Zerologon) can forge tickets for ANY user, forever, no matter how many
      admin passwords you rotate. That is a "golden ticket", and it is what
      "domain-wide persistence" cost 1,000 points for at Qualifiers.

      The only fix is changing the krbtgt key. AD remembers the current AND
      the previous key, so one reset is not enough: the stolen key is still
      accepted as "previous". The second reset pushes it out.

    THE PROCEDURE
      1. Remove how they got in first (rogue admins, DCSync rights, GPO edits),
         otherwise they simply dump the new key.
      2. Run this script                     -> reset #1
      3. Wait: single DC 10+ minutes; several DCs until replication is clean
         (the script shows repadmin /replsummary and can force a sync).
      4. Run this script again               -> reset #2
      5. Rotate every admin password (harden\Rotate-Passwords.ps1 -Group "Domain Admins").

    WHAT BREAKS
      After reset #2 every ticket issued before reset #1 is invalid. Machines
      and services simply ask for new ones; a few may need a restart or a
      re-logon. Doing both resets back to back (no wait) on a multi-DC domain
      can break replication and secure channels: the script refuses to do
      that unless you insist.

    WHAT IT READS    krbtgt (pwdLastSet, key version), list of DCs, replication summary
    WHAT IT CHANGES  the krbtgt password (random; the KDC derives new keys from it).
                     The password is never shown or stored - nobody ever needs it.
    HOW TO UNDO      cannot be undone (and does not need to be).

    MANUAL EQUIVALENT
      Get-ADUser krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber'
      Set-ADAccountPassword krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
      repadmin /replsummary ; repadmin /syncall /AdeP
      Microsoft's New-KrbtgtKeys.ps1 does the same with more checks.

.PARAMETER MinMinutesBetween
    Refuse a reset if the previous one was more recent than this. Default 10.

.PARAMETER IgnoreWait
    Allow the reset even though the previous one was very recent (single-DC labs only).

.EXAMPLE
    .\Reset-Krbtgt.ps1 -WhatIf
.EXAMPLE
    .\Reset-Krbtgt.ps1          # reset #1 ... wait ... run again for reset #2
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(0, 1440)][int]$MinMinutesBetween = 10,
    [switch]$IgnoreWait,
    [switch]$Force,
    [string]$ConfigPath          # accepted so the launcher can pass it; not used
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Reset-Krbtgt'
if (-not (Test-CcdcIsDC)) {
    Write-Finding -Level RED -Category 'Setup' -Message 'This is not a domain controller. Run it on a DC (preferably the PDC emulator: netdom query fsmo).'
    Complete-Ccdc; return
}

function Get-KrbtgtState {
    $dn = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
    $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn", '(&(objectClass=user)(sAMAccountName=krbtgt))')
    foreach ($p in 'pwdLastSet', 'msDS-KeyVersionNumber', 'distinguishedName') { [void]$s.PropertiesToLoad.Add($p) }
    $r = $s.FindOne()
    if (-not $r) { throw 'krbtgt account not found' }
    return [pscustomobject]@{
        DN      = [string]$r.Properties['distinguishedname'][0]
        PwdSet  = [datetime]::FromFileTime([int64]$r.Properties['pwdlastset'][0])
        Kvno    = $(if ($r.Properties['msds-keyversionnumber'].Count -gt 0) { [int]$r.Properties['msds-keyversionnumber'][0] } else { 0 })
        Entry   = $r.GetDirectoryEntry()
    }
}

Write-Section 'Current state'
$before = Get-KrbtgtState
$ageMin = [int]((Get-Date) - $before.PwdSet).TotalMinutes
Write-Finding -Level INFO -Category 'krbtgt' -Message ("password last set {0} ({1}), key version {2}" -f $before.PwdSet.ToString('yyyy-MM-dd HH:mm:ss'), $(if ($ageMin -lt 1440) { "$ageMin min ago" } else { "$([int]($ageMin / 1440)) days ago" }), $before.Kvno)

# Which reset is this? Our own log remembers resets done with this script.
$history = Join-Path $script:CcdcLogRoot 'krbtgt_resets.txt'
$previous = @(); if (Test-Path $history) { $previous = @(Get-Content $history | Where-Object { $_ }) }
$recent = @($previous | Where-Object { try { ([datetime]$_) -gt (Get-Date).AddHours(-24) } catch { $false } })
$number = $recent.Count + 1
if ($recent.Count -ge 2) { Write-Finding -Level GREEN -Category 'krbtgt' -Message 'Two resets were already done in the last 24 hours with this script. A third is only needed if the domain was compromised AGAIN since.' }

# Domain controllers and replication health.
$dcs = @()
try {
    $cfg = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
    $ds = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$cfg", '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))')
    [void]$ds.PropertiesToLoad.Add('dNSHostName')
    $dcs = @($ds.FindAll() | ForEach-Object { [string]$_.Properties['dnshostname'][0] })
} catch { $null = $_ }
Write-Finding -Level INFO -Category 'Domain' -Message ("{0} domain controller(s): {1}" -f $dcs.Count, ($dcs -join ', '))
if ($dcs.Count -gt 1) {
    Write-Section 'Replication (must be clean before reset #2)'
    $rep = @(& repadmin.exe /replsummary 2>&1)
    foreach ($line in $rep) { if ("$line".Trim()) { Write-Host "    $line" -ForegroundColor DarkGray } }
    # Data rows look like:  TREX   10m:05s   0 /   5    0   -> "fails / total". Any non-zero fails count is a problem.
    if (@($rep | Where-Object { "$_" -match '\s[1-9]\d*\s*/\s*\d+\s' }).Count -gt 0) {
        Write-Finding -Level RED -Category 'Replication' -Message 'Replication shows failures. Fix them before reset #2, or the DCs will disagree about the krbtgt key.' -Detail 'repadmin /showrepl ; dcdiag /test:replications'
    }
}

Write-Section ("Reset #{0}" -f $number)
if ($ageMin -lt $MinMinutesBetween -and -not $IgnoreWait) {
    Write-Finding -Level YELLOW -Category 'Wait' -Message ("krbtgt was reset only {0} minute(s) ago. Wait until {1} before the next reset." -f $ageMin, $before.PwdSet.AddMinutes($MinMinutesBetween).ToString('HH:mm')) `
        -Detail "Resetting twice without a pause invalidates tickets that DCs and services have not had time to renew.`nSingle DC and in a hurry: -IgnoreWait.  Several DCs: wait for clean replication instead."
    Complete-Ccdc; return
}
if ($number -eq 1) {
    Write-Finding -Level YELLOW -Category 'Before' -Message 'Have you removed how they got in? (rogue admins, DCSync rights, malicious GPOs)' -Detail 'audit\Audit-Users.ps1, audit\Audit-AD-GPO.ps1. If they can still DCSync, they will just read the new key.'
}

$entry = $before.Entry
$ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'krbtgt' -Action ("Reset password (reset #{0})" -f $number) -Undo 'none (not needed)' -ScriptBlock {
    # 64 random characters. The value does not matter: nobody logs on as krbtgt, the KDC derives its keys from it.
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 48; $rng.GetBytes($bytes)
    $pw = [Convert]::ToBase64String($bytes) + 'aA1!'
    try {
        if (Test-CcdcModule 'ActiveDirectory') {
            Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
        } else {
            $entry.Invoke('SetPassword', $pw)
            $entry.CommitChanges()
        }
    } finally { $pw = $null; $bytes = $null; $rng.Dispose() }
}
if (-not $ok) { Complete-Ccdc; return }

Add-Content -Path $history -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -WhatIf:$false
$after = Get-KrbtgtState
Write-Finding -Level GREEN -Category 'krbtgt' -Message ("Reset #{0} done at {1}. Key version {2} -> {3}." -f $number, $after.PwdSet.ToString('HH:mm:ss'), $before.Kvno, $after.Kvno)
if ($after.PwdSet -eq $before.PwdSet) { Write-Finding -Level RED -Category 'krbtgt' -Message 'pwdLastSet did not change: the reset did NOT take effect. Check the error above.' }

if ($dcs.Count -gt 1) {
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'all domain controllers' -Action 'Push the change now (repadmin /syncall /AdeP)' -ScriptBlock {
        $null = & repadmin.exe /syncall /AdeP 2>&1
    }
}
if ($number -eq 1) {
    Write-Finding -Level YELLOW -Category 'Next' -Message ("Reset #2 is still needed. Earliest: {0}." -f (Get-Date).AddMinutes($MinMinutesBetween).ToString('HH:mm')) `
        -Detail "Until then the STOLEN key still works as the 'previous' key.`nMeanwhile: rotate admin passwords (harden\Rotate-Passwords.ps1 -Group `"Domain Admins`"), watch the scoreboard.`nThen run this script again."
} else {
    Write-Finding -Level GREEN -Category 'Next' -Message 'Both resets done: tickets forged with the old key are dead.' `
        -Detail "Now: rotate every admin and service account password, check scored services (hunt\Test-ScoredServices.ps1),`nand if Zerologon was involved reset the DC machine account too: Reset-ComputerMachinePassword (on each DC).`nWrite it up: hunt\New-IncidentReport.ps1"
}
Complete-Ccdc
