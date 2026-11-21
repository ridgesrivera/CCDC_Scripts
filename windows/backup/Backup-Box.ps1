<#
.SYNOPSIS
    Backup-Box - snapshot everything you would need to rebuild/restore this box. Writes ONLY to the backup folder.

.DESCRIPTION
    PURPOSE
      Take a known-good copy early (minute 5-10), before you or the Red Team
      break something. Restoring a config file beats rebuilding a service.

    WHAT IT BACKS UP (each part skipped automatically if not present)
      All boxes : key registry hives (Run keys, Winlogon, IFEO, Services, Lsa, SMB, policies),
                  scheduled tasks (one XML per task, re-importable), firewall policy (.wfw),
                  local users/groups list, service list, system info
      DC        : AD database via ntdsutil IFM (ntds.dit + SYSTEM hive) ONLY with -IncludeAdIfm,
                  all GPOs (Backup-GPO), DNS zones (dnscmd /ZoneExport),
                  users/groups/OUs as LDIF (ldifde - contains NO passwords)
      IIS       : appcmd config backup + applicationHost.config + every site's web root

    !! SENSITIVE OUTPUT !!
      The IFM copy contains ntds.dit = every domain password HASH. If Red Team
      grabs it, every account in the domain is compromised, so IFM is OFF unless you pass
      -IncludeAdIfm. Web roots contain wp-config.php = DB passwords. The script
      locks the backup folder to Administrators + SYSTEM only. Do not copy it
      to a share. (-SkipAdIfm is still accepted for old notes; it is now the default.)

    WHAT IT READS    registry, Task Scheduler, AD, DNS, IIS config, web roots
    WHAT IT CHANGES  creates C:\ccdc\backups\<stamp>_box\ (and an IIS config backup inside
                     %windir%\system32\inetsrv\backup\ via appcmd). No system settings change.
    HOW TO UNDO      delete the backup folder.  (appcmd delete backup "ccdc_<stamp>")

    HOW TO RESTORE (examples)
      reg import <file>.reg
      Register-ScheduledTask -Xml (Get-Content task.xml -Raw) -TaskName <name>
      netsh advfirewall import firewall.wfw
      Restore-GPO -All -Path <gpo folder>     (or Import-GPO for one)
      %windir%\system32\inetsrv\appcmd restore backup "ccdc_<stamp>"
      AD from IFM: Directory Services Restore Mode - see docs\incident-response.md (last resort)

    MANUAL EQUIVALENT
      ntdsutil "activate instance ntds" ifm "create full C:\ccdc\ifm" quit quit
      Backup-GPO -All -Path C:\ccdc\gpo
      dnscmd /ZoneExport great.local great.local.bak      (lands in %windir%\System32\dns)
      %windir%\system32\inetsrv\appcmd add backup "before-ccdc"
      reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run run.reg

.EXAMPLE
    .\Backup-Box.ps1
.EXAMPLE
    .\Backup-Box.ps1 -SkipWebRoots
.EXAMPLE
    .\Backup-Box.ps1 -IncludeAdIfm      # DC: also copy ntds.dit (move it off-box, delete after)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination,
    [switch]$IncludeAdIfm,
    [switch]$SkipAdIfm,     # kept for compatibility; IFM is now opt-in via -IncludeAdIfm
    [switch]$SkipWebRoots,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Backup-Box'
$null = Get-CcdcConfig -Path $ConfigPath
if (-not $Destination) { $Destination = Join-Path $script:CcdcBackupRoot ("{0}_box" -f $script:CcdcStamp) }
$isDC = Test-CcdcIsDC

if ($WhatIfPreference) {
    Write-Finding -Level INFO -Category 'Plan' -Message "WhatIf: would back up to $Destination (registry, tasks, firewall, users$(if ($isDC) { "$(if ($IncludeAdIfm) { ', AD IFM' }), GPO, DNS, LDIF" })$(if (Test-Path "$env:windir\System32\inetsrv\appcmd.exe") { ', IIS' }))"
    Complete-Ccdc; return
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
# Lock the folder FIRST so sensitive files are never readable by normal users.
$null = & icacls.exe $Destination /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 2>&1
Write-Finding -Level GREEN -Category 'Backup' -Message "Destination $Destination (ACL: Administrators + SYSTEM only)"

function Step([string]$name, [scriptblock]$sb) {
    # Run one backup step; a failure in one step never stops the others.
    try { & $sb; Write-Finding -Level GREEN -Category 'Backup' -Message $name }
    catch { Write-Finding -Level YELLOW -Category 'Backup' -Message "$name FAILED: $($_.Exception.Message)" }
}
function New-SubDir([string]$n) { $d = Join-Path $Destination $n; New-Item -ItemType Directory -Path $d -Force | Out-Null; return $d }

# ---------------------------------------------------------------------------
Write-Section 'System snapshot'
# ---------------------------------------------------------------------------
$sys = New-SubDir 'system'
Step 'systeminfo / ipconfig / netstat' {
    systeminfo.exe | Out-File (Join-Path $sys 'systeminfo.txt') -Encoding UTF8
    ipconfig.exe /all | Out-File (Join-Path $sys 'ipconfig.txt') -Encoding UTF8
    netstat.exe -ano | Out-File (Join-Path $sys 'netstat.txt') -Encoding UTF8
}
Step 'services list' { Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName | Export-Csv (Join-Path $sys 'services.csv') -NoTypeInformation }
Step 'local users + groups' {
    Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name, Disabled, Description, SID | Export-Csv (Join-Path $sys 'local_users.csv') -NoTypeInformation
    net.exe localgroup Administrators | Out-File (Join-Path $sys 'local_administrators.txt') -Encoding UTF8
}

# ---------------------------------------------------------------------------
Write-Section 'Registry'
# ---------------------------------------------------------------------------
$reg = New-SubDir 'registry'
$keys = @(
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM\SYSTEM\CurrentControlSet\Services',
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders',
    'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
    'HKLM\SOFTWARE\Policies'
)
$regOk = 0
foreach ($k in $keys) {
    $file = Join-Path $reg (($k -replace '[\\ ]', '_') + '.reg')
    $null = & reg.exe export $k $file /y 2>&1
    if ($LASTEXITCODE -eq 0) { $regOk++; Write-CcdcLog "BACKUP registry $k" } else { Write-CcdcLog "BACKUP registry $k not present" }
}
Write-Finding -Level GREEN -Category 'Registry' -Message ("{0} registry areas exported (Run keys, Winlogon, IFEO, services, LSA, RDP, policies)" -f $regOk)

# ---------------------------------------------------------------------------
Write-Section 'Scheduled tasks + firewall'
# ---------------------------------------------------------------------------
$tdir = New-SubDir 'scheduled_tasks'
Step 'scheduled tasks (XML each)' {
    foreach ($t in (Get-ScheduledTask)) {
        $safe = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_').Trim('_')
        Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File (Join-Path $tdir "$safe.xml") -Encoding Unicode
    }
}
Step 'firewall policy (.wfw)' {
    $null = & netsh.exe advfirewall export (Join-Path $Destination 'firewall.wfw')
    if ($LASTEXITCODE -ne 0) { throw 'netsh export failed' }
}

# ---------------------------------------------------------------------------
if ($isDC) {
    Write-Section 'Domain controller'
    $domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext

    if ($IncludeAdIfm -and -not $SkipAdIfm) {
        $ifm = Join-Path $Destination 'ad_ifm'
        Write-Finding -Level YELLOW -Category 'AD' -Message 'Creating IFM (ntds.dit = all password hashes). Folder is ACL-locked; never share it.'
        Step 'AD database (ntdsutil IFM)' {
            $out = & ntdsutil.exe 'activate instance ntds' 'ifm' "create full `"$ifm`"" 'quit' 'quit' 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $ifm 'Active Directory\ntds.dit'))) { throw ($out | Select-Object -Last 3) -join ' ' }
        }
    } else { Write-Finding -Level INFO -Category 'AD' -Message 'AD IFM (ntds.dit) skipped - pass -IncludeAdIfm to include it. AD objects are still exported as LDIF below.' }

    if (Test-CcdcModule GroupPolicy) {
        $gdir = New-SubDir 'gpo'
        Step 'all GPOs (Backup-GPO)' { Backup-GPO -All -Path $gdir | Out-Null; Get-GPOReport -All -ReportType Html -Path (Join-Path $gdir 'all-gpos.html') }
    } else { Write-Finding -Level YELLOW -Category 'AD' -Message 'GroupPolicy module missing - GPO backup skipped (copy \\<domain>\SYSVOL by hand)' }

    $ldif = New-SubDir 'ldif'
    Step 'users/groups/OUs/computers as LDIF (no passwords)' {
        foreach ($cls in @('user', 'group', 'organizationalUnit', 'computer')) {
            $null = & ldifde.exe -f (Join-Path $ldif "$cls.ldf") -d $domainDN -r "(objectClass=$cls)" -p subtree 2>&1
        }
    }

    if (Test-CcdcModule DnsServer) {
        $ddir = New-SubDir 'dns'
        Step 'DNS zones (dnscmd /ZoneExport)' {
            foreach ($z in (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })) {
                $fname = "ccdc_$($script:CcdcStamp)_$($z.ZoneName).dns"
                $null = & dnscmd.exe /ZoneExport $z.ZoneName $fname 2>&1   # always writes into %windir%\System32\dns
                $src = Join-Path "$env:windir\System32\dns" $fname
                if (Test-Path $src) { Move-Item $src (Join-Path $ddir "$($z.ZoneName).dns") -Force }
            }
            Get-DnsServerZone | Export-Csv (Join-Path $ddir 'zones.csv') -NoTypeInformation
        }
    }
}

# ---------------------------------------------------------------------------
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
if (Test-Path $appcmd) {
    Write-Section 'IIS'
    $idir = New-SubDir 'iis'
    Step 'appcmd config backup' {
        $null = & $appcmd add backup "ccdc_$($script:CcdcStamp)" 2>&1
        Copy-Item "$env:windir\System32\inetsrv\config\*.config" $idir -Force
        Write-CcdcLog "IIS restore: appcmd restore backup ccdc_$($script:CcdcStamp)"
    }
    if (-not $SkipWebRoots) {
        $xml = [xml](Get-Content "$env:windir\System32\inetsrv\config\applicationHost.config" -Raw)
        $paths = $xml.configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath |
            ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } | Where-Object { Test-Path $_ } | Sort-Object -Unique
        foreach ($p in $paths) {
            $dest = Join-Path $idir ('webroot_' + (($p -replace ':', '') -replace '\\', '_'))
            Step "web root $p" { Copy-Item -Path $p -Destination $dest -Recurse -Force }
        }
    }
}

$size = [math]::Round(((Get-ChildItem $Destination -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Finding -Level INFO -Category 'Backup' -Message "Total: $size MB in $Destination"
Complete-Ccdc
