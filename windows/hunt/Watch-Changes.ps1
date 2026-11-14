<#
.SYNOPSIS
    Watch-Changes - baseline the box, then diff against it every N minutes. Read-only toward the system.

.DESCRIPTION
    PURPOSE
      After you have cleaned a box, take a BASELINE. From then on, every run
      (or every -IntervalMinutes with -Loop) shows only what CHANGED:
        new user / group member / scheduled task / service / Run key / WMI consumer  -> RED
        new listening port                                                            -> YELLOW
        a scored port that STOPPED listening                                          -> RED (service down!)
        anything removed                                                              -> YELLOW
      This is the "every 15 minutes" loop: one person per box runs it all day.

    WHAT IT SNAPSHOTS
      users, privileged group members (local + domain on a DC), scheduled tasks,
      services (name|start mode|binary), listening ports + process, Run keys,
      WMI consumers, SMB shares.

    WHAT IT READS    the same sources as the audit scripts
    WHAT IT CHANGES  nothing on the system. Writes JSON snapshots to C:\ccdc\baseline\
                     (no secrets in them) plus its normal log.
    HOW TO UNDO      delete C:\ccdc\baseline\ to start over.

    WORKFLOW
      1. Clean the box (audit + harden).
      2. .\Watch-Changes.ps1 -Mode Baseline
      3. .\Watch-Changes.ps1 -Loop               (Ctrl+C to stop)
      4. You made a legit change (e.g. added a firewall rule port)? Review the
         diff, then accept it:  .\Watch-Changes.ps1 -Mode Baseline

    MANUAL EQUIVALENT
      net user > before.txt   ...later...   net user > after.txt ; fc before.txt after.txt
      Compare-Object (Get-Content before.txt) (Get-Content after.txt)

.EXAMPLE
    .\Watch-Changes.ps1 -Mode Baseline
.EXAMPLE
    .\Watch-Changes.ps1 -Loop -IntervalMinutes 15
#>
[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Baseline', 'Diff')][string]$Mode = 'Auto',
    [string]$BaselineDir = 'C:\ccdc\baseline',
    [switch]$Loop,
    [ValidateRange(1, 240)][int]$IntervalMinutes = 15,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Watch-Changes' -OutFile $OutFile -ReadOnly
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config
$scoredPorts = @(); if ($hostCfg) { $scoredPorts = @($hostCfg.scoredPorts.tcp) }
if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
$baselineFile = Join-Path $BaselineDir ("baseline_{0}.json" -f $env:COMPUTERNAME)

function Get-Snapshot {
    # Each category is a sorted list of strings, so "diff" is just set comparison.
    $snap = [ordered]@{}
    $snap.users = @(Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object { "local|$($_.Name)|disabled=$($_.Disabled)" })

    $grp = @()
    foreach ($g in @('Administrators', 'Remote Desktop Users', 'Backup Operators', 'Remote Management Users')) {
        try {
            ([ADSI]"WinNT://./$g,group").psbase.Invoke('Members') | ForEach-Object {
                $grp += "$g <- " + ($_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null) -replace '^WinNT://', '')
            }
        } catch { $null = $_ }   # group does not exist on this SKU
    }
    if (Test-CcdcIsDC) {
        $dn = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
        $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn", '(&(objectCategory=person)(objectClass=user))')
        $s.PageSize = 1000; [void]$s.PropertiesToLoad.Add('sAMAccountName'); [void]$s.PropertiesToLoad.Add('userAccountControl')
        foreach ($r in $s.FindAll()) { $snap.users += "domain|$($r.Properties['samaccountname'][0])|disabled=$([bool]([int]$r.Properties['useraccountcontrol'][0] -band 2))" }
        foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'DnsAdmins', 'Group Policy Creator Owners', 'Account Operators')) {
            $gs = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn", "(&(objectClass=group)(sAMAccountName=$g))")
            $gr = $gs.FindOne(); if (-not $gr) { continue }
            $ms = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn", "(memberOf:1.2.840.113556.1.4.1941:=$($gr.Properties['distinguishedname'][0]))")
            [void]$ms.PropertiesToLoad.Add('sAMAccountName')
            foreach ($m in $ms.FindAll()) { $grp += "$g <- $($m.Properties['samaccountname'][0])" }
        }
    }
    $snap.groups = $grp
    $snap.tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        "$($_.TaskPath)$($_.TaskName)|" + (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ';') })
    $snap.services = @(Get-WmiObject Win32_Service | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.PathName)" })
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $snap.listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 49152 } |
        ForEach-Object { "TCP|$($_.LocalPort)|$($procs[[int]$_.OwningProcess])" } | Sort-Object -Unique)
    $rk = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $rk += "$k|$($_.Name)|$($_.Value)" } }
    }
    $snap.runkeys = $rk
    $snap.wmi = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object { "$($_.__CLASS)|$($_.Name)" })
    $snap.shares = @(Get-WmiObject Win32_Share | ForEach-Object { "$($_.Name)|$($_.Path)" })
    foreach ($k in @($snap.Keys)) { $snap[$k] = @($snap[$k] | Where-Object { $_ } | Sort-Object -Unique) }
    return $snap
}

function Save-Snapshot($snap, [string]$path) {
    $obj = [ordered]@{ host = $env:COMPUTERNAME; taken = (Get-Date).ToString('s'); data = $snap }
    ($obj | ConvertTo-Json -Depth 5) | Out-File -FilePath $path -Encoding UTF8
}

function Compare-Snapshot($base, $now) {
    $changes = 0
    foreach ($cat in $now.Keys) {
        $old = @($base.$cat); $new = @($now[$cat])
        $added   = @($new | Where-Object { $old -notcontains $_ })
        $removed = @($old | Where-Object { $new -notcontains $_ })
        foreach ($a in $added) {
            $changes++
            $lvl = if ($cat -eq 'listeners') { 'YELLOW' } else { 'RED' }
            Write-Finding -Level $lvl -Category "NEW $cat" -Message $a
        }
        foreach ($r in $removed) {
            $changes++
            $lvl = 'YELLOW'
            if ($cat -eq 'listeners' -and $scoredPorts -contains [int](($r -split '\|')[1])) { $lvl = 'RED'; $r = "$r  <- SCORED PORT NO LONGER LISTENING" }
            Write-Finding -Level $lvl -Category "GONE $cat" -Message $r
        }
    }
    if ($changes -eq 0) { Write-Finding -Level GREEN -Category 'Diff' -Message 'No changes since baseline.' }
}

# ---------------------------------------------------------------------------
if ($Mode -eq 'Auto') { $Mode = if (Test-Path $baselineFile) { 'Diff' } else { 'Baseline' } }

if ($Mode -eq 'Baseline') {
    Write-Section 'Taking baseline'
    $snap = Get-Snapshot
    if (Test-Path $baselineFile) {
        $old = $baselineFile -replace '\.json$', ("_replaced_{0}.json" -f $script:CcdcStamp)
        Move-Item $baselineFile $old -Force   # keep the previous baseline for the record
        Write-Finding -Level INFO -Category 'Baseline' -Message "Previous baseline kept as $old"
    }
    Save-Snapshot $snap $baselineFile
    foreach ($k in $snap.Keys) { Write-Finding -Level INFO -Category 'Baseline' -Message ("{0,-10} {1} items" -f $k, $snap[$k].Count) }
    Write-Finding -Level GREEN -Category 'Baseline' -Message "Saved $baselineFile. Now run with -Loop."
    Complete-Ccdc
    return
}

if (-not (Test-Path $baselineFile)) {
    Write-Finding -Level YELLOW -Category 'Diff' -Message "No baseline at $baselineFile yet. Run with -Mode Baseline first (or -Mode Auto)."
    Complete-Ccdc
    return
}
$base = (Get-Content $baselineFile -Raw | ConvertFrom-Json)
Write-Finding -Level INFO -Category 'Diff' -Message "Baseline taken $($base.taken)"
do {
    Write-Section ("Diff at {0}" -f (Get-Date -Format 'HH:mm:ss'))
    $now = Get-Snapshot
    Compare-Snapshot $base.data $now
    Save-Snapshot $now (Join-Path $BaselineDir ("latest_{0}.json" -f $env:COMPUTERNAME))
    if ($Loop) {
        Write-Host ("  next check at {0:HH:mm} (Ctrl+C to stop)" -f (Get-Date).AddMinutes($IntervalMinutes)) -ForegroundColor DarkGray
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} while ($Loop)
Complete-Ccdc
