<#
.SYNOPSIS
    Watch-Changes - baseline the box, then diff against it every N minutes. Read-only toward the system.

.DESCRIPTION
    PURPOSE
      After you have cleaned a box, take a BASELINE. From then on, every run
      (or every -IntervalMinutes with -Loop) shows only what CHANGED:
        new user / group member / scheduled task / service / Run key / WMI consumer  -> RED
        new SSH key, startup file, IFEO / Winlogon / LSA entry, Defender exclusion    -> RED
        new firewall BLOCK rule, hosts-file entry, port proxy, web script file        -> RED
        new GPO or GPO version, SPN, no-preauth account, trust (on a DC)              -> RED
        new listening port, firewall allow rule, installed program, computer account  -> YELLOW
        a scored port that STOPPED listening                                          -> RED (service down!)
        anything removed                                                              -> YELLOW
      This is the "every 15 minutes" loop: one person per box runs it all day,
      or -InstallTask makes Windows run it on a schedule so the hunt happens
      even when everyone is busy with injects.

    WHAT IT SNAPSHOTS
      users, privileged group members (local + domain on a DC), scheduled tasks,
      services (name|start mode|binary), listening ports + process, Run keys,
      WMI consumers, SMB shares, firewall rules + profiles, Defender exclusions,
      hosts file, port proxies, SSH keys + sshd_config, startup folders,
      IFEO / Winlogon / AppInit / LSA values, installed programs, script files
      in web roots, and on a DC: GPO versions, computer accounts, SPNs,
      no-preauth accounts, trusts.

    SCHEDULED MODE
      .\Watch-Changes.ps1 -InstallTask [-IntervalMinutes 15]
        registers the task 'CCDC-Watch-Changes' (runs as SYSTEM). Each run
        appends changes to C:\ccdc\alerts\alerts_<HOST>.csv and pops a message
        on every logged-on desktop when something is RED.
      .\Watch-Changes.ps1 -UninstallTask     removes it again.
      Keep the toolkit folder where it is: the task runs this file by path.

    WHAT IT READS    the same sources as the audit scripts
    WHAT IT CHANGES  nothing on the system. Writes JSON snapshots to C:\ccdc\baseline\
                     (no secrets in them) plus its normal log.
    HOW TO UNDO      delete C:\ccdc\baseline\ to start over.  -UninstallTask removes the scheduled task.

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
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [switch]$Scheduled,          # set by the scheduled task: write alerts + pop a message instead of relying on the console
    [string[]]$WebRoots = @(),
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
$taskName = 'CCDC-Watch-Changes'

# ---------------------------------------------------------------------------
# Scheduled task: "persistence hunting as a scheduled task, not something done when there is time".
# ---------------------------------------------------------------------------
if ($UninstallTask) {
    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop; Write-Finding -Level GREEN -Category 'Task' -Message "Removed scheduled task $taskName." }
    catch { Write-Finding -Level YELLOW -Category 'Task' -Message "Could not remove ${taskName}: $($_.Exception.Message)" }
    Complete-Ccdc
    return
}
if ($InstallTask) {
    try {
        $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode Diff -Scheduled -BaselineDir `"$BaselineDir`""
        if ($ConfigPath) { $taskArgs += " -ConfigPath `"$ConfigPath`"" }
        $act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs
        # Repeats for 7 days: longer than any competition, and avoids the "infinite duration" quirks of older Windows.
        $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 7)
        Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trig -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        Write-Finding -Level GREEN -Category 'Task' -Message "Scheduled task $taskName runs every $IntervalMinutes min as SYSTEM." -Detail "Changes go to C:\ccdc\alerts\alerts_$($env:COMPUTERNAME).csv and RED ones pop a message on screen.`nRemove: .\Watch-Changes.ps1 -UninstallTask"
        if (-not (Test-Path $baselineFile)) { Write-Finding -Level YELLOW -Category 'Task' -Message 'No baseline yet: the task has nothing to compare with. Clean the box, then run: .\Watch-Changes.ps1 -Mode Baseline' }
        else { Write-Finding -Level YELLOW -Category 'Task' -Message 'The new task itself will show up as a change. Accept it with: .\Watch-Changes.ps1 -Mode Baseline' }
    } catch { Write-Finding -Level RED -Category 'Task' -Message "Could not register ${taskName}: $($_.Exception.Message)" }
    Complete-Ccdc
    return
}

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

    # Firewall rules from the registry (fast). Value format: v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=x|
    $fw = @()
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules', 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules')) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($v in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            $f = @{}; $ports = @()
            foreach ($part in ([string]$v.Value -split '\|')) { $kv = $part -split '=', 2; if ($kv.Count -eq 2) { if ($kv[0] -like 'LPort*') { $ports += $kv[1] } else { $f[$kv[0]] = $kv[1] } } }
            if ($f.Active -ne 'TRUE') { continue }
            # Inbound allow rules and ALL block rules matter; outbound allow rules are noise.
            if ($f.Action -eq 'Allow' -and $f.Dir -ne 'In') { continue }
            $fw += "{0}|{1}|{2}|proto={3}|ports={4}|app={5}" -f $f.Action, $f.Dir, $f.Name, $f.Protocol, ($ports -join ','), $f.App
        }
    }
    $snap.firewall = $fw
    $snap.fwprofiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|enabled=$($_.Enabled)|in=$($_.DefaultInboundAction)|out=$($_.DefaultOutboundAction)" })

    $def = @()
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mp) {
            foreach ($kind in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')) { foreach ($v in @($mp.$kind)) { if ($v) { $def += "$kind|$v" } } }
            if ($mp.DisableRealtimeMonitoring) { $def += 'RealTimeProtection|OFF' }
        }
    }
    $snap.defender = $def
    $snap.hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
    $snap.portproxy = @(& netsh.exe interface portproxy show all 2>$null | Where-Object { $_ -match '^\s*\S+\s+\d+\s+\S+\s+\d+\s*$' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })

    $ssh = @()
    $keyFiles = @("$env:ProgramData\ssh\administrators_authorized_keys")
    $keyFiles += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' }
    foreach ($kf in $keyFiles) {
        if (-not (Test-Path -LiteralPath $kf)) { continue }
        foreach ($line in @(Get-Content -LiteralPath $kf -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })) {
            $parts = $line.Trim() -split '\s+'
            $tail = if ($parts.Count -ge 2 -and $parts[1].Length -gt 20) { $parts[1].Substring($parts[1].Length - 20) } else { '' }
            $ssh += "key|$kf|$($parts[0])|...$tail"
        }
    }
    $sshdCfg = "$env:ProgramData\ssh\sshd_config"
    if (Test-Path $sshdCfg) { $ssh += "sshd_config|sha256=$(Get-CcdcFileHash -Path $sshdCfg)" }
    $snap.ssh = $ssh

    $st = @()
    $stDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $stDirs += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    foreach ($d in $stDirs) { Get-ChildItem -LiteralPath $d -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $st += $_.FullName } }
    $snap.startup = $st

    # Single registry values Red Team flips: sticky-keys debuggers, Winlogon, AppInit, LSA packages.
    $reg = @()
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { $reg += "IFEO|$($_.PSChildName)|$dbg" }
    }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) { $reg += "Winlogon|Userinit|$($wl.Userinit)"; $reg += "Winlogon|Shell|$($wl.Shell)" }
    $ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    if ($ai -and $ai.AppInit_DLLs) { $reg += "AppInit_DLLs|$($ai.AppInit_DLLs)" }
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    if ($lsa) { foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') { foreach ($v in @($lsa.$n)) { if ($v) { $reg += "LSA|$n|$v" } } } }
    $snap.regvalues = $reg

    $sw = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { $sw += "$($_.DisplayName)|$($_.DisplayVersion)" }
    }
    $snap.software = $sw

    # Script files in web roots: a new .php / .aspx is how a web shell arrives. Path|size|modified.
    $roots = @($WebRoots)
    $appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHost) {
        try { $roots += ([xml](Get-Content $appHost -Raw)).configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } } catch { $null = $_ }
    }
    foreach ($d in @('C:\inetpub\wwwroot', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\Apache24\htdocs')) { if (Test-Path $d) { $roots += $d } }
    $web = @()
    foreach ($r in ($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)) {
        $web += Get-ChildItem -Path $r -Recurse -File -Force -Include *.php, *.php5, *.phtml, *.asp, *.aspx, *.ashx, *.asmx, *.jsp, *.config, *.htaccess -ErrorAction SilentlyContinue |
            Select-Object -First 40000 | ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" }
    }
    $snap.webfiles = $web

    if (Test-CcdcIsDC) {
        # $dn was set in the group section above.
        $q = { param($filter, $props)
            $ds = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn", $filter)
            $ds.PageSize = 1000; foreach ($pp in $props) { [void]$ds.PropertiesToLoad.Add($pp) }
            $ds.FindAll() }
        $snap.gpos = @(& $q '(objectClass=groupPolicyContainer)' @('displayName', 'versionNumber', 'name') | ForEach-Object { "$($_.Properties['displayname'][0])|$($_.Properties['name'][0])|version=$($_.Properties['versionnumber'][0])" })
        $snap.gplinks = @(& $q '(gPLink=*)' @('distinguishedName', 'gPLink') | ForEach-Object { "$($_.Properties['distinguishedname'][0])|$($_.Properties['gplink'][0])" })
        $snap.computers = @(& $q '(objectCategory=computer)' @('sAMAccountName') | ForEach-Object { [string]$_.Properties['samaccountname'][0] })
        $snap.spns = @(& $q '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' @('sAMAccountName', 'servicePrincipalName') | ForEach-Object { "$($_.Properties['samaccountname'][0])|$(@($_.Properties['serviceprincipalname']) -join ',')" })
        # userAccountControl bit 0x400000 = "do not require Kerberos pre-authentication" (AS-REP roastable)
        $snap.nopreauth = @(& $q '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('sAMAccountName') | ForEach-Object { [string]$_.Properties['samaccountname'][0] })
        $snap.trusts = @(& $q '(objectClass=trustedDomain)' @('name', 'trustDirection') | ForEach-Object { "$($_.Properties['name'][0])|direction=$($_.Properties['trustdirection'][0])" })
    }
    foreach ($k in @($snap.Keys)) { $snap[$k] = @($snap[$k] | Where-Object { $_ } | Sort-Object -Unique) }
    return $snap
}

function Save-Snapshot($snap, [string]$path) {
    $obj = [ordered]@{ host = $env:COMPUTERNAME; taken = (Get-Date).ToString('s'); data = $snap }
    ($obj | ConvertTo-Json -Depth 5) | Out-File -FilePath $path -Encoding UTF8
}

function Compare-Snapshot($base, $now) {
    $changes = 0; $red = 0
    $yellowCats = @('listeners', 'software', 'computers', 'fwprofiles')   # new items here are "review", not "act now"
    foreach ($cat in $now.Keys) {
        # A baseline taken by an older version of this script does not have the newer categories.
        if ($base.PSObject.Properties.Name -notcontains $cat) {
            Write-Finding -Level INFO -Category 'Diff' -Message "'$cat' is not in this baseline (taken by an older version). Re-run -Mode Baseline to start tracking it."
            continue
        }
        $old = @($base.$cat); $new = @($now[$cat])
        # Hashtable lookups keep this fast for the big categories (web files, firewall rules).
        $oldSet = @{}; foreach ($o in $old) { $oldSet[[string]$o] = $true }
        $newSet = @{}; foreach ($n in $new) { $newSet[[string]$n] = $true }
        $added   = @($new | Where-Object { -not $oldSet.ContainsKey([string]$_) })
        $removed = @($old | Where-Object { -not $newSet.ContainsKey([string]$_) })
        $shown = 0
        foreach ($a in $added) {
            $changes++
            $lvl = if ($yellowCats -contains $cat) { 'YELLOW' } else { 'RED' }
            if ($cat -eq 'firewall' -and $a -like 'Allow|*') { $lvl = 'YELLOW' }      # a new BLOCK rule stays RED: it can take a scored service down
            if ($cat -eq 'fwprofiles' -and $a -match 'enabled=False|out=Block') { $lvl = 'RED' }
            if ($lvl -eq 'RED') { $red++ }
            if ($Scheduled) { Write-CcdcAlert -Level $lvl -Rule "New-$cat" -Detail $a -Source 'Watch-Changes' }
            if (++$shown -le 40) { Write-Finding -Level $lvl -Category "NEW $cat" -Message $a }
        }
        foreach ($r in $removed) {
            $changes++
            $lvl = 'YELLOW'
            if ($cat -eq 'listeners' -and $scoredPorts -contains [int](($r -split '\|')[1])) { $lvl = 'RED'; $red++; $r = "$r  <- SCORED PORT NO LONGER LISTENING" }
            if ($Scheduled) { Write-CcdcAlert -Level $lvl -Rule "Gone-$cat" -Detail $r -Source 'Watch-Changes' }
            if (++$shown -le 40) { Write-Finding -Level $lvl -Category "GONE $cat" -Message $r }
        }
        if ($shown -gt 40) { Write-Finding -Level YELLOW -Category "MORE $cat" -Message ("{0} more change(s) in '{1}' not shown. Full list: latest_{2}.json vs the baseline." -f ($shown - 40), $cat, $env:COMPUTERNAME) }
    }
    if ($changes -eq 0) { Write-Finding -Level GREEN -Category 'Diff' -Message 'No changes since baseline.' }
    elseif ($Scheduled -and $red -gt 0) {
        # The task runs as SYSTEM with no window, so tell whoever is logged on.
        try { $null = & msg.exe * /TIME:120 ("CCDC Watch-Changes on {0}: {1} RED change(s) since baseline. See C:\ccdc\alerts\alerts_{0}.csv or run hunt\Watch-Changes.ps1" -f $env:COMPUTERNAME, $red) 2>&1 } catch { $null = $_ }
    }
    if ($changes -gt 0) { Write-Finding -Level INFO -Category 'Next' -Message 'Remove what is hostile: hunt\Remove-Persistence.ps1 / hunt\Kick-Block.ps1.  Accept what is yours: -Mode Baseline' }
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
