<#
.SYNOPSIS
    Remove-Persistence - pick suspicious persistence from a numbered list; it is preserved as evidence, then contained. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      audit\Audit-Persistence.ps1 FINDS things. This script REMOVES them, in the
      order an incident report needs: Preserve -> Contain -> Record.
        1. It lists the removable persistence it can see, numbered, worst first.
        2. You type the numbers you want gone (nothing is touched until you do).
        3. For each one it first saves the evidence (definition, file copy,
           SHA256, timestamps, who created it and from which IP when the event
           log still knows), then contains it, then writes the undo command.
      Every hour an attacker keeps access matters, and an incident report needs
      proof of what was found and removed. Step 3 is that proof.

    WHAT IT CAN REMOVE                       HOW (default = reversible)
      Scheduled tasks (incl. hidden ones)    export XML, disable (-Delete: unregister)
      Services                               export definition, stop + set Disabled (-Delete: sc delete)
      Run / RunOnce values                   export key, delete the value
      Startup-folder files                   move to quarantine
      WMI event subscriptions                save MOF, remove consumer + binding + filter
      IFEO debuggers (sticky keys)           export key, delete the Debugger value
      Winlogon Userinit / Shell              export key, reset to the Windows default
      AppInit_DLLs                           export key, clear the value
      LSA packages (password filters, SSPs)  export key, remove the unknown entry
      Defender exclusions / real-time off    remove the exclusion, turn protection on
      SSH authorized_keys entries            back up the file, delete that one line
      Web shells                             move to quarantine (outside the web root)
      PowerShell profile scripts             move to quarantine
      Port proxies (netsh portproxy)         delete the forward

    WHAT IT DOES NOT DO
      Rogue ACCOUNTS: use harden\Disable-Accounts.ps1.   Firewall: harden\Set-Firewall.ps1.
      It never deletes a file under C:\Windows (a task that runs cmd.exe is
      removed; cmd.exe is not). It refuses to stop a service that is listening
      on a scored port unless you pass -AllowScored.

    WHAT IT READS    Task Scheduler, services, registry, WMI, Defender, web roots, event logs
    WHAT IT CHANGES  only the items you select. Before each change:
                       C:\ccdc\quarantine\<stamp>\      exported definitions + file copies
                       C:\ccdc\evidence\evidence_<HOST>.jsonl   one record per item
                       C:\ccdc\backups\<stamp>\         registry exports / file backups
    HOW TO UNDO      C:\ccdc\logs\Remove-Persistence_*_rollback.ps1 holds one undo
                     command per item (re-enable task, reg import, move file back...).

    MANUAL EQUIVALENT
      Export-ScheduledTask -TaskName X | Out-File x.xml ; Disable-ScheduledTask -TaskName X
      sc.exe qc X ; sc.exe stop X ; sc.exe config X start= disabled
      reg export "HKLM\...\Run" run.reg ; reg delete "HKLM\...\Run" /v X /f
      Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Remove-WmiObject
      Move-Item C:\inetpub\wwwroot\x.php C:\ccdc\quarantine\

.PARAMETER MinLevel
    RED (default) lists only what is very likely malicious. YELLOW also lists
    everything that merely is not default (vendor Run keys, third-party services).

.PARAMETER Task
    Skip the list and act on these scheduled tasks (full path, e.g. '\Updater' or '\Microsoft\Windows\evil').

.PARAMETER Service
    Skip the list and act on these service names.

.PARAMETER File
    Skip the list and quarantine these files (web shells, dropped tools).

.PARAMETER All
    Act on every listed item without asking for numbers. You still confirm each one unless -Force.

.PARAMETER Delete
    Tasks and services are deleted instead of disabled (their definition is still exported first).

.PARAMETER KillProcess
    Also stop running processes whose executable is a quarantined payload.

.PARAMETER AllowScored
    Allow stopping a service that currently listens on a scored port.

.EXAMPLE
    .\Remove-Persistence.ps1 -WhatIf          # list everything RED and show what would happen
.EXAMPLE
    .\Remove-Persistence.ps1                  # list, type numbers, confirm each
.EXAMPLE
    .\Remove-Persistence.ps1 -Task '\WindowsUpdateCheck' -Service evilsvc -Delete -KillProcess
.EXAMPLE
    .\Remove-Persistence.ps1 -File C:\inetpub\wwwroot\wp-content\uploads\x.php
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('RED', 'YELLOW')][string]$MinLevel = 'RED',
    [string[]]$Task = @(),
    [string[]]$Service = @(),
    [string[]]$File = @(),
    [switch]$All,
    [switch]$Delete,
    [switch]$KillProcess,
    [switch]$AllowScored,
    [int]$RecentDays = 3,
    [string[]]$WebRoots = @(),
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Remove-Persistence'
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config
$scoredPorts = @(); if ($hostCfg) { $scoredPorts = @($hostCfg.scoredPorts.tcp) }
$cutoff = (Get-Date).AddDays(-$RecentDays)

# Same heuristics as audit\Audit-Persistence.ps1 (keep the two in step).
$badPathRegex = '(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)|Users\\Public|ProgramData\\(?!Microsoft)|Windows\\Temp|\\Temp\\|PerfLogs|\$Recycle)'
$badCmdRegex  = '(?i)(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|bitsadmin|certutil.+-urlcache|mshta|regsvr32.+/i:http|rundll32.+javascript|\bnc(\.exe)?\s|ncat|socat|powercat)'
$launcherRegex = '(?i)(cmd(\.exe)?"?\s+/c|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)'
$protectedPathRegex = '(?i)^[A-Z]:\\(Windows|Program Files( \(x86\))?)\\'

function Get-Severity([string]$text) {
    if ($text -match $badCmdRegex -or $text -match $badPathRegex) { return 'RED' }
    return 'YELLOW'
}

function Get-PayloadPath([string]$commandLine) {
    <#
      Finds the file a command line really runs. For "powershell -File C:\x\a.ps1"
      the payload is a.ps1, not powershell.exe, so script-looking arguments win.
      Returns '' when nothing on disk matches.
    #>
    if (-not $commandLine) { return '' }
    $cl = [Environment]::ExpandEnvironmentVariables($commandLine)
    $found = @()
    foreach ($m in [regex]::Matches($cl, '(?i)[A-Z]:\\[^"''|<>*?\r\n]+?\.(ps1|bat|cmd|vbs|vbe|js|jse|hta|wsf|exe|dll|scr|py|php|aspx?)\b')) { $found += $m.Value.Trim() }
    # Prefer a payload outside Windows / Program Files (that is the attacker's file).
    $pick = $found | Where-Object { $_ -notmatch $protectedPathRegex -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    if (-not $pick) { $pick = $found | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1 }
    return [string]$pick
}

$script:candidates = New-Object System.Collections.ArrayList
function Add-Candidate {
    param([string]$Type, [string]$Level, [string]$Name, [string]$Detail = '', [string]$Payload = '', $Data = $null)
    [void]$script:candidates.Add([pscustomobject]@{ N = 0; Type = $Type; Level = $Level; Name = $Name; Detail = $Detail; Payload = $Payload; Data = $Data })
}

# ---------------------------------------------------------------------------
# Collectors: each adds candidates. Nothing is changed here.
# ---------------------------------------------------------------------------
function Find-Tasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }
    $visible = @{}
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        $visible[$full.ToLower()] = $true
        if ($t.TaskName -like 'CCDC-*') { continue }   # our own (firewall rollback, watch loop)
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        $isMsPath = $t.TaskPath -like '\Microsoft\*'
        $isMsAuthor = $t.Author -match 'Microsoft|^\$\(@%SystemRoot%'
        if ($isMsPath -and $isMsAuthor -and $actions -notmatch $badCmdRegex -and $actions -notmatch $badPathRegex) { continue }
        $lvl = Get-Severity $actions
        if ($isMsPath -and -not $isMsAuthor) { $lvl = 'RED' }
        Add-Candidate -Type 'Task' -Level $lvl -Name $full -Detail ("[{0}] author={1} runs: {2}" -f $t.State, $t.Author, $actions) -Payload (Get-PayloadPath $actions) -Data $t
    }
    # Hidden tasks: registered in the registry but invisible to Task Scheduler (SD value deleted).
    $treeRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    if ((Test-Path $treeRoot) -and $visible.Count -gt 0) {
        foreach ($key in (Get-ChildItem $treeRoot -Recurse -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if (-not $props -or -not ($props.PSObject.Properties.Name -contains 'Id')) { continue }
            if ($props.PSObject.Properties.Name -contains 'SD') { continue }
            $taskPath = '\' + ($key.Name -replace '^.*\\TaskCache\\Tree\\', '')
            Add-Candidate -Type 'HiddenTask' -Level 'RED' -Name $taskPath -Detail 'no SD value: hidden from schtasks / Task Scheduler on purpose' `
                -Payload '' -Data @{ TreeKey = $key.Name; Id = [string]$props.Id; File = (Join-Path "$env:windir\System32\Tasks" $taskPath.TrimStart('\')) }
        }
    }
}

function Find-Services {
    foreach ($s in (Get-WmiObject Win32_Service)) {
        $p = [string]$s.PathName
        if (-not $p) { continue }
        $normal = $p -match '(?i)^"?[A-Z]:\\Windows\\' -or $p -match '(?i)^"?[A-Z]:\\Program Files( \(x86\))?\\'
        $launcher = $p -match $launcherRegex -and $p -notmatch '(?i)\\svchost\.exe'
        if ($normal -and -not $launcher -and $p -notmatch $badCmdRegex) { continue }
        $lvl = if ($launcher -or $p -match $badPathRegex -or $p -match $badCmdRegex) { 'RED' } else { 'YELLOW' }
        Add-Candidate -Type 'Service' -Level $lvl -Name $s.Name -Detail ("({0}) start={1} state={2} as {3} runs: {4}" -f $s.DisplayName, $s.StartMode, $s.State, $s.StartName, $p) -Payload (Get-PayloadPath $p) -Data $s
    }
}

function Find-RunKeys {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$|^S-1-5-(18|19|20)$' } | ForEach-Object {
        $runKeys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $runKeys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $runKeys) {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $val = [string]$p.Value
            Add-Candidate -Type 'RunKey' -Level (Get-Severity $val) -Name ("{0} -> {1}" -f ($k -replace '^(HKLM:|Registry::HKEY_USERS)\\', ''), $p.Name) -Detail $val -Payload (Get-PayloadPath $val) -Data @{ Key = $k; Value = $p.Name }
        }
    }
}

function Find-StartupFiles {
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $dirs += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    foreach ($dir in $dirs) {
        Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
            $lvl = if ($_.Extension -match '(?i)^\.(bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|scr|exe)$' -and $_.LastWriteTime -gt $cutoff) { 'RED' } else { 'YELLOW' }
            Add-Candidate -Type 'StartupFile' -Level $lvl -Name $_.FullName -Detail ("modified {0}" -f $_.LastWriteTime) -Payload $_.FullName
        }
    }
}

function Find-Wmi {
    foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        foreach ($o in (Get-WmiObject -Namespace root\subscription -Class $cls -ErrorAction SilentlyContinue)) {
            if ($o.Name -in @('SCM Event Log Consumer', 'BVTConsumer')) { continue }
            $what = if ($cls -eq 'CommandLineEventConsumer') { [string]$o.CommandLineTemplate } else { "$($o.ScriptingEngine): $($o.ScriptText)" }
            if ($what.Length -gt 200) { $what = $what.Substring(0, 200) + '...' }
            Add-Candidate -Type 'Wmi' -Level 'RED' -Name ("{0}: {1}" -f $cls, $o.Name) -Detail $what -Payload (Get-PayloadPath $what) -Data $o
        }
    }
}

function Find-Registry {
    # IFEO debuggers
    $accessibility = @('sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe')
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                $lvl = if ($accessibility -contains $_.PSChildName.ToLower()) { 'RED' } else { 'YELLOW' }
                Add-Candidate -Type 'Ifeo' -Level $lvl -Name ("IFEO {0}" -f $_.PSChildName) -Detail "Debugger = $dbg" -Data @{ Key = $_.PSPath; RegKey = $_.Name }
            }
        }
    }
    # Winlogon
    $wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wl = Get-ItemProperty $wlKey -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Userinit -and $wl.Userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') {
            Add-Candidate -Type 'Winlogon' -Level 'RED' -Name 'Winlogon Userinit' -Detail $wl.Userinit -Payload (Get-PayloadPath ($wl.Userinit -replace '(?i)C:\\Windows\\system32\\userinit\.exe,?', '')) -Data @{ Value = 'Userinit'; Default = 'C:\Windows\system32\userinit.exe,' }
        }
        if ($wl.Shell -and $wl.Shell -notmatch '(?i)^explorer\.exe$') {
            Add-Candidate -Type 'Winlogon' -Level 'RED' -Name 'Winlogon Shell' -Detail $wl.Shell -Payload (Get-PayloadPath $wl.Shell) -Data @{ Value = 'Shell'; Default = 'explorer.exe' }
        }
    }
    # AppInit_DLLs
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($v -and $v.AppInit_DLLs) {
            $lvl = if ($v.LoadAppInit_DLLs -eq 1) { 'RED' } else { 'YELLOW' }
            Add-Candidate -Type 'AppInit' -Level $lvl -Name ("AppInit_DLLs ({0})" -f $(if ($k -match 'WOW6432') { '32-bit' } else { '64-bit' })) -Detail $v.AppInit_DLLs -Payload (Get-PayloadPath $v.AppInit_DLLs) -Data @{ Key = $k }
        }
    }
    # LSA packages
    $lsaKnown = @{
        'Authentication Packages' = @('msv1_0')
        'Notification Packages'   = @('scecli', 'rassfm')
        'Security Packages'       = @('', '""', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp')
    }
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig')) {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $v) { continue }
        foreach ($name in $lsaKnown.Keys) {
            foreach ($pkg in @($v.$name)) {
                if ($null -eq $pkg) { continue }
                $p = ([string]$pkg).Trim()
                if ($lsaKnown[$name] -contains $p.ToLower()) { continue }
                $dll = Join-Path "$env:windir\System32" ($p + $(if ($p -notmatch '\.dll$') { '.dll' } else { '' }))
                Add-Candidate -Type 'LsaPackage' -Level 'RED' -Name ("LSA {0}: {1}" -f $name, $p) -Detail 'unknown DLL loaded into LSASS at boot (sees every password)' -Payload $(if (Test-Path $dll) { $dll } else { '' }) -Data @{ Key = $k; Value = $name; Entry = $pkg }
            }
        }
    }
}

function Find-Defender {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { return }
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $mp) { return }
    foreach ($kind in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')) {
        foreach ($v in @($mp.$kind)) { if ($v) { Add-Candidate -Type 'DefenderExclusion' -Level 'RED' -Name ("Defender {0}: {1}" -f $kind, $v) -Detail 'Defender does not scan this' -Data @{ Kind = $kind; Value = [string]$v } } }
    }
    if ($mp.DisableRealtimeMonitoring) { Add-Candidate -Type 'DefenderOff' -Level 'RED' -Name 'Defender real-time protection is OFF' -Detail 'DisableRealtimeMonitoring = True' }
}

function Find-SshKeys {
    $files = @("$env:ProgramData\ssh\administrators_authorized_keys")
    $files += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys'; Join-Path $_.FullName '.ssh\authorized_keys2' }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($line in @(Get-Content -LiteralPath $f -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })) {
            $parts = $line.Trim() -split '\s+'
            $comment = if ($parts.Count -ge 3) { $parts[2..($parts.Count - 1)] -join ' ' } else { '(no comment)' }
            $tail = if ($parts.Count -ge 2 -and $parts[1].Length -gt 16) { $parts[1].Substring($parts[1].Length - 16) } else { '' }
            Add-Candidate -Type 'SshKey' -Level 'RED' -Name ("{0}: {1} ...{2} {3}" -f $f, $parts[0], $tail, $comment) -Detail ("file modified {0}. This key logs in without any password." -f (Get-Item -LiteralPath $f).LastWriteTime) -Data @{ File = $f; Line = $line }
        }
    }
}

function Get-WebRoots {
    $roots = @($WebRoots)
    $appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHost) {
        try {
            $xml = [xml](Get-Content $appHost -Raw)
            $roots += $xml.configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }
        } catch { $null = $_ }
    }
    foreach ($d in @('C:\inetpub\wwwroot', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\Apache24\htdocs')) { if (Test-Path $d) { $roots += $d } }
    return @($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
}

function Find-WebShells {
    $shellExt = @('*.php', '*.php3', '*.php5', '*.phtml', '*.asp', '*.aspx', '*.ashx', '*.asmx', '*.jsp', '*.cfm')
    $shellPatterns = '(?i)(eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|base64_decode\s*\(\s*\$_|assert\s*\(\s*\$_|system\s*\(\s*\$_|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|preg_replace\s*\(.*/e[''"]|ProcessStartInfo|cmd\.exe\s*/c|WScript\.Shell|Request\.Form\(.{0,40}\)\s*\)\s*;?\s*Execute|eval\(Request)'
    foreach ($r in (Get-WebRoots)) {
        foreach ($f in (Get-ChildItem -Path $r -Recurse -File -Include $shellExt -Force -ErrorAction SilentlyContinue)) {
            $isRecent = $f.LastWriteTime -gt $cutoff -or $f.CreationTime -gt $cutoff
            $inUploads = $f.FullName -match '(?i)\\uploads?\\' -and $f.Extension -match '(?i)^\.ph'
            $hit = $null
            if ($f.Length -lt 2MB -and ($isRecent -or $inUploads -or $MinLevel -eq 'YELLOW')) { $hit = Select-String -LiteralPath $f.FullName -Pattern $shellPatterns -List -ErrorAction SilentlyContinue }
            if (($hit -and $isRecent) -or $inUploads) {
                $why = @(); if ($inUploads) { $why += 'PHP inside an uploads folder' }; if ($hit) { $why += "suspicious code on line $($hit.LineNumber)" }
                Add-Candidate -Type 'WebShell' -Level 'RED' -Name $f.FullName -Detail ("{0}; created {1}, modified {2}" -f ($why -join ', '), $f.CreationTime, $f.LastWriteTime) -Payload $f.FullName
            } elseif ($hit) {
                Add-Candidate -Type 'WebShell' -Level 'YELLOW' -Name $f.FullName -Detail ("suspicious code on line {0} but file is old (could be the application itself)" -f $hit.LineNumber) -Payload $f.FullName
            }
        }
    }
}

function Find-Profiles {
    $profiles = @("$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
                  "$env:windir\SysWOW64\WindowsPowerShell\v1.0\profile.ps1", "$env:ProgramFiles\PowerShell\7\profile.ps1")
    $profiles += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Join-Path $_.FullName 'Documents\WindowsPowerShell\profile.ps1'
        Join-Path $_.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
        Join-Path $_.FullName 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
    }
    foreach ($p in ($profiles | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $body = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
        # Aliases / functions that shadow real commands are how tools get sabotaged ("why does netstat show nothing?").
        $lvl = if ($body -match $badCmdRegex -or $body -match '(?i)(set-alias|new-alias|function\s+(get-|netstat|ipconfig|net|ls|dir|cat|whoami|tasklist))') { 'RED' } else { 'YELLOW' }
        Add-Candidate -Type 'PsProfile' -Level $lvl -Name $p -Detail ("runs at every PowerShell start; modified {0}" -f (Get-Item -LiteralPath $p).LastWriteTime) -Payload $p
    }
}

function Find-PortProxy {
    # Output rows look like:  0.0.0.0   8080   10.0.0.5   3389
    $family = ''
    foreach ($line in @(& netsh.exe interface portproxy show all 2>$null)) {
        if ($line -match '(?i)ipv4:|ipv6:') { $family = (($line -split '\s+') | Where-Object { $_ -match '(?i)ipv[46]:' }) -join '' }
        if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
            # "Listen on ipv4: Connect to ipv4:" -> v4tov4
            $kind = 'v4tov4'
            if ($family -match '(?i)ipv(\d):ipv(\d):') { $kind = "v$($Matches[1])tov$($Matches[2])" }
            Add-Candidate -Type 'PortProxy' -Level 'RED' -Name ("portproxy {0}:{1} -> {2}:{3}" -f $Matches[1], $Matches[2], $Matches[3], $Matches[4]) -Detail 'traffic to this port is silently forwarded elsewhere (pivot or service hijack)' `
                -Data @{ Kind = $kind; ListenAddress = $Matches[1]; ListenPort = $Matches[2]; ConnectAddress = $Matches[3]; ConnectPort = $Matches[4] }
        }
    }
}

# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------
$quarantine = $null
function Get-Quarantine { if (-not $script:quarantine) { $script:quarantine = Get-CcdcQuarantineDir }; return $script:quarantine }

function Get-FileFacts([string]$path) {
    # Hash + timestamps + owner of a payload file (the "when was it created" for the report).
    $facts = @{}
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $facts }
    $fi = Get-Item -LiteralPath $path -Force
    $facts['PayloadPath']     = $path
    $facts['PayloadSha256']   = Get-CcdcFileHash -Path $path
    $facts['PayloadCreated']  = $fi.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
    $facts['PayloadModified'] = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    $facts['PayloadSize']     = $fi.Length
    try { $facts['PayloadOwner'] = (Get-Acl -LiteralPath $path).Owner } catch { $null = $_ }
    try { $facts['PayloadSignature'] = [string](Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop).Status } catch { $null = $_ }
    return $facts
}

function Copy-ToQuarantine([string]$path) {
    # Keeps a copy as evidence. ".quarantined" is appended so it can never be run or served by accident.
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    $dest = Join-Path (Get-Quarantine) ((($path -replace ':', '') -replace '[\\/]', '_') + '.quarantined')
    try { Copy-Item -LiteralPath $path -Destination $dest -Force -WhatIf:$false; return $dest } catch { return '' }
}

function Find-CreationEvent([string]$type, [string]$name) {
    <#
      Looks for the event that recorded this task / service being created, so
      the evidence says WHO made it, WHEN, and FROM WHICH ADDRESS.
      Needs the audit policy (4698 / 4697); 7045 is always logged.
    #>
    $out = @{}
    $safe = $name -replace "'", ''
    try {
        if ($type -eq 'Task') {
            $ev = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4698] and EventData[Data[@Name='TaskName']='$safe']]" -MaxEvents 1 -ErrorAction Stop
        } else {
            $ev = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4697] and EventData[Data[@Name='ServiceName']='$safe']]" -MaxEvents 1 -ErrorAction Stop
        }
        if ($ev) {
            $d = Get-CcdcEventData -Record $ev
            $out['CreatedAt'] = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $out['CreatedBy'] = "{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']
            $out['SourceIp']  = Get-CcdcLogonSource -LogonId $d['SubjectLogonId']
        }
    } catch { $null = $_ }
    if (-not $out['CreatedAt'] -and $type -eq 'Service') {
        try {
            $ev = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045] and EventData[Data[@Name='ServiceName']='$safe']]" -MaxEvents 1 -ErrorAction Stop
            if ($ev) { $out['CreatedAt'] = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); $out['CreatedBy'] = try { $ev.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { [string]$ev.UserId } }
        } catch { $null = $_ }
    }
    return $out
}

function Find-WebRequests([string]$fileName) {
    <#
      Which addresses requested this file? Reads recent IIS logs (W3C format)
      and returns "ip xN (first HH:mm)" strings. The first one to POST to a
      web shell is very likely whoever planted or used it.
    #>
    $hits = @{}
    $logs = Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
    foreach ($log in $logs) {
        $ipIdx = -1; $dateIdx = -1; $timeIdx = -1
        foreach ($line in (Select-String -LiteralPath $log.FullName -Pattern '^#Fields:' -ErrorAction SilentlyContinue | Select-Object -Last 1)) {
            $fields = @(($line.Line -replace '^#Fields:\s*', '') -split '\s+')
            $ipIdx = [array]::IndexOf($fields, 'c-ip'); $dateIdx = [array]::IndexOf($fields, 'date'); $timeIdx = [array]::IndexOf($fields, 'time')
        }
        if ($ipIdx -lt 0) { continue }
        foreach ($m in (Select-String -LiteralPath $log.FullName -SimpleMatch -Pattern $fileName -ErrorAction SilentlyContinue)) {
            $cols = @($m.Line -split '\s+')
            if ($cols.Count -le $ipIdx) { continue }
            $ip = $cols[$ipIdx]
            $when = if ($dateIdx -ge 0 -and $timeIdx -ge 0) { "$($cols[$dateIdx]) $($cols[$timeIdx]) UTC" } else { '' }
            if (-not $hits.ContainsKey($ip)) { $hits[$ip] = @{ Count = 0; First = $when } }
            $hits[$ip].Count++
        }
    }
    return @($hits.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 8 | ForEach-Object { "{0} x{1} (first {2})" -f $_.Key, $_.Value.Count, $_.Value.First })
}

$rollbackFile  = $script:CcdcLogFile -replace '\.log$', '_rollback.ps1'
$rollbackLines = New-Object System.Collections.ArrayList
[void]$rollbackLines.Add("# Undo commands for Remove-Persistence run $($script:CcdcStamp) on $env:COMPUTERNAME. Review each line before running it.")
$script:done = 0

function Complete-Removal {
    # Called after a successful containment: evidence record + rollback line + on-screen confirmation.
    param($c, [hashtable]$Evidence, [string]$ActionTaken, [string]$UndoCommand)
    $Evidence['Type'] = $c.Type; $Evidence['Name'] = $c.Name; $Evidence['Detail'] = $c.Detail
    $Evidence['ActionTaken'] = $ActionTaken; $Evidence['Undo'] = $UndoCommand
    $evFile = Add-CcdcEvidence -Item $Evidence
    if ($UndoCommand) { [void]$rollbackLines.Add($UndoCommand) }
    $script:done++
    $src = if ($Evidence['SourceIp']) { "  created by $($Evidence['CreatedBy']) from $($Evidence['SourceIp'])" } elseif ($Evidence['CreatedBy']) { "  created by $($Evidence['CreatedBy'])" } else { '' }
    Write-Finding -Level GREEN -Category 'Removed' -Message ("{0}: {1} -> {2}{3}" -f $c.Type, $c.Name, $ActionTaken, $src) -Detail $(if ($evFile) { "evidence: $evFile" } else { '' })
    if ($Evidence['WebRequests']) { Write-Finding -Level YELLOW -Category 'Source' -Message 'Addresses that requested this file (IIS logs):' -Detail (@($Evidence['WebRequests']) -join "`n") }
}

function Stop-PayloadProcess([string]$path) {
    if (-not $KillProcess -or -not $path -or $path -match $protectedPathRegex) { return }
    foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -ieq $path })) {
        $procId = $proc.Id
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target ("{0} (PID {1})" -f $proc.ProcessName, $procId) -Action 'Kill running payload process' -ScriptBlock { Stop-Process -Id $procId -Force })
    }
}

# ---------------------------------------------------------------------------
# One candidate in -> preserved, contained, recorded.
# NOTE for authors: scriptblocks passed to Invoke-CcdcChange must not use
# variables named $Target/$Action/$Force/$Undo/$Cmdlet (they are its parameters).
# ---------------------------------------------------------------------------
function Remove-Candidate($c) {
    $q = Get-Quarantine
    $ev = Get-FileFacts $c.Payload
    $safeName = ($c.Name -replace '[\\/:*?"<>| ]', '_'); if ($safeName.Length -gt 80) { $safeName = $safeName.Substring($safeName.Length - 80) }

    switch ($c.Type) {
        'Task' {
            $t = $c.Data; $tn = $t.TaskName; $tp = $t.TaskPath
            $xmlFile = Join-Path $q ("task_{0}.xml" -f $safeName)
            if (-not $WhatIfPreference) {
                try { Export-ScheduledTask -TaskName $tn -TaskPath $tp | Out-File -FilePath $xmlFile -Encoding Unicode } catch { Write-Finding -Level YELLOW -Category 'Preserve' -Message "Could not export task XML: $($_.Exception.Message)" }
                $ev['DefinitionFile'] = $xmlFile
                $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload
                foreach ($kv in (Find-CreationEvent 'Task' $c.Name).GetEnumerator()) { $ev[$kv.Key] = $kv.Value }
                if (-not $ev['CreatedAt'] -and $t.Date) { $ev['CreatedAt'] = "$($t.Date) (task registration date)" }
            }
            if ($Delete) {
                $undo = "Register-ScheduledTask -TaskName '$tn' -TaskPath '$tp' -Xml (Get-Content '$xmlFile' -Raw) -Force"
                $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'DELETE scheduled task (XML exported first)' -Undo $undo -ScriptBlock {
                    Stop-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $tn -TaskPath $tp -Confirm:$false
                }
                if ($ok) { Complete-Removal $c $ev 'task deleted' $undo }
            } else {
                $undo = "Enable-ScheduledTask -TaskName '$tn' -TaskPath '$tp'"
                $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Disable scheduled task' -Undo $undo -ScriptBlock {
                    Stop-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction SilentlyContinue
                    Disable-ScheduledTask -TaskName $tn -TaskPath $tp | Out-Null
                }
                if ($ok) { Complete-Removal $c $ev 'task disabled (re-run with -Delete to remove it)' $undo }
            }
            if ($ok) { Stop-PayloadProcess $c.Payload }
        }
        'HiddenTask' {
            $treeKey = [string]$c.Data.TreeKey; $taskId = [string]$c.Data.Id; $taskFile = [string]$c.Data.File
            $tasksKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$taskId"
            $ev['TaskId'] = $taskId
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Remove hidden task (registry keys exported, task file quarantined)' -Undo 'reg import the two exported .reg files in the backup folder, move the task file back, restart the Schedule service' -ScriptBlock {
                $r1 = Backup-CcdcRegistry -Key $treeKey
                $r2 = Backup-CcdcRegistry -Key $tasksKey
                if (-not $r1) { throw "could not export $treeKey - refusing to delete without a backup" }
                $null = $r2
                if (Test-Path -LiteralPath $taskFile) { Move-Item -LiteralPath $taskFile -Destination (Join-Path $q ("hiddentask_{0}.xml.quarantined" -f $safeName)) -Force }
                Remove-Item -LiteralPath ("Registry::$tasksKey") -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath ("Registry::$treeKey") -Recurse -Force
            }
            if ($ok) {
                Complete-Removal $c $ev 'hidden task registry entries removed' "# hidden task $($c.Name): reg import the exports under $(Get-CcdcBackupDir)"
                Write-Finding -Level YELLOW -Category 'Next' -Message 'The Task Scheduler service still has this task in memory until it restarts.' -Detail 'It will not survive a reboot. To stop it now, kill the process it started (see the task file in quarantine for what it runs).'
            }
        }
        'Service' {
            $svc = $c.Data; $svcName = [string]$svc.Name
            # Safety rail: do not take down a scored service because its path looked odd.
            $svcPid = [int]$svc.ProcessId
            if ($svcPid -gt 0 -and $scoredPorts.Count -gt 0 -and -not $AllowScored) {
                $own = @(Get-NetTCPConnection -State Listen -OwningProcess $svcPid -ErrorAction SilentlyContinue | Where-Object { $scoredPorts -contains [int]$_.LocalPort })
                if ($own.Count -gt 0) {
                    Write-Finding -Level RED -Category 'Safety' -Message ("SKIPPED service '{0}': it is listening on scored port {1}." -f $svcName, (($own | ForEach-Object { $_.LocalPort } | Sort-Object -Unique) -join ',')) -Detail 'If you are sure it is malicious, re-run with -AllowScored.'
                    return
                }
            }
            $defFile = Join-Path $q ("service_{0}.txt" -f $safeName)
            if (-not $WhatIfPreference) {
                (& sc.exe qc $svcName 2>&1) | Out-File -FilePath $defFile -Encoding UTF8
                $regFile = Backup-CcdcRegistry -Key "HKLM\SYSTEM\CurrentControlSet\Services\$svcName"
                $ev['DefinitionFile'] = $defFile; $ev['RegistryExport'] = $regFile
                $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload
                foreach ($kv in (Find-CreationEvent 'Service' $svcName).GetEnumerator()) { $ev[$kv.Key] = $kv.Value }
            }
            $oldMode = switch ([string]$svc.StartMode) { 'Auto' { 'auto' } 'Manual' { 'demand' } default { 'demand' } }
            if ($Delete) {
                $undo = "reg import `"$($ev['RegistryExport'])`"   # then reboot or: sc.exe start $svcName"
                $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $svcName -Action 'Stop and DELETE service (definition exported first)' -Undo $undo -ScriptBlock {
                    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                    $null = & sc.exe delete $svcName 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete returned $LASTEXITCODE" }
                }
                if ($ok) { Complete-Removal $c $ev 'service stopped and deleted' $undo }
            } else {
                $undo = "sc.exe config `"$svcName`" start= $oldMode ; sc.exe start `"$svcName`""
                $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $svcName -Action 'Stop service and set it to Disabled' -Undo $undo -ScriptBlock {
                    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                    $null = & sc.exe config $svcName start= disabled 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "sc.exe config returned $LASTEXITCODE" }
                }
                if ($ok) { Complete-Removal $c $ev 'service stopped and disabled (re-run with -Delete to remove it)' $undo }
            }
            if ($ok) { Stop-PayloadProcess $c.Payload }
        }
        'RunKey' {
            $rk = [string]$c.Data.Key; $rv = [string]$c.Data.Value
            $regKey = ($rk -replace '^HKLM:\\', 'HKLM\') -replace '^Registry::HKEY_USERS\\', 'HKU\'
            if (-not $WhatIfPreference) { $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload }
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Delete Run value (key exported first)' -Undo "reg import <export of $regKey in the backup folder>" -ScriptBlock {
                $script:lastRegExport = Backup-CcdcRegistry -Key $regKey
                Remove-ItemProperty -Path $rk -Name $rv -Force
            }
            if ($ok) { $ev['RegistryExport'] = $script:lastRegExport; Complete-Removal $c $ev 'Run value deleted' "reg import `"$($script:lastRegExport)`""; Stop-PayloadProcess $c.Payload }
        }
        { $_ -in 'StartupFile', 'WebShell', 'PsProfile', 'File' } {
            $src = [string]$c.Payload
            if ($src -match $protectedPathRegex -and $c.Type -eq 'File') {
                Write-Finding -Level RED -Category 'Safety' -Message "SKIPPED $src - refusing to move a file under Windows / Program Files." -Detail 'If it really is a replaced system binary, restore it with: sfc /scanfile="<path>"'
                return
            }
            $dest = Join-Path $q ((($src -replace ':', '') -replace '[\\/]', '_') + '.quarantined')
            if ($c.Type -eq 'WebShell' -and -not $WhatIfPreference) { $ev['WebRequests'] = @(Find-WebRequests (Split-Path $src -Leaf)) }
            $undo = "Move-Item -LiteralPath '$dest' -Destination '$src'"
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $src -Action 'Move file to quarantine' -Undo $undo -ScriptBlock {
                Move-Item -LiteralPath $src -Destination $dest -Force
            }
            if ($ok) { $ev['QuarantinePath'] = $dest; Complete-Removal $c $ev 'file moved to quarantine' $undo; Stop-PayloadProcess $src }
        }
        'Wmi' {
            $consumer = $c.Data
            $mofFile = Join-Path $q ("wmi_{0}.mof" -f $safeName)
            $rel = [string]$consumer.__RELPATH
            $bindings = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { ([string]$_.Consumer) -like "*$rel" -or ([string]$_.Consumer) -like "*Name=`"$($consumer.Name)`"" })
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action ("Remove WMI consumer + {0} binding(s) + their filters (MOF saved first)" -f $bindings.Count) -Undo "mofcomp `"$mofFile`"" -ScriptBlock {
                $mof = @("#pragma namespace(`"\\\\.\\root\\subscription`")", $consumer.GetText('mof'))
                $filters = @()
                foreach ($b in $bindings) {
                    $mof += $b.GetText('mof')
                    try { $f = [wmi]("\\.\root\subscription:" + ([string]$b.Filter -replace '^.*:', '')); $mof += $f.GetText('mof'); $filters += $f } catch { $null = $_ }
                }
                $mof | Out-File -FilePath $mofFile -Encoding Unicode
                foreach ($b in $bindings) { $b | Remove-WmiObject }
                $consumer | Remove-WmiObject
                foreach ($f in $filters) {
                    # Only remove a filter nothing else is bound to.
                    $still = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { ([string]$_.Filter) -like "*$($f.__RELPATH)" })
                    if ($still.Count -eq 0) { $f | Remove-WmiObject }
                }
            }
            if ($ok) { $ev['DefinitionFile'] = $mofFile; if (-not $WhatIfPreference) { $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload }; Complete-Removal $c $ev 'WMI subscription removed' "mofcomp `"$mofFile`"" }
        }
        'Ifeo' {
            $ifeoPath = [string]$c.Data.Key; $ifeoReg = [string]$c.Data.RegKey
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Delete IFEO Debugger value (key exported first)' -Undo "reg import <export of $ifeoReg>" -ScriptBlock {
                $script:lastRegExport = Backup-CcdcRegistry -Key $ifeoReg
                Remove-ItemProperty -Path $ifeoPath -Name Debugger -Force
            }
            if ($ok) { $ev['RegistryExport'] = $script:lastRegExport; Complete-Removal $c $ev 'Debugger value deleted' "reg import `"$($script:lastRegExport)`"" }
        }
        'Winlogon' {
            $wlValue = [string]$c.Data.Value; $wlDefault = [string]$c.Data.Default
            if (-not $WhatIfPreference) { $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload }
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action "Reset to default '$wlDefault' (key exported first)" -Undo 'reg import <export of the Winlogon key>' -ScriptBlock {
                $script:lastRegExport = Backup-CcdcRegistry -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name $wlValue -Value $wlDefault
            }
            if ($ok) { $ev['RegistryExport'] = $script:lastRegExport; Complete-Removal $c $ev "reset to $wlDefault" "reg import `"$($script:lastRegExport)`"" }
        }
        'AppInit' {
            $aiKey = [string]$c.Data.Key
            if (-not $WhatIfPreference) { $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload }
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Clear AppInit_DLLs (key exported first)' -Undo 'reg import <export of the Windows key>' -ScriptBlock {
                $script:lastRegExport = Backup-CcdcRegistry -Key (($aiKey -replace '^HKLM:\\', 'HKLM\'))
                Set-ItemProperty -Path $aiKey -Name AppInit_DLLs -Value ''
                Set-ItemProperty -Path $aiKey -Name LoadAppInit_DLLs -Value 0 -Type DWord
            }
            if ($ok) { $ev['RegistryExport'] = $script:lastRegExport; Complete-Removal $c $ev 'AppInit_DLLs cleared' "reg import `"$($script:lastRegExport)`"" }
        }
        'LsaPackage' {
            $lsaKey = [string]$c.Data.Key; $lsaValue = [string]$c.Data.Value; $lsaEntry = [string]$c.Data.Entry
            if (-not $WhatIfPreference) { $ev['PayloadCopy'] = Copy-ToQuarantine $c.Payload }
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Remove entry from the LSA package list (key exported first; takes effect at next boot)' -Undo 'reg import <export of the Lsa key>' -ScriptBlock {
                $script:lastRegExport = Backup-CcdcRegistry -Key (($lsaKey -replace '^HKLM:\\', 'HKLM\'))
                $current = @((Get-ItemProperty -Path $lsaKey -Name $lsaValue).$lsaValue)
                $keep = @($current | Where-Object { $_ -ne $lsaEntry })
                Set-ItemProperty -Path $lsaKey -Name $lsaValue -Value ([string[]]$keep) -Type MultiString
            }
            if ($ok) {
                $ev['RegistryExport'] = $script:lastRegExport
                Complete-Removal $c $ev 'LSA package entry removed' "reg import `"$($script:lastRegExport)`""
                Write-Finding -Level YELLOW -Category 'Next' -Message 'The DLL stays loaded in LSASS until reboot. Every password typed since it was installed is compromised: rotate them.'
            }
        }
        'DefenderExclusion' {
            $exKind = [string]$c.Data.Kind; $exValue = [string]$c.Data.Value
            $undo = "Add-MpPreference -$exKind '$exValue'"
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Remove Defender exclusion' -Undo $undo -ScriptBlock {
                $splat = @{ $exKind = $exValue }
                Remove-MpPreference @splat
            }
            if ($ok) { Complete-Removal $c $ev 'exclusion removed' $undo; Write-Finding -Level YELLOW -Category 'Next' -Message "Now scan what was excluded: Start-MpScan -ScanType CustomScan -ScanPath '$exValue'" }
        }
        'DefenderOff' {
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Windows Defender' -Action 'Turn real-time protection back on' -Undo 'Set-MpPreference -DisableRealtimeMonitoring $true' -ScriptBlock {
                Set-MpPreference -DisableRealtimeMonitoring $false
            }
            if ($ok) { Complete-Removal $c $ev 'real-time protection enabled' '' }
        }
        'SshKey' {
            $keyFile = [string]$c.Data.File; $keyLine = [string]$c.Data.Line
            $ev['KeyFile'] = $keyFile
            $ev['KeyFileModified'] = (Get-Item -LiteralPath $keyFile).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Delete this key line (file backed up first)' -Undo 'copy the backed-up file back over the original' -ScriptBlock {
                $script:lastFileBackup = Backup-CcdcFile -Path $keyFile
                $keep = @(Get-Content -LiteralPath $keyFile | Where-Object { $_ -ne $keyLine })
                # WriteAllLines writes UTF-8 without a BOM; sshd rejects a key file that starts with a BOM.
                [System.IO.File]::WriteAllLines($keyFile, [string[]]$keep)
            }
            if ($ok) { $ev['FileBackup'] = $script:lastFileBackup; Complete-Removal $c $ev 'key line removed' "Copy-Item -LiteralPath '$($script:lastFileBackup)' -Destination '$keyFile' -Force" }
        }
        'PortProxy' {
            $ppKind = [string]$c.Data.Kind; $ppAddr = [string]$c.Data.ListenAddress; $ppPort = [string]$c.Data.ListenPort
            $undo = "netsh interface portproxy add $ppKind listenaddress=$ppAddr listenport=$ppPort connectaddress=$($c.Data.ConnectAddress) connectport=$($c.Data.ConnectPort)"
            $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $c.Name -Action 'Delete port proxy' -Undo $undo -ScriptBlock {
                $null = & netsh.exe interface portproxy delete $ppKind "listenaddress=$ppAddr" "listenport=$ppPort" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "netsh returned $LASTEXITCODE" }
            }
            if ($ok) { Complete-Removal $c $ev 'port proxy deleted' $undo }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$direct = ($Task.Count + $Service.Count + $File.Count) -gt 0
if ($direct) {
    Write-Section 'Targets you named'
    foreach ($tn in $Task) {
        $leaf = ($tn -split '\\')[-1]; $path = ($tn.Substring(0, $tn.Length - $leaf.Length)); if (-not $path) { $path = '\' }
        $t = Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $t) { Write-Finding -Level YELLOW -Category 'Target' -Message "Scheduled task '$tn' not found (give the full path, e.g. '\Folder\Name')."; continue }
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        Add-Candidate -Type 'Task' -Level 'RED' -Name "$($t.TaskPath)$($t.TaskName)" -Detail ("[{0}] author={1} runs: {2}" -f $t.State, $t.Author, $actions) -Payload (Get-PayloadPath $actions) -Data $t
    }
    foreach ($sn in $Service) {
        $s = Get-WmiObject Win32_Service -Filter ("Name='{0}'" -f ($sn -replace "'", '')) -ErrorAction SilentlyContinue
        if (-not $s) { Write-Finding -Level YELLOW -Category 'Target' -Message "Service '$sn' not found (use the short name from: Get-Service)."; continue }
        Add-Candidate -Type 'Service' -Level 'RED' -Name $s.Name -Detail ("({0}) start={1} state={2} as {3} runs: {4}" -f $s.DisplayName, $s.StartMode, $s.State, $s.StartName, $s.PathName) -Payload (Get-PayloadPath ([string]$s.PathName)) -Data $s
    }
    foreach ($fp in $File) {
        if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) { Write-Finding -Level YELLOW -Category 'Target' -Message "File '$fp' not found."; continue }
        $full = (Get-Item -LiteralPath $fp -Force).FullName
        $isWeb = @(Get-WebRoots | Where-Object { $full -like "$_*" }).Count -gt 0
        Add-Candidate -Type $(if ($isWeb) { 'WebShell' } else { 'File' }) -Level 'RED' -Name $full -Detail 'named on the command line' -Payload $full
    }
} else {
    Write-Section 'Looking for removable persistence'
    foreach ($finder in @('Find-Tasks', 'Find-Services', 'Find-RunKeys', 'Find-StartupFiles', 'Find-Wmi', 'Find-Registry', 'Find-Defender', 'Find-SshKeys', 'Find-WebShells', 'Find-Profiles', 'Find-PortProxy')) {
        try { & $finder } catch { Write-Finding -Level YELLOW -Category 'Scan' -Message "$finder failed: $($_.Exception.Message)" }
    }
}

$list = @($script:candidates | Where-Object { $MinLevel -eq 'YELLOW' -or $_.Level -eq 'RED' -or $direct } | Sort-Object @{ Expression = { if ($_.Level -eq 'RED') { 0 } else { 1 } } }, Type, Name)
$hiddenYellow = @($script:candidates).Count - $list.Count
if ($list.Count -eq 0) {
    Write-Finding -Level GREEN -Category 'Scan' -Message "Nothing at level $MinLevel to remove."
    if ($hiddenYellow -gt 0) { Write-Finding -Level INFO -Category 'Scan' -Message "$hiddenYellow lower-confidence item(s) exist: re-run with -MinLevel YELLOW to see them." }
    Complete-Ccdc
    return
}

Write-Section ("{0} candidate(s)" -f $list.Count)
$i = 0
foreach ($c in $list) {
    $i++; $c.N = $i
    $color = if ($c.Level -eq 'RED') { 'Red' } else { 'Yellow' }
    Write-Host ("  [{0,2}] " -f $i) -NoNewline -ForegroundColor White
    Write-Host ("{0,-17} " -f $c.Type) -NoNewline -ForegroundColor Cyan
    Write-Host $c.Name -ForegroundColor $color
    if ($c.Detail) { Write-Host ("       {0}" -f $(if ($c.Detail.Length -gt 220) { $c.Detail.Substring(0, 220) + '...' } else { $c.Detail })) -ForegroundColor DarkGray }
    if ($c.Payload -and $c.Payload -ne $c.Name) { Write-Host ("       payload: {0}" -f $c.Payload) -ForegroundColor DarkGray }
    Write-CcdcLog ("CANDIDATE {0} {1} {2} | {3}" -f $c.Level, $c.Type, $c.Name, $c.Detail)
}
if ($hiddenYellow -gt 0) { Write-Host ("`n  (+{0} lower-confidence item(s) hidden: -MinLevel YELLOW shows them)" -f $hiddenYellow) -ForegroundColor DarkGray }
Write-Host '  Accounts are not listed here: use harden\Disable-Accounts.ps1.' -ForegroundColor DarkGray

# Which ones? Direct targets, -All and -WhatIf need no prompt.
$selected = @()
if ($direct -or $All -or $WhatIfPreference) {
    $selected = $list
} else {
    Write-Host ""
    $answer = Read-Host '  Numbers to remove (e.g. 1,3,5-7), A = all listed, Enter = none'
    if ($answer -match '^\s*a(ll)?\s*$') { $selected = $list }
    else {
        $nums = @()
        foreach ($part in ($answer -split '[,\s]+' | Where-Object { $_ })) {
            if ($part -match '^(\d+)-(\d+)$') { $nums += ([int]$Matches[1])..([int]$Matches[2]) }
            elseif ($part -match '^\d+$') { $nums += [int]$part }
        }
        $selected = @($list | Where-Object { $nums -contains $_.N })
    }
}
if ($selected.Count -eq 0) {
    Write-Finding -Level INFO -Category 'Remove' -Message 'Nothing selected. Nothing was changed.'
    Complete-Ccdc
    return
}

Write-Section ("Preserve -> contain -> record ({0} item(s))" -f $selected.Count)
foreach ($c in $selected) {
    try { Remove-Candidate $c } catch { Write-Finding -Level RED -Category 'Remove' -Message ("{0} '{1}' failed: {2}" -f $c.Type, $c.Name, $_.Exception.Message) }
}

if ($rollbackLines.Count -gt 1) {
    $rollbackLines | Set-Content -Path $rollbackFile -Encoding UTF8 -WhatIf:$false
    Write-Finding -Level INFO -Category 'Rollback' -Message "Undo commands: $rollbackFile"
}
if ($script:done -gt 0) {
    Write-Finding -Level INFO -Category 'Next' -Message ("{0} item(s) contained. Evidence: {1}\evidence_{2}.jsonl   Quarantine: {3}" -f $script:done, $script:CcdcEvidenceRoot, $env:COMPUTERNAME, $script:quarantine) `
        -Detail "1. File the incident report now:  hunt\New-IncidentReport.ps1`n2. Find how they got in (rotate the account they used; it is in the evidence when the log had it).`n3. Re-baseline the watch loop:  hunt\Watch-Changes.ps1 -Mode Baseline"
}
Complete-Ccdc
