<#
.SYNOPSIS
    Audit-Persistence - hunt the places Red Team hides to survive reboots. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Walks the common Windows persistence locations and flags anything that
      looks non-default. It does NOT remove anything - removal is a
      deliberate, logged step (harden\Harden-Baseline.ps1 -Only IFEO, or by
      hand following docs\incident-response.md).

    CHECKS
      1. Scheduled tasks       non-Microsoft author, actions in user-writable paths, encoded PowerShell
      2. Services              binaries outside Windows\ / Program Files, cmd/powershell launchers, unquoted paths
      3. Run / RunOnce keys    HKLM (64+32 bit) and every loaded user hive
      4. Startup folders       all-users and per-user
      5. WMI subscriptions     __EventFilter / consumers / bindings in root\subscription
      6. Winlogon              Userinit and Shell values
      7. IFEO debuggers        sticky-keys style hijacks (sethc, utilman, osk, narrator, magnify...)
                               plus accessibility binaries that were swapped for cmd.exe
      8. AppInit_DLLs          DLLs injected into every GUI process
      9. OpenSSH               administrators_authorized_keys, per-user authorized_keys, sshd_config
     10. Defender exclusions   paths/processes/extensions Defender ignores
     11. System32 changes      .exe/.dll/.sys modified in the last -RecentDays days
     12. Web shells            recent .php/.asp/.aspx/... in IIS web roots + eval/base64/system patterns

    WHAT IT READS   registry, Task Scheduler, WMI, file system, Defender preferences
    WHAT IT CHANGES nothing (own log + optional report only)
    HOW TO UNDO     nothing to undo

    MANUAL EQUIVALENT
      schtasks /query /fo LIST /v | more
      Get-ScheduledTask | ? Author -notmatch Microsoft | fl TaskName,TaskPath,Author,Actions
      Get-WmiObject win32_service | select Name,PathName | ? PathName -notmatch 'Windows'
      reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
      reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
      reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /f Debugger
      Get-WmiObject -Namespace root\subscription -Class __EventConsumer
      Get-MpPreference | select Exclusion*
      type C:\ProgramData\ssh\administrators_authorized_keys

.PARAMETER RecentDays
    "Recent" window for file modification checks. Default 3.

.PARAMETER WebRoots
    Extra web root folders to scan (IIS site paths are discovered automatically).

.EXAMPLE
    .\Audit-Persistence.ps1 -OutFile C:\ccdc\reports\persist.csv
#>
[CmdletBinding()]
param(
    [int]$RecentDays = 3,
    [string[]]$WebRoots = @(),
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Persistence' -OutFile $OutFile -ReadOnly
$null   = Get-CcdcConfig -Path $ConfigPath
$cutoff = (Get-Date).AddDays(-$RecentDays)

# Paths a normal program should not run from. Attackers love these because
# any user can write there.
$badPathRegex  = '(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)|Users\\Public|ProgramData\\(?!Microsoft)|Windows\\Temp|\\Temp\\|PerfLogs|\$Recycle)'
# Command lines that are almost always malicious in a scheduled task / Run key.
$badCmdRegex   = '(?i)(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|bitsadmin|certutil.+-urlcache|mshta|regsvr32.+/i:http|rundll32.+javascript|\bnc(\.exe)?\s|ncat|socat|powercat)'

function Get-Severity([string]$text) {
    if ($text -match $badCmdRegex) { return 'RED' }
    if ($text -match $badPathRegex) { return 'RED' }
    return 'YELLOW'
}

# ---------------------------------------------------------------------------
Write-Section '1. Scheduled tasks (non-Microsoft)'
# ---------------------------------------------------------------------------
if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $n = 0
    foreach ($t in $tasks) {
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        $isMsPath = $t.TaskPath -like '\Microsoft\*'
        $isMsAuthor = $t.Author -match 'Microsoft|^\$\(@%SystemRoot%'
        # Microsoft-path tasks are only interesting if their action looks bad (attackers hide there too).
        if ($isMsPath -and $isMsAuthor -and $actions -notmatch $badCmdRegex -and $actions -notmatch $badPathRegex) { continue }
        $n++
        $lvl = Get-Severity $actions
        if ($isMsPath -and -not $isMsAuthor) { $lvl = 'RED' }   # non-MS task hiding under \Microsoft\
        Write-Finding -Level $lvl -Category 'SchedTask' -Message ("{0}{1}  [{2}] author={3}" -f $t.TaskPath, $t.TaskName, $t.State, $t.Author) -Detail $actions
    }
    if ($n -eq 0) { Write-Finding -Level GREEN -Category 'SchedTask' -Message 'No non-Microsoft scheduled tasks found.' }
} else {
    Write-Finding -Level INFO -Category 'SchedTask' -Message 'Get-ScheduledTask unavailable; run: schtasks /query /fo LIST /v'
}

# ---------------------------------------------------------------------------
Write-Section '2. Services with unusual binary paths'
# ---------------------------------------------------------------------------
$n = 0
foreach ($s in (Get-WmiObject Win32_Service)) {
    $p = [string]$s.PathName
    if (-not $p) { continue }
    $normal = $p -match '(?i)^"?[A-Z]:\\Windows\\' -or $p -match '(?i)^"?[A-Z]:\\Program Files( \(x86\))?\\'
    # Unquoted path with a space before .exe = "unquoted service path" privesc.
    $unquoted = ($p -notmatch '^"') -and ($p -match '^[^"]*\s[^"]*\.exe')
    if ($normal -and -not $unquoted -and $p -notmatch $badCmdRegex -and $p -notmatch '(?i)(cmd(\.exe)?\s+/c|powershell)') { continue }
    $n++
    $lvl = if ($p -match '(?i)(cmd(\.exe)?\s+/c|powershell)' -or $p -match $badPathRegex -or $p -match $badCmdRegex) { 'RED' } else { 'YELLOW' }
    $why = if ($unquoted -and $normal) { 'unquoted path with spaces' } else { 'binary outside Windows/Program Files' }
    Write-Finding -Level $lvl -Category 'Service' -Message ("{0} ({1}) start={2} state={3} - {4}" -f $s.Name, $s.DisplayName, $s.StartMode, $s.State, $why) -Detail $p
}
if ($n -eq 0) { Write-Finding -Level GREEN -Category 'Service' -Message 'All service binaries live in standard locations.' }

# ---------------------------------------------------------------------------
Write-Section '3. Run / RunOnce keys'
# ---------------------------------------------------------------------------
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
# HKEY_USERS contains every user hive currently loaded (logged-on users +
# service accounts). HKCU is just "the current user's" entry in there.
# "Registry::" lets us read it without mapping a PSDrive.
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$|^S-1-5-(18|19|20)$' } | ForEach-Object {
    $runKeys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
    $runKeys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
$n = 0
foreach ($k in $runKeys) {
    $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }   # PSPath, PSParentPath... are PowerShell metadata
        $n++
        Write-Finding -Level (Get-Severity ([string]$p.Value)) -Category 'RunKey' -Message ("{0} -> {1}" -f ($k -replace '^(HKLM:|Registry::HKEY_USERS)\\', ''), $p.Name) -Detail ([string]$p.Value)
    }
}
if ($n -eq 0) { Write-Finding -Level GREEN -Category 'RunKey' -Message 'Run/RunOnce keys are empty.' }

# ---------------------------------------------------------------------------
Write-Section '4. Startup folders'
# ---------------------------------------------------------------------------
$startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
$startup += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
$n = 0
foreach ($dir in $startup) {
    Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
        $n++
        Write-Finding -Level YELLOW -Category 'Startup' -Message $_.FullName -Detail ("modified {0}" -f $_.LastWriteTime)
    }
}
if ($n -eq 0) { Write-Finding -Level GREEN -Category 'Startup' -Message 'Startup folders are empty.' }

# ---------------------------------------------------------------------------
Write-Section '5. WMI event subscriptions'
# ---------------------------------------------------------------------------
# Fileless persistence: a filter (trigger) + consumer (action) + binding.
# A clean box usually has only "SCM Event Log Consumer"/BVTFilter or nothing.
$wmiFound = $false
foreach ($cls in @('__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding')) {
    foreach ($o in (Get-WmiObject -Namespace root\subscription -Class $cls -ErrorAction SilentlyContinue)) {
        if ($o.Name -in @('SCM Event Log Filter', 'SCM Event Log Consumer', 'BVTFilter')) { continue }
        if ($cls -eq '__FilterToConsumerBinding' -and $o.Filter -match 'SCM Event Log Filter|BVTFilter') { continue }
        $wmiFound = $true
        $detail = switch ($cls) {
            '__EventFilter'             { $o.Query }
            'CommandLineEventConsumer'  { $o.CommandLineTemplate }
            'ActiveScriptEventConsumer' { "$($o.ScriptingEngine): $($o.ScriptText)".Substring(0, [Math]::Min(200, "$($o.ScriptingEngine): $($o.ScriptText)".Length)) }
            default                     { "$($o.Filter) -> $($o.Consumer)" }
        }
        $lvl = if ($cls -match 'Consumer|Binding') { 'RED' } else { 'YELLOW' }
        Write-Finding -Level $lvl -Category 'WMI' -Message ("{0}: {1}" -f $cls, $(if ($o.Name) { $o.Name } else { '(binding)' })) -Detail $detail
    }
}
if (-not $wmiFound) { Write-Finding -Level GREEN -Category 'WMI' -Message 'No non-default WMI subscriptions.' }

# ---------------------------------------------------------------------------
Write-Section '6. Winlogon Userinit / Shell'
# ---------------------------------------------------------------------------
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl) {
    # Expected: Userinit = C:\Windows\system32\userinit.exe,   Shell = explorer.exe
    if ($wl.Userinit -match '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') {
        Write-Finding -Level GREEN -Category 'Winlogon' -Message "Userinit = $($wl.Userinit)"
    } else { Write-Finding -Level RED -Category 'Winlogon' -Message "Userinit modified: $($wl.Userinit)" }
    if ($wl.Shell -match '(?i)^explorer\.exe$') {
        Write-Finding -Level GREEN -Category 'Winlogon' -Message "Shell = $($wl.Shell)"
    } else { Write-Finding -Level RED -Category 'Winlogon' -Message "Shell modified: $($wl.Shell)" }
}

# ---------------------------------------------------------------------------
Write-Section '7. Image File Execution Options debuggers / accessibility hijacks'
# ---------------------------------------------------------------------------
# Setting HKLM\...\IFEO\sethc.exe\Debugger = cmd.exe means pressing Shift 5x
# on the RDP login screen gives a SYSTEM shell with no password.
$accessibility = @('sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe')
$n = 0
foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            $n++
            $lvl = if ($accessibility -contains $_.PSChildName.ToLower()) { 'RED' } else { 'YELLOW' }
            Write-Finding -Level $lvl -Category 'IFEO' -Message ("{0} Debugger = {1}" -f $_.PSChildName, $dbg) -Detail 'Remove with: harden\Harden-Baseline.ps1 -Only RemoveIfeoDebuggers'
        }
    }
}
if ($n -eq 0) { Write-Finding -Level GREEN -Category 'IFEO' -Message 'No IFEO debuggers set.' }
# Also catch the "copy cmd.exe over sethc.exe" variant by comparing version info.
foreach ($exe in $accessibility) {
    $f = Join-Path $env:windir "System32\$exe"
    if (-not (Test-Path $f)) { continue }
    $orig = (Get-Item $f).VersionInfo.OriginalFilename
    if ($orig -and $orig -notmatch [regex]::Escape(($exe -replace '\.exe$', ''))) {
        Write-Finding -Level RED -Category 'IFEO' -Message "$f has OriginalFilename '$orig' - binary was REPLACED" -Detail 'Restore with: sfc /scanfile=<path>'
    }
}

# ---------------------------------------------------------------------------
Write-Section '8. AppInit_DLLs'
# ---------------------------------------------------------------------------
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
    $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($v -and $v.AppInit_DLLs) {
        $lvl = if ($v.LoadAppInit_DLLs -eq 1) { 'RED' } else { 'YELLOW' }
        Write-Finding -Level $lvl -Category 'AppInit' -Message ("AppInit_DLLs = {0} (LoadAppInit_DLLs={1})" -f $v.AppInit_DLLs, $v.LoadAppInit_DLLs) -Detail $k
    } elseif ($v) { Write-Finding -Level GREEN -Category 'AppInit' -Message "AppInit_DLLs empty ($($k -replace '^HKLM:\\SOFTWARE\\', ''))" }
}

# ---------------------------------------------------------------------------
Write-Section '9. OpenSSH keys and config'
# ---------------------------------------------------------------------------
$sshFiles = @("$env:ProgramData\ssh\administrators_authorized_keys")
$sshFiles += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' }
$anyKeys = $false
foreach ($f in $sshFiles) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    $keys = @(Get-Content -LiteralPath $f -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
    if ($keys.Count -eq 0) { continue }
    $anyKeys = $true
    foreach ($k in $keys) {
        $parts = $k -split '\s+'
        $comment = if ($parts.Count -ge 3) { $parts[2..($parts.Count - 1)] -join ' ' } else { '(no comment)' }
        Write-Finding -Level RED -Category 'SSHKey' -Message ("{0}: {1} key '{2}'" -f $f, $parts[0], $comment) -Detail 'Every key here can log in without a password. Remove any you did not add.'
    }
}
if (-not $anyKeys) { Write-Finding -Level GREEN -Category 'SSHKey' -Message 'No authorized_keys entries found.' }
$sshd = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $sshd) {
    $cfg = Get-Content $sshd | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
    foreach ($line in $cfg) {
        if ($line -match '(?i)^\s*(PasswordAuthentication|PermitEmptyPasswords|AuthorizedKeysFile|PubkeyAuthentication|PermitRootLogin|Match|ForceCommand|AllowUsers|AllowGroups)') {
            $lvl = if ($line -match '(?i)PermitEmptyPasswords\s+yes') { 'RED' } else { 'INFO' }
            Write-Finding -Level $lvl -Category 'sshd_config' -Message $line.Trim()
        }
    }
    $sshdMod = (Get-Item $sshd).LastWriteTime
    if ($sshdMod -gt $cutoff) { Write-Finding -Level YELLOW -Category 'sshd_config' -Message "sshd_config modified recently: $sshdMod" }
} else { Write-Finding -Level INFO -Category 'sshd_config' -Message 'OpenSSH server not installed.' }

# ---------------------------------------------------------------------------
Write-Section '10. Defender exclusions'
# ---------------------------------------------------------------------------
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    $ex = @()
    foreach ($kind in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')) {
        foreach ($v in @($mp.$kind)) { if ($v) { $ex += "$kind = $v" } }
    }
    if ($ex) { foreach ($e in $ex) { Write-Finding -Level RED -Category 'Defender' -Message "Exclusion: $e" -Detail 'Red Team adds exclusions so their tools are not scanned.' } }
    else { Write-Finding -Level GREEN -Category 'Defender' -Message 'No Defender exclusions.' }
} else {
    Write-Finding -Level INFO -Category 'Defender' -Message 'Defender cmdlets not present (Server 2012 R2 / 3rd-party AV).'
}

# ---------------------------------------------------------------------------
Write-Section "11. System32 binaries modified in the last $RecentDays days"
# ---------------------------------------------------------------------------
# Windows Update also touches these, so treat as YELLOW unless unsigned.
$recent = Get-ChildItem "$env:windir\System32" -File -Include *.exe, *.dll, *.sys -Recurse -Depth 1 -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $cutoff -or $_.CreationTime -gt $cutoff } | Select-Object -First 50
if ($recent) {
    foreach ($f in $recent) {
        $sig = (Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue).Status
        $lvl = if ($sig -ne 'Valid') { 'RED' } else { 'YELLOW' }
        Write-Finding -Level $lvl -Category 'System32' -Message ("{0}  ({1}, signature: {2})" -f $f.FullName, $f.LastWriteTime, $sig)
    }
} else { Write-Finding -Level GREEN -Category 'System32' -Message 'No recently modified binaries in System32.' }

# ---------------------------------------------------------------------------
Write-Section '12. Web shells in IIS web roots'
# ---------------------------------------------------------------------------
# Discover site folders from IIS config without needing the WebAdministration module.
$roots = @($WebRoots)
$appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
if (Test-Path $appHost) {
    $xml = [xml](Get-Content $appHost -Raw)
    $roots += $xml.configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }
}
if (Test-Path 'C:\inetpub\wwwroot') { $roots += 'C:\inetpub\wwwroot' }
$roots = $roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$shellExt = @('*.php', '*.php3', '*.php5', '*.phtml', '*.asp', '*.aspx', '*.ashx', '*.asmx', '*.jsp', '*.cfm', '*.config')
# Content patterns that show up in nearly every web shell. WordPress core uses
# some of these legitimately, so a hit in a RECENT file is what matters most.
$shellPatterns = '(?i)(eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|base64_decode\s*\(\s*\$_|assert\s*\(\s*\$_|system\s*\(\s*\$_|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|preg_replace\s*\(.*/e[''"]|ProcessStartInfo|cmd\.exe\s*/c|WScript\.Shell|Request\.Form\(.{0,40}\)\s*\)\s*;?\s*Execute|eval\(Request)'
if (-not $roots) { Write-Finding -Level INFO -Category 'WebShell' -Message 'No web roots found.' }
foreach ($r in $roots) {
    Write-Finding -Level INFO -Category 'WebShell' -Message "Scanning $r"
    $files = Get-ChildItem -Path $r -Recurse -File -Include $shellExt -Force -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $isRecent = $f.LastWriteTime -gt $cutoff -or $f.CreationTime -gt $cutoff
        $hit = $null
        if ($f.Length -lt 2MB) { $hit = Select-String -LiteralPath $f.FullName -Pattern $shellPatterns -List -ErrorAction SilentlyContinue }
        if ($hit -and $isRecent) {
            Write-Finding -Level RED -Category 'WebShell' -Message ("RECENT + suspicious code: {0}" -f $f.FullName) -Detail ("line {0}: {1}" -f $hit.LineNumber, $hit.Line.Trim().Substring(0, [Math]::Min(120, $hit.Line.Trim().Length)))
        } elseif ($hit) {
            Write-Finding -Level YELLOW -Category 'WebShell' -Message ("suspicious code: {0}" -f $f.FullName) -Detail ("line {0}" -f $hit.LineNumber)
        } elseif ($isRecent -and $f.Extension -ne '.config') {
            Write-Finding -Level YELLOW -Category 'WebShell' -Message ("recently modified script: {0} ({1})" -f $f.FullName, $f.LastWriteTime)
        }
    }
    # PHP in an uploads folder is never legitimate in WordPress.
    Get-ChildItem -Path $r -Recurse -File -Filter *.php -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\uploads\\' } | ForEach-Object {
        Write-Finding -Level RED -Category 'WebShell' -Message "PHP file inside an uploads folder: $($_.FullName)"
    }
}

Complete-Ccdc
