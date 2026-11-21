<#
.SYNOPSIS
    Audit-Persistence - hunt the places Red Team hides to survive reboots. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Walks the common Windows persistence locations and flags anything that
      looks non-default. It does NOT remove anything - removal is a
      deliberate, logged step (hunt\Remove-Persistence.ps1, or by
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
     13. LSA packages          unknown SSP / password-filter DLLs loaded into LSASS (memssp, mimilib)
     14. Netsh helper DLLs     non-Microsoft DLLs loaded by every netsh.exe run
     15. Hidden tasks          tasks whose registry SD was deleted so schtasks cannot see them
     16. svchost ServiceDll    service DLL swapped to a file outside System32
     17. PS profiles/BootExec  profile.ps1 scripts that run on every PowerShell start; BootExecute

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

# Shared rules (lib\CCDC-Common.ps1), the same ones panel R uses to remove things.
$badPathRegex = $script:CcdcBadPathRegex
$badCmdRegex  = $script:CcdcBadCmdRegex
function Get-Severity([string]$text) { return (Get-CcdcPersistSeverity $text) }

# ---------------------------------------------------------------------------
Write-Section '1. Scheduled tasks (Windows'' own and Microsoft-signed hidden)'
# ---------------------------------------------------------------------------
if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $n = 0
    foreach ($t in $tasks) {
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        if (Test-CcdcTaskIsNoise $t $actions) { continue }   # Windows' own, Microsoft-signed, or the toolkit's
        $n++
        Write-Finding -Level (Get-Severity $actions) -Category 'SchedTask' -Message ("{0}{1}  [{2}]" -f $t.TaskPath, $t.TaskName, $t.State) -Detail $actions
    }
    if ($n -eq 0) { Write-Finding -Level GREEN -Category 'SchedTask' -Message 'No suspicious scheduled tasks.' }
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
        $rv = [string]$p.Value; $rl = Get-Severity $rv
        $exe = if ($rv -match '^\s*"([^"]+)"') { $Matches[1] } else { ($rv -split '\s+')[0] }
        if ($rl -ne 'RED' -and (Test-CcdcMsSigned $exe)) { continue }   # Microsoft-signed autostart (e.g. SecurityHealthSystray)
        $n++
        Write-Finding -Level $rl -Category 'RunKey' -Message ("{0} -> {1}" -f ($k -replace '^(HKLM:|Registry::HKEY_USERS)\\', ''), $p.Name) -Detail ([string]$p.Value)
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
            Write-Finding -Level $lvl -Category 'IFEO' -Message ("{0} Debugger = {1}" -f $_.PSChildName, $dbg) -Detail 'Remove with: panel R (hunt\Remove-Persistence.ps1)'
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

# ---------------------------------------------------------------------------
Write-Section '13. LSA packages (password filters / SSPs loaded into LSASS)'
# ---------------------------------------------------------------------------
# A DLL listed here is loaded into LSASS at boot and sees every password in
# clear text (mimikatz "misc::memssp" / mimilib, custom password filters).
$lsaKnown = @{
    'Authentication Packages' = @('msv1_0')
    'Notification Packages'   = @('scecli', 'rassfm')          # rassfm = RRAS servers
    'Security Packages'       = @('', '""', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp')
}
$lsaFound = 0
foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig')) {
    $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if (-not $v) { continue }
    foreach ($name in $lsaKnown.Keys) {
        foreach ($pkg in @($v.$name)) {
            if ($null -eq $pkg) { continue }
            $p = ([string]$pkg).Trim()
            if ($lsaKnown[$name] -contains $p.ToLower()) { continue }
            $lsaFound++
            Write-Finding -Level RED -Category 'LSA' -Message ("{0} contains '{1}' ({2})" -f $name, $p, ($k -replace '^HKLM:\\SYSTEM\\CurrentControlSet\\Control\\', '')) -Detail 'Unknown DLL loaded into LSASS - can capture every password. Check %windir%\System32\<name>.dll signature.'
        }
    }
}
if ($lsaFound -eq 0) { Write-Finding -Level GREEN -Category 'LSA' -Message 'LSA authentication/notification/security packages are all defaults.' }

# ---------------------------------------------------------------------------
Write-Section '14. Netsh helper DLLs'
# ---------------------------------------------------------------------------
# Every netsh.exe run loads these DLLs. Default helpers are bare file names in System32.
$nsFound = 0
$ns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
if ($ns) {
    foreach ($p in $ns.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $dll = [string]$p.Value
        $full = if ($dll -match '\\') { [Environment]::ExpandEnvironmentVariables($dll) } else { Join-Path "$env:windir\System32" $dll }
        $sig = if (Test-Path -LiteralPath $full) { (Get-AuthenticodeSignature -FilePath $full -ErrorAction SilentlyContinue) } else { $null }
        $msSigned = $sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft'
        if ($dll -match '\\' -or -not $msSigned) {
            $nsFound++
            $lvl = if (-not $msSigned) { 'RED' } else { 'YELLOW' }
            Write-Finding -Level $lvl -Category 'NetshHelper' -Message ("{0} = {1}" -f $p.Name, $dll) -Detail ("signature: {0}" -f $(if ($sig) { $sig.Status } else { 'file not found' }))
        }
    }
}
if ($nsFound -eq 0) { Write-Finding -Level GREEN -Category 'NetshHelper' -Message 'Netsh helpers are Microsoft-signed System32 DLLs.' }

# ---------------------------------------------------------------------------
Write-Section '15. Hidden scheduled tasks (registry vs Task Scheduler)'
# ---------------------------------------------------------------------------
# Red Team trick ("Tarrask"): delete a task's SD value in the registry and it
# disappears from schtasks / Get-ScheduledTask / Task Scheduler, but still runs.
$treeRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
$hidden = 0
if (Test-Path $treeRoot) {
    $visible = @{}
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) { $visible[("$($t.TaskPath)$($t.TaskName)").ToLower()] = $true }
    foreach ($key in (Get-ChildItem $treeRoot -Recurse -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props -or -not ($props.PSObject.Properties.Name -contains 'Id')) { continue }   # folders have no Id
        $taskPath = '\' + ($key.Name -replace '^.*\\TaskCache\\Tree\\', '')
        $noSd = -not ($props.PSObject.Properties.Name -contains 'SD')
        $notListed = $visible.Count -gt 0 -and -not $visible.ContainsKey($taskPath.ToLower())
        if ($noSd -or $notListed) {
            $hidden++
            $why = @(); if ($noSd) { $why += 'no SD value (hidden on purpose)' }; if ($notListed) { $why += 'not returned by Get-ScheduledTask' }
            # No SD = deliberately hidden (RED). Merely "not listed" can be an ACL quirk (YELLOW).
            Write-Finding -Level $(if ($noSd) { 'RED' } else { 'YELLOW' }) -Category 'HiddenTask' -Message ("{0}  - {1}" -f $taskPath, ($why -join ', ')) -Detail ("Inspect: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0}  and  %windir%\System32\Tasks{1}" -f $props.Id, $taskPath)
        }
    }
}
if ($hidden -eq 0) { Write-Finding -Level GREEN -Category 'HiddenTask' -Message 'No hidden scheduled tasks (registry matches Task Scheduler).' }

# ---------------------------------------------------------------------------
Write-Section '16. svchost ServiceDll hijacks'
# ---------------------------------------------------------------------------
# svchost services run whatever DLL Parameters\ServiceDll points to. Swapping
# that one value keeps the familiar service name while running Red Team code.
$sdFound = 0
foreach ($svcKey in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue)) {
    $dll = (Get-ItemProperty (Join-Path $svcKey.PSPath 'Parameters') -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
    if (-not $dll) { continue }
    $full = [Environment]::ExpandEnvironmentVariables([string]$dll)
    if ($full -match '(?i)^[A-Z]:\\Windows\\(System32|SysWOW64)\\') { continue }
    $sdFound++
    $lvl = if ($full -match $badPathRegex -or $full -notmatch '(?i)^[A-Z]:\\(Windows|Program Files)') { 'RED' } else { 'YELLOW' }
    Write-Finding -Level $lvl -Category 'ServiceDll' -Message ("{0} ServiceDll = {1}" -f $svcKey.PSChildName, $dll) -Detail 'Expected under %windir%\System32. Check signature: Get-AuthenticodeSignature <path>'
}
if ($sdFound -eq 0) { Write-Finding -Level GREEN -Category 'ServiceDll' -Message 'All svchost ServiceDll values point into System32.' }

# ---------------------------------------------------------------------------
Write-Section '17. PowerShell profiles and BootExecute'
# ---------------------------------------------------------------------------
# A profile runs every time PowerShell starts - including when YOU start it as admin.
$profiles = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1",
              "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")
$profiles += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Join-Path $_.FullName 'Documents\WindowsPowerShell\profile.ps1'
    Join-Path $_.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
    Join-Path $_.FullName 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
}
$pf = 0
foreach ($p in ($profiles | Sort-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $pf++
    $body = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
    $lvl = if ($body -match $badCmdRegex) { 'RED' } else { 'YELLOW' }
    Write-Finding -Level $lvl -Category 'PSProfile' -Message "PowerShell profile exists: $p" -Detail ("modified {0}. Read it before trusting any PowerShell window on this box." -f (Get-Item -LiteralPath $p).LastWriteTime)
}
if ($pf -eq 0) { Write-Finding -Level GREEN -Category 'PSProfile' -Message 'No PowerShell profile scripts.' }
$be = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
$beOdd = @($be | Where-Object { $_ -and $_ -notmatch '(?i)^autocheck autochk( /q /v)? \*$' })
if ($beOdd) { foreach ($b in $beOdd) { Write-Finding -Level RED -Category 'BootExecute' -Message "BootExecute entry: $b" -Detail 'Default is only: autocheck autochk *' } }
else { Write-Finding -Level GREEN -Category 'BootExecute' -Message 'BootExecute is default.' }

Complete-Ccdc
