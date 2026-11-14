<#
.SYNOPSIS
    Shared helper library for every script in the Services\ folder.
.DESCRIPTION
    Dot-sourced by each per-service script. Do not run directly.

    Provides:
      - Console helpers (banner / OK / WARN / CRIT / INFO / STEP)
      - Service inspection (state, start mode, binary path, signature, run-as
        account, service DACL, svchost sharing)
      - Port inspection (expected ports vs. what is actually listening)
      - Connection inspection (established sessions, grouped by remote IP)
      - Firewall inspection (inbound rules that cover the service's ports)
      - Backup plumbing (locked-down backup folders, robocopy + ACL save,
        registry export, service-definition export, SHA256 manifest)
      - Restore plumbing (find latest backup, confirmation prompts)
      - A main dispatcher: Invoke-ServiceMain

    Every per-service script supports:
        -Action Info     what the service is, ports, connections, firewall, risks
        -Action Backup   back the service up to C:\ccdc\backups\services\<Svc>\<stamp>
        -Action Restore  restore from the latest backup (or -RestoreFrom <dir>)
        -Action Verify   re-hash the latest backup and compare to its manifest
        -Action Detect   one line: is this service on this box?
        -Action All      Info + Backup   (default)

    ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less files as
    ANSI, so fancy characters break.
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------
#  Console helpers
# ---------------------------------------------------------------------------
function Write-Banner { param([string]$T, [string]$C = "Cyan") $l = "=" * 74; Write-Host "`n$l`n  $T`n$l" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta }
function Write-Plain  { param([string]$m) Write-Host "         $m" -ForegroundColor Gray }

$script:CCDCStamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $script:CCDCBackupRoot) { $script:CCDCBackupRoot = "C:\ccdc\backups\services" }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Test-IsDomainController {
    try { (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4 } catch { $false }
}

function Test-ServiceInstalled {
    param([string[]]$Names)
    foreach ($n in $Names) { if (Get-Service -Name $n -ErrorAction SilentlyContinue) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
#  Service inspection
# ---------------------------------------------------------------------------
function Get-ExePathFromCommandLine {
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $cl = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($cl.StartsWith('"')) { return $cl.Substring(1, $cl.IndexOf('"', 1) - 1) }
    # Unquoted: grow token by token until a file exists (handles spaces in path)
    $parts = $cl -split ' '
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $candidate = ($parts[0..$i] -join ' ')
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        if (Test-Path -LiteralPath "$candidate.exe" -PathType Leaf) { return "$candidate.exe" }
    }
    return $parts[0]
}

function Get-CCDCServiceObjects {
    param([string[]]$Names)
    $all = @()
    foreach ($n in $Names) {
        $all += Get-CimInstance Win32_Service -Filter "Name LIKE '$($n.Replace('*','%'))'" -ErrorAction SilentlyContinue
    }
    $all | Sort-Object Name -Unique
}

function Get-ServicePids {
    param([string[]]$Names)
    @(Get-CCDCServiceObjects $Names | Where-Object { $_.ProcessId -gt 0 } | Select-Object -ExpandProperty ProcessId -Unique)
}

function Show-ServiceDetails {
    param([string[]]$Names)
    Write-STEP "Windows service(s)"
    $svcs = Get-CCDCServiceObjects $Names
    if (-not $svcs) { Write-WARN "None of these services exist on this box: $($Names -join ', ')"; return }

    foreach ($s in $svcs) {
        $color = if ($s.State -eq 'Running') { 'Green' } else { 'Yellow' }
        Write-Host ("  {0,-22} {1}" -f $s.Name, $s.DisplayName) -ForegroundColor $color
        Write-Plain ("State: {0}   StartMode: {1}   PID: {2}   RunAs: {3}" -f $s.State, $s.StartMode, $s.ProcessId, $s.StartName)
        Write-Plain ("Binary: {0}" -f $s.PathName)

        # svchost sharing + ServiceDll
        $exe = Get-ExePathFromCommandLine $s.PathName
        $sigTarget = $exe
        if ($exe -match 'svchost\.exe$') {
            $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
            if ($dll) { $dll = [Environment]::ExpandEnvironmentVariables($dll); $sigTarget = $dll; Write-Plain "ServiceDll: $dll" }
            if ($s.ProcessId -gt 0) {
                $shared = @(Get-CimInstance Win32_Service -Filter "ProcessId=$($s.ProcessId)" -ErrorAction SilentlyContinue)
                if ($shared.Count -gt 1) { Write-Plain "Shared svchost PID hosts $($shared.Count) services: $(($shared.Name | Select-Object -First 8) -join ', ')" }
            }
        }

        # Signature check on the actual code that runs
        if ($sigTarget -and (Test-Path -LiteralPath $sigTarget)) {
            $sig = Get-AuthenticodeSignature -LiteralPath $sigTarget -ErrorAction SilentlyContinue
            if ($sig.Status -eq 'Valid') { Write-OK "Signed: $($sig.SignerCertificate.Subject -replace ',.*$','')" }
            else { Write-WARN "Signature status '$($sig.Status)' on $sigTarget  <- verify this binary" }
        } elseif ($sigTarget) {
            Write-WARN "Binary path not found on disk: $sigTarget"
        }

        # Unquoted path with spaces (classic privesc)
        if ($s.PathName -and $s.PathName -notmatch '^\s*"' -and ($exe -match ' ')) {
            Write-CRIT "Unquoted service path with spaces (privesc): $($s.PathName)"
        }

        # Service DACL - flag non-admin write rights
        $sddl = (& sc.exe sdshow $s.Name 2>$null | Where-Object { $_ -match 'D:' }) -join ''
        foreach ($ace in [regex]::Matches($sddl, '\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^)]+)\)')) {
            $rights = $ace.Groups[1].Value; $sid = $ace.Groups[2].Value
            if ($rights -match '^0x' -or $sid -notin 'WD', 'AU', 'BU', 'IU', 'S-1-1-0') { continue }
            $tokens = for ($i = 0; $i -lt $rights.Length; $i += 2) { $rights.Substring($i, [Math]::Min(2, $rights.Length - $i)) }
            $bad = $tokens | Where-Object { $_ -in 'WP', 'DC', 'WD', 'WO', 'GA', 'GW' }
            if ($bad) { Write-CRIT "Service DACL gives '$sid' rights $($bad -join ',') (modify/reconfigure) -> $($ace.Value)" }
        }

        # Failure actions (red team sometimes sets 'run program' on failure)
        $fail = (& sc.exe qfailure $s.Name 2>$null) -join ' '
        if ($fail -match 'COMMAND_LINE\s*:\s*\S+') { Write-WARN "Failure action runs a command: $($Matches[0])" }
    }
}

# ---------------------------------------------------------------------------
#  Ports / connections / firewall
# ---------------------------------------------------------------------------
function Get-ProcName { param([int]$ProcId) try { (Get-Process -Id $ProcId -ErrorAction Stop).ProcessName } catch { "pid$ProcId" } }

function Show-ExpectedPorts {
    param([object[]]$Ports)
    if (-not $Ports) { return }
    Write-STEP "Expected ports (documentation) vs. what is listening now"
    $tcpL = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    $udpL = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)
    foreach ($p in $Ports) {
        $hits = @()
        if ($p.Proto -match 'TCP') { $hits += $tcpL | Where-Object LocalPort -eq $p.Port }
        if ($p.Proto -match 'UDP') { $hits += $udpL | Where-Object LocalPort -eq $p.Port }
        $who = ($hits | ForEach-Object { "$(Get-ProcName $_.OwningProcess)($($_.OwningProcess))@$($_.LocalAddress)" } | Select-Object -Unique) -join ', '
        $line = "{0,-8} {1,-8} {2,-40}" -f $p.Port, $p.Proto, $p.Use
        if ($hits) { Write-Host "  [LISTEN] $line -> $who" -ForegroundColor Green }
        else       { Write-Host "  [ -- ]   $line" -ForegroundColor DarkGray }
    }
}

function Show-ServiceListeners {
    param([string[]]$Names)
    Write-STEP "Ports actually opened by the service process(es)"
    $pids = Get-ServicePids $Names
    if (-not $pids) { Write-INFO "Service not running - no listeners."; return }
    $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess }
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess }
    foreach ($t in $tcp | Sort-Object LocalPort -Unique) { Write-Plain ("TCP {0,-6} on {1,-16} {2}({3})" -f $t.LocalPort, $t.LocalAddress, (Get-ProcName $t.OwningProcess), $t.OwningProcess) }
    foreach ($u in $udp | Sort-Object LocalPort -Unique) { Write-Plain ("UDP {0,-6} on {1,-16} {2}({3})" -f $u.LocalPort, $u.LocalAddress, (Get-ProcName $u.OwningProcess), $u.OwningProcess) }
    if (-not $tcp -and -not $udp) { Write-INFO "Process has no listening sockets (or shares svchost - see expected ports above)." }
}

function Show-ServiceConnections {
    param([string[]]$Names, [object[]]$Ports)
    Write-STEP "Live connections (ESTABLISHED) to/from this service"
    $pids = Get-ServicePids $Names
    $portNums = @($Ports | Where-Object { $_.Proto -match 'TCP' } | ForEach-Object { [int]$_.Port })
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        ($pids -contains $_.OwningProcess) -or ($portNums -contains $_.LocalPort)
    }
    if (-not $conns) { Write-INFO "No established connections right now."; return }
    $conns | Group-Object RemoteAddress | Sort-Object Count -Descending | ForEach-Object {
        $lp = ($_.Group.LocalPort | Sort-Object -Unique) -join ','
        $rp = ($_.Group.RemotePort | Sort-Object -Unique | Select-Object -First 5) -join ','
        $proc = ($_.Group | ForEach-Object { Get-ProcName $_.OwningProcess } | Sort-Object -Unique) -join ','
        Write-Plain ("{0,-40} x{1,-4} localPort:{2,-12} remotePort:{3,-20} {4}" -f $_.Name, $_.Count, $lp, $rp, $proc)
    }
    # Outbound from the service process to non-private space is a red flag for most services
    $pub = $conns | Where-Object { ($pids -contains $_.OwningProcess) -and ($_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fe80|0\.0\.0\.0)') }
    foreach ($c in $pub) { Write-WARN "Connection to public address $($c.RemoteAddress):$($c.RemotePort) (local $($c.LocalPort)) - confirm it is the scoring engine / expected" }
}

function Test-PortInSpec {
    param([string[]]$Spec, [int]$Port)
    foreach ($s in $Spec) {
        if ($s -eq 'Any') { return $true }
        if ($s -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true } }
        elseif ($s -match '^\d+$' -and [int]$s -eq $Port) { return $true }
    }
    return $false
}

$script:FwCache = $null
function Get-FwInboundRules {
    if ($script:FwCache) { return $script:FwCache }
    $rules = @{}
    Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | ForEach-Object { $rules[$_.InstanceID] = $_ }
    $out = foreach ($pf in (Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) {
        if ($rules.ContainsKey($pf.InstanceID)) {
            [pscustomobject]@{ Rule = $rules[$pf.InstanceID]; Protocol = $pf.Protocol; LocalPort = @($pf.LocalPort) }
        }
    }
    $script:FwCache = @($out)
    $script:FwCache
}

function Show-FirewallForPorts {
    param([object[]]$Ports)
    if (-not $Ports) { return }
    Write-STEP "Inbound firewall rules covering these ports (enabled only)"
    $prof = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($pr in $prof) {
        if (-not $pr.Enabled) { Write-CRIT "Firewall profile '$($pr.Name)' is DISABLED" }
    }
    $fw = Get-FwInboundRules
    foreach ($p in $Ports) {
        if ($p.Port -isnot [int]) { continue }
        $matching = $fw | Where-Object {
            ($_.Protocol -eq 'Any' -or $p.Proto -match $_.Protocol) -and (Test-PortInSpec $_.LocalPort $p.Port)
        }
        if (-not $matching) { Write-Plain ("{0,-6}/{1,-7} no explicit inbound rule" -f $p.Port, $p.Proto); continue }
        foreach ($m in $matching | Select-Object -First 6) {
            $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $m.Rule -ErrorAction SilentlyContinue
            $color = if ($m.Rule.Action -eq 'Allow') { 'Gray' } else { 'Yellow' }
            Write-Host ("         {0,-6}/{1,-7} {2,-5} remote:{3,-22} '{4}'" -f $p.Port, $m.Protocol, $m.Rule.Action, (($af.RemoteAddress) -join ','), $m.Rule.DisplayName) -ForegroundColor $color
        }
    }
}

function Show-RecentEvents {
    param([string]$LogName, [int[]]$Ids, [int]$Max = 10, [int]$Hours = 24)
    $f = @{ LogName = $LogName; StartTime = (Get-Date).AddHours(-$Hours) }
    if ($Ids) { $f.Id = $Ids }
    $ev = Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction SilentlyContinue
    if (-not $ev) { return }
    Write-STEP "Recent events: $LogName (last ${Hours}h, max $Max)"
    foreach ($e in $ev) {
        $msg = ($e.Message -split "`n")[0]
        if ($msg.Length -gt 110) { $msg = $msg.Substring(0, 110) + '...' }
        Write-Plain ("{0:MM-dd HH:mm:ss} id={1,-5} {2,-12} {3}" -f $e.TimeCreated, $e.Id, $e.LevelDisplayName, $msg)
    }
}

function Show-ServiceOverview {
    param([hashtable]$Def)
    Write-Banner "$($Def.Title)   [$env:COMPUTERNAME]" "Cyan"
    Write-STEP "What it is"
    foreach ($l in ($Def.Description -split "`n")) { Write-Plain $l.TrimEnd() }

    if ($Def.KeyPaths) {
        Write-STEP "Important files / registry locations"
        foreach ($k in $Def.KeyPaths) {
            $exists = if ($k -match '^HK') { Test-Path ("Registry::" + $k) } else { Test-Path ([Environment]::ExpandEnvironmentVariables($k)) }
            if ($exists) { Write-OK $k } else { Write-Host "  [ -- ] $k" -ForegroundColor DarkGray }
        }
    }

    if ($Def.ServiceNames) { Show-ServiceDetails $Def.ServiceNames }
    Show-ExpectedPorts $Def.Ports
    if ($Def.ServiceNames) {
        Show-ServiceListeners $Def.ServiceNames
        Show-ServiceConnections $Def.ServiceNames $Def.Ports
    }
    Show-FirewallForPorts $Def.Ports

    if ($Def.RedTeam) {
        Write-STEP "How red team abuses it / what to look for"
        foreach ($r in $Def.RedTeam) { Write-Host "  [!] $r" -ForegroundColor Yellow }
    }
    if ($Def.Hardening) {
        Write-STEP "Hardening quick wins (do NOT break scoring - test after each)"
        foreach ($h in $Def.Hardening) { Write-Host "  [+] $h" -ForegroundColor Green }
    }
}

# ---------------------------------------------------------------------------
#  Backup plumbing
# ---------------------------------------------------------------------------
function Protect-BackupRoot {
    param([string]$Path)
    # Only Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18). Uses SIDs so it works on non-English Windows.
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /q 2>&1 | Out-Null
}

function New-BackupFolder {
    param([string]$ServiceName)
    if (-not (Test-Path $script:CCDCBackupRoot)) {
        New-Item -ItemType Directory -Path $script:CCDCBackupRoot -Force | Out-Null
        Protect-BackupRoot (Split-Path $script:CCDCBackupRoot -Parent)
        Protect-BackupRoot $script:CCDCBackupRoot
    }
    $dir = Join-Path $script:CCDCBackupRoot "$ServiceName\$($script:CCDCStamp)"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-INFO "Backup folder: $dir"
    $dir
}

function Export-RegKey {
    param([string]$Key, [string]$File)
    $k = $Key -replace '^HKLM:\\', 'HKLM\' -replace '^HKCU:\\', 'HKCU\'
    if (-not (Test-Path ("Registry::" + $k))) { Write-INFO "Registry key not present: $k"; return $false }
    New-Item -ItemType Directory -Path (Split-Path $File) -Force | Out-Null
    & reg.exe export $k $File /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-OK "Registry $k -> $(Split-Path $File -Leaf)"; return $true }
    Write-WARN "reg export failed for $k"; return $false
}

function Export-ServiceDefinition {
    param([string[]]$Names, [string]$Dest)
    $d = Join-Path $Dest "ServiceDefinition"
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    foreach ($s in Get-CCDCServiceObjects $Names) {
        $n = $s.Name
        & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$n" "$d\$n.reg" /y 2>&1 | Out-Null
        @(
            "### sc qc"; (& sc.exe qc $n 5000)
            "### sc sdshow (service DACL - restore with: sc sdset $n <sddl>)"; (& sc.exe sdshow $n)
            "### sc qfailure"; (& sc.exe qfailure $n)
            "### sc qtriggerinfo"; (& sc.exe qtriggerinfo $n)
        ) | Out-File "$d\$n.sc.txt" -Encoding UTF8
        $s | Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId, Description |
            Export-Clixml "$d\$n.service.xml"
    }
    Write-OK "Service definition(s) (registry, sc qc, DACL, failure actions) -> ServiceDefinition\"
}

function Copy-Tree {
    <# robocopy a directory tree + save its NTFS ACLs (icacls) so restore keeps permissions #>
    param([string]$Source, [string]$Dest, [string]$Label, [string[]]$ExcludeDirs, [string[]]$ExcludeFiles)
    $src = [Environment]::ExpandEnvironmentVariables($Source)
    if (-not (Test-Path -LiteralPath $src)) { Write-INFO "$Label - not found, skipping: $src"; return $false }
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    if (Test-Path -LiteralPath $src -PathType Leaf) {
        Copy-Item -LiteralPath $src -Destination $Dest -Force -ErrorAction SilentlyContinue
        Write-OK "$Label -> $Dest"; return $true
    }
    $rc_args = @($src, $Dest, '/E', '/COPY:DAT', '/DCOPY:T', '/R:1', '/W:1', '/XJ', '/NP', '/NFL', '/NDL', '/NJH', '/MT:8')
    if ($ExcludeDirs)  { $rc_args += '/XD'; $rc_args += $ExcludeDirs }
    if ($ExcludeFiles) { $rc_args += '/XF'; $rc_args += $ExcludeFiles }
    & robocopy.exe @rc_args | Out-Null
    $rc = $LASTEXITCODE
    # Save ACLs next to the copy. Restore with: icacls "<parent of source>" /restore "<file>.acl"
    & icacls.exe $src /save "$Dest.acl" /t /c /q 2>&1 | Out-Null
    "$src" | Out-File "$Dest.source.txt" -Encoding UTF8
    if ($rc -lt 8) { Write-OK "$Label -> $Dest"; return $true }
    Write-WARN "$Label copied with errors (robocopy rc=$rc) -> $Dest"; return $false
}

function Restore-Tree {
    <# Restore a tree copied by Copy-Tree. -Mirror also deletes files that were not in the backup (removes webshells, but DANGEROUS). #>
    param([string]$BackupDir, [string]$Target, [switch]$Mirror)
    if (-not (Test-Path $BackupDir)) { Write-WARN "Backup tree missing: $BackupDir"; return }
    if (-not $Target -and (Test-Path "$BackupDir.source.txt")) { $Target = (Get-Content "$BackupDir.source.txt" -TotalCount 1).Trim() }
    if (-not $Target) { Write-WARN "No restore target for $BackupDir"; return }
    $mode = if ($Mirror) { '/MIR' } else { '/E' }
    & robocopy.exe $BackupDir $Target $mode '/COPY:DAT' '/DCOPY:T' '/R:1' '/W:1' '/XJ' '/NP' '/NFL' '/NDL' '/NJH' | Out-Null
    if ($LASTEXITCODE -lt 8) { Write-OK "Restored files -> $Target ($mode)" } else { Write-WARN "robocopy rc=$LASTEXITCODE restoring $Target" }
    if (Test-Path "$BackupDir.acl") {
        & icacls.exe (Split-Path $Target -Parent) /restore "$BackupDir.acl" /c /q 2>&1 | Out-Null
        Write-OK "Restored NTFS ACLs for $Target"
    }
}

function Save-Manifest {
    param([string]$Dir, [string]$ServiceName, [string]$Notes)
    $files = Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'MANIFEST.csv' }
    $files | ForEach-Object {
        $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        [pscustomobject]@{ RelPath = $_.FullName.Substring($Dir.Length).TrimStart('\'); Size = $_.Length; SHA256 = $h.Hash }
    } | Export-Csv (Join-Path $Dir 'MANIFEST.csv') -NoTypeInformation
    $size = ($files | Measure-Object Length -Sum).Sum
    [pscustomobject]@{
        Service = $ServiceName; Host = $env:COMPUTERNAME; Taken = (Get-Date).ToString('s')
        By = "$env:USERDOMAIN\$env:USERNAME"; Files = @($files).Count; Bytes = $size; Notes = $Notes
    } | ConvertTo-Json | Out-File (Join-Path $Dir 'BACKUP_INFO.json') -Encoding UTF8
    Write-OK ("Manifest written: {0} files, {1:N1} MB" -f @($files).Count, ($size / 1MB))
}

function Get-LatestBackup {
    param([string]$ServiceName, [string]$RestoreFrom)
    if ($RestoreFrom) {
        if (Test-Path $RestoreFrom) { return (Resolve-Path $RestoreFrom).Path }
        Write-CRIT "RestoreFrom path not found: $RestoreFrom"; return $null
    }
    $base = Join-Path $script:CCDCBackupRoot $ServiceName
    $latest = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) { Write-CRIT "No backups found under $base"; return $null }
    $latest.FullName
}

function Test-BackupIntegrity {
    param([string]$Dir)
    $mf = Join-Path $Dir 'MANIFEST.csv'
    if (-not (Test-Path $mf)) { Write-WARN "No MANIFEST.csv in $Dir"; return $false }
    $bad = 0
    foreach ($row in Import-Csv $mf) {
        $p = Join-Path $Dir $row.RelPath
        if (-not (Test-Path -LiteralPath $p)) { Write-CRIT "MISSING: $($row.RelPath)"; $bad++; continue }
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        if ($h -ne $row.SHA256) { Write-CRIT "MODIFIED: $($row.RelPath)"; $bad++ }
    }
    if ($bad -eq 0) { Write-OK "Backup intact: $Dir" ; return $true }
    Write-CRIT "$bad file(s) missing/modified in $Dir - someone touched your backup"; return $false
}

function Confirm-Action {
    param([string]$Message)
    if ($script:CCDCForce) { return $true }
    Write-Host "`n  $Message" -ForegroundColor Yellow
    $a = Read-Host "  Type YES to continue"
    return ($a -eq 'YES')
}

function Invoke-Safely {
    <# Run a scriptblock, print a WARN instead of dying on error. #>
    param([string]$Label, [scriptblock]$Block)
    try { & $Block; return $true } catch { Write-WARN "$Label failed: $($_.Exception.Message)"; return $false }
}

# ---------------------------------------------------------------------------
#  Main dispatcher
# ---------------------------------------------------------------------------
function Invoke-ServiceMain {
    <#
      $Def keys:
        Name         short folder name used for backups (e.g. 'DNS')
        Title        banner title
        Description  multi-line string: what the service does
        ServiceNames Windows service names (wildcards OK)
        Ports        @( @{Port=53; Proto='TCP/UDP'; Use='DNS queries'} ... )
        KeyPaths     important files / registry keys
        RedTeam      list of abuse notes
        Hardening    list of hardening tips
        Detect       scriptblock -> $true if the service/role is on this box
        InfoExtra    scriptblock -> service-specific details
        Backup       scriptblock param($Dir)  -> do the backup into $Dir
        Restore      scriptblock param($Dir)  -> restore from $Dir
    #>
    param([hashtable]$Def, [string]$Action, [string]$RestoreFrom, [string]$BackupRoot, [switch]$Force)

    if ($BackupRoot) { $script:CCDCBackupRoot = $BackupRoot }
    $script:CCDCForce = [bool]$Force
    if (-not (Test-IsAdmin)) { Write-CRIT "Run this from an elevated (Administrator) PowerShell."; return }

    $present = $true
    if ($Def.Detect) { $present = [bool](& $Def.Detect) }

    if ($Action -eq 'Detect') {
        if ($present) { Write-Host ("  [PRESENT] {0,-22} {1}" -f $Def.Name, $Def.Title) -ForegroundColor Green }
        else          { Write-Host ("  [absent]  {0,-22} {1}" -f $Def.Name, $Def.Title) -ForegroundColor DarkGray }
        return
    }

    if ($Action -in 'Info', 'All') {
        Show-ServiceOverview $Def
        if ($present -and $Def.InfoExtra) { Write-STEP "Service-specific details"; & $Def.InfoExtra }
    }

    if (-not $present) {
        Write-Host "`n  [SKIP] $($Def.Title) is not installed / not running on $env:COMPUTERNAME." -ForegroundColor DarkGray
        return
    }

    if ($Action -in 'Backup', 'All') {
        Write-Banner "BACKUP: $($Def.Title)" "Green"
        $dir = New-BackupFolder $Def.Name
        if ($Def.ServiceNames) { Export-ServiceDefinition $Def.ServiceNames $dir }
        Invoke-Safely "Backup" { & $Def.Backup $dir } | Out-Null
        Save-Manifest $dir $Def.Name
        Write-Host "`n  Backup complete: $dir" -ForegroundColor Green
        Write-Host "  Copy it OFF this box too (red team can delete local backups)." -ForegroundColor DarkYellow
    }

    if ($Action -eq 'Verify') {
        $dir = Get-LatestBackup $Def.Name $RestoreFrom
        if ($dir) { Test-BackupIntegrity $dir | Out-Null }
    }

    if ($Action -eq 'Restore') {
        if (-not $Def.Restore) { Write-WARN "No scripted restore for $($Def.Title). See the notes printed by -Action Info."; return }
        $dir = Get-LatestBackup $Def.Name $RestoreFrom
        if (-not $dir) { return }
        Write-Banner "RESTORE: $($Def.Title) from $dir" "Yellow"
        Test-BackupIntegrity $dir | Out-Null
        if (-not (Confirm-Action "This overwrites live $($Def.Title) config on $env:COMPUTERNAME.")) { Write-INFO "Aborted."; return }
        Invoke-Safely "Restore" { & $Def.Restore $dir } | Out-Null
        Write-Host "`n  Restore finished - CHECK THE SCORING ENGINE NOW." -ForegroundColor Yellow
    }
}
