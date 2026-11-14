<#
.SYNOPSIS
    Invoke-AuditTools - run the staged third-party audit tools and turn their output into findings. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Our own audit scripts cover the common spots. These vendor tools go
      deeper and are what the pros use, so this script runs each one the
      same safe way every time, saves the raw output, and prints only the
      lines that need a human:
        Autoruns (autorunsc)  EVERY autostart location (~200 of them), with signatures - unsigned = RED
        Sigcheck              unsigned .exe/.dll/.sys directly in System32
        AccessChk             services that Everyone / Users / Authenticated Users can reconfigure
                              (the privesc winPEAS would find, done the blue-team way)
        Hayabusa              Sigma rules over the local event logs -> critical/high detections
        PingCastle            AD health check report (domain-joined boxes; best on the DC)
        Locksmith             AD Certificate Services misconfigurations (Mode 0 = identify only)
        winPEAS               ONLY with -IncludeWinPEAS (see tools\README.md for the trade-offs)

      Tools that are not staged are skipped with a note. Stage them first:
        .\tools\Get-CcdcTools.ps1        (on a trusted machine)  then  -Verify  on the box

    WHAT IT READS    autostart locations, System32, service DACLs, event logs, AD (LDAP)
    WHAT IT CHANGES  nothing on the system. Writes raw tool output to C:\ccdc\reports\tools_<host>_<stamp>\
                     (ACL: Administrators + SYSTEM). Sysinternals tools record "EULA accepted" in HKCU.
    HOW TO UNDO      delete the report folder

    MANUAL EQUIVALENT
      autorunsc64.exe -accepteula -a * -c -h -s -m -nobanner -o autoruns.csv
      sigcheck64.exe -accepteula -u -e -c -nobanner -w unsigned.csv C:\Windows\System32
      accesschk64.exe -accepteula -nobanner -uwcqv "Authenticated Users" *
      hayabusa.exe csv-timeline -l -o hayabusa.csv -m high -w -q
      PingCastle.exe --healthcheck
      powershell -File Invoke-Locksmith.ps1 -Mode 0

.PARAMETER Only
    Run only these: Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith, WinPEAS.
.PARAMETER IncludeWinPEAS
    Also run winPEAS (off by default: Defender flags it and its output can contain credentials).
.PARAMETER HayabusaMinLevel
    Minimum Hayabusa rule level to keep: critical, high (default), medium, low.

.EXAMPLE
    .\Invoke-AuditTools.ps1
.EXAMPLE
    .\Invoke-AuditTools.ps1 -Only Autoruns,AccessChk -OutFile C:\ccdc\reports\tools.txt
#>
[CmdletBinding()]
param(
    [ValidateSet('Autoruns', 'Sigcheck', 'AccessChk', 'Hayabusa', 'PingCastle', 'Locksmith', 'WinPEAS')]
    [string[]]$Only = @(),
    [switch]$IncludeWinPEAS,
    [ValidateSet('critical', 'high', 'medium', 'low')][string]$HayabusaMinLevel = 'high',
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Invoke-AuditTools' -OutFile $OutFile -ReadOnly
$null  = Get-CcdcConfig -Path $ConfigPath
$tools = Join-Path $script:CcdcToolkitRoot 'tools'
$si    = Join-Path $tools 'bin\sysinternals'
$out   = 'C:\ccdc\reports\tools_{0}_{1}' -f $env:COMPUTERNAME, $script:CcdcStamp
New-Item -ItemType Directory -Path $out -Force | Out-Null
# Raw output can include file paths, account names and (winPEAS) credentials: admins only.
$null = & icacls.exe $out /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /q 2>&1
Write-Finding -Level INFO -Category 'Setup' -Message "Raw tool output: $out"

$manifest = Join-Path $tools 'staged-tools.csv'
if (Test-Path $manifest) {
    Write-Finding -Level INFO -Category 'Setup' -Message 'Tip: verify the staged copies first: .\tools\Get-CcdcTools.ps1 -Verify'
} else {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'No tools\staged-tools.csv - tools were not staged with Get-CcdcTools.ps1, so their hashes cannot be verified.'
}

function Test-Want([string]$name) {
    if ($Only) { return ($Only -contains $name) }
    if ($name -eq 'WinPEAS') { return [bool]$IncludeWinPEAS }
    return $true
}
function Find-Tool([string[]]$candidates) {
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}
function Test-MsSigned([string]$path) {
    # Refuse to run a "Microsoft" tool whose signature is not valid - someone may have swapped it.
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
    return ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft')
}
$is64 = [Environment]::Is64BitOperatingSystem
function Get-Si([string]$base) {
    # Sysinternals ship <name>64.exe and <name>.exe; prefer the 64-bit one.
    $cands = @()
    if ($is64) { $cands += (Join-Path $si "${base}64.exe") }
    $cands += (Join-Path $si "$base.exe")
    $p = Find-Tool $cands
    if ($p -and -not (Test-MsSigned $p)) {
        Write-Finding -Level RED -Category 'Setup' -Message "$p is NOT validly Microsoft-signed - not running it (tampered copy?)"
        return $null
    }
    return $p
}

# ---------------------------------------------------------------------------
if (Test-Want 'Autoruns') {
    Write-Section 'Autoruns: every autostart entry, Microsoft-signed ones hidden'
    $exe = Get-Si 'autorunsc'
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'Autoruns' -Message 'autorunsc not staged (tools\bin\sysinternals). Skipped.' }
    else {
        $csv = Join-Path $out 'autoruns.csv'
        # -a * all locations, -c CSV, -h hashes, -s verify signatures, -m hide Microsoft-signed.
        # -o writes the file itself: autorunsc's console output is UTF-16 and garbles in a pipe.
        $null = & $exe -accepteula -nobanner -a * -c -h -s -m -o $csv 2>&1
        $rows = @(Import-Csv $csv -ErrorAction SilentlyContinue | Where-Object { $_.'Entry' })
        $unsigned = @($rows | Where-Object { $_.Signer -match '(?i)not verified|^\s*$' -and $_.'Image Path' })
        foreach ($r in ($unsigned | Select-Object -First 40)) {
            Write-Finding -Level RED -Category 'Autoruns' -Message ("UNSIGNED [{0}] {1} -> {2}" -f $r.Category, $r.Entry, $r.'Image Path') -Detail ("{0} | {1}" -f $r.'Entry Location', $r.'Launch String')
        }
        $signedOther = @($rows | Where-Object { $unsigned -notcontains $_ })
        Write-Finding -Level INFO -Category 'Autoruns' -Message ("{0} non-Microsoft autostart entries: {1} unsigned (RED above), {2} signed by others. Full list: {3}" -f $rows.Count, $unsigned.Count, $signedOther.Count, $csv)
        if ($unsigned.Count -gt 40) { Write-Finding -Level YELLOW -Category 'Autoruns' -Message "Only the first 40 unsigned entries are shown - open $csv" }
    }
}

# ---------------------------------------------------------------------------
if (Test-Want 'Sigcheck') {
    Write-Section 'Sigcheck: unsigned executables directly in System32'
    $exe = Get-Si 'sigcheck'
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'Sigcheck' -Message 'sigcheck not staged. Skipped.' }
    else {
        $csv = Join-Path $out 'sigcheck_system32_unsigned.csv'
        # -u unsigned only, -e executable images only (any extension), -c CSV. No -s: recursing System32 takes minutes.
        $null = & $exe -accepteula -nobanner -u -e -c -w $csv "$env:windir\System32" 2>&1
        $rows = @(Import-Csv $csv -ErrorAction SilentlyContinue | Where-Object { $_.Path })
        foreach ($r in ($rows | Select-Object -First 30)) { Write-Finding -Level RED -Category 'Sigcheck' -Message "UNSIGNED in System32: $($r.Path)" -Detail ("{0} {1} {2}" -f $r.Publisher, $r.Description, $r.Date) }
        if ($rows.Count -eq 0) { Write-Finding -Level GREEN -Category 'Sigcheck' -Message 'Every executable directly in System32 is signed.' }
        else { Write-Finding -Level INFO -Category 'Sigcheck' -Message "$($rows.Count) unsigned executable(s). Some third-party drivers are legitimately unsigned - check path + date. Full list: $csv" }
    }
}

# ---------------------------------------------------------------------------
if (Test-Want 'AccessChk') {
    Write-Section 'AccessChk: services low-privileged users can reconfigure'
    $exe = Get-Si 'accesschk'
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'AccessChk' -Message 'accesschk not staged. Skipped.' }
    else {
        $txt = Join-Path $out 'accesschk_services.txt'
        $hits = 0
        foreach ($who in @('Everyone', 'Users', 'Authenticated Users', 'INTERACTIVE')) {
            # -u suppress errors, -w write access only, -c services, -q no banner, -v verbose (shows which right)
            $res = & $exe -accepteula -nobanner -uwcqv $who '*' 2>$null
            "### $who" | Out-File $txt -Append -Encoding UTF8
            $res | Out-File $txt -Append -Encoding UTF8
            $svc = $null
            foreach ($line in $res) {
                if ($line -match '^RW\s+(\S+)') { $svc = $Matches[1]; continue }
                # The rights that let a user point a service at their own binary.
                if ($svc -and $line -match '(?i)SERVICE_ALL_ACCESS|SERVICE_CHANGE_CONFIG|WRITE_DAC|WRITE_OWNER') {
                    $hits++
                    Write-Finding -Level RED -Category 'AccessChk' -Message "'$who' can reconfigure service '$svc' ($($line.Trim()))" -Detail "Privesc to SYSTEM. Fix: sc sdshow $svc  /  sc sdset $svc <default SDDL>  (compare with a clean box)"
                    $svc = $null
                }
            }
        }
        if ($hits -eq 0) { Write-Finding -Level GREEN -Category 'AccessChk' -Message 'No service is reconfigurable by Everyone/Users/Authenticated Users/INTERACTIVE.' }
    }
}

# ---------------------------------------------------------------------------
if (Test-Want 'Hayabusa') {
    Write-Section "Hayabusa: Sigma detections in local event logs (level >= $HayabusaMinLevel)"
    $hdir = Join-Path $tools 'bin\hayabusa'
    $exe = Get-ChildItem $hdir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'Hayabusa' -Message 'hayabusa not staged (tools\bin\hayabusa). Skipped.' }
    else {
        $csv = Join-Path $out 'hayabusa.csv'
        Write-Host '     scanning event logs (can take a few minutes on a busy DC)...' -ForegroundColor DarkGray
        # csv-timeline -l = live local logs, -w = no interactive wizard, -q = quiet, -C = overwrite output.
        # Run from its own folder so it finds rules\ and config\.
        Push-Location $exe.DirectoryName
        try { $null = & $exe.FullName csv-timeline -l -o $csv -m $HayabusaMinLevel -w -q -C 2>&1 } finally { Pop-Location }
        if (-not (Test-Path $csv)) {
            Write-Finding -Level YELLOW -Category 'Hayabusa' -Message "No output produced (exit $LASTEXITCODE). Run by hand: $($exe.FullName) csv-timeline -l -o $csv"
        } else {
            $rows = @(Import-Csv $csv -ErrorAction SilentlyContinue)
            $groups = $rows | Group-Object RuleTitle | Sort-Object Count -Descending
            foreach ($g in ($groups | Select-Object -First 25)) {
                $first = $g.Group | Select-Object -First 1
                $lvl = if ($first.Level -match '(?i)^crit|^high') { 'RED' } else { 'YELLOW' }
                $last = ($g.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
                Write-Finding -Level $lvl -Category 'Hayabusa' -Message ("[{0}] {1}  x{2}  (latest {3})" -f $first.Level, $g.Name, $g.Count, $last) -Detail ("{0} | {1}" -f $first.Channel, ([string]$first.Details).Substring(0, [Math]::Min(150, ([string]$first.Details).Length)))
            }
            if (-not $rows) { Write-Finding -Level GREEN -Category 'Hayabusa' -Message "No $HayabusaMinLevel+ detections in the local logs." }
            else { Write-Finding -Level INFO -Category 'Hayabusa' -Message ("{0} detections, {1} distinct rules. Full timeline: {2}" -f $rows.Count, @($groups).Count, $csv) }
        }
    }
}

# ---------------------------------------------------------------------------
$domainJoined = $false
try { $domainJoined = [bool]([ADSI]'LDAP://RootDSE').defaultNamingContext } catch { $domainJoined = $false }

if (Test-Want 'PingCastle') {
    Write-Section 'PingCastle: AD health check'
    $exe = Find-Tool @((Join-Path $tools 'bin\pingcastle\PingCastle.exe'))
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'PingCastle' -Message 'PingCastle not staged. Skipped.' }
    elseif (-not $domainJoined) { Write-Finding -Level INFO -Category 'PingCastle' -Message 'Not domain-joined - skipped.' }
    else {
        Write-Host '     running health check (1-5 minutes)...' -ForegroundColor DarkGray
        $p = Start-Process -FilePath $exe -ArgumentList '--healthcheck', '--no-enum-limit' -WorkingDirectory $out -NoNewWindow -Wait -PassThru
        $report = Get-ChildItem $out -Filter 'ad_hc_*.html' -ErrorAction SilentlyContinue | Select-Object -First 1
        $xmlRep = Get-ChildItem $out -Filter 'ad_hc_*.xml' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($report) {
            Write-Finding -Level INFO -Category 'PingCastle' -Message "Report: $($report.FullName)  (open it in a browser; fix the highest-points rules first)"
            if ($xmlRep) {
                try {
                    $x = [xml](Get-Content $xmlRep.FullName -Raw)
                    $score = $x.HealthcheckData.GlobalScore
                    $lvl = if ([int]$score -ge 50) { 'RED' } elseif ([int]$score -ge 20) { 'YELLOW' } else { 'GREEN' }
                    Write-Finding -Level $lvl -Category 'PingCastle' -Message "Global risk score: $score / 100 (lower is better)"
                    foreach ($rr in ($x.HealthcheckData.RiskRules.HealthcheckRiskRule | Sort-Object { [int]$_.Points } -Descending | Select-Object -First 15)) {
                        $l2 = if ([int]$rr.Points -ge 20) { 'RED' } else { 'YELLOW' }
                        Write-Finding -Level $l2 -Category 'PingCastle' -Message ("{0} pts  {1}" -f $rr.Points, $rr.Rationale) -Detail $rr.RiskId
                    }
                } catch { Write-Finding -Level INFO -Category 'PingCastle' -Message 'Could not parse the XML report - read the HTML.' }
            }
        } else { Write-Finding -Level YELLOW -Category 'PingCastle' -Message "No report produced (exit $($p.ExitCode)). Run it by hand from $out." }
    }
}

if (Test-Want 'Locksmith') {
    Write-Section 'Locksmith: AD Certificate Services (ESC1-ESC16)'
    $ps1 = Find-Tool @((Join-Path $tools 'bin\locksmith\Invoke-Locksmith.ps1'))
    if (-not $ps1) { Write-Finding -Level YELLOW -Category 'Locksmith' -Message 'Locksmith not staged. Skipped.' }
    elseif (-not $domainJoined) { Write-Finding -Level INFO -Category 'Locksmith' -Message 'Not domain-joined - skipped.' }
    elseif (-not (Get-Module -ListAvailable ActiveDirectory)) { Write-Finding -Level INFO -Category 'Locksmith' -Message 'Needs the ActiveDirectory module (RSAT) - run it on the DC.' }
    else {
        $txt = Join-Path $out 'locksmith.txt'
        # Mode 0 = identify and print issues ONLY. (Mode 4 makes changes - never used here.)
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ps1 -Mode 0 *>&1 | Out-File $txt -Encoding UTF8
        $issues = @(Select-String -Path $txt -Pattern '\bESC\d+\b' -AllMatches | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique)
        if ($issues) { Write-Finding -Level RED -Category 'Locksmith' -Message "AD CS issues reported: $($issues -join ', ')" -Detail "Details + fix commands: $txt" }
        else { Write-Finding -Level GREEN -Category 'Locksmith' -Message "No ESC issues reported (output: $txt)" }
    }
}

# ---------------------------------------------------------------------------
if (Test-Want 'WinPEAS') {
    Write-Section 'winPEAS: attacker-style privilege-escalation enumeration'
    $exe = Find-Tool @((Join-Path $tools 'bin\peass\winPEASx64.exe'))
    if (-not $exe) { Write-Finding -Level YELLOW -Category 'WinPEAS' -Message 'winPEAS not staged (or Defender removed it). Skipped. Get-CcdcTools.ps1 -IncludeOffensive stages it.' }
    else {
        Write-Finding -Level YELLOW -Category 'WinPEAS' -Message 'winPEAS output can contain CREDENTIALS it finds. It stays in the locked report folder - delete it when done, never copy it to a share.'
        $txt = Join-Path $out 'winpeas.txt'
        $p = Start-Process -FilePath $exe -ArgumentList 'quiet', 'notcolor' -RedirectStandardOutput $txt -NoNewWindow -Wait -PassThru
        if (-not (Test-Path $exe)) { Write-Finding -Level YELLOW -Category 'WinPEAS' -Message 'The binary disappeared while running - Defender quarantined it. That is Defender doing its job; use the other checks.' }
        elseif (Test-Path $txt) { Write-Finding -Level INFO -Category 'WinPEAS' -Message "Output: $txt (exit $($p.ExitCode)). Read the red/yellow lines; most also show in Audit-Persistence / AccessChk above." }
    }
}

Complete-Ccdc
