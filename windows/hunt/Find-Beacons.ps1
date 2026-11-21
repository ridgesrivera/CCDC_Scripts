<#
.SYNOPSIS
    Find-Beacons - look for command-and-control (C2) beacons: programs on this box calling out to an attacker. READ-ONLY.

.DESCRIPTION
    PURPOSE
      An implant (Cobalt Strike, Sliver, Meterpreter, a PowerShell reverse shell)
      has to talk to its controller. That shows up as an outbound connection from
      a program that should not be making one, often repeating every few seconds
      ("beaconing"). This watches connections for -Seconds (default 60) and flags:
        RED     a connection out of your own network from powershell / cmd / rundll32 /
                mshta / regsvr32 / certutil and similar, from a program in a user-
                writable folder (Temp, AppData, ProgramData, Public, inetpub), or to a
                well-known C2 / reverse-shell port (4444, 50050, 1337 ...)
        YELLOW  repeated short connections to the same address (the beacon rhythm),
                repeated failed connection attempts (a beacon that is being blocked),
                unsigned programs talking out, odd DNS names (very long / random
                labels = possible DNS tunnelling), named pipes used by C2 frameworks
      Each RED / YELLOW line shows the process, PID, path, remote IP:port and what to do.

    WHAT IT READS    TCP connections (sampled), processes + signatures, DNS client cache, named pipes
    WHAT IT CHANGES  nothing
    HOW TO UNDO      nothing to undo

    WHAT TO DO WITH A HIT
      1. Note the PID, path and remote IP (incident report evidence).
      2. Block the remote IP: panel X -> 2.  3. Remove the program / its persistence: panel R.
      4. Find how it got there: panel E (Red Team response).

    MANUAL EQUIVALENT
      netstat -ano | findstr ESTABLISHED     (repeat a few times; note PIDs)
      Get-Process -Id <pid> | fl Path ; Get-AuthenticodeSignature <path>
      Get-DnsClientCache | sort Entry

.PARAMETER Seconds
    How long to watch. Default 60 (a beacon that sleeps longer may need -Seconds 300).

.EXAMPLE
    .\Find-Beacons.ps1 -Seconds 120
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 1800)][int]$Seconds = 60,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Find-Beacons' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath

# "Our network" = the subnets this box is on. Anything else is outside.
$nets = @()
foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' })) {
    $len = if ($a.PrefixLength) { $a.PrefixLength } else { 24 }
    $nets += "$($a.IPAddress)/$len"
}
function Test-Outside([string]$ip) {
    if (-not $ip -or $ip -match '^(127\.|::1$|0\.0\.0\.0|::$|fe80:)') { return $false }
    foreach ($n in $nets) { if (Test-CcdcIpInCidr -Ip $ip -Cidr $n) { return $false } }
    return $true
}
$lolbins = 'powershell', 'pwsh', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'msbuild', 'installutil', 'wmic', 'notepad', 'calc', 'mspaint', 'regasm', 'regsvcs', 'msiexec', 'curl', 'nc', 'ncat', 'socat', 'plink'
$c2Ports = 4444, 4445, 4446, 5555, 1337, 31337, 50050, 6666, 6667, 7777, 8888, 9999, 1234, 9001, 2222, 12345
$userPath = '(?i)\\(temp|tmp|appdata|programdata|users\\public|perflogs|inetpub|windows\\tasks|recycle)'

# ---------------------------------------------------------------------------
Write-Section "Watching connections for $Seconds s (sample every 5 s)"
# ---------------------------------------------------------------------------
$seen = @{}     # "pid|remote:port" -> stats
$samples = [Math]::Max(2, [int]($Seconds / 5))
for ($i = 0; $i -lt $samples; $i++) {
    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Established', 'SynSent' -and $_.RemoteAddress -notmatch '^(0\.0\.0\.0|::)$' })) {
        $rip = $c.RemoteAddress -replace '^::ffff:', ''
        if ($c.State -eq 'Established' -and [int]$c.LocalPort -lt 49152 -and [int]$c.RemotePort -ge 49152) { continue }   # inbound to one of our services
        $k = "$($c.OwningProcess)|${rip}:$($c.RemotePort)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = @{ Pid = [int]$c.OwningProcess; Ip = $rip; Port = [int]$c.RemotePort; Hits = 0; LocalPorts = @{}; Syn = 0 } }
        $s = $seen[$k]; $s.Hits++; $s.LocalPorts[[int]$c.LocalPort] = 1; if ($c.State -eq 'SynSent') { $s.Syn++ }
    }
    Write-Progress -Activity 'Watching for beacons' -Status "$($i + 1) / $samples" -PercentComplete (100 * ($i + 1) / $samples)
    if ($i -lt $samples - 1) { Start-Sleep -Seconds 5 }
}
Write-Progress -Activity 'Watching for beacons' -Completed

$procInfo = @{}
foreach ($p in @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)) { $procInfo[[int]$p.ProcessId] = $p }
$sigCache = @{}
function Get-Signed([string]$path) {
    if (-not $path) { return '?' }
    if (-not $sigCache.ContainsKey($path)) { $st = (Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue).Status; $sigCache[$path] = [string]$st }
    return $sigCache[$path]
}

$hits = 0
foreach ($s in ($seen.Values | Sort-Object { $_.Pid })) {
    $p = $procInfo[$s.Pid]
    $name = if ($p) { ($p.Name -replace '\.exe$', '') } else { "pid $($s.Pid)" }
    $path = if ($p) { [string]$p.ExecutablePath } else { '' }
    $out = Test-Outside $s.Ip
    $why = @(); $lvl = $null
    if ($c2Ports -contains $s.Port) { $why += "port $($s.Port) is a common C2 / reverse-shell port"; $lvl = 'RED' }
    if ($out -and $lolbins -contains $name.ToLower()) { $why += "$name should not be talking outside your network"; $lvl = 'RED' }
    if ($out -and $path -match $userPath) { $why += 'program runs from a user-writable folder'; $lvl = 'RED' }
    if ($s.LocalPorts.Count -ge 3) { $why += "reconnected $($s.LocalPorts.Count) times in $Seconds s (beacon rhythm)"; if (-not $lvl) { $lvl = 'YELLOW' } }
    if ($s.Syn -ge 3) { $why += "keeps trying to connect and failing ($($s.Syn)x): a blocked beacon?"; if (-not $lvl) { $lvl = 'YELLOW' } }
    if ($out -and $path -and -not $lvl) { $sig = Get-Signed $path; if ($sig -ne 'Valid') { $why += "unsigned program ($sig) talking outside"; $lvl = 'YELLOW' } }
    if (-not $lvl) { continue }
    $hits++
    $cmd = if ($p -and $p.CommandLine) { [string]$p.CommandLine } else { '' }
    if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + '...' }
    Write-Finding -Level $lvl -Category 'Beacon' -Message ("{0} (PID {1}) -> {2}:{3}{4}" -f $name, $s.Pid, $s.Ip, $s.Port, $(if ($out) { '  [outside your network]' } else { '' })) -Detail (@("why: $($why -join '; ')", "path: $path", "cmd: $cmd", "do: panel X -> 2 block $($s.Ip); panel R to remove; Stop-Process -Id $($s.Pid) once you have the evidence") -join "`n")
}
if ($hits -eq 0) { Write-Finding -Level GREEN -Category 'Beacon' -Message "No suspicious outbound connections in $Seconds s ($($seen.Count) connection(s) checked). Slow beacons may need -Seconds 300." }

# ---------------------------------------------------------------------------
Write-Section 'Named pipes used by C2 frameworks'
# ---------------------------------------------------------------------------
$pipeRx = '(?i)^(msagent_|postex_|status_|mojo\.5688\.8052|MSSE-\d+-server|interprocess_|lsadump|winsock|ntsvcs_|scerpc_|DserNamePipe|gruntsvc|demoagent|sliver)'
$pipes = @(Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pipeRx })
foreach ($pp in $pipes) { Write-Finding -Level RED -Category 'Pipe' -Message "Named pipe '$($pp.Name)' matches a default C2 pipe name (Cobalt Strike / Sliver / Covenant)" -Detail 'Find the owning process with Sysinternals handle.exe or Process Explorer, then panel R.' }
if (-not $pipes) { Write-Finding -Level GREEN -Category 'Pipe' -Message 'No default C2 pipe names.' }

# ---------------------------------------------------------------------------
Write-Section 'DNS names this box looked up (DNS tunnelling / random C2 domains)'
# ---------------------------------------------------------------------------
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $odd = @(Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { $_.Entry } | Sort-Object -Unique | Where-Object {
        $labels = $_ -split '\.'
        ($labels | Where-Object { $_.Length -ge 30 }) -or ($labels[0] -match '^[a-z0-9]{20,}$' -and $labels[0] -match '\d' -and $labels[0] -match '[a-z]') -or ($_ -match '(?i)\.(ngrok|trycloudflare|duckdns|no-ip|serveo|interactsh|oast)\.')
    })
    foreach ($d in $odd) { Write-Finding -Level YELLOW -Category 'DNS' -Message "Unusual name looked up: $d" -Detail 'Long random labels can be DNS tunnelling; tunnel services (ngrok, trycloudflare...) are common C2 relays.' }
    if (-not $odd) { Write-Finding -Level GREEN -Category 'DNS' -Message 'Nothing unusual in the DNS cache.' }
} else { Write-Finding -Level INFO -Category 'DNS' -Message 'Get-DnsClientCache not available on this Windows version: ipconfig /displaydns' }

Complete-Ccdc
