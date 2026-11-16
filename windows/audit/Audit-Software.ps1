<#
.SYNOPSIS
    Audit-Software - installed programs, remote-access tools, attack tools and junk, with a decision column. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Two things at once:
        1. HUNT: remote-access tools (AnyDesk, TeamViewer, VNC, ngrok, RustDesk...)
           call out to a vendor's servers, so they work through NAT and never
           show up in a port scan. They are a favourite way to keep access.
           An unauthenticated VNC server was a real finding this season.
        2. INJECT: "unnecessary software audit" and "remote access tool audit"
           come up at almost every event. They want each item listed per host
           with a decision (remove / restrict / keep) and a reason. -OutFile
           x.csv gives you that table with the facts filled in.

    WHAT IT CHECKS
      * Installed programs (64-bit, 32-bit and per-user uninstall keys)
      * Services and running processes that match the tool lists (catches
        portable copies that were never "installed")
      * Executables with tool names dropped in Downloads, Desktop, Temp, Public, ProgramData
      * Windows features that are rarely needed: Telnet, TFTP, SMB1, FTP server, SNMP
      * Listening ports that belong to remote-access tools (5900 VNC, 5938 TeamViewer, 7070 AnyDesk...)

    CATEGORIES
      RemoteAccess  RED     keeps access without a password you control
      AttackTool    RED     scanners, credential dumpers, tunnels (ours or theirs? decide)
      Junk          YELLOW  games, torrent clients, chat, media players
      Outdated      YELLOW  end-of-life runtimes and servers
      Other         INFO    everything else (for the inventory table)

    WHAT IT READS    registry uninstall keys, services, processes, a few folders, features
    WHAT IT CHANGES  nothing (own log + optional report only)
    HOW TO UNDO      nothing to undo

    MANUAL EQUIVALENT
      Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                       HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName,DisplayVersion,Publisher
      Get-Service | ? DisplayName -match 'vnc|anydesk|teamviewer'
      Get-WindowsFeature | ? Installed            (servers)
      Uninstall: appwiz.cpl, or the UninstallString shown in the detail line.

.PARAMETER ShowAll
    Also print the "Other" programs on screen (they are always in the -OutFile report).

.EXAMPLE
    .\Audit-Software.ps1
.EXAMPLE
    .\Audit-Software.ps1 -ShowAll -OutFile C:\ccdc\reports\software_TREX.csv
#>
[CmdletBinding()]
param(
    [switch]$ShowAll,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Software' -OutFile $OutFile -ReadOnly
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config
$scoredPorts = @(); if ($hostCfg) { $scoredPorts = @($hostCfg.scoredPorts.tcp) }

$rxRemote = '(?i)(anydesk|teamviewer|\bvnc\b|tightvnc|ultravnc|realvnc|tigervnc|ngrok|rustdesk|screenconnect|connectwise control|logmein|gotomypc|splashtop|radmin|ammyy|dameware|chrome remote|remote utilities|supremo|atera|tailscale|zerotier|bomgar|beyondtrust remote|parsec|meshagent|meshcentral|nomachine|action1|simplehelp|fleetdeck|netsupport|aeroadmin|getscreen|zoho assist|pdq connect|level\.io|cloudflared|frpc|chisel|plink)'
$rxAttack = '(?i)(nmap|zenmap|masscan|mimikatz|metasploit|meterpreter|cobalt ?strike|netcat|\bncat\b|\bnc(64)?\.exe|psexec|paexec|john the ripper|hashcat|cain ?& ?abel|burp ?suite|responder|bloodhound|sharphound|rubeus|lazagne|procdump|proxychains|powersploit|empire|impacket|crackmapexec|kerbrute|winpeas|seatbelt|hydra|sqlmap|wireshark|npcap|winpcap|process hacker|angry ip)'
$rxJunk   = '(?i)(torrent|utorrent|bittorrent|qbittorrent|limewire|kazaa|emule|steam|epic games|minecraft|roblox|league of legends|discord|spotify|itunes|\bvlc\b|ccleaner|toolbar|coupon|candy crush|solitaire|xbox|skype|whatsapp|telegram|tor browser|opera gx|winamp|dropbox|mega(sync)?\b)'
$rxOld    = '(?i)(java\(tm\) [5-8] |java [5-8] update|adobe flash|shockwave|silverlight|python 2\.|php 5\.|php 7\.[0-3]|adobe reader (x|xi|9|8)|quicktime|internet explorer|xampp|wamp|filezilla server 0\.|apache tomcat [5-8]\.|openssl 1\.0|mysql server 5\.[0-6]|sql server 20(05|08|12))'
# Tools a blue team installs on purpose: listed, but as YELLOW "is this ours?" instead of RED.
$rxOurs   = '(?i)(wireshark|npcap|winpcap|nmap|procdump|process hacker|winpeas)'

$rows = New-Object System.Collections.ArrayList
function Add-Row {
    param([string]$Source, [string]$Name, [string]$Version = '', [string]$Publisher = '', [string]$Installed = '', [string]$Location = '', [string]$Uninstall = '')
    $text = "$Name $Location"
    $cat = 'Other'; $lvl = 'INFO'; $decision = 'Keep (document purpose)'
    if ($text -match $rxRemote)     { $cat = 'RemoteAccess'; $lvl = 'RED';    $decision = 'REMOVE unless the packet lists it as a business tool; if kept: password + firewall restrict' }
    elseif ($text -match $rxAttack) { $cat = 'AttackTool';   $lvl = 'RED';    $decision = 'REMOVE (not a business tool)' ; if ($text -match $rxOurs) { $lvl = 'YELLOW'; $decision = 'Ours? keep during the event, else REMOVE' } }
    elseif ($text -match $rxJunk)   { $cat = 'Junk';         $lvl = 'YELLOW'; $decision = 'REMOVE (no business purpose)' }
    elseif ($text -match $rxOld)    { $cat = 'Outdated';     $lvl = 'YELLOW'; $decision = 'UPDATE or remove if no scored service needs it' }
    $row = [pscustomobject]@{
        Host = $env:COMPUTERNAME; Category = $cat; Name = $Name; Version = $Version; Publisher = $Publisher; Installed = $Installed
        Source = $Source; Location = $Location; Decision = $decision; Reason = ''; Uninstall = $Uninstall; Level = $lvl
    }
    [void]$rows.Add($row)
    return $row
}

# ---------------------------------------------------------------------------
Write-Section 'Installed programs'
# ---------------------------------------------------------------------------
$uninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
    $uninstallKeys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
}
$seenNames = @{}
foreach ($k in $uninstallKeys) {
    foreach ($p in @(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })) {
        if ($p.SystemComponent -eq 1 -and $p.DisplayName -notmatch $rxRemote) { continue }     # hidden Windows components
        $id = "$($p.DisplayName)|$($p.DisplayVersion)"
        if ($seenNames.ContainsKey($id)) { continue }
        $seenNames[$id] = $true
        $date = [string]$p.InstallDate
        if ($date -match '^(\d{4})(\d\d)(\d\d)$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
        $scope = if ($k -match 'HKEY_USERS') { 'installed (per-user)' } else { 'installed' }
        $null = Add-Row -Source $scope -Name $p.DisplayName -Version ([string]$p.DisplayVersion) -Publisher ([string]$p.Publisher) -Installed $date -Location ([string]$p.InstallLocation) -Uninstall ([string]$p.UninstallString)
    }
}
$installed = @($rows)
Write-Finding -Level INFO -Category 'Inventory' -Message ("{0} installed programs" -f $installed.Count)
# Recently installed software is worth a look whatever its name is.
foreach ($r in ($installed | Where-Object { $_.Installed -match '^\d{4}-\d\d-\d\d$' -and ([datetime]$_.Installed) -gt (Get-Date).AddDays(-14) -and $_.Category -eq 'Other' })) {
    Write-Finding -Level YELLOW -Category 'Recent' -Message ("installed {0}: {1} {2}" -f $r.Installed, $r.Name, $r.Version) -Detail "publisher: $($r.Publisher)"
}

# ---------------------------------------------------------------------------
Write-Section 'Services and processes (catches portable tools)'
# ---------------------------------------------------------------------------
foreach ($s in (Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)) {
    $text = "$($s.Name) $($s.DisplayName) $($s.PathName)"
    if ($text -notmatch $rxRemote -and $text -notmatch $rxAttack) { continue }
    $null = Add-Row -Source ("service ({0}, start {1})" -f $s.State, $s.StartMode) -Name ("{0} [{1}]" -f $s.DisplayName, $s.Name) -Location ([string]$s.PathName)
}
$procSeen = @{}
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    $path = [string]$p.Path
    $text = "$($p.ProcessName).exe $path"
    if ($text -notmatch $rxRemote -and $text -notmatch $rxAttack) { continue }
    if ($procSeen.ContainsKey($p.ProcessName)) { continue }
    $procSeen[$p.ProcessName] = $true
    $null = Add-Row -Source ("running process (PID {0})" -f $p.Id) -Name "$($p.ProcessName).exe" -Location $path
}

# ---------------------------------------------------------------------------
Write-Section 'Dropped executables in user-writable folders'
# ---------------------------------------------------------------------------
$dropDirs = @('C:\Users\Public', 'C:\Temp', 'C:\Tools', "$env:windir\Temp", $env:ProgramData)
$dropDirs += Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Downloads'; Join-Path $_.FullName 'Desktop'; Join-Path $_.FullName 'AppData\Local\Temp'; Join-Path $_.FullName 'AppData\Roaming' }
foreach ($d in ($dropDirs | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)) {
    Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -File -Force -Include *.exe, *.msi, *.ps1, *.bat, *.zip, *.7z -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $rxRemote -or $_.Name -match $rxAttack } | Select-Object -First 60 | ForEach-Object {
            $null = Add-Row -Source ("file (modified {0})" -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) -Name $_.Name -Location $_.FullName
        }
}

# ---------------------------------------------------------------------------
Write-Section 'Windows features that are rarely needed'
# ---------------------------------------------------------------------------
$featureNotes = @{
    'Telnet-Client' = 'clear-text remote shell client'; 'Telnet-Server' = 'clear-text remote shell SERVER'; 'TFTP-Client' = 'file transfer with no authentication'
    'FS-SMB1' = 'SMBv1 (EternalBlue)'; 'Web-Ftp-Server' = 'IIS FTP server (check anonymous access: services\FTP.ps1)'; 'SNMP-Service' = 'SNMP (default community strings)'
    'SMB1Protocol' = 'SMBv1 (EternalBlue)'; 'TelnetClient' = 'clear-text remote shell client'; 'TFTP' = 'file transfer with no authentication'; 'SimpleTCP' = 'echo/chargen/daytime services'
    'PowerShell-V2' = 'PowerShell 2.0 (bypasses script block logging)'; 'MicrosoftWindowsPowerShellV2' = 'PowerShell 2.0 (bypasses script block logging)'; 'MicrosoftWindowsPowerShellV2Root' = 'PowerShell 2.0 (bypasses script block logging)'
}
$features = @()
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $features = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed } | ForEach-Object { $_.Name })
} elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    $features = @(Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object { "$($_.State)" -eq 'Enabled' } | ForEach-Object { $_.FeatureName })
}
$fHits = 0
foreach ($f in $features) {
    if (-not $featureNotes.ContainsKey($f)) { continue }
    $fHits++
    $row = Add-Row -Source 'Windows feature' -Name "Windows feature: $f"
    $row.Category = 'Outdated'; $row.Level = 'YELLOW'; $row.Decision = 'REMOVE if no scored service needs it'; $row.Reason = $featureNotes[$f]
    $row.Uninstall = "Uninstall-WindowsFeature $f   (client: Disable-WindowsOptionalFeature -Online -FeatureName $f)"
}
if ($fHits -eq 0) { Write-Finding -Level GREEN -Category 'Feature' -Message 'No rarely-needed Windows features are installed (or the feature cmdlets are unavailable).' }

# ---------------------------------------------------------------------------
Write-Section 'Remote-access listening ports'
# ---------------------------------------------------------------------------
$remotePorts = @{ 5800 = 'VNC web viewer'; 5900 = 'VNC'; 5901 = 'VNC'; 5938 = 'TeamViewer'; 7070 = 'AnyDesk'; 6568 = 'AnyDesk'; 4899 = 'Radmin'; 5650 = 'pcAnywhere / Remote Utilities'
                  21115 = 'RustDesk'; 21116 = 'RustDesk'; 8040 = 'ScreenConnect'; 8041 = 'ScreenConnect'; 4040 = 'ngrok local API'; 23 = 'Telnet'; 4444 = 'common reverse-shell port'; 1080 = 'SOCKS proxy' }
$pHits = 0
foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique)) {
    $port = [int]$c.LocalPort
    if (-not $remotePorts.ContainsKey($port) -or $scoredPorts -contains $port) { continue }
    $pHits++
    $pn = try { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { "pid$($c.OwningProcess)" }
    Write-Finding -Level RED -Category 'Port' -Message ("TCP {0} is listening: {1} (process {2})" -f $port, $remotePorts[$port], $pn) -Detail 'If it is VNC: does it ask for a password? Test from another box before Red Team does.'
}
if ($pHits -eq 0) { Write-Finding -Level GREEN -Category 'Port' -Message 'No well-known remote-access ports are listening.' }

# ---------------------------------------------------------------------------
Write-Section 'Findings'
# ---------------------------------------------------------------------------
$order = @{ RemoteAccess = 0; AttackTool = 1; Junk = 2; Outdated = 3; Other = 4 }
$sorted = @($rows | Sort-Object @{ Expression = { $order[$_.Category] } }, Name)
$flagged = @($sorted | Where-Object { $_.Category -ne 'Other' })
foreach ($r in $sorted) {
    if ($r.Category -eq 'Other' -and -not $ShowAll) { continue }
    $detail = "{0}; decision: {1}" -f $r.Source, $r.Decision
    if ($r.Reason)    { $detail += " ($($r.Reason))" }
    if ($r.Location)  { $detail += "`npath: $($r.Location)" }
    if ($r.Uninstall -and $r.Category -ne 'Other') { $detail += "`nremove: $($r.Uninstall)" }
    Write-Finding -Level $r.Level -Category $r.Category -Message ("{0,-13} {1} {2}" -f $r.Category, $r.Name, $r.Version) -Detail $detail
}
if ($flagged.Count -eq 0) { Write-Finding -Level GREEN -Category 'Software' -Message 'Nothing matched the remote-access, attack-tool, junk or outdated lists.' }

# The inject table: one row per item with the decision column, written next to -OutFile (or to reports\).
$tablePath = if ($OutFile) { $OutFile -replace '\.[^.\\]+$', '' } else { 'C:\ccdc\reports\software_{0}_{1}' -f $env:COMPUTERNAME, $script:CcdcStamp }
$tablePath = "${tablePath}_inventory.csv"
try {
    $dir = Split-Path -Parent $tablePath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $sorted | Select-Object Host, Category, Name, Version, Publisher, Installed, Source, Location, Decision, Reason | Export-Csv -Path $tablePath -NoTypeInformation -Encoding UTF8
    Write-Finding -Level INFO -Category 'Inject' -Message "Inventory table for the software / remote-access audit injects: $tablePath" -Detail 'Fill the Reason column in your own words (business purpose for anything kept). One file per host; combine them for the response.'
} catch { Write-Finding -Level YELLOW -Category 'Inject' -Message "Could not write the inventory table: $($_.Exception.Message)" }
Complete-Ccdc
