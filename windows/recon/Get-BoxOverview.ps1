<#
.SYNOPSIS
    Get-BoxOverview - "What is this box?" in one screen. READ-ONLY.

.DESCRIPTION
    PURPOSE
      First thing you run on an unfamiliar Windows box. Answers: what OS, what
      role in the domain, what IPs, what is listening and which process owns
      it, which roles/features are installed, which services run, which
      patches are installed, and which listeners are probably SCORED.

    WHAT IT READS
      WMI/CIM (Win32_OperatingSystem, Win32_ComputerSystem, Win32_Service),
      Get-NetIPAddress, Get-NetTCPConnection / Get-NetUDPEndpoint (fallback:
      netstat -ano), Get-WindowsFeature (servers), Get-HotFix, and the
      toolkit config (config\ccdc.json) for expected scored ports.

    WHAT IT CHANGES
      Nothing. Writes only its own log in C:\ccdc\logs\ and the optional
      -OutFile report.

    HOW TO UNDO
      Nothing to undo.

    MANUAL EQUIVALENT (show these to students first)
      hostname ; systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Domain"
      ipconfig /all
      netstat -ano | findstr LISTENING        then: tasklist /FI "PID eq <pid>"
      Get-WindowsFeature | Where-Object Installed
      Get-Service | Where-Object Status -eq Running
      Get-HotFix | Sort-Object InstalledOn

.PARAMETER OutFile
    Optional report path (.csv for CSV, anything else for text).

.PARAMETER ConfigPath
    Optional path to a toolkit config JSON (defaults to config\ccdc.json, then the example).

.EXAMPLE
    .\Get-BoxOverview.ps1
.EXAMPLE
    .\Get-BoxOverview.ps1 -OutFile C:\ccdc\reports\overview.txt
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Get-BoxOverview' -OutFile $OutFile -ReadOnly
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config

# Ports -> friendly name. Used to guess what a listener is and whether it is
# probably scored. Ports in the config's scoredPorts always win.
$wellKnown = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'; 88 = 'Kerberos'
    110 = 'POP3'; 465 = 'SMTPS'; 995 = 'POP3S'; 1194 = 'OpenVPN'; 2049 = 'NFS'; 5800 = 'VNC (web)'; 5900 = 'VNC'; 5901 = 'VNC :1'
    8000 = 'HTTP alt'; 8888 = 'HTTP alt'; 135 = 'RPC endpoint mapper'; 139 = 'NetBIOS session'; 143 = 'IMAP'
    389 = 'LDAP'; 443 = 'HTTPS'; 445 = 'SMB'; 464 = 'Kerberos kpasswd'; 587 = 'SMTP submission'
    636 = 'LDAPS'; 993 = 'IMAPS'; 1433 = 'MSSQL'; 3268 = 'Global Catalog'; 3269 = 'Global Catalog SSL'
    3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'PostgreSQL'; 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS'
    8080 = 'HTTP alt'; 8443 = 'HTTPS alt'; 9389 = 'AD Web Services'
}
# Ports commonly used by the scoring engine in CCDC-style events.
$commonlyScored = @(21, 22, 23, 25, 53, 80, 88, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1194, 1433, 2049, 3306, 3389, 5432, 5900, 5901, 8000, 8080, 8443)
$scoredFromConfig = @()
if ($hostCfg) { $scoredFromConfig = @($hostCfg.scoredPorts.tcp) }

# ---------------------------------------------------------------------------
Write-Section 'Identity'
# ---------------------------------------------------------------------------
$os = Get-WmiObject Win32_OperatingSystem
$cs = Get-WmiObject Win32_ComputerSystem
$roleNames = @{ 0 = 'Standalone workstation'; 1 = 'Member workstation'; 2 = 'Standalone server'
                3 = 'Member server'; 4 = 'Backup domain controller'; 5 = 'Primary domain controller' }
Write-Finding -Level INFO -Category 'Identity' -Message ("Hostname : {0}" -f $env:COMPUTERNAME)
Write-Finding -Level INFO -Category 'Identity' -Message ("OS       : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Finding -Level INFO -Category 'Identity' -Message ("Domain   : {0}   Role: {1}" -f $cs.Domain, $roleNames[[int]$cs.DomainRole])
Write-Finding -Level INFO -Category 'Identity' -Message ("Booted   : {0}" -f $os.ConvertToDateTime($os.LastBootUpTime))
Write-Finding -Level INFO -Category 'Identity' -Message ("PowerShell: {0}" -f $PSVersionTable.PSVersion)
if ($hostCfg) {
    Write-Finding -Level GREEN -Category 'Identity' -Message ("Config match: '{0}' - {1}" -f $hostCfg.name, $hostCfg.role)
} else {
    Write-Finding -Level YELLOW -Category 'Identity' -Message 'Hostname not found in toolkit config - scored-port guesses are generic.'
}

# ---------------------------------------------------------------------------
Write-Section 'IP addresses'
# ---------------------------------------------------------------------------
$ips = Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|::1|fe80)' }
if ($ips) {
    foreach ($ip in $ips) {
        Write-Finding -Level INFO -Category 'Network' -Message ("{0,-28} {1}/{2}" -f $ip.InterfaceAlias, $ip.IPAddress, $ip.PrefixLength)
    }
} else {
    # Very old boxes: fall back to WMI.
    Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
        Write-Finding -Level INFO -Category 'Network' -Message ("{0}  {1}" -f $_.Description, ($_.IPAddress -join ', '))
    }
}
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object ServerAddresses
foreach ($d in $dns) { Write-Finding -Level INFO -Category 'Network' -Message ("DNS servers ({0}): {1}" -f $d.InterfaceAlias, ($d.ServerAddresses -join ', ')) }

# ---------------------------------------------------------------------------
Write-Section 'Listening ports -> process'
# ---------------------------------------------------------------------------
# Build PID -> process name/path once (faster than calling Get-Process per port).
$procs = @{}
Get-WmiObject Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
# Services hosted in svchost share a PID, so map PID -> service names too.
$svcByPid = @{}
Get-WmiObject Win32_Service -Filter "State='Running'" | ForEach-Object {
    $k = [int]$_.ProcessId
    if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
    $svcByPid[$k] += $_.Name
}

$listeners = @()
$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
if ($tcp) {
    foreach ($c in $tcp) { $listeners += [pscustomobject]@{ Proto = 'TCP'; Address = $c.LocalAddress; Port = [int]$c.LocalPort; PID = [int]$c.OwningProcess } }
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $listeners += [pscustomobject]@{ Proto = 'UDP'; Address = $u.LocalAddress; Port = [int]$u.LocalPort; PID = [int]$u.OwningProcess }
    }
} else {
    # Fallback for boxes without the NetTCPIP module: parse netstat -ano.
    foreach ($line in (netstat -ano | Select-String 'LISTENING')) {
        $parts = ($line.ToString().Trim() -split '\s+')
        $addr  = $parts[1]; $port = [int]($addr.Substring($addr.LastIndexOf(':') + 1))
        $listeners += [pscustomobject]@{ Proto = 'TCP'; Address = $addr; Port = $port; PID = [int]$parts[-1] }
    }
}

# De-duplicate IPv4/IPv6 twins of the same listener, ignore UDP ephemeral noise above 49152.
$listeners = $listeners | Where-Object { -not ($_.Proto -eq 'UDP' -and $_.Port -ge 49152) } |
    Sort-Object Proto, Port, PID -Unique

$likelyScored = @()
foreach ($l in $listeners) {
    $p    = $procs[$l.PID]
    $name = if ($p) { $p.Name } else { '?' }
    $path = if ($p -and $p.ExecutablePath) { $p.ExecutablePath } else { '' }
    $svc  = if ($svcByPid.ContainsKey($l.PID)) { ($svcByPid[$l.PID] -join ',') } else { '' }
    $what = if ($wellKnown.ContainsKey($l.Port)) { $wellKnown[$l.Port] } else { '' }
    $msg  = '{0} {1,-5} {2,-15} pid {3,-6} {4,-18} {5} {6}' -f $l.Proto, $l.Port, $l.Address, $l.PID, $name, $what, $(if ($svc) { "[svc: $svc]" })

    $level = 'INFO'
    # A listener whose binary lives in a user-writable place is suspicious.
    if ($path -match '\\(Users|Temp|ProgramData|Windows\\Temp|AppData|Public)\\') { $level = 'RED' }
    elseif ($l.Proto -eq 'TCP' -and $l.Port -lt 49152 -and -not $what -and $l.Address -notmatch '^(127\.|::1)') { $level = 'YELLOW' }
    Write-Finding -Level $level -Category 'Listener' -Message $msg -Detail $path

    if ($l.Proto -eq 'TCP' -and ($scoredFromConfig -contains $l.Port -or $commonlyScored -contains $l.Port) -and $l.Address -notmatch '^(127\.|::1)') {
        $likelyScored += ('{0}/{1}' -f $l.Port, $(if ($what) { $what } else { $name }))
    }
}

# ---------------------------------------------------------------------------
Write-Section 'Likely scored services'
# ---------------------------------------------------------------------------
$likelyScored = $likelyScored | Sort-Object -Unique
if ($likelyScored) { Write-Finding -Level GREEN -Category 'Scored' -Message ('Listening now: {0}' -f ($likelyScored -join ', ')) }
foreach ($port in $scoredFromConfig) {
    if (-not ($listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -eq [int]$port })) {
        Write-Finding -Level RED -Category 'Scored' -Message ("Config says TCP $port is scored on this box but NOTHING is listening") -Detail 'Check the service is running before anything else.'
    }
}
if ($hostCfg -and $hostCfg.scoredServices) {
    Write-Finding -Level INFO -Category 'Scored' -Message ('Config scored services: {0}' -f ($hostCfg.scoredServices -join ', '))
}

# ---------------------------------------------------------------------------
Write-Section 'Installed roles / features'
# ---------------------------------------------------------------------------
if (Test-CcdcModule ServerManager) {
    # Server SKU: Get-WindowsFeature lists AD-Domain-Services, DNS, Web-Server, etc.
    $features = Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' }
    foreach ($f in $features) { Write-Finding -Level INFO -Category 'Role' -Message ("{0} ({1})" -f $f.DisplayName, $f.Name) }
    foreach ($bad in @('Telnet-Server', 'FS-SMB1', 'Web-Ftp-Server', 'Telnet-Client', 'TFTP-Client')) {
        if (Get-WindowsFeature -Name $bad -ErrorAction SilentlyContinue | Where-Object Installed) {
            Write-Finding -Level YELLOW -Category 'Role' -Message "Risky feature installed: $bad"
        }
    }
} else {
    Write-Finding -Level INFO -Category 'Role' -Message 'Client OS (no ServerManager). Optional features: run "Get-WindowsOptionalFeature -Online | ? State -eq Enabled" if needed (slow).'
}

# ---------------------------------------------------------------------------
Write-Section 'Running services (non-Microsoft binaries highlighted)'
# ---------------------------------------------------------------------------
foreach ($s in (Get-WmiObject Win32_Service -Filter "State='Running'" | Sort-Object Name)) {
    $path = [string]$s.PathName
    # Anything not under Windows\ or Program Files is worth a look.
    $level = if ($path -and $path -notmatch '(?i)\\Windows\\|\\Program Files( \(x86\))?\\') { 'YELLOW' } else { 'INFO' }
    if ($level -eq 'INFO' -and $s.Name -notmatch '^(W3SVC|DNS|NTDS|MSSQL|MySQL|sshd|TermService|WinRM|Kdc|Netlogon|IISADMIN|WAS|DFSR|LanmanServer)$') { continue } # keep the list short
    Write-Finding -Level $level -Category 'Service' -Message ("{0,-28} {1}" -f $s.Name, $s.DisplayName) -Detail $path
}
Write-Finding -Level INFO -Category 'Service' -Message ('Total running services: {0} (full list: Get-Service | ? Status -eq Running)' -f @(Get-Service | Where-Object Status -eq 'Running').Count)

# ---------------------------------------------------------------------------
Write-Section 'Hotfixes'
# ---------------------------------------------------------------------------
# InstalledOn is already a [datetime] (or $null) on Get-HotFix output.
$hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn
if ($hf) {
    $latest = $hf | Select-Object -Last 1
    Write-Finding -Level INFO -Category 'Patch' -Message ('{0} hotfixes installed. Most recent: {1} on {2}' -f @($hf).Count, $latest.HotFixID, $latest.InstalledOn)
    Write-Finding -Level INFO -Category 'Patch' -Message ('IDs: {0}' -f (($hf | ForEach-Object HotFixID) -join ' '))
    if ($latest.InstalledOn -and ([datetime]$latest.InstalledOn) -lt (Get-Date).AddDays(-365)) {
        Write-Finding -Level YELLOW -Category 'Patch' -Message 'No patches in over a year - assume known exploits work (see audit\Audit-Vulns.ps1).'
    }
} else {
    Write-Finding -Level YELLOW -Category 'Patch' -Message 'No hotfixes reported (or Get-HotFix failed).'
}

Complete-Ccdc
