<#
.SYNOPSIS
    Test-ScoredServices - "is every scored service still up, and if not, WHY?" READ-ONLY.

.DESCRIPTION
    PURPOSE
      SLA penalties cost this team more than Red Team did at both scored
      events. A service that fails 5 checks in a row is an SLA violation, and
      with one-minute checks that is five minutes. This script walks the same
      ladder the scoring engine depends on, for every scored port on THIS box,
      and names the rung that is broken:

        1. Is anything listening on the port?  On the right address (not only 127.0.0.1)?
        2. Is the Windows service behind it running, and will it start after a reboot?
        3. Does a TCP connection to this box's own IP succeed?
        4. Does the firewall allow it? Is there a BLOCK rule covering it (block beats allow)?
        5. Does the service ANSWER correctly?
             HTTP   status code, page title, defacement words, "database error" pages
             DNS    the server answers, and the zone still has every record it had at baseline
             LDAP   RootDSE bind                SMB   every baseline share still exists
             RDP    connections not denied      SSH   sshd config valid, passwords allowed, AllowUsers
        6. Scored ACCOUNTS: still enabled, not locked, password unchanged since baseline
           (a changed password without a Password Change Request = failed check).
        7. Quiet sabotage that makes a healthy service look "flaky": hosts file entries,
           port proxies, IPsec rules, outbound default-block, clock drift, DC not found,
           full disk.

      First run saves a BASELINE of what "correct" looks like (page titles, DNS
      records, shares, account password dates). Run it right after you have
      confirmed the scoreboard is green. Later runs compare against it.

    WHAT IT READS    listeners, services, firewall rules (registry), local HTTP/DNS/LDAP
                     answers, DNS zones, shares, account flags, hosts file
    WHAT IT CHANGES  nothing on the system. Writes C:\ccdc\baseline\scored_<HOST>.json
                     and, on state changes, a row in C:\ccdc\alerts\alerts_<HOST>.csv.
    HOW TO UNDO      delete the baseline file to start over (or -SaveBaseline).

    LIMITS
      It tests from the box itself. It cannot see the router / NAT or what the
      scoring engine sees from 10.100.x.x. Green here + red on the scoreboard
      means: router rule, 1:1 NAT, or the scored account's password.

    MANUAL EQUIVALENT
      netstat -ano | findstr LISTENING ; Get-Service W3SVC,DNS,sshd,TermService
      Test-NetConnection <ip> -Port 80 ; Get-NetFirewallRule -Action Block -Enabled True -Direction Inbound
      Invoke-WebRequest http://<ip>/ -UseBasicParsing ; Resolve-DnsName <name> -Server <ip>
      type C:\Windows\System32\drivers\etc\hosts ; netsh interface portproxy show all

.PARAMETER Tcp
    TCP ports to test. Default: this host's scoredPorts.tcp from the config, else well-known ports that are listening.

.PARAMETER Udp
    UDP ports to test (listening check only). Default: scoredPorts.udp from the config.

.PARAMETER Url
    Extra URLs to fetch (e.g. http://192.168.220.20:8080/wiki/). HTTP ports are fetched at "/" automatically.

.PARAMETER DnsName
    Extra names to resolve against this server.

.PARAMETER Loop
    Repeat every -IntervalSeconds, printing one status line per pass and full detail only when something changes.

.PARAMETER SaveBaseline
    Replace the baseline with the current state (do this only while the scoreboard is green).

.EXAMPLE
    .\Test-ScoredServices.ps1
.EXAMPLE
    .\Test-ScoredServices.ps1 -Loop -IntervalSeconds 60 -Beep
.EXAMPLE
    .\Test-ScoredServices.ps1 -Tcp 80,443,3389 -Url http://192.168.220.20:8000/ -SaveBaseline
#>
[CmdletBinding()]
param(
    [int[]]$Tcp = @(),
    [int[]]$Udp = @(),
    [string[]]$Url = @(),
    [string[]]$DnsName = @(),
    [switch]$Loop,
    [ValidateRange(10, 3600)][int]$IntervalSeconds = 60,
    [switch]$SaveBaseline,
    [switch]$Beep,
    [string]$BaselineDir = 'C:\ccdc\baseline',
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Test-ScoredServices' -OutFile $OutFile -ReadOnly
$config  = Get-CcdcConfig -Path $ConfigPath
$hostCfg = Get-CcdcHostConfig -Config $config
$isDC    = Test-CcdcIsDC
$role    = Get-CcdcDomainRole
$domainFqdn = ''
try { $cs = Get-WmiObject Win32_ComputerSystem; if ($cs.PartOfDomain) { $domainFqdn = [string]$cs.Domain } } catch { $null = $_ }

# This box's main IPv4 address: tests go to it, not to 127.0.0.1, because a
# service that was re-bound to localhost passes a loopback test and fails scoring.
$myIp = ''
if ($hostCfg -and $hostCfg.ip) { $myIp = [string]$hostCfg.ip }
$nicIps = @(Get-CcdcLocalIps | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^(127\.|169\.254\.)' })
if (-not $myIp -or $nicIps -notcontains $myIp) {
    if ($myIp -and $nicIps.Count -gt 0) { Write-Finding -Level YELLOW -Category 'Setup' -Message "Config says this host is $myIp but the NICs have: $($nicIps -join ', '). Using the NIC address." }
    $myIp = [string]($nicIps | Select-Object -First 1)
}
if (-not $myIp) { $myIp = '127.0.0.1'; Write-Finding -Level YELLOW -Category 'Setup' -Message 'No non-loopback IPv4 address found: testing against 127.0.0.1 only.' }

$wellKnown = @(21, 22, 23, 25, 53, 80, 88, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1194, 1433, 2049, 3306, 3389, 5432, 5800, 5900, 5901, 5985, 8000, 8080, 8443, 8888)
if ($Tcp.Count -eq 0 -and $hostCfg) { $Tcp = @($hostCfg.scoredPorts.tcp | Where-Object { $_ } | ForEach-Object { [int]$_ }) }
if ($Udp.Count -eq 0 -and $hostCfg) { $Udp = @($hostCfg.scoredPorts.udp | Where-Object { $_ } | ForEach-Object { [int]$_ }) }
if ($Tcp.Count -eq 0) {
    $Tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $wellKnown -contains [int]$_.LocalPort } | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique)
    Write-Finding -Level YELLOW -Category 'Setup' -Message ("This host is not in the config and no -Tcp given: GUESSING from what is listening now: {0}" -f ($Tcp -join ', ')) -Detail 'A service that is already down will be missed. Put the real scored ports in config\ccdc.json or pass -Tcp.'
}
$scoredAccounts = @(); if ($hostCfg) { $scoredAccounts = @($hostCfg.scoredAccounts | Where-Object { $_ }) }
$httpPorts = @(80, 443, 8000, 8008, 8080, 8443, 8888)

# Port -> the Windows services that normally own it (first one installed wins).
$svcMap = @{
    21 = @('ftpsvc', 'FileZilla Server', 'Wing FTP Server'); 22 = @('sshd'); 25 = @('SMTPSVC', 'MSExchangeFrontEndTransport', 'hMailServer')
    53 = @('DNS'); 80 = @('W3SVC', 'Apache2.4', 'nginx'); 443 = @('W3SVC', 'Apache2.4', 'nginx'); 88 = @('kdc'); 389 = @('NTDS'); 636 = @('NTDS')
    445 = @('LanmanServer'); 1433 = @('MSSQLSERVER', 'MSSQL$SQLEXPRESS'); 3306 = @('MySQL', 'MySQL80', 'MariaDB'); 3389 = @('TermService'); 5985 = @('WinRM'); 5986 = @('WinRM')
    110 = @('hMailServer', 'MSExchangePop3'); 143 = @('hMailServer', 'MSExchangeImap4'); 5432 = @('postgresql*')
    23 = @('TlntSvr'); 1194 = @('OpenVPNService', 'OpenVPNServiceInteractive', 'OpenVPNAccessServer'); 2049 = @('NfsService')
    5900 = @('tvnserver', 'uvnc_service', 'vncserver', 'TigerVNC'); 5901 = @('tvnserver', 'uvnc_service', 'vncserver', 'TigerVNC'); 5800 = @('tvnserver', 'uvnc_service')
    8080 = @('W3SVC', 'Apache2.4', 'nginx', 'Tomcat*'); 8443 = @('W3SVC', 'Apache2.4', 'nginx', 'Tomcat*')
}

if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
$baselineFile = Join-Path $BaselineDir ("scored_{0}.json" -f $env:COMPUTERNAME)
$baseline = $null
if ((Test-Path $baselineFile) -and -not $SaveBaseline) {
    try { $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json } catch { Write-Finding -Level YELLOW -Category 'Setup' -Message "Baseline file unreadable, taking a new one: $_" }
}

# Accept any certificate: we are testing our own self-signed sites, not trusting them.
# (A compiled callback is used because a PowerShell scriptblock callback can fail on .NET worker threads.)
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12, Tls11, Tls' } catch { $null = $_ }
try {
    if (-not ('CcdcTrustAllCerts' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CcdcTrustAllCerts {
    public static bool Accept(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) { return true; }
    public static void Enable() { ServicePointManager.ServerCertificateValidationCallback = Accept; }
}
'@
    }
    [CcdcTrustAllCerts]::Enable()
} catch {
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch { $null = $_ }
}

# ---------------------------------------------------------------------------
# Results: key -> state. UP / WARN / DOWN. Loop mode reports transitions.
# ---------------------------------------------------------------------------
$script:results = [ordered]@{}
$script:current = @{}     # facts for the baseline
function Set-Result([string]$Key, [string]$State, [string]$Message, [string]$Detail = '') {
    # A key keeps its worst state within one pass (DOWN > WARN > UP).
    $rank = @{ UP = 0; WARN = 1; DOWN = 2 }
    if ($script:results.Contains($Key)) {
        $old = $script:results[$Key]
        if ($rank[$State] -lt $rank[$old.State]) { return }
        if ($rank[$State] -eq $rank[$old.State]) { $old.Message = "$($old.Message); $Message"; if ($Detail) { $old.Detail = (@($old.Detail, $Detail) | Where-Object { $_ }) -join "`n" }; return }
    }
    $script:results[$Key] = [pscustomobject]@{ Key = $Key; State = $State; Message = $Message; Detail = $Detail }
}

function Get-BaseValue([string]$section, [string]$name) {
    # Reads baseline.<section>.<name> without throwing when either is missing.
    if (-not $baseline) { return $null }
    $sec = $baseline.$section
    if ($null -eq $sec) { return $null }
    $p = $sec.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------
# Firewall rules straight from the registry: fast, and works without the
# NetSecurity cmdlets. Each value looks like:
#   v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=evil|
# ---------------------------------------------------------------------------
function Get-FwRules {
    $rules = @()
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
                     'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules')) {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $r = @{ Id = $p.Name; LPort = @(); RA = @(); Source = $(if ($k -match 'Policies') { 'GPO' } else { 'local' }) }
            foreach ($part in ([string]$p.Value -split '\|')) {
                $kv = $part -split '=', 2
                if ($kv.Count -ne 2) { continue }
                switch -Regex ($kv[0]) {
                    '^LPort(2_\d+)?$' { $r.LPort += $kv[1] }
                    '^RA(4|6|42|62)$' { $r.RA += $kv[1] }
                    default           { $r[$kv[0]] = $kv[1] }
                }
            }
            if ($r.Active -ne 'TRUE' -or $r.Dir -ne 'In') { continue }
            $rules += [pscustomobject]$r
        }
    }
    return $rules
}

function Test-FwRuleCoversPort($rule, [int]$port, [int]$protoNumber) {
    if ($rule.Protocol -and [string]$rule.Protocol -ne [string]$protoNumber) { return $false }
    if (@($rule.LPort).Count -eq 0) {
        # No port listed = every port, unless the rule is tied to one program / service
        # (most built-in Windows rules are), which we cannot match to a port from here.
        return (-not ($rule.App -or $rule.Svc))
    }
    foreach ($lp in $rule.LPort) {
        if ($lp -match '^(\d+)-(\d+)$') { if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { return $true } }
        elseif ($lp -match '^\d+$')     { if ([int]$lp -eq $port) { return $true } }
        elseif ($lp -eq 'RPC' -or $lp -eq 'RPC-EPMap' -or $lp -eq 'IPHTTPS') { continue }
    }
    return $false
}

function Test-Firewall([string]$key, [int]$port, [int]$protoNumber, $rules, $profiles) {
    $block = @($rules | Where-Object { $_.Action -eq 'Block' -and (Test-FwRuleCoversPort $_ $port $protoNumber) })
    $allow = @($rules | Where-Object { $_.Action -eq 'Allow' -and (Test-FwRuleCoversPort $_ $port $protoNumber) })
    foreach ($b in $block) {
        $scope = if (@($b.RA).Count -gt 0) { "from $(@($b.RA) -join ',')" } else { 'from ANY address' }
        # A block rule limited to some addresses is how "70% of packets dropped" style sabotage looks on Windows.
        Set-Result $key 'DOWN' ("firewall BLOCK rule '{0}' covers this port ({1})" -f $b.Name, $scope) ("Block rules beat allow rules. Remove: Remove-NetFirewallRule -Name '{0}'   (rule source: {1})" -f $b.Id, $b.Source)
    }
    $open = @($allow | Where-Object { @($_.RA).Count -eq 0 })
    if ($allow.Count -gt 0 -and $open.Count -eq 0 -and $block.Count -eq 0) {
        Set-Result $key 'WARN' ("firewall allows this port only from: {0}" -f ((@($allow | ForEach-Object { $_.RA }) | Sort-Object -Unique | Select-Object -First 6) -join ', ')) 'If the scoring engine is not inside those ranges the check fails. Scored ports should be open to any source.'
    }
    $on = @($profiles | Where-Object { $_.Enabled })
    $denyDefault = @($on | Where-Object { "$($_.DefaultInboundAction)" -ne 'Allow' })
    if ($on.Count -gt 0 -and $denyDefault.Count -gt 0 -and $allow.Count -eq 0) {
        Set-Result $key 'DOWN' 'firewall is on, default-deny inbound, and NO allow rule covers this port' ("Fix: New-NetFirewallRule -DisplayName 'CCDC scored {0}' -Direction Inbound -Protocol {1} -LocalPort {0} -Action Allow" -f $port, $(if ($protoNumber -eq 6) { 'TCP' } else { 'UDP' }))
    }
}

function Get-OwningServices([int]$procId) {
    if ($procId -le 4) { return @() }
    return @(Get-WmiObject Win32_Service -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue)
}

function Test-TcpConnect([string]$ip, [int]$port, [int]$timeoutMs = 2000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ip, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $client.Connected
    } catch { return $false } finally { $client.Close() }
}

# ---------------------------------------------------------------------------
# Rungs 1-4 for one TCP port
# ---------------------------------------------------------------------------
function Test-ScoredTcpPort([int]$port, $rules, $profiles, $procNames) {
    $key = "tcp/$port"
    $listen = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
    if ($listen.Count -eq 0) {
        $hint = 'Find what should own it: Get-Service | ? Status -ne Running'
        foreach ($name in @($svcMap[$port])) {
            if (-not $name) { continue }
            $svc = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $name } | Select-Object -First 1
            if ($svc) { $hint = "Service '$($svc.Name)' is $($svc.State), start mode $($svc.StartMode).  Fix: Set-Service '$($svc.Name)' -StartupType Automatic; Start-Service '$($svc.Name)'"; break }
        }
        Set-Result $key 'DOWN' 'NOTHING is listening on this port' $hint
        return
    }
    $addrs = @($listen | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
    $reachable = @($addrs | Where-Object { $_ -in '0.0.0.0', '::', $myIp })
    $procId = [int]($listen | Select-Object -First 1).OwningProcess
    $procName = if ($procId -eq 4) { 'System (HTTP.sys / IIS or SMB)' } else { [string]$procNames[$procId] }
    if ($reachable.Count -eq 0) {
        Set-Result $key 'DOWN' ("listening ONLY on {0}, not on {1}: the listening address was changed" -f ($addrs -join ','), $myIp) "Owner: $procName (PID $procId). Check the service's bind / listen address setting."
    } else {
        Set-Result $key 'UP' ("listening on {0} ({1})" -f ($addrs -join ','), $procName)
    }
    # Start-mode check. Several services can share one process (lsass.exe hosts NTDS, Kdc AND
    # KeyIso; svchost groups others), so only warn when NONE of the owners starts automatically.
    # Some services are Manual by design and are started by Windows itself (TermService, trigger-
    # start services): those are not a reboot risk.
    $owners = @(Get-OwningServices $procId)
    $onDemand = @('TermService', 'KeyIso', 'SessionEnv', 'UmRdpService', 'W32Time', 'Netlogon', 'Kdc', 'NTDS', 'DNS', 'LanmanServer')
    $auto = @($owners | Where-Object { $_.StartMode -eq 'Auto' -or $onDemand -contains $_.Name })
    if ($owners.Count -gt 0 -and $auto.Count -eq 0) {
        $svc = $owners[0]
        $trig = Test-Path ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}\TriggerInfo" -f $svc.Name)
        if (-not $trig -and $svc.StartMode -ne 'Auto') { Set-Result $key 'WARN' ("service '{0}' start mode is {1}: it will NOT come back after a reboot" -f $svc.Name, $svc.StartMode) "Fix: Set-Service '$($svc.Name)' -StartupType Automatic" }
    }
    foreach ($svc in $owners) {
        if ($svc.StartMode -eq 'Disabled') { Set-Result $key 'WARN' ("service '{0}' is DISABLED but owns this port: it will not start again" -f $svc.Name) "Fix: Set-Service '$($svc.Name)' -StartupType Automatic" }
    }
    if ($reachable.Count -gt 0 -and -not (Test-TcpConnect $myIp $port)) {
        Set-Result $key 'DOWN' "TCP connect to ${myIp}:$port failed although something is listening" 'Usually the host firewall, an IPsec rule, or the process is hung. Restart the service if the firewall is clean.'
    }
    Test-Firewall $key $port 6 $rules $profiles
}

# ---------------------------------------------------------------------------
# Rung 5: protocol checks
# ---------------------------------------------------------------------------
$defaceRegex = '(?i)(hacked\s+by|pwn(e)?d|owned\s+by|defaced|red\s*team\s+was\s+here|you\s+have\s+been\s+hacked|h4ck|greetz)'
$dbErrorRegex = '(?i)(error establishing a database connection|database connection (failed|error)|sqlstate\[|could not connect to (the )?database|access denied for user|unknown database|mysqli?_connect|(db|database) error)'

function Test-Http([string]$u) {
    $key = "http $u"
    $status = 0; $body = ''; $err = ''
    try {
        $req = [System.Net.WebRequest]::Create($u)
        $req.Timeout = 8000; $req.AllowAutoRedirect = $true; $req.UserAgent = 'Mozilla/5.0 (service check)'
        try { $resp = $req.GetResponse() } catch {
            # A 404 / 500 arrives as an exception that still carries the response.
            $we = $_.Exception
            while ($we -and $we -isnot [System.Net.WebException]) { $we = $we.InnerException }
            if (-not $we -or -not $we.Response) { throw }
            $resp = $we.Response
        }
        $status = [int]$resp.StatusCode
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $buf = New-Object char[] 200000
        $n = $reader.ReadBlock($buf, 0, $buf.Length)      # first 200 KB is plenty for a title and error text
        if ($n -gt 0) { $body = -join $buf[0..($n - 1)] }
        $reader.Close(); $resp.Close()
    } catch { $err = $_.Exception.Message; if ($_.Exception.InnerException) { $err = $_.Exception.InnerException.Message } }

    if ($err) { Set-Result $key 'DOWN' "no HTTP answer: $err"; return }
    $title = ''
    if ($body -match '(?is)<title[^>]*>(.*?)</title>') { $title = ($Matches[1] -replace '\s+', ' ').Trim() }
    if ($title.Length -gt 100) { $title = $title.Substring(0, 100) }
    $script:current.http[$u] = @{ status = $status; title = $title; length = $body.Length }
    $base = Get-BaseValue 'http' $u

    if ($status -ge 500) { Set-Result $key 'DOWN' "HTTP $status (server error)" 'Read the web server / PHP error log. For IIS: C:\inetpub\logs\LogFiles and the Application event log.' }
    elseif ($body -match $defaceRegex) { Set-Result $key 'DOWN' ("page contains defacement text: '{0}'" -f $Matches[0]) 'A defaced page fails a content check. Restore the web root from backup: services\IIS.ps1 -Action Restore' }
    elseif ($body -match $dbErrorRegex) { Set-Result $key 'DOWN' ("page shows a DATABASE error: '{0}'" -f $Matches[0]) 'Is the DB up and reachable? Log in by hand with the exact credentials in the app config (wp-config.php / LocalSettings.php).' }
    elseif ($base -and [int]$base.status -ne $status) { Set-Result $key $(if ($status -ge 400) { 'DOWN' } else { 'WARN' }) ("HTTP status changed: {0} at baseline, {1} now" -f $base.status, $status) }
    elseif ($base -and [string]$base.title -ne $title) { Set-Result $key 'WARN' ("page TITLE changed: '{0}' -> '{1}'" -f $base.title, $title) 'A default page or a replaced page fails a content check. If you changed it on purpose: -SaveBaseline' }
    elseif ($base -and [int]$base.length -gt 0 -and $body.Length -lt ([int]$base.length * 0.4)) { Set-Result $key 'WARN' ("page is much smaller than at baseline ({0} -> {1} chars)" -f $base.length, $body.Length) }
    elseif ($status -ge 400) { Set-Result $key 'WARN' "HTTP $status" 'The site may be bound to a host name, or need a path: pass the exact scored URL with -Url.' }
    else { Set-Result $key 'UP' ("HTTP {0} '{1}'" -f $status, $title) }
}

function Test-Dns {
    $key = 'dns'
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { return }
    $names = @($DnsName)
    if ($domainFqdn) { $names += $domainFqdn; if ($isDC) { $names += "_ldap._tcp.$domainFqdn" } }
    foreach ($n in ($names | Sort-Object -Unique)) {
        $type = if ($n -like '_*') { 'SRV' } else { 'A' }
        try {
            $ans = @(Resolve-DnsName -Name $n -Type $type -Server $myIp -DnsOnly -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' -or $_.QueryType -eq $type })
            $data = @($ans | ForEach-Object { if ($_.IPAddress) { $_.IPAddress } elseif ($_.NameTarget) { $_.NameTarget } else { $_.Name } } | Sort-Object -Unique)
            $script:current.dns[$n] = $data
            $base = Get-BaseValue 'dns' $n
            if ($data.Count -eq 0) { Set-Result $key 'DOWN' "DNS server answered but has NO $type record for $n" }
            elseif ($base -and (@($base) -join ',') -ne ($data -join ',')) { Set-Result $key 'DOWN' ("{0} now resolves to {1} (baseline: {2})" -f $n, ($data -join ','), (@($base) -join ',')) 'Records were changed. Restore: services\DNS.ps1 -Action Restore' }
            else { Set-Result $key 'UP' ("{0} -> {1}" -f $n, (($data | Select-Object -First 3) -join ',')) }
        } catch { Set-Result $key 'DOWN' "DNS query for $n against $myIp FAILED: $($_.Exception.Message)" 'Is the DNS service running and listening on this address? Get-Service DNS; dnscmd /info /listenaddresses' }
    }
    # Zone contents versus baseline: catches deleted / repointed records before the scoring engine does.
    if (Test-CcdcModule 'DnsServer') {
        try {
            $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })
            foreach ($z in $zones) {
                $recs = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction SilentlyContinue | Where-Object { $_.RecordType -in 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV' } | ForEach-Object {
                    $rd = $_.RecordData
                    $val = switch ($_.RecordType) { 'A' { "$($rd.IPv4Address)" } 'AAAA' { "$($rd.IPv6Address)" } 'CNAME' { $rd.HostNameAlias } 'MX' { $rd.MailExchange } 'NS' { $rd.NameServer } 'SRV' { "$($rd.DomainName):$($rd.Port)" } }
                    "{0}|{1}|{2}" -f $_.HostName, $_.RecordType, $val
                } | Sort-Object -Unique)
                $script:current.zones[$z.ZoneName] = $recs
            }
            if ($baseline -and $baseline.zones) {
                foreach ($bz in $baseline.zones.PSObject.Properties) {
                    if (-not $script:current.zones.ContainsKey($bz.Name)) { Set-Result $key 'DOWN' "DNS ZONE '$($bz.Name)' is GONE" 'Restore: services\DNS.ps1 -Action Restore'; continue }
                    $now = @($script:current.zones[$bz.Name])
                    $missing = @(@($bz.Value) | Where-Object { $now -notcontains $_ })
                    $added   = @($now | Where-Object { @($bz.Value) -notcontains $_ })
                    if ($missing.Count -gt 0) { Set-Result $key 'DOWN' ("zone {0}: {1} record(s) MISSING or changed since baseline" -f $bz.Name, $missing.Count) ((($missing | Select-Object -First 10) -join "`n") + "`nRestore: services\DNS.ps1 -Action Restore   (or accept: -SaveBaseline)") }
                    if ($added.Count -gt 0)   { Set-Result $key 'WARN' ("zone {0}: {1} NEW record(s) since baseline" -f $bz.Name, $added.Count) (($added | Select-Object -First 10) -join "`n") }
                }
            }
        } catch { Set-Result $key 'WARN' "could not read DNS zones: $($_.Exception.Message)" }
    }
}

function Test-Ldap {
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$myIp/RootDSE")
        $nc = [string]$root.Properties['defaultNamingContext'].Value
        if ($nc) { Set-Result 'ldap' 'UP' "RootDSE answered ($nc)" } else { Set-Result 'ldap' 'DOWN' 'LDAP answered but returned no naming context' }
    } catch { Set-Result 'ldap' 'DOWN' "LDAP bind to $myIp failed: $($_.Exception.Message)" 'Check: Get-Service NTDS,kdc,Netlogon ; dcdiag /q' }
}

function Test-Smb {
    $shares = @(Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Path)" } | Sort-Object)
    $script:current.shares = $shares
    $svc = Get-Service LanmanServer -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') { Set-Result 'smb' 'DOWN' "Server service (LanmanServer) is $($svc.Status)" 'Fix: Start-Service LanmanServer'; return }
    $missing = @()
    if ($baseline -and $baseline.shares) { $missing = @(@($baseline.shares) | Where-Object { $shares -notcontains $_ }) }
    if ($missing.Count -gt 0) { Set-Result 'smb' 'DOWN' ("share(s) GONE since baseline: {0}" -f ($missing -join ', ')) 'Restore: services\SMB_FileShares.ps1 -Action Restore' }
    else { Set-Result 'smb' 'UP' ("{0} shares present" -f $shares.Count) }
}

function Test-Rdp {
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    if ($ts -and $ts.fDenyTSConnections -eq 1) { Set-Result 'rdp' 'DOWN' 'Remote Desktop is DISABLED (fDenyTSConnections = 1)' "Fix: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0" }
    else { Set-Result 'rdp' 'UP' 'Remote Desktop connections allowed' }
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    if ($pol -and $pol.fDenyTSConnections -eq 1) { Set-Result 'rdp' 'DOWN' 'Remote Desktop is disabled BY POLICY (a GPO sets fDenyTSConnections = 1)' 'gpresult /h report.html, then fix or unlink that GPO.' }
}

function Test-Ssh {
    $sshd = "$env:windir\System32\OpenSSH\sshd.exe"
    if (-not (Test-Path $sshd)) { $sshd = "$env:ProgramFiles\OpenSSH\sshd.exe" }
    if (-not (Test-Path $sshd)) { return }
    # sshd -T prints the EFFECTIVE config (after includes and defaults); it also fails loudly on a broken config.
    $out = @(& $sshd -T 2>&1)
    if ($LASTEXITCODE -ne 0) { Set-Result 'ssh' 'DOWN' 'sshd_config is INVALID: sshd will not start / restart' ((($out | Select-Object -First 5) -join "`n") + "`nFile: C:\ProgramData\ssh\sshd_config  (restore: services\OpenSSH.ps1 -Action Restore)"); return }
    $cfg = @{}
    foreach ($line in $out) { $kv = "$line" -split '\s+', 2; if ($kv.Count -eq 2) { $cfg[$kv[0].ToLower()] = $kv[1] } }
    if ($cfg['passwordauthentication'] -eq 'no') { Set-Result 'ssh' 'DOWN' 'PasswordAuthentication is NO: a scoring check that logs in with a password will fail' 'Set "PasswordAuthentication yes" in C:\ProgramData\ssh\sshd_config, then Restart-Service sshd' }
    foreach ($opt in 'allowusers', 'allowgroups', 'denyusers', 'denygroups') {
        if (-not $cfg[$opt]) { continue }
        $lockedOut = @($scoredAccounts | Where-Object { $opt -eq 'allowusers' -and ($cfg[$opt] -split '\s+') -notcontains $_ })
        if ($lockedOut.Count -gt 0) { Set-Result 'ssh' 'DOWN' ("{0} = '{1}' does not include scored account(s) {2}" -f $opt, $cfg[$opt], ($lockedOut -join ',')) 'Red Team sets "AllowUsers nobody" to lock everyone out. Remove the line, Restart-Service sshd.' }
        else { Set-Result 'ssh' 'WARN' ("sshd restricts logins: {0} {1}" -f $opt, $cfg[$opt]) 'Make sure the account the scoring engine uses is still allowed.' }
    }
    if ($cfg['port'] -and $cfg['port'] -ne '22' -and $Tcp -contains 22) { Set-Result 'ssh' 'DOWN' "sshd is configured for port $($cfg['port']), not 22" }
    if (-not $script:results.Contains('ssh')) { Set-Result 'ssh' 'UP' 'sshd config valid, password logins allowed' }
}

# ---------------------------------------------------------------------------
# Rung 6: scored accounts
# ---------------------------------------------------------------------------
function Test-ScoredAccount([string]$name) {
    $key = "account $name"
    $pwdSet = ''; $disabled = $false; $locked = $false; $found = $false
    try {
        if ($isDC -or ($role -in 1, 3 -and $name -match '\\')) {
            $sam = ($name -split '\\')[-1]
            $s = New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=person)(sAMAccountName=$sam))")
            foreach ($p in 'userAccountControl', 'lockoutTime', 'pwdLastSet') { [void]$s.PropertiesToLoad.Add($p) }
            $r = $s.FindOne()
            if ($r) {
                $found = $true
                $disabled = [bool]([int]$r.Properties['useraccountcontrol'][0] -band 2)
                if ($r.Properties['lockouttime'].Count -gt 0) { $locked = ([int64]$r.Properties['lockouttime'][0] -gt 0) }
                if ($r.Properties['pwdlastset'].Count -gt 0) { $pwdSet = [datetime]::FromFileTime([int64]$r.Properties['pwdlastset'][0]).ToString('yyyy-MM-dd HH:mm') }
            }
        }
        if (-not $found -and -not $isDC) {
            $u = [ADSI]"WinNT://$env:COMPUTERNAME/$(($name -split '\\')[-1]),user"
            $flags = [int]$u.UserFlags.Value     # throws if the user does not exist
            $found = $true
            $disabled = [bool]($flags -band 0x2); $locked = [bool]($flags -band 0x10)
            $pwdSet = (Get-Date).AddSeconds(-[int]$u.PasswordAge.Value).ToString('yyyy-MM-dd HH:mm')
        }
    } catch { $null = $_ }
    if (-not $found) { Set-Result $key 'DOWN' 'scored account NOT FOUND (deleted or renamed?)' 'Check audit\Audit-Users.ps1 and the Security log (4726 deleted, 4781 renamed).'; return }
    $script:current.accounts[$name] = $pwdSet
    if ($disabled) { Set-Result $key 'DOWN' 'scored account is DISABLED' $(if ($isDC) { "Fix: Enable-ADAccount '$name'" } else { "Fix: net user `"$name`" /active:yes" }) }
    if ($locked)   { Set-Result $key 'DOWN' 'scored account is LOCKED OUT (someone is guessing its password)' $(if ($isDC) { "Fix: Unlock-ADAccount '$name'" } else { "Fix: net user `"$name`" /active:yes" }) }
    $base = Get-BaseValue 'accounts' $name
    if ($base -and $pwdSet) {
        # PasswordAge has one-minute resolution on local accounts: allow 2 minutes of slack.
        $delta = [math]::Abs(([datetime]$pwdSet - [datetime]$base).TotalMinutes)
        if ($delta -gt 2) { Set-Result $key 'DOWN' ("PASSWORD CHANGED at {0} (baseline: {1})" -f $pwdSet, $base) 'If WE changed it: was the Password Change Request filed? If not us: Red Team did. Reset it and file the PCR. Then -SaveBaseline.' }
    }
    if (-not $script:results.Contains($key)) { Set-Result $key 'UP' "enabled, not locked, password set $pwdSet" }
}

# ---------------------------------------------------------------------------
# Rung 7: quiet sabotage
# ---------------------------------------------------------------------------
function Test-Sabotage {
    # hosts file
    $hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
    $script:current.hosts = $hosts
    $baseHosts = @(); if ($baseline -and $baseline.hosts) { $baseHosts = @($baseline.hosts) }
    $newHosts = @($hosts | Where-Object { $baseHosts -notcontains $_ })
    if ($baseline -and $newHosts.Count -gt 0) { Set-Result 'sabotage hosts-file' 'DOWN' ("{0} NEW hosts file entr(ies): names now resolve somewhere else" -f $newHosts.Count) (($newHosts -join "`n") + "`nFile: C:\Windows\System32\drivers\etc\hosts") }
    elseif (-not $baseline -and $hosts.Count -gt 0) { Set-Result 'sabotage hosts-file' 'WARN' ("hosts file has {0} entr(ies): check they are meant to be there" -f $hosts.Count) ($hosts -join "`n") }

    # port proxies
    $pp = @(& netsh.exe interface portproxy show all 2>$null | Where-Object { $_ -match '^\s*\S+\s+\d+\s+\S+\s+\d+\s*$' })
    if ($pp.Count -gt 0) { Set-Result 'sabotage portproxy' 'DOWN' ("{0} port prox(ies) forward traffic away from the real service" -f $pp.Count) ((($pp | ForEach-Object { $_.Trim() }) -join "`n") + "`nRemove: hunt\Remove-Persistence.ps1") }

    # outbound default block (breaks DNS forwarding, DB connections, AD)
    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    foreach ($p in $profiles) {
        if ($p.Enabled -and "$($p.DefaultOutboundAction)" -eq 'Block') { Set-Result 'sabotage firewall-outbound' 'DOWN' ("firewall profile {0} BLOCKS outbound by default" -f $p.Name) "Fix: Set-NetFirewallProfile -Name $($p.Name) -DefaultOutboundAction Allow" }
    }
    # IPsec rules can drop traffic without showing up as firewall rules
    if (Get-Command Get-NetIPsecRule -ErrorAction SilentlyContinue) {
        $ipsec = @(Get-NetIPsecRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
        if ($ipsec.Count -gt 0) { Set-Result 'sabotage ipsec' 'WARN' ("{0} IPsec rule(s) are active: they can silently drop or require-auth traffic" -f $ipsec.Count) ((($ipsec | Select-Object -First 5 | ForEach-Object { $_.DisplayName }) -join ', ') + "`nReview: Get-NetIPsecRule | fl DisplayName,InboundSecurity,OutboundSecurity") }
    }
    # disk space
    $sys = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction SilentlyContinue
    if ($sys -and $sys.Size -gt 0) {
        $pct = [math]::Round(100 * $sys.FreeSpace / $sys.Size, 1)
        if ($pct -lt 3) { Set-Result 'sabotage disk' 'DOWN' "system drive is FULL ($pct% free): services and logs start failing" 'Look for huge new files: Get-ChildItem C:\ -Recurse -File -EA 0 | sort Length -desc | select -First 15 FullName,Length' }
        elseif ($pct -lt 10) { Set-Result 'sabotage disk' 'WARN' "system drive is at $pct% free" }
    }
    # domain members: can we still find a DC, and is the clock close enough for Kerberos (5 minutes)?
    if ($domainFqdn -and -not $isDC) {
        $dc = @(& nltest.exe "/dsgetdc:$domainFqdn" 2>&1)
        if ($LASTEXITCODE -ne 0) {
            Set-Result 'sabotage domain' 'DOWN' "cannot locate a domain controller for $domainFqdn" "Check that the DNS client settings point at the DC: Get-DnsClientServerAddress ; nslookup -type=SRV _ldap._tcp.$domainFqdn"
        } else {
            $dcName = (($dc | Where-Object { $_ -match 'DC:\s*\\\\(\S+)' } | Select-Object -First 1) -replace '.*\\\\', '').Trim()
            if ($dcName) {
                $w = @(& w32tm.exe /stripchart "/computer:$dcName" /samples:1 /dataonly 2>&1)
                $off = $w | Where-Object { $_ -match '([+-]\d+\.\d+)s' } | Select-Object -Last 1
                if ($off -and "$off" -match '([+-]\d+\.\d+)s') {
                    $secs = [math]::Abs([double]$Matches[1])
                    if ($secs -gt 240) { Set-Result 'sabotage clock' 'DOWN' ("clock is {0:N0}s away from DC {1}: Kerberos fails beyond 300s" -f $secs, $dcName) "Fix: w32tm /resync /force   (or: net time \\$dcName /set /y)" }
                    elseif ($secs -gt 60) { Set-Result 'sabotage clock' 'WARN' ("clock is {0:N0}s away from DC {1}" -f $secs, $dcName) 'Fix: w32tm /resync /force' }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# One full pass
# ---------------------------------------------------------------------------
function Invoke-Pass {
    $script:results = [ordered]@{}
    $script:current = @{ http = @{}; dns = @{}; zones = @{}; shares = @(); accounts = @{}; hosts = @() }
    $rules = Get-FwRules
    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $procNames = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[[int]$_.Id] = $_.ProcessName }

    foreach ($port in ($Tcp | Sort-Object -Unique)) { Test-ScoredTcpPort $port $rules $profiles $procNames }
    foreach ($port in ($Udp | Sort-Object -Unique)) {
        $key = "udp/$port"
        $ep = @(Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue)
        if ($ep.Count -eq 0) { Set-Result $key 'DOWN' 'NOTHING is listening on this UDP port' }
        else { Set-Result $key 'UP' ("listening on {0}" -f (($ep | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique | Select-Object -First 4) -join ',')) }
        Test-Firewall $key $port 17 $rules $profiles
    }
    $urls = @($Url)
    foreach ($port in ($Tcp | Where-Object { $httpPorts -contains $_ })) {
        $scheme = if ($port -in 443, 8443) { 'https' } else { 'http' }
        $urls += $(if ($port -in 80, 443) { "${scheme}://$myIp/" } else { "${scheme}://${myIp}:$port/" })
    }
    foreach ($u in ($urls | Sort-Object -Unique)) { Test-Http $u }
    if ($Tcp -contains 53 -or $Udp -contains 53 -or $DnsName.Count -gt 0) { Test-Dns }
    if ($Tcp -contains 389 -and $isDC) { Test-Ldap }
    if ($Tcp -contains 445) { Test-Smb }
    if ($Tcp -contains 3389) { Test-Rdp }
    if ($Tcp -contains 22) { Test-Ssh }
    foreach ($a in $scoredAccounts) { Test-ScoredAccount $a }
    Test-Sabotage
}

function Save-Baseline {
    $obj = [ordered]@{ host = $env:COMPUTERNAME; taken = (Get-Date).ToString('s'); http = $script:current.http; dns = $script:current.dns
                       zones = $script:current.zones; shares = $script:current.shares; accounts = $script:current.accounts; hosts = $script:current.hosts }
    ($obj | ConvertTo-Json -Depth 6) | Out-File -FilePath $baselineFile -Encoding UTF8
}

function Show-Results([bool]$full, $previous, $failCounts) {
    $down = @($script:results.Values | Where-Object State -eq 'DOWN')
    $warn = @($script:results.Values | Where-Object State -eq 'WARN')
    foreach ($r in $script:results.Values) {
        $before = if ($previous -and $previous.ContainsKey($r.Key)) { $previous[$r.Key] } else { $null }
        $changed = ($null -ne $before -and $before -ne $r.State)
        if ($r.State -eq 'DOWN') { $failCounts[$r.Key] = 1 + [int]$failCounts[$r.Key] } else { $failCounts[$r.Key] = 0 }
        if ($changed) {
            # Record every transition: it is the timeline for the "what happened" part of an incident report.
            Write-CcdcAlert -Level $(if ($r.State -eq 'DOWN') { 'RED' } elseif ($r.State -eq 'WARN') { 'YELLOW' } else { 'GREEN' }) -Rule "Service$($r.State)" -Detail ("{0}: {1} (was {2})" -f $r.Key, $r.Message, $before) -Source 'Test-ScoredServices'
            if ($Beep -and $r.State -eq 'DOWN') { try { [console]::Beep(900, 400) } catch { $null = $_ } }
        }
        if (-not $full -and -not $changed -and $r.State -eq 'UP') { continue }
        $lvl = @{ UP = 'GREEN'; WARN = 'YELLOW'; DOWN = 'RED' }[$r.State]
        $tag = if ($changed) { " [CHANGED: was $before]" } else { '' }
        $sla = if ($r.State -eq 'DOWN' -and $Loop -and $r.Key -match '^(tcp|udp|http|dns|ldap|smb|rdp|ssh)') { "  (failing for $($failCounts[$r.Key]) pass(es); SLA penalty after 5 failed scoring checks)" } else { '' }
        Write-Finding -Level $lvl -Category 'Scored' -Message ("{0,-22} {1}{2}{3}" -f $r.Key, $r.Message, $tag, $sla) -Detail $r.Detail
    }
    if (-not $full) {
        $color = if ($down.Count -gt 0) { 'Red' } elseif ($warn.Count -gt 0) { 'Yellow' } else { 'DarkGreen' }
        Write-Host ("  {0}  UP:{1}  WARN:{2}  DOWN:{3}" -f (Get-Date -Format 'HH:mm:ss'), @($script:results.Values | Where-Object State -eq 'UP').Count, $warn.Count, $down.Count) -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Finding -Level INFO -Category 'Setup' -Message ("Testing {0} against {1}: TCP {2}{3}{4}" -f $env:COMPUTERNAME, $myIp, ($Tcp -join ','), $(if ($Udp) { "  UDP $($Udp -join ',')" } else { '' }), $(if ($scoredAccounts) { "  accounts $($scoredAccounts -join ',')" } else { '' }))
if ($baseline) { Write-Finding -Level INFO -Category 'Setup' -Message "Comparing with baseline taken $($baseline.taken)" }

$previous = $null; $failCounts = @{}; $first = $true
try {
    do {
        if ($first) { Write-Section 'Scored services' }
        Invoke-Pass
        Show-Results $first $previous $failCounts
        if ($first -and (-not $baseline -or $SaveBaseline)) {
            $downNow = @($script:results.Values | Where-Object State -eq 'DOWN').Count
            Save-Baseline
            $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
            Write-Finding -Level $(if ($downNow -gt 0) { 'YELLOW' } else { 'GREEN' }) -Category 'Baseline' -Message "Baseline saved: $baselineFile" -Detail $(if ($downNow -gt 0) { 'Something is DOWN right now, so this baseline may record a broken state. Fix it, confirm the scoreboard is green, then run again with -SaveBaseline.' } else { 'Later runs compare page titles, DNS records, shares and account password dates against this.' })
        }
        $previous = @{}; foreach ($r in $script:results.Values) { $previous[$r.Key] = $r.State }
        $first = $false
        if ($Loop) { Start-Sleep -Seconds $IntervalSeconds }
    } while ($Loop)
} finally {
    Write-Host '  Green here but red on the scoreboard? Then it is outside this box: router / NAT rule, or the scored account password (PCR).' -ForegroundColor DarkGray
    Complete-Ccdc
}
