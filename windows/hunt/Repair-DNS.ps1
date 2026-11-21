<#
.SYNOPSIS
    Repair-DNS - DNS is down: find out why, try the standard fixes, verify, and tell you what is left. CHANGES STATE (each fix confirmed).

.DESCRIPTION
    PURPOSE
      When DNS stops answering, everything on the network that uses names breaks
      with it (logons to the domain, web sites, other boxes' checks). This works out
      whether DNS was simply TURNED OFF (quick fix) or something BIGGER is wrong
      (crash, deleted zone, broken AD), fixes what is safe to fix, and hands you
      the rest with the exact next step.

    STEP 1  DIAGNOSE   service state and start mode; when and how it stopped (System log:
                       stopped normally, start type changed, or CRASHED); DNS Server log errors;
                       is port 53 listening; firewall rules for 53; paused zones
    STEP 2  FIX        (each one asks y/N first)
                       start type Disabled -> Automatic; start the service; restart it if it
                       runs but does not answer; turn the built-in DNS firewall rules back on;
                       resume paused zones; clear the DNS cache; on a DC re-register the DC's
                       own records (ipconfig /registerdns + restart Netlogon)
    STEP 3  VERIFY     port 53 listening; look up the domain and every zone; on a DC the
                       _ldap._tcp.dc._msdcs record that tells machines where the DC is
    STEP 4  VERDICT    FIXED, or what is still wrong and exactly what to do next

    Not a DNS server? It checks this box's DNS client settings and hosts file instead.

    WHAT IT READS    DNS service, System + DNS Server logs, firewall rules, zones, NIC DNS settings
    WHAT IT CHANGES  only the fixes you confirm; each prints its undo
    HOW TO UNDO      Set-Service DNS -StartupType <old> (printed); firewall rules: Disable-NetFirewallRule -Name <name>

    MANUAL EQUIVALENT
      Get-Service DNS ; Set-Service DNS -StartupType Automatic ; Start-Service DNS
      Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 50
      Resolve-DnsName <domain> -Server 127.0.0.1 ; nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> 127.0.0.1
      ipconfig /registerdns ; net stop netlogon ; net start netlogon

.EXAMPLE
    .\Repair-DNS.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force,
    [string]$ConfigPath
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Repair-DNS'
$isDC = Test-CcdcIsDC
$domain = $null
try { $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name } catch { $domain = $env:USERDNSDOMAIN }
$myIp = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | ForEach-Object { $_.IPAddress }) | Select-Object -First 1
$problems = New-Object System.Collections.ArrayList   # what is still wrong at the end

function Test-Lookup([string]$name, [string]$server, [string]$type = 'A') {
    # $true if the server answers the query. Resolve-DnsName on 2012+, nslookup otherwise.
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try { $null = Resolve-DnsName -Name $name -Server $server -Type $type -DnsOnly -QuickTimeout -ErrorAction Stop; return $true } catch { return $false }
    }
    $o = & nslookup.exe "-type=$type" $name $server 2>&1 | Out-String
    return ($o -notmatch 'timed out|can''t find|Non-existent|No response')
}
function Test-Port53 { return [bool](Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue) }

$svc = Get-WmiObject Win32_Service -Filter "Name='DNS'" -ErrorAction SilentlyContinue

# ===========================================================================
if (-not $svc) {
    Write-Section 'This box is not a DNS server: checking its DNS client side'
    $servers = @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ })
    Write-Finding -Level INFO -Category 'Client' -Message ("This box asks these DNS servers: {0}" -f $(if ($servers) { $servers -join ', ' } else { '(none set!)' }))
    foreach ($srv in $servers) {
        $ok = if ($domain) { Test-Lookup $domain $srv } else { Test-Lookup 'localhost' $srv }
        Write-Finding -Level $(if ($ok) { 'GREEN' } else { 'RED' }) -Category 'Client' -Message ("{0}: {1}" -f $srv, $(if ($ok) { "answers ($domain)" } else { 'NO ANSWER: that DNS server is down or blocked. Run this script ON that server.' }))
    }
    if (-not $servers) { [void]$problems.Add('No DNS servers set on this box: set the DC''s IP on the network card (ncpa.cpl > IPv4 > DNS).') }
    $hostsLines = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*\d' })
    foreach ($h in $hostsLines) { Write-Finding -Level YELLOW -Category 'Hosts' -Message "hosts file entry: $($h.Trim())" -Detail 'A hosts entry overrides DNS. Not yours? Remove it (panel W -> 1 then U puts the hosts file back).' }
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DNS client cache' -Action 'Flush (ipconfig /flushdns)' -ScriptBlock { $null = & ipconfig.exe /flushdns }
    foreach ($p in $problems) { Write-Finding -Level RED -Category 'Left' -Message $p }
    Complete-Ccdc; return
}

# ===========================================================================
Write-Section 'Step 1: diagnose'
# ===========================================================================
Write-Finding -Level $(if ($svc.State -eq 'Running') { 'GREEN' } else { 'RED' }) -Category 'Service' -Message ("DNS service: {0}, start mode {1}" -f $svc.State, $svc.StartMode)

# How did it go down? Service Control Manager events for the DNS service, last 24 h.
$since = (Get-Date).AddHours(-24)
$scm = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -MaxEvents 3000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 7031, 7034, 7036, 7040, 7023, 7024 -and $_.Message -match 'DNS Server' } | Sort-Object TimeCreated)
$crashed = @($scm | Where-Object { $_.Id -in 7031, 7034, 7023, 7024 })
$stoppedEv = @($scm | Where-Object { $_.Id -eq 7036 -and $_.Message -match 'stopped' }) | Select-Object -Last 1
$typeEv = @($scm | Where-Object { $_.Id -eq 7040 }) | Select-Object -Last 1
$cause = 'unknown'
if ($crashed) {
    $cause = 'crashed'
    foreach ($c in ($crashed | Select-Object -Last 3)) { Write-Finding -Level RED -Category 'Cause' -Message ("{0}  CRASHED / failed: {1}" -f $c.TimeCreated.ToString('HH:mm'), (($c.Message -split "`n")[0]).Trim()) }
    [void]$problems.Add('DNS CRASHED (not just stopped). Unpatched DNS / DC bugs (SIGRed, LDAPNightmare) crash it on purpose: check panel 5 and panel E, and watch for it going down again.')
} elseif ($typeEv -and $typeEv.Message -match 'disabled') {
    $cause = 'disabled'
    Write-Finding -Level RED -Category 'Cause' -Message ("{0}  someone set DNS to DISABLED: {1}" -f $typeEv.TimeCreated.ToString('HH:mm'), (($typeEv.Message -split "`n")[0]).Trim())
} elseif ($stoppedEv -and $svc.State -ne 'Running') {
    $cause = 'stopped'
    Write-Finding -Level YELLOW -Category 'Cause' -Message ("{0}  DNS was STOPPED normally (someone turned it off)" -f $stoppedEv.TimeCreated.ToString('HH:mm'))
}
if ($cause -in 'disabled', 'stopped') { Write-Finding -Level INFO -Category 'Cause' -Message 'Who did it: panel E (attacks) or panel D -> 7 (what happened). A service stopped by an attacker means they had admin.' }

# DNS Server log: the errors that explain zone / AD problems.
$dnsErr = @(Get-WinEvent -FilterHashtable @{ LogName = 'DNS Server'; Level = 1, 2; StartTime = $since } -MaxEvents 10 -ErrorAction SilentlyContinue)
foreach ($e in ($dnsErr | Select-Object -First 5)) { Write-Finding -Level YELLOW -Category 'DnsLog' -Message ("{0}  event {1}: {2}" -f $e.TimeCreated.ToString('HH:mm'), $e.Id, (($e.Message -split "`n")[0]).Trim()) }

# Firewall: a block rule on 53, or the built-in DNS rules switched off.
$fwBlock = @(); $fwBuiltinOff = @()
if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    $fwBuiltinOff = @(Get-NetFirewallRule -Name 'DNSSrv-*' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -ne 'True' })
    foreach ($r in @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue)) {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($pf -and (@($pf.LocalPort) -contains '53' -or @($pf.LocalPort) -contains 'Any')) { $fwBlock += $r }
    }
}
foreach ($r in $fwBuiltinOff) { Write-Finding -Level RED -Category 'Firewall' -Message "Built-in DNS firewall rule is OFF: $($r.DisplayName)" }
foreach ($r in $fwBlock) { Write-Finding -Level RED -Category 'Firewall' -Message "Firewall BLOCK rule covers port 53: $($r.DisplayName)" -Detail "Not yours? Disable-NetFirewallRule -Name '$($r.Name)'  (or panel W -> 1 then U)" }

# Zones
$hasDnsModule = Test-CcdcModule DnsServer
$zones = @()
if ($hasDnsModule -and $svc.State -eq 'Running') {
    $zones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })
    foreach ($z in ($zones | Where-Object { $_.IsPaused })) { Write-Finding -Level RED -Category 'Zone' -Message "Zone $($z.ZoneName) is PAUSED (DNS answers nothing for it)" }
    if ($domain -and -not ($zones | Where-Object { $_.ZoneName -eq $domain })) {
        Write-Finding -Level RED -Category 'Zone' -Message "The domain's zone '$domain' is MISSING from this DNS server"
        [void]$problems.Add("Zone '$domain' is missing. AD-integrated zones come back when AD replication / the zone object is restored; a file zone can be re-added from the backup: look in C:\ccdc\backups\*\dns and use  dnscmd /ZoneAdd $domain /Primary /file <file>  (copy the file to %windir%\System32\dns first).")
    }
}

# ===========================================================================
Write-Section 'Step 2: standard fixes (each asks first)'
# ===========================================================================
if ($svc.StartMode -eq 'Disabled') {
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DNS service' -Action 'Start type Disabled -> Automatic' -Undo 'Set-Service DNS -StartupType Disabled' -ScriptBlock { Set-Service -Name DNS -StartupType Automatic -ErrorAction Stop }
}
$svc = Get-WmiObject Win32_Service -Filter "Name='DNS'"
if ($svc.State -ne 'Running') {
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DNS service' -Action 'Start it' -Undo 'Stop-Service DNS' -ScriptBlock {
        Start-Service -Name DNS -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Service DNS).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        if ((Get-Service DNS).Status -ne 'Running') { throw 'service did not reach Running within 30 s' }
    }
}
foreach ($r in $fwBuiltinOff) {
    $rn = $r.Name
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $r.DisplayName -Action 'Turn the built-in DNS firewall rule back on' -Undo "Disable-NetFirewallRule -Name '$rn'" -ScriptBlock { Enable-NetFirewallRule -Name $rn -ErrorAction Stop }
}
foreach ($r in $fwBlock) {
    $rn = $r.Name
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $r.DisplayName -Action 'Disable this BLOCK rule on port 53 (not deleted)' -Undo "Enable-NetFirewallRule -Name '$rn'" -ScriptBlock { Disable-NetFirewallRule -Name $rn -ErrorAction Stop }
}
if ($hasDnsModule) {
    foreach ($z in @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsPaused })) {
        $zn = $z.ZoneName
        $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "zone $zn" -Action 'Resume zone' -Undo "Suspend-DnsServerZone -Name $zn" -ScriptBlock { Resume-DnsServerZone -Name $zn -ErrorAction Stop }
    }
}
# Running but not answering locally? A restart is the standard next step.
if ((Get-Service DNS).Status -eq 'Running' -and $domain -and -not (Test-Lookup $domain '127.0.0.1')) {
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DNS service' -Action 'Restart it (running but not answering)' -ScriptBlock { Restart-Service -Name DNS -Force -ErrorAction Stop; Start-Sleep -Seconds 5 }
}
$null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DNS caches' -Action 'Clear the server cache and this box''s cache' -ScriptBlock {
    if (Get-Command Clear-DnsServerCache -ErrorAction SilentlyContinue) { Clear-DnsServerCache -Force -ErrorAction SilentlyContinue }
    $null = & ipconfig.exe /flushdns
}
if ($isDC -and $domain -and -not (Test-Lookup "_ldap._tcp.dc._msdcs.$domain" '127.0.0.1' 'SRV')) {
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'DC records' -Action 'Re-register this DC''s DNS records (ipconfig /registerdns + restart Netlogon)' -ScriptBlock {
        $null = & ipconfig.exe /registerdns
        Restart-Service -Name Netlogon -Force -ErrorAction Stop
        Start-Sleep -Seconds 10
    }
}

# ===========================================================================
Write-Section 'Step 3: verify'
# ===========================================================================
$svc = Get-WmiObject Win32_Service -Filter "Name='DNS'"
$checks = @()
$checks += @{ Name = 'DNS service running'; Ok = ($svc.State -eq 'Running') }
$checks += @{ Name = 'Listening on port 53'; Ok = (Test-Port53) }
if ($domain) {
    $checks += @{ Name = "Answers $domain (127.0.0.1)"; Ok = (Test-Lookup $domain '127.0.0.1') }
    if ($myIp) { $checks += @{ Name = "Answers $domain on $myIp (what other boxes use)"; Ok = (Test-Lookup $domain $myIp) } }
}
if ($isDC -and $domain) { $checks += @{ Name = 'DC locator record (_ldap._tcp.dc._msdcs)'; Ok = (Test-Lookup "_ldap._tcp.dc._msdcs.$domain" '127.0.0.1' 'SRV') } }
if ($hasDnsModule) {
    foreach ($z in @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and -not $_.IsReverseLookupZone -and $_.ZoneName -notmatch '^(TrustAnchors|_msdcs\.)' })) {
        $checks += @{ Name = "Zone $($z.ZoneName) answers"; Ok = (Test-Lookup $z.ZoneName '127.0.0.1' 'SOA') }
    }
}
foreach ($c in $checks) { Write-Finding -Level $(if ($c.Ok) { 'GREEN' } else { 'RED' }) -Category 'Verify' -Message $c.Name }
if ((Test-Port53) -and $myIp -and $domain -and (Test-Lookup $domain '127.0.0.1') -and -not (Test-Lookup $domain $myIp)) {
    [void]$problems.Add("DNS answers locally but NOT on ${myIp}: the listening address was limited, or the firewall blocks it. Check: Get-DnsServerSetting -All | Select ListeningIPAddress  (fix: dnsmgmt.msc > server > Properties > Interfaces > All IP addresses).")
}

# ===========================================================================
Write-Section 'Step 4: verdict'
# ===========================================================================
$failed = @($checks | Where-Object { -not $_.Ok })
if (-not $failed -and -not $problems.Count) {
    Write-Finding -Level GREEN -Category 'Verdict' -Message ("DNS is FIXED and answering. Cause: {0}." -f $(switch ($cause) { 'stopped' { 'it had been turned off' } 'disabled' { 'it had been disabled' } 'crashed' { 'it crashed (see above)' } default { 'not clear from the logs' } }))
    if ($cause -in 'stopped', 'disabled') { Write-Finding -Level INFO -Category 'Verdict' -Message 'Someone with admin turned it off: run panel E now to find out who, and rotate that account.' }
} else {
    Write-Finding -Level RED -Category 'Verdict' -Message 'DNS is NOT fully fixed. What is left for you:'
    foreach ($p in $problems) { Write-Finding -Level RED -Category 'Left' -Message $p }
    foreach ($f in $failed) { Write-Finding -Level RED -Category 'Left' -Message "Still failing: $($f.Name)" }
    Write-Finding -Level INFO -Category 'Left' -Message 'DNS Server log: Event Viewer > Applications and Services Logs > DNS Server. Zone files / exports: C:\ccdc\backups. Settings changed by someone: panel W -> 1.'
}
Complete-Ccdc
