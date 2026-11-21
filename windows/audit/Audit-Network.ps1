<#
.SYNOPSIS
    Audit-Network - connections, firewall, SMB, shares, RDP, WinRM. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Shows who this box is talking to right now and how exposed it is:
        * established TCP connections + owning process (spot reverse shells / C2)
        * firewall profile state and inbound "allow anything from anywhere" rules
        * SMBv1 on/off, SMB signing required or not
        * non-default shares and who can write to them
        * RDP enabled? NLA required?
        * WinRM running? listeners? Basic/unencrypted allowed?

    WHAT IT READS   Get-NetTCPConnection, Get-NetFirewall*, Get-SmbServerConfiguration,
                    Get-SmbShare/Get-SmbShareAccess, registry (LanmanServer, Terminal Server, WSMAN)
    WHAT IT CHANGES nothing (own log + optional report)
    HOW TO UNDO     nothing to undo. Fixes live in harden\Set-Firewall.ps1 and harden\Harden-Walkthrough.ps1.

    MANUAL EQUIVALENT
      netstat -ano | findstr ESTABLISHED
      netsh advfirewall show allprofiles
      netsh advfirewall firewall show rule name=all dir=in | more
      Get-SmbServerConfiguration | select EnableSMB1Protocol,RequireSecuritySignature
      net share ;  Get-SmbShareAccess -Name <share>
      reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication
      winrm enumerate winrm/config/listener

.EXAMPLE
    .\Audit-Network.ps1 -OutFile C:\ccdc\reports\network.txt
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-Network' -OutFile $OutFile -ReadOnly
$config = Get-CcdcConfig -Path $ConfigPath

# Classic reverse-shell / C2 ports. Not proof - just a strong hint.
$c2Ports = @(1234, 1337, 4444, 4445, 5555, 6666, 6667, 7777, 8888, 9001, 9999, 31337, 50050)
# Our own pod subnet (from config) so we can tell "inside" from "outside".
$podPrefix = $null
if ($config -and $config.subnet) { $podPrefix = ($config.subnet -split '/')[0] -replace '\.\d+$', '.' }

# ---------------------------------------------------------------------------
Write-Section 'Established connections'
# ---------------------------------------------------------------------------
$procs = @{}; Get-WmiObject Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' }
if (-not $conns) { Write-Finding -Level GREEN -Category 'Conn' -Message 'No established non-loopback TCP connections.' }
foreach ($c in ($conns | Sort-Object RemoteAddress)) {
    $p = $procs[[int]$c.OwningProcess]
    $name = if ($p) { $p.Name } else { "pid $($c.OwningProcess)" }
    $path = if ($p) { $p.ExecutablePath } else { '' }
    $lvl = 'INFO'
    if ($c2Ports -contains [int]$c.RemotePort -or $c2Ports -contains [int]$c.LocalPort) { $lvl = 'RED' }
    elseif ($name -match '^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|nc|ncat|certutil)(\.exe)?$') { $lvl = 'RED' }
    elseif ($podPrefix -and -not $c.RemoteAddress.StartsWith($podPrefix) -and $c.LocalPort -gt 1024) { $lvl = 'YELLOW' }  # outbound to outside the pod
    Write-Finding -Level $lvl -Category 'Conn' -Message ("{0}:{1} -> {2}:{3}  {4}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $name) -Detail $path
}

# ---------------------------------------------------------------------------
Write-Section 'Firewall profiles'
# ---------------------------------------------------------------------------
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($fp in $profiles) {
    $lvl = if (-not $fp.Enabled) { 'RED' } elseif ($fp.DefaultInboundAction -eq 'Allow') { 'RED' } else { 'GREEN' }
    Write-Finding -Level $lvl -Category 'Firewall' -Message ("{0,-8} enabled={1} inbound={2} outbound={3} logBlocked={4}" -f $fp.Name, $fp.Enabled, $fp.DefaultInboundAction, $fp.DefaultOutboundAction, $fp.LogBlocked)
}
if (-not $profiles) { Write-Finding -Level YELLOW -Category 'Firewall' -Message 'Get-NetFirewallProfile failed; run: netsh advfirewall show allprofiles' }

Write-Section 'Inbound ALLOW rules open to Any address'
# Pull all enabled inbound allow rules once, then their filters in bulk (fast).
$rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) {
    $addr = @{}; $rules | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object { $addr[$_.InstanceID] = $_ }
    $port = @{}; $rules | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object { $port[$_.InstanceID] = $_ }
    $app  = @{}; $rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { $app[$_.InstanceID] = $_ }
    $anyAny = 0; $custom = 0
    foreach ($r in $rules) {
        $a = $addr[$r.InstanceID]; $p = $port[$r.InstanceID]; $ap = $app[$r.InstanceID]
        $remoteAny = ($a.RemoteAddress -contains 'Any')
        $portAny   = ($p.LocalPort -contains 'Any')
        $progAny   = (-not $ap -or $ap.Program -eq 'Any')
        if ($remoteAny -and $portAny -and $progAny) {
            $anyAny++
            Write-Finding -Level RED -Category 'FwRule' -Message ("ANY port from ANY address: '{0}' ({1})" -f $r.DisplayName, $r.Profile) -Detail "Name=$($r.Name)"
        } elseif (-not $r.DisplayGroup) {
            # Rules with no group were created by a person or installer, not Windows.
            $custom++
            Write-Finding -Level YELLOW -Category 'FwRule' -Message ("custom rule '{0}' {1}/{2} from {3}" -f $r.DisplayName, $p.Protocol, ($p.LocalPort -join ','), ($a.RemoteAddress -join ',')) -Detail $(if ($ap -and $ap.Program -ne 'Any') { $ap.Program })
        }
    }
    Write-Finding -Level INFO -Category 'FwRule' -Message ("{0} enabled inbound allow rules; {1} any/any; {2} custom (no group)" -f $rules.Count, $anyAny, $custom)
}

# ---------------------------------------------------------------------------
Write-Section 'SMB'
# ---------------------------------------------------------------------------
$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb) {
    if ($smb.EnableSMB1Protocol) { Write-Finding -Level RED -Category 'SMB' -Message 'SMBv1 server ENABLED (EternalBlue / MS17-010 class attacks)' }
    else { Write-Finding -Level GREEN -Category 'SMB' -Message 'SMBv1 server disabled' }
    if ($smb.RequireSecuritySignature) { Write-Finding -Level GREEN -Category 'SMB' -Message 'SMB server signing REQUIRED' }
    else { Write-Finding -Level YELLOW -Category 'SMB' -Message 'SMB server signing not required (NTLM relay possible)' }
} else {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
    Write-Finding -Level INFO -Category 'SMB' -Message ("Registry: SMB1={0} RequireSecuritySignature={1}" -f $v.SMB1, $v.RequireSecuritySignature)
}
$ws = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
if ($ws) {
    $lvl = if ($ws.RequireSecuritySignature -eq 1) { 'GREEN' } else { 'YELLOW' }
    Write-Finding -Level $lvl -Category 'SMB' -Message ("SMB client RequireSecuritySignature={0}" -f [int]$ws.RequireSecuritySignature)
}

Write-Section 'Shares and permissions'
$defaultShares = '^(ADMIN\$|IPC\$|[A-Z]\$|print\$|NETLOGON|SYSVOL)$'
$shares = Get-SmbShare -ErrorAction SilentlyContinue
foreach ($s in $shares) {
    if ($s.Name -match $defaultShares) { Write-Finding -Level INFO -Category 'Share' -Message ("{0,-12} {1} (default)" -f $s.Name, $s.Path); continue }
    Write-Finding -Level YELLOW -Category 'Share' -Message ("{0,-12} {1}  <- non-default share" -f $s.Name, $s.Path)
    foreach ($acc in (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)) {
        $lvl = if ($acc.AccountName -match 'Everyone|Authenticated Users|Guest|ANONYMOUS|\\Users$' -and $acc.AccessRight -in @('Full', 'Change') -and $acc.AccessControlType -eq 'Allow') { 'RED' } else { 'INFO' }
        Write-Finding -Level $lvl -Category 'Share' -Message ("    {0}: {1} {2} {3}" -f $s.Name, $acc.AccountName, $acc.AccessControlType, $acc.AccessRight)
    }
}
if (-not $shares) { Write-Finding -Level INFO -Category 'Share' -Message 'Get-SmbShare unavailable; run: net share' }

# ---------------------------------------------------------------------------
Write-Section 'RDP'
# ---------------------------------------------------------------------------
$ts  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($ts) {
    if ($ts.fDenyTSConnections -eq 0) {
        Write-Finding -Level INFO -Category 'RDP' -Message ("RDP ENABLED on port {0}" -f $rdp.PortNumber)
        if ($rdp.UserAuthentication -eq 1) { Write-Finding -Level GREEN -Category 'RDP' -Message 'NLA required' }
        else { Write-Finding -Level YELLOW -Category 'RDP' -Message 'NLA NOT required (login screen reachable pre-auth; sticky-keys backdoors usable)' }
        if ($rdp.PortNumber -ne 3389) { Write-Finding -Level YELLOW -Category 'RDP' -Message "Non-standard RDP port $($rdp.PortNumber) - did we or Red Team change it?" }
    } else { Write-Finding -Level INFO -Category 'RDP' -Message 'RDP disabled' }
}

# ---------------------------------------------------------------------------
Write-Section 'WinRM'
# ---------------------------------------------------------------------------
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue
if ($winrm -and $winrm.Status -eq 'Running') {
    Write-Finding -Level INFO -Category 'WinRM' -Message 'WinRM service RUNNING'
    $listeners = & winrm enumerate winrm/config/listener 2>$null
    if ($listeners) {
        $txt = $listeners -join "`n"
        Write-Finding -Level INFO -Category 'WinRM' -Message ("Listeners: {0}" -f ((($listeners | Select-String 'Transport|Port\s*=|ListeningOn') -replace '\s+', ' ') -join ' | '))
        if ($txt -match 'Transport = HTTP\b') { Write-Finding -Level YELLOW -Category 'WinRM' -Message 'HTTP listener present (5985) - fine inside the pod if auth is Kerberos/NTLM' }
    }
    $svc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service' -ErrorAction SilentlyContinue
    if ($svc.allow_unencrypted -eq 1) { Write-Finding -Level RED -Category 'WinRM' -Message 'AllowUnencrypted = true' }
    if ($svc.auth_basic -eq 1) { Write-Finding -Level RED -Category 'WinRM' -Message 'Basic auth enabled (cleartext creds)' }
} else {
    Write-Finding -Level INFO -Category 'WinRM' -Message 'WinRM not running'
}

Complete-Ccdc
