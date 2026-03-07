# =============================================================================
# Invoke-ThreatMonitor.ps1
# CCDC Blue Team - Background Threat Monitor + IP Capture
# Runs continuously, fires Windows toast notifications, logs attacker IPs
# Run as: Administrator
# Usage:  .\Invoke-ThreatMonitor.ps1
# Silent: Start-Process powershell -ArgumentList "-WindowStyle Hidden -File C:\BlueTeam\Invoke-ThreatMonitor.ps1" -Verb RunAs
# =============================================================================

#Requires -RunAsAdministrator

param(
    [int]$PollSeconds       = 15,
    [string]$LogDir         = "C:\BlueTeam\Monitor",
    [int]$BruteForceThresh  = 5,    # Failed logins in window to trigger alert
    [int]$BruteForceWindow  = 2,    # Minutes to count failed logins over
    [switch]$AutoBlock              # Auto-block IPs that trigger CRITICAL alerts
)

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction SilentlyContinue

$LogFile        = "$LogDir\ThreatMonitor_$(Get-Date -Format 'yyyyMMdd').log"
$IPFile         = "$LogDir\AttackerIPs.txt"
$BlockedIPFile  = "$LogDir\BlockedIPs.txt"
$EvidenceDir    = "$LogDir\Evidence"
$null = New-Item -ItemType Directory -Path $EvidenceDir -Force -ErrorAction SilentlyContinue

# Dedup tracker - avoid re-alerting the same event
$seen = [System.Collections.Generic.HashSet[string]]::new()

# IP tracking: IP -> [count, last seen, reasons[]]
$ipTracker = [System.Collections.Generic.Dictionary[string, object]]::new()

# Known safe IPs (your team's machines - populate before comp!)
$whitelistedIPs = @(
    '127.0.0.1',
    '::1',
    '-',
    ''
    # Add your team IPs here e.g. '192.168.1.10'
)

# C2/suspicious ports to watch
$c2Ports = @(4444, 5555, 6666, 7777, 8888, 1234, 9999, 31337, 1337, 4321, 2222, 6667, 6697)

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Severity, [string]$Message, [string]$IP = "")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts | [$Severity] $Message"
    if ($IP) { $line += " | IP: $IP" }
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Cyan" }
        "OK"       { "Green" }
        default    { "White" }
    }
    Write-Host $line -ForegroundColor $color
}

# ─────────────────────────────────────────────────────────────────────────────
# WINDOWS TOAST NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────
function Send-ToastNotification {
    param([string]$Title, [string]$Body, [string]$Severity = "HIGH")

    try {
        $icon = switch ($Severity) {
            "CRITICAL" { "[!!]" }
            "HIGH"     { "[HI]" }
            "MEDIUM"   { "[MD]" }
            default    { "[--]" }
        }

        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]           | Out-Null

        $timestamp = Get-Date -Format 'HH:mm:ss'
        $hostname  = $env:COMPUTERNAME
        $line1     = "$icon CCDC ALERT: $Title"
        $line2     = $Body
        $line3     = "$hostname | $timestamp"

        $xml = "<toast><visual><binding template=`"ToastGeneric`">" +
               "<text>$line1</text>" +
               "<text>$line2</text>" +
               "<text>$line3</text>" +
               "</binding></visual></toast>"

        $toastXml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $toastXml.LoadXml($xml)
        $toast    = New-Object Windows.UI.Notifications.ToastNotification $toastXml
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CCDC Blue Team")
        $notifier.Show($toast)
    } catch {
        # Toast failed - fallback to msg.exe popup
        try { msg * /TIME:10 "[$Severity] $Title - $Body" } catch {}
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# IP TRACKER & BLOCKER
# ─────────────────────────────────────────────────────────────────────────────
function Register-AttackerIP {
    param([string]$IP, [string]$Reason, [string]$Severity = "HIGH")

    if (-not $IP -or $IP -in $whitelistedIPs -or $IP -match '^(127\.|::1|169\.254)') { return }

    # Log to attacker IP file
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Severity | $IP | $Reason"
    Add-Content -Path $IPFile -Value $entry -ErrorAction SilentlyContinue

    # Track in memory
    if (-not $ipTracker.ContainsKey($IP)) {
        $ipTracker[$IP] = @{ Count = 0; LastSeen = Get-Date; Reasons = @() }
    }
    $ipTracker[$IP].Count++
    $ipTracker[$IP].LastSeen = Get-Date
    $ipTracker[$IP].Reasons += $Reason

    Write-Log -Severity $Severity -Message "ATTACKER IP RECORDED: $Reason" -IP $IP

    # Auto-block if enabled or if IP has hit 3+ different alert types
    if ($AutoBlock -or $ipTracker[$IP].Count -ge 3) {
        Block-IP -IP $IP -Reason $Reason
    }
}

function Block-IP {
    param([string]$IP, [string]$Reason)
    if (-not $IP -or $IP -in $whitelistedIPs) { return }

    $ruleName = "CCDC_BLOCK_$IP"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) { return }  # Already blocked

    try {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -RemoteAddress $IP `
            -Action Block `
            -Protocol Any `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        # Also block outbound (C2 callbacks)
        New-NetFirewallRule -DisplayName "${ruleName}_OUT" `
            -Direction Outbound `
            -RemoteAddress $IP `
            -Action Block `
            -Protocol Any `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | BLOCKED | $IP | $Reason"
        Add-Content -Path $BlockedIPFile -Value $entry -ErrorAction SilentlyContinue

        Write-Log -Severity "OK" -Message "FIREWALL BLOCK APPLIED: $Reason" -IP $IP
        Send-ToastNotification -Title "IP BLOCKED" -Body "$IP has been firewalled. Reason: $Reason" -Severity "OK"
    } catch {
        Write-Log -Severity "MEDIUM" -Message "Could not block IP (check firewall perms): $($_.Exception.Message)" -IP $IP
    }
}

function Get-AttackerIPSummary {
    if ($ipTracker.Count -eq 0) {
        Write-Log -Severity "OK" -Message "No attacker IPs recorded yet"
        return
    }
    Write-Host "`n  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        ATTACKER IP SUMMARY               ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
    foreach ($entry in $ipTracker.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
        Write-Host "  $($entry.Key) | Hits: $($entry.Value.Count) | Last: $($entry.Value.LastSeen.ToString('HH:mm:ss'))" -ForegroundColor Yellow
        $entry.Value.Reasons | Select-Object -Unique | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
    }
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# EVENT ANALYZERS
# ─────────────────────────────────────────────────────────────────────────────
function Watch-SecurityEvents {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = (Get-Date).AddSeconds(-($PollSeconds * 2))
            Id        = @(4624, 4625, 4648, 4697, 4698, 4720, 4732, 1102)
        } -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $key = "SEC-$($evt.Id)-$($evt.RecordId)"
            if ($seen.Contains($key)) { continue }
            $seen.Add($key) | Out-Null

            $msg = $evt.Message

            switch ($evt.Id) {

                1102 {  # Log cleared
                    Write-Log -Severity "CRITICAL" -Message "⚠ AUDIT LOG CLEARED - Attacker covering tracks!"
                    Send-ToastNotification -Title "AUDIT LOG CLEARED" -Body "An attacker may be covering their tracks!" -Severity "CRITICAL"
                    Save-Evidence "LogCleared" $msg
                }

                4720 {  # New user created
                    $user = if ($msg -match 'New Account.*?Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
                    $by   = if ($msg -match 'Subject:.*?Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
                    Write-Log -Severity "HIGH" -Message "NEW USER CREATED: '$user' by '$by'"
                    Send-ToastNotification -Title "New User Created" -Body "User: $user | Created by: $by" -Severity "HIGH"
                    Save-Evidence "NewUser_$user" $msg
                }

                4732 {  # Added to group
                    if ($msg -match 'Administrators') {
                        $user = if ($msg -match 'Member.*?Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
                        Write-Log -Severity "CRITICAL" -Message "USER ADDED TO ADMINISTRATORS: $user"
                        Send-ToastNotification -Title "Admin Group Modified!" -Body "$user was added to Administrators" -Severity "CRITICAL"
                        Save-Evidence "AdminGroupAdd" $msg
                    }
                }

                4625 {  # Failed logon
                    $user = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
                    $ip   = if ($msg -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { "" }
                    if ($ip -and $ip -notin $whitelistedIPs) {
                        Register-AttackerIP -IP $ip -Reason "Failed logon attempt (user: $user)" -Severity "MEDIUM"
                    }
                }

                4624 {  # Successful logon
                    $logonType = if ($msg -match 'Logon Type:\s+(\d+)') { $matches[1] } else { "0" }
                    $ip        = if ($msg -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { "" }
                    $user      = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
                    if ($logonType -in @('3','10') -and $ip -notin $whitelistedIPs -and $ip) {
                        Write-Log -Severity "MEDIUM" -Message "REMOTE LOGON SUCCESS: $user (Type $logonType)" -IP $ip
                        Register-AttackerIP -IP $ip -Reason "Successful remote logon as $user (Type $logonType)" -Severity "MEDIUM"
                    }
                }

                4648 {  # Explicit credential use
                    $ip     = if ($msg -match 'Network Address:\s+(\S+)') { $matches[1] } else { "" }
                    $target = if ($msg -match 'Target Server Name:\s+(\S+)') { $matches[1] } else { "" }
                    if ($ip -notin $whitelistedIPs -and $ip -and $target -notmatch 'localhost|127\.0\.0\.1') {
                        Write-Log -Severity "HIGH" -Message "LATERAL MOVEMENT: Explicit creds used -> $target" -IP $ip
                        Send-ToastNotification -Title "Lateral Movement Detected" -Body "Explicit credentials used toward $target" -Severity "HIGH"
                        Register-AttackerIP -IP $ip -Reason "Lateral movement attempt to $target" -Severity "HIGH"
                    }
                }

                4697 {  # Service installed
                    Write-Log -Severity "HIGH" -Message "NEW SERVICE INSTALLED"
                    Send-ToastNotification -Title "New Service Installed" -Body "A new service was installed on $env:COMPUTERNAME" -Severity "HIGH"
                    Save-Evidence "ServiceInstalled" $msg
                }

                4698 {  # Scheduled task created
                    $taskName = if ($msg -match 'Task Name:\s+(.+)') { $matches[1].Trim() } else { "unknown" }
                    Write-Log -Severity "HIGH" -Message "SCHEDULED TASK CREATED: $taskName"
                    Send-ToastNotification -Title "Scheduled Task Created" -Body "Task: $taskName" -Severity "HIGH"
                    Save-Evidence "NewTask_$taskName" $msg
                }
            }
        }
    } catch {}
}

function Watch-NetworkConnections {
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($conn in $conns) {
            $key = "NET-$($conn.RemoteAddress)-$($conn.RemotePort)-$($conn.OwningProcess)"
            if ($seen.Contains($key)) { continue }

            $isC2Port   = $conn.RemotePort -in $c2Ports -or $conn.LocalPort -in $c2Ports
            $proc       = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $isSuspProc = $proc.Name -match '(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|nc\.exe|ncat)'

            if ($isC2Port -or $isSuspProc) {
                $seen.Add($key) | Out-Null
                $severity = if ($isC2Port -and $isSuspProc) { "CRITICAL" } elseif ($isC2Port) { "HIGH" } else { "MEDIUM" }

                Write-Log -Severity $severity `
                    -Message "SUSPICIOUS CONNECTION: $($proc.Name) (PID $($conn.OwningProcess)) -> :$($conn.RemotePort)" `
                    -IP $conn.RemoteAddress

                Send-ToastNotification `
                    -Title "Suspicious Network Connection" `
                    -Body "$($proc.Name) connecting to $($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Severity $severity

                Register-AttackerIP -IP $conn.RemoteAddress `
                    -Reason "C2-like connection from $($proc.Name) on port $($conn.RemotePort)" `
                    -Severity $severity
            }
        }
    } catch {}
}

function Watch-BruteForce {
    try {
        $cutoff   = (Get-Date).AddMinutes(-$BruteForceWindow)
        $failures = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = $cutoff
            Id        = 4625
        } -ErrorAction SilentlyContinue

        if ($failures.Count -ge $BruteForceThresh) {
            $key = "BF-$(Get-Date -Format 'yyyyMMddHHmm')"
            if (-not $seen.Contains($key)) {
                $seen.Add($key) | Out-Null
                Write-Log -Severity "CRITICAL" -Message "BRUTE FORCE: $($failures.Count) failed logins in ${BruteForceWindow}min!"
                Send-ToastNotification -Title "BRUTE FORCE ATTACK" -Body "$($failures.Count) failed logins in ${BruteForceWindow} minutes!" -Severity "CRITICAL"

                # Extract and register all source IPs
                $failures | ForEach-Object {
                    $ip = if ($_.Message -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { "" }
                    Register-AttackerIP -IP $ip -Reason "Brute force ($($failures.Count) failures in ${BruteForceWindow}min)" -Severity "CRITICAL"
                }

                Save-Evidence "BruteForce" ($failures | Select-Object TimeCreated, Message | Out-String)
            }
        }
    } catch {}
}

function Watch-SuspiciousProcesses {
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue
        $badProcs = @('mimikatz', 'procdump', 'wce', 'pwdump', 'nmap', 'netcat', 'nc64', 'meterpreter', 'cobaltstrike')

        foreach ($bad in $badProcs) {
            $match = $procs | Where-Object { $_.Name -match $bad }
            if ($match) {
                $key = "PROC-$bad"
                if (-not $seen.Contains($key)) {
                    $seen.Add($key) | Out-Null
                    Write-Log -Severity "CRITICAL" -Message "MALICIOUS PROCESS DETECTED: $($match.Name) (PID $($match.Id))"
                    Send-ToastNotification -Title "Malicious Process!" -Body "$($match.Name) is running on $env:COMPUTERNAME" -Severity "CRITICAL"
                    Save-Evidence "MaliciousProc_$($match.Name)" ($match | Select-Object * | Out-String)
                }
            }
        }
    } catch {}
}

function Watch-WMISubscriptions {
    try {
        $filters   = Get-WMIObject -Namespace root\subscription -Class __EventFilter   -ErrorAction SilentlyContinue
        $consumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue

        $key = "WMI-$(($filters.Count) + ($consumers.Count))"
        if (($filters -or $consumers) -and -not $seen.Contains($key)) {
            $seen.Add($key) | Out-Null
            Write-Log -Severity "CRITICAL" -Message "WMI PERSISTENCE SUBSCRIPTIONS DETECTED! Filters: $($filters.Count) Consumers: $($consumers.Count)"
            Send-ToastNotification -Title "WMI Persistence Detected!" -Body "Red team may have installed WMI event subscriptions" -Severity "CRITICAL"
            Save-Evidence "WMI_Subscriptions" ($filters | Out-String) + ($consumers | Out-String)
        }
    } catch {}
}

function Save-Evidence {
    param([string]$Name, [string]$Data)
    $path = "$EvidenceDir\$(Get-Date -Format 'HHmmss')_$Name.txt"
    $Data | Out-File -FilePath $path -Encoding UTF8 -ErrorAction SilentlyContinue
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"

  ╔════════════════════════════════════════════════════════════╗
  ║        CCDC BLUE TEAM - BACKGROUND THREAT MONITOR         ║
  ║                                                            ║
  ║  Logs    : $LogFile
  ║  IPs     : $IPFile
  ║  Evidence: $EvidenceDir
  ║  AutoBlock: $AutoBlock                                     
  ╚════════════════════════════════════════════════════════════╝

  Watching every ${PollSeconds}s | Press CTRL+C to stop | Type 'ips' for IP summary

"@ -ForegroundColor Cyan

Write-Log -Severity "OK" -Message "Monitor started on $env:COMPUTERNAME by $env:USERNAME"

# Register CTRL+C handler to print IP summary on exit
[Console]::TreatControlCAsInput = $false
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Get-AttackerIPSummary
    Write-Log -Severity "OK" -Message "Monitor stopped."
}

$ticker = 0
while ($true) {
    Watch-SecurityEvents
    Watch-NetworkConnections
    Watch-BruteForce
    Watch-SuspiciousProcesses

    # WMI check is slower - only every 5 polls
    if ($ticker % 5 -eq 0) { Watch-WMISubscriptions }

    # Print IP summary every 10 polls
    if ($ticker % 10 -eq 0 -and $ticker -gt 0) { Get-AttackerIPSummary }

    $ticker++
    Start-Sleep -Seconds $PollSeconds
}
