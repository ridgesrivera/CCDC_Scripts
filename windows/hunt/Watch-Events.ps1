<#
.SYNOPSIS
    Watch-Events - live event-log alerting: who did what, and FROM WHICH IP. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Watch-Changes tells you WHAT changed since the baseline, every 15 minutes.
      This script tells you the moment it happens, who did it and where they
      logged on from, by reading the Windows event logs every few seconds.
      Leave it running in its own window on every box.

      An incident report without a source IP earns nothing, so for every
      alert that has no IP of its own (user created, group changed, task
      created...) the script looks up the logon session that made the change
      and prints the address that session came from.

    WHAT IT ALERTS ON
      Accounts    user created / enabled / deleted / password reset, group membership
                  changes, lockouts. RED when it touches a privileged group or a scored account
      Logons      RDP (4624 type 10, RDP 1149), OpenSSH logins (key-based = RED),
                  password guessing / spraying (many 4625 / 4771 from one address)
      Persistence scheduled task created (4698 / TaskScheduler 106), service installed
                  (4697 / 7045), suspicious command lines (4688 / Sysmon 1), a web
                  server or SQL Server spawning a shell (web shell / xp_cmdshell)
      Tampering   event log cleared (1102 / 104), audit policy removed (4719), Defender
                  turned off or exclusion added (5001 / 5007), firewall rule added /
                  deleted / profile changed, service set to Disabled (7040), shutdown (1074)
      AD (on DC)  DCSync (4662 replication by a non-DC account), Zerologon (5827-5831,
                  4742 by ANONYMOUS), Kerberoasting (many RC4 4769), AS-REP roasting
                  (4768 without pre-auth), GPO edited / linked (5136), AdminSDHolder or
                  domain ACL changed, new trust (4706), new computer account (4741),
                  DSRM password change (4794), DNS zone deleted (DNS audit 513)
      Credential  LSASS access (Sysmon 10 / 8), ntds.dit theft tools (vssadmin, ntdsutil,
      theft       diskshadow), reg save of SAM/SYSTEM, procdump / comsvcs MiniDump

    WHAT IT NEEDS
      Most rules need the audit policy from logging\Setup-Logging.ps1 (or
      harden\Harden-Baseline.ps1 -Only EnableAuditPolicy). Without it Windows
      simply does not write those events. 4688 rules also need "include command
      line in process creation events". Sysmon rules need Sysmon installed.
      Logs that do not exist on this box are skipped quietly.

    WHAT IT READS    Security, System, Defender, PowerShell, Firewall, TaskScheduler,
                     RDP, OpenSSH, Sysmon, DNS Server audit and Directory Service logs
    WHAT IT CHANGES  nothing on the system. Appends alerts to
                     C:\ccdc\alerts\alerts_<HOST>.csv (no secrets) plus its normal log.
    HOW TO UNDO      nothing to undo. Ctrl+C stops the loop.

    MANUAL EQUIVALENT
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4698; StartTime=(Get-Date).AddHours(-1)}
      Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | fl TimeCreated,Message
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | group {$_.Properties[19].Value} | sort Count -desc

.PARAMETER LookbackMinutes
    How far back the FIRST pass looks. Default 60 for a one-shot run, 10 with -Loop.

.PARAMETER Loop
    Keep polling every -IntervalSeconds until Ctrl+C.

.PARAMETER FailedLogonThreshold
    Failed logons from one address within 10 minutes before it is called guessing. Default 8.

.PARAMETER TrustedRanges
    Extra CIDRs that count as "ours" (added to subnet + adminSources from the config).

.PARAMETER IgnoreSubject
    Account names whose account-management events are not shown (e.g. your own
    admin account while you run Rotate-Passwords). Use sparingly: Red Team may
    be using the same account.

.PARAMETER ShowNetworkLogons
    Also show successful network (type 3) logons from outside the trusted ranges. Noisy on a DC.

.PARAMETER Beep
    Console beep on every RED alert.

.EXAMPLE
    .\Watch-Events.ps1 -Loop -Beep
.EXAMPLE
    .\Watch-Events.ps1 -LookbackMinutes 240 -OutFile C:\ccdc\reports\events.csv
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 10080)][int]$LookbackMinutes = -1,
    [switch]$Loop,
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 30,
    [ValidateRange(2, 1000)][int]$FailedLogonThreshold = 8,
    [string[]]$TrustedRanges = @(),
    [string[]]$IgnoreSubject = @(),
    [switch]$ShowNetworkLogons,
    [switch]$Beep,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Watch-Events' -OutFile $OutFile -ReadOnly
$config   = Get-CcdcConfig -Path $ConfigPath
$ranges   = Get-CcdcTrustedRanges -Config $config -Extra $TrustedRanges
$localIps = Get-CcdcLocalIps
$scored   = @(Get-CcdcScoredAccounts -Config $config | ForEach-Object { $_.ToLower() })
$isDC     = Test-CcdcIsDC
if ($LookbackMinutes -lt 0) { $LookbackMinutes = if ($Loop) { 10 } else { 60 } }

if ($ranges.Count -eq 0) {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'No trusted ranges (no config subnet/adminSources, no -TrustedRanges): cannot mark addresses as outside.'
} else {
    Write-Finding -Level INFO -Category 'Setup' -Message ("Trusted ranges: {0}" -f ($ranges -join ', '))
}

# ---------------------------------------------------------------------------
# What we query. One Get-WinEvent call per log, filtered by event ID + time.
# ---------------------------------------------------------------------------
$watch = [ordered]@{
    'Security' = @(1102, 4625, 4662, 4688, 4697, 4698, 4702, 4706, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733,
                   4740, 4741, 4742, 4756, 4757, 4768, 4769, 4771, 4794, 5136, 5137)
    'System'   = @(104, 1074, 7040, 7045, 5827, 5828, 5829, 5830, 5831)
    'Microsoft-Windows-Windows Defender/Operational' = @(1116, 1117, 5001, 5007, 5010, 5012, 5013)
    'Microsoft-Windows-PowerShell/Operational'       = @(4104)
    # Rule added/changed/deleted. Windows 11 / Server 2022+ renumbered them (2097/2099/2052).
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = @(2003, 2004, 2005, 2006, 2033, 2052, 2097, 2099)
    'Microsoft-Windows-TaskScheduler/Operational'    = @(106)
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = @(1149)
    'OpenSSH/Operational'                            = @(4)
    'Microsoft-Windows-Sysmon/Operational'           = @(1, 8, 10)
    'Microsoft-Windows-DNSServer/Audit'              = @(513, 516)
}
# Only keep logs that exist here (no Sysmon / OpenSSH / DNS role = no such log).
$activeLogs = @()
foreach ($log in $watch.Keys) {
    $info = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
    if ($info -and $info.IsEnabled) { $activeLogs += $log }
    elseif ($info) { Write-Finding -Level INFO -Category 'Setup' -Message "Log exists but is disabled: $log" -Detail "Enable: wevtutil sl `"$log`" /e:true" }
}
Write-Finding -Level INFO -Category 'Setup' -Message ("Watching {0} logs" -f $activeLogs.Count) -Detail ($activeLogs -join "`n")
$ap = (& auditpol.exe /get /subcategory:'{0CCE9235-69AE-11D9-BED3-505054503030}' /r 2>$null | Select-Object -Last 1)
if ($ap -and $ap -notmatch 'Success') {
    Write-Finding -Level YELLOW -Category 'Setup' -Message 'Audit policy "User Account Management" is not logging success: account rules will stay silent.' -Detail 'Fix: logging\Setup-Logging.ps1   or   harden\Harden-Baseline.ps1 -Only EnableAuditPolicy'
}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
$privGroupRegex = '(?i)(admin|operators|dnsadmins|group policy creator|remote desktop users|remote management users|schema|enterprise|cert publishers|hyper-v|key admins)'
# Command lines that are (almost) never legitimate on a competition box.
$badCmdRegex = '(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20}|frombase64string|downloadstring|downloadfile|invoke-webrequest.+-outfile|iex\s*\(|invoke-expression|invoke-mimikatz|mimikatz|sekurlsa|lsadump|rubeus|sharphound|bloodhound|certutil.+(-urlcache|-decode)|bitsadmin.+/transfer|mshta\s+(http|javascript|vbscript)|regsvr32.+/i:|rundll32.+(javascript|comsvcs.+minidump)|procdump.+lsass|vssadmin.+create\s+shadow|ntdsutil|diskshadow|wbadmin.+ntds|reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\(sam|system|security)|wevtutil(\.exe)?\s+cl\s|clear-eventlog|net1?(\.exe)?\s+(user|localgroup|group)\s.+/add|netsh.+(advfirewall|firewall).+(state\s+off|disable)|netsh.+portproxy.+add|set-mppreference.+(disable|exclusion)|add-mppreference|sc(\.exe)?\s+(create|config)\s.+binpath|schtasks(\.exe)?.+/create|\bnc(at)?(\.exe)?\s+.*-e\s|psexe(c|svc)|wmic.+process\s+call\s+create|new-localuser|add-localgroupmember|add-adgroupmember)'
# Parents that should never start a shell: if they do it is a web shell or SQL command execution.
$serverParentRegex = '(?i)\\(w3wp|php-cgi|php|httpd|nginx|tomcat\d*|java|sqlservr|mysqld|node)\.exe$'
$shellChildRegex   = '(?i)\\(cmd|powershell|pwsh|whoami|net1?|ipconfig|systeminfo|certutil|bitsadmin|cscript|wscript|mshta|rundll32|regsvr32|nltest|quser|tasklist)\.exe$'
$dcsyncGuids       = '(?i)(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c)'
$criticalSvcRegex  = '(?i)^(DNS|NTDS|Netlogon|kdc|W3SVC|WAS|sshd|TermService|LanmanServer|LanmanWorkstation|MSSQL.*|MySQL.*|ftpsvc|SMTPSVC|WinRM|WinDefend|EventLog|mpssvc|W32Time|DFSR|ADWS|Sysmon.*)$'
$sensitiveAdAttrs  = @('servicePrincipalName', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-AllowedToDelegateTo', 'sIDHistory', 'msDS-KeyCredentialLink', 'gPLink', 'scriptPath', 'userAccountControl')

# Rolling state for the "many small events = one attack" rules.
$failByIp   = @{}   # ip -> ArrayList of @{Time; User}
$rc4ByIp    = @{}   # ip -> ArrayList of @{Time; Service}
$lastTold   = @{}   # dedupe key -> last time we alerted
$script:alertCount = 0

function Test-Fresh([string]$key, [int]$quietSeconds = 300) {
    # $true if we have NOT alerted on this key within the quiet period (then remembers it).
    $now = Get-Date
    if ($lastTold.ContainsKey($key) -and ($now - $lastTold[$key]).TotalSeconds -lt $quietSeconds) { return $false }
    $lastTold[$key] = $now
    return $true
}

function Send-Alert {
    param([string]$Level, [string]$Rule, [string]$Message, [string]$User = '', [string]$Ip = '', [string]$Detail = '', $When)
    $t = if ($When) { [datetime]$When } else { Get-Date }
    $src = ''
    $ipClean = ''
    if ($Ip -match '^console') {
        $src = '  src=local console / service (no network address)'
    } elseif ($Ip) {
        $ipClean = ConvertTo-CcdcIp $Ip
        $class = Get-CcdcIpClass -Ip $ipClean -Ranges $ranges -LocalIps $localIps
        $src = "  src=$ipClean"
        if ($class -eq 'outside') { $src += ' (OUTSIDE team ranges)' }
        elseif ($class -eq 'local') { $src += ' (this machine)' }
    }
    Write-Finding -Level $Level -Category $Rule -Message ("{0} {1}: {2}{3}" -f $t.ToString('HH:mm:ss'), $Rule, $Message, $src) -Detail $Detail
    Write-CcdcAlert -Level $Level -Rule $Rule -User $User -SourceIp $ipClean -Detail "$Message $Detail" -Source 'Watch-Events' -Time $t
    $script:alertCount++
    if ($Beep -and $Level -eq 'RED') { try { [console]::Beep(1200, 250) } catch { $null = $_ } }
}

function Get-Short([string]$s, [int]$max = 300) {
    if (-not $s) { return '' }
    $s = ($s -replace '\s+', ' ').Trim()
    if ($s.Length -gt $max) { return $s.Substring(0, $max) + '...' }
    return $s
}

function Resolve-Sid([string]$sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount]).Value } catch { return $sid }
}

function Get-Who($d) {
    # "DOMAIN\user" of whoever performed the action.
    if ($d['SubjectUserName']) { return ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']) }
    return ''
}

function Test-Ignored($d) { return ($IgnoreSubject -and $IgnoreSubject -contains $d['SubjectUserName']) }

function Add-Rolling($table, [string]$key, $item) {
    if (-not $table.ContainsKey($key)) { $table[$key] = New-Object System.Collections.ArrayList }
    [void]$table[$key].Add($item)
}

# ---------------------------------------------------------------------------
# One event in -> zero or one alert out.
# ---------------------------------------------------------------------------
function Invoke-EventRule($e) {
    $d   = Get-CcdcEventData -Record $e
    $id  = [int]$e.Id
    $log = [string]$e.LogName
    $t   = $e.TimeCreated
    $who = Get-Who $d
    # Source address of the session that did it (only looked up for rules that use it).
    $bySession = { Get-CcdcLogonSource -LogonId $d['SubjectLogonId'] }

    if ($log -eq 'Security') {
        switch ($id) {
            1102 { Send-Alert RED 'LogCleared' ("Security log CLEARED by {0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']) -User $d['SubjectUserName'] -When $t; return }
            4720 {
                if (Test-Ignored $d) { return }
                Send-Alert RED 'UserCreated' ("account '{0}' created by {1}" -f $d['TargetUserName'], $who) -User $who -Ip (& $bySession) -When $t; return
            }
            4722 { if (Test-Ignored $d) { return }; Send-Alert YELLOW 'UserEnabled' ("account '{0}' enabled by {1}" -f $d['TargetUserName'], $who) -User $who -Ip (& $bySession) -When $t; return }
            { $_ -in 4724, 4725, 4726, 4740 } {
                if ($id -ne 4740 -and (Test-Ignored $d)) { return }
                $what = @{ 4724 = 'password RESET'; 4725 = 'DISABLED'; 4726 = 'DELETED'; 4740 = 'LOCKED OUT' }[$id]
                $rule = @{ 4724 = 'PasswordReset'; 4725 = 'UserDisabled'; 4726 = 'UserDeleted'; 4740 = 'Lockout' }[$id]
                $isScored = $scored -contains ([string]$d['TargetUserName']).ToLower()
                $lvl = if ($isScored -or $id -eq 4726) { 'RED' } else { 'YELLOW' }
                $msg = "account '{0}' {1} by {2}" -f $d['TargetUserName'], $what, $who
                if ($isScored) { $msg += '  <- SCORED ACCOUNT: the service check will fail' }
                # 4740: TargetDomainName holds the computer the bad passwords came from.
                $detail = if ($id -eq 4740) { "caller computer: $($d['TargetDomainName'])" } else { '' }
                Send-Alert $lvl $rule $msg -User $who -Ip $(if ($id -eq 4740) { '' } else { & $bySession }) -Detail $detail -When $t; return
            }
            { $_ -in 4728, 4732, 4756 } {
                if (Test-Ignored $d) { return }
                $member = if ($d['MemberName'] -and $d['MemberName'] -ne '-') { ($d['MemberName'] -split ',')[0] -replace '^CN=' } else { Resolve-Sid $d['MemberSid'] }
                $lvl = if ($d['TargetUserName'] -match $privGroupRegex) { 'RED' } else { 'YELLOW' }
                Send-Alert $lvl 'GroupAdd' ("'{0}' ADDED to group '{1}' by {2}" -f $member, $d['TargetUserName'], $who) -User $who -Ip (& $bySession) -When $t; return
            }
            { $_ -in 4729, 4733, 4757 } {
                if (Test-Ignored $d) { return }
                $member = if ($d['MemberName'] -and $d['MemberName'] -ne '-') { ($d['MemberName'] -split ',')[0] -replace '^CN=' } else { Resolve-Sid $d['MemberSid'] }
                Send-Alert YELLOW 'GroupRemove' ("'{0}' removed from group '{1}' by {2}" -f $member, $d['TargetUserName'], $who) -User $who -Ip (& $bySession) -When $t; return
            }
            { $_ -in 4698, 4702 } {
                # TaskContent is the task XML; pull out what it runs.
                $cmd = ''
                if ($d['TaskContent'] -match '(?s)<Command>(.*?)</Command>') { $cmd = $Matches[1] }
                if ($d['TaskContent'] -match '(?s)<Arguments>(.*?)</Arguments>') { $cmd += ' ' + $Matches[1] }
                $verb = if ($id -eq 4698) { 'CREATED' } else { 'updated' }
                $lvl = if ($id -eq 4698 -or $cmd -match $badCmdRegex) { 'RED' } else { 'YELLOW' }
                # Windows itself updates its own tasks all day: only show those when the action looks bad.
                if ($id -eq 4702 -and $d['TaskName'] -like '\Microsoft\*' -and $cmd -notmatch $badCmdRegex) { return }
                if (-not (Test-Fresh "task|$($d['TaskName'])|$id" 60)) { return }
                Send-Alert $lvl 'TaskCreated' ("scheduled task '{0}' {1} by {2}" -f $d['TaskName'], $verb, $who) -User $who -Ip (& $bySession) -Detail ("runs: {0}" -f (Get-Short $cmd)) -When $t; return
            }
            4697 {
                if (-not (Test-Fresh "svc|$($d['ServiceName'])" 60)) { return }
                Send-Alert RED 'ServiceInstalled' ("service '{0}' installed by {1}" -f $d['ServiceName'], $who) -User $who -Ip (& $bySession) -Detail ("binary: {0}  account: {1}" -f (Get-Short $d['ServiceFileName']), $d['ServiceAccount']) -When $t; return
            }
            4719 {
                # %%8448 / %%8450 = success / failure auditing REMOVED.
                if ($d['AuditPolicyChanges'] -match '8448|8450') {
                    Send-Alert RED 'AuditPolicy' ("audit policy REMOVED by {0} (subcategory {1})" -f $who, $d['SubcategoryGuid']) -User $who -Ip (& $bySession) -When $t
                }
                return
            }
            4742 {
                if ($d['SubjectUserSid'] -eq 'S-1-5-7' -or $d['SubjectUserName'] -match 'ANONYMOUS') {
                    Send-Alert RED 'Zerologon' ("computer account '{0}' changed by ANONYMOUS LOGON - Zerologon (CVE-2020-1472) signature" -f $d['TargetUserName']) -Detail 'Reset the DC machine account password twice and patch. See audit\Audit-Vulns.ps1.' -When $t
                }
                return
            }
            4741 { Send-Alert YELLOW 'ComputerCreated' ("computer account '{0}' created by {1}" -f $d['TargetUserName'], $who) -User $who -Ip (& $bySession) -Detail 'Ordinary users can add computers unless ms-DS-MachineAccountQuota is 0.' -When $t; return }
            4706 { Send-Alert RED 'TrustCreated' ("domain TRUST to '{0}' created by {1}" -f $d['DomainName'], $who) -User $who -Ip (& $bySession) -When $t; return }
            4794 { Send-Alert RED 'DsrmPassword' ("DSRM administrator password change attempted by {0}" -f $who) -User $who -Ip (& $bySession) -When $t; return }
            4662 {
                if ($d['Properties'] -notmatch $dcsyncGuids) { return }
                if ($d['SubjectUserName'] -match '\$$' -or $d['SubjectUserSid'] -eq 'S-1-5-18') { return }   # DCs replicate with their machine account
                if (-not (Test-Fresh "dcsync|$($d['SubjectUserName'])" 300)) { return }
                Send-Alert RED 'DCSync' ("directory REPLICATION requested by user {0} - DCSync: every password hash in the domain is being read" -f $who) -User $who -Ip (& $bySession) -Detail 'Disable the account, remove its replication rights (audit\Audit-AD-GPO.ps1), then harden\Reset-Krbtgt.ps1.' -When $t; return
            }
            4768 {
                # PreAuthType 0 = the DC handed out an AS-REP without proof of the password.
                if ($d['PreAuthType'] -ne '0' -or $d['TargetUserName'] -match '\$$') { return }
                if (-not (Test-Fresh "asrep|$($d['TargetUserName'])" 300)) { return }
                Send-Alert YELLOW 'AsRepRoast' ("TGT issued for '{0}' WITHOUT pre-authentication (AS-REP roastable)" -f $d['TargetUserName']) -User $d['TargetUserName'] -Ip $d['IpAddress'] -Detail 'Fix: harden\Harden-AD.ps1 -Only RequirePreAuth' -When $t; return
            }
            4769 {
                # RC4 (0x17) service tickets for user-run services are what Kerberoasting asks for.
                if ($d['TicketEncryptionType'] -ne '0x17' -or $d['ServiceName'] -match '\$$|^krbtgt$') { return }
                Add-Rolling $rc4ByIp (ConvertTo-CcdcIp $d['IpAddress']) @{ Time = $t; Service = $d['ServiceName']; User = $d['TargetUserName'] }
                return
            }
            { $_ -in 4625, 4771 } {
                $ip = ConvertTo-CcdcIp $d['IpAddress']
                if (-not $ip) { $ip = "host:$($d['WorkstationName'])" }
                Add-Rolling $failByIp $ip @{ Time = $t; User = $d['TargetUserName'] }
                return
            }
            4688 {
                $cmd = [string]$d['CommandLine']; $img = [string]$d['NewProcessName']; $parent = [string]$d['ParentProcessName']
                if ($parent -match $serverParentRegex -and $img -match $shellChildRegex) {
                    if (-not (Test-Fresh "spawn|$parent|$img|$cmd" 120)) { return }
                    Send-Alert RED 'ServerSpawnedShell' ("{0} started {1} as {2} - web shell or SQL command execution" -f (Split-Path $parent -Leaf), (Split-Path $img -Leaf), $who) -User $who -Detail (Get-Short $cmd) -When $t; return
                }
                if ($cmd -match $badCmdRegex) {
                    if ($cmd -like "*$($script:CcdcToolkitRoot)*") { return }   # our own scripts
                    if (-not (Test-Fresh "cmd|$cmd" 120)) { return }
                    Send-Alert RED 'SuspiciousCommand' ("{0} ran by {1}" -f (Split-Path $img -Leaf), $who) -User $who -Ip (& $bySession) -Detail (Get-Short $cmd) -When $t
                }
                return
            }
            { $_ -in 5136, 5137 } {
                if ($d['SubjectUserName'] -match '\$$') { return }   # replication / the DC itself
                $class = [string]$d['ObjectClass']; $dn = [string]$d['ObjectDN']; $attr = [string]$d['AttributeLDAPDisplayName']
                if ($id -eq 5137) {
                    if ($class -eq 'groupPolicyContainer') { Send-Alert RED 'GpoCreated' ("new GPO created by {0}" -f $who) -User $who -Ip (& $bySession) -Detail $dn -When $t }
                    elseif ($class -eq 'trustedDomain')    { Send-Alert RED 'TrustCreated' ("trust object created by {0}" -f $who) -User $who -Ip (& $bySession) -Detail $dn -When $t }
                    return
                }
                if ($class -eq 'groupPolicyContainer') {
                    if (-not (Test-Fresh "gpo|$dn" 120)) { return }
                    Send-Alert RED 'GpoChanged' ("GPO EDITED by {0}" -f $who) -User $who -Ip (& $bySession) -Detail ("{0}`nCompare with the backup: services\GroupPolicy.ps1 / audit\Audit-AD-GPO.ps1" -f $dn) -When $t; return
                }
                if ($dn -match '(?i)^CN=AdminSDHolder,' -or ($class -eq 'domainDNS' -and $attr -eq 'nTSecurityDescriptor')) {
                    if (-not (Test-Fresh "acl|$dn" 120)) { return }
                    Send-Alert RED 'AdAclChanged' ("permissions on {0} changed by {1} (AdminSDHolder / DCSync rights backdoor)" -f ($dn -split ',')[0], $who) -User $who -Ip (& $bySession) -Detail $dn -When $t; return
                }
                if ($sensitiveAdAttrs -contains $attr) {
                    # userAccountControl changes on every enable/disable; only the dangerous bits matter and 4738 covers those poorly, so show all but dedupe.
                    if (-not (Test-Fresh "attr|$dn|$attr" 120)) { return }
                    $lvl = if ($attr -in 'gPLink', 'sIDHistory', 'msDS-KeyCredentialLink', 'msDS-AllowedToActOnBehalfOfOtherIdentity') { 'RED' } else { 'YELLOW' }
                    Send-Alert $lvl 'AdAttrChanged' ("{0} changed on {1} by {2}" -f $attr, ($dn -split ',')[0], $who) -User $who -Ip (& $bySession) -Detail ("{0}`nvalue: {1}" -f $dn, (Get-Short $d['AttributeValue'] 160)) -When $t
                }
                return
            }
        }
        return
    }

    if ($log -eq 'System') {
        switch ($id) {
            104  { Send-Alert RED 'LogCleared' ("event log '{0}' CLEARED by {1}" -f $d['Channel'], $d['SubjectUserName']) -User $d['SubjectUserName'] -When $t; return }
            7045 {
                if (-not (Test-Fresh "svc|$($d['ServiceName'])" 60)) { return }
                $lvl = if ($d['ImagePath'] -match '(?i)(cmd(\.exe)?\s+/c|powershell|\\Users\\|\\Temp\\|\\ProgramData\\|%COMSPEC%|\\\\127\.0\.0\.1\\|ADMIN\$)') { 'RED' } else { 'YELLOW' }
                Send-Alert $lvl 'ServiceInstalled' ("service '{0}' installed (runs as {1})" -f $d['ServiceName'], $d['AccountName']) -Detail ("binary: {0}" -f (Get-Short $d['ImagePath'])) -When $t; return
            }
            7040 {
                # param1 display name, param2 old start type, param3 new start type, param4 service name
                if ($d['param3'] -notmatch '(?i)disabled') { return }
                $lvl = if ($d['param4'] -match $criticalSvcRegex) { 'RED' } else { 'YELLOW' }
                Send-Alert $lvl 'ServiceDisabled' ("service '{0}' ({1}) start type set to DISABLED" -f $d['param4'], $d['param1']) -Detail "Undo: Set-Service '$($d['param4'])' -StartupType Automatic; Start-Service '$($d['param4'])'" -When $t; return
            }
            1074 { Send-Alert RED 'Shutdown' ("shutdown/restart requested by {0} via {1}" -f $d['param7'], (Get-Short $d['param1'] 80)) -User $d['param7'] -Detail ("type: {0}  reason: {1}" -f $d['param5'], $d['param3']) -When $t; return }
            default {
                # 5827-5831: Netlogon denied / allowed a vulnerable secure channel connection.
                Send-Alert RED 'Zerologon' ("Netlogon event {0}: vulnerable secure channel connection from '{1}'" -f $id, $d['Data0']) -Detail (Get-Short $e.Message 200) -When $t; return
            }
        }
        return
    }

    switch -Wildcard ($log) {
        '*Windows Defender*' {
            if ($id -in 1116, 1117) {
                Send-Alert RED 'Malware' ("Defender detected {0}" -f $d['Threat Name']) -User $d['Detection User'] -Detail ("path: {0}`nprocess: {1}" -f (Get-Short $d['Path'] 200), $d['Process Name']) -When $t
            } elseif ($id -eq 5007) {
                $chg = "$($d['Old Value']) -> $($d['New Value'])"
                if ($chg -match '(?i)(Exclusions|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection|SpyNet|Real-Time Protection)') {
                    Send-Alert RED 'DefenderTamper' 'Defender configuration changed (exclusion added or protection switched off)' -Detail ("{0}`nCheck: Get-MpPreference | fl Exclusion*, Disable*   Fix: hunt\Remove-Persistence.ps1" -f (Get-Short $chg 250)) -When $t
                }
            } else {
                Send-Alert RED 'DefenderTamper' ("Defender protection DISABLED (event {0})" -f $id) -Detail 'Fix: Set-MpPreference -DisableRealtimeMonitoring $false   or   harden\Harden-Baseline.ps1 -Only EnableDefenderRealtime' -When $t
            }
            return
        }
        '*PowerShell*' {
            $text = [string]$d['ScriptBlockText']
            if ($d['Path'] -and $d['Path'] -like "$($script:CcdcToolkitRoot)*") { return }   # our own toolkit contains these words
            if ($text -notmatch $badCmdRegex) { return }
            $hit = $Matches[0]
            if (-not (Test-Fresh "ps|$($d['ScriptBlockId'])|$hit" 300)) { return }
            Send-Alert RED 'SuspiciousPowerShell' ("script block matched '{0}'" -f (Get-Short $hit 40)) -User (Resolve-Sid ([string]$e.UserId)) -Detail ("{0}`n{1}" -f $(if ($d['Path']) { "file: $($d['Path'])" } else { 'typed interactively / in memory' }), (Get-Short $text 240)) -When $t
            return
        }
        '*Firewall*' {
            if ($d['ModifyingApplication'] -match '(?i)\\svchost\.exe$' -and $id -notin 2003, 2033) { return }   # Windows managing app rules
            if ($id -eq 2033) { Send-Alert RED 'FirewallChanged' 'ALL firewall rules were deleted' -Detail "by: $($d['ModifyingApplication'])" -When $t; return }
            if ($id -eq 2003) { Send-Alert RED 'FirewallChanged' 'firewall PROFILE setting changed (on/off or default action)' -Detail ("{0}`nCheck: Get-NetFirewallProfile | ft Name,Enabled,DefaultInboundAction" -f (Get-Short $e.Message 200)) -When $t; return }
            $verb = if ($id -in 2004, 2097) { 'ADDED' } elseif ($id -in 2006, 2052) { 'DELETED' } else { 'modified' }
            if (-not (Test-Fresh "fw|$($d['RuleName'])|$verb" 30)) { return }
            # Action 2 = Block. A new inbound block rule on a scored port is sabotage that looks like "the service is flaky".
            $isBlock = ($d['Action'] -eq '2')
            $lvl = if ($isBlock -or $verb -eq 'DELETED') { 'RED' } else { 'YELLOW' }
            Send-Alert $lvl 'FirewallChanged' ("rule '{0}' {1}{2}" -f $d['RuleName'], $verb, $(if ($isBlock) { ' (BLOCK rule)' } else { '' })) -Detail ("ports: {0}  direction: {1}  by: {2}" -f $d['LocalPorts'], $(if ($d['Direction'] -eq '1') { 'in' } elseif ($d['Direction'] -eq '2') { 'out' } else { $d['Direction'] }), $d['ModifyingApplication']) -When $t
            return
        }
        '*TaskScheduler*' {
            if ($d['TaskName'] -like '\Microsoft\*') { return }
            if (-not (Test-Fresh "task|$($d['TaskName'])|4698" 60)) { return }   # already reported from the Security log
            Send-Alert RED 'TaskCreated' ("scheduled task '{0}' registered by {1}" -f $d['TaskName'], $d['UserContext']) -User $d['UserContext'] -Detail 'Inspect / remove: hunt\Remove-Persistence.ps1' -When $t
            return
        }
        '*TerminalServices*' {
            $class = Get-CcdcIpClass -Ip $d['Param3'] -Ranges $ranges -LocalIps $localIps
            if (-not (Test-Fresh "rdp|$($d['Param1'])|$($d['Param3'])" 120)) { return }
            Send-Alert $(if ($class -eq 'outside') { 'RED' } else { 'YELLOW' }) 'RdpLogon' ("RDP connection authenticated as {0}\{1}" -f $d['Param2'], $d['Param1']) -User $d['Param1'] -Ip $d['Param3'] -When $t
            return
        }
        'OpenSSH*' {
            $p = [string]$d['payload']; if (-not $p) { $p = [string]$e.Message }
            if ($p -match 'Accepted (\S+) for (\S+) from (\S+)') {
                $method = $Matches[1]; $user = $Matches[2]; $ip = $Matches[3]
                # Key-based logins never need the password you just rotated.
                $lvl = if ($method -eq 'publickey') { 'RED' } else { 'YELLOW' }
                Send-Alert $lvl 'SshLogon' ("SSH login as {0} using {1}" -f $user, $method) -User $user -Ip $ip -Detail $(if ($method -eq 'publickey') { 'Keys: C:\ProgramData\ssh\administrators_authorized_keys and C:\Users\*\.ssh\authorized_keys' } else { '' }) -When $t
            } elseif ($p -match 'Failed \S+ for (invalid user )?(\S+) from (\S+)') {
                Add-Rolling $failByIp $Matches[3] @{ Time = $t; User = $Matches[2] }
            }
            return
        }
        '*Sysmon*' {
            if ($id -eq 1) {
                $cmd = [string]$d['CommandLine']; $img = [string]$d['Image']; $parent = [string]$d['ParentImage']
                if ($parent -match $serverParentRegex -and $img -match $shellChildRegex) {
                    if (-not (Test-Fresh "spawn|$parent|$img|$cmd" 120)) { return }
                    Send-Alert RED 'ServerSpawnedShell' ("{0} started {1} as {2} - web shell or SQL command execution" -f (Split-Path $parent -Leaf), (Split-Path $img -Leaf), $d['User']) -User $d['User'] -Detail (Get-Short $cmd) -When $t
                } elseif ($cmd -match $badCmdRegex -and $cmd -notlike "*$($script:CcdcToolkitRoot)*") {
                    if (-not (Test-Fresh "cmd|$cmd" 120)) { return }
                    Send-Alert RED 'SuspiciousCommand' ("{0} ran by {1}" -f (Split-Path $img -Leaf), $d['User']) -User $d['User'] -Detail (Get-Short $cmd) -When $t
                }
            } elseif ($d['TargetImage'] -match '(?i)\\lsass\.exe$') {
                # 8 = CreateRemoteThread into LSASS, 10 = process opened LSASS memory.
                if ($d['SourceImage'] -match '(?i)\\(MsMpEng|MsSense|svchost|csrss|wininit|lsm|services|wmiprvse|vmtoolsd|taskmgr|Sysmon(64)?|lsass)\.exe$') { return }
                if ($id -eq 10 -and $d['GrantedAccess'] -notmatch '(?i)^0x(1010|1410|1438|143a|1fffff|1f1fff|1f3fff)$') { return }
                if (-not (Test-Fresh "lsass|$($d['SourceImage'])" 300)) { return }
                Send-Alert RED 'LsassAccess' ("{0} opened LSASS memory (credential dumping)" -f $d['SourceImage']) -User $d['SourceUser'] -Detail "access mask: $($d['GrantedAccess'])" -When $t
            }
            return
        }
        '*DNSServer*' {
            # 513 = zone deleted, 516 = record deleted (Microsoft-Windows-DNSServer/Audit).
            $lvl = if ($id -eq 513) { 'RED' } else { 'YELLOW' }
            if ($id -eq 516 -and -not (Test-Fresh "dnsdel|$($e.Message)" 60)) { return }
            Send-Alert $lvl 'DnsChanged' (Get-Short $e.Message 160) -Detail 'Restore from the export: services\DNS.ps1 -Action Restore' -When $t
            return
        }
    }
}

function Invoke-RollingRules {
    # Password guessing / spraying and Kerberoasting are many small events; judge them together.
    # Live: a sliding 10-minute window. One-shot: the whole lookback period.
    $cut = if ($Loop) { (Get-Date).AddMinutes(-10) } else { $script:firstSince }
    foreach ($ip in @($failByIp.Keys)) {
        $recent = @($failByIp[$ip] | Where-Object { $_.Time -gt $cut })
        if ($recent.Count -eq 0) { $failByIp.Remove($ip); continue }
        $failByIp[$ip] = New-Object System.Collections.ArrayList (, $recent)
        if ($recent.Count -lt $FailedLogonThreshold) { continue }
        if (-not (Test-Fresh "fail|$ip" 300)) { continue }
        $users = @($recent | ForEach-Object { $_.User } | Sort-Object -Unique)
        $kind = if ($users.Count -ge 5) { 'password SPRAY' } else { 'password guessing' }
        Send-Alert RED 'FailedLogons' ("{0}: {1} failed logons since {3} against {2} account(s)" -f $kind, $recent.Count, $users.Count, $cut.ToString('HH:mm')) -Ip ($ip -replace '^host:', '') -Detail ("accounts: {0}" -f (($users | Select-Object -First 12) -join ', '))
    }
    foreach ($ip in @($rc4ByIp.Keys)) {
        $recent = @($rc4ByIp[$ip] | Where-Object { $_.Time -gt $cut })
        if ($recent.Count -eq 0) { $rc4ByIp.Remove($ip); continue }
        $rc4ByIp[$ip] = New-Object System.Collections.ArrayList (, $recent)
        $svcs = @($recent | ForEach-Object { $_.Service } | Sort-Object -Unique)
        if ($svcs.Count -lt 3) { continue }
        if (-not (Test-Fresh "roast|$ip" 600)) { continue }
        Send-Alert RED 'Kerberoast' ("RC4 service tickets for {0} different service accounts requested by {1}" -f $svcs.Count, $recent[0].User) -User $recent[0].User -Ip $ip -Detail ("services: {0}`nRotate those accounts to long random passwords: harden\Rotate-Passwords.ps1" -f (($svcs | Select-Object -First 10) -join ', '))
    }
}

function Get-NewEvents([datetime]$since) {
    $all = New-Object System.Collections.ArrayList
    foreach ($log in $activeLogs) {
        # The event log service rejects queries with more than ~20 event IDs, so ask in chunks.
        $ids = @($watch[$log])
        for ($i = 0; $i -lt $ids.Count; $i += 15) {
            $chunk = @($ids[$i..([Math]::Min($i + 14, $ids.Count - 1))])
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $chunk; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop
                foreach ($x in $ev) { [void]$all.Add($x) }
            } catch {
                # "No events were found" is the normal quiet case.
                if ($_.Exception.Message -notmatch 'No events were found' -and $_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                    if (Test-Fresh "logerr|$log" 900) { Write-Finding -Level INFO -Category 'Setup' -Message "Could not read $log" -Detail $_.Exception.Message }
                }
            }
        }
    }
    # Successful logons are far too many to pull by ID on a DC, so ask the log for only the types we care about.
    $types = @("Data[@Name='LogonType']='10'")
    if ($ShowNetworkLogons) { $types += "Data[@Name='LogonType']='3'" }
    $utc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    try {
        $xp = "*[System[EventID=4624 and TimeCreated[@SystemTime>='$utc']] and EventData[$($types -join ' or ')]]"
        foreach ($x in (Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 5000 -ErrorAction Stop)) { [void]$all.Add($x) }
    } catch { $null = $_ }
    return @($all | Sort-Object TimeCreated)
}

function Invoke-LogonRule($e) {
    $d = Get-CcdcEventData -Record $e
    $class = Get-CcdcIpClass -Ip $d['IpAddress'] -Ranges $ranges -LocalIps $localIps
    $user = "{0}\{1}" -f $d['TargetDomainName'], $d['TargetUserName']
    if ($d['LogonType'] -eq '10') {
        if (-not (Test-Fresh "rdp|$($d['TargetUserName'])|$(ConvertTo-CcdcIp $d['IpAddress'])" 120)) { return }
        Send-Alert $(if ($class -eq 'outside') { 'RED' } else { 'YELLOW' }) 'RdpLogon' ("RDP logon as {0}" -f $user) -User $user -Ip $d['IpAddress'] -When $e.TimeCreated
    } elseif ($class -eq 'outside' -and $d['TargetUserName'] -notmatch '\$$|^ANONYMOUS LOGON$') {
        if (-not (Test-Fresh "net|$($d['TargetUserName'])|$(ConvertTo-CcdcIp $d['IpAddress'])" 600)) { return }
        Send-Alert YELLOW 'NetworkLogon' ("network logon as {0} ({1})" -f $user, $d['AuthenticationPackageName']) -User $user -Ip $d['IpAddress'] -Detail 'Could be the scoring engine. An ADMIN account here is not.' -When $e.TimeCreated
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$since = (Get-Date).AddMinutes(-$LookbackMinutes)
$script:firstSince = $since
# Record IDs already handled, so the small overlap between polls never alerts twice.
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
if (-not $isDC) { Write-Finding -Level INFO -Category 'Setup' -Message 'Not a DC: the AD rules (DCSync, roasting, GPO edits) only fire on domain controllers. Run this there too.' }
try {
    do {
        $pollStart = Get-Date
        Write-Section ("Events since {0}" -f $since.ToString('HH:mm:ss'))
        $before = $script:alertCount
        foreach ($e in (Get-NewEvents $since)) {
            if (-not $seen.Add(("{0}|{1}" -f $e.LogName, $e.RecordId))) { continue }
            try {
                if ($e.Id -eq 4624 -and $e.LogName -eq 'Security') { Invoke-LogonRule $e } else { Invoke-EventRule $e }
            } catch { Write-CcdcLog "rule error on event $($e.Id): $($_.Exception.Message)" 'ERROR' }
        }
        Invoke-RollingRules
        if ($seen.Count -gt 100000) { $seen.Clear() }
        if ($script:alertCount -eq $before) { Write-Host ("  [OK] {0} nothing new" -f (Get-Date -Format 'HH:mm:ss')) -ForegroundColor DarkGreen }
        # Next poll starts where this one began, so nothing written during the poll is missed.
        $since = $pollStart.AddSeconds(-2)
        if ($Loop) { Start-Sleep -Seconds $IntervalSeconds }
    } while ($Loop)
} finally {
    Write-Finding -Level INFO -Category 'Summary' -Message ("{0} alert(s). Saved to {1}\alerts_{2}.csv" -f $script:alertCount, $script:CcdcAlertRoot, $env:COMPUTERNAME) -Detail 'Turn them into an incident report: hunt\New-IncidentReport.ps1'
    Complete-Ccdc
}
