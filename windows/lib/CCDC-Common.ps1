<#
=============================================================================
 CCDC-Common.ps1  -  shared helpers for every script in windows\
=============================================================================
 PURPOSE
   One place for the boring-but-important plumbing so every script behaves
   the same way:
     * colour-coded findings   RED = likely malicious / critical
                               YELLOW = review
                               GREEN = ok
     * a timestamped change log in C:\ccdc\logs\  (actions only, NEVER secrets)
     * optional report file (-OutFile)
     * dry-run + per-action confirmation for anything that changes state
     * "back up before you change it" helpers for files and registry keys
     * reading config\ccdc.json (optional) for IPs / scored ports

 HOW IT IS USED
   Each script does:   . "$PSScriptRoot\..\lib\CCDC-Common.ps1"
   The leading dot means "dot-source": run this file inside MY scope so its
   functions become available to me. Nothing here runs on its own.

 WHAT IT READS   : config\ccdc.json (only if you created it)
 WHAT IT CHANGES : creates C:\ccdc\logs and C:\ccdc\backups, appends to log files
 HOW TO UNDO     : delete C:\ccdc\ (only our own logs/backups live there)

 WHY NO Start-Transcript?
   A transcript records EVERYTHING printed to the console. The password
   rotation script prints new passwords once on screen - a transcript would
   write them to disk, and the Red Team loves finding those files. So we log
   explicit, hand-picked messages instead.

 PSScriptAnalyzer note: PSAvoidUsingWriteHost is intentionally ignored in
 this toolkit. These are interactive console tools; Write-Host is the only
 way to get coloured output on Windows PowerShell 5.1.
=============================================================================
#>

# ---------------------------------------------------------------------------
# Paths. Kept short and predictable so teammates can find them under pressure.
# ---------------------------------------------------------------------------
$script:CcdcRoot      = 'C:\ccdc'
$script:CcdcLogRoot   = Join-Path $script:CcdcRoot 'logs'
$script:CcdcBackupRoot= Join-Path $script:CcdcRoot 'backups'
$script:CcdcStamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:CcdcLogFile   = $null
$script:CcdcOutFile   = $null
# ArrayList so .Add() is cheap; "+=" on arrays copies the whole array each time.
$script:CcdcFindings  = New-Object System.Collections.ArrayList
$script:CcdcToolkitRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# ^ Inside this file $PSScriptRoot is windows\lib; two levels up is the repo root.

function Initialize-Ccdc {
    <#
      Call once at the top of a script. Creates the log file and prints a banner.
      -ScriptName  short name used in the log file name
      -OutFile     optional report path (.csv = CSV, anything else = text)
      -ReadOnly    just prints a "READ-ONLY" badge so students see the contract
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [string]$OutFile,
        [switch]$ReadOnly
    )
    foreach ($d in @($script:CcdcRoot, $script:CcdcLogRoot)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force -WhatIf:$false | Out-Null }
    }
    $script:CcdcLogFile = Join-Path $script:CcdcLogRoot ("{0}_{1}_{2}.log" -f $ScriptName, $env:COMPUTERNAME, $script:CcdcStamp)
    $script:CcdcOutFile = $OutFile

    $mode = if ($ReadOnly) { 'READ-ONLY (changes nothing)' } elseif ($WhatIfPreference) { 'DRY RUN (-WhatIf): nothing will change' } else { 'CHANGES STATE (dry-run with -WhatIf)' }
    $line = '=' * 72
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0}   [{1}]" -f $ScriptName, $mode) -ForegroundColor Cyan
    Write-Host ("  Host: {0}   User: {1}   {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date)) -ForegroundColor DarkGray
    Write-Host ("  Log : {0}" -f $script:CcdcLogFile) -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor Cyan

    Write-CcdcLog "START $ScriptName mode=$mode host=$env:COMPUTERNAME user=$env:USERDOMAIN\$env:USERNAME"
    if (-not (Test-CcdcIsAdmin)) {
        Write-Finding -Level YELLOW -Category 'Setup' -Message 'Not running elevated - many checks will be incomplete. Use "Run as Administrator".'
    }
}

function Write-CcdcLog {
    # Appends one line to the run log. Callers must NEVER pass secrets here.
    param([string]$Message, [string]$Level = 'INFO')
    if (-not $script:CcdcLogFile) { return }
    $entry = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    # -WhatIf:$false - our own log is not a system change, so it is written even during a dry run.
    Add-Content -Path $script:CcdcLogFile -Value $entry -ErrorAction SilentlyContinue -WhatIf:$false
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host (("--- {0} " -f $Title).PadRight(72, '-')) -ForegroundColor Magenta
    Write-CcdcLog "SECTION $Title"
}

function Write-Finding {
    <#
      The ONE way scripts report results. Colour + log + report in one call.
        RED    = likely malicious or critical misconfig - act now
        YELLOW = review; could be legit, could be bad
        GREEN  = checked and looks ok
        INFO   = plain information (inventory)
    #>
    param(
        [ValidateSet('RED', 'YELLOW', 'GREEN', 'INFO')][string]$Level = 'INFO',
        [string]$Category = '',
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Detail = ''
    )
    $color = @{ RED = 'Red'; YELLOW = 'Yellow'; GREEN = 'Green'; INFO = 'Gray' }[$Level]
    $tag   = @{ RED = '[!!]'; YELLOW = '[??]'; GREEN = '[OK]'; INFO = '[..]' }[$Level]
    Write-Host ("  {0} {1}" -f $tag, $Message) -ForegroundColor $color
    # Multi-line details (separated by "`n") are each indented under the finding.
    if ($Detail) { foreach ($dl in ($Detail -split "`n")) { Write-Host ("       {0}" -f $dl.TrimEnd()) -ForegroundColor DarkGray } }

    [void]$script:CcdcFindings.Add([pscustomobject]@{
        Time = (Get-Date -Format 'HH:mm:ss'); Level = $Level; Category = $Category
        Message = $Message; Detail = $Detail; Host = $env:COMPUTERNAME
    })
    if ($Level -ne 'INFO') { Write-CcdcLog ("{0} {1}: {2} {3}" -f $Level, $Category, $Message, $Detail) $Level }
}

function Complete-Ccdc {
    # Prints a RED/YELLOW/GREEN tally and writes the -OutFile report if asked.
    $red    = @($script:CcdcFindings | Where-Object Level -eq 'RED').Count
    $yellow = @($script:CcdcFindings | Where-Object Level -eq 'YELLOW').Count
    $green  = @($script:CcdcFindings | Where-Object Level -eq 'GREEN').Count
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "  SUMMARY  " -NoNewline -ForegroundColor Cyan
    Write-Host "RED: $red  " -NoNewline -ForegroundColor Red
    Write-Host "YELLOW: $yellow  " -NoNewline -ForegroundColor Yellow
    Write-Host "GREEN: $green" -ForegroundColor Green
    if ($script:CcdcOutFile) {
        try {
            $parent = Split-Path -Parent $script:CcdcOutFile
            if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force -WhatIf:$false | Out-Null }
            if ($script:CcdcOutFile -like '*.csv') {
                $script:CcdcFindings | Export-Csv -Path $script:CcdcOutFile -NoTypeInformation -WhatIf:$false
            } else {
                $script:CcdcFindings | Format-Table -AutoSize -Wrap Time, Level, Category, Message, Detail |
                    Out-String -Width 250 | Out-File -FilePath $script:CcdcOutFile -Encoding UTF8 -WhatIf:$false
            }
            Write-Host "  Report: $($script:CcdcOutFile)" -ForegroundColor DarkGray
        } catch { Write-Host "  Could not write report: $_" -ForegroundColor Yellow }
    }
    Write-Host "  Log   : $($script:CcdcLogFile)" -ForegroundColor DarkGray
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-CcdcLog "END red=$red yellow=$yellow green=$green"
}

# ---------------------------------------------------------------------------
# Change control: the heart of "audit vs change are separate".
# ---------------------------------------------------------------------------
function Invoke-CcdcChange {
    <#
      Wraps every state-changing action in a harden script:
        1. -WhatIf  -> print what WOULD happen, change nothing  (dry run)
        2. no -Force -> ask "y/N" for THIS action
        3. run it, log success/failure (never log secrets)
      -Cmdlet  pass $PSCmdlet from a script with [CmdletBinding(SupportsShouldProcess)]
      -Undo    a human-readable undo hint written to the log for rollback
      Returns $true if the action ran successfully.
    #>
    param(
        [Parameter(Mandatory = $true)]$Cmdlet,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [switch]$Force,
        [string]$Undo = ''
    )
    # ShouldProcess returns $false under -WhatIf (and prints "What if: ...").
    if (-not $Cmdlet.ShouldProcess($Target, $Action)) {
        Write-CcdcLog "WHATIF $Action on $Target"
        return $false
    }
    if (-not $Force) {
        $answer = Read-Host ("  >> {0} on [{1}]? (y/N)" -f $Action, $Target)
        if ($answer -notmatch '^(y|yes)$') {
            Write-Host "     skipped" -ForegroundColor DarkGray
            Write-CcdcLog "SKIPPED $Action on $Target"
            return $false
        }
    }
    try {
        # 'Stop' turns non-terminating cmdlet errors into exceptions so the
        # catch below sees them. (Native .exe tools never throw - scriptblocks
        # that call reg.exe / auditpol.exe must check $LASTEXITCODE and throw.)
        # GOTCHA for authors: the scriptblock runs inside this function, so
        # variables named $Target/$Action/$Force/$Undo/$Cmdlet/$ScriptBlock
        # refer to THIS function's parameters. Use other names in callers.
        $ErrorActionPreference = 'Stop'
        & $ScriptBlock
        Write-Host ("     done: {0} -> {1}" -f $Action, $Target) -ForegroundColor Green
        Write-CcdcLog ("CHANGED {0} on {1}{2}" -f $Action, $Target, $(if ($Undo) { " | UNDO: $Undo" } else { '' })) 'CHANGE'
        return $true
    } catch {
        Write-Host ("     FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-CcdcLog ("FAILED {0} on {1}: {2}" -f $Action, $Target, $_.Exception.Message) 'ERROR'
        return $false
    }
}

function Get-CcdcBackupDir {
    # One backup folder per script run: C:\ccdc\backups\<stamp>\
    $dir = Join-Path $script:CcdcBackupRoot $script:CcdcStamp
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    return $dir
}

function Backup-CcdcFile {
    # Copies a file/folder into the run's backup folder, preserving its path
    # (C:\inetpub\x\wp-config.php -> ...\backups\<stamp>\C\inetpub\x\wp-config.php)
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $rel  = ($Path -replace ':', '') -replace '^\\+', ''
    $dest = Join-Path (Get-CcdcBackupDir) $rel
    $destParent = Split-Path -Parent $dest
    if (-not (Test-Path $destParent)) { New-Item -ItemType Directory -Path $destParent -Force -WhatIf:$false | Out-Null }
    Copy-Item -LiteralPath $Path -Destination $dest -Recurse -Force -WhatIf:$false
    Write-CcdcLog "BACKUP $Path -> $dest" 'BACKUP'
    return $dest
}

function Backup-CcdcRegistry {
    # reg.exe export is used (not PowerShell) because the .reg file can be
    # re-imported with a double-click or "reg import FILE" to undo.
    param([Parameter(Mandatory = $true)][string]$Key)   # e.g. HKLM\SYSTEM\...\LanmanServer\Parameters
    $safe = ($Key -replace '[\\/:*?"<>| ]', '_')
    if ($safe.Length -gt 120) { $safe = $safe.Substring($safe.Length - 120) }
    $dest = Join-Path (Get-CcdcBackupDir) ("reg_{0}.reg" -f $safe)
    $null = & reg.exe export $Key $dest /y 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-CcdcLog "BACKUP registry $Key -> $dest (undo: reg import `"$dest`")" 'BACKUP'
        return $dest
    }
    Write-CcdcLog "BACKUP registry $Key skipped (key does not exist)" 'BACKUP'
    return $null
}

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
function Test-CcdcIsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CcdcDomainRole {
    # Win32_ComputerSystem.DomainRole: 0/1 workstation, 2/3 member server, 4/5 DC
    $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs) { return $null }
    return [int]$cs.DomainRole
}

function Test-CcdcIsDC { return ((Get-CcdcDomainRole) -ge 4) }

function Test-CcdcModule {
    # Import a module if it exists; return $true/$false. Never throws.
    # Used for ActiveDirectory / GroupPolicy / DnsServer / WebAdministration.
    param([Parameter(Mandatory = $true)][string]$Name)
    if (Get-Module -Name $Name) { return $true }
    if (Get-Module -ListAvailable -Name $Name) {
        try { Import-Module $Name -ErrorAction Stop -WarningAction SilentlyContinue; return $true } catch { return $false }
    }
    return $false
}

function Get-CcdcConfig {
    <#
      Loads the toolkit config. Search order:
        1. -Path you pass
        2. <repo>\config\ccdc.json            (your competition copy, gitignored)
      Returns $null if nothing is found (scripts must still work without it).
    #>
    param([string]$Path)
    $candidates = @()
    if ($Path) { $candidates += $Path }
    $candidates += (Join-Path $script:CcdcToolkitRoot 'config\ccdc.json')
    # No fallback to the practice-lab example: a competition box must never load lab settings.
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            try {
                $cfg = Get-Content -Raw -Path $c | ConvertFrom-Json
                Write-CcdcLog "CONFIG loaded $c"
                return $cfg
            } catch { Write-Host "  Config $c is not valid JSON: $_" -ForegroundColor Yellow }
        }
    }
    return $null
}

function Get-CcdcHostConfig {
    # Finds this machine's entry in the config by hostname (case-insensitive).
    param($Config, [string]$Name = $env:COMPUTERNAME)
    if (-not $Config -or -not $Config.hosts) { return $null }
    return ($Config.hosts | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
}

function Get-CcdcScoredAccounts {
    # Every scoredAccounts entry across the config - rotation scripts skip these.
    param($Config)
    if (-not $Config -or -not $Config.hosts) { return @() }
    return @($Config.hosts | ForEach-Object { $_.scoredAccounts } | Where-Object { $_ } | Sort-Object -Unique)
}

function Get-CcdcAuditPolicyPlan {
    <#
      The audit subcategories we turn on (used by Harden-Walkthrough and
      Setup-Logging so both agree). GUIDs are used instead of names because
      auditpol subcategory NAMES are localised on non-English Windows.
    #>
    return @(
        @{ Name = 'Credential Validation';        Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Kerberos Authentication Service'; Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Kerberos Service Ticket Operations'; Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'User Account Management';      Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Security Group Management';    Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Computer Account Management';  Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Process Creation';             Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Logon';                        Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Logoff';                       Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Special Logon';                Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Other Object Access Events';   Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}' },  # scheduled tasks (4698)
        @{ Name = 'Security System Extension';    Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}' },  # new services (4697)
        @{ Name = 'Audit Policy Change';          Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Directory Service Changes';    Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}' },
        @{ Name = 'Directory Service Access';     Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}' },  # DCSync (4662)
        @{ Name = 'Sensitive Privilege Use';      Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}' }
    )
}

function Test-CcdcTranscriptionOn {
    # If PowerShell Transcription is forced by GPO, everything printed on screen
    # (including passwords we display once) is written to disk. Detect it.
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    return ($v -and $v.EnableTranscripting -eq 1)
}

# ---------------------------------------------------------------------------
# Hunt helpers: event parsing, "is this IP ours?", alerts, evidence, quarantine.
# Used by hunt\Find-Attacks, hunt\Remove-Persistence, hunt\Kick-Block
# and hunt\New-IncidentReport so they all write to the same places:
#   C:\ccdc\alerts\alerts_<HOST>.csv        one row per alert (time, rule, user, source IP)
#   C:\ccdc\evidence\evidence_<HOST>.jsonl  one JSON object per thing we removed
#   C:\ccdc\quarantine\<stamp>\             files moved out of harm's way
# An incident report without a source IP earns nothing, so every helper here
# tries to keep the IP next to the finding.
# ---------------------------------------------------------------------------
$script:CcdcAlertRoot      = Join-Path $script:CcdcRoot 'alerts'
$script:CcdcEvidenceRoot   = Join-Path $script:CcdcRoot 'evidence'
$script:CcdcQuarantineRoot = Join-Path $script:CcdcRoot 'quarantine'

function Get-CcdcEventData {
    <#
      Turns one event record (from Get-WinEvent) into a hashtable of its named
      fields, e.g. $d.TargetUserName, $d.IpAddress. We read the event XML
      instead of the rendered Message because the XML field names are the same
      on every language of Windows and do not need parsing with regexes.
    #>
    param([Parameter(Mandatory = $true)]$Record)
    $d = @{}
    try { $x = [xml]$Record.ToXml() } catch { return $d }
    $i = 0
    foreach ($n in $x.SelectNodes("//*[local-name()='EventData']/*")) {
        $name = $n.GetAttribute('Name')
        if (-not $name) { $name = "Data$i" }
        $d[$name] = $n.InnerText
        $i++
    }
    # A few events (log cleared 1102/104, RDP 1149) use <UserData> instead.
    foreach ($n in $x.SelectNodes("//*[local-name()='UserData']//*[not(*)]")) { $d[$n.LocalName] = $n.InnerText }
    return $d
}

function ConvertTo-CcdcIp {
    # Normalises the address formats event logs use: '-', '::ffff:10.0.0.5', '10.0.0.5:51234'.
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text.Trim()
    if ($t -eq '-' -or $t -eq 'LOCAL') { return '' }
    $t = $t -replace '^::ffff:', ''
    if ($t -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { $t = $Matches[1] }
    return $t
}

function Test-CcdcIpInCidr {
    # $true if $Ip is inside $Cidr ("192.168.220.0/24"; a bare address means that one host).
    param([string]$Ip, [string]$Cidr)
    try {
        $addr  = [System.Net.IPAddress]::Parse($Ip)
        $parts = $Cidr -split '/'
        $net   = [System.Net.IPAddress]::Parse($parts[0])
        if ($addr.AddressFamily -ne $net.AddressFamily) { return $false }
        $a = $addr.GetAddressBytes(); $n = $net.GetAddressBytes()
        $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { $a.Length * 8 }
        for ($i = 0; $i -lt $a.Length; $i++) {
            # How many bits of this byte belong to the network part (8, then fewer, then 0).
            $take = [Math]::Min(8, [Math]::Max(0, $bits - (8 * $i)))
            if ($take -eq 0) { break }
            $mask = (0xFF -shl (8 - $take)) -band 0xFF
            if (($a[$i] -band $mask) -ne ($n[$i] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Get-CcdcTrustedRanges {
    # Our own ranges: config subnet + adminSources. Everything else is "outside".
    param($Config, [string[]]$Extra = @())
    $r = @($Extra)
    if ($Config) {
        if ($Config.subnet) { $r += [string]$Config.subnet }
        foreach ($a in @($Config.adminSources)) { if ($a) { $r += [string]$a } }
    }
    return @($r | Where-Object { $_ } | Sort-Object -Unique)
}

function Get-CcdcLocalIps {
    # This machine's own addresses (so "connection from myself" is not an alert).
    $ips = @('127.0.0.1', '::1')
    try {
        foreach ($nic in (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)) { $ips += @($nic.IPAddress) }
    } catch { $null = $_ }
    return @($ips | Where-Object { $_ } | Sort-Object -Unique)
}

function Get-CcdcIpClass {
    <#
      'local'   = empty / loopback / this machine
      'trusted' = inside the team ranges from the config (or -Ranges)
      'outside' = anything else. NOT automatically Red Team: the scoring engine
                  and customers also come from outside. But an admin logon,
                  RDP session or new account from 'outside' deserves a look.
      'unknown' = no ranges configured, so we cannot tell
    #>
    param([string]$Ip, [string[]]$Ranges = @(), [string[]]$LocalIps = @())
    $ip2 = ConvertTo-CcdcIp $Ip
    if (-not $ip2 -or $ip2 -match '^(127\.|::1$|fe80:)' -or $LocalIps -contains $ip2) { return 'local' }
    if (-not $Ranges -or $Ranges.Count -eq 0) { return 'unknown' }
    foreach ($c in $Ranges) { if (Test-CcdcIpInCidr -Ip $ip2 -Cidr $c) { return 'trusted' } }
    return 'outside'
}

function Write-CcdcAlert {
    <#
      Appends one row to C:\ccdc\alerts\alerts_<HOST>.csv. This file is the
      shared "what did we see, when, from where" record: the scheduled
      Watch-Changes writes to it,
      and New-IncidentReport reads it. Never pass secrets in -Detail.
    #>
    param(
        [string]$Level = 'YELLOW', [Parameter(Mandatory = $true)][string]$Rule,
        [string]$User = '', [string]$SourceIp = '', [string]$Detail = '',
        [string]$Source = '', [datetime]$Time = (Get-Date)
    )
    try {
        if (-not (Test-Path $script:CcdcAlertRoot)) { New-Item -ItemType Directory -Path $script:CcdcAlertRoot -Force -WhatIf:$false | Out-Null }
        $file = Join-Path $script:CcdcAlertRoot ("alerts_{0}.csv" -f $env:COMPUTERNAME)
        $flat = ($Detail -replace '\s+', ' ')
        if ($flat.Length -gt 600) { $flat = $flat.Substring(0, 600) + '...' }
        [pscustomobject]@{
            Time = $Time.ToString('yyyy-MM-dd HH:mm:ss'); Host = $env:COMPUTERNAME; Level = $Level; Rule = $Rule
            User = $User; SourceIp = $SourceIp; Detail = $flat; Source = $Source
        } | Export-Csv -Path $file -Append -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    } catch { Write-CcdcLog "ALERT file write failed: $($_.Exception.Message)" 'ERROR' }
}

function Get-CcdcFileHash {
    # SHA256 of a file via .NET (Get-FileHash does not exist on PowerShell 3 / Server 2012).
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '') } finally { $fs.Close(); $sha.Dispose() }
    } catch { return '' }
}

function Get-CcdcQuarantineDir {
    # One quarantine folder per script run. It is OUTSIDE every web root on purpose.
    $dir = Join-Path $script:CcdcQuarantineRoot $script:CcdcStamp
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    return $dir
}

function Add-CcdcEvidence {
    <#
      Records one removed/contained item as a JSON line in
      C:\ccdc\evidence\evidence_<HOST>.jsonl: what, where, when it was created,
      who/where from if known, and what we did. An incident report needs proof
      of what was removed, so this is written BEFORE removal.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Item)
    try {
        if (-not (Test-Path $script:CcdcEvidenceRoot)) { New-Item -ItemType Directory -Path $script:CcdcEvidenceRoot -Force -WhatIf:$false | Out-Null }
        $file = Join-Path $script:CcdcEvidenceRoot ("evidence_{0}.jsonl" -f $env:COMPUTERNAME)
        $Item['RecordedAt'] = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $Item['Host']       = $env:COMPUTERNAME
        $Item['Operator']   = "$env:USERDOMAIN\$env:USERNAME"
        Add-Content -Path $file -Value (([pscustomobject]$Item | ConvertTo-Json -Compress -Depth 4)) -Encoding UTF8 -WhatIf:$false
        Write-CcdcLog ("EVIDENCE {0} {1}" -f $Item['Type'], $Item['Name']) 'EVIDENCE'
        return $file
    } catch { Write-CcdcLog "EVIDENCE write failed: $($_.Exception.Message)" 'ERROR'; return $null }
}

function Get-CcdcLogonSource {
    <#
      "Who was that?" -> "Where did they log on from?"
      Account-change events (4720 user created, 4732 group add, 4698 task
      created...) do not carry an IP address, but they do carry the LOGON ID
      of the session that made the change. The matching 4624 logon event has
      the same ID plus the source IP. Returns the IP address, or
      'console (logon type N)' for a local session, or '' when it cannot be
      found (log rolled over, or the change was made by SYSTEM).
    #>
    param([string]$LogonId, [int]$MaxHoursBack = 24)
    if (-not $LogonId -or $LogonId -match '^0x3e[4-7]$') { return '' }   # SYSTEM / service logons have no remote source
    if (-not $script:CcdcLogonCache) { $script:CcdcLogonCache = @{} }
    if ($script:CcdcLogonCache.ContainsKey($LogonId)) { return $script:CcdcLogonCache[$LogonId] }
    $result = ''
    try {
        $since = (Get-Date).AddHours(-$MaxHoursBack).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $xp = "*[System[EventID=4624 and TimeCreated[@SystemTime>='$since']] and EventData[Data[@Name='TargetLogonId']='$LogonId']]"
        $ev = Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 1 -ErrorAction Stop
        if ($ev) {
            $d = Get-CcdcEventData -Record $ev
            $ip = ConvertTo-CcdcIp $d['IpAddress']
            $result = if ($ip) { $ip } else { "console (logon type $($d['LogonType']))" }
        }
    } catch { $null = $_ }
    $script:CcdcLogonCache[$LogonId] = $result
    return $result
}

# Compatibility shims for older Windows live in Compat.ps1 (shared with services\).
. (Join-Path $PSScriptRoot 'Compat.ps1')

# ---------------------------------------------------------------------------
# Registry reader that keeps the value TYPE, so a value can be written back
# exactly as it was (Snapshot-State restore, Audit-Vulns comparisons).
# Key ids look like 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'.
# ---------------------------------------------------------------------------
function ConvertTo-CcdcRegData {
    param($Data, [string]$Kind)
    if ($null -eq $Data) { return $null }
    switch ($Kind) {
        'Binary'      { return [Convert]::ToBase64String([byte[]]$Data) }
        'MultiString' { return @([string[]]$Data) }
        'DWord'       { return [int]$Data }
        'QWord'       { return [long]$Data }
        default       { return [string]$Data }
    }
}

function Open-CcdcRegKey {
    # Returns a read-only RegistryKey (64-bit view) or $null. Caller must Close() it.
    param([Parameter(Mandatory = $true)][string]$KeyId, [switch]$Writable)
    $parts = $KeyId -split '\\', 2
    $hive = switch ($parts[0]) { 'HKLM' { 'LocalMachine' } 'HKCU' { 'CurrentUser' } 'HKU' { 'Users' } default { $null } }
    if (-not $hive) { return $null }
    try {
        $view = if ([Environment]::Is64BitOperatingSystem) { [Microsoft.Win32.RegistryView]::Registry64 } else { [Microsoft.Win32.RegistryView]::Default }
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive, $view)
        if ($parts.Count -lt 2 -or -not $parts[1]) { return $base }
        if ($Writable) { return $base.CreateSubKey($parts[1]) }
        return $base.OpenSubKey($parts[1], $false)
    } catch { return $null }
}

function Read-CcdcRegValue {
    # @{ Type = 'DWord'; Data = 1 } or $null when the value (or key) does not exist.
    param([Parameter(Mandatory = $true)][string]$KeyId, [Parameter(Mandatory = $true)][string]$Name)
    $k = Open-CcdcRegKey -KeyId $KeyId
    if (-not $k) { return $null }
    try {
        $vn = if ($Name -eq '(default)') { '' } else { $Name }
        if (@($k.GetValueNames()) -notcontains $vn) { return $null }
        $kind = [string]$k.GetValueKind($vn)
        $raw = $k.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return @{ Type = $kind; Data = (ConvertTo-CcdcRegData -Data $raw -Kind $kind) }
    } catch { return $null } finally { $k.Close() }
}

# The registry areas that decide how attackable a Windows box is. Snapshot-State
# saves every value under these keys; Audit-Vulns reads the same keys, so a vuln
# check can be evaluated against "now" AND against any snapshot.
# Depth = how many levels of subkeys to include. Only = keep just these value names.
# Values named in $script:CcdcRegNeverSave are never written to disk (secrets).
$script:CcdcRegNeverSave = @('DefaultPassword', 'AutoAdminLogonPassword', 'AltDefaultPassword')
function Get-CcdcRegCatalog {
    return @(
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Depth = 1 }                       # NTLM, LM hash, anonymous, RunAsPPL, packages, MSV1_0, Kerberos
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Depth = 0 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'; Depth = 2 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; Depth = 0 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Depth = 0 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg'; Depth = 0 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Depth = 0 }  # SMB1, signing, null sessions, compression
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Depth = 0 }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Depth = 0; Only = @('Start') }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Depth = 0 }      # Zerologon enforcement
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Depth = 0 }          # LDAP signing / channel binding
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'; Depth = 0 }                      # cert binding (Certifried)
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters'; Depth = 0 }           # SIGRed workaround
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Depth = 2 }         # NBT-NS per interface
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Depth = 0; Only = @('DisabledComponents') }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security'; Depth = 0; Only = @('MaxSize', 'Retention') }
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System'; Depth = 0; Only = @('MaxSize', 'Retention') }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Depth = 0 }  # UAC, LocalAccountTokenFilterPolicy
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Depth = 0 }      # Shell, Userinit, AutoAdminLogon
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Depth = 0; Only = @('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs') }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; Depth = 1; Only = @('Debugger', 'GlobalFlag', 'VerifierDlls') }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Depth = 0 }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Depth = 0 }
        @{ Key = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Depth = 0 }
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Depth = 1 }            # Point and Print
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Depth = 0 }           # LLMNR
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Depth = 0 }
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'; Depth = 1 }             # script block / module logging, transcription
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Depth = 0 }              # AlwaysInstallElevated
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM'; Depth = 1 }
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; Depth = 1 }
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Depth = 1 }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Policies\LAPS'; Depth = 0 }
        @{ Key = 'HKLM\SOFTWARE\Classes\ms-msdt'; Depth = 0 }                                   # Follina handler present?
    )
}

function Get-CcdcRegTree {
    # Reads one catalog entry. Returns @{ Keys = @(key ids seen); Values = @{ 'key|name' = @{Type;Data} } }
    param([Parameter(Mandatory = $true)][string]$KeyId, [int]$Depth = 0, [string[]]$Only = @())
    $out = @{ Keys = @($KeyId); Values = @{} }
    $k = Open-CcdcRegKey -KeyId $KeyId
    if (-not $k) { return $out }
    try {
        foreach ($vn in $k.GetValueNames()) {
            $name = if ($vn -eq '') { '(default)' } else { $vn }
            if ($Only.Count -and $Only -notcontains $name) { continue }
            if ($script:CcdcRegNeverSave -contains $name) { $out.Values["$KeyId|$name"] = @{ Type = 'Secret'; Data = '(present, not saved)' }; continue }
            try {
                $kind = [string]$k.GetValueKind($vn)
                $raw = $k.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $out.Values["$KeyId|$name"] = @{ Type = $kind; Data = (ConvertTo-CcdcRegData -Data $raw -Kind $kind) }
            } catch { $null = $_ }
        }
        if ($Depth -gt 0) {
            foreach ($sub in $k.GetSubKeyNames()) {
                $child = Get-CcdcRegTree -KeyId "$KeyId\$sub" -Depth ($Depth - 1) -Only $Only
                $out.Keys += $child.Keys
                foreach ($e in $child.Values.GetEnumerator()) { $out.Values[$e.Key] = $e.Value }
            }
        }
    } catch { $null = $_ } finally { $k.Close() }
    return $out
}

# ---------------------------------------------------------------------------
# Snapshots: C:\ccdc\snapshots\<HOST>\<yyyyMMdd_HHmmss>_<label>\state.xml
# The OLDEST one is the "original" (how the box was when we got here).
# ---------------------------------------------------------------------------
$script:CcdcSnapshotRoot = Join-Path (Join-Path $script:CcdcRoot 'snapshots') $env:COMPUTERNAME

function Get-CcdcSnapshotList {
    # Oldest first. Each item: Path, Name, Time, Label.
    if (-not (Test-Path $script:CcdcSnapshotRoot)) { return @() }
    return @(Get-ChildItem $script:CcdcSnapshotRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'state.xml') } | Sort-Object Name | ForEach-Object {
            $t = $null; try { $t = [datetime]::ParseExact($_.Name.Substring(0, 15), 'yyyyMMdd_HHmmss', $null) } catch { $null = $_ }
            [pscustomobject]@{ Path = $_.FullName; Name = $_.Name; Time = $t; Label = $(if ($_.Name.Length -gt 16) { $_.Name.Substring(16) } else { '' }) }
        })
}

function Import-CcdcSnapshot {
    # 'original' (oldest), 'latest', a folder name, or a full path. $null if none.
    param([string]$Which = 'original')
    $list = Get-CcdcSnapshotList
    if ($list.Count -eq 0) { return $null }
    $pick = switch ($Which) {
        'original' { $list[0] }
        'latest'   { $list[-1] }
        default    { $list | Where-Object { $_.Name -eq $Which -or $_.Path -eq $Which } | Select-Object -First 1 }
    }
    if (-not $pick) { return $null }
    try {
        $s = Import-Clixml (Join-Path $pick.Path 'state.xml')
        $s['Dir'] = $pick.Path
        return $s
    } catch { return $null }
}

function Get-CcdcToolkitChanges {
    # Every CHANGED line the toolkit logged since $Since: Time, Script, Text.
    # Used to tell "the toolkit did this" apart from "someone else did this".
    param([datetime]$Since = [datetime]::MinValue)
    $out = @()
    foreach ($f in (Get-ChildItem $script:CcdcLogRoot -Filter '*.log' -ErrorAction SilentlyContinue)) {
        $scr = ($f.BaseName -split "_")[0]
        foreach ($line in (Get-Content $f.FullName -ErrorAction SilentlyContinue)) {
            if ($line -notmatch '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[CHANGE\] (.*)$') { continue }
            $t = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
            if ($t -lt $Since) { continue }
            $out += [pscustomobject]@{ Time = $t; Script = $scr; Text = $Matches[2] }
        }
    }
    return @($out | Sort-Object Time)
}

function Get-CcdcExtraFacts {
    # Security facts that are not a single registry value. Saved in every
    # snapshot and read live by Audit-Vulns, so both sides compare the same thing.
    $x = @{}
    $smb = $null
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        try { $smb = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $null = $_ }
    }
    if ($null -eq $smb) {
        # Older Windows: SMB1 server is on unless LanmanServer\Parameters\SMB1 = 0.
        $v = Read-CcdcRegValue -KeyId 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        $smb = -not ($v -and [int]$v.Data -eq 0)
    }
    $x.Smb1Server = $smb
    # HiveNightmare: can BUILTIN\Users (S-1-5-32-545) read the SAM hive file?
    $x.SamUsersRead = $null
    try {
        $acl = Get-Acl -Path "$env:windir\System32\config\SAM" -ErrorAction Stop
        $x.SamUsersRead = $false
        foreach ($a in $acl.Access) {
            if ($a.AccessControlType -ne 'Allow') { continue }
            if (-not ($a.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)) { continue }
            try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = '' }
            if ($sid -eq 'S-1-5-32-545') { $x.SamUsersRead = $true }
        }
    } catch { $null = $_ }
    $x.ShadowCopies = @(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue).Count
    return $x
}

function Test-CcdcRegKeyCaptured {
    # Was this key inside what a snapshot captured? True when the key itself was
    # seen, or when it sits under a catalog root the snapshot read (the subkey
    # simply did not exist yet, so every value in it counts as "not set").
    param($RegKeys, [Parameter(Mandatory = $true)][string]$KeyId)
    if (@($RegKeys) -contains $KeyId) { return $true }
    foreach ($c in (Get-CcdcRegCatalog)) {
        if ($KeyId.StartsWith($c.Key + '\', [StringComparison]::OrdinalIgnoreCase) -and @($RegKeys) -contains $c.Key) {
            $extra = ($KeyId.Substring($c.Key.Length + 1) -split '\\').Count
            if ($extra -le $c.Depth) { return $true }
        }
    }
    return $false
}


# ---------------------------------------------------------------------------
# Persistence rules shared by audit\Audit-Persistence and hunt\Remove-Persistence,
# so both flag (and hide) exactly the same things.
# ---------------------------------------------------------------------------
# Paths any user can write to: programs should not autostart from here.
$script:CcdcBadPathRegex = '(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)|Users\\Public|ProgramData\\(?!Microsoft)|Windows\\Temp|\\Temp\\|PerfLogs|\$Recycle)'
# Command lines that are almost always malicious in a task / Run key / service.
$script:CcdcBadCmdRegex = '(?i)(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|bitsadmin|certutil.+-urlcache|mshta|regsvr32.+/i:http|rundll32.+javascript|\bnc(\.exe)?\s|ncat|socat|powercat|-w(indowstyle)?\s+h(idden)?\b|test-netconnection|invoke-webrequest|\biwr\s|net\.sockets|net\.webclient|https?://|\becho\b.+>)'
# A script file started from outside Windows / Program Files (also catches C:\ProgramData\Microsoft\...\x.vbs).
$script:CcdcScriptOutsideRegex = '(?i)(wscript|cscript|powershell|pwsh|cmd)(\.exe)?\b.*\b[A-Z]:\\(?!Windows\\|Program Files)[^"|]+\.(vbs|vbe|js|jse|ps1|bat|cmd|hta|wsf)\b'

function Get-CcdcPersistSeverity([string]$text) {
    if ($text -match $script:CcdcBadCmdRegex -or $text -match $script:CcdcBadPathRegex -or $text -match $script:CcdcScriptOutsideRegex) { return 'RED' }
    return 'YELLOW'
}
$script:CcdcSigCache = @{}
function Test-CcdcMsSigned([string]$path) {
    # True when the file is signed by Microsoft (catalog signatures count). Cached per path.
    if (-not $path) { return $false }
    $path = [Environment]::ExpandEnvironmentVariables($path.Trim().Trim('"'))
    if (-not $script:CcdcSigCache.ContainsKey($path)) {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        $script:CcdcSigCache[$path] = [bool]($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
    }
    return $script:CcdcSigCache[$path]
}
function Test-CcdcTaskIsNoise($Task, [string]$Actions) {
    # True = a normal task nobody needs to look at: the toolkit's own, Windows' internal
    # (no command line), or a Microsoft-signed program run normally. Suspicious content is never noise.
    if ($Task.TaskName -like 'CCDC-*' -or $Task.TaskName -like 'BT-Alert-*') { return $true }
    if ((Get-CcdcPersistSeverity $Actions) -eq 'RED') { return $false }
    if (-not $Actions -and $Task.TaskPath -like '\Microsoft\*') { return $true }
    $exe = @($Task.Actions | Where-Object { $_.Execute } | ForEach-Object { $_.Execute }) | Select-Object -First 1
    if ($exe -and $exe -notmatch '(?i)\\?(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$' -and (Test-CcdcMsSigned $exe)) { return $true }
    if ($exe -and $exe -match '(?i)\\?(rundll32|cmd)(\.exe)?$' -and $Task.TaskPath -like '\Microsoft\*' -and $Actions -match '(?i)%(windir|systemroot)%\\system32\\') { return $true }
    return $false
}
