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
     * reading config\ccdc.json (or the example) for IPs / scored ports

 HOW IT IS USED
   Each script does:   . "$PSScriptRoot\..\lib\CCDC-Common.ps1"
   The leading dot means "dot-source": run this file inside MY scope so its
   functions become available to me. Nothing here runs on its own.

 WHAT IT READS   : config\ccdc.json or config\example.great-cretaceous.json
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
        3. <repo>\config\example.great-cretaceous.json
      Returns $null if nothing is found (scripts must still work without it).
    #>
    param([string]$Path)
    $candidates = @()
    if ($Path) { $candidates += $Path }
    $candidates += (Join-Path $script:CcdcToolkitRoot 'config\ccdc.json')
    $candidates += (Join-Path $script:CcdcToolkitRoot 'config\example.great-cretaceous.json')
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
      The audit subcategories we turn on (used by Harden-Baseline and
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
