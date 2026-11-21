<#
.SYNOPSIS
    Setup-Logging - turn on the logs you need for hunting, install Sysmon if present, forward to Graylog. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      Without logs you cannot answer "what did Red Team do?" for an inject
      or an incident report. This script:
        1. Enables advanced audit policy (logons, account/group changes, process
           creation, scheduled tasks, services, DCSync-relevant DS access)
        2. Grows the Security / PowerShell / Sysmon logs so events are not overwritten
        3. Enables PowerShell script block (4104) + module logging, and command
           lines in process creation events (4688)
        4. Installs or updates Sysmon IF the binary is present locally
           (default tools\sysmon\Sysmon64.exe or dev\tools\sysmon\ - see dev\tools\README.md in the repo; nothing is downloaded)
        5. Optionally configures Winlogbeat or NXLog (if installed/present) to
           ship events to Graylog (tarpit) at -GraylogIp

    WHAT IT READS    auditpol, registry, services, config\ccdc.json (graylog section)
    WHAT IT CHANGES  audit policy, event log sizes, PowerShell logging policy keys,
                     Sysmon service + config, winlogbeat.yml / nxlog.conf + their services
    HOW TO UNDO      auditpol /restore /file:<backup csv printed below>
                     reg import <backups\...\reg_*.reg>
                     Sysmon64.exe -u            (uninstall Sysmon)
                     restore winlogbeat.yml / nxlog.conf from C:\ccdc\backups\<stamp>\

    MANUAL EQUIVALENT
      auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
      wevtutil sl Security /ms:1073741824
      reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
      Sysmon64.exe -accepteula -i sysmonconfig.xml
      Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5

.EXAMPLE
    .\Setup-Logging.ps1 -WhatIf
.EXAMPLE
    .\Setup-Logging.ps1 -GraylogIp 192.168.100.170 -Forwarder Winlogbeat
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SysmonPath,
    [string]$SysmonConfig,
    [string]$GraylogIp,
    [ValidateSet('Auto', 'Winlogbeat', 'NXLog', 'None')][string]$Forwarder = 'Auto',
    [int]$BeatsPort = 5044,
    [int]$GelfPort = 12201,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Setup-Logging'
$config = Get-CcdcConfig -Path $ConfigPath
# Staged tools: <toolkit>\tools (copied over by hand) or dev\tools (where Get-CcdcTools stages them).
$tools  = @((Join-Path $script:CcdcToolkitRoot 'tools'), (Join-Path $script:CcdcToolkitRoot 'dev\tools') | Where-Object { Test-Path (Join-Path $_ 'sysmon') }) | Select-Object -First 1
if (-not $tools) { $tools = Join-Path $script:CcdcToolkitRoot 'tools' }
if (-not $SysmonPath)   { $SysmonPath   = Join-Path $tools 'sysmon\Sysmon64.exe' }
if (-not $SysmonConfig) { $SysmonConfig = Join-Path $tools 'sysmon\sysmonconfig.xml' }
if (-not $GraylogIp -and $config -and $config.graylog) {
    $GraylogIp = $config.graylog.ip
    if ($config.graylog.beatsPort) { $BeatsPort = [int]$config.graylog.beatsPort }
    if ($config.graylog.gelfUdpPort) { $GelfPort = [int]$config.graylog.gelfUdpPort }
}

function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    $cur = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -ne $cur -and [int]$cur -eq $Value) { Write-Finding -Level GREEN -Category 'Registry' -Message "$Name already $Value"; return }
    $regPath = $Path -replace '^HKLM:\\', 'HKLM\'
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$regPath\$Name" -Action "Set $Value" -Undo "reg import <backup of $regPath>" -ScriptBlock {
        $null = Backup-CcdcRegistry -Key $regPath
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    })
}

# ---------------------------------------------------------------------------
Write-Section '1. Advanced audit policy'
# ---------------------------------------------------------------------------
$auditBackup = Join-Path (Get-CcdcBackupDir) 'auditpol_before.csv'
if (-not $WhatIfPreference) {
    $null = & auditpol.exe /backup /file:"$auditBackup" 2>&1
    Write-Finding -Level INFO -Category 'Audit' -Message "Current policy backed up: $auditBackup" -Detail "Undo: auditpol /restore /file:`"$auditBackup`""
}
Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
$plan = Get-CcdcAuditPolicyPlan
[void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($plan.Count) subcategories" -Action 'Enable success+failure auditing' -Undo "auditpol /restore /file:`"$auditBackup`"" -ScriptBlock {
    foreach ($sub in $plan) {
        $null = & auditpol.exe /set /subcategory:"$($sub.Guid)" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($sub.Name)" }
    }
})

# ---------------------------------------------------------------------------
Write-Section '2. Event log sizes'
# ---------------------------------------------------------------------------
$sizes = @{ 'Security' = 1GB; 'Microsoft-Windows-PowerShell/Operational' = 256MB; 'Windows PowerShell' = 128MB; 'System' = 128MB }
foreach ($log in $sizes.Keys) {
    $want = [int64]$sizes[$log]
    $cur = (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue).MaximumSizeInBytes
    if ($cur -ge $want) { Write-Finding -Level GREEN -Category 'LogSize' -Message ("{0} already {1} MB" -f $log, [int]($cur / 1MB)); continue }
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $log -Action ("Max size {0} MB (was {1} MB)" -f [int]($want / 1MB), [int]($cur / 1MB)) -Undo "wevtutil sl `"$log`" /ms:$cur" -ScriptBlock {
        $null = & wevtutil.exe sl $log /ms:$want
        if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }
    })
}

# ---------------------------------------------------------------------------
Write-Section '3. PowerShell + process command-line logging'
# ---------------------------------------------------------------------------
Set-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames') -or
    -not (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction SilentlyContinue).'*') {
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'ModuleLogging\ModuleNames' -Action "Log all modules ('*')" -Undo 'reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames /f' -ScriptBlock {
        New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
        New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -PropertyType String -Force | Out-Null
    })
}
Set-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Write-Finding -Level INFO -Category 'PowerShell' -Message 'We deliberately do NOT enable PowerShell Transcription: it would write passwords shown by Rotate-Passwords to disk.'

# ---------------------------------------------------------------------------
Write-Section '4. Sysmon'
# ---------------------------------------------------------------------------
$sysmonSvc = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not (Test-Path $SysmonPath)) {
    $state = if ($sysmonSvc) { "already installed ($($sysmonSvc.Name), $($sysmonSvc.Status))" } else { 'not installed' }
    Write-Finding -Level YELLOW -Category 'Sysmon' -Message "Sysmon binary not found at $SysmonPath - $state" -Detail 'Copy Sysmon64.exe + a config into tools\sysmon\ (see dev\tools\README.md for URL + checksum steps).'
} elseif (-not (Test-Path $SysmonConfig)) {
    Write-Finding -Level YELLOW -Category 'Sysmon' -Message "Sysmon config not found at $SysmonConfig - refusing to install with no config (default config is too noisy/blind)."
} elseif ($sysmonSvc) {
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $sysmonSvc.Name -Action "Update config from $SysmonConfig" -Undo 'Sysmon64.exe -c <previous config>' -ScriptBlock {
        $null = & $SysmonPath -c $SysmonConfig 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Sysmon -c exit $LASTEXITCODE" }
    })
} else {
    $sig = (Get-AuthenticodeSignature $SysmonPath).Status
    if ($sig -ne 'Valid') { Write-Finding -Level RED -Category 'Sysmon' -Message "Sysmon binary signature is '$sig' - do NOT install an unverified binary." }
    else {
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target 'Sysmon' -Action "Install with $SysmonConfig" -Undo "$SysmonPath -u" -ScriptBlock {
            $null = & $SysmonPath -accepteula -i $SysmonConfig 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Sysmon -i exit $LASTEXITCODE" }
            $null = & wevtutil.exe sl 'Microsoft-Windows-Sysmon/Operational' /ms:536870912
        })
    }
}

# ---------------------------------------------------------------------------
Write-Section '5. Forward to Graylog'
# ---------------------------------------------------------------------------
$wlbDir = @((Join-Path $tools 'winlogbeat'), "$env:ProgramFiles\Winlogbeat", "$env:ProgramData\Elastic\Beats\winlogbeat") | Where-Object { Test-Path (Join-Path $_ 'winlogbeat.exe') } | Select-Object -First 1
$nxDir  = @("${env:ProgramFiles(x86)}\nxlog", "$env:ProgramFiles\nxlog") | Where-Object { Test-Path (Join-Path $_ 'nxlog.exe') } | Select-Object -First 1
if ($Forwarder -eq 'Auto') { $Forwarder = if ($wlbDir) { 'Winlogbeat' } elseif ($nxDir) { 'NXLog' } else { 'None' } }

if ($Forwarder -eq 'None') {
    Write-Finding -Level INFO -Category 'Forward' -Message 'No Winlogbeat/NXLog found - events stay local. (See dev\tools\README.md to stage one.)'
} elseif (-not $GraylogIp) {
    Write-Finding -Level YELLOW -Category 'Forward' -Message 'No -GraylogIp and none in config - skipping forwarding.'
} elseif ($Forwarder -eq 'Winlogbeat') {
    if (-not $wlbDir) { Write-Finding -Level YELLOW -Category 'Forward' -Message 'Winlogbeat requested but winlogbeat.exe not found.' }
    else {
        # Graylog needs a "Beats" input listening on $BeatsPort (System > Inputs on tarpit).
        $yml = @"
# Written by CCDC Setup-Logging.ps1 - ships Windows events to Graylog (Beats input).
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104
  - name: Microsoft-Windows-Windows Defender/Operational
  - name: Microsoft-Windows-TaskScheduler/Operational
output.logstash:
  hosts: ["${GraylogIp}:$BeatsPort"]
"@
        $ymlPath = Join-Path $wlbDir 'winlogbeat.yml'
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $ymlPath -Action "Write config -> ${GraylogIp}:$BeatsPort and (re)start service" -Undo 'restore winlogbeat.yml from backup; Restart-Service winlogbeat' -ScriptBlock {
            $null = Backup-CcdcFile -Path $ymlPath
            [System.IO.File]::WriteAllText($ymlPath, $yml, (New-Object System.Text.UTF8Encoding $false))
            if (-not (Get-Service winlogbeat -ErrorAction SilentlyContinue)) {
                # Winlogbeat ships install-service-winlogbeat.ps1 in its folder.
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $wlbDir 'install-service-winlogbeat.ps1') | Out-Null
            }
            Restart-Service winlogbeat
        })
    }
} elseif ($Forwarder -eq 'NXLog') {
    # Graylog needs a "GELF UDP" input on $GelfPort.
    $conf = @"
# Written by CCDC Setup-Logging.ps1 - ships Windows events to Graylog via GELF UDP.
define ROOT $nxDir
Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data
LogFile   %ROOT%\data\nxlog.log
<Extension gelf>
    Module xm_gelf
</Extension>
<Input eventlog>
    Module im_msvistalog
</Input>
<Output graylog>
    Module om_udp
    Host   $GraylogIp
    Port   $GelfPort
    OutputType GELF_UDP
</Output>
<Route r>
    Path eventlog => graylog
</Route>
"@
    $confPath = Join-Path $nxDir 'conf\nxlog.conf'
    [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $confPath -Action "Write config -> ${GraylogIp}:$GelfPort/udp and restart nxlog" -Undo 'restore nxlog.conf from backup; Restart-Service nxlog' -ScriptBlock {
        $null = Backup-CcdcFile -Path $confPath
        [System.IO.File]::WriteAllText($confPath, $conf, (New-Object System.Text.UTF8Encoding $false))
        Restart-Service nxlog
    })
}
Write-Finding -Level INFO -Category 'Forward' -Message "Remember: Set-Firewall on tarpit must allow ${BeatsPort}/tcp (Beats) or ${GelfPort}/udp (GELF) from the pod."

Complete-Ccdc
