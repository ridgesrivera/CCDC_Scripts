#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Task Scheduler (service: Schedule) info / backup / restore.
.DESCRIPTION
    Exports every scheduled task as XML (re-registerable) + a CSV baseline.
    Restore re-registers tasks that were DELETED or MODIFIED, and lists tasks
    that are NEW since the backup (likely persistence) - it does not delete them
    unless you confirm.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'ScheduledTasks'
    Title        = 'Task Scheduler'
    ServiceNames = @('Schedule')
    Description  = @"
Runs programs on a schedule / at boot / at logon / on an event. Hundreds of
built-in tasks live under \Microsoft\Windows\. Task definitions are XML
files in C:\Windows\System32\Tasks\ plus registry cache at HKLM\SOFTWARE\
Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache. Red team's #1
persistence mechanism on Windows. Can be pushed by GPO too.
"@
    Ports        = @(@{ Port = 135; Proto = 'TCP'; Use = 'RPC - remote task creation (schtasks /s, atexec)' })
    KeyPaths     = @("$env:SystemRoot\System32\Tasks", 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache')
    RedTeam      = @(
        'Task running powershell -enc / cmd /c / rundll32 / mshta / a binary in ProgramData, Temp, Users\Public'
        'Task as SYSTEM triggered every minute or at boot'
        'Hidden task: delete SD value in TaskCache\Tree\<name> so it does not show in schtasks / Get-ScheduledTask'
        'Hijacking an existing Microsoft task action'
        'atexec.py (impacket) creating a temp task remotely'
    )
    Hardening    = @(
        'Review non-\Microsoft\ tasks first (Info output)'
        'Disable rather than delete if unsure: Disable-ScheduledTask -TaskName X'
        'Compare TaskCache\Tree entries against Get-ScheduledTask for hidden tasks (Info output)'
    )
    Detect       = { Test-ServiceInstalled 'Schedule' }
}

$Def.InfoExtra = {
    Write-STEP "Non-Microsoft tasks"
    foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
        $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        $l = "{0}{1}  [{2}] as {3}  -> {4}" -f $t.TaskPath, $t.TaskName, $t.State, $t.Principal.UserId, $act
        if ($act -match 'powershell|pwsh|cmd(\.exe)? /c|rundll32|mshta|regsvr32|wscript|cscript|certutil|bitsadmin|\\Temp\\|\\ProgramData\\|\\Users\\Public|-enc|http') { Write-CRIT $l } else { Write-Plain $l }
    }
    Write-STEP "Microsoft-path tasks with suspicious actions"
    foreach ($t in Get-ScheduledTask -TaskPath '\Microsoft\*' -ErrorAction SilentlyContinue) {
        $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        if ($act -match '-enc|http|\\Temp\\|\\Users\\Public|mshta|bitsadmin|\.ps1') { Write-CRIT "$($t.TaskPath)$($t.TaskName) -> $act" }
    }
    Write-STEP "Hidden tasks (in TaskCache\Tree but invisible to Get-ScheduledTask)"
    $visible = Get-ScheduledTask | ForEach-Object { ($_.TaskPath + $_.TaskName).TrimStart('\') }
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    Get-ChildItem $tree -Recurse -ErrorAction SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath).Id } | ForEach-Object {
        $rel = $_.Name.Substring($_.Name.IndexOf('\Tree\') + 6)
        $sd = (Get-ItemProperty $_.PSPath).SD
        if (-not $sd) { Write-CRIT "Task with NO SD (hidden): $rel" }
        elseif ($visible -notcontains $rel) { Write-WARN "In registry but not listed: $rel" }
    }
}

$Def.Backup = {
    param($Dir)
    $x = Join-Path $Dir 'xml'; New-Item -ItemType Directory $x -Force | Out-Null
    $rows = foreach ($t in Get-ScheduledTask) {
        $safe = (($t.TaskPath + $t.TaskName).TrimStart('\') -replace '[\\/:*?"<>|]', '__')
        try { Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File "$x\$safe.xml" -Encoding Unicode } catch {}
        [pscustomobject]@{
            File = "$safe.xml"; TaskPath = $t.TaskPath; TaskName = $t.TaskName; State = "$($t.State)"; RunAs = $t.Principal.UserId
            Actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
            Triggers = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task', '' }) -join ','
        }
    }
    $rows | Export-Csv "$Dir\tasks.csv" -NoTypeInformation
    Write-OK "Exported $(@($rows).Count) tasks as XML"
    Copy-Tree "$env:SystemRoot\System32\Tasks" (Join-Path $Dir 'System32_Tasks') 'Raw Tasks folder' | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache' "$Dir\reg\TaskCache.reg" | Out-Null
}

$Def.Restore = {
    param($Dir)
    $bk = Import-Csv "$Dir\tasks.csv"
    $now = Get-ScheduledTask
    $nowMap = @{}; foreach ($t in $now) { $nowMap[$t.TaskPath + $t.TaskName] = $t }
    foreach ($b in $bk) {
        $key = $b.TaskPath + $b.TaskName
        $cur = $nowMap[$key]
        $curAct = if ($cur) { ($cur.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | ' }
        if (-not $cur -or $curAct -ne $b.Actions) {
            $why = if (-not $cur) { 'DELETED' } else { "MODIFIED (now: $curAct)" }
            if ($b.TaskPath -like '\Microsoft\*' -and $cur) { Write-CRIT "$key $why" }
            if (Confirm-Action "Task $key was $why. Re-register from backup?") {
                try {
                    $xml = Get-Content "$Dir\xml\$($b.File)" -Raw
                    Register-ScheduledTask -Xml $xml -TaskName $b.TaskName -TaskPath $b.TaskPath -Force -ErrorAction Stop | Out-Null
                    if ($b.State -eq 'Disabled') { Disable-ScheduledTask -TaskName $b.TaskName -TaskPath $b.TaskPath | Out-Null }
                    Write-OK "Restored $key"
                } catch { Write-WARN "$key : $_  (tasks with stored passwords need: schtasks /create /xml file /tn name /ru user /rp pw)" }
            }
        }
    }
    Write-STEP "Tasks that are NEW since the backup"
    $known = $bk | ForEach-Object { $_.TaskPath + $_.TaskName }
    foreach ($t in $now | Where-Object { $known -notcontains ($_.TaskPath + $_.TaskName) }) {
        $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
        Write-CRIT "NEW: $($t.TaskPath)$($t.TaskName) as $($t.Principal.UserId) -> $act"
        if (Confirm-Action "Disable NEW task $($t.TaskPath)$($t.TaskName)?") { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-Null; Write-OK "Disabled (export it for your incident report before deleting)" }
    }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
