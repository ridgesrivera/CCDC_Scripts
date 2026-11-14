#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Run every per-service script in this folder: detect, document, back up, verify.
.DESCRIPTION
    Each <Service>.ps1 quietly skips itself if that service is not on this box,
    so this is safe to run on ANY Windows machine (DC, web server, workstation).

      .\Invoke-AllServices.ps1                     # Detect + Backup everything present (default)
      .\Invoke-AllServices.ps1 -Action Detect      # one-line-per-service inventory
      .\Invoke-AllServices.ps1 -Action Info        # full write-up of every present service -> log
      .\Invoke-AllServices.ps1 -Action Verify      # re-hash latest backups, detect tampering
      .\Invoke-AllServices.ps1 -Only DNS,IIS       # just these
      .\Invoke-AllServices.ps1 -Skip SMB_FileShares
      .\Invoke-AllServices.ps1 -OffboxPath \\10.x.x.x\backups   # also copy backups off this box

    Credentials for scripts that need them are passed through only to scripts
    that accept them (-DbUser/-DbPassword -> MySQL, -SqlUser/-SqlPassword -> MSSQL,
    -KeyPassword -> ADCS). Without them those scripts try defaults / prompt.

    Restore is deliberately NOT batch: run <Service>.ps1 -Action Restore per service.
#>
[CmdletBinding()]
param(
    [ValidateSet('Detect', 'Info', 'Backup', 'Verify')][string]$Action = 'Backup',
    [string[]]$Only,
    [string[]]$Skip,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [string]$OffboxPath,
    [string]$DbUser,
    [string]$DbPassword,
    [string]$SqlUser,
    [string]$SqlPassword,
    [string]$KeyPassword
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$logDir = 'C:\ccdc\logs'; New-Item -ItemType Directory $logDir -Force | Out-Null
$log = Join-Path $logDir "Services_$($Action)_$(Get-Date -Format yyyyMMdd_HHmmss).log"
Start-Transcript -Path $log -Force | Out-Null

# Order matters a little: identity + firewall first, big file copies last.
$order = 'ActiveDirectory', 'DNS', 'DHCP', 'GroupPolicy', 'ADCS', 'WindowsFirewall', 'ScheduledTasks', 'RDP', 'WinRM', 'OpenSSH', 'SNMP', 'W32Time',
         'PrintSpooler', 'VNC', 'OpenVPN', 'MSSQL', 'MySQL', 'Mail', 'Exchange', 'IIS', 'FTP', 'WebServers_NonIIS', 'NFS', 'SMB_FileShares'
$all = Get-ChildItem $PSScriptRoot -Filter *.ps1 | Where-Object { $_.Name -notmatch '^(_|Invoke-AllServices)' }
$scripts = @($order | ForEach-Object { $n = $_; $all | Where-Object BaseName -eq $n }) + @($all | Where-Object { $order -notcontains $_.BaseName })
if ($Only) { $scripts = $scripts | Where-Object { $Only -contains $_.BaseName } }
if ($Skip) { $scripts = $scripts | Where-Object { $Skip -notcontains $_.BaseName } }

Write-Banner "CCDC SERVICE RUNNER - $Action - $env:COMPUTERNAME" "Green"
Write-INFO "Log: $log"

$pass = @{ DbUser = $DbUser; DbPassword = $DbPassword; SqlUser = $SqlUser; SqlPassword = $SqlPassword; KeyPassword = $KeyPassword }
$before = Get-Date
$results = @()

if ($Action -in 'Info', 'Backup') {
    Write-STEP "Detecting services first"
    foreach ($s in $scripts) { & $s.FullName -Action Detect -BackupRoot $BackupRoot }
}

foreach ($s in $scripts) {
    if ($Action -eq 'Verify') { break }   # handled in the summary below
    $splat = @{ Action = $Action; BackupRoot = $BackupRoot }
    if ($Action -eq 'Backup') { $splat.Force = $true }
    $params = (Get-Command $s.FullName).Parameters.Keys
    foreach ($k in $pass.Keys) { if ($pass[$k] -and $params -contains $k) { $splat[$k] = $pass[$k] } }
    $t0 = Get-Date
    try { & $s.FullName @splat; $ok = $true } catch { Write-CRIT "$($s.BaseName) threw: $_"; $ok = $false }
    $results += [pscustomobject]@{ Script = $s.BaseName; Ok = $ok; Seconds = [int]((Get-Date) - $t0).TotalSeconds }
}

if ($Action -eq 'Backup') {
    Write-Banner "BACKUP SUMMARY" "Green"
    $new = Get-ChildItem $BackupRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.FullName -Directory | Where-Object CreationTime -ge $before.AddSeconds(-5)
    }
    foreach ($d in $new) {
        $sz = (Get-ChildItem $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        Write-OK ("{0,-20} {1,8:N1} MB  {2}" -f $d.Parent.Name, ($sz / 1MB), $d.FullName)
    }
    if (-not $new) { Write-WARN "No new backup folders were created." }

    if ($OffboxPath) {
        Write-STEP "Copying to off-box location $OffboxPath"
        $dest = Join-Path $OffboxPath "$env:COMPUTERNAME"
        foreach ($d in $new) {
            & robocopy.exe $d.FullName (Join-Path $dest "$($d.Parent.Name)\$($d.Name)") /E /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
            if ($LASTEXITCODE -lt 8) { Write-OK "-> $dest\$($d.Parent.Name)\$($d.Name)" } else { Write-WARN "robocopy rc=$LASTEXITCODE for $($d.FullName)" }
        }
    } else {
        Write-WARN "Backups only exist on THIS box. Use -OffboxPath \\host\share (or copy $BackupRoot to your jump box)."
    }
}

if ($Action -eq 'Verify') {
    Write-Banner "VERIFY SUMMARY" "Yellow"
    foreach ($svcDir in Get-ChildItem $BackupRoot -Directory -ErrorAction SilentlyContinue) {
        $latest = Get-ChildItem $svcDir.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) { Test-BackupIntegrity $latest.FullName | Out-Null }
    }
}

# The per-script timing table only means something when scripts did real work.
if ($Action -ne 'Detect') { $results | Format-Table -AutoSize | Out-String | Write-Host }
Stop-Transcript | Out-Null
Write-Host "  Full log: $log" -ForegroundColor DarkGray
