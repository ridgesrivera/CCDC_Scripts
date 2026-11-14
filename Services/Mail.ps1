#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Windows mail servers (hMailServer, IIS SMTP, MailEnable) info / backup / restore.
    For Microsoft Exchange use Exchange.ps1.
.DESCRIPTION
    hMailServer: copies hMailServer.INI, the Data folder (mailboxes), and the
    database (built-in MSSQL CE file, or tells you to run MSSQL.ps1 / MySQL.ps1
    if it uses an external DB). Service is stopped briefly for a consistent copy
    unless -NoStop.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [switch]$NoStop
)
. "$PSScriptRoot\_ServiceCommon.ps1"

function Get-HMailPaths {
    $svc = Get-CimInstance Win32_Service -Filter "Name='hMailServer'" -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    $bin = Split-Path (Get-ExePathFromCommandLine $svc.PathName)
    $root = Split-Path $bin
    $ini = @("$bin\hMailServer.INI", "$root\Bin\hMailServer.INI") | Where-Object { Test-Path $_ } | Select-Object -First 1
    $cfg = @{}
    if ($ini) { Get-Content $ini | ForEach-Object { if ($_ -match '^\s*([^=;\[]+?)\s*=\s*(.*)$') { $cfg[$Matches[1]] = $Matches[2] } } }
    [pscustomobject]@{
        Root = $root; Bin = $bin; Ini = $ini
        DataFolder = if ($cfg.DataFolder) { $cfg.DataFolder } else { "$root\Data" }
        DatabaseFolder = if ($cfg.DatabaseFolder) { $cfg.DatabaseFolder } else { "$root\Database" }
        DatabaseType = $cfg.DatabaseType; DatabaseServer = $cfg.DatabaseServer; DatabaseName = $cfg.DatabaseName
        LogFolder = $cfg.LogFolder
    }
}

$MailEnableRoot = @("${env:ProgramFiles(x86)}\Mail Enable", "$env:ProgramFiles\Mail Enable") | Where-Object { Test-Path $_ } | Select-Object -First 1

$Def = @{
    Name         = 'Mail'
    Title        = 'Mail Server (hMailServer / IIS SMTP / MailEnable)'
    ServiceNames = @('hMailServer', 'SMTPSVC', 'MEPOPS', 'MEIMAPS', 'MESMTPCS', 'MEMTAS')
    Description  = @"
Sends and receives email. Scoring normally: SMTP send to a user, then log in
with POP3 or IMAP as that user and read it (so user passwords + mailbox
data must survive). Webmail (Roundcube etc.) may sit on IIS/Apache on top.
  hMailServer: Program Files (x86)\hMailServer\  (Bin\hMailServer.INI,
               Data\<domain>\<user>\*.eml, Database\*.sdf or external DB)
  IIS SMTP:    old IIS6 metabase SMTP relay (C:\inetpub\mailroot)
  MailEnable:  Program Files (x86)\Mail Enable\  (Config, Postoffices)
"@
    Ports        = @(
        @{ Port = 25; Proto = 'TCP'; Use = 'SMTP' }
        @{ Port = 465; Proto = 'TCP'; Use = 'SMTPS' }
        @{ Port = 587; Proto = 'TCP'; Use = 'SMTP submission' }
        @{ Port = 110; Proto = 'TCP'; Use = 'POP3' }
        @{ Port = 995; Proto = 'TCP'; Use = 'POP3S' }
        @{ Port = 143; Proto = 'TCP'; Use = 'IMAP' }
        @{ Port = 993; Proto = 'TCP'; Use = 'IMAPS' }
    )
    KeyPaths     = @("${env:ProgramFiles(x86)}\hMailServer", "$env:ProgramFiles\hMailServer", "$env:SystemDrive\inetpub\mailroot", "${env:ProgramFiles(x86)}\Mail Enable")
    RedTeam      = @(
        'Open relay -> spam / phishing from your domain'
        'Forwarding rules on mailboxes (silent exfil of every email)'
        'hMailServer Administrator password is in hMailServer.INI (hashed) - and the DB password is weakly encrypted'
        'Cleartext POP3/IMAP/SMTP auth sniffing'
        'Deleting accounts / domains so scoring login fails'
    )
    Hardening    = @(
        'Disable open relay: only authenticated users / local IPs may relay'
        'Change hMailServer administrator password (hMailAdmin -> File -> Change password)'
        'Review per-account forwarding + rules (Info output)'
        'Enable IP ranges / auto-ban in hMailServer'
    )
    Detect       = { Test-ServiceInstalled 'hMailServer', 'SMTPSVC', 'MEPOPS', 'MESMTPCS' }
}

$Def.InfoExtra = {
    $h = Get-HMailPaths
    if ($h) {
        Write-STEP "hMailServer"
        $h | Format-List | Out-String | ForEach-Object { $_.Trim() -split "`n" } | ForEach-Object { Write-Plain $_ }
        try {
            $app = New-Object -ComObject hMailServer.Application
            Write-INFO "COM API available - authenticate with: `$app.Authenticate('Administrator','<pw>')  to list accounts / forwards"
            [void]$app
        } catch { Write-Plain "hMailServer COM not registered (32-bit COM - run from 32-bit PowerShell: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe)" }
        if (Test-Path $h.DataFolder) {
            Get-ChildItem $h.DataFolder -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $users = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue
                Write-Plain ("domain {0,-25} mailboxes: {1}" -f $_.Name, (($users.Name) -join ', '))
            }
        }
    }
    if (Get-Service SMTPSVC -ErrorAction SilentlyContinue) { Write-STEP "IIS SMTP (SMTPSVC) - config is in the IIS6 metabase: $env:SystemRoot\System32\inetsrv\MetaBase.xml" }
    if ($MailEnableRoot) { Write-STEP "MailEnable at $MailEnableRoot"; Get-ChildItem "$MailEnableRoot\Postoffices" -Directory -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain "Postoffice: $($_.Name)" } }
}

$Def.Backup = {
    param($Dir)
    $h = Get-HMailPaths
    if ($h) {
        $h | Export-Clixml "$Dir\hmail_paths.xml"
        $stopped = $false
        if (-not $NoStop -and (Get-Service hMailServer).Status -eq 'Running') {
            Write-INFO "Stopping hMailServer for a consistent copy (~seconds)..."
            Stop-Service hMailServer -Force; $stopped = $true
        }
        try {
            if ($h.Ini) { Copy-Item $h.Ini "$Dir\hMailServer.INI" -Force; Write-OK "hMailServer.INI" }
            Copy-Tree $h.DataFolder (Join-Path $Dir 'hmail_Data') 'hMailServer Data (all mailboxes)' | Out-Null
            if (Test-Path $h.DatabaseFolder) { Copy-Tree $h.DatabaseFolder (Join-Path $Dir 'hmail_Database') 'hMailServer built-in database' | Out-Null }
            if ($h.DatabaseType -and $h.DatabaseType -notmatch 'MSSQLCE') { Write-WARN "hMailServer uses external DB ($($h.DatabaseType) on $($h.DatabaseServer), db '$($h.DatabaseName)') -> ALSO run MSSQL.ps1 or MySQL.ps1" }
        } finally { if ($stopped) { Start-Service hMailServer; Write-OK "hMailServer started again" } }
    }
    if (Get-Service SMTPSVC -ErrorAction SilentlyContinue) {
        Copy-Item "$env:SystemRoot\System32\inetsrv\MetaBase.xml" "$Dir\MetaBase.xml" -Force -ErrorAction SilentlyContinue
        Copy-Tree "$env:SystemDrive\inetpub\mailroot" (Join-Path $Dir 'mailroot') 'IIS SMTP mailroot' | Out-Null
    }
    if ($MailEnableRoot) {
        Copy-Tree "$MailEnableRoot\Config" (Join-Path $Dir 'MailEnable_Config') 'MailEnable Config' | Out-Null
        Copy-Tree "$MailEnableRoot\Postoffices" (Join-Path $Dir 'MailEnable_Postoffices') 'MailEnable Postoffices (mailboxes)' | Out-Null
        Export-RegKey 'HKLM\SOFTWARE\WOW6432Node\Mail Enable' "$Dir\reg\MailEnable.reg" | Out-Null
    }
}

$Def.Restore = {
    param($Dir)
    if (Test-Path "$Dir\hmail_paths.xml") {
        $h = Import-Clixml "$Dir\hmail_paths.xml"
        Stop-Service hMailServer -Force -ErrorAction SilentlyContinue
        if (Test-Path "$Dir\hMailServer.INI") { Copy-Item "$Dir\hMailServer.INI" $h.Ini -Force; Write-OK "INI restored" }
        Restore-Tree (Join-Path $Dir 'hmail_Data') $h.DataFolder
        if (Test-Path (Join-Path $Dir 'hmail_Database')) { Restore-Tree (Join-Path $Dir 'hmail_Database') $h.DatabaseFolder }
        Start-Service hMailServer; Write-OK "hMailServer restarted"
    }
    if (Test-Path "$Dir\MetaBase.xml") { Write-INFO "IIS SMTP: stop IISADMIN, copy $Dir\MetaBase.xml over $env:SystemRoot\System32\inetsrv\MetaBase.xml, start it (manual - metabase is shared with IIS6 compat)" }
    if (Test-Path (Join-Path $Dir 'MailEnable_Config')) {
        'MEPOPS', 'MEIMAPS', 'MESMTPCS', 'MEMTAS' | ForEach-Object { Stop-Service $_ -Force -ErrorAction SilentlyContinue }
        Restore-Tree (Join-Path $Dir 'MailEnable_Config'); Restore-Tree (Join-Path $Dir 'MailEnable_Postoffices')
        'MEPOPS', 'MEIMAPS', 'MESMTPCS', 'MEMTAS' | ForEach-Object { Start-Service $_ -ErrorAction SilentlyContinue }
        Write-OK "MailEnable restored"
    }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
