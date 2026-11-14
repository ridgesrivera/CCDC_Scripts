#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - FTP server info / backup / restore.
    Covers IIS FTP (FTPSVC) and FileZilla Server (filezilla-server / FileZilla Server).
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force,
    [switch]$Mirror
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$AppCmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
$FzPaths = @(
    "$env:ProgramData\filezilla-server"                 # FileZilla Server 1.x (settings.xml, users.xml, groups.xml)
    "${env:ProgramFiles}\FileZilla Server"              # 0.9.x (FileZilla Server.xml)
    "${env:ProgramFiles(x86)}\FileZilla Server"
)

function Get-IisFtpSites {
    if (-not (Test-Path $AppCmd)) { return @() }
    [xml]$x = & $AppCmd list site /config /xml
    $x.appcmd.SITE | Where-Object { $_.bindings -match 'ftp/' }
}

$Def = @{
    Name         = 'FTP'
    Title        = 'FTP Server (IIS FTP / FileZilla Server)'
    ServiceNames = @('FTPSVC', 'filezilla-server', 'FileZilla Server')
    Description  = @"
File Transfer Protocol. Cleartext by default - usernames and passwords fly
over the wire unless FTPS is forced. Scoring typically logs in as a user and
uploads/downloads a file, so the user, their home folder and NTFS write
permission all must survive.
  IIS FTP:    sites in applicationHost.config (bindings 'ftp/*:21:'),
              user isolation, FTP authorization rules, passive port range.
  FileZilla:  %ProgramData%\filezilla-server\ (1.x) or
              Program Files\FileZilla Server\FileZilla Server.xml (0.9.x)
"@
    Ports        = @(
        @{ Port = 21; Proto = 'TCP'; Use = 'FTP control' }
        @{ Port = 20; Proto = 'TCP'; Use = 'FTP active data' }
        @{ Port = 990; Proto = 'TCP'; Use = 'Implicit FTPS' }
        @{ Port = 14147; Proto = 'TCP'; Use = 'FileZilla 0.9 admin interface' }
        @{ Port = 14148; Proto = 'TCP'; Use = 'FileZilla 1.x admin interface' }
        @{ Port = '49152-65535'; Proto = 'TCP'; Use = 'Passive data (default range)' }
    )
    KeyPaths     = @("$env:SystemDrive\inetpub\ftproot", "$env:ProgramData\filezilla-server", "${env:ProgramFiles}\FileZilla Server")
    RedTeam      = @(
        'Anonymous login enabled with write -> drop webshell into a folder that is also a web root'
        'Sniffing cleartext creds (reuse against RDP/SMB)'
        'Adding FTP users / changing home dir to C:\'
        'FileZilla admin port exposed with weak/no admin password'
    )
    Hardening    = @(
        'Disable anonymous auth unless scoring needs it'
        'Require SSL (if scoring supports FTPS - confirm first!)'
        'FTP root must NOT overlap a web root (upload->execute)'
        'Bind FileZilla admin interface to 127.0.0.1 only'
    )
    Detect       = { (Test-ServiceInstalled 'FTPSVC', 'filezilla-server', 'FileZilla Server') }
}

$Def.InfoExtra = {
    foreach ($s in Get-IisFtpSites) {
        Write-STEP "IIS FTP site: $($s.'SITE.NAME')  bindings: $($s.bindings)"
        $ftp = $s.site.ftpServer
        Write-Plain "Anonymous auth : $($ftp.security.authentication.anonymousAuthentication.enabled)"
        Write-Plain "Basic auth     : $($ftp.security.authentication.basicAuthentication.enabled)"
        Write-Plain "SSL policy     : control=$($ftp.security.ssl.controlChannelPolicy) data=$($ftp.security.ssl.dataChannelPolicy)"
        Write-Plain "User isolation : $($ftp.userIsolation.mode)"
        if ($ftp.security.authentication.anonymousAuthentication.enabled -eq 'true') { Write-WARN "Anonymous FTP is ON" }
        & $AppCmd list config $s.'SITE.NAME' -section:system.ftpServer/security/authorization 2>$null | ForEach-Object { Write-Plain $_ }
        & $AppCmd list vdir "/app.name:$($s.'SITE.NAME')/" | ForEach-Object { Write-Plain $_ }
    }
    if (Test-Path $AppCmd) {
        & $AppCmd list config -section:system.ftpServer/firewallSupport 2>$null | ForEach-Object { Write-Plain "passive: $_" }
    }
    foreach ($p in $FzPaths) {
        if (Test-Path $p) {
            Write-STEP "FileZilla config at $p"
            Get-ChildItem $p -Filter *.xml -ErrorAction SilentlyContinue | ForEach-Object { Write-Plain "$($_.Name)  $($_.LastWriteTime)" }
            $users = Get-ChildItem $p -Filter *.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern '<user name="([^"]+)"|<User Name="([^"]+)"' -AllMatches
            foreach ($m in $users.Matches) { Write-Plain "FTP user: $(($m.Groups[1].Value, $m.Groups[2].Value) -join '')" }
        }
    }
}

$Def.Backup = {
    param($Dir)
    $map = @()
    if (Test-Path $AppCmd) {
        Copy-Item "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" "$Dir\applicationHost.config" -Force -ErrorAction SilentlyContinue
        foreach ($s in Get-IisFtpSites) {
            $n = $s.'SITE.NAME'
            & $AppCmd list site $n /config /xml > "$Dir\iis_ftp_site_$($n -replace '[^\w]','_').xml"
            $paths = (& $AppCmd list vdir "/app.name:$n/" /text:physicalPath) | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }
            $i = 0
            foreach ($p in $paths) { $i++; $f = "ftp_$($n -replace '[^\w]','_')_$i"; if (Copy-Tree $p (Join-Path $Dir "content\$f") "FTP content $p") { $map += [pscustomobject]@{ Folder = $f; Source = $p } } }
        }
        & $AppCmd list config -section:system.ftpServer/firewallSupport > "$Dir\ftp_firewallSupport.txt" 2>&1
    }
    $j = 0
    foreach ($p in $FzPaths) {
        if (Test-Path $p) {
            $j++; Copy-Tree $p (Join-Path $Dir "filezilla_$j") "FileZilla config $p" -ExcludeDirs 'logs' | Out-Null
            $map += [pscustomobject]@{ Folder = "..\filezilla_$j"; Source = $p }
        }
    }
    $map | Export-Csv "$Dir\content_map.csv" -NoTypeInformation
}

$Def.Restore = {
    param($Dir)
    foreach ($m in Import-Csv "$Dir\content_map.csv") { Restore-Tree (Join-Path $Dir "content\$($m.Folder)") $m.Source -Mirror:$Mirror }
    Write-INFO "IIS FTP site config lives in applicationHost.config -> run IIS.ps1 -Action Restore to roll it back"
    foreach ($svc in 'FTPSVC', 'filezilla-server', 'FileZilla Server') { if (Get-Service $svc -ErrorAction SilentlyContinue) { Restart-Service $svc -Force; Write-OK "Restarted $svc" } }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
