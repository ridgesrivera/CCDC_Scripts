#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Non-IIS web stacks on Windows: Apache (XAMPP/WAMP/standalone), nginx, Tomcat, Node/PM2.
.DESCRIPTION
    Finds each install, shows its listeners + doc roots, and backs up config +
    content (htdocs / www / webapps). Databases behind them -> MySQL.ps1 / MSSQL.ps1.
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

function Find-WebStacks {
    $out = @()
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(httpd|nginx|tomcat\d*|java|node)\.exe$' }
    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'httpd\.exe|nginx\.exe|tomcat\d*\.exe|prunsrv|pm2|node\.exe' }
    $cands = @()
    $cands += 'C:\xampp\apache', 'C:\wamp64\bin\apache\*', 'C:\wamp\bin\apache\*', 'C:\Apache24', "$env:ProgramFiles\Apache*\*", 'C:\laragon\bin\apache\*'
    $cands += 'C:\nginx', 'C:\nginx-*', "$env:ProgramFiles\nginx*"
    $cands += "$env:ProgramFiles\Apache Software Foundation\Tomcat*", 'C:\tomcat*', 'C:\xampp\tomcat'
    foreach ($p in (@($procs | ForEach-Object { $_.ExecutablePath }) + @($svcs | ForEach-Object { Get-ExePathFromCommandLine $_.PathName }))) { if ($p) { $cands += (Split-Path (Split-Path $p)) } }
    foreach ($c in $cands | ForEach-Object { Resolve-Path $_ -ErrorAction SilentlyContinue } | ForEach-Object { $_.Path } | Sort-Object -Unique) {
        $type = if (Test-Path "$c\conf\httpd.conf") { 'Apache' } elseif (Test-Path "$c\conf\nginx.conf") { 'nginx' } elseif (Test-Path "$c\conf\server.xml") { 'Tomcat' } else { $null }
        if (-not $type) { continue }
        $roots = @()
        switch ($type) {
            'Apache' {
                $conf = Get-ChildItem "$c\conf" -Recurse -Filter *.conf -ErrorAction SilentlyContinue
                $roots = $conf | Select-String -Pattern '^\s*(DocumentRoot|Alias\s+\S+)\s+"?([^"\s]+)"?' | ForEach-Object { $_.Matches.Groups[2].Value }
                $srvRoot = (Select-String "$c\conf\httpd.conf" -Pattern '^\s*Define\s+SRVROOT\s+"?([^"]+)"?' | Select-Object -First 1).Matches.Groups[1].Value
                $roots = $roots | ForEach-Object { ($_ -replace '\$\{SRVROOT\}', $srvRoot) -replace '/', '\' }
            }
            'nginx' { $roots = Get-ChildItem "$c\conf" -Recurse -Filter *.conf | Select-String '^\s*root\s+"?([^";]+)' | ForEach-Object { $r = $_.Matches.Groups[1].Value -replace '/', '\'; if ($r -notmatch '^[A-Za-z]:') { "$c\$r" } else { $r } } }
            'Tomcat' { $roots = @("$c\webapps") }
        }
        $roots = $roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
        $out += [pscustomobject]@{ Type = $type; Home = $c; Roots = @($roots) }
    }
    # Common app roots even if not referenced
    foreach ($extra in 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\wamp\www', 'C:\laragon\www', 'C:\xampp\phpMyAdmin', 'C:\xampp\php') {
        if ((Test-Path $extra) -and -not ($out.Roots -contains $extra)) { if ($out) { $out[0].Roots += $extra } }
    }
    $out
}

$Def = @{
    Name         = 'WebServersNonIIS'
    Title        = 'Apache / nginx / Tomcat on Windows'
    ServiceNames = @('Apache*', 'wampapache*', 'nginx*', 'Tomcat*')
    Description  = @"
Open-source web servers often found on Windows boxes in CCDC:
  Apache  - XAMPP (C:\xampp\apache, htdocs), WAMP (C:\wamp64), standalone
            (C:\Apache24). conf\httpd.conf + conf\extra\*.conf. PHP via mod_php
            (C:\xampp\php\php.ini).
  nginx   - conf\nginx.conf, often a reverse proxy in front of an app.
  Tomcat  - Java app server; conf\server.xml, conf\tomcat-users.xml
            (manager app creds!), webapps\*.war.
XAMPP's control panel may run Apache/MySQL as plain processes, not services.
"@
    Ports        = @(
        @{ Port = 80; Proto = 'TCP'; Use = 'HTTP' }
        @{ Port = 443; Proto = 'TCP'; Use = 'HTTPS' }
        @{ Port = 8080; Proto = 'TCP'; Use = 'Tomcat HTTP / alt' }
        @{ Port = 8443; Proto = 'TCP'; Use = 'Tomcat HTTPS / alt' }
        @{ Port = 8009; Proto = 'TCP'; Use = 'Tomcat AJP (Ghostcat CVE-2020-1938)' }
        @{ Port = 8005; Proto = 'TCP'; Use = 'Tomcat shutdown port' }
        @{ Port = 3000; Proto = 'TCP'; Use = 'Node.js apps (common)' }
    )
    KeyPaths     = @('C:\xampp', 'C:\wamp64', 'C:\Apache24', 'C:\nginx', "$env:ProgramFiles\Apache Software Foundation")
    RedTeam      = @(
        'PHP webshells in htdocs / uploads; .htaccess AddType tricks to run .jpg as PHP'
        'Tomcat manager with tomcat:tomcat / admin:admin -> deploy malicious .war'
        'XAMPP /phpmyadmin and /dashboard exposed; /server-status /server-info exposed'
        'AJP 8009 open (Ghostcat file read)'
    )
    Hardening    = @(
        'php.ini: disable_functions = exec,passthru,shell_exec,system,proc_open,popen ; expose_php=Off  (test the app!)'
        'Change / remove users in tomcat-users.xml; restrict manager to 127.0.0.1 (META-INF\context.xml RemoteAddrValve)'
        'Comment out AJP connector if unused'
        'Restrict /phpmyadmin + /dashboard to localhost (httpd-xampp.conf: Require local)'
        'Run ..\harden\Harden-IIS-PHP.ps1 for PHP/WordPress hardening'
    )
    Detect       = { [bool](Find-WebStacks) }
}

$Def.InfoExtra = {
    foreach ($w in Find-WebStacks) {
        Write-STEP "$($w.Type) at $($w.Home)"
        foreach ($r in $w.Roots) { Write-Plain "content root: $r" }
        if ($w.Type -eq 'Apache') { & "$($w.Home)\bin\httpd.exe" -v 2>$null | Select-Object -First 1 | ForEach-Object { Write-Plain $_ }; Select-String "$($w.Home)\conf\httpd.conf" -Pattern '^\s*Listen\s+' | ForEach-Object { Write-Plain $_.Line.Trim() } }
        if ($w.Type -eq 'Tomcat' -and (Test-Path "$($w.Home)\conf\tomcat-users.xml")) {
            Select-String "$($w.Home)\conf\tomcat-users.xml" -Pattern '<user\s[^>]*' | Where-Object { $_.Line -notmatch '^\s*<!--' } | ForEach-Object { Write-CRIT "tomcat user: $($_.Matches[0].Value)" }
            if (Select-String "$($w.Home)\conf\server.xml" -Pattern '<Connector[^>]*protocol="AJP' | Where-Object { $_.Line -notmatch '<!--' }) { Write-WARN "AJP connector enabled" }
        }
        foreach ($r in $w.Roots) {
            Get-ChildItem $r -Recurse -File -Include *.php, *.phtml, *.jsp, *.war, .htaccess -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddHours(-6) |
                Select-Object -First 15 | ForEach-Object { Write-WARN "recent: $($_.LastWriteTime) $($_.FullName)" }
        }
    }
}

$Def.Backup = {
    param($Dir)
    $map = @(); $i = 0
    foreach ($w in Find-WebStacks) {
        $i++
        $f = "{0:D2}_{1}_conf" -f $i, $w.Type
        if (Copy-Tree "$($w.Home)\conf" (Join-Path $Dir $f) "$($w.Type) conf ($($w.Home))") { $map += [pscustomobject]@{ Folder = $f; Source = "$($w.Home)\conf" } }
        $j = 0
        foreach ($r in $w.Roots) {
            $j++; $f = "{0:D2}_{1}_root{2}_{3}" -f $i, $w.Type, $j, ((Split-Path $r -Leaf) -replace '[^\w\.-]', '_')
            if (Copy-Tree $r (Join-Path $Dir $f) "$($w.Type) content $r" -ExcludeDirs 'logs', 'tmp', 'temp', 'work') { $map += [pscustomobject]@{ Folder = $f; Source = $r } }
        }
    }
    if (Test-Path 'C:\xampp\php\php.ini') { Copy-Item 'C:\xampp\php\php.ini' "$Dir\xampp_php.ini" -Force; Write-OK "XAMPP php.ini" }
    $map | Export-Csv "$Dir\content_map.csv" -NoTypeInformation
}

$Def.Restore = {
    param($Dir)
    foreach ($m in Import-Csv "$Dir\content_map.csv") { Restore-Tree (Join-Path $Dir $m.Folder) $m.Source -Mirror:$Mirror }
    if (Test-Path "$Dir\xampp_php.ini") { Copy-Item "$Dir\xampp_php.ini" 'C:\xampp\php\php.ini' -Force }
    foreach ($s in Get-CCDCServiceObjects @('Apache*', 'wampapache*', 'nginx*', 'Tomcat*')) { Restart-Service $s.Name -Force -ErrorAction SilentlyContinue; Write-OK "Restarted $($s.Name)" }
    Write-INFO "If XAMPP runs Apache as a process (no service), restart it from xampp-control.exe"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
