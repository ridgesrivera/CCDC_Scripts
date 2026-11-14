#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - MySQL / MariaDB on Windows (standalone, XAMPP, WAMP, Laragon) info / backup / restore.
.DESCRIPTION
    Finds mysqld via services + common install folders, reads my.ini, runs
    mysqldump --all-databases (routines, events, triggers) and copies my.ini.
    Credentials: -DbUser root -DbPassword ...  (XAMPP default root has NO password).
.EXAMPLE
    .\MySQL.ps1 -DbUser root -DbPassword 'pw'
    .\MySQL.ps1 -Action Restore -DbUser root -DbPassword 'pw'
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [string]$DbUser = 'root',
    [string]$DbPassword,
    [int]$DbPort = 0
)
. "$PSScriptRoot\_ServiceCommon.ps1"

function Find-MySql {
    $res = @()
    $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'mysqld|mariadbd' }
    foreach ($s in $svcs) {
        $exe = Get-ExePathFromCommandLine $s.PathName
        $ini = if ($s.PathName -match '--defaults-file="?([^"]+?)"?(\s|$)') { $Matches[1] } else { $null }
        $res += [pscustomobject]@{ Source = "service:$($s.Name)"; Service = $s.Name; Bin = Split-Path $exe; Ini = $ini; State = $s.State }
    }
    foreach ($d in 'C:\xampp\mysql\bin', 'C:\wamp64\bin\mysql\*\bin', 'C:\wamp\bin\mysql\*\bin', 'C:\laragon\bin\mysql\*\bin', "$env:ProgramFiles\MySQL\*\bin", "$env:ProgramFiles\MariaDB*\bin") {
        foreach ($b in (Resolve-Path $d -ErrorAction SilentlyContinue)) {
            if (-not ($res | Where-Object { $_.Bin -eq $b.Path })) {
                $p = Get-Process mysqld, mariadbd -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$($b.Path)*" }
                $res += [pscustomobject]@{ Source = 'folder'; Service = $null; Bin = $b.Path; Ini = $null; State = $(if ($p) { 'Running (no service)' } else { 'Stopped' }) }
            }
        }
    }
    foreach ($r in $res) {
        if (-not $r.Ini) {
            $cand = @("$($r.Bin)\..\my.ini", "$($r.Bin)\..\data\my.ini", "$env:ProgramData\MySQL\*\my.ini", 'C:\xampp\mysql\bin\my.ini') | ForEach-Object { Resolve-Path $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
            if ($cand) { $r.Ini = $cand.Path }
        }
        $r | Add-Member -NotePropertyName DataDir -NotePropertyValue $null -Force
        $r | Add-Member -NotePropertyName Port -NotePropertyValue 3306 -Force
        if ($r.Ini -and (Test-Path $r.Ini)) {
            $txt = Get-Content $r.Ini
            $dd = ($txt | Select-String '^\s*datadir\s*=\s*"?([^"]+)"?' | Select-Object -First 1).Matches.Groups[1].Value
            $pt = ($txt | Select-String '^\s*port\s*=\s*(\d+)' | Select-Object -First 1).Matches.Groups[1].Value
            if ($dd) { $r.DataDir = $dd.Trim() }; if ($pt) { $r.Port = [int]$pt }
        }
    }
    $res
}

function Get-MyArgs { param($Inst)
    $a = @("--user=$DbUser", '--host=127.0.0.1', "--port=$(if ($DbPort) { $DbPort } else { $Inst.Port })")
    if ($DbPassword) { $a += "--password=$DbPassword" }
    $a
}

$Def = @{
    Name         = 'MySQL'
    Title        = 'MySQL / MariaDB (Windows)'
    ServiceNames = @('MySQL*', 'MariaDB*', 'mysql')
    Description  = @"
Open-source database used by PHP apps (WordPress, Joomla, osCommerce,
PrestaShop, custom shops) on XAMPP/WAMP or standalone. Config is my.ini;
data lives in the datadir (one folder per database). App credentials are in
the app config (wp-config.php, configuration.php, .env, config.inc.php).
root@localhost with no password is the XAMPP default. phpMyAdmin (if
present at /phpmyadmin) is a full DB admin panel exposed over the web.
"@
    Ports        = @(
        @{ Port = 3306; Proto = 'TCP'; Use = 'MySQL / MariaDB' }
        @{ Port = 33060; Proto = 'TCP'; Use = 'MySQL X protocol (8.x)' }
    )
    KeyPaths     = @('C:\xampp\mysql', 'C:\wamp64\bin\mysql', "$env:ProgramData\MySQL", "$env:ProgramFiles\MySQL", 'C:\xampp\phpMyAdmin\config.inc.php')
    RedTeam      = @(
        'root with blank password / remote root (root@%)'
        'SELECT ... INTO OUTFILE into the web root -> webshell'
        'UDF (lib_mysqludf_sys) for command execution'
        'phpMyAdmin with config auth (auto-login) exposed to the world'
        'Dumping users / customer tables (PII deduction)'
    )
    Hardening    = @(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '<new>';  then update the app config file"
        "DROP USER 'root'@'%'; remove anonymous users ''@'localhost'"
        'bind-address=127.0.0.1 in my.ini if only the local web app uses it'
        'secure_file_priv set to a non-web folder'
        'Restrict /phpmyadmin to localhost (httpd-xampp.conf: Require local)'
    )
    Detect       = { [bool](Find-MySql) }
}

$Def.InfoExtra = {
    foreach ($m in Find-MySql) {
        Write-STEP "Instance via $($m.Source)  [$($m.State)]"
        Write-Plain "bin: $($m.Bin)"; Write-Plain "ini: $($m.Ini)"; Write-Plain "datadir: $($m.DataDir)   port: $($m.Port)"
        $mysql = Join-Path $m.Bin 'mysql.exe'
        if (Test-Path $mysql) {
            $q = "SELECT user,host,plugin,IF(authentication_string='' ,'EMPTY-PW','set') FROM mysql.user; SHOW DATABASES; SHOW VARIABLES WHERE Variable_name IN ('bind_address','secure_file_priv','version','port');"
            $out = & $mysql @(Get-MyArgs $m) -N -e $q 2>&1
            foreach ($l in $out) { if ("$l" -match 'EMPTY-PW|\t%\t') { Write-WARN "$l" } else { Write-Plain "$l" } }
        }
        if (Test-Path 'C:\xampp\phpMyAdmin\config.inc.php') {
            $auth = Select-String 'C:\xampp\phpMyAdmin\config.inc.php' -Pattern "auth_type'\]\s*=\s*'(\w+)" | Select-Object -First 1
            if ($auth -and $auth.Matches.Groups[1].Value -eq 'config') { Write-CRIT "phpMyAdmin auth_type=config (auto-login, no password prompt)" }
        }
    }
}

$Def.Backup = {
    param($Dir)
    $n = 0
    foreach ($m in Find-MySql) {
        $n++; $iDir = Join-Path $Dir "instance_$n"; New-Item -ItemType Directory $iDir -Force | Out-Null
        $m | Export-Clixml "$iDir\instance.xml"
        if ($m.Ini) { Copy-Item $m.Ini "$iDir\my.ini" -Force -ErrorAction SilentlyContinue }
        $dump = Join-Path $m.Bin 'mysqldump.exe'
        if (-not (Test-Path $dump)) { $dump = Join-Path $m.Bin 'mariadb-dump.exe' }
        if ((Test-Path $dump) -and $m.State -match 'Running') {
            $f = Join-Path $iDir 'all_databases.sql'
            $a = @(Get-MyArgs $m) + @('--all-databases', '--routines', '--events', '--triggers', '--single-transaction', '--add-drop-database', "--result-file=$f")
            $err = & $dump @a 2>&1
            if ((Test-Path $f) -and (Get-Item $f).Length -gt 1000) { Write-OK ("mysqldump -> {0} ({1:N1} MB)" -f $f, ((Get-Item $f).Length / 1MB)) }
            else { Write-WARN "mysqldump failed: $err  (wrong -DbUser/-DbPassword?)" }
            # per-database dumps too (easier single-DB restore)
            $mysql = Join-Path $m.Bin 'mysql.exe'
            $dbs = & $mysql @(Get-MyArgs $m) -N -e "SHOW DATABASES" 2>$null | Where-Object { $_ -notmatch '^(information_schema|performance_schema|sys)$' }
            foreach ($db in $dbs) { & $dump @(Get-MyArgs $m) --routines --events --triggers --single-transaction --databases $db "--result-file=$iDir\db_$db.sql" 2>$null }
        } else {
            Write-WARN "mysqld not running or dump tool missing - copying datadir cold (stop the service first for a consistent copy)"
        }
        if ($m.DataDir -and (Test-Path $m.DataDir) -and $m.State -notmatch 'Running') { Copy-Tree $m.DataDir (Join-Path $iDir 'datadir') 'MySQL datadir (cold)' | Out-Null }
    }
}

$Def.Restore = {
    param($Dir)
    foreach ($iDir in Get-ChildItem $Dir -Directory -Filter 'instance_*') {
        $m = Import-Clixml "$($iDir.FullName)\instance.xml"
        $mysql = Join-Path $m.Bin 'mysql.exe'
        $sqlFiles = Get-ChildItem $iDir.FullName -Filter 'db_*.sql'
        Write-INFO "Per-DB dumps available: $(($sqlFiles.BaseName -replace '^db_','') -join ', ')"
        $pick = if ($script:CCDCForce) { 'ALL' } else { Read-Host "  Database to restore (name, or ALL for all_databases.sql)" }
        $file = if ($pick -eq 'ALL') { "$($iDir.FullName)\all_databases.sql" } else { "$($iDir.FullName)\db_$pick.sql" }
        if (-not (Test-Path $file)) { Write-WARN "Not found: $file"; continue }
        $cmdline = "`"$mysql`" $((Get-MyArgs $m) -join ' ') < `"$file`""
        & cmd.exe /c $cmdline
        if ($LASTEXITCODE -eq 0) { Write-OK "Restored $file" } else { Write-WARN "mysql import exit $LASTEXITCODE" }
        if ((Test-Path "$($iDir.FullName)\my.ini") -and $m.Ini -and (Confirm-Action "Also restore my.ini to $($m.Ini)?")) { Copy-Item "$($iDir.FullName)\my.ini" $m.Ini -Force; Write-OK "my.ini restored (restart MySQL)" }
    }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
