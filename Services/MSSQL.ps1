#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Microsoft SQL Server (services: MSSQLSERVER / MSSQL$<instance>) info / backup / restore.
.DESCRIPTION
    Uses .NET SqlClient (no sqlcmd / SqlServer module needed - works on Server Core).
    Default auth = Windows integrated (you must be sysadmin in SQL; local admins
    often are NOT on newer installs). Use -SqlUser sa -SqlPassword ... otherwise.
    Backups are COPY_ONLY full backups (do not break any existing backup chain).
.EXAMPLE
    .\MSSQL.ps1
    .\MSSQL.ps1 -Action Backup -SqlUser sa -SqlPassword 'P@ss'
    .\MSSQL.ps1 -Action Restore -Database shopdb       # restore one DB from latest backup
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [string]$SqlUser,
    [string]$SqlPassword,
    [string]$Instance,          # e.g. SQLEXPRESS ; default = every instance found
    [string]$Database           # restore only this DB
)
. "$PSScriptRoot\_ServiceCommon.ps1"

function Get-SqlInstances {
    $k = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (-not (Test-Path $k)) { return @() }
    $p = Get-ItemProperty $k
    foreach ($n in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        $id = $n.Value
        $tcp = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$id\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        $t = Get-ItemProperty $tcp -ErrorAction SilentlyContinue
        $setup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$id\Setup" -ErrorAction SilentlyContinue
        $mss = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$id\MSSQLServer" -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Name       = $n.Name
            Id         = $id
            Service    = if ($n.Name -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$($n.Name)" }
            Server     = if ($n.Name -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$($n.Name)" }
            TcpPort    = $t.TcpPort
            TcpDynamic = $t.TcpDynamicPorts
            Edition    = $setup.Edition
            Version    = $setup.Version
            LoginMode  = if ($mss.LoginMode -eq 2) { 'Mixed (SQL + Windows)' } else { 'Windows only' }
            BackupDir  = $mss.BackupDirectory
        }
    }
}

function Invoke-Sql {
    param([string]$Server, [string]$Query, [string]$Db = 'master', [int]$Timeout = 3600)
    $cs = if ($SqlUser) { "Server=$Server;Database=$Db;User ID=$SqlUser;Password=$SqlPassword;Connect Timeout=10" } else { "Server=$Server;Database=$Db;Integrated Security=True;Connect Timeout=10" }
    $cn = New-Object System.Data.SqlClient.SqlConnection $cs
    $cn.Open()
    try {
        $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = $Timeout
        $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        $dt = New-Object System.Data.DataTable; [void]$da.Fill($dt)
        $cols = @($dt.Columns | ForEach-Object { $_.ColumnName })
        if ($dt.Rows.Count -gt 0) { $dt.Rows | Select-Object -Property $cols }
    } finally { $cn.Close() }
}

$Def = @{
    Name         = 'MSSQL'
    Title        = 'Microsoft SQL Server'
    ServiceNames = @('MSSQLSERVER', 'MSSQL$*', 'SQLSERVERAGENT', 'SQLAgent$*', 'SQLBrowser')
    Description  = @"
Relational database behind most Windows web apps / e-commerce (the IIS site's
web.config <connectionStrings> tells you which DB and which login).
  MSSQLSERVER / MSSQL`$NAME = database engine     SQLBrowser = tells clients
  which port a named instance is on (UDP 1434)    SQLAgent = scheduled jobs
Default instance listens on 1433; named instances (SQLEXPRESS) use a DYNAMIC
port unless set - check the registry IPAll\TcpPort shown below.
'sa' + xp_cmdshell = OS command execution as the SQL service account.
"@
    Ports        = @(
        @{ Port = 1433; Proto = 'TCP'; Use = 'SQL Server default instance' }
        @{ Port = 1434; Proto = 'UDP'; Use = 'SQL Browser (named instance lookup)' }
        @{ Port = 1434; Proto = 'TCP'; Use = 'Dedicated Admin Connection (DAC)' }
        @{ Port = 2383; Proto = 'TCP'; Use = 'Analysis Services' }
    )
    KeyPaths     = @('HKLM\SOFTWARE\Microsoft\Microsoft SQL Server')
    RedTeam      = @(
        'xp_cmdshell enabled -> OS commands (often as a privileged service account)'
        'sa with weak/default password; new sysadmin logins'
        'SQL Agent jobs that run PowerShell/CmdExec (persistence)'
        'Dumping customer tables / credit cards (PII deduction)'
        'Linked servers / TRUSTWORTHY databases for privesc'
        'DROP DATABASE or truncate tables to kill the scored app'
    )
    Hardening    = @(
        "EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;"
        'Change sa password (and the app login - update web.config connectionString too!)'
        'Disable logins you do not recognize; review sysadmin role members'
        'Review SQL Agent jobs (Info output)'
        'Firewall 1433 to the web server IP only if DB is on a separate box'
    )
    Detect       = { [bool](Get-SqlInstances) }
}

$Def.InfoExtra = {
    foreach ($i in Get-SqlInstances) {
        Write-STEP "Instance $($i.Name)  ($($i.Edition) $($i.Version))"
        Write-Plain "Service: $($i.Service)  Connect: $($i.Server)  TCP port: $($i.TcpPort)  dynamic: $($i.TcpDynamic)"
        Write-Plain "Auth mode: $($i.LoginMode)   Default backup dir: $($i.BackupDir)"
        try {
            $dbs = Invoke-Sql $i.Server "SELECT name, state_desc, recovery_model_desc, CAST(SUM(mf.size)*8/1024 AS int) AS MB FROM sys.databases d JOIN sys.master_files mf ON d.database_id=mf.database_id GROUP BY name,state_desc,recovery_model_desc"
            foreach ($d in $dbs) { Write-Plain ("DB {0,-30} {1,-8} {2,-8} {3} MB" -f $d.name, $d.state_desc, $d.recovery_model_desc, $d.MB) }
            $sa = Invoke-Sql $i.Server "SELECT p.name, p.type_desc, p.is_disabled FROM sys.server_principals p JOIN sys.server_role_members m ON p.principal_id=m.member_principal_id WHERE m.role_principal_id=SUSER_ID('sysadmin')"
            foreach ($s in $sa) { Write-WARN ("sysadmin: {0} ({1}) disabled={2}" -f $s.name, $s.type_desc, $s.is_disabled) }
            $cfg = Invoke-Sql $i.Server "SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures','remote access','Ad Hoc Distributed Queries')"
            foreach ($c in $cfg) { if ([int]$c.value_in_use -eq 1 -and $c.name -ne 'remote access') { Write-CRIT "$($c.name) ENABLED" } else { Write-Plain "$($c.name) = $($c.value_in_use)" } }
            $jobs = Invoke-Sql $i.Server "SELECT j.name, j.enabled, s.subsystem, LEFT(s.command,120) AS cmd FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id=s.job_id"
            foreach ($j in $jobs) { $l = "Agent job: $($j.name) [$($j.subsystem)] $($j.cmd)"; if ($j.subsystem -match 'CmdExec|PowerShell|ActiveScripting') { Write-WARN $l } else { Write-Plain $l } }
            $ls = Invoke-Sql $i.Server "SELECT name, type_desc, create_date FROM sys.server_principals WHERE type IN ('S','U','G') AND create_date > DATEADD(hour,-24,GETDATE())"
            foreach ($l in $ls) { Write-WARN "Login created in last 24h: $($l.name) $($l.create_date)" }
        } catch { Write-WARN "Cannot query $($i.Server): $($_.Exception.Message)  (try -SqlUser sa -SqlPassword ...)" }
    }
}

$Def.Backup = {
    param($Dir)
    foreach ($i in Get-SqlInstances) {
        if ($Instance -and $i.Name -ne $Instance) { continue }
        $iDir = Join-Path $Dir $i.Name; New-Item -ItemType Directory $iDir -Force | Out-Null
        # SQL Server writes the .bak as ITS service account -> write to its own backup dir, then move.
        $stage = if ($i.BackupDir -and (Test-Path $i.BackupDir)) { $i.BackupDir } else { $iDir }
        try {
            $dbs = Invoke-Sql $i.Server "SELECT name FROM sys.databases WHERE name <> 'tempdb' AND state_desc='ONLINE'"
        } catch { Write-WARN "Cannot connect to $($i.Server): $($_.Exception.Message)"; continue }
        foreach ($d in $dbs) {
            $f = Join-Path $stage "CCDC_$($d.name)_$($script:CCDCStamp).bak"
            try {
                Invoke-Sql $i.Server "BACKUP DATABASE [$($d.name)] TO DISK = N'$f' WITH COPY_ONLY, INIT, CHECKSUM" | Out-Null
                if ($stage -ne $iDir) { Move-Item $f (Join-Path $iDir "$($d.name).bak") -Force } else { Rename-Item $f "$($d.name).bak" -Force }
                Write-OK "[$($i.Name)] $($d.name).bak"
            } catch { Write-WARN "[$($i.Name)] $($d.name): $($_.Exception.Message)" }
        }
        # Logins / config / jobs inventory (for rebuild)
        try {
            Invoke-Sql $i.Server "SELECT name, type_desc, is_disabled, default_database_name, create_date FROM sys.server_principals WHERE type IN ('S','U','G')" | Export-Csv "$iDir\logins.csv" -NoTypeInformation
            Invoke-Sql $i.Server "SELECT r.name AS role, p.name AS member FROM sys.server_role_members m JOIN sys.server_principals r ON r.principal_id=m.role_principal_id JOIN sys.server_principals p ON p.principal_id=m.member_principal_id" | Export-Csv "$iDir\server_roles.csv" -NoTypeInformation
            Invoke-Sql $i.Server "SELECT name, value_in_use FROM sys.configurations" | Export-Csv "$iDir\sp_configure.csv" -NoTypeInformation
            Invoke-Sql $i.Server "SELECT j.name, j.enabled, s.step_name, s.subsystem, s.command FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id=s.job_id" | Export-Csv "$iDir\agent_jobs.csv" -NoTypeInformation
        } catch {}
        Export-RegKey "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\$($i.Id)" "$iDir\reg_instance.reg" | Out-Null
        $i | Export-Clixml "$iDir\instance.xml"
    }
}

$Def.Restore = {
    param($Dir)
    foreach ($iDir in Get-ChildItem $Dir -Directory | Where-Object { Test-Path "$($_.FullName)\instance.xml" }) {
        $i = Import-Clixml "$($iDir.FullName)\instance.xml"
        if ($Instance -and $i.Name -ne $Instance) { continue }
        foreach ($bak in Get-ChildItem $iDir.FullName -Filter *.bak) {
            $db = $bak.BaseName
            if ($Database -and $db -ne $Database) { continue }
            if ($db -in 'master', 'model', 'msdb') { Write-INFO "Skipping system DB $db (needs single-user mode - do by hand)"; continue }
            if (-not (Confirm-Action "Overwrite database [$db] on $($i.Server) from $($bak.Name)?")) { continue }
            # copy to a place the SQL service can read
            $stage = if ($i.BackupDir -and (Test-Path $i.BackupDir)) { $i.BackupDir } else { $env:TEMP }
            $f = Join-Path $stage "CCDC_restore_$db.bak"; Copy-Item $bak.FullName $f -Force
            try {
                Invoke-Sql $i.Server "IF DB_ID('$db') IS NOT NULL ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [$db] FROM DISK=N'$f' WITH REPLACE, RECOVERY; ALTER DATABASE [$db] SET MULTI_USER;" | Out-Null
                Write-OK "Restored [$db] on $($i.Server)"
            } catch { Write-WARN "[$db]: $($_.Exception.Message)" }
            Remove-Item $f -Force -ErrorAction SilentlyContinue
        }
    }
    Write-INFO "Orphaned SQL users after restore? -> ALTER USER [x] WITH LOGIN = [x]"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
