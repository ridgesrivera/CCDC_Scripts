<#
.SYNOPSIS
    Harden-MSSQL - audit SQL Server logins and switch off the features that turn a SQL login into a shell. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      A SQL Server is a common way from one weak password to the whole box.
      SQL Server has features that reach outside
      the database: xp_cmdshell runs operating-system commands as the service
      account, so anyone with a sysadmin login (or the default 'sa' password)
      owns the box. This script audits, then turns those features off.

    AUDIT (always, read-only)
      * sa: enabled? renamed?            * every sysadmin login
      * SQL logins with a BLANK password or password = login name (PWDCOMPARE)
      * SQL logins without password policy   * linked servers, TRUSTWORTHY databases
      * authentication mode, service account (LocalSystem = SQL commands run as SYSTEM)

    CHANGES (each confirmed y/N unless -Force)
      MODULE                  sp_configure option               WHO NEEDS IT ON
      DisableXpCmdshell       xp_cmdshell                        almost nobody
      DisableOleAutomation    Ole Automation Procedures          old maintenance scripts
      DisableAdHocQueries     Ad Hoc Distributed Queries         OPENROWSET imports
      DisableClr              clr enabled                        apps with .NET assemblies: SKIPPED
                                                                 automatically if user assemblies exist
      DisableRemoteDac        remote admin connections           nobody during a competition
      -DisableLogin a,b       ALTER LOGIN [a] DISABLE            (never 'sa' unless you name it)
      -RotateLogin x     prompts for a new password for login x. If an application
                              or the scoring engine logs in as x: update the app config
                              and file a Password Change Request FIRST.

    WHAT IT READS    SQL Server configuration and login catalog (sys.configurations, sys.sql_logins...)
    WHAT IT CHANGES  the sp_configure options above; logins only when asked. No data is touched.
    HOW TO UNDO      C:\ccdc\logs\Harden-MSSQL_*_rollback.sql puts each option back.

    CONNECTING
      Default is Windows authentication (you must be sysadmin in SQL). Local
      administrators are often NOT sysadmin on newer installs: then pass
      -SqlUser sa and type the password when asked (it is never written to disk).

    MANUAL EQUIVALENT
      sqlcmd -S localhost -E
        SELECT name, is_disabled FROM sys.sql_logins;
        EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
        EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
        ALTER LOGIN [x] DISABLE;      ALTER LOGIN [sa] WITH PASSWORD = '...';

.EXAMPLE
    .\Harden-MSSQL.ps1 -WhatIf                 # audit + show what would change
.EXAMPLE
    .\Harden-MSSQL.ps1 -Instance SQLEXPRESS -SqlUser sa
.EXAMPLE
    .\Harden-MSSQL.ps1 -Only DisableXpCmdshell -DisableLogin backdoor -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('DisableXpCmdshell', 'DisableOleAutomation', 'DisableAdHocQueries', 'DisableClr', 'DisableRemoteDac')][string[]]$Only = @(),
    [string[]]$Skip = @(),
    [string[]]$DisableLogin = @(),
    [string]$RotateLogin,
    [string]$Instance,
    [string]$SqlUser,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Harden-MSSQL'
$null = Get-CcdcConfig -Path $ConfigPath

# ---------------------------------------------------------------------------
# Instances (from the registry: works without sqlcmd or the SqlServer module)
# ---------------------------------------------------------------------------
$instances = @()
$instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
if (Test-Path $instKey) {
    $ip = Get-ItemProperty $instKey
    foreach ($n in ($ip.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        if ($Instance -and $n.Name -ne $Instance) { continue }
        $instances += [pscustomobject]@{ Name = $n.Name; Server = $(if ($n.Name -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$($n.Name)" }) }
    }
}
if ($instances.Count -eq 0) {
    Write-Finding -Level INFO -Category 'Setup' -Message 'No SQL Server instance found on this machine.'
    Complete-Ccdc; return
}

$sqlPlain = $null
if ($SqlUser) {
    $sec = Read-Host -AsSecureString "  Password for SQL login '$SqlUser' (not saved)"
    $sqlPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

function Invoke-Sql {
    # Runs one statement and returns rows as objects. Uses .NET SqlClient.
    param([string]$Server, [string]$Query)
    $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $b['Data Source'] = $Server; $b['Initial Catalog'] = 'master'; $b['Connect Timeout'] = 8
    if ($SqlUser) { $b['User ID'] = $SqlUser; $b['Password'] = $sqlPlain } else { $b['Integrated Security'] = $true }
    $cn = New-Object System.Data.SqlClient.SqlConnection $b.ConnectionString
    $cn.Open()
    try {
        $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 60
        $table = New-Object System.Data.DataTable
        $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        [void]$da.Fill($table)
        return @($table.Rows)
    } finally { $cn.Close() }
}

$modules = [ordered]@{
    DisableXpCmdshell    = 'xp_cmdshell'
    DisableOleAutomation = 'Ole Automation Procedures'
    DisableAdHocQueries  = 'Ad Hoc Distributed Queries'
    DisableClr           = 'clr enabled'
    DisableRemoteDac     = 'remote admin connections'
}
$run = if ($Only.Count -gt 0) { $Only } else { @($modules.Keys | Where-Object { $Skip -notcontains $_ }) }
$rollback = $script:CcdcLogFile -replace '\.log$', '_rollback.sql'
$rollbackLines = New-Object System.Collections.ArrayList
[void]$rollbackLines.Add("-- Rollback for Harden-MSSQL run $($script:CcdcStamp). Run in sqlcmd / SSMS against the instance named in each block.")

foreach ($inst in $instances) {
    $server = $inst.Server
    Write-Section "Instance $($inst.Name)  ($server)"
    try { $ver = Invoke-Sql $server "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(40)) AS v, CAST(SERVERPROPERTY('Edition') AS nvarchar(80)) AS e, CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS winonly, IS_SRVROLEMEMBER('sysadmin') AS sa, SUSER_SNAME() AS me" | Select-Object -First 1 }
    catch {
        Write-Finding -Level RED -Category 'Connect' -Message "Cannot connect to ${server}: $($_.Exception.Message)" -Detail 'Is the service running? If Windows auth is refused, retry with -SqlUser sa (you will be asked for the password).'
        continue
    }
    Write-Finding -Level INFO -Category 'Instance' -Message ("SQL Server {0} {1}; connected as {2}" -f $ver.v, $ver.e, $ver.me)
    if ([int]$ver.sa -ne 1) {
        Write-Finding -Level RED -Category 'Connect' -Message "$($ver.me) is NOT sysadmin on this instance: cannot audit or change it." -Detail 'Retry with -SqlUser sa, or add yourself: start SQL in single-user mode (-m) and run sp_addsrvrolemember.'
        continue
    }
    if ([int]$ver.winonly -eq 1) { Write-Finding -Level GREEN -Category 'Auth' -Message 'Windows authentication only: SQL logins such as sa cannot be used at all.' }
    else { Write-Finding -Level YELLOW -Category 'Auth' -Message 'Mixed mode: SQL logins (sa and friends) can log in with a password over the network.' }

    # --- logins ---------------------------------------------------------------
    $sa = Invoke-Sql $server "SELECT name, is_disabled FROM sys.sql_logins WHERE sid = 0x01" | Select-Object -First 1
    if ($sa) {
        if ([bool]$sa.is_disabled) { Write-Finding -Level GREEN -Category 'sa' -Message "Built-in admin login '$($sa.name)' is disabled." }
        elseif ([int]$ver.winonly -ne 1) { Write-Finding -Level RED -Category 'sa' -Message "Built-in admin login '$($sa.name)' is ENABLED in mixed mode: first thing Red Team tries." -Detail "Does an application log in as sa? Check its connection string first. Then either`n  rotate:  .\Harden-MSSQL.ps1 -RotateLogin $($sa.name)`n  disable: .\Harden-MSSQL.ps1 -DisableLogin $($sa.name)" }
    }
    $admins = @(Invoke-Sql $server "SELECT p.name, p.type_desc, p.is_disabled FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = 'sysadmin'")
    foreach ($a in $admins) {
        $builtin = $a.name -match '^(sa|NT SERVICE\\|NT AUTHORITY\\SYSTEM|##)'
        Write-Finding -Level $(if ($builtin -or [bool]$a.is_disabled) { 'INFO' } else { 'YELLOW' }) -Category 'sysadmin' -Message ("{0} ({1}){2}" -f $a.name, $a.type_desc, $(if ([bool]$a.is_disabled) { ' [disabled]' } else { '' })) -Detail $(if ($builtin) { '' } else { "Known and needed? If not: .\Harden-MSSQL.ps1 -DisableLogin '$($a.name)'" })
    }
    # PWDCOMPARE checks a guess against the stored hash without us ever seeing the password.
    $weak = @(Invoke-Sql $server "SELECT name, CASE WHEN PWDCOMPARE('', password_hash) = 1 THEN 'BLANK password' WHEN PWDCOMPARE(name, password_hash) = 1 THEN 'password = login name' WHEN PWDCOMPARE('password', password_hash) = 1 THEN 'password = password' WHEN PWDCOMPARE('Password1', password_hash) = 1 THEN 'password = Password1' WHEN PWDCOMPARE('sa', password_hash) = 1 THEN 'password = sa' END AS why FROM sys.sql_logins WHERE is_disabled = 0 AND (PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('password', password_hash) = 1 OR PWDCOMPARE('Password1', password_hash) = 1 OR PWDCOMPARE('sa', password_hash) = 1)")
    foreach ($w in $weak) { Write-Finding -Level RED -Category 'WeakLogin' -Message ("SQL login '{0}': {1}" -f $w.name, $w.why) -Detail "Fix: .\Harden-MSSQL.ps1 -RotateLogin '$($w.name)'   (update the application that uses it)" }
    if ($weak.Count -eq 0) { Write-Finding -Level GREEN -Category 'WeakLogin' -Message 'No enabled SQL login has a blank or trivially guessable password.' }
    $noPolicy = @(Invoke-Sql $server "SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND is_policy_checked = 0 AND name NOT LIKE '##%'")
    if ($noPolicy.Count -gt 0) { Write-Finding -Level YELLOW -Category 'Policy' -Message ("SQL logins exempt from the Windows password policy (no lockout): {0}" -f (($noPolicy | ForEach-Object { $_.name }) -join ', ')) -Detail 'Fix per login: ALTER LOGIN [x] WITH CHECK_POLICY = ON;' }

    $linked = @(Invoke-Sql $server "SELECT name, data_source FROM sys.servers WHERE is_linked = 1")
    foreach ($l in $linked) { Write-Finding -Level YELLOW -Category 'Linked' -Message ("Linked server '{0}' -> {1}" -f $l.name, $l.data_source) -Detail 'A linked server lets a login here run queries (and often commands) on another server. Needed?' }
    $trust = @(Invoke-Sql $server "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb'")
    foreach ($t in $trust) { Write-Finding -Level YELLOW -Category 'Trustworthy' -Message "Database '$($t.name)' is TRUSTWORTHY: its owner-level code can act as sysadmin." -Detail "Fix (if the app does not need it): ALTER DATABASE [$($t.name)] SET TRUSTWORTHY OFF;" }
    try {
        foreach ($s in @(Invoke-Sql $server "SELECT servicename, service_account FROM sys.dm_server_services")) {
            $lvl = if ($s.service_account -match '(?i)LocalSystem|NT AUTHORITY\\SYSTEM|Administrator') { 'YELLOW' } else { 'INFO' }
            Write-Finding -Level $lvl -Category 'Service' -Message ("{0} runs as {1}" -f $s.servicename, $s.service_account) -Detail $(if ($lvl -eq 'YELLOW') { 'Anything SQL executes on the OS (xp_cmdshell, agent jobs) runs with that power.' } else { '' })
        }
    } catch { $null = $_ }

    # --- dangerous features ------------------------------------------------------
    $cfg = @{}
    foreach ($r in @(Invoke-Sql $server "SELECT name, CAST(value_in_use AS int) AS v FROM sys.configurations")) { $cfg[[string]$r.name] = [int]$r.v }
    $userAssemblies = @(Invoke-Sql $server "SELECT COUNT(*) AS n FROM (SELECT 1 AS x FROM sys.assemblies WHERE is_user_defined = 1) q")[0].n
    foreach ($m in $modules.Keys) {
        $opt = $modules[$m]
        if (-not $cfg.ContainsKey($opt)) { continue }
        if ($cfg[$opt] -eq 0) { Write-Finding -Level GREEN -Category 'Feature' -Message "$opt is off."; continue }
        $lvl = if ($m -eq 'DisableXpCmdshell') { 'RED' } else { 'YELLOW' }
        Write-Finding -Level $lvl -Category 'Feature' -Message "$opt is ON." -Detail $(if ($m -eq 'DisableXpCmdshell') { 'Any sysadmin login = operating-system shell as the SQL service account.' } else { '' })
        if ($run -notcontains $m) { continue }
        if ($m -eq 'DisableClr' -and [int]$userAssemblies -gt 0) {
            Write-Finding -Level YELLOW -Category 'Feature' -Message "Leaving 'clr enabled' ON: $userAssemblies user assembly(ies) exist in master, so an application probably needs it." -Detail 'Check each database: SELECT name FROM sys.assemblies WHERE is_user_defined = 1. Force with -Only DisableClr.'
            if ($Only -notcontains 'DisableClr') { continue }
        }
        $old = $cfg[$opt]
        $undo = "-- $server`nEXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '$opt', $old; RECONFIGURE;"
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$server : $opt" -Action 'Turn OFF (sp_configure ... 0)' -Undo ($undo -replace "`n", ' ') -ScriptBlock {
            $null = Invoke-Sql $server "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '$opt', 0; RECONFIGURE;"
        }
        if ($ok) { [void]$rollbackLines.Add($undo) }
    }

    # --- logins on request ---------------------------------------------------------
    foreach ($login in $DisableLogin) {
        $safe = $login -replace '\]', ']]'
        $exists = @(Invoke-Sql $server ("SELECT name FROM sys.server_principals WHERE name = N'{0}'" -f ($login -replace "'", "''")))
        if ($exists.Count -eq 0) { Write-Finding -Level YELLOW -Category 'Login' -Message "Login '$login' does not exist on $server."; continue }
        $undo = "-- $server`nALTER LOGIN [$safe] ENABLE;"
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$server : login $login" -Action 'Disable login' -Undo "ALTER LOGIN [$safe] ENABLE;" -ScriptBlock {
            $null = Invoke-Sql $server "ALTER LOGIN [$safe] DISABLE;"
        }
        if ($ok) { [void]$rollbackLines.Add($undo); Write-Finding -Level YELLOW -Category 'Login' -Message "Existing connections of '$login' stay open. Kill them: SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = '$login';  then  KILL <id>;" }
    }
    if ($RotateLogin) {
        $safe = $RotateLogin -replace '\]', ']]'
        Write-Finding -Level YELLOW -Category 'Login' -Message "Changing the password of '$RotateLogin' breaks every application that logs in with it until its config is updated." -Detail 'Scored service using this login? File the Password Change Request first.'
        if ($PSCmdlet.ShouldProcess("$server : login $RotateLogin", 'Set a new password (you will type it twice)')) {
            $p1 = Read-Host -AsSecureString "  New password for '$RotateLogin'"
            $p2 = Read-Host -AsSecureString '  Again'
            $n1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
            $n2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
            if (-not $n1 -or $n1 -cne $n2) { Write-Finding -Level RED -Category 'Login' -Message 'Passwords are empty or do not match. Nothing changed.' }
            else {
                try {
                    # ALTER LOGIN takes no parameters, so the value is embedded with quotes doubled. It is not logged by this script.
                    $null = Invoke-Sql $server ("ALTER LOGIN [{0}] WITH PASSWORD = N'{1}';" -f $safe, ($n1 -replace "'", "''"))
                    Write-Finding -Level GREEN -Category 'Login' -Message "Password of '$RotateLogin' changed on $server. Write it on the password sheet (paper)."
                    Write-CcdcLog "CHANGED password of SQL login $RotateLogin on $server" 'CHANGE'
                    if ($SqlUser -and $SqlUser -ieq $RotateLogin) { $sqlPlain = $n1 }
                } catch { Write-Finding -Level RED -Category 'Login' -Message "Password change failed: $($_.Exception.Message)" }
            }
            $n1 = $null; $n2 = $null
        }
    }
}

$sqlPlain = $null
if ($rollbackLines.Count -gt 1) {
    $rollbackLines | Set-Content -Path $rollback -Encoding UTF8 -WhatIf:$false
    Write-Finding -Level INFO -Category 'Rollback' -Message "Rollback statements written to $rollback"
}
Write-Finding -Level INFO -Category 'Next' -Message 'Also: restrict TCP 1433 to the hosts that need it (harden\Set-Firewall.ps1), back up the databases (services\MSSQL.ps1 -Action Backup), look for PII tables.'
Complete-Ccdc
