<#
.SYNOPSIS
    whoshere - every way into this box, whether it is open, and who is using it right now. READ-ONLY.

.DESCRIPTION
    PURPOSE
      RDP and SSH are not the only ways in. This checks every common remote-access
      path on Windows, says in one line what it is, whether it is ON here, and who
      is connected through it right now (user + IP). Then recent logons, failed
      logons, anything else listening, and (with a baseline) what is NEW.

    WAYS IN THAT IT CHECKS
      RDP          remote desktop (3389)            SSH          OpenSSH server (22)
      SMB          file shares + admin shares C$ / ADMIN$ (445): also how PsExec runs commands
      WinRM        PowerShell remoting (5985/5986)  WMI / DCOM   remote management over RPC (135)
      PsExec-style a service created remotely to run one command (event 7045)
      VNC          another remote desktop (5900+)   Telnet       old clear-text shell (23)
      FTP          file transfer (21)               Web          IIS / web apps (80/443): web shells
      Databases    SQL Server (1433), MySQL (3306), PostgreSQL (5432)

    WHAT IT READS    sessions, connections, services, Security / System / OpenSSH logs, registry
    WHAT IT CHANGES  nothing; -SaveBaseline writes C:\bt\baseline.xml
    HOW TO UNDO      delete C:\bt\baseline.xml

    USAGE
      .\whoshere.ps1                   who is on, every way in
      .\whoshere.ps1 -Minutes 15       only the last 15 minutes of logons
      .\whoshere.ps1 -SaveBaseline     after cleanup: remember "normal"; later runs show what is NEW

    MANUAL EQUIVALENT
      query user ; Get-SmbSession ; netstat -ano | findstr ESTABLISHED ; Get-Service sshd,WinRM,TermService

.EXAMPLE
    .\whoshere.ps1 -Minutes 15
#>
param([int]$Minutes = 60, [switch]$SaveBaseline)
$since = (Get-Date).AddMinutes(-$Minutes)
$bl = "C:\bt\baseline.xml"
New-Item C:\bt -ItemType Directory -Force | Out-Null
function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }   # (not "H": h = built-in alias for Get-History)
function Note($t) { Write-Host "    $t" -ForegroundColor DarkGray }
function Leaf($p) { $p = [string]$p; if ($p -and $p -ne '-') { [IO.Path]::GetFileName($p) } else { '-' } }

$myIps = @(Get-NetIPAddress -EA 0 | ForEach-Object { $_.IPAddress -replace '%.*$', '' }) + @('127.0.0.1', '::1')
$listen = @(Get-NetTCPConnection -State Listen -EA 0)
$est = @(Get-NetTCPConnection -State Established -EA 0 | Where-Object { $myIps -notcontains ($_.RemoteAddress -replace '^::ffff:', '') })
$svcs = @{}; foreach ($s in (Get-CimInstance Win32_Service -EA 0)) { $svcs[$s.Name] = $s }
$procName = @{}; foreach ($p in (Get-Process -EA 0)) { $procName[$p.Id] = $p.ProcessName }

function Show-Way([string]$name, [string]$what, [int[]]$ports, [string[]]$services) {
  # One access path: is it on, and who is connected to it right now.
  $isListening = @($listen | Where-Object { $ports -contains [int]$_.LocalPort })
  $running = @($services | Where-Object { $svcs.ContainsKey($_) -and $svcs[$_].State -eq 'Running' })
  $on = ($isListening.Count -gt 0 -or $running.Count -gt 0)
  $conns = @($est | Where-Object { $ports -contains [int]$_.LocalPort })
  $state = if ($on) { 'ON ' } else { 'off' }
  $color = if (-not $on) { 'DarkGray' } elseif ($conns.Count) { 'Yellow' } else { 'White' }
  Write-Host ("  [{0}] {1,-12} {2}" -f $state, $name, $what) -ForegroundColor $color
  if ($on) {
    $detail = @()
    if ($isListening) { $detail += 'port ' + (($isListening | ForEach-Object { $_.LocalPort } | Sort-Object -Unique) -join ',') }
    if ($running) { $detail += 'service ' + ($running -join ',') }
    Note ($detail -join '; ')
  }
  foreach ($g in ($conns | Group-Object { $_.RemoteAddress -replace '^::ffff:', '' })) {
    Write-Host ("        CONNECTED from {0}  ({1} connection(s), process {2})" -f $g.Name, $g.Count, $procName[[int]$g.Group[0].OwningProcess]) -ForegroundColor Yellow
  }
}

Section "Ways in: ON = someone could connect this way. Yellow = someone IS connected now."
Show-Way 'RDP'      'remote desktop: full desktop as a user'                 @(3389) @('TermService')
$rdpOff = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA 0).fDenyTSConnections -eq 1
if (-not $rdpOff) {
  $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA 0).UserAuthentication
  if ($nla -ne 1) { Write-Host '        NLA is OFF: the login screen is offered to anyone before they prove who they are' -ForegroundColor Yellow }
}
Show-Way 'SSH'      'OpenSSH server: command line as a user'                 @(22) @('sshd')
$ak = "$env:ProgramData\ssh\administrators_authorized_keys"
if (Test-Path $ak) { $n = @(Get-Content $ak -EA 0 | Where-Object { $_ -match '^\s*(ssh|ecdsa)-' }).Count; if ($n) { Write-Host "        $n admin SSH key(s) in $ak (a key = login with no password)" -ForegroundColor Yellow } }
Show-Way 'SMB'      'file shares; admin shares C$/ADMIN$ also let an admin run commands remotely (PsExec)' @(445, 139) @('LanmanServer')
Show-Way 'WinRM'    'PowerShell remoting: remote command line'               @(5985, 5986) @('WinRM')
Show-Way 'WMI/DCOM' 'remote management over RPC (wmic, Invoke-WmiMethod)'     @(135) @('RpcSs')
Show-Way 'VNC'      'another remote desktop (TightVNC, UltraVNC, RealVNC)'    @(5800, 5900, 5901, 5902, 5903) @('tvnserver', 'uvnc_service', 'vncserver', 'TigerVNC')
Show-Way 'Telnet'   'old remote shell, passwords sent in clear text'         @(23) @('TlntSvr')
Show-Way 'FTP'      'file transfer (often clear-text passwords)'             @(21, 990) @('ftpsvc', 'FileZilla Server', 'filezilla-server')
Show-Way 'Web'      'IIS / web apps: a web shell is a page that runs commands' @(80, 443, 8080, 8443, 8000) @('W3SVC', 'Apache2.4', 'nginx')
Show-Way 'SQL'      'databases: a DB login can often run OS commands (xp_cmdshell)' @(1433, 3306, 5432) @('MSSQLSERVER', 'MySQL', 'MySQL80', 'MariaDB')
Note 'Turn off what this box does not need (and nobody scores/uses): services.msc, or Set-Service <name> -StartupType Disabled.'

Section "Who is logged on right now"
Write-Host "  RDP / console sessions:" -ForegroundColor White
if (Get-Command query.exe -EA 0) { query user 2>$null | ForEach-Object { "    $_" } } else { Note '(query.exe not on this edition)' }
Write-Host "  SMB (shares) sessions:" -ForegroundColor White
$smb = @(Get-SmbSession -EA 0)
if ($smb) { $smb | ForEach-Object { "    {0,-28} from {1}  ({2} open files)" -f $_.ClientUserName, $_.ClientComputerName, $_.NumOpens } } else { Note 'none' }
Write-Host "  Remote shells (WinRM / SSH):" -ForegroundColor White
$procs = @(Get-CimInstance Win32_Process -EA 0)
$sshd = @($procs | Where-Object { $_.Name -eq 'sshd.exe' } | ForEach-Object { $_.ProcessId })
$shells = @($procs | Where-Object { $_.Name -eq 'wsmprovhost.exe' -or ($sshd -contains $_.ParentProcessId -and $_.Name -ne 'sshd.exe') })
if ($shells) { foreach ($p in $shells) { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -EA 0; "    {0,-16} PID {1,-6} user {2}\{3}" -f $p.Name, $p.ProcessId, $o.Domain, $o.User } } else { Note 'none' }

# Web shell check: a web server process should never start a command shell.
$webPids = @($procs | Where-Object { $_.Name -in 'w3wp.exe', 'httpd.exe', 'php-cgi.exe', 'tomcat9.exe', 'java.exe', 'sqlservr.exe' } | ForEach-Object { $_.ProcessId })
$bad = @($procs | Where-Object { $webPids -contains $_.ParentProcessId -and $_.Name -in 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'certutil.exe', 'rundll32.exe' })
foreach ($p in $bad) { Write-Host ("  [!!] {0} started by a web/SQL server process (PID {1}): web shell or xp_cmdshell in use: {2}" -f $p.Name, $p.ParentProcessId, $p.CommandLine) -ForegroundColor Red }

# PsExec-style: services created in the time window (System 7045)
$svcNew = @(Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = 7045; StartTime = $since} -EA 0)
foreach ($e in $svcNew) { Write-Host ("  [!!] service installed {0}: {1} -> {2}  (remote command tools like PsExec do this)" -f $e.TimeCreated.ToString('HH:mm'), $e.Properties[0].Value, $e.Properties[1].Value) -ForegroundColor Red }

Section "Successful logons, last $Minutes min (machine accounts hidden)"
$ok = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -EA 0 |
      Where-Object { $_.Properties[8].Value -in 2,3,8,10 -and $_.Properties[5].Value -notlike '*$' }
if ($ok) {
  $ok | Group-Object { '{0,-16} {1,-12} from {2,-15} via {3}' -f $_.Properties[5].Value, @{2='keyboard'; 3='network'; 8='cleartext'; 10='RDP'}[[int]$_.Properties[8].Value], $_.Properties[18].Value, (Leaf $_.Properties[17].Value) } |
    Sort-Object Count -Descending | Select-Object -First 25 Count, @{n='User / how / from / process'; e={$_.Name}} | Format-Table -AutoSize -Wrap
  Note "network = SMB, WinRM, WMI, LDAP, SQL with Windows auth. cleartext = a password sent in plain text (IIS basic auth, FTP). From '-' = a local process."
} else { Note 'none' }
$sshLog = @(Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 200 -EA 0 | Where-Object { $_.TimeCreated -ge $since -and $_.Message -match 'Accepted|Failed' })
if ($sshLog) {
  Write-Host "  SSH (OpenSSH log):" -ForegroundColor White
  $sshLog | ForEach-Object { if ($_.Message -match '(Accepted|Failed) (\S+) for (invalid user )?(\S+) from (\S+)') { '{0} {1} for {2} from {3}' -f $Matches[1], $Matches[2], $Matches[4], $Matches[5] } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "    {0,4}x  {1}" -f $_.Count, $_.Name }
}

Section "FAILED logons, last $Minutes min (many from one IP = password guessing)"
$fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -EA 0
if ($fail) { $fail | Group-Object { '{0} from {1}' -f $_.Properties[5].Value, $_.Properties[19].Value } | Sort-Object Count -Descending | Select-Object -First 15 Count, Name | Format-Table -AutoSize } else { Note 'none' }

Section "Other connections (not one of the ways in above)"
$known = 21, 22, 23, 80, 135, 139, 443, 445, 990, 1433, 3306, 3389, 5432, 5800, 5900, 5901, 5902, 5903, 5985, 5986, 8000, 8080, 8443
$other = @($est | Where-Object { $known -notcontains [int]$_.LocalPort })
if ($other) {
  $other | Group-Object { '{0,-16} -> {1,-6} {2}' -f ($_.RemoteAddress -replace '^::ffff:', ''), $_.RemotePort, $procName[[int]$_.OwningProcess] } |
    Sort-Object Count -Descending | Select-Object -First 20 Count, @{n='Remote IP -> port / process (outbound from this box)'; e={$_.Name}} | Format-Table -AutoSize
  Note 'Outbound from an unexpected process (powershell, rundll32, something in Temp) can be a C2 beacon: panel 8.'
} else { Note 'none' }

Section "Listening ports not covered above (under 49152; yellow = check this)"
$std = 53,88,389,464,593,636,3268,3269,9389,47001 + $known
$listen | Where-Object { $_.LocalPort -lt 49152 } | Sort-Object LocalPort -Unique | ForEach-Object {
  if ($std -notcontains [int]$_.LocalPort) { Write-Host ('  {0,-6} {1}   <-- what is this?' -f $_.LocalPort, $procName[[int]$_.OwningProcess]) -ForegroundColor Yellow }
}

# ---------- baseline / what's new ----------
# admins by well-known SID so it works on any language: Domain Admins = <domain SID>-512, local Administrators = S-1-5-32-544
$admins = if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4 -and (Get-Module -ListAvailable ActiveDirectory)) {
            Import-Module ActiveDirectory; Get-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-512" | ForEach-Object SamAccountName }
          elseif (Get-Command Get-LocalGroupMember -EA 0) { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object Name }
          else { $g = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
                 net localgroup "$g" | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^The command|^-+$' } }   # PowerShell 4 / 2012 R2
$now = [pscustomobject]@{
  Listen   = @($listen | ForEach-Object LocalPort | Sort-Object -Unique)
  Tasks    = @(Get-ScheduledTask | ForEach-Object { $_.TaskPath + $_.TaskName })
  Services = @($svcs.Values | ForEach-Object { "$($_.Name) -> $($_.PathName)" })
  Admins   = @($admins)
  Run      = @((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run).PSObject.Properties | Where-Object Name -notlike 'PS*' | ForEach-Object { "$($_.Name) = $($_.Value)" })
}
if ($SaveBaseline) {
  $now | Export-Clixml $bl
  Section "Baseline saved to $bl"
  "Fix what you found FIRST, then save the baseline again, so 'normal' means 'clean'."
} elseif (Test-Path $bl) {
  $old = Import-Clixml $bl
  Section "NEW since the baseline ($((Get-Item $bl).LastWriteTime))"
  $any = $false
  foreach ($k in 'Admins','Listen','Tasks','Services','Run') {
    $new = Compare-Object @($old.$k) @($now.$k) | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject
    foreach ($x in $new) { Write-Host ("[NEW {0,-8}] {1}" -f $k, $x) -ForegroundColor Red; $any = $true }
  }
  if (-not $any) { Write-Host "Nothing new. " -ForegroundColor Green -NoNewline; "(Same admins, ports, tasks, services and Run keys as the baseline.)" }
} else {
  Section "No baseline yet"
  "Run .\whoshere.ps1 -SaveBaseline once you've cleaned up, so future runs show what's NEW."
}
