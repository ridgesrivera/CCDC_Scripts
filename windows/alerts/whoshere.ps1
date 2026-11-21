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
# The box talking to itself (its own IPs, link-local fe80::) is not 'someone else'.
$est = @(Get-NetTCPConnection -State Established -EA 0 | Where-Object { $ra = ($_.RemoteAddress -replace '^::ffff:', '') -replace '%.*$', ''; $myIps -notcontains $ra -and $ra -notmatch '^fe80:' })
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

Section "Logons from other machines, last $Minutes min (machine accounts and this box hidden)"
$ok = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -EA 0 |
      Where-Object { $_.Properties[8].Value -in 3,8,10 -and $_.Properties[5].Value -notlike '*$' -and $myIps -notcontains [string]$_.Properties[18].Value -and $_.Properties[18].Value -ne '-' }
if ($ok) {
  $ok | Group-Object { '{0,-16} {1,-10} from {2}' -f $_.Properties[5].Value, @{3='network'; 8='cleartext'; 10='RDP'}[[int]$_.Properties[8].Value], $_.Properties[18].Value } |
    Sort-Object Count -Descending | Select-Object -First 20 Count, @{n='User / how / from'; e={$_.Name}} | Format-Table -AutoSize
  Note 'network = SMB, WinRM, WMI, LDAP. cleartext = password sent in plain text (IIS basic auth, FTP). Unknown user or IP? panel E.'
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

Section "SSH keys (a key = log in with NO password; checked even if SSH is off)"
$keyFiles = @("$env:ProgramData\ssh\administrators_authorized_keys") + @(Get-ChildItem 'C:\Users' -Directory -EA 0 | ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })
$anyKey = $false
foreach ($kf in $keyFiles) {
  if (-not (Test-Path $kf)) { continue }
  foreach ($line in (Get-Content $kf -EA 0 | Where-Object { $_ -match '^\s*[^#\s]' })) {
    $parts = $line.Trim() -split '\s+'
    $type = ($parts | Where-Object { $_ -match '^(ssh-|ecdsa-|sk-)' } | Select-Object -First 1)
    $comment = if ($parts.Count -ge 3) { $parts[-1] } else { '(no comment)' }
    Write-Host ("  [??] {0,-12} {1,-28} in {2}" -f $type, $comment, $kf) -ForegroundColor Yellow
    $anyKey = $true
  }
}
if ($anyKey) { Note 'Not your team''s key? Delete that line from the file (copy the file somewhere safe first). administrators_authorized_keys = admin login.' }
else { Note 'No SSH keys on this box.' }

Section "Every listening port (OK = expected, CHECK = out of place, RISKY = likely malicious)"
# What each well-known port is, so you can tell at a glance whether it belongs.
$portInfo = @{
  21 = 'FTP file transfer'; 22 = 'SSH'; 23 = 'Telnet (clear-text shell)'; 25 = 'SMTP mail'; 53 = 'DNS'; 80 = 'web (HTTP)'; 88 = 'Kerberos (AD logins)'
  110 = 'POP3 mail'; 135 = 'RPC / WMI'; 139 = 'NetBIOS file sharing'; 143 = 'IMAP mail'; 389 = 'LDAP (Active Directory)'; 443 = 'web (HTTPS)'
  445 = 'SMB file sharing'; 464 = 'Kerberos password change'; 587 = 'mail submission'; 593 = 'RPC over HTTP'; 636 = 'LDAPS (AD)'; 993 = 'IMAPS'; 995 = 'POP3S'
  1433 = 'SQL Server'; 3268 = 'AD Global Catalog'; 3269 = 'AD Global Catalog (SSL)'; 3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'PostgreSQL'
  5800 = 'VNC (web)'; 5900 = 'VNC'; 5901 = 'VNC'; 5985 = 'WinRM (PowerShell remoting)'; 5986 = 'WinRM (HTTPS)'; 8080 = 'web (alt)'; 8443 = 'web (alt HTTPS)'
  9389 = 'AD Web Services'; 47001 = 'WinRM listener (local)'; 1194 = 'OpenVPN'; 2049 = 'NFS'; 161 = 'SNMP'
}
$riskyPorts = 23, 1337, 31337, 4444, 4445, 5555, 6666, 6667, 7777, 9001, 9999, 12345, 50050, 8888
$shellProcs = 'powershell', 'pwsh', 'cmd', 'nc', 'ncat', 'socat', 'python', 'python3', 'perl', 'ruby', 'rundll32', 'mshta', 'plink'
$winProcs = 'System', 'lsass', 'svchost', 'services', 'wininit', 'spoolsv', 'dns', 'dfsrs', 'Microsoft.ActiveDirectory.WebServices', 'ismserv', 'inetinfo', 'w3wp', 'sqlservr', 'sqlbrowser', 'sshd', 'mysqld', 'httpd', 'nginx', 'certsrv', 'wsmprovhost', 'ntfrs', 'dhcpserver', 'tvnserver', 'winvnc'
$isDCbox = (Get-CimInstance Win32_ComputerSystem -EA 0).DomainRole -ge 4
$procPath = @{}; foreach ($p in $procs) { $procPath[[int]$p.ProcessId] = [string]$p.ExecutablePath }
$svcByPid = @{}; foreach ($v in $svcs.Values) { if ($v.ProcessId) { $svcByPid[[int]$v.ProcessId] += @($v.Name) } }
$rows = @()
foreach ($l in ($listen | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } | Sort-Object LocalPort -Unique)) {
  $port = [int]$l.LocalPort; $owner = [int]$l.OwningProcess
  $name = $procName[$owner]; $path = $procPath[$owner]; $svcNames = (@($svcByPid[$owner]) | Select-Object -First 3) -join ','
  if ($port -ge 49152 -and $winProcs -contains $name) { continue }   # Windows dynamic RPC ports: normal
  $what = if ($portInfo.ContainsKey($port)) { $portInfo[$port] } else { 'unknown port' }
  $verdict = 'OK'; $why = ''
  if ($riskyPorts -contains $port) { $verdict = 'RISKY'; $why = 'common backdoor / reverse-shell port' }
  elseif ($shellProcs -contains $name) { $verdict = 'RISKY'; $why = "$name should never listen on a port (bind shell)" }
  elseif ($path -match '(?i)\\(temp|appdata|users\\public|programdata|windows\\tasks|perflogs)\\') { $verdict = 'RISKY'; $why = 'program runs from a user-writable folder' }
  elseif ($port -in 5800, 5900, 5901) { $verdict = 'CHECK'; $why = 'VNC: remote desktop, often no password or a weak one' }
  elseif ($port -eq 21) { $verdict = 'CHECK'; $why = 'FTP sends passwords in clear text' }
  elseif ($isDCbox -and $name -eq 'spoolsv') { $verdict = 'CHECK'; $why = 'Print Spooler on a DC: not needed, and a known attack path (panel 12)' }
  elseif (-not $portInfo.ContainsKey($port) -and $winProcs -notcontains $name) { $verdict = 'CHECK'; $why = 'not a usual Windows / AD / web port: what is this program?' }
  $rows += [pscustomobject]@{ Port = $port; What = $what; Program = $name; Service = $svcNames; Verdict = $verdict; Why = $why; Path = $path }
}
foreach ($r in $rows) {
  $col = @{ OK = 'Gray'; CHECK = 'Yellow'; RISKY = 'Red' }[$r.Verdict]
  Write-Host ("  [{0,-5}] TCP {1,-6} {2,-28} {3,-18} {4}" -f $r.Verdict, $r.Port, $r.What, $r.Program, $(if ($r.Service) { "svc: $($r.Service)" } else { '' })) -ForegroundColor $col
  if ($r.Verdict -ne 'OK') { Write-Host ("          {0}  ({1})" -f $r.Why, $(if ($r.Path) { $r.Path } else { 'path unknown' })) -ForegroundColor $col }
}
Note 'Ports above 49152 owned by Windows itself (lsass, svchost, dns...) are normal RPC ports and are hidden.'
Note 'Not needed on this box? Stop the service (Set-Service <svc> -StartupType Disabled) after checking nothing uses it. RISKY: panel 8 and R.'

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
