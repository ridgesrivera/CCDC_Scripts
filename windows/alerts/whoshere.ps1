<#
.SYNOPSIS
    whoshere - "Is anyone else on this box?" on one screen. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Interactive sessions, SMB sessions, WinRM sessions, recent logons (grouped, machine
      accounts hidden), failed logons, established connections, listening ports with
      non-standard ones in yellow. With a saved baseline it prints only what is NEW
      (admins, listening ports, tasks, services, Run keys) in red.

    WHAT IT READS    sessions, Security log, network state, tasks, services, Run keys
    WHAT IT CHANGES  nothing; -SaveBaseline writes C:\bt\baseline.xml
    HOW TO UNDO      delete C:\bt\baseline.xml

    USAGE
      .\whoshere.ps1 -SaveBaseline     after cleanup: remember what "normal" looks like
      .\whoshere.ps1                   any time later: shows what's NEW since the baseline
      .\whoshere.ps1 -Minutes 15       only the last 15 minutes of logons

    MANUAL EQUIVALENT
      query user; Get-SmbSession; netstat -ano | findstr ESTABLISHED; net localgroup administrators

.EXAMPLE
    .\whoshere.ps1 -Minutes 15
#>
param([int]$Minutes = 60, [switch]$SaveBaseline)
$since = (Get-Date).AddMinutes(-$Minutes)
$bl = "C:\bt\baseline.xml"
New-Item C:\bt -ItemType Directory -Force | Out-Null
function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }   # (not "H": h = built-in alias for Get-History)
function Leaf($p) { $p = [string]$p; if ($p -and $p -ne '-') { [IO.Path]::GetFileName($p) } else { '-' } }

Section "Interactive sessions (RDP / console)"
if (Get-Command query.exe -EA 0) { query user 2>$null } else { "(query.exe not on this edition)" }

Section "SMB sessions (connected to my shares)"
$smb = Get-SmbSession -EA 0
if ($smb) { $smb | Select ClientComputerName, ClientUserName, NumOpens | Format-Table -AutoSize } else { "none" }

Section "Remote PowerShell (WinRM) sessions"
$w = Get-CimInstance Win32_Process -Filter "Name='wsmprovhost.exe'" -EA 0
if ($w) { $w | ForEach-Object { [pscustomobject]@{ PID = $_.ProcessId; User = (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } } | Format-Table -AutoSize } else { "none" }

Section "Successful logons, last $Minutes min (machine accounts hidden, grouped)"
$ok = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -EA 0 |
      Where-Object { $_.Properties[8].Value -in 2,3,10 -and $_.Properties[5].Value -notlike '*$' }
if ($ok) {
  $ok | Group-Object { '{0,-16} type {1,-2} from {2,-15} via {3}' -f $_.Properties[5].Value, $_.Properties[8].Value, $_.Properties[18].Value, (Leaf $_.Properties[17].Value) } |
    Sort-Object Count -Descending | Select-Object Count, @{n='User / logon type / source IP / process'; e={$_.Name}} | Format-Table -AutoSize -Wrap
  Write-Host "Types: 2 = at the keyboard, 3 = network (SMB/WinRM/LDAP), 10 = RDP. Source '-' = a local process." -ForegroundColor DarkGray
} else { "none" }

Section "FAILED logons, last $Minutes min (lots from one IP = password spraying)"
$bad = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -EA 0
if ($bad) { $bad | Group-Object { '{0} from {1}' -f $_.Properties[5].Value, $_.Properties[19].Value } | Sort-Object Count -Descending | Select-Object -First 15 Count, Name | Format-Table -AutoSize } else { "none" }

Section "Established connections (grouped by remote IP + process)"
Get-NetTCPConnection -State Established -EA 0 | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' } |
  Group-Object { '{0,-16} {1}' -f $_.RemoteAddress, (Get-Process -Id $_.OwningProcess -EA 0).Name } |
  Sort-Object Count -Descending | Select-Object Count, @{n='Remote IP / process'; e={$_.Name}} | Format-Table -AutoSize

Section "Listening ports (under 49152; yellow = not a usual Windows/AD/web/SQL port)"
$std = 53,80,88,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986,9389,47001
Get-NetTCPConnection -State Listen -EA 0 | Where-Object { $_.LocalPort -lt 49152 } | Sort-Object LocalPort -Unique | ForEach-Object {
  $line = '{0,-6} {1}' -f $_.LocalPort, (Get-Process -Id $_.OwningProcess -EA 0).Name
  if ($_.LocalPort -in $std) { Write-Host $line } else { Write-Host "$line   <-- check this" -ForegroundColor Yellow }
}

# ---------- baseline / what's new ----------
# admins by well-known SID so it works on any language: Domain Admins = <domain SID>-512, local Administrators = S-1-5-32-544
$admins = if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4 -and (Get-Module -ListAvailable ActiveDirectory)) {
            Import-Module ActiveDirectory; Get-ADGroupMember -Identity "$((Get-ADDomain).DomainSID.Value)-512" | ForEach-Object SamAccountName }
          elseif (Get-Command Get-LocalGroupMember -EA 0) { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object Name }
          else { $g = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
                 net localgroup "$g" | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^The command|^-+$' } }   # PowerShell 4 / 2012 R2
$now = [pscustomobject]@{
  Listen   = @(Get-NetTCPConnection -State Listen -EA 0 | ForEach-Object LocalPort | Sort-Object -Unique)
  Tasks    = @(Get-ScheduledTask | ForEach-Object { $_.TaskPath + $_.TaskName })
  Services = @(Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) -> $($_.PathName)" })
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
