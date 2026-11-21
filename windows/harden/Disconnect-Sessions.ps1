<#
.SYNOPSIS
    Disconnect-Sessions - log off other people's sessions (RDP, console, SMB, WinRM, SSH). CHANGES STATE.

.DESCRIPTION
    PURPOSE
      Changing a password does not end the sessions that are already open.
      An attacker who is logged on stays logged on. This is the Windows
      version of "passwd USER, then pkill -KILL -u USER": after you rotate or
      disable an account, end what it has open. It is also the "proof of
      session termination" step the offboarding injects ask for.

    WHAT IT ENDS
      * Interactive sessions (console / RDP)          logoff <id>
      * SMB sessions to this machine's shares          Close-SmbSession
      * PowerShell remoting hosts (wsmprovhost.exe)    Stop-Process
      * Shells started through OpenSSH (children of sshd.exe)

    SAFETY RAILS
      * Never touches YOUR session or your account unless you name it explicitly.
      * Lists first; every logoff is confirmed (y/N) unless -Force.
      * With no -User and no -AllOthers it only LISTS (nothing changes).

    WHAT IT READS    quser, Get-SmbSession, process owners
    WHAT IT CHANGES  ends the selected sessions (unsaved work in them is lost)
    HOW TO UNDO      cannot be undone; the user simply logs on again (with the NEW password).

    MANUAL EQUIVALENT
      quser                      then   logoff <ID>
      Get-SmbSession             then   Close-SmbSession -SessionId <id> -Force
      Domain-wide Kerberos tickets stay valid until they expire (10 h): for a
      compromised domain see harden\Reset-Krbtgt.ps1.

.PARAMETER User
    Account names whose sessions to end (without domain prefix).

.PARAMETER AllOthers
    End every session that is not yours.

.EXAMPLE
    .\Disconnect-Sessions.ps1                       # list only
.EXAMPLE
    .\Disconnect-Sessions.ps1 -User hacker,svc_old
.EXAMPLE
    .\Disconnect-Sessions.ps1 -AllOthers -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$User = @(),
    [switch]$AllOthers,
    [switch]$Force,
    [string]$ConfigPath          # accepted so the launcher can pass it; not used
)
$null = $ConfigPath

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Disconnect-Sessions'
$me = $env:USERNAME
$acting = ($User.Count -gt 0 -or $AllOthers)
function Test-Selected([string]$name) {
    $n = ($name -split '\\')[-1]
    if ($User -contains $n) { return $true }                   # named explicitly (even if it is you)
    return ($AllOthers -and $n -ine $me -and $n -notmatch '\$$')
}

# ---------------------------------------------------------------------------
Write-Section 'Interactive sessions (console / RDP)'
# ---------------------------------------------------------------------------
# quser columns shift when SESSIONNAME is empty (disconnected sessions), so take
# the user name as the first token and the session ID as the first all-digit token.
$mySessionId = (Get-Process -Id $PID).SessionId
$n = 0
foreach ($line in @(& quser.exe 2>$null | Select-Object -Skip 1)) {
    $tok = @(("$line".Trim() -replace '^>', '') -split '\s+')
    if ($tok.Count -lt 3) { continue }
    $name = $tok[0]
    $sid = $null; for ($i = 1; $i -lt $tok.Count; $i++) { if ($tok[$i] -match '^\d+$') { $sid = [int]$tok[$i]; break } }
    if ($null -eq $sid) { continue }
    $n++
    $mine = ($sid -eq $mySessionId)
    Write-Finding -Level $(if ($mine) { 'INFO' } else { 'YELLOW' }) -Category 'Session' -Message ("{0}{1}" -f "$line".Trim(), $(if ($mine) { '   <- this is you' } else { '' }))
    if ($mine -or -not $acting -or -not (Test-Selected $name)) { continue }
    $sessId = $sid
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$name (session $sessId)" -Action 'Log off session' -ScriptBlock {
        $null = & logoff.exe $sessId 2>&1
        if ($LASTEXITCODE -ne 0) { throw "logoff returned $LASTEXITCODE" }
    }
}
if ($n -eq 0) { Write-Finding -Level INFO -Category 'Session' -Message 'No interactive sessions reported by quser.' }

# ---------------------------------------------------------------------------
Write-Section 'SMB sessions (who is connected to our shares)'
# ---------------------------------------------------------------------------
$script:myAddrs = @(Get-CcdcLocalIps | ForEach-Object { $_ -replace '%.*$', '' })
if (Get-Command Get-SmbSession -ErrorAction SilentlyContinue) {
    $smb = @(Get-SmbSession -ErrorAction SilentlyContinue)
    if ($smb.Count -eq 0) { Write-Finding -Level INFO -Category 'SMB' -Message 'No SMB sessions.' }
    foreach ($s in $smb) {
        # The box talking to itself (machine account, or one of our own addresses) is Group Policy / SYSVOL, not a person.
        $client = ([string]$s.ClientComputerName).Trim('[', ']') -replace '%.*$', ''
        $self = ([string]$s.ClientUserName -like "*\$($env:COMPUTERNAME)$") -or ($script:myAddrs -contains $client)
        Write-Finding -Level $(if ($self) { 'INFO' } else { 'YELLOW' }) -Category 'SMB' -Message ("{0} from {1} ({2} open files){3}" -f $s.ClientUserName, $s.ClientComputerName, $s.NumOpens, $(if ($self) { '   <- this machine itself (Group Policy / SYSVOL)' } else { '' }))
        if (-not $acting -or -not (Test-Selected ([string]$s.ClientUserName))) { continue }
        $smbId = $s.SessionId
        $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($s.ClientUserName) from $($s.ClientComputerName)" -Action 'Close SMB session' -ScriptBlock {
            Close-SmbSession -SessionId $smbId -Force
        }
    }
} else { Write-Finding -Level INFO -Category 'SMB' -Message 'Get-SmbSession not available: use  net session  and  net session \\<client> /delete' }

# ---------------------------------------------------------------------------
Write-Section 'Remote shells (PowerShell remoting, OpenSSH)'
# ---------------------------------------------------------------------------
$procs = @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue)
$sshdPids = @($procs | Where-Object { $_.Name -ieq 'sshd.exe' } | ForEach-Object { [int]$_.ProcessId })
$remote = @($procs | Where-Object { $_.Name -ieq 'wsmprovhost.exe' -or ($sshdPids -contains [int]$_.ParentProcessId -and $_.Name -ine 'sshd.exe') })
if ($remote.Count -eq 0) { Write-Finding -Level INFO -Category 'Remote' -Message 'No PowerShell-remoting or SSH shells running.' }
foreach ($p in $remote) {
    $owner = ''
    try { $o = $p.GetOwner(); if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch { $null = $_ }
    $kind = if ($p.Name -ieq 'wsmprovhost.exe') { 'PowerShell remoting (WinRM)' } else { 'SSH shell' }
    $isMe = (($owner -split '\\')[-1] -ieq $me) -or ([int]$p.ProcessId -eq $PID)
    Write-Finding -Level $(if ($isMe) { 'INFO' } else { 'YELLOW' }) -Category 'Remote' -Message ("{0}: {1} PID {2} owner {3}, started {4}" -f $kind, $p.Name, $p.ProcessId, $owner, $(try { [Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate).ToString('HH:mm:ss') } catch { '?' }))
    if (-not $acting -or -not $owner -or -not (Test-Selected $owner)) { continue }
    if ([int]$p.ProcessId -eq $PID) { continue }
    $procId = [int]$p.ProcessId
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$kind of $owner (PID $procId)" -Action 'End remote shell' -ScriptBlock {
        Stop-Process -Id $procId -Force
    }
}

if (-not $acting) { Write-Finding -Level INFO -Category 'Next' -Message 'Listed only. End sessions with  -User name1,name2  or  -AllOthers  (add -WhatIf to preview).' }
else { Write-Finding -Level INFO -Category 'Next' -Message 'Sessions ended can log straight back in unless the password was rotated or the account disabled first.' -Detail 'harden\Rotate-Passwords.ps1 / harden\Disable-Accounts.ps1. Proof for an offboarding inject: screenshot this output, then quser again.' }
Complete-Ccdc
