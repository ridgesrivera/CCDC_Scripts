<#
.SYNOPSIS
    Kick-Block - kick a user (log off everywhere + disable the account) and/or block an IP. CHANGES STATE, reversible.

.DESCRIPTION
    PURPOSE
      An alert fired. You want them OUT, now:
        1. end every session the user has open (RDP / console, SMB, WinRM, SSH)
        2. disable the account so they cannot log straight back in
        3. block the source IP on this box's firewall (inbound AND outbound)
      Changing a password does not end sessions that are already open, so this
      does all three in one place, confirms each action, and keeps an undo list.

    SAFETY RAILS
      * Lists first. Every action is confirmed (y/N) unless -Force.
      * Never touches YOUR session or your account unless you name it.
      * Refuses to block this machine's own addresses, and warns before blocking
        an IP that is trusted (C:\bt\trusted.txt: scoring engine, teammates) or
        that has a live RDP connection (it may be you).
      * Warns before disabling an account listed as scored in the config.
      * Accounts are DISABLED, never deleted. IPs get a named firewall rule.

    WHAT IT READS    quser, Get-SmbSession, processes, Security log (4624 logons from an IP), firewall
    WHAT IT CHANGES  ends sessions; disables accounts; adds firewall rules 'CCDC Block <ip>' (in + out);
                     writes C:\ccdc\kick-block.csv (what was done + the undo command)
    HOW TO UNDO      .\Kick-Block.ps1 -Unblock 10.1.2.3        removes the block rules
                     .\Kick-Block.ps1 -Enable  bob             re-enables the account
                     .\Kick-Block.ps1 -List                    shows everything done + undo commands
                     (ended sessions cannot be undone: the user just logs on again)

    MANUAL EQUIVALENT
      quser ; logoff <ID>          Get-SmbSession | ? ClientUserName -like *bob | Close-SmbSession -Force
      net user bob /active:no      (domain account on a member: Disable-ADAccount bob)
      New-NetFirewallRule -DisplayName 'CCDC Block 10.6.6.6' -Direction Inbound  -RemoteAddress 10.6.6.6 -Action Block
      New-NetFirewallRule -DisplayName 'CCDC Block 10.6.6.6' -Direction Outbound -RemoteAddress 10.6.6.6 -Action Block

.PARAMETER User
    Account names to kick (log off everywhere). Add -DisableAccount to also disable them.

.PARAMETER AllOthers
    End every session that is not yours (does not disable anything).

.PARAMETER DisableAccount
    Disable the -User accounts after logging them off.

.PARAMETER BlockIp
    IP addresses to block in + out. Their SMB sessions are closed too.

.PARAMETER Unblock
    Remove CCDC (and LIVE ALERTS) block rules for these IPs.

.PARAMETER Enable
    Re-enable these accounts (undo of -DisableAccount).

.PARAMETER List
    Show sessions, current block rules and the undo list. Changes nothing.

.EXAMPLE
    .\Kick-Block.ps1 -User bob -DisableAccount -BlockIp 10.6.6.6
.EXAMPLE
    .\Kick-Block.ps1 -Unblock 10.6.6.6
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$User = @(),
    [switch]$AllOthers,
    [switch]$DisableAccount,
    [string[]]$BlockIp = @(),
    [string[]]$Unblock = @(),
    [string[]]$Enable = @(),
    [switch]$List,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Kick-Block'
$config = Get-CcdcConfig -Path $ConfigPath
$me = $env:USERNAME
$acting = ($User.Count -gt 0 -or $AllOthers)
$journal = 'C:\ccdc\kick-block.csv'
$isDC = Test-CcdcIsDC
function Test-Selected([string]$name) {
    $n = ($name -split '\\')[-1]
    if ($User -contains $n) { return $true }                   # named explicitly (even if it is you)
    return ($AllOthers -and $n -ine $me -and $n -notmatch '\$$')
}
function Add-Journal([string]$type, [string]$value, [string]$undo) {
    [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Type = $type; Value = $value; Undo = $undo } |
        Export-Csv -Path $journal -Append -NoTypeInformation -WhatIf:$false
}
function Set-AccountEnabled([string]$name, [bool]$enabled) {
    # Local account (or any account on a DC): net user. Domain account seen from a member: LDAP.
    $local = $isDC -or [bool](Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='$($name -replace "'", "''")'" -ErrorAction SilentlyContinue)
    if ($local) {
        $o = & net.exe user $name ("/active:{0}" -f $(if ($enabled) { 'yes' } else { 'no' })) 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
        return
    }
    $se = New-Object DirectoryServices.DirectorySearcher([ADSI]'', "(&(objectCategory=person)(sAMAccountName=$name))")
    $r = $se.FindOne(); if (-not $r) { throw "no local or domain account named '$name'" }
    $de = $r.GetDirectoryEntry(); $uac = [int]$de.Properties['userAccountControl'].Value
    $de.Properties['userAccountControl'].Value = $(if ($enabled) { $uac -band (-bnot 2) } else { $uac -bor 2 })
    $de.CommitChanges()
}
function Get-BlockRules {
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        return @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'CCDC Block *' -or $_.DisplayName -like 'BT block*' })
    }
    return @()
}

if ($List) { $acting = $false }

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


# ---------------------------------------------------------------------------
# Disable accounts
# ---------------------------------------------------------------------------
if ($DisableAccount -and $User.Count) {
    Write-Section 'Disable accounts'
    $scored = @(Get-CcdcScoredAccounts -Config $config)
    foreach ($u in $User) {
        if ($u -ieq $me) { Write-Finding -Level YELLOW -Category 'Disable' -Message "Skipping '$u': that is the account you are using."; continue }
        if ($scored -contains $u) { Write-Finding -Level RED -Category 'Disable' -Message "'$u' is listed as a SCORED account: disabling it takes that service down." -Detail 'Rotate its password through the Password Change Request process instead, unless it is clearly compromised.' }
        $acct = $u
        if (Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $acct -Action 'Disable account' -Undo "Kick-Block.ps1 -Enable $acct" -ScriptBlock { Set-AccountEnabled $acct $false }) {
            Add-Journal 'account' $acct ".\Kick-Block.ps1 -Enable $acct"
        }
    }
    Write-Finding -Level INFO -Category 'Disable' -Message 'Kerberos tickets already issued stay valid until they expire (up to 10 h). Domain compromise: panel 15 (reset krbtgt).'
}

# ---------------------------------------------------------------------------
# Block IPs
# ---------------------------------------------------------------------------
if ($BlockIp.Count) {
    Write-Section 'Block IPs (firewall, inbound + outbound)'
    $mine = @(Get-CcdcLocalIps)
    $trusted = @(); if (Test-Path 'C:\bt\trusted.txt') { $trusted = @(Get-Content 'C:\bt\trusted.txt' | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }) }
    $fwOn = $true
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) { $fwOn = [bool](Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -or $_.Enabled -eq $true }) }
    if (-not $fwOn) { Write-Finding -Level RED -Category 'Block' -Message 'The Windows Firewall is OFF on every profile: block rules do nothing until it is on (panel 11).' }
    foreach ($ip in $BlockIp) {
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { Write-Finding -Level RED -Category 'Block' -Message "'$ip' is not an IP address."; continue }
        if ($mine -contains $ip) { Write-Finding -Level RED -Category 'Block' -Message "Refusing to block ${ip}: it is THIS machine."; continue }
        if ($trusted -contains $ip) { Write-Finding -Level YELLOW -Category 'Block' -Message "$ip is in C:\bt\trusted.txt (scoring engine / teammate?). Blocking it can take services down or lock a teammate out." }
        $rdp = @(Get-NetTCPConnection -State Established -LocalPort 3389 -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq $ip })
        if ($rdp.Count) { Write-Finding -Level YELLOW -Category 'Block' -Message "$ip has a LIVE RDP connection to this box. If that is YOU, answer N." }
        $addr = $ip
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $addr -Action 'Block in + out (firewall rules CCDC Block)' -Undo "Kick-Block.ps1 -Unblock $addr" -ScriptBlock {
            if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
                $null = New-NetFirewallRule -DisplayName "CCDC Block $addr" -Group 'CCDC Block' -Direction Inbound -RemoteAddress $addr -Action Block -ErrorAction Stop
                $null = New-NetFirewallRule -DisplayName "CCDC Block $addr" -Group 'CCDC Block' -Direction Outbound -RemoteAddress $addr -Action Block -ErrorAction Stop
            } else {
                $o1 = & netsh.exe advfirewall firewall add rule name="CCDC Block $addr" dir=in action=block remoteip=$addr 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o1 -join ' ') }
                $o2 = & netsh.exe advfirewall firewall add rule name="CCDC Block $addr" dir=out action=block remoteip=$addr 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o2 -join ' ') }
            }
        }
        if (-not $ok) { continue }
        Add-Journal 'ip' $addr ".\Kick-Block.ps1 -Unblock $addr"
        # Open SMB sessions from that address keep working through a new block rule: close them.
        if (Get-Command Get-SmbSession -ErrorAction SilentlyContinue) {
            foreach ($s in @(Get-SmbSession -ErrorAction SilentlyContinue | Where-Object { ([string]$_.ClientComputerName).Trim('[', ']') -eq $addr })) {
                $smbId = $s.SessionId
                $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "$($s.ClientUserName) from $addr" -Action 'Close SMB session' -ScriptBlock { Close-SmbSession -SessionId $smbId -Force }
            }
        }
        # Who logged on from there? Those are the accounts to kick next.
        try {
            $since = (Get-Date).AddHours(-24).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
            $xp = "*[System[EventID=4624 and TimeCreated[@SystemTime>='$since']] and EventData[Data[@Name='IpAddress']='$addr']]"
            $who = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 500 -ErrorAction Stop | ForEach-Object { (Get-CcdcEventData -Record $_)['TargetUserName'] } | Where-Object { $_ -and $_ -notmatch '\$$' } | Sort-Object -Unique)
            if ($who) { Write-Finding -Level RED -Category 'Block' -Message ("Accounts that logged on from {0} in the last 24 h: {1}" -f $addr, ($who -join ', ')) -Detail 'Kick them too: panel X -> 1 (log off + disable), and rotate their passwords.' }
        } catch { $null = $_ }
    }
}

# ---------------------------------------------------------------------------
# Undo: unblock / re-enable
# ---------------------------------------------------------------------------
foreach ($ip in $Unblock) {
    if (-not $script:unblockHeader) { Write-Section 'Unblock'; $script:unblockHeader = $true }
    $addr = $ip
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $addr -Action 'Remove block rules (CCDC Block / BT block)' -ScriptBlock {
        if (Get-Command Remove-NetFirewallRule -ErrorAction SilentlyContinue) {
            $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "CCDC Block $addr" -or $_.DisplayName -like "BT block $addr*" })
            if (-not $rules) { throw "no block rule for $addr" }
            $rules | Remove-NetFirewallRule -ErrorAction Stop
        } else { $o = & netsh.exe advfirewall firewall delete rule name="CCDC Block $addr" 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') } }
    }
}
foreach ($u in $Enable) {
    if (-not $script:enableHeader) { Write-Section 'Re-enable accounts'; $script:enableHeader = $true }
    $acct = $u
    $null = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $acct -Action 'Enable account' -ScriptBlock { Set-AccountEnabled $acct $true }
}

# ---------------------------------------------------------------------------
# Current blocks + undo list
# ---------------------------------------------------------------------------
Write-Section 'Current blocks and what was done'
$br = Get-BlockRules
if ($br.Count) {
    foreach ($g in ($br | Group-Object DisplayName)) { Write-Finding -Level INFO -Category 'Blocked' -Message ("{0}  ({1})" -f $g.Name, (($g.Group | ForEach-Object { [string]$_.Direction }) -join ' + ')) }
} else { Write-Finding -Level INFO -Category 'Blocked' -Message 'No IPs blocked by the toolkit.' }
if (Test-Path $journal) {
    foreach ($j in (Import-Csv $journal | Select-Object -Last 15)) { Write-Finding -Level INFO -Category 'Done' -Message ("{0}  {1,-8} {2}" -f $j.Time, $j.Type, $j.Value) -Detail ("undo: {0}" -f $j.Undo) }
}
if (-not $acting -and -not $BlockIp.Count -and -not $DisableAccount -and -not $Unblock.Count -and -not $Enable.Count) {
    Write-Finding -Level INFO -Category 'Next' -Message 'Listed only. Kick: -User bob -DisableAccount   Block: -BlockIp 10.6.6.6   (panel X asks for you)'
}
Complete-Ccdc
