#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Remote Desktop (service: TermService) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$TS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RdpTcp = "$TS\WinStations\RDP-Tcp"

$Def = @{
    Name         = 'RDP'
    Title        = 'Remote Desktop Services (RDP)'
    ServiceNames = @('TermService', 'UmRdpService', 'SessionEnv')
    Description  = @"
Graphical remote login. Users and admins depend on it, AND it is a common
way in for an attacker with stolen credentials.
Who may log in = local 'Administrators' + 'Remote Desktop Users' group +
the 'Allow log on through Remote Desktop Services' user right.
Key settings: fDenyTSConnections (0 = RDP on), PortNumber (default 3389),
UserAuthentication (1 = NLA required), SecurityLayer.
"@
    Ports        = @(
        @{ Port = 3389; Proto = 'TCP/UDP'; Use = 'RDP (UDP = RemoteFX transport)' }
    )
    KeyPaths     = @($TS.Replace('HKLM:', 'HKLM'), $RdpTcp.Replace('HKLM:', 'HKLM'))
    RedTeam      = @(
        'Logging in with dumped / default creds; adding users to Remote Desktop Users'
        'Sticky keys / utilman backdoor (sethc.exe, utilman.exe replaced or IFEO Debugger = cmd.exe) -> SYSTEM shell at the logon screen'
        'Disabling NLA so they can reach the logon screen without creds'
        'Changing the RDP port so scoring breaks'
        'Session hijack with tscon as SYSTEM'
        'RestrictedAdmin mode for pass-the-hash RDP'
    )
    Hardening    = @(
        'NLA on: UserAuthentication=1'
        'Remove unknown users from Remote Desktop Users / Administrators'
        'Check IFEO Debugger keys for sethc/utilman/osk/narrator/magnify/displayswitch (Info output)'
        'Firewall 3389 to scoring + team subnets if allowed by rules'
        'Log off unknown sessions: logoff <id>'
    )
    Detect       = { Test-ServiceInstalled 'TermService' }
}

$Def.InfoExtra = {
    $t = Get-ItemProperty $TS; $r = Get-ItemProperty $RdpTcp
    if ($t.fDenyTSConnections -eq 0) { Write-OK "RDP ENABLED (fDenyTSConnections=0)" } else { Write-WARN "RDP DISABLED (fDenyTSConnections=$($t.fDenyTSConnections))" }
    Write-INFO "Port: $($r.PortNumber)"
    if ($r.UserAuthentication -eq 1) { Write-OK "NLA required" } else { Write-WARN "NLA NOT required" }
    Write-INFO "SecurityLayer: $($r.SecurityLayer) (0=RDP 1=Negotiate 2=TLS)  MinEncryptionLevel: $($r.MinEncryptionLevel)"
    $ra = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).DisableRestrictedAdmin
    if ($ra -eq 0) { Write-WARN "RestrictedAdmin ENABLED (pass-the-hash RDP possible)" }
    Write-STEP "Who can RDP in"
    foreach ($g in 'Remote Desktop Users', 'Administrators') {
        $m = Get-LocalGroupMember -Name $g -ErrorAction SilentlyContinue
        Write-Plain ("{0,-22} {1}" -f $g, (($m.Name) -join ', '))
    }
    Write-STEP "Current sessions"
    & qwinsta 2>$null | ForEach-Object { Write-Plain $_ }
    Write-STEP "Accessibility backdoor check (sticky keys etc.)"
    foreach ($exe in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe') {
        $ifeo = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe" -ErrorAction SilentlyContinue).Debugger
        if ($ifeo) { Write-CRIT "IFEO Debugger on $exe = $ifeo" }
        $p = "$env:SystemRoot\System32\$exe"
        if (Test-Path $p) {
            $vi = (Get-Item $p).VersionInfo
            if ($vi.OriginalFilename -and $vi.OriginalFilename -notmatch [regex]::Escape($exe.Replace('.exe', ''))) { Write-CRIT "$exe is actually '$($vi.OriginalFilename)' - REPLACED BINARY" }
            elseif ((Get-AuthenticodeSignature $p).Status -ne 'Valid') {
                # many of these are catalog-signed; only flag if the hash matches cmd/powershell
                $h = (Get-FileHash $p).Hash
                if ($h -in (Get-FileHash "$env:SystemRoot\System32\cmd.exe", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe").Hash) { Write-CRIT "$exe is a copy of cmd/powershell!" }
            }
        }
    }
    Show-RecentEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids 21, 24, 25 -Max 10
    $rdpLogons = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-6) } -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -eq 10 }
    if ($rdpLogons) {
        Write-STEP "RDP (type 10) logons last 6h"
        $rdpLogons | Group-Object { "$($_.Properties[6].Value)\$($_.Properties[5].Value) from $($_.Properties[18].Value)" } | ForEach-Object { Write-Plain ("{0,-60} x{1}" -f $_.Name, $_.Count) }
    }
}

$Def.Backup = {
    param($Dir)
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' "$Dir\reg\Terminal_Server.reg" | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' "$Dir\reg\TS_Policies.reg" | Out-Null
    foreach ($g in 'Remote Desktop Users', 'Administrators') {
        Get-LocalGroupMember -Name $g -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, PrincipalSource, @{n = 'SID'; e = { $_.SID.Value } } |
            Export-Csv "$Dir\group_$($g -replace ' ','_').csv" -NoTypeInformation
    }
    & secedit /export /areas USER_RIGHTS /cfg "$Dir\user_rights.inf" 2>&1 | Out-Null
    Write-OK "User rights (SeRemoteInteractiveLogonRight etc.) -> user_rights.inf"
    # Hash baseline of accessibility binaries
    'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe' | ForEach-Object {
        $p = "$env:SystemRoot\System32\$_"; if (Test-Path $p) { Get-FileHash $p | Select-Object Path, Hash }
    } | Export-Csv "$Dir\accessibility_hashes.csv" -NoTypeInformation
    # RDP certificate thumbprint
    Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -ErrorAction SilentlyContinue | Select-Object TerminalName, SSLCertificateSHA1Hash | Export-Csv "$Dir\rdp_cert.csv" -NoTypeInformation
}

$Def.Restore = {
    param($Dir)
    & reg.exe import "$Dir\reg\Terminal_Server.reg" 2>&1 | Out-Null; Write-OK "Terminal Server registry restored"
    if (Test-Path "$Dir\reg\TS_Policies.reg") { & reg.exe import "$Dir\reg\TS_Policies.reg" 2>&1 | Out-Null }
    $bk = Import-Csv "$Dir\group_Remote_Desktop_Users.csv" -ErrorAction SilentlyContinue
    $now = Get-LocalGroupMember -Name 'Remote Desktop Users' -ErrorAction SilentlyContinue
    foreach ($m in $now) { if ($bk.SID -notcontains $m.SID.Value) { Write-CRIT "NEW in Remote Desktop Users: $($m.Name)  -> Remove-LocalGroupMember 'Remote Desktop Users' '$($m.Name)'" } }
    foreach ($m in $bk) { if ($now.SID.Value -notcontains $m.SID) { try { Add-LocalGroupMember 'Remote Desktop Users' -Member $m.SID -ErrorAction Stop; Write-OK "Re-added $($m.Name)" } catch {} } }
    Write-INFO "User rights: secedit /configure /db secedit.sdb /cfg `"$Dir\user_rights.inf`" /areas USER_RIGHTS   (run by hand if needed)"
    Restart-Service TermService -Force -ErrorAction SilentlyContinue
    Write-WARN "Restarting TermService drops every RDP session (including yours if you're on RDP)"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
