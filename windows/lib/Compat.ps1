<#
=============================================================================
 Compat.ps1  -  stand-ins for cmdlets that older Windows does not have
=============================================================================
 Dot-sourced by lib\CCDC-Common.ps1 and services\_ServiceCommon.ps1.
 Each stand-in is defined ONLY when the real cmdlet is missing, so on
 Windows 8 / Server 2012 and newer nothing here is used.

   Get-NetTCPConnection   (Windows 8 / 2012+)   -> parses netstat.exe -ano
   Get-NetIPAddress       (Windows 8 / 2012+)   -> WMI network adapters
   Get-LocalGroupMember   (PowerShell 5.1 only) -> WinNT provider

 They take the parameters the toolkit actually uses and return objects with
 the same property names.
=============================================================================
#>

# ---------------------------------------------------------------------------
# Compatibility shims for older Windows (Server 2008 R2 / Windows 7).
# Get-NetTCPConnection and Get-NetIPAddress only exist on Windows 8 / 2012
# and newer. When they are missing we define small stand-ins built on
# netstat.exe and WMI, so every script that calls them keeps working.
# On a modern box these are never defined and the real cmdlets are used.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    function Get-NetTCPConnection {
        param([string]$State, [int]$LocalPort = -1, [string]$ErrorAction)
        $map = @{ 'LISTENING' = 'Listen'; 'ESTABLISHED' = 'Established'; 'TIME_WAIT' = 'TimeWait'; 'CLOSE_WAIT' = 'CloseWait'; 'SYN_SENT' = 'SynSent' }
        foreach ($line in (& netstat.exe -ano -p TCP 2>$null)) {
            # "  TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4"   (state word is English on most builds)
            if ($line -notmatch '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s+(\S+)\s+(\d+)\s*$') { continue }
            $st = if ($map.ContainsKey($Matches[5])) { $map[$Matches[5]] } else { $Matches[5] }
            $o = [pscustomobject]@{
                LocalAddress = ($Matches[1] -replace '^\[|\]$', ''); LocalPort = [int]$Matches[2]
                RemoteAddress = ($Matches[3] -replace '^\[|\]$', ''); RemotePort = $(if ($Matches[4] -eq '*') { 0 } else { [int]$Matches[4] })
                State = $st; OwningProcess = [int]$Matches[6]
            }
            if ($State -and $o.State -ne $State) { continue }
            if ($LocalPort -ge 0 -and $o.LocalPort -ne $LocalPort) { continue }
            $o
        }
    }
}
if (-not (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue)) {
    function Get-NetIPAddress {
        param([string]$AddressFamily, [string]$ErrorAction)
        foreach ($nic in (Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
            foreach ($ip in @($nic.IPAddress)) {
                $fam = if ($ip -match ':') { 'IPv6' } else { 'IPv4' }
                if ($AddressFamily -and $fam -ne $AddressFamily) { continue }
                [pscustomobject]@{ IPAddress = $ip; AddressFamily = $fam; InterfaceIndex = $nic.InterfaceIndex }
            }
        }
    }
}


# ---------------------------------------------------------------------------
#  Compatibility: Get-LocalGroupMember exists only on PowerShell 5.1 (2016+ /
#  Windows 10). On older boxes, stand in with the WinNT provider so the RDP /
#  WinRM scripts still list group members. Same property names.
# ---------------------------------------------------------------------------
if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
    function Get-LocalGroupMember {
        param([Parameter(Position = 0)][string]$Name, [string]$SID, [string]$ErrorAction)
        try {
            if ($SID) { $Name = (New-Object Security.Principal.SecurityIdentifier($SID)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1] }
            $g = [ADSI]"WinNT://$env:COMPUTERNAME/$Name,group"
            foreach ($o in @($g.Invoke('Members'))) {
                $path = $o.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $o, $null)
                $cls  = $o.GetType().InvokeMember('Class', 'GetProperty', $null, $o, $null)
                $sidB = $o.GetType().InvokeMember('objectSid', 'GetProperty', $null, $o, $null)
                $sidO = $null; try { $sidO = New-Object Security.Principal.SecurityIdentifier($sidB, 0) } catch { $null = $_ }
                $nm = ($path -replace '^WinNT://', '') -replace '/', '\'
                [pscustomobject]@{ Name = $nm; ObjectClass = $cls; PrincipalSource = $(if ($nm -like "$env:COMPUTERNAME\*") { 'Local' } else { 'ActiveDirectory' }); SID = $sidO }
            }
        } catch { $null = $_ }
    }
}

