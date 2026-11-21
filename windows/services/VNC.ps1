#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - VNC servers on Windows (TightVNC, UltraVNC, RealVNC, TigerVNC) info / backup / restore.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$RegKeys = @(
    'HKLM\SOFTWARE\TightVNC\Server', 'HKLM\SOFTWARE\WOW6432Node\TightVNC\Server'
    'HKLM\SOFTWARE\RealVNC\vncserver', 'HKLM\SOFTWARE\RealVNC\WinVNC4'
    'HKLM\SOFTWARE\TigerVNC\WinVNC4', 'HKLM\SOFTWARE\ORL\WinVNC3'
)
$IniFiles = @("$env:ProgramFiles\uvnc bvba\UltraVNC\ultravnc.ini", "${env:ProgramFiles(x86)}\uvnc bvba\UltraVNC\ultravnc.ini", "$env:ProgramFiles\UltraVNC\ultravnc.ini", "$env:ProgramData\UltraVNC\ultravnc.ini")

$Def = @{
    Name         = 'VNC'
    Title        = 'VNC Remote Desktop'
    ServiceNames = @('tvnserver', 'uvnc_service', 'vncserver', 'WinVNC4', 'TigerVNC*')
    Description  = @"
Third-party remote desktop (screen sharing). Usually a single shared
password (max 8 chars, stored weakly-encrypted with a FIXED DES key - anyone
who reads the registry/ini can decrypt it). No per-user accounts unless
RealVNC Enterprise / Windows auth is configured. Default port 5900.
"@
    Ports        = @(
        @{ Port = 5900; Proto = 'TCP'; Use = 'VNC (display :0)' }
        @{ Port = 5800; Proto = 'TCP'; Use = 'VNC Java/HTTP viewer' }
        @{ Port = 5500; Proto = 'TCP'; Use = 'VNC reverse (listening viewer)' }
    )
    KeyPaths     = $RegKeys + $IniFiles
    RedTeam      = @(
        'Decrypting the stored VNC password (fixed DES key) from registry / ultravnc.ini'
        'No password / "AuthRequired=0" / blank password'
        'Watching or controlling the scored desktop session'
    )
    Hardening    = @(
        'Set a new strong VNC password via the VNC server config tool (8 chars max)'
        'Disable the 5800 HTTP viewer; enable "loopback only" if not scored remotely'
        'Firewall 5900 to scoring subnet'
    )
    Detect       = { Test-ServiceInstalled 'tvnserver', 'uvnc_service', 'vncserver', 'WinVNC4' }
}

$Def.InfoExtra = {
    foreach ($k in $RegKeys) {
        $p = "Registry::$k"
        if (Test-Path $p) {
            Write-STEP "$k"
            $v = Get-ItemProperty $p
            foreach ($n in 'RfbPort', 'HttpPort', 'UseVncAuthentication', 'UseControlAuthentication', 'AllowLoopback', 'LoopbackOnly', 'AcceptHttpConnections', 'SecurityTypes', 'Authentication', 'QueryConnect') {
                if ($null -ne $v.$n) { Write-Plain ("{0,-26} {1}" -f $n, $v.$n) }
            }
            if ($v.UseVncAuthentication -eq 0) { Write-CRIT "TightVNC: VNC authentication DISABLED (no password)" }
            if ($v.Password -or $v.PasswordViewOnly) { Write-WARN "Password stored (DES, trivially decryptable) - rotate it" }
        }
    }
    foreach ($f in $IniFiles) { if (Test-Path $f) { Write-STEP "$f"; Get-Content $f | Where-Object { $_ -match '^(PortNumber|HTTPPortNumber|AuthRequired|passwd|NewMSLogon|LoopbackOnly|AllowLoopback)' } | ForEach-Object { Write-Plain $_ } } }
}

$Def.Backup = {
    param($Dir)
    $i = 0
    foreach ($k in $RegKeys) { $i++; Export-RegKey $k "$Dir\reg\vnc_$i.reg" | Out-Null }
    foreach ($f in $IniFiles) { if (Test-Path $f) { Copy-Item $f "$Dir\$((Split-Path (Split-Path $f) -Leaf) -replace ' ','_')_ultravnc.ini" -Force; "$f" | Out-File "$Dir\ultravnc_ini_source.txt" -Append; Write-OK "Copied $f" } }
}

$Def.Restore = {
    param($Dir)
    Get-ChildItem "$Dir\reg\*.reg" -ErrorAction SilentlyContinue | ForEach-Object { & reg.exe import $_.FullName 2>&1 | Out-Null; Write-OK "Imported $($_.Name)" }
    if (Test-Path "$Dir\ultravnc_ini_source.txt") {
        $src = (Get-Content "$Dir\ultravnc_ini_source.txt" | Select-Object -First 1).Trim()
        $bk = Get-ChildItem "$Dir\*_ultravnc.ini" | Select-Object -First 1
        if ($bk) { Copy-Item $bk.FullName $src -Force; Write-OK "Restored $src" }
    }
    foreach ($s in 'tvnserver', 'uvnc_service', 'vncserver', 'WinVNC4') { if (Get-Service $s -ErrorAction SilentlyContinue) { Restart-Service $s -Force; Write-OK "Restarted $s" } }
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
