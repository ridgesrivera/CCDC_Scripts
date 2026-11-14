#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - OpenSSH Server for Windows (service: sshd) info / backup / restore.
.DESCRIPTION
    Backup includes HOST PRIVATE KEYS (so clients don't get host-key warnings after
    restore). They are sensitive - keep the backup protected.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$SshDir = "$env:ProgramData\ssh"

$Def = @{
    Name         = 'OpenSSH'
    Title        = 'OpenSSH Server (Windows)'
    ServiceNames = @('sshd', 'ssh-agent')
    Description  = @"
SSH remote shell on Windows (optional feature since Server 2019 / Win10).
Config:   %ProgramData%\ssh\sshd_config
Admin keys: %ProgramData%\ssh\administrators_authorized_keys  (used for ANY
           member of Administrators - per-user authorized_keys is IGNORED
           for admins by the default 'Match Group administrators' block)
User keys: C:\Users\<user>\.ssh\authorized_keys
Default shell is cmd.exe unless HKLM\SOFTWARE\OpenSSH DefaultShell is set.
"@
    Ports        = @(@{ Port = 22; Proto = 'TCP'; Use = 'SSH' })
    KeyPaths     = @("$SshDir\sshd_config", "$SshDir\administrators_authorized_keys", 'HKLM\SOFTWARE\OpenSSH')
    RedTeam      = @(
        'Dropping their public key in administrators_authorized_keys -> passwordless admin forever'
        'Per-user authorized_keys for non-admin footholds'
        'Changing DefaultShell to a backdoor binary'
        'PasswordAuthentication + weak passwords'
    )
    Hardening    = @(
        'Empty / verify every authorized_keys file (Info output lists them)'
        'administrators_authorized_keys ACL: only Administrators + SYSTEM'
        'PermitRootLogin / AllowGroups / AllowUsers in sshd_config'
        'Restart-Service sshd after config changes'
    )
    Detect       = { Test-ServiceInstalled 'sshd' }
}

$Def.InfoExtra = {
    if (Test-Path "$SshDir\sshd_config") {
        Write-STEP "Effective (non-comment) sshd_config lines"
        Get-Content "$SshDir\sshd_config" | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { Write-Plain $_ }
    }
    $ds = (Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue).DefaultShell
    if ($ds) { Write-INFO "DefaultShell: $ds" }
    Write-STEP "authorized_keys files"
    $files = @("$SshDir\administrators_authorized_keys") + (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\.ssh\authorized_keys" })
    foreach ($f in $files) {
        if (Test-Path $f) {
            $keys = Get-Content $f | Where-Object { $_ -match '^\s*(ssh-|ecdsa-|sk-)' }
            Write-WARN "$f : $(@($keys).Count) key(s)"
            foreach ($k in $keys) { $p = @($k -split "\s+") + @("",""); $tail = if ($p[1].Length -gt 12) { $p[1].Substring($p[1].Length - 12) } else { $p[1] }; Write-Plain "  $($p[0]) ...$tail $($p[2..9] -join " ")" }
        }
    }
    Show-RecentEvents -LogName 'OpenSSH/Operational' -Max 10
}

$Def.Backup = {
    param($Dir)
    Copy-Tree $SshDir (Join-Path $Dir 'ProgramData_ssh') 'ProgramData\ssh (config + host keys + admin keys)' -ExcludeDirs 'logs' | Out-Null
    Export-RegKey 'HKLM\SOFTWARE\OpenSSH' "$Dir\reg\OpenSSH.reg" | Out-Null
    $uk = Join-Path $Dir 'user_authorized_keys'; New-Item -ItemType Directory $uk -Force | Out-Null
    Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $f = "$($_.FullName)\.ssh\authorized_keys"; if (Test-Path $f) { Copy-Item $f "$uk\$($_.Name).authorized_keys"; Write-OK "authorized_keys for $($_.Name)" }
    }
}

$Def.Restore = {
    param($Dir)
    Stop-Service sshd -Force -ErrorAction SilentlyContinue
    Restore-Tree (Join-Path $Dir 'ProgramData_ssh') $SshDir
    if (Test-Path "$Dir\reg\OpenSSH.reg") { & reg.exe import "$Dir\reg\OpenSSH.reg" 2>&1 | Out-Null }
    # admin keys: replace exactly (remove anything red team appended)
    $ak = "$Dir\ProgramData_ssh\administrators_authorized_keys"
    if (Test-Path $ak) { Copy-Item $ak "$SshDir\administrators_authorized_keys" -Force } else { Remove-Item "$SshDir\administrators_authorized_keys" -Force -ErrorAction SilentlyContinue }
    & icacls.exe "$SshDir\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" /grant "*S-1-5-18:F" 2>&1 | Out-Null
    Get-ChildItem C:\Users -Directory | ForEach-Object {
        $live = "$($_.FullName)\.ssh\authorized_keys"; $bk = "$Dir\user_authorized_keys\$($_.Name).authorized_keys"
        if (Test-Path $bk) { Copy-Item $bk $live -Force; Write-OK "Restored keys for $($_.Name)" }
        elseif (Test-Path $live) { Write-CRIT "$live exists but was NOT in backup -> review / delete" }
    }
    Start-Service sshd; Write-OK "sshd restarted"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
