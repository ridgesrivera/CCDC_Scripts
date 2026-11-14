#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Active Directory Certificate Services (service: CertSvc) info / backup / restore.
.DESCRIPTION
    Backup contains the CA PRIVATE KEY (protected by -KeyPassword). Treat as sensitive.
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\ccdc\backups\services',
    [switch]$Force,
    [string]$KeyPassword
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$Def = @{
    Name         = 'ADCS'
    Title        = 'AD Certificate Services (Certificate Authority)'
    ServiceNames = @('CertSvc')
    Description  = @"
The internal PKI. Issues certificates for LDAPS, HTTPS, smart card / PKINIT
logon, Wi-Fi, etc. If a template is misconfigured (ESC1-ESC15) any domain
user can request a cert AS a Domain Admin and log in with it - even after you
change every password. Database: %windir%\System32\CertLog\
Web enrollment (if installed) lives in IIS at /certsrv.
"@
    Ports        = @(
        @{ Port = 135; Proto = 'TCP'; Use = 'RPC/DCOM cert requests' }
        @{ Port = 80; Proto = 'TCP'; Use = 'Web enrollment / CRL (http)' }
        @{ Port = 443; Proto = 'TCP'; Use = 'Web enrollment (https)' }
        @{ Port = '49152-65535'; Proto = 'TCP'; Use = 'RPC dynamic' }
    )
    KeyPaths     = @("$env:SystemRoot\System32\CertLog", "$env:SystemRoot\System32\CertSrv", 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')
    RedTeam      = @(
        'ESC1: template with "Supply in request" + Client Auth + Domain Users can enroll'
        'ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA'
        'ESC8: NTLM relay to /certsrv web enrollment'
        'Stealing the CA key -> forge any certificate forever (golden cert)'
    )
    Hardening    = @(
        'certutil -config - -getreg policy\EditFlags   (must NOT contain EDITF_ATTRIBUTESUBJECTALTNAME2)'
        'Remove Domain Users / Authenticated Users enroll rights from client-auth templates'
        'Revoke certs issued during the competition you do not recognize (certutil -view)'
        'Disable web enrollment if not scored, or require HTTPS + EPA'
    )
    Detect       = { Test-ServiceInstalled 'CertSvc' }
}

$Def.InfoExtra = {
    & certutil -cainfo name 2>$null | Select-Object -First 3 | ForEach-Object { Write-Plain $_ }
    $flags = (& certutil -getreg policy\EditFlags 2>$null) -join ' '
    if ($flags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') { Write-CRIT "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 is SET. Fix: certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; restart CertSvc" }
    else { Write-OK "EDITF_ATTRIBUTESUBJECTALTNAME2 not set" }
    Write-STEP "Published templates"
    & certutil -CATemplates 2>$null | ForEach-Object { Write-Plain $_ }
    Write-STEP "Certificates issued in the last 24h"
    $since = (Get-Date).AddDays(-1).ToString('MM/dd/yyyy')
    & certutil -view -restrict "NotBefore>=$since,Disposition=20" -out "RequestID,RequesterName,CommonName,CertificateTemplate" csv 2>$null | Select-Object -First 25 | ForEach-Object { Write-Plain $_ }
}

$Def.Backup = {
    param($Dir)
    if (-not $KeyPassword) {
        $sec = Read-Host "Password to protect the CA private key backup" -AsSecureString
    } else { $sec = ConvertTo-SecureString $KeyPassword -AsPlainText -Force }
    $caDir = Join-Path $Dir 'CA'
    if (Get-Command Backup-CARoleService -ErrorAction SilentlyContinue) {
        Backup-CARoleService -Path $caDir -Password $sec -ErrorAction Stop
    } else {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        & certutil -p $plain -backup $caDir | Out-Null
    }
    Write-OK "CA database + private key -> CA\  (password protected)"
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' "$Dir\reg\CertSvc_Configuration.reg" | Out-Null
    & certutil -CATemplates > "$Dir\published_templates.txt" 2>&1
    & certutil -v -dstemplate > "$Dir\all_templates_ad.txt" 2>&1
    & certutil -getreg policy\EditFlags > "$Dir\EditFlags.txt" 2>&1
    Copy-Tree "$env:SystemRoot\System32\CertSrv\CertEnroll" (Join-Path $Dir 'CertEnroll') 'CertEnroll (CA cert + CRLs)' | Out-Null
}

$Def.Restore = {
    param($Dir)
    if (-not $KeyPassword) { $sec = Read-Host "CA backup password" -AsSecureString } else { $sec = ConvertTo-SecureString $KeyPassword -AsPlainText -Force }
    Stop-Service CertSvc -Force
    if (Get-Command Restore-CARoleService -ErrorAction SilentlyContinue) {
        Restore-CARoleService -Path (Join-Path $Dir 'CA') -Password $sec -Force -ErrorAction Stop
    } else {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        & certutil -f -p $plain -restore (Join-Path $Dir 'CA')
    }
    & reg.exe import "$Dir\reg\CertSvc_Configuration.reg" 2>&1 | Out-Null
    Start-Service CertSvc
    Write-OK "CA restored (database, key, configuration). Templates live in AD - not touched."
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
