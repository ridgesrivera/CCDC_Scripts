#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - IIS Web Server (services: W3SVC, WAS) info / backup / restore.
.DESCRIPTION
    Backs up: appcmd configuration backup (applicationHost.config, administration.config,
    redirection.config), every site's physical path (web roots, web.config files),
    app pool identities, bindings, SSL cert bindings, installed IIS features, and
    optionally the SSL certs WITH private keys (-ExportCertsPassword).
.EXAMPLE
    .\IIS.ps1
    .\IIS.ps1 -Action Restore              # config + web content (keeps extra files)
    .\IIS.ps1 -Action Restore -Mirror      # also DELETES files not in backup (kills dropped webshells)
#>
[CmdletBinding()]
param(
    [ValidateSet('Info', 'Backup', 'Restore', 'Verify', 'Detect', 'All')][string]$Action = 'All',
    [string]$RestoreFrom,
    [string]$BackupRoot = 'C:\CCDC_Backups\Services',
    [switch]$Force,
    [switch]$Mirror,
    [string]$ExportCertsPassword
)
. "$PSScriptRoot\_ServiceCommon.ps1"

$AppCmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

$Def = @{
    Name         = 'IIS'
    Title        = 'IIS Web Server'
    ServiceNames = @('W3SVC', 'WAS', 'IISADMIN', 'AppHostSvc')
    Description  = @"
Microsoft's web server. Hosts websites, e-commerce apps (ASP.NET / PHP via
FastCGI), web APIs, Exchange OWA, ADCS /certsrv, WSUS, etc.
  W3SVC   = the HTTP service     WAS = process activation (app pools / w3wp.exe)
  Config  = %windir%\System32\inetsrv\config\applicationHost.config
  Content = usually C:\inetpub\wwwroot (check every site's physicalPath!)
Each site runs in an Application Pool (w3wp.exe) under an identity; if that
identity is LocalSystem a webshell = SYSTEM. HTTP.sys (kernel) owns the
socket, so listeners show as PID 4 (System).
"@
    Ports        = @(
        @{ Port = 80; Proto = 'TCP'; Use = 'HTTP' }
        @{ Port = 443; Proto = 'TCP'; Use = 'HTTPS' }
        @{ Port = 8080; Proto = 'TCP'; Use = 'Alt HTTP (common custom binding)' }
        @{ Port = 8172; Proto = 'TCP'; Use = 'Web Management Service (WMSvc) - remote IIS admin' }
    )
    KeyPaths     = @(
        "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
        "$env:SystemDrive\inetpub\wwwroot"
        "$env:SystemDrive\inetpub\logs\LogFiles"
        "$env:SystemRoot\System32\inetsrv\backup"
    )
    RedTeam      = @(
        'Webshells (.aspx/.ashx/.asmx/.php/.jsp) dropped in web roots or uploads folders'
        'Malicious IIS native modules / managed handlers registered in applicationHost.config (IIS backdoors)'
        'App pool identity changed to LocalSystem'
        'Directory browsing on, or a virtual directory added that points at C:\'
        'web.config tampering (custom handlers, <system.webServer><handlers>)'
        'Stopping the site / app pool, or changing bindings so scoring fails'
    )
    Hardening    = @(
        'App pools -> ApplicationPoolIdentity, never LocalSystem'
        'Disable directory browsing; remove unused handlers (e.g. WebDAV)'
        'Look for files newer than competition start in web roots: Get-ChildItem -Recurse | ? LastWriteTime -gt (Get-Date).AddHours(-3)'
        'Check globalModules list in Info output against a known-good IIS (unknown DLL = backdoor)'
        'Restrict uploads folders: no execute (handlers accessPolicy="Read")'
    )
    Detect       = { Test-ServiceInstalled 'W3SVC' }
}

$Def.InfoExtra = {
    if (-not (Test-Path $AppCmd)) { Write-WARN "appcmd.exe missing"; return }
    Write-STEP "Sites"
    & $AppCmd list site | ForEach-Object { Write-Plain $_ }
    Write-STEP "Application pools (identity)"
    [xml]$pools = & $AppCmd list apppool /config /xml
    foreach ($p in $pools.appcmd.APPPOOL) {
        $id = $p.add.processModel.identityType; if (-not $id) { $id = 'ApplicationPoolIdentity' }
        $user = $p.add.processModel.userName
        $line = "{0,-30} state={1,-8} identity={2} {3}  .NET={4}" -f $p.'APPPOOL.NAME', $p.state, $id, $user, $p.add.managedRuntimeVersion
        if ($id -eq 'LocalSystem') { Write-CRIT $line } else { Write-Plain $line }
    }
    Write-STEP "Virtual directories -> physical paths"
    & $AppCmd list vdir | ForEach-Object { Write-Plain $_ }
    Write-STEP "Global (native) modules - unknown DLLs here are IIS backdoors"
    [xml]$gm = & $AppCmd list config -section:system.webServer/globalModules /xml
    foreach ($m in $gm.appcmd.CONFIG.'system.webServer-globalModules'.add) {
        $img = [Environment]::ExpandEnvironmentVariables($m.image)
        $sig = if (Test-Path $img) { (Get-AuthenticodeSignature $img).Status } else { 'MISSING' }
        if ($sig -ne 'Valid' -or $img -notmatch '\\inetsrv\\') { Write-CRIT ("{0,-32} {1} [{2}]" -f $m.name, $img, $sig) } else { Write-Plain ("{0,-32} {1}" -f $m.name, $img) }
    }
    Write-STEP "Directory browsing"
    & $AppCmd list config -section:system.webServer/directoryBrowse 2>$null | Select-String 'enabled="true"' | ForEach-Object { Write-WARN "Directory browsing enabled: $_" }
    Write-STEP "SSL certificate bindings (HTTP.sys)"
    & netsh http show sslcert | Select-String 'IP:port|Hostname:port|Certificate Hash' | ForEach-Object { Write-Plain $_.Line.Trim() }
    Write-STEP "Recently modified script files in web roots (last 6h)"
    $roots = (& $AppCmd list vdir /text:physicalPath) | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } | Sort-Object -Unique
    foreach ($r in $roots) {
        Get-ChildItem $r -Recurse -File -Include *.aspx, *.ashx, *.asmx, *.asp, *.php, *.jsp, *.config, *.dll, *.exe, *.ps1 -ErrorAction SilentlyContinue |
            Where-Object LastWriteTime -gt (Get-Date).AddHours(-6) | Select-Object -First 20 | ForEach-Object { Write-WARN "$($_.LastWriteTime)  $($_.FullName)" }
    }
}

$Def.Backup = {
    param($Dir)
    # 1. appcmd native backup (stored in inetsrv\backup\<name>) + copy it out
    $bname = "CCDC_$($script:CCDCStamp)"
    & $AppCmd add backup $bname | Out-Null
    Copy-Tree "$env:SystemRoot\System32\inetsrv\backup\$bname" (Join-Path $Dir 'appcmd_backup') 'appcmd config backup' | Out-Null
    Copy-Tree "$env:SystemRoot\System32\inetsrv\config" (Join-Path $Dir 'inetsrv_config') 'inetsrv\config (applicationHost.config etc)' -ExcludeDirs 'schema' | Out-Null

    # 2. Human-readable + machine-readable inventory
    & $AppCmd list site /config /xml > "$Dir\sites.xml"
    & $AppCmd list apppool /config /xml > "$Dir\apppools.xml"
    & $AppCmd list vdir /xml > "$Dir\vdirs.xml"
    & $AppCmd list config -section:system.webServer/globalModules > "$Dir\globalModules.txt"
    & netsh http show sslcert > "$Dir\sslcert_bindings.txt"
    & netsh http show urlacl > "$Dir\urlacl.txt"
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature Web-* | Where-Object Installed | Select-Object Name, DisplayName | Export-Csv "$Dir\installed_iis_features.csv" -NoTypeInformation
    }

    # 3. Every physical path (web roots) - de-duplicated so nested vdirs are not copied twice
    $roots = (& $AppCmd list vdir /text:physicalPath) | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') } | Sort-Object -Unique
    $top = @(); foreach ($r in ($roots | Sort-Object Length)) { if (-not ($top | Where-Object { $r.StartsWith("$_\", 'OrdinalIgnoreCase') })) { $top += $r } }
    $map = @(); $i = 0
    foreach ($r in $top) {
        $i++; $leaf = "webroot_{0:D2}_{1}" -f $i, ((Split-Path $r -Leaf) -replace '[^\w\.-]', '_')
        if (Copy-Tree $r (Join-Path $Dir "content\$leaf") "Web content $r") { $map += [pscustomobject]@{ Folder = $leaf; Source = $r } }
    }
    $map | Export-Csv "$Dir\content_map.csv" -NoTypeInformation

    # 4. Optional: SSL certs with private keys
    if ($ExportCertsPassword) {
        $pw = ConvertTo-SecureString $ExportCertsPassword -AsPlainText -Force
        $hashes = (& netsh http show sslcert | Select-String 'Certificate Hash\s*:\s*(\w+)').Matches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        New-Item -ItemType Directory "$Dir\certs" -Force | Out-Null
        foreach ($h in $hashes) {
            $c = Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $h
            if ($c) { Export-PfxCertificate -Cert $c -FilePath "$Dir\certs\$h.pfx" -Password $pw -ErrorAction SilentlyContinue | Out-Null; Write-OK "SSL cert $h -> certs\$h.pfx" }
        }
    } else { Write-INFO "SSL private keys not exported (use -ExportCertsPassword <pw> to include them)" }
}

$Def.Restore = {
    param($Dir)
    # Config: put the appcmd backup back into inetsrv\backup and restore it
    $name = "CCDC_restore_$($script:CCDCStamp)"
    $dst = "$env:SystemRoot\System32\inetsrv\backup\$name"
    New-Item -ItemType Directory $dst -Force | Out-Null
    Copy-Item "$Dir\appcmd_backup\*" $dst -Recurse -Force
    & $AppCmd add backup "PRE_RESTORE_$($script:CCDCStamp)" | Out-Null
    Write-INFO "Current (possibly tampered) config saved as inetsrv\backup\PRE_RESTORE_$($script:CCDCStamp)"
    & $AppCmd restore backup $name /stop:true
    if ($LASTEXITCODE -eq 0) { Write-OK "IIS configuration restored" } else { Write-WARN "appcmd restore returned $LASTEXITCODE" }

    # Content
    foreach ($m in Import-Csv "$Dir\content_map.csv") {
        Restore-Tree (Join-Path $Dir "content\$($m.Folder)") $m.Source -Mirror:$Mirror
    }
    # Certs
    if ((Test-Path "$Dir\certs") -and $ExportCertsPassword) {
        $pw = ConvertTo-SecureString $ExportCertsPassword -AsPlainText -Force
        Get-ChildItem "$Dir\certs\*.pfx" | ForEach-Object { Import-PfxCertificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\My -Password $pw | Out-Null; Write-OK "Imported cert $($_.BaseName)" }
    }
    & iisreset /restart | Out-Null
    Write-OK "iisreset done"
}

Invoke-ServiceMain -Def $Def -Action $Action -RestoreFrom $RestoreFrom -BackupRoot $BackupRoot -Force:$Force
