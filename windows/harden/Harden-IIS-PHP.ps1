<#
.SYNOPSIS
    Harden-IIS-PHP - back up and lock down IIS + PHP apps (WordPress, MediaWiki). CHANGES STATE (only the WP edit flag).

.DESCRIPTION
    PURPOSE
      Built for fernbank (Server 2022, IIS + PHP, WordPress + MediaWiki whose
      databases live on hatchery). Does the safe, high-value things:
        1. BACKUP  IIS config (applicationHost.config), php.ini, and every web root
        2. WP      add define('DISALLOW_FILE_EDIT', true) to wp-config.php
                   (kills the "edit plugin/theme PHP from wp-admin" web shell trick)
        3. CHECK   who can WRITE wp-config.php / LocalSettings.php (should be admins only)
        4. LIST    WordPress admin users, plugins + versions, must-use plugins, themes
        5. CHECK   MediaWiki anonymous edit/account-creation/uploads; php.ini risky settings

      It never prints DB passwords. It shows DB host/user/name so you know the
      dependency (e.g. "WordPress -> hatchery:3306 as user wp"). If you change
      that DB password on hatchery, you MUST update wp-config.php / LocalSettings.php
      at the same time or the scored sites go down.

    WHAT IT READS    applicationHost.config, wp-config.php, LocalSettings.php, php.ini,
                     plugin headers, file ACLs; WP database (read-only SELECT via PHP CLI)
    WHAT IT CHANGES  wp-config.php (one define line) - after backing it up
                     creates C:\ccdc\backups\<stamp>\ copies; a temp .php helper in %TEMP% (deleted)
    HOW TO UNDO      copy the backed-up wp-config.php back:
                       Copy-Item C:\ccdc\backups\<stamp>\C\inetpub\...\wp-config.php <original path>

    WHY SHORTINIT?
      To list admins we load WordPress with SHORTINIT=true: that gives us the
      database object WITHOUT loading plugins/themes. If Red Team backdoored a
      plugin, a normal wp-load.php would run their code as Administrator.

    WHY NOT Set-Content -Encoding UTF8?
      Windows PowerShell 5.1 writes a UTF-8 "BOM" (3 invisible bytes) first.
      PHP outputs those bytes before <?php -> "headers already sent" -> broken
      site / broken logins. We write with UTF8Encoding($false) = no BOM.

    MANUAL EQUIVALENT
      %windir%\system32\inetsrv\appcmd add backup "before-ccdc"
      %windir%\system32\inetsrv\appcmd list vdir /text:physicalPath
      notepad C:\inetpub\wwwroot\wordpress\wp-config.php   (add the define above "That's all, stop editing!")
      icacls C:\inetpub\wwwroot\wordpress\wp-config.php
      php wp-cli.phar user list --role=administrator       (if WP-CLI is available)

.EXAMPLE
    .\Harden-IIS-PHP.ps1 -WhatIf
.EXAMPLE
    .\Harden-IIS-PHP.ps1 -WebRoots D:\sites -SkipWebRootBackup
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$WebRoots = @(),
    [switch]$SkipWebRootBackup,
    [switch]$Force,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Harden-IIS-PHP' -OutFile $OutFile
$null = Get-CcdcConfig -Path $ConfigPath
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

# ---------------------------------------------------------------------------
Write-Section 'Discover IIS sites and PHP'
# ---------------------------------------------------------------------------
$appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
$roots = @($WebRoots)
if (Test-Path $appHost) {
    $xml = [xml](Get-Content $appHost -Raw)
    foreach ($site in $xml.configuration.'system.applicationHost'.sites.site) {
        foreach ($vd in $site.application.virtualDirectory) {
            $p = [Environment]::ExpandEnvironmentVariables($vd.physicalPath)
            $roots += $p
            $binds = ($site.bindings.binding | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
            Write-Finding -Level INFO -Category 'IIS' -Message ("site '{0}' {1} -> {2}" -f $site.name, $vd.path, $p) -Detail $binds
        }
    }
} else { Write-Finding -Level YELLOW -Category 'IIS' -Message 'applicationHost.config not found - is IIS installed?' }
$roots = @($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)

$php = Get-Command php.exe -ErrorAction SilentlyContinue
$phpExe = if ($php) { $php.Source } else { (Get-ChildItem 'C:\PHP*\php.exe', 'C:\Program Files\PHP\*\php.exe', 'C:\tools\php*\php.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName }
$phpIni = $null
if ($phpExe) {
    $phpIni = ((& $phpExe --ini 2>$null) | Select-String 'Loaded Configuration File:\s*(.+)$').Matches.Groups[1].Value
    Write-Finding -Level INFO -Category 'PHP' -Message ("PHP: {0}  ini: {1}" -f $phpExe, $phpIni)
} else { Write-Finding -Level YELLOW -Category 'PHP' -Message 'php.exe not found on PATH or common folders.' }

# Find apps (limit depth so a huge uploads folder does not stall us).
$wpConfigs = @(); $mwConfigs = @()
foreach ($r in $roots) {
    $wpConfigs += Get-ChildItem -Path $r -Filter wp-config.php -Recurse -Depth 3 -ErrorAction SilentlyContinue
    $mwConfigs += Get-ChildItem -Path $r -Filter LocalSettings.php -Recurse -Depth 3 -ErrorAction SilentlyContinue
}
$wpConfigs = @($wpConfigs | Sort-Object FullName -Unique); $mwConfigs = @($mwConfigs | Sort-Object FullName -Unique)
Write-Finding -Level INFO -Category 'Apps' -Message ("WordPress installs: {0}   MediaWiki installs: {1}" -f $wpConfigs.Count, $mwConfigs.Count)

# ---------------------------------------------------------------------------
Write-Section '1. Backup'
# ---------------------------------------------------------------------------
if ($WhatIfPreference) { Write-Finding -Level INFO -Category 'Backup' -Message 'WhatIf: would back up IIS config, php.ini and web roots.' }
else {
    foreach ($f in @($appHost, "$env:windir\System32\inetsrv\config\administration.config", $phpIni)) {
        if ($f -and (Test-Path $f)) { $d = Backup-CcdcFile -Path $f; Write-Finding -Level GREEN -Category 'Backup' -Message "$f -> $d" }
    }
    if (-not $SkipWebRootBackup) {
        foreach ($r in $roots) {
            $size = [math]::Round(((Get-ChildItem $r -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB), 1)
            Write-Host "     copying $r ($size MB)..." -ForegroundColor DarkGray
            $d = Backup-CcdcFile -Path $r
            Write-Finding -Level GREEN -Category 'Backup' -Message "web root $r -> $d"
        }
    }
    # Lock the backup folder down: it contains wp-config.php (DB passwords!).
    $bdir = Get-CcdcBackupDir
    $null = & icacls.exe $bdir /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 2>&1
    Write-Finding -Level INFO -Category 'Backup' -Message "Backup ACL restricted to Administrators/SYSTEM: $bdir"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Test-WritableByLowPriv([string]$path) {
    # Returns identities other than admins/SYSTEM/owner that can modify the file.
    $risky = @()
    foreach ($ace in (Get-Acl -LiteralPath $path).Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ([string]$ace.FileSystemRights -notmatch 'FullControl|Modify|Write') { continue }
        if ([string]$ace.IdentityReference -match '(?i)Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER') { continue }
        $risky += "$($ace.IdentityReference) ($($ace.FileSystemRights))"
    }
    return $risky
}
function Get-PhpDefine([string]$text, [string]$name) {
    # Reads define('NAME', 'value'); from wp-config.php
    $m = [regex]::Match($text, "define\(\s*['""]$name['""]\s*,\s*['""]([^'""]*)['""]")
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

# ---------------------------------------------------------------------------
Write-Section '2-4. WordPress'
# ---------------------------------------------------------------------------
foreach ($cfg in $wpConfigs) {
    $wpDir = $cfg.DirectoryName
    $text  = [System.IO.File]::ReadAllText($cfg.FullName)
    Write-Finding -Level INFO -Category 'WP' -Message "WordPress at $wpDir"
    # Dependency info (never the password):
    Write-Finding -Level INFO -Category 'WP' -Message ("DB: host={0} name={1} user={2}  <- changing this DB user's password requires editing wp-config.php" -f (Get-PhpDefine $text 'DB_HOST'), (Get-PhpDefine $text 'DB_NAME'), (Get-PhpDefine $text 'DB_USER'))

    # --- DISALLOW_FILE_EDIT ---
    if ($text -match "define\(\s*['""]DISALLOW_FILE_EDIT['""]\s*,\s*true\s*\)") {
        Write-Finding -Level GREEN -Category 'WP' -Message 'DISALLOW_FILE_EDIT already true'
    } else {
        $nl = if ($text -match "`r`n") { "`r`n" } else { "`n" }
        $line = "define('DISALLOW_FILE_EDIT', true); // CCDC: no PHP editing from wp-admin"
        # Insert before the "stop editing" marker if present, else before wp-settings.php is required.
        $marker = [regex]::Match($text, "(?m)^/\*\s*That's all, stop editing!.*$|^require_once\s*\(?\s*ABSPATH\s*\.\s*'wp-settings\.php'")
        $newText = if ($marker.Success) { $text.Insert($marker.Index, $line + $nl + $nl) } else { $text.TrimEnd() + $nl + $line + $nl }
        $cfgPath = $cfg.FullName
        [void](Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target $cfgPath -Action 'Add DISALLOW_FILE_EDIT=true' -Undo 'restore wp-config.php from C:\ccdc\backups\<stamp>\' -ScriptBlock {
            $null = Backup-CcdcFile -Path $cfgPath
            [System.IO.File]::WriteAllText($cfgPath, $newText, $utf8NoBom)   # no BOM - see header
        })
    }
    if ($text -match "define\(\s*['""]WP_DEBUG['""]\s*,\s*true") { Write-Finding -Level YELLOW -Category 'WP' -Message 'WP_DEBUG is true (leaks paths/errors to visitors)' }

    # --- config file permissions ---
    $w = Test-WritableByLowPriv $cfg.FullName
    if ($w) { Write-Finding -Level RED -Category 'WP' -Message 'wp-config.php writable by non-admins' -Detail (($w -join '; ') + '  Fix: icacls wp-config.php /remove:g IIS_IUSRS Users  (then re-test the site)') }
    else { Write-Finding -Level GREEN -Category 'WP' -Message 'wp-config.php not writable by low-priv identities' }

    # --- plugins / mu-plugins / themes (file-based, no PHP execution) ---
    foreach ($kind in @('plugins', 'mu-plugins')) {
        $pdir = Join-Path $wpDir "wp-content\$kind"
        if (-not (Test-Path $pdir)) { continue }
        foreach ($pf in (Get-ChildItem $pdir -Filter *.php -Recurse -Depth 1 -ErrorAction SilentlyContinue)) {
            $head = Get-Content -LiteralPath $pf.FullName -TotalCount 40 -ErrorAction SilentlyContinue
            $pn = ($head | Select-String '^\s*\*?\s*Plugin Name:\s*(.+)$').Matches | Select-Object -First 1
            if (-not $pn -and $kind -eq 'plugins') { continue }
            $ver = ($head | Select-String '^\s*\*?\s*Version:\s*(.+)$').Matches | Select-Object -First 1
            $name = if ($pn) { $pn.Groups[1].Value.Trim() } else { $pf.Name }
            $v = if ($ver) { $ver.Groups[1].Value.Trim() } else { '?' }
            # mu-plugins load automatically and do not show in the normal plugin list - favourite hiding spot.
            $lvl = if ($kind -eq 'mu-plugins') { 'RED' } elseif ($pf.LastWriteTime -gt (Get-Date).AddDays(-3)) { 'YELLOW' } else { 'INFO' }
            Write-Finding -Level $lvl -Category "WP-$kind" -Message ("{0} {1}  ({2})" -f $name, $v, $pf.FullName.Replace($wpDir, '.')) -Detail ("modified {0}" -f $pf.LastWriteTime)
        }
    }
    Get-ChildItem (Join-Path $wpDir 'wp-content\themes') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Finding -Level INFO -Category 'WP-theme' -Message $_.Name
    }
    $up = Join-Path $wpDir 'wp-content\uploads'
    if ((Test-Path $up) -and -not (Test-Path (Join-Path $up 'web.config'))) {
        Write-Finding -Level YELLOW -Category 'WP' -Message 'uploads\ has no web.config blocking script execution' -Detail 'Consider a web.config in uploads\ that removes the PHP handler (test the site after!).'
    }

    # --- admin users via PHP CLI with SHORTINIT (no plugins executed) ---
    if ($phpExe) {
        $helper = Join-Path $env:TEMP ("ccdc_wpadmins_{0}.php" -f $script:CcdcStamp)
        $phpCode = @'
<?php
// CCDC helper: list WordPress administrators WITHOUT loading plugins/themes.
define('SHORTINIT', true);
$_SERVER['HTTP_HOST'] = 'localhost';
require $argv[1] . '/wp-load.php';
global $wpdb;
$key = $wpdb->prefix . 'capabilities';
$rows = $wpdb->get_results($wpdb->prepare(
  "SELECT u.user_login, u.user_email, u.user_registered FROM {$wpdb->users} u
   JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
   WHERE m.meta_key = %s AND m.meta_value LIKE %s", $key, '%administrator%'));
foreach ($rows as $r) { echo $r->user_login, "\t", $r->user_email, "\t", $r->user_registered, "\n"; }
'@
        try {
            [System.IO.File]::WriteAllText($helper, $phpCode, $utf8NoBom)   # helper contains no secrets
            $out = & $phpExe $helper $wpDir 2>&1
            foreach ($l in $out) {
                $parts = "$l" -split "`t"
                if ($parts.Count -ge 3) {
                    $reg = [datetime]::MinValue
                    # Admin registered in the last 3 days = very likely Red Team.
                    $lvl = if ([datetime]::TryParse($parts[2], [ref]$reg) -and $reg -gt (Get-Date).AddDays(-3)) { 'RED' } else { 'YELLOW' }
                    Write-Finding -Level $lvl -Category 'WP-admin' -Message ("admin: {0} <{1}> registered {2}" -f $parts[0], $parts[1], $parts[2])
                } elseif ("$l".Trim()) { Write-Finding -Level YELLOW -Category 'WP-admin' -Message "php: $l" }
            }
        } finally { Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
Write-Section '5. MediaWiki'
# ---------------------------------------------------------------------------
foreach ($ls in $mwConfigs) {
    $t = [System.IO.File]::ReadAllText($ls.FullName)
    Write-Finding -Level INFO -Category 'MW' -Message "MediaWiki at $($ls.DirectoryName)"
    $dbs = [regex]::Match($t, '\$wgDBserver\s*=\s*["'']([^"'']*)').Groups[1].Value
    $dbu = [regex]::Match($t, '\$wgDBuser\s*=\s*["'']([^"'']*)').Groups[1].Value
    $dbn = [regex]::Match($t, '\$wgDBname\s*=\s*["'']([^"'']*)').Groups[1].Value
    Write-Finding -Level INFO -Category 'MW' -Message "DB: server=$dbs name=$dbn user=$dbu  <- changing this DB password requires editing LocalSettings.php"
    if ($t -match "\`$wgGroupPermissions\['\*'\]\['edit'\]\s*=\s*true") { Write-Finding -Level YELLOW -Category 'MW' -Message 'Anonymous users can edit pages' }
    if ($t -notmatch "\`$wgGroupPermissions\['\*'\]\['createaccount'\]\s*=\s*false") { Write-Finding -Level YELLOW -Category 'MW' -Message 'Anonymous account creation not disabled' }
    if ($t -match '\$wgEnableUploads\s*=\s*true') { Write-Finding -Level YELLOW -Category 'MW' -Message 'File uploads enabled - check $wgFileExtensions and the images\ folder for scripts' }
    $w = Test-WritableByLowPriv $ls.FullName
    if ($w) { Write-Finding -Level RED -Category 'MW' -Message 'LocalSettings.php writable by non-admins' -Detail ($w -join '; ') }
    else { Write-Finding -Level GREEN -Category 'MW' -Message 'LocalSettings.php not writable by low-priv identities' }
}
if (-not $mwConfigs) { Write-Finding -Level INFO -Category 'MW' -Message 'No MediaWiki found.' }

if ($phpIni -and (Test-Path $phpIni)) {
    Write-Section 'php.ini quick check (report only)'
    $ini = Get-Content $phpIni | Where-Object { $_ -notmatch '^\s*;' }
    function Get-Ini($k) { ($ini | Select-String "^\s*$k\s*=\s*(.*)$").Matches | Select-Object -Last 1 | ForEach-Object { $_.Groups[1].Value.Trim() } }
    if ((Get-Ini 'allow_url_include') -match '(?i)^(on|1)') { Write-Finding -Level RED -Category 'PHP' -Message 'allow_url_include = On (remote file inclusion)' }
    if ((Get-Ini 'display_errors') -match '(?i)^(on|1)') { Write-Finding -Level YELLOW -Category 'PHP' -Message 'display_errors = On' }
    if ((Get-Ini 'expose_php') -match '(?i)^(on|1)') { Write-Finding -Level INFO -Category 'PHP' -Message 'expose_php = On (version in headers)' }
    $df = Get-Ini 'disable_functions'
    Write-Finding -Level INFO -Category 'PHP' -Message ("disable_functions = {0}" -f $(if ($df) { $df } else { '(none) - consider exec,shell_exec,system,passthru,proc_open,popen; TEST WordPress/MediaWiki after' }))
}

Complete-Ccdc
