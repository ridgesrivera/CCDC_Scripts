<#
.SYNOPSIS
    Audit-SensitiveFiles - find PII, card numbers, passwords and keys lying in files, and who can read them. READ-ONLY.

.DESCRIPTION
    PURPOSE
      Red Team scores for data, not only for shells: customer PII is 200
      points, card numbers 50, sensitive files 25, password dumps 50 - per
      system. Anonymous access and data leakage cost 700 points at Regionals.
      The season's lesson: "find PII and card data in the first hour and
      restrict it". This script finds it; you decide where it should live.

    WHAT IT LOOKS FOR
      In file CONTENT (text files, configs, CSV/SQL dumps, .docx / .xlsx):
        * US Social Security numbers          * payment card numbers (Luhn-checked)
        * private keys                        * password / secret / API-key assignments
        * long lists of e-mail addresses (customer or employee lists)
      By file NAME: password lists, payroll, customer exports, database dumps,
      KeePass databases, certificates with private keys, ntds.dit copies,
      unattend.xml, SSH private keys.
      For each hit: is it under a WEB ROOT or a SHARE (reachable from the
      network), and can Everyone / Users / Authenticated Users read it?

      Values are never printed or logged: only counts and file paths. The
      report must not become the next sensitive file.

    WHAT IT READS    files under -Path (default: user profiles, web roots, share folders,
                     data drives). Skips Windows, Program Files and files over -MaxFileMB.
    WHAT IT CHANGES  nothing (own log + optional report only)
    HOW TO UNDO      nothing to undo

    WHAT TO DO WITH A FINDING
      1. Is it needed by a scored service? If yes, leave it in place and tighten the ACL.
      2. Under a web root or share and not needed there: move it out.
           Move-Item <file> C:\ccdc\secured\        (then check the service still scores)
      3. Tighten:  icacls <file> /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
      4. Passwords found in files are burned: rotate them (harden\Rotate-Passwords.ps1).

    MANUAL EQUIVALENT
      Get-ChildItem C:\Users,C:\inetpub -Recurse -Include *.txt,*.csv,*.sql -EA 0 |
        Select-String -Pattern '\b\d{3}-\d{2}-\d{4}\b' -List | select Path
      dir /s /b C:\*pass* C:\*.kdbx C:\*.sql 2>nul
      icacls <file>

.PARAMETER Path
    Folders to scan. Default: C:\Users, web roots, non-admin share folders, other fixed drives.

.PARAMETER MaxFileMB
    Skip content scanning of files larger than this. Default 5.

.PARAMETER MaxFiles
    Stop after this many files (keeps the run short on big file servers). Default 60000.

.EXAMPLE
    .\Audit-SensitiveFiles.ps1 -OutFile C:\ccdc\reports\sensitive.csv
.EXAMPLE
    .\Audit-SensitiveFiles.ps1 -Path D:\Shares,C:\inetpub
#>
[CmdletBinding()]
param(
    [string[]]$Path = @(),
    [ValidateRange(1, 200)][int]$MaxFileMB = 5,
    [int]$MaxFiles = 60000,
    [string]$OutFile,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Audit-SensitiveFiles' -OutFile $OutFile -ReadOnly
$null = Get-CcdcConfig -Path $ConfigPath

# ---------------------------------------------------------------------------
# Where to look, and which folders are reachable from the network
# ---------------------------------------------------------------------------
$webRoots = @()
$appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
if (Test-Path $appHost) {
    try { $webRoots += ([xml](Get-Content $appHost -Raw)).configuration.'system.applicationHost'.sites.site.application.virtualDirectory.physicalPath | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } } catch { $null = $_ }
}
foreach ($d in @('C:\inetpub', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\Apache24\htdocs', 'C:\inetpub\ftproot')) { if (Test-Path $d) { $webRoots += $d } }
$webRoots = @($webRoots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
# Type 0 = ordinary disk share (not C$, ADMIN$, IPC$). SYSVOL/NETLOGON are scanned too: scripts there often hold passwords.
$shares = @(Get-WmiObject Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 0 -and $_.Path })
$sharePaths = @($shares | ForEach-Object { $_.Path.TrimEnd('\') } | Sort-Object -Unique)

if ($Path.Count -eq 0) {
    $Path = @('C:\Users') + $webRoots + $sharePaths
    # Data drives (D:, E:...) are where file servers keep the interesting things.
    $Path += @(Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -ne $env:SystemDrive } | ForEach-Object { "$($_.DeviceID)\" })
    # Top-level folders on C: that are not part of Windows (C:\Data, C:\Backups, C:\Scripts...).
    $Path += @(Get-ChildItem "$env:SystemDrive\" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|inetpub|ccdc|Documents and Settings|Config\.Msi|\$WinREAgent)$' } |
        ForEach-Object { $_.FullName })
}
$Path = @($Path | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
# Drop folders that are inside another folder on the list (no double scanning).
$roots = @(); foreach ($p in ($Path | Sort-Object Length)) { if (-not ($roots | Where-Object { $p -like "$($_.TrimEnd('\'))\*" })) { $roots += $p } }
Write-Finding -Level INFO -Category 'Scope' -Message ("Scanning {0} folder(s)" -f $roots.Count) -Detail ($roots -join "`n")

$skipDirRegex  = '(?i)\\(AppData\\Local\\(Microsoft|Packages|Temp)|AppData\\LocalLow|node_modules|\.git\\objects|WinSxS|wp-includes|\$Recycle\.Bin|ccdc\\(logs|reports|backups|quarantine|evidence|alerts))\\'
$contentExt    = @('.txt', '.csv', '.tsv', '.log', '.sql', '.json', '.xml', '.ini', '.conf', '.config', '.cfg', '.yml', '.yaml', '.md', '.htm', '.html', '.php', '.bak', '.old', '.dat', '.env',
                   '.ps1', '.bat', '.cmd', '.vbs', '.py', '.sh', '.properties', '.inc', '.rtf', '.docx', '.xlsx', '')
$nameRegex     = '(?i)(passw|pwd|cred|secret|ssn|social.?sec|payroll|salar|customer|client.?list|credit|card|cardholder|pii|employee|personnel|hr[_ -]|w-?2|tax|invoice|billing|patient|medical|backup|dump|export|confidential|private|id_rsa|id_ed25519|\.kdbx?$|\.pfx$|\.p12$|\.pem$|\.key$|\.ppk$|ntds\.dit|\.sql(\.gz|\.zip)?$|\.bak$|\.mdf$|unattend\.xml|sysprep\.(xml|inf)|web\.config\.bak|\.ovpn$|\.rdp$|\.htpasswd)'
$rxSsn      = [regex]'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
$rxCard     = [regex]'(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])'
$rxKey      = [regex]'-----BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----'
$rxSecret   = [regex]'(?im)^.{0,60}\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|connectionstring)\b["'']?\s*[:=>]+\s*["'']?[^\s"''<>]{4,}'
$rxEmail    = [regex]'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
$broadRegex = '(?i)^(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users|NT AUTHORITY\\ANONYMOUS LOGON|NT AUTHORITY\\IUSR|BUILTIN\\IIS_IUSRS|.*\\Domain Users|.*\\Guests?)$'

function Test-Luhn([string]$digits) {
    # The checksum every real card number passes. Cuts random 16-digit numbers out of the results.
    $sum = 0; $alt = $false
    for ($i = $digits.Length - 1; $i -ge 0; $i--) {
        $n = [int]$digits[$i] - 48
        if ($alt) { $n *= 2; if ($n -gt 9) { $n -= 9 } }
        $sum += $n; $alt = -not $alt
    }
    return (($sum % 10) -eq 0)
}

function Get-CardCount([string]$text) {
    $count = 0
    foreach ($m in $rxCard.Matches($text)) {
        $d = $m.Value -replace '[ -]', ''
        if ($d.Length -lt 13 -or $d.Length -gt 19) { continue }
        # Known issuer prefixes: Visa 4, Mastercard 51-55 / 2221-2720, Amex 34/37, Discover 6011/65.
        if ($d -notmatch '^(4|5[1-5]|2[2-7]|3[47]|6011|65)') { continue }
        if ($d -match '^(\d)\1+$') { continue }
        if (Test-Luhn $d) { $count++; if ($count -ge 50) { break } }
    }
    return $count
}

function Get-OfficeText([string]$file) {
    # .docx / .xlsx are zip files; the words live in a couple of XML parts inside.
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($file)
        try {
            $sb = New-Object System.Text.StringBuilder
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -notmatch '^(word/document\.xml|xl/sharedStrings\.xml|xl/worksheets/sheet\d+\.xml)$') { continue }
                if ($entry.Length -gt 20MB) { continue }
                $reader = New-Object System.IO.StreamReader($entry.Open())
                [void]$sb.Append(($reader.ReadToEnd() -replace '<[^>]+>', ' ')); $reader.Close()
            }
            return $sb.ToString()
        } finally { $zip.Dispose() }
    } catch { return '' }
}

function Get-Exposure([string]$file) {
    # Where is it reachable from, and which broad groups may read it?
    $where = @()
    foreach ($w in $webRoots)   { if ($file -like "$($w.TrimEnd('\'))\*") { $where += 'WEB ROOT'; break } }
    foreach ($s in $shares)     { if ($file -like "$($s.Path.TrimEnd('\'))\*") { $where += "SHARE \\$env:COMPUTERNAME\$($s.Name)"; break } }
    $who = @()
    try {
        foreach ($ace in (Get-Acl -LiteralPath $file -ErrorAction Stop).Access) {
            if ($ace.AccessControlType -eq 'Allow' -and "$($ace.IdentityReference)" -match $broadRegex -and "$($ace.FileSystemRights)" -match 'Read|FullControl|Modify') { $who += "$($ace.IdentityReference)" }
        }
    } catch { $null = $_ }
    return [pscustomobject]@{ Where = ($where -join ' + '); Who = (($who | Sort-Object -Unique) -join ', ') }
}

# ---------------------------------------------------------------------------
Write-Section 'Scanning'
# ---------------------------------------------------------------------------
$maxBytes = $MaxFileMB * 1MB
$seen = 0; $hits = 0; $skippedBig = 0
$totals = @{ SSN = 0; Card = 0; Key = 0; Secret = 0; Name = 0 }
:scan foreach ($root in $roots) {
    foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.FullName -match $skipDirRegex) { continue }
        $seen++
        if ($seen -gt $MaxFiles) { Write-Finding -Level YELLOW -Category 'Scope' -Message "Stopped after $MaxFiles files. Narrow with -Path or raise -MaxFiles."; break scan }
        if (($seen % 5000) -eq 0) { Write-Host ("  ... {0} files checked, {1} findings" -f $seen, $hits) -ForegroundColor DarkGray }

        $found = @()
        $nameHit = $f.Name -match $nameRegex
        $ext = $f.Extension.ToLower()
        if ($contentExt -contains $ext -and $f.Length -gt 0) {
            if ($f.Length -gt $maxBytes) { $skippedBig++ }
            else {
                $text = ''
                if ($ext -in '.docx', '.xlsx') { $text = Get-OfficeText $f.FullName }
                else { try { $text = [System.IO.File]::ReadAllText($f.FullName) } catch { $text = '' } }
                if ($text) {
                    $nSsn = $rxSsn.Matches($text).Count
                    $nCard = Get-CardCount $text
                    $nMail = if ($text.Length -lt 4MB) { $rxEmail.Matches($text).Count } else { 0 }
                    if ($nSsn -gt 0)  { $found += "SSN x$nSsn"; $totals.SSN++ }
                    if ($nCard -gt 0) { $found += "card number x$nCard"; $totals.Card++ }
                    if ($rxKey.IsMatch($text)) { $found += 'PRIVATE KEY'; $totals.Key++ }
                    # Application code is full of "$password = $_POST[...]": only count secrets in config-like files.
                    if ($ext -notin '.php', '.html', '.htm', '.py', '.md', '.log' -or $f.Name -match '(?i)(config|settings|\.env|credentials)') {
                        $nSec = $rxSecret.Matches($text).Count
                        if ($nSec -gt 0) { $found += "password/secret assignment x$nSec"; $totals.Secret++ }
                    }
                    if ($nMail -ge 25) { $found += "e-mail addresses x$nMail (contact list)" }
                }
            }
        }
        if (-not $found -and -not $nameHit) { continue }
        if (-not $found) { $found += 'sensitive-looking file name'; $totals.Name++ }

        $hits++
        $exp = Get-Exposure $f.FullName
        $data = ($found -join ', ')
        # RED: regulated data, or anything sensitive that the network can reach / everyone can read.
        $regulated = $data -match 'SSN|card number|PRIVATE KEY'
        $lvl = if ($regulated -or ($exp.Where -and $data -notmatch '^sensitive-looking')) { 'RED' } elseif ($exp.Where -or $exp.Who -or $data -match 'password') { 'YELLOW' } else { 'INFO' }
        $detail = "{0}; {1:N0} bytes; modified {2}" -f $data, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
        if ($exp.Where) { $detail += "`nREACHABLE: $($exp.Where)" }
        if ($exp.Who)   { $detail += "`nreadable by: $($exp.Who)" }
        Write-Finding -Level $lvl -Category 'Sensitive' -Message $f.FullName -Detail $detail
    }
}

Write-Section 'Summary'
Write-Finding -Level INFO -Category 'Summary' -Message ("{0} files checked, {1} findings: SSN in {2} file(s), card numbers in {3}, private keys in {4}, secrets in {5}, name-only {6}" -f $seen, $hits, $totals.SSN, $totals.Card, $totals.Key, $totals.Secret, $totals.Name)
if ($skippedBig -gt 0) { Write-Finding -Level INFO -Category 'Summary' -Message "$skippedBig file(s) over $MaxFileMB MB were not content-scanned (raise -MaxFileMB to include them)." }
if ($hits -eq 0) { Write-Finding -Level GREEN -Category 'Summary' -Message 'No sensitive data patterns found in the scanned folders.' }
else {
    Write-Finding -Level INFO -Category 'Next' -Message 'For each RED: needed by a scored service? If not, move it out of the web root / share. Then tighten the ACL.' `
        -Detail "icacls `"<file>`" /inheritance:r /grant:r `"Administrators:F`" `"SYSTEM:F`"`nPasswords found in files are burned: rotate them.`nDatabases hold PII too: services\MSSQL.ps1 / services\MySQL.ps1 list the tables."
}
Complete-Ccdc
