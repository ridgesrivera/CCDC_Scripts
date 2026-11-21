<#
.SYNOPSIS
    pii-hunt - read-only PII discovery for Windows boxes (files, shares, SQL Server).

.DESCRIPTION
    PURPOSE
      1) Files: card numbers (Luhn-checked), US SSNs, DDMMYY-NNNN national IDs, emails,
         "password=" / connectionString strings
      2) SMB shares and who can reach them (Everyone / Authenticated Users flagged)
      3) SQL Server (if present): sysadmins, xp_cmdshell, every DB/table/column that
         looks like PII, with row counts, guest user
      4) MySQL / Postgres / Mongo: tells you where to look if installed

    WHAT IT READS    files under -Paths (< -MaxMB), shares, SQL metadata (Windows auth)
    WHAT IT CHANGES  nothing; writes C:\bt\pii-report.txt
    HOW TO UNDO      delete the report

    MANUAL EQUIVALENT
      Select-String -Path C:\inetpub\* -Pattern '\d{3}-\d{2}-\d{4}' -List
      sqlcmd -S . -E -Q "SELECT TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%ssn%'"

.EXAMPLE
    .\pii-hunt.ps1 -Paths C:\inetpub,C:\Shares
#>
param(
  [string[]]$Paths = @("C:\inetpub","C:\Shares","C:\Users","C:\ProgramData","C:\Temp","C:\Windows\Temp","C:\xampp","C:\wamp64","C:\backup","C:\Windows\Panther"),
  [int]$MaxMB = 25
)
$ErrorActionPreference = "SilentlyContinue"
New-Item C:\bt -ItemType Directory -Force | Out-Null
$report = "C:\bt\pii-report.txt"
"PII hunt on $env:COMPUTERNAME  $(Get-Date)" | Out-File $report
function Say($s, $color = "Gray") { Write-Host $s -ForegroundColor $color; $s | Out-File $report -Append }

function Test-Luhn([string]$n) {
  $d = ($n -replace '\D','').ToCharArray() | ForEach-Object { [int][string]$_ }
  if ($d.Count -lt 13 -or $d.Count -gt 19) { return $false }
  $sum = 0; $alt = $false
  for ($i = $d.Count - 1; $i -ge 0; $i--) { $x = $d[$i]; if ($alt) { $x *= 2; if ($x -gt 9) { $x -= 9 } }; $sum += $x; $alt = -not $alt }
  return ($sum % 10 -eq 0)
}

$exts = "*.csv","*.txt","*.xml","*.json","*.sql","*.log","*.config","*.ini","*.asp","*.aspx","*.php","*.env","*.bak","*.xlsx","*.xls","*.docx","*.ps1","*.bat","*.yml","*.yaml","*.conf"
$rxCard = '\b(?:\d[ -]?){13,19}\b'
$rxSSN  = '\b\d{3}-\d{2}-\d{4}\b'
$rxNID  = '\b[0-3]\d[01]\d\d{2}-\d{4}\b'      # DDMMYY-NNNN national-ID style (several countries use it)
$rxMail = '\b[\w.+-]+@[\w-]+\.[\w.]+\b'
$rxPw   = '(?i)(password|passwd|pwd|cpassword|connectionstring)\s*[=:"]'

Say "`n=== 1. FILES ===" Cyan
$office = @(); $hits = 0
foreach ($p in $Paths) {
  if (-not (Test-Path $p)) { continue }
  # Skip browser / app caches under AppData: never customer data, often locked by a running program.
  Get-ChildItem $p -Recurse -File -Include $exts -Force | Where-Object { $_.Length -lt ($MaxMB * 1MB) -and $_.FullName -notmatch '(?i)\\AppData\\Local\\(Microsoft|Packages|Temp|Google|Mozilla)\\|\\INetCache\\|\\CacheStorage\\' } | ForEach-Object {
    $f = $_.FullName
    if ($_.Extension -in ".xlsx",".docx") { $office += $f; return }   # zipped: listed once at the end
    $text = $null
    try { $text = [IO.File]::ReadAllText($f) } catch { return }   # locked / unreadable file: skip it, keep scanning
    $cards = @([regex]::Matches($text, $rxCard) | Where-Object { Test-Luhn $_.Value }).Count
    $ssn   = ([regex]::Matches($text, $rxSSN)).Count
    $nid   = ([regex]::Matches($text, $rxNID)).Count
    $mail  = ([regex]::Matches($text, $rxMail)).Count
    $pw    = ([regex]::Matches($text, $rxPw)).Count
    if ($cards -or $ssn -or $nid -gt 2 -or $mail -gt 5 -or $pw) {
      $c = if ($cards -or $ssn) { "Red" } else { "Yellow" }; $hits++
      Say ("{0}`n    cards={1} ssn={2} national-id={3} emails={4} pw-strings={5}  modified={6}" -f $f, $cards, $ssn, $nid, $mail, $pw, $_.LastWriteTime) $c
    }
  }
}
if ($hits -eq 0) { Say "No PII found in files." Green }
if ($office) {
  Say ("{0} Office file(s) could not be read automatically (zipped): open the ones that look like customer or HR data. List in {1}" -f $office.Count, $report) Yellow
  $office | ForEach-Object { "   OFFICE $_" | Out-File $report -Append }
}
if ($hits) { Say "Anything above under C:\inetpub\wwwroot (or htdocs) can be downloaded by anyone: move or restrict it." Yellow }

Say "`n=== 2. SMB SHARES ===" Cyan
Get-SmbShare | Where-Object { $_.Name -notin "IPC$" } | ForEach-Object {
  $acc = (Get-SmbShareAccess $_.Name | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ", "
  Say ("{0,-14} {1,-30} {2}" -f $_.Name, $_.Path, $acc) $(if ($acc -match "Everyone|Authenticated Users|Domain Users") { "Red" } else { "Gray" })
}

Say "`n=== 3. SQL SERVER ===" Cyan
$inst = Get-Service | Where-Object { $_.Name -match '^MSSQL(\$|SERVER$)' }
if (-not $inst) { Say "No SQL Server services found." }
foreach ($s in $inst) {
  $name = if ($s.Name -eq "MSSQLSERVER") { "." } else { ".\" + ($s.Name -replace '^MSSQL\$','') }
  Say "Instance $name  ($($s.Status))" Green
  try {
    $cn = New-Object System.Data.SqlClient.SqlConnection "Server=$name;Integrated Security=SSPI;Database=master;Connect Timeout=8"
    $cn.Open()
    $q = { param($sql) $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $r = $cmd.ExecuteReader(); $t = New-Object System.Data.DataTable; $t.Load($r); ,$t }
    Say "-- Logins (type S = SQL auth). sysadmin members flagged:"
    (& $q "SELECT p.name, p.type, p.is_disabled, IS_SRVROLEMEMBER('sysadmin', p.name) AS sa FROM sys.server_principals p WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' AND p.name NOT LIKE 'NT %'").Rows |
      ForEach-Object { Say ("   {0,-28} type={1} disabled={2} sysadmin={3}" -f $_.name, $_.type, $_.is_disabled, $_.sa) $(if ($_.sa -eq 1 -and $_.type -eq 'S') { "Red" } else { "Gray" }) }
    $xp = (& $q "SELECT CAST(value_in_use AS INT) v FROM sys.configurations WHERE name='xp_cmdshell'").Rows[0].v
    Say "-- xp_cmdshell = $xp" $(if ($xp -eq 1) { "Red" } else { "Green" })
    $dbs = (& $q "SELECT name FROM sys.databases WHERE database_id > 4").Rows | ForEach-Object { $_.name }
    foreach ($db in $dbs) {
      $cn.ChangeDatabase($db)
      Say "-- Database [$db]" Green
      $cols = & $q @"
SELECT t.TABLE_SCHEMA s, t.TABLE_NAME tb, c.COLUMN_NAME col FROM INFORMATION_SCHEMA.COLUMNS c
JOIN INFORMATION_SCHEMA.TABLES t ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_TYPE = 'BASE TABLE'
WHERE c.COLUMN_NAME LIKE '%card%' OR c.COLUMN_NAME LIKE '%cc%' OR c.COLUMN_NAME LIKE '%cvv%' OR c.COLUMN_NAME LIKE '%pan%'
   OR c.COLUMN_NAME LIKE '%ssn%' OR c.COLUMN_NAME LIKE '%social%' OR c.COLUMN_NAME LIKE '%national%' OR c.COLUMN_NAME LIKE '%taxid%' OR c.COLUMN_NAME LIKE '%passport%' OR c.COLUMN_NAME LIKE '%license%' OR c.COLUMN_NAME LIKE '%kennitala%' OR c.COLUMN_NAME LIKE '%personnummer%' OR c.COLUMN_NAME LIKE '%dob%' OR c.COLUMN_NAME LIKE '%birth%'
   OR c.COLUMN_NAME LIKE '%pass%' OR c.COLUMN_NAME LIKE '%pwd%' OR c.COLUMN_NAME LIKE '%email%' OR c.COLUMN_NAME LIKE '%phone%'
   OR c.COLUMN_NAME LIKE '%addr%' OR c.COLUMN_NAME LIKE '%street%' OR c.COLUMN_NAME LIKE '%exp%'
"@
      $cols.Rows | Group-Object s, tb | ForEach-Object {
        $first = $_.Group[0]
        $cnt = (& $q "SELECT COUNT(*) n FROM [$($first.s)].[$($first.tb)]").Rows[0].n
        Say ("   {0}.{1}  rows={2}  PII-looking columns: {3}" -f $first.s, $first.tb, $cnt, (($_.Group | ForEach-Object { $_.col }) -join ", ")) Red
      }
      $g = (& $q "SELECT COUNT(*) n FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND permission_name = 'CONNECT' AND state = 'G'").Rows[0].n
      if ($g -gt 0) { Say "   guest user ENABLED in [$db]" Red }
    }
    $cn.Close()
  } catch { Say "   could not connect with Windows auth: $($_.Exception.Message)" Yellow }
}

Say "`n=== 4. OTHER DATABASES ===" Cyan
Get-Service | Where-Object { $_.Name -match 'mysql|maria|postgres|mongo' } | ForEach-Object { Say "Found service $($_.Name) ($($_.Status)) - check it by hand (mysql -u root -p / psql -U postgres): list databases, find PII columns, check who can log in" Yellow }
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 1433,1434,3306,5432,27017,6379 | ForEach-Object {
  Say ("DB port {0} listening on {1}  (0.0.0.0/:: = reachable from the network unless firewalled)" -f $_.LocalPort, $_.LocalAddress) Yellow
}
Say "`nReport saved to $report" Green
