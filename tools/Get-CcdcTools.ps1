<#
.SYNOPSIS
    Get-CcdcTools - download, verify and hash the third-party audit tools the toolkit uses.

.DESCRIPTION
    PURPOSE
      Stage every useful third-party tool into tools\ in ONE command, from the
      official source, and write a SHA256 manifest so a teammate can prove the
      copy on the USB stick / share was not tampered with.

      Run it BEFORE the competition on a trusted machine (Windows PowerShell 5.1
      or PowerShell 7 on Windows/Linux/macOS), then copy the whole repo folder.
      If the competition network allows internet and the rules allow it, you
      can also run it on a box - but re-check the hashes with -Verify anyway.

    WHAT GETS STAGED (default = defensive tools only)
      sysinternals  Sysinternals Suite: autorunsc, sigcheck, accesschk, procexp, tcpview, ...  -> tools\bin\sysinternals\
      sysmon        Sysmon (Setup-Logging.ps1 installs it)                                     -> tools\sysmon\
      sysmonconfig  SwiftOnSecurity sysmon-config (only if you have none)                     -> tools\sysmon\sysmonconfig.xml
      pingcastle    PingCastle - AD health / attack-path report (run on the DC)               -> tools\bin\pingcastle\
      locksmith     Locksmith - AD Certificate Services misconfig finder (ESC1-ESC16)          -> tools\bin\locksmith\
      hayabusa      Hayabusa - Sigma-rule hunting over the Windows event logs                 -> tools\bin\hayabusa\
      With -IncludeOffensive (attacker-style enumerators, see tools\README.md first):
      winpeas       winPEAS x64 + .bat - privilege-escalation enumeration                      -> tools\bin\peass\
      With -IncludeLinux (for the Linux boxes in the pod):
      pspy          pspy64 - watch processes/cron without root                                -> tools\linux\
      lynis         Lynis - Linux hardening audit (tar.gz)                                     -> tools\linux\
      linpeas       linpeas.sh (only with BOTH -IncludeLinux and -IncludeOffensive)            -> tools\linux\

    WHAT IT READS    the internet (official vendor / GitHub release URLs listed in $catalog below)
    WHAT IT CHANGES  writes files under tools\ (all gitignored) and tools\staged-tools.csv (the manifest)
    HOW TO UNDO      delete tools\bin, tools\sysmon\*.exe, tools\linux, tools\staged-tools.csv

    VERIFY ON THE COMPETITION BOX (no internet needed)
      powershell -ExecutionPolicy Bypass -File .\tools\Get-CcdcTools.ps1 -Verify
      Re-hashes every file against tools\staged-tools.csv and checks Microsoft
      signatures. Anything MISSING / MODIFIED = do not run it.

    MANUAL EQUIVALENT
      Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile s.zip
      Expand-Archive s.zip tools\bin\sysinternals
      Get-AuthenticodeSignature tools\bin\sysinternals\autorunsc64.exe
      Get-FileHash tools\bin\sysinternals\autorunsc64.exe -Algorithm SHA256

    NOTES
      * Windows Defender may quarantine winPEAS and (sometimes) Hayabusa's rule
        files as they land. That is expected; the script reports what went missing.
        Do NOT add Defender exclusions on competition boxes to make them run -
        Audit-Persistence flags exclusions RED for a reason.
      * GitHub's API allows 60 unauthenticated requests/hour. If you hit the
        limit, set $env:GITHUB_TOKEN to a read-only token for the run.

.PARAMETER Only
    Stage only these tool names (see list above).
.PARAMETER IncludeOffensive
    Also stage attacker-style enumerators (winPEAS, linPEAS with -IncludeLinux).
.PARAMETER IncludeLinux
    Also stage Linux tools (pspy, lynis).
.PARAMETER Verify
    Do not download. Re-hash everything in the manifest and report.
.PARAMETER Force
    Re-download tools that are already staged.

.EXAMPLE
    .\tools\Get-CcdcTools.ps1
.EXAMPLE
    .\tools\Get-CcdcTools.ps1 -IncludeLinux -IncludeOffensive
.EXAMPLE
    .\tools\Get-CcdcTools.ps1 -Verify
#>
[CmdletBinding()]
param(
    [string[]]$Only = @(),
    [switch]$IncludeOffensive,
    [switch]$IncludeLinux,
    [switch]$Verify,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
# 'powershell -File x.ps1 -Only a,b' passes ONE string "a,b" - split it ourselves.
$Only = @($Only | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })
$toolsRoot = $PSScriptRoot
$manifest  = Join-Path $toolsRoot 'staged-tools.csv'
# Windows PowerShell 5.1 has no $IsWindows; it only runs on Windows.
$onWindows = ($PSVersionTable.PSEdition -ne 'Core') -or $IsWindows
# Older Windows PowerShell defaults to TLS 1.0, which GitHub and Microsoft refuse.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }
# The progress bar makes Invoke-WebRequest 10x slower on Windows PowerShell 5.1.
$ProgressPreference = 'SilentlyContinue'

function Say([string]$tag, [string]$msg, [string]$color = 'Gray') { Write-Host ("  {0,-8} {1}" -f $tag, $msg) -ForegroundColor $color }

# ---------------------------------------------------------------------------
# Catalog. Kind: url = fixed URL; github = latest release asset matching AssetRegex.
# Extract: unzip into Dest (merged, nothing else in Dest is deleted). Check: file inside Dest
# that proves the tool is staged. Signer: expected Authenticode publisher for *.exe (Windows only check).
# ---------------------------------------------------------------------------
$catalog = @(
    @{ Name = 'sysinternals'; Set = 'blue'; Kind = 'url'; Url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'; Dest = 'bin\sysinternals'; Extract = $true; Check = 'autorunsc64.exe'; Signer = 'Microsoft' }
    @{ Name = 'sysmon'; Set = 'blue'; Kind = 'url'; Url = 'https://download.sysinternals.com/files/Sysmon.zip'; Dest = 'sysmon'; Extract = $true; Check = 'Sysmon64.exe'; Signer = 'Microsoft' }
    @{ Name = 'sysmonconfig'; Set = 'blue'; Kind = 'url'; Url = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'; Dest = 'sysmon\sysmonconfig.xml'; Extract = $false; KeepExisting = $true }
    @{ Name = 'pingcastle'; Set = 'blue'; Kind = 'github'; Repo = 'netwrix/pingcastle'; AssetRegex = '(?i)^PingCastle.*\.zip$'; Dest = 'bin\pingcastle'; Extract = $true; Check = 'PingCastle.exe' }
    @{ Name = 'locksmith'; Set = 'blue'; Kind = 'url'; Url = 'https://raw.githubusercontent.com/jakehildreth/Locksmith/main/Invoke-Locksmith.ps1'; Dest = 'bin\locksmith\Invoke-Locksmith.ps1'; Extract = $false }
    @{ Name = 'hayabusa'; Set = 'blue'; Kind = 'github'; Repo = 'Yamato-Security/hayabusa'; AssetRegex = '(?i)^hayabusa-[\d.]+-win-x64\.zip$'; Dest = 'bin\hayabusa'; Extract = $true }
    @{ Name = 'winpeas'; Set = 'offensive'; Kind = 'url'; Url = 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe'; Dest = 'bin\peass\winPEASx64.exe'; Extract = $false }
    @{ Name = 'winpeas-bat'; Set = 'offensive'; Kind = 'url'; Url = 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat'; Dest = 'bin\peass\winPEAS.bat'; Extract = $false }
    @{ Name = 'pspy'; Set = 'linux'; Kind = 'url'; Url = 'https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64'; Dest = 'linux\pspy64'; Extract = $false }
    @{ Name = 'lynis'; Set = 'linux'; Kind = 'github-tarball'; Repo = 'CISOfy/lynis'; Dest = 'linux\lynis.tar.gz'; Extract = $false }
    @{ Name = 'linpeas'; Set = 'linux-offensive'; Kind = 'url'; Url = 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh'; Dest = 'linux\linpeas.sh'; Extract = $false }
)

function Get-FileRecord([string]$full, [string]$name, [string]$source) {
    $rel = $full.Substring($toolsRoot.Length).TrimStart('\', '/')
    $signer = ''
    if ($onWindows -and $full -match '(?i)\.(exe|dll|ps1|msi)$') {
        $sig = Get-AuthenticodeSignature -FilePath $full -ErrorAction SilentlyContinue
        $signer = if ($sig -and $sig.Status -eq 'Valid') { ($sig.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1') } elseif ($sig) { "[$($sig.Status)]" } else { '' }
    }
    [pscustomobject]@{
        Tool = $name; File = ($rel -replace '/', '\'); SHA256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
        Size = (Get-Item -LiteralPath $full).Length; Signer = $signer; Source = $source; Staged = (Get-Date).ToString('s')
    }
}

function Resolve-Local([string]$rel) { Join-Path $toolsRoot ($rel -replace '\\', [IO.Path]::DirectorySeparatorChar) }

# ---------------------------------------------------------------------------
# -Verify: offline integrity check
# ---------------------------------------------------------------------------
if ($Verify) {
    Write-Host "`n  Verifying staged tools against $manifest`n" -ForegroundColor Cyan
    if (-not (Test-Path $manifest)) { Say 'MISSING' "No manifest. Run this script without -Verify on a trusted machine first." Red; exit 1 }
    $bad = 0; $ok = 0
    foreach ($row in Import-Csv $manifest) {
        $p = Resolve-Local $row.File
        if (-not (Test-Path -LiteralPath $p)) { Say 'MISSING' "$($row.File)  (deleted, or quarantined by AV)" Red; $bad++; continue }
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        if ($h -ne $row.SHA256) { Say 'MODIFIED' "$($row.File)  expected $($row.SHA256.Substring(0,16))... got $($h.Substring(0,16))..." Red; $bad++; continue }
        if ($onWindows -and $row.Signer -and $row.Signer -notmatch '^\[') {
            $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') { Say 'BADSIG' "$($row.File) signature now '$($sig.Status)'" Red; $bad++; continue }
        }
        $ok++
    }
    $color = if ($bad) { 'Red' } else { 'Green' }
    Write-Host ("`n  {0} files OK, {1} problems" -f $ok, $bad) -ForegroundColor $color
    if ($bad) { exit 1 } else { exit 0 }
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
$sets = @('blue')
if ($IncludeOffensive) { $sets += 'offensive' }
if ($IncludeLinux) { $sets += 'linux' }
if ($IncludeLinux -and $IncludeOffensive) { $sets += 'linux-offensive' }
$todo = @($catalog | Where-Object { $sets -contains $_.Set })
if ($Only) { $todo = @($catalog | Where-Object { $Only -contains $_.Name }) }
if (-not $todo) { Say 'ERROR' "Nothing selected. Names: $(($catalog | ForEach-Object Name) -join ', ')" Red; exit 1 }

$ghHeaders = @{ 'User-Agent' = 'ccdc-toolkit-stager'; 'Accept' = 'application/vnd.github+json' }
if ($env:GITHUB_TOKEN) { $ghHeaders.Authorization = "Bearer $env:GITHUB_TOKEN" }

# Downloads land in a fresh temp folder first, never directly in tools\.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ccdc_tools_{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

$old = @(); if (Test-Path $manifest) { $old = @(Import-Csv $manifest) }
$records = New-Object System.Collections.ArrayList
$failed = @()

Write-Host "`n  Staging tools into $toolsRoot  (sets: $($sets -join ', '))`n" -ForegroundColor Cyan
try {
    foreach ($t in $todo) {
        $dest = Resolve-Local $t.Dest
        $already = if ($t.Check) { Test-Path (Join-Path $dest $t.Check) }
                   elseif ($t.Extract) { (Test-Path $dest) -and @(Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0 }
                   else { Test-Path $dest }
        if ($already -and ($t.KeepExisting -or -not $Force)) {
            Say 'SKIP' "$($t.Name) already staged ($($t.Dest)) - use -Force to refresh" DarkGray
            # keep its previous manifest rows
            foreach ($r in ($old | Where-Object Tool -eq $t.Name)) { [void]$records.Add($r) }
            continue
        }
        try {
            $url = $t.Url
            if ($t.Kind -eq 'github') {
                $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers $ghHeaders -UseBasicParsing
                $asset = $rel.assets | Where-Object { $_.name -match $t.AssetRegex } | Select-Object -First 1
                if (-not $asset) { throw "no release asset matching $($t.AssetRegex) in $($t.Repo) $($rel.tag_name)" }
                $url = $asset.browser_download_url
            } elseif ($t.Kind -eq 'github-tarball') {
                $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers $ghHeaders -UseBasicParsing
                $url = $rel.tarball_url
            }
            $file = Join-Path $tmp ([IO.Path]::GetFileName(($url -split '\?')[0]))
            if (-not [IO.Path]::GetExtension($file)) { $file += $(if ($t.Kind -eq 'github-tarball') { '.tar.gz' } else { '' }) }
            Say 'GET' "$($t.Name)  <- $url" White
            Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -Headers @{ 'User-Agent' = 'ccdc-toolkit-stager' }
            if (-not (Test-Path $file)) { throw 'download vanished right after it finished (antivirus quarantine?)' }

            # Unpack into the temp folder first so signatures are checked BEFORE anything reaches tools\.
            $unpacked = $file
            if ($t.Extract) {
                $unpacked = Join-Path $tmp ("x_" + $t.Name)
                Expand-Archive -LiteralPath $file -DestinationPath $unpacked -Force
            }
            if ($t.Signer -and $onWindows) {
                foreach ($exe in @(Get-ChildItem $unpacked -Recurse -File -Filter *.exe)) {
                    $sig = Get-AuthenticodeSignature -FilePath $exe.FullName
                    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch $t.Signer) {
                        throw "$($exe.Name): signature '$($sig.Status)' / '$($sig.SignerCertificate.Subject)' is not a valid $($t.Signer) signature - NOT staging it"
                    }
                }
            } elseif ($t.Signer) { Say 'NOTE' "$($t.Name): signature not checked (not on Windows) - run -Verify on Windows before use" Yellow }

            if ($t.Extract) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                $placed = @()
                foreach ($f in @(Get-ChildItem $unpacked -Recurse -File)) {
                    $target = Join-Path $dest $f.FullName.Substring($unpacked.Length).TrimStart('\', '/')
                    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
                    Copy-Item -LiteralPath $f.FullName -Destination $target -Force
                    if (Test-Path -LiteralPath $target) { $placed += Get-Item -LiteralPath $target }
                }
            } else {
                New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
                Move-Item -LiteralPath $file -Destination $dest -Force
                $placed = @(Get-Item -LiteralPath $dest -ErrorAction SilentlyContinue)
            }
            if (-not $placed) { throw 'files vanished after staging (antivirus quarantine?)' }

            foreach ($p in $placed) { [void]$records.Add((Get-FileRecord $p.FullName $t.Name $url)) }
            Say 'OK' ("{0}  {1} file(s) -> {2}" -f $t.Name, $placed.Count, $t.Dest) Green
        } catch {
            $failed += $t.Name
            Say 'FAIL' "$($t.Name): $($_.Exception.Message)" Red
            foreach ($r in ($old | Where-Object Tool -eq $t.Name)) { [void]$records.Add($r) }   # keep previous good copy's rows
        }
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# Rows for tools not touched this run are kept as they were.
$touched = @($todo | ForEach-Object Name)
foreach ($r in ($old | Where-Object { $touched -notcontains $_.Tool })) { [void]$records.Add($r) }
$records | Sort-Object Tool, File | Export-Csv -Path $manifest -NoTypeInformation
Write-Host ""
Say 'MANIFEST' "$manifest ($($records.Count) files). Copy it WITH the tools; verify on the box with -Verify." Cyan
if ($failed) { Say 'FAILED' ($failed -join ', ') Red; exit 1 }
