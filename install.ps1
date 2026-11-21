<#
.SYNOPSIS
    install.ps1 - download the CCDC Blue Team Toolkit onto this box and open the panel.

.DESCRIPTION
    PURPOSE
      One line in an Administrator PowerShell gets the whole toolkit:

        irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 | iex

      It downloads the repo as a zip, unpacks it to C:\ccdc\toolkit, unblocks
      the files, locks the folder to Administrators + SYSTEM (so a normal user
      cannot plant code in scripts you will run as admin), and opens the panel.
      Running it again updates in place; the old copy is kept as a backup.

    NO INTERNET ON THE BOX?
      Copy the repo folder over RDP / USB / a share instead and double-click
      CCDC-Toolkit.bat. Nothing in the toolkit needs the internet at runtime.

    WHAT IT READS    https://github.com/ridgesrivera/CCDC_Scripts (zip of one branch)
    WHAT IT CHANGES  creates C:\ccdc\toolkit (old copy moved to C:\ccdc\toolkit.old-<time>),
                     sets that folder's ACL to Administrators + SYSTEM only
    HOW TO UNDO      Remove-Item C:\ccdc\toolkit -Recurse -Force

    MANUAL EQUIVALENT
      Invoke-WebRequest https://github.com/ridgesrivera/CCDC_Scripts/archive/refs/heads/main.zip -OutFile $env:TEMP\t.zip
      Expand-Archive $env:TEMP\t.zip C:\ccdc ; Get-ChildItem C:\ccdc -Recurse | Unblock-File

.PARAMETER Branch
    Branch to download. Default main.

.PARAMETER Path
    Install folder. Default C:\ccdc\toolkit.

.PARAMETER NoLaunch
    Install only, do not open the panel.

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1))) -Branch main -NoLaunch
#>
[CmdletBinding()]
param(
    [string]$Branch = 'main',
    [string]$Path = 'C:\ccdc\toolkit',
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
$repo = 'ridgesrivera/CCDC_Scripts'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[!] Run this from an ADMINISTRATOR PowerShell (right-click > Run as administrator).' -ForegroundColor Red
    return
}

# Older servers default to TLS 1.0, which GitHub refuses.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$zip   = Join-Path $env:TEMP "ccdc_toolkit_$stamp.zip"
$tmp   = Join-Path $env:TEMP "ccdc_toolkit_$stamp"
$url   = "https://github.com/$repo/archive/refs/heads/$Branch.zip"

Write-Host "[*] Downloading $url" -ForegroundColor Cyan
$oldPref = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'   # the progress bar makes iwr 10x slower on 5.1
try { Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing }
catch { Write-Host "[!] Download failed: $_" -ForegroundColor Red; Write-Host '    No internet? Copy the folder over and run CCDC-Toolkit.bat.' -ForegroundColor Yellow; return }
finally { $ProgressPreference = $oldPref }

Write-Host '[*] Unpacking' -ForegroundColor Cyan
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
} else {
    # PowerShell 4 (Server 2012 R2) has no Expand-Archive.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
}
$inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
if (-not $inner -or -not (Test-Path (Join-Path $inner.FullName 'windows\Launch-Toolkit.ps1'))) {
    Write-Host '[!] The download does not look like the toolkit. Nothing changed.' -ForegroundColor Red; return
}

$parent = Split-Path $Path -Parent
New-Item -ItemType Directory -Path $parent -Force | Out-Null
if (Test-Path $Path) {
    $old = "$Path.old-$stamp"
    Move-Item $Path $old
    Write-Host "[*] Previous copy kept at $old" -ForegroundColor DarkGray
}
Move-Item $inner.FullName $Path
Get-ChildItem $Path -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
Remove-Item $zip, $tmp -Recurse -Force -ErrorAction SilentlyContinue

# Administrators (S-1-5-32-544) + SYSTEM (S-1-5-18) only. SIDs, so it works in any language.
$null = & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C /Q 2>&1

Write-Host "[+] Toolkit installed to $Path" -ForegroundColor Green
Write-Host "    Next time: double-click $Path\CCDC-Toolkit.bat" -ForegroundColor Gray
if (-not $NoLaunch) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Path 'windows\Launch-Toolkit.ps1')
}
