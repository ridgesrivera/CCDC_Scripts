# tools/

Nothing in this toolkit downloads anything at runtime (competition networks are offline or hostile).
Third-party binaries are **staged here by hand before the competition** and are **not committed** (see `.gitignore`).

## Verify every download
1. Download on a trusted machine from the official URL below.
2. Check the publisher signature and the hash:
   ```powershell
   Get-AuthenticodeSignature .\Sysmon64.exe      # Status must be Valid, signer Microsoft
   Get-FileHash .\Sysmon64.exe -Algorithm SHA256  # compare with the value you recorded / the vendor page
   ```
3. Record the SHA256 in the table below (commit that) so teammates can verify the copy on the USB stick.

| Tool | Put it here | Official source | Used by | SHA256 (fill in when staged) |
|------|-------------|-----------------|---------|------------------------------|
| Sysmon | `tools\sysmon\Sysmon64.exe` | https://learn.microsoft.com/sysinternals/downloads/sysmon | `logging\Setup-Logging.ps1` | |
| Sysmon config | `tools\sysmon\sysmonconfig.xml` | e.g. SwiftOnSecurity sysmon-config or Olaf Hartong sysmon-modular (GitHub). Review before use | `logging\Setup-Logging.ps1` | |
| Winlogbeat (zip) | `tools\winlogbeat\` (extracted) | https://www.elastic.co/downloads/beats/winlogbeat (OSS / matching Graylog-supported version) | `logging\Setup-Logging.ps1` | |
| NXLog CE (msi) | install, or keep the msi in `tools\nxlog\` | https://nxlog.co/products/nxlog-community-edition/download | `logging\Setup-Logging.ps1` | |
| Autoruns | `tools\bin\Autoruns64.exe` | https://learn.microsoft.com/sysinternals/downloads/autoruns | manual persistence review | |
| PSScriptAnalyzer | dev machine only | `Install-Module PSScriptAnalyzer -Scope CurrentUser` | `tools\lint\Test-PsSyntax.ps1` | n/a |

`Setup-Logging.ps1` refuses to install Sysmon if the binary's Authenticode signature isn't `Valid`.

## lint/
Developer checks (not for competition boxes):
```powershell
pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows
```
Parses every script, flags PowerShell 7-only syntax that breaks on Windows PowerShell 5.1, and runs PSScriptAnalyzer
with `PSScriptAnalyzerSettings.psd1` if it's installed.
