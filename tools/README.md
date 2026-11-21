# tools/

Third-party tools are **staged here before the competition** and are **not committed** (see `.gitignore`).
The toolkit scripts never download anything themselves. `Get-CcdcTools.ps1` does the downloading, run on purpose.

## Stage everything (trusted machine, before the event)
```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Get-CcdcTools.ps1                  # defensive tools
powershell -ExecutionPolicy Bypass -File .\tools\Get-CcdcTools.ps1 -IncludeLinux    # + pspy, lynis for the Linux boxes
powershell -ExecutionPolicy Bypass -File .\tools\Get-CcdcTools.ps1 -IncludeOffensive  # + winPEAS (read the section below first)
```
It downloads from the official source, checks the Microsoft signature on Sysinternals and Sysmon before anything reaches `tools\`, and writes
`tools\staged-tools.csv` (a SHA256 for every file). It works on Windows PowerShell 5.1 and on PowerShell 7 (Linux/macOS too; signature checks then wait for `-Verify` on Windows).

## On the competition box (no internet needed)
```powershell
.\tools\Get-CcdcTools.ps1 -Verify      # every file re-hashed against the manifest; MISSING / MODIFIED = don't run it
```
Then run what you need by hand, e.g. `bin\pingcastle\PingCastle.exe --healthcheck` on the DC, `bin\sysinternals\autorunsc64.exe -a * -s -m -accepteula`. The panel does not wrap them (keeps the toolkit small).

## What gets staged, and why
| Tool | Lands in | What it gives you | Used by |
|------|----------|-------------------|---------|
| **Sysinternals Suite** | `bin\sysinternals\` | `autorunsc` (every autostart location, with signatures), `sigcheck` (unsigned binaries), `accesschk` (weak service/file ACLs), `procexp`/`tcpview` (live GUI triage), `tcpvcon`, `handle`, `strings` | by hand |
| **Sysmon** + SwiftOnSecurity config | `sysmon\` | process/network/file telemetry (event IDs 1, 3, 11...) | `logging\Setup-Logging.ps1` |
| **PingCastle** | `bin\pingcastle\` | AD health check: a scored report of every AD weakness (old krbtgt, delegation, ACL paths, GPO issues). Run it on trex | by hand |
| **Locksmith** | `bin\locksmith\` | AD Certificate Services misconfigs (ESC1-ESC16). Mode 0 = report only | by hand |
| **Hayabusa** | `bin\hayabusa\` | Thousands of Sigma rules over the event logs: shows you what Red Team already *did* (mimikatz, PsExec, new services, log clearing...) | by hand |
| winPEAS *(opt-in)* | `bin\peass\` | Attacker-style privesc enumeration | by hand |
| pspy, Lynis *(opt-in, Linux)* | `linux\` | pspy: watch processes/cron jobs live without root. Lynis: Linux hardening audit | copy to the Linux boxes |
| linPEAS *(opt-in, Linux + offensive)* | `linux\` | Attacker-style privesc enumeration for Linux | by hand |

Not scripted (versions must match the Graylog server, so pick them by hand): **Winlogbeat** → `tools\winlogbeat\` (extracted), **NXLog CE** → install, or put the msi in `tools\nxlog\`. Both are used by `Setup-Logging.ps1`.

## Is winPEAS a good idea?
**It's useful, with caveats, so it's opt-in.** winPEAS lists what an attacker would use to get from a normal user to SYSTEM: weak service permissions,
unquoted service paths, AlwaysInstallElevated, writable autoruns, stored credentials. Finding those first is exactly the blue team's job.

But on a competition box:
- **Defender flags and quarantines it.** Don't add a Defender exclusion to make it run. That opens a hole, and `Audit-Persistence` would rightly flag your own exclusion RED.
- **Its output can contain real credentials** (autologon passwords, saved creds, unattend files). A copy left on disk is a gift to Red Team and
  could count as "recovered passwords" against you. `[T]` saves it only to the admin-only report folder; delete it when done.
- **It's built for attacking, not for spotting changes.** Most of what it finds is already covered blue-team-style:
  `[T]` AccessChk (service ACLs), `[T]` Autoruns, `[3]` Audit-Persistence (unquoted paths, Run keys, tasks), `[5]` Audit-Vulns (AlwaysInstallElevated, UAC, WDigest).
- **Read your competition's rules.** Some events restrict offensive tooling on blue team boxes, and some require any code you bring to be publicly available. Check the team packet.

Rule of thumb: run the defensive tools on every box. Run winPEAS once per box, early, only if Defender is off or already flagging other things, and treat its output like a password list.

## Verify a download by hand
```powershell
Get-AuthenticodeSignature .\bin\sysinternals\autorunsc64.exe   # Status must be Valid, signer Microsoft
Get-FileHash .\bin\sysinternals\autorunsc64.exe -Algorithm SHA256
```

## lint/
Developer checks (not for competition boxes):
```powershell
pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows
```
Parses every script, flags PowerShell 7-only syntax that breaks on Windows PowerShell 5.1, and runs PSScriptAnalyzer
with `PSScriptAnalyzerSettings.psd1` if it's installed.
