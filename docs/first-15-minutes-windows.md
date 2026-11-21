# First 15 Minutes: Windows

One page, in priority order. Open the panel first: **double-click `CCDC-Toolkit.bat`** (it asks for admin).
No copy on the box yet? Admin PowerShell: `irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 | iex`

> **The panel saves an ORIGINAL snapshot the first time it opens**: how the box was before anyone touched it.
> Every change you run from the panel takes another snapshot first. Broke something? **`W`** shows what changed
> (and whether the toolkit did it), **`U`** puts it back.

> **Short on time?** Press **`[0]`**. It walks through the safe steps below in order, asking before each one.
> Then come back here for the steps that need a decision (passwords, firewall, hardening).

> Golden rule: **a broken scored service costs more than a slightly insecure one.**
> Before every change, ask: "Could this stop the scoring engine from logging in or connecting?"

| # | Min | Do this | Panel | Manual fallback |
|---|-----|---------|-------|-----------------|
| 0 | 0-1 | Know the box: role, IPs, what's listening, what it runs | `[1]` | `hostname`, `ipconfig`, `netstat -ano \| findstr LISTEN` |
| 1 | 1-2 | **Turn on live alerts** so you see Red Team the moment they act. Read the backfill's PRIVILEGED GROUP CHANGES first | `[D]` → `[1]` (or paste `windows\alerts\bt-deploy-PASTE.txt`) | Event Viewer → Security, filter 4624 / 4720 / 4728 / 4732 |
| 2 | 2-4 | **Vulnerability check**: what can Red Team walk straight into (Zerologon, PrintNightmare, EternalBlue, relay, cleartext creds) | `[5]` | see the script header for the registry keys |
| 3 | 4-7 | **Rotate admin creds** (Administrator, Domain Admins). Exclude scored accounts. Write new passwords on paper. Then kick old sessions | `[10]`, then `[X]` | `net user Administrator *` |
| 4 | 7-8 | **Audit admins, disable rogue ones** | `[2]` → `[11]` | `net localgroup administrators`, `net user x /active:no` |
| 5 | 8-9 | **Back up** before you (or Red Team) break something | `[B]`, and `[K]` → `[2]` per service | `reg export`, `Backup-GPO -All`, `appcmd add backup` |
| 6 | 9-12 | **Persistence hunt**: tasks, services, Run keys, WMI, sticky keys, SSH keys, web shells. Remove what's bad (evidence is kept) | `[3]` → `[R]` | `schtasks /query /fo LIST /v`, `reg query ...\Run` |
| 7 | 12-15 | **Fix the vulns from step 2** that can't break scoring: SMBv1, WDigest, LLMNR/NBT-NS, spooler on a DC, Guest, NLA. Re-run `[5]`: the CHANGE column shows what you fixed | `[13]`, then `[5]` | each finding prints its fix command |
| 8 | 15 | **Firewall**: default-deny inbound, scored ports open to any source, keep your session | `[12]` (dry run first; test a NEW connection before typing YES) | `netsh advfirewall set allprofiles state on` |
| + | 15+ | **Save the scored-service baseline while the scoreboard is green**, then keep the loop running | `[C]` → `[3]`, then `[C]` → `[2]` | browse the site, `Test-NetConnection <ip> -Port <p>` |
| + | 15+ | **Find PII / card data / passwords in files** before Red Team does | `[8]` | `dir /s /b C:\*pass* C:\*.sql` |
| + | 15+ | **DC:** roastable / weak account flags, security policy. **SQL box:** sa, weak logins, xp_cmdshell | `[15]`, `[7]`, `[16]` | see each script's header |
| + | 15+ | Logging, then watch for changes | `[L]`, `[W]` → `[3]` (or `[4]` to loop) | Event Viewer |
| + | any | **Something broke after a change?** See exactly what changed and put it back | `[W]` → `[1]`, then `[U]` | `reg import`, `netsh advfirewall import` (backups in `C:\ccdc\backups`) |
| + | any | Keep the **BT ALERTS** window open on every box. Closed it? Reopen it. Need history? Sweep the logs | `[D]` → `[2]`, `[D]` → `[5]`, `[E]` | Event Viewer > Security |
| + | 20+ | Deep scan with the vendor tools (needs `tools\Get-CcdcTools.ps1 -Verify` first) | `[T]` | `autorunsc64 -a * -s -m`, `PingCastle.exe --healthcheck` |

## Box-specific first moves (practice lab: Great Cretaceous)
For the current event, see [`events/`](events/).
- **trex (DC)**: Rotate Domain Admins first. Do NOT rotate the Keycloak bind account without updating hellcreek. Run `[6]` AD + GPO.
- **fernbank (IIS)**: Run `[14]` Harden-IIS-PHP early. It backs up web roots and lists WP admins. DB lives on hatchery.
- **fossil (Win10)**: RDP + SSH are scored. Check `administrators_authorized_keys` (in `[3]`) before touching sshd.

## Don'ts
- Don't reboot a scored box mid-round without telling the captain.
- Don't delete accounts. Disable them (re-enable is instant if it was scored).
- Don't write passwords in a file, a chat, or a sticky note photo. Paper, handed to the captain.
- Don't run a script you can't explain. `?` plus the key (e.g. `?13`) or `[H]` in the panel explains any option.
