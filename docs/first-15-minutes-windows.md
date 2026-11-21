# First 15 Minutes: Windows

One page, in priority order. Open the panel first:
**right-click `windows\Launch-Toolkit.bat` → Run as administrator.**

> Golden rule: **a broken scored service costs more than a slightly insecure one.**
> Before every change, ask: "Could this stop the scoring engine from logging in or connecting?"

| # | Min | Do this | Panel / script | Manual fallback |
|---|-----|---------|----------------|-----------------|
| 0 | 0-1 | Know the box: role, IPs, what's listening, what's scored | `[1]` `recon\Get-BoxOverview.ps1` | `hostname`, `ipconfig`, `netstat -ano \| findstr LISTEN` |
| 1 | 1-4 | **Rotate admin creds** (Administrator, Domain Admins). Exclude scored accounts. Write new passwords on paper | `[7]` `harden\Rotate-Passwords.ps1 -Group "Domain Admins"` (DC) / `-Scope Local -Users Administrator` | `net user Administrator *` / `Set-ADAccountPassword <u> -Reset` |
| 1b | 4-5 | **Turn on live alerts** so you see Red Team the moment they act. Read the backfill's PRIVILEGED GROUP CHANGES first. `-Trust` the scorer IP when it shows up | `[D]` → `[1]`, or paste `windows\alerts\bt-deploy-PASTE.txt` ([how it works](live-alerts.md)) | Event Viewer → Security, filter 4624 / 4720 / 4728 / 4732 |
| 2 | 4-6 | **Audit admins, disable rogue ones** | `[2]` `audit\Audit-Users.ps1` → `[8]` `harden\Disable-Accounts.ps1 -Users x,y` | `net localgroup administrators`, `net group "Domain Admins" /domain`, `net user x /active:no` |
| 3 | 6-8 | **Back up** before you (or Red Team) break something | `[B]` `backup\Backup-Box.ps1` | `reg export`, `Backup-GPO -All`, `appcmd add backup` |
| 4 | 8-9 | **Confirm scored services are UP** (check the scoreboard too) | `[1]` again (the "Likely scored services" section) | browse the site, `Test-NetConnection <ip> -Port <p>` |
| 5 | 9-13 | **Persistence hunt**: tasks, services, Run keys, WMI, sticky keys, SSH keys, web shells | `[3]` `audit\Audit-Persistence.ps1`, then `[10]` `-Only RemoveIfeoDebuggers` | `schtasks /query /fo LIST /v`, `reg query ...\Run` |
| 6 | 13-15 | **Firewall**: default-deny inbound, allow scored ports, keep your session | `[9]` `harden\Set-Firewall.ps1` (dry run first, test a NEW connection before typing YES) | `netsh advfirewall set allprofiles state on` |
| + | 15+ | **Security policy scan**: what to turn on in GPO without breaking scoring (do every SAFE item; read Breaks for CAUTION) | `[P]` `audit\Audit-SecurityPolicy.ps1` | [`security-policy-reference.md`](security-policy-reference.md), `gpmc.msc` |
| + | 15+ | Hardening baseline, logging, then start the watch loop | `[10]` `Harden-Baseline.ps1`, `[L]` `Setup-Logging.ps1`, `[W]` `Watch-Changes.ps1` (baseline, then loop) | see each script's header |
| + | 20+ | Deep scan with the vendor tools (needs `tools\Get-CcdcTools.ps1 -Verify` first) | `[T]` `Invoke-AuditTools.ps1`: Autoruns, AccessChk, Hayabusa; PingCastle + Locksmith on the DC | `autorunsc64 -a * -s -m`, `PingCastle.exe --healthcheck` |

## Box-specific first moves (Great Cretaceous)
- **trex (DC)**: Rotate Domain Admins first. Do NOT rotate the Keycloak bind account without updating hellcreek. Run `[6]` AD + GPO.
- **fernbank (IIS)**: Run `[11]` Harden-IIS-PHP early. It backs up web roots and lists WP admins. DB lives on hatchery.
- **fossil (Win10)**: RDP + SSH are scored. Check `administrators_authorized_keys` (in `[3]`) before touching sshd.

## Don'ts
- Don't reboot a scored box mid-round without telling the captain.
- Don't delete accounts. Disable them (re-enable is instant if it was scored).
- Don't write passwords in a file, a chat, or a sticky note photo. Paper, handed to the captain.
- Don't run a script you can't explain. `[H]` in the panel shows any script's header.
