# CCDC Blue Team Toolkit: Windows

One panel for defending a Windows box during CCDC. It is built to be quick on a box under pressure:
see who is on it, find attacks and know what to do about them, kick and block, harden step by step,
and undo anything that breaks. Every script opens with a header that says what it does, what it reads,
what it changes, how to undo it, and the manual commands it automates, so newer members can learn from it.

> Scope: **Windows**. Linux is planned.

---

## 1. Get it onto a box

| Situation | Do this |
|---|---|
| **Box has internet** | Admin PowerShell: `irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 \| iex`. Installs to `C:\ccdc\toolkit`, locks the folder to admins, opens the panel. |
| **No internet** | Copy this folder over (RDP drive, share, USB) and **double-click `CCDC-Toolkit.bat`**. It asks for admin, unblocks the files and opens the panel. |
| **Only want alerts, fast** | Open `windows\alerts\bt-deploy-PASTE.txt`, copy all, paste into an Admin PowerShell. |

| Windows | Works |
|---|---|
| Server 2016 / 2019 / 2022 / 2025, Windows 10 / 11 | Everything |
| Server 2012 / 2012 R2, Windows 8.1 | Everything (alerts need 2012 R2+) |
| Server 2008 R2, Windows 7 with WMF 3.0+ | Designed to work, not yet tested: audits, snapshots, hardening. No live alerts |
| PowerShell 2 only | The launcher says so and points to the manual commands |

## 2. The panel

```
  START  [0] First 15 minutes (guided, zero)

  MONITOR   keep LIVE ALERTS open in its own window
   [D]  LIVE ALERTS                   [N]  Who is on this box

  RED TEAM RESPONSE   something is happening
   [E]  Find attacks (what to do)     [X]  Kick user / block IP
   [R]  Remove persistence            [I]  Incident worksheet

  SNAPSHOT  what changed, and put it back
   [S]  Take snapshot                 [W]  What changed?
   [U]  Undo changes

  AUDIT     read-only, safe any time
   [1]  Box overview                  [2]  Users & admins
   [3]  Persistence hunt              [4]  Network exposure
   [5]  Vulns (CVE check)             [6]  AD + GPO (DC)
   [7]  PII / sensitive files         [8]  C2 beacon scan
   [A]  Run ALL quick audits (1-6) -> one report folder

  HARDEN    step by step, every change reversible
   [10] Rotate passwords              [11] Firewall (basic)
   [12] Hardening walkthrough         [13] IIS / PHP hardening
   [14] SQL Server hardening          [15] Reset krbtgt (DC)

  BACKUP & LOGGING
   [B]  Backup this box               [P]  Per-service backup
   [L]  Setup logging
```

The header above the menu shows the box's role and IPs, whether you're elevated, whether LIVE ALERTS are armed
(or were disabled), the newest alert, and the snapshots. Type `?` plus a key (`?12`) to explain any option.

## 3. Competition day

**`[0]` First 15 minutes** does only what belongs at the very start, asking before each step:

1. **Snapshot:** records how the box looks before anyone changes it (the ORIGINAL).
2. **Backup:** registry, tasks and firewall. On a DC it also backs up GPOs, DNS zones and AD objects. With IIS it also backs up the IIS config and web roots.
3. **LIVE ALERTS on:** keep the watch window open all day.
4. **Who is on this box:** every way in, and who is connected right now.
5. **Users & admins:** who has admin, and which accounts are risky.
6. **Vulnerability check:** what Red Team can walk straight into.

Then, by hand, in this order: `10` rotate admin passwords (scored accounts go through a Password Change Request
first), `X` kick unknown admins, `12` apply the SAFE hardening steps, `11` basic firewall.

**Something is happening?** Press `E`. It tells you which attack it is and what to do. `X` kicks and blocks.
**Something broke?** `W` → `1` shows what changed (and whether the toolkit did it), `U` puts it back.

Full checklist: [`docs/first-15-minutes-windows.md`](docs/first-15-minutes-windows.md). Event notes: [`docs/events/`](docs/events/).
Every Windows attack, how to spot it, how to stop it without breaking things: [`docs/Windows-Attacks-CCDC.pdf`](docs/Windows-Attacks-CCDC.pdf).

---

## What's in the box

### Monitor
| Key | Script | What it does |
|---|---|---|
| D | `alerts\bt-alerts.ps1` | **LIVE ALERTS.** Fires within ~1 s on RDP / untrusted network logons, password spraying, Kerberoasting, user / group / password changes, new services and tasks, log clearing, Defender changes, tampering with the alerts. Each alert: who, from which IP, how, what that IP did before, what to do. [`docs/live-alerts.md`](docs/live-alerts.md) |
| N | `alerts\whoshere.ps1` | **Every way in:** RDP, SSH, SMB / admin shares, WinRM, WMI, VNC, Telnet, FTP, web, SQL. Each one explained, whether it is ON, and who is connected right now from where. Plus PsExec-style services, web shells, logons, failed logons, odd ports, outbound connections |

### Red Team response
| Key | Script | What it does |
|---|---|---|
| E | `hunt\Find-Attacks.ps1` | **You don't need to know the attack.** Part 1: logon attempts on every service (Windows, Kerberos, NTLM, SSH, SQL Server, IIS, FTP) with a verdict per IP: brute force, spray, or logged in after failing. Part 2: Kerberoasting, AS-REP roasting, DCSync, pass-the-hash, new admin, new service / PsExec, new task, web shell / xp_cmdshell, credential dumping, log cleared, Defender tampering, Zerologon. Each finding: what it is, evidence, numbered steps |
| X | `hunt\Kick-Block.ps1` | Log a user off everywhere (RDP, SMB, WinRM, SSH) + disable the account, and/or block an IP in + out (closes its SMB sessions, shows who logged on from it). Refuses to block this box, warns before blocking a trusted IP or a live RDP session. Undo: unblock / re-enable |
| R | `hunt\Remove-Persistence.ps1` | Numbered list of removable persistence; each pick is exported + hashed (creator, source IP), then disabled / quarantined, with an undo command |
| I | `hunt\New-IncidentReport.ps1` | Candidate attacker IPs, timeline, what was removed: the facts for an incident report |

### Snapshot
| Key | Script | What it does |
|---|---|---|
| S W U | `backup\Snapshot-State.ps1` | Take / Compare / Restore. Captures registry security settings, services, users, admin groups, shares, hosts file, Defender, firewall (+ full export), audit policy, local security policy. Compare marks each change **[toolkit: script time]** or **NOT BY THE TOOLKIT**. Restore is per item, confirmed, backed up, and itself undoable. The panel takes the ORIGINAL automatically and a snapshot before every change |
| W → 3-5 | `hunt\Watch-Changes.ps1` | Attacker footprints since a baseline: new users, group members, tasks, services, Run keys, listeners, SSH keys, web files, GPOs |

### Audit (read-only)
| Key | Script | What it does |
|---|---|---|
| 1 | `recon\Get-BoxOverview.ps1` | OS, role, IPs, listeners → process, roles, services, patches |
| 2 | `audit\Audit-Users.ps1` | Admin groups (one line each), and risks grouped by type: Kerberoastable, AS-REP roastable, no password required, password in description, accounts created after setup |
| 3 | `audit\Audit-Persistence.ps1` | Tasks, services, Run keys, WMI, Winlogon, IFEO / sticky keys, SSH keys, Defender exclusions, web shells, LSA packages, hidden tasks, ServiceDll hijacks |
| 4 | `audit\Audit-Network.ps1` | Connections + process, firewall profiles, any/any rules, SMBv1 / signing, shares + ACLs, RDP NLA, WinRM |
| 5 | `audit\Audit-Vulns.ps1` | Zerologon, PrintNightmare, EternalBlue, SMBGhost, BlueKeep, SIGRed, noPac, PetitPotam / ESC8, Certifried, MS14-068, HiveNightmare, Follina, ProxyShell, CVE-2024-38063, LDAPNightmare, CVE-2025-33073, relay, NTLMv1, poisoning, WDigest, LSA protection, anonymous / Guest, Defender, patch age, AD CS ESC1. **NOW vs ORIGINAL**: what you fixed, what regressed |
| 6 | `audit\Audit-AD-GPO.ps1` | DC: GPO changes, SYSVOL, GPP cpassword, root ACL, DCSync holders, AdminSDHolder, delegation, krbtgt age |
| 7 | `audit\Audit-SensitiveFiles.ps1`, `alerts\pii-hunt.ps1` | SSNs, card numbers, keys, passwords in files and SQL Server; files readable by everyone. Never prints the values |
| 8 | `hunt\Find-Beacons.ps1` | Watches outbound connections for a minute: implants calling home (C2 ports, powershell / rundll32 talking out, programs in Temp / AppData, beacon rhythm, failed callbacks, unsigned programs), C2 named pipes, DNS tunnelling |

### Harden (step by step, reversible)
| Key | Script | What it does |
|---|---|---|
| 10 | `harden\Rotate-Passwords.ps1` | Random passwords, shown once, never saved; scored accounts excluded |
| 11 | `harden\Set-Firewall.ps1` | **Basic firewall:** keeps everything that is listening open, blocks other inbound, leaves outbound alone, logs drops. Safety timer reverts it if you get cut off. One-key revert any time |
| 12 | `harden\Harden-Walkthrough.ps1` | **Hardening walkthrough:** each change shown with what it stops and its risk (SAFE / CAUTION / DANGER, with evidence from this box). Apply or skip. On a DC registry settings go into one GPO "CCDC Hardening". Undo one step or all |
| 13 | `harden\Harden-IIS-PHP.ps1` | Back up IIS / web roots, WP `DISALLOW_FILE_EDIT`, config ACLs, WP admins / plugins |
| 14 | `harden\Harden-MSSQL.ps1` | sa, sysadmins, weak SQL logins; turn off xp_cmdshell and friends |
| 15 | `harden\Reset-Krbtgt.ps1` | DC, after a domain compromise: one krbtgt reset per run, enforced wait before the second |
| (12) | `harden\Harden-AD.ps1` | Account flags (AS-REP, password not required, reversible encryption); run by the walkthrough |

### Backup & logging
| Key | Script | What it does |
|---|---|---|
| B | `backup\Backup-Box.ps1` | Registry, tasks, firewall, users; DC: GPOs, DNS, AD objects (LDIF); IIS: appcmd backup + applicationHost.config + web roots |
| P | `services\*.ps1` | Per service (AD, DNS, DHCP, IIS, SQL, MySQL, SMB, FTP, RDP, WinRM, SSH, VNC, SNMP, OpenVPN, NFS, mail...): detect, back up, verify, restore one |
| L | `logging\Setup-Logging.ps1` | Audit policy, log sizes, PowerShell logging, Sysmon (if staged), forward to Graylog / syslog |

`C:\ccdc\snapshots` snapshots · `C:\ccdc\reports` reports · `C:\ccdc\logs` action logs with undo commands ·
`C:\ccdc\backups` backups · `C:\ccdc\firewall` saved firewalls · `C:\ccdc\evidence`, `C:\ccdc\quarantine` removed items · `C:\bt` live alerts

---

## Rules every script follows
1. **Generic.** No hard-coded IPs, hostnames, domains or accounts.
2. **Explainable.** Header: purpose, reads, changes, undo, manual equivalent.
3. **Audit and change are separate.** Changing scripts support `-WhatIf` and ask y/N per action.
4. **Reversible.** Anything that could break a service records what it replaced and has an undo. Snapshots before changes.
5. **Never write passwords to disk.** Shown once, set through ADSI, never on a command line, no transcripts.
6. **Never touch scored services or accounts automatically.** Nothing auto-blocks IPs.
7. **Compatible:** Windows PowerShell 3+ (5.1 recommended), no external modules, any display language, GUI or Server Core.

## Before the event
- Practise on a VM: open the panel, press `0`, run the alerts self-test (`D` → `8`), apply one step in `12`, then try `W` → `1` and `U`, and `12` → `3`.
- Optional third-party tools (Sysmon for `L`, PingCastle, Sysinternals): stage with `tools\Get-CcdcTools.ps1`. See [`tools/README.md`](tools/README.md).

## Folder map
```
CCDC-Toolkit.bat   install.ps1
windows/
  Launch-Toolkit.ps1        the panel
  lib/                      CCDC-Common.ps1 (shared helpers), Compat.ps1 (older Windows)
  alerts/                   LIVE ALERTS bundle (standalone, installs to C:\bt) + whoshere
  recon/ audit/             read-only
  hunt/                     Find-Attacks, Find-Beacons, Kick-Block, Remove-Persistence, Watch-Changes, New-IncidentReport
  harden/                   Set-Firewall, Harden-Walkthrough, Harden-AD, Rotate-Passwords, Harden-IIS-PHP, Harden-MSSQL, Reset-Krbtgt
  backup/ logging/ services/
config/  docs/  tools/
```

## Maintaining
- Lint: `pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows`.
- After editing anything in `windows/alerts/`, rebuild the paste: `python3 tools/build-alert-paste.py`.
- Notes for AI assistants and contributors: [`CLAUDE.md`](CLAUDE.md).
