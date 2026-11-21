# CCDC Blue Team Toolkit: Windows

One panel for defending a Windows box during CCDC: **live alerts**, scored-service checks, audits,
hardening, incident response and backups. It's built to be used under time pressure and to be read
by newer club members. Every script opens with a header that says what it does, what it reads, what
it changes, how to undo it, and the manual commands it automates.

> Scope: **Windows** (Server 2012 R2 and newer, Windows PowerShell 5.1, no modules, no internet at runtime).
> Linux is planned. The original v1 scripts are unchanged in [`legacy/`](legacy/README.md).

---

## 1. Get it onto a box

Pick whichever works on the box in front of you.

| Situation | Do this |
|---|---|
| **Box has internet** | Admin PowerShell: `irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 \| iex`. Installs to `C:\ccdc\toolkit`, locks the folder to admins, opens the panel. |
| **No internet** | Copy this folder over (RDP drive, share, USB) and **double-click `CCDC-Toolkit.bat`**. It asks for admin, unblocks the files and opens the panel. |
| **Only want alerts, fast** | Open `windows\alerts\bt-deploy-PASTE.txt`, copy all, paste into an Admin PowerShell. |

## 2. The panel

```
==============================================================================
  CCDC BLUE TEAM TOOLKIT v3.0                                           10:04
==============================================================================
  HOST    WEB01  Windows Server 2022 Standard  |  Member server
  IP      10.0.0.10
  RIGHTS  Administrator
  ALERTS  14 detections armed, watch window open
  LAST    10:02:11 NEW USER svc_backup by Administrator from 10.0.0.66 ...
------------------------------------------------------------------------------
  START  [0] First 15 minutes (guided)  overview, backup, alerts, audits, baselines

  MONITOR   keep these running in their own windows
   [D]  LIVE ALERTS                   [C]  Scored services
   [W]  Change watch                  [N]  Who is on this box

  AUDIT     read-only, safe any time
   [1]  Box overview                  [2]  Users & admins
   [3]  Persistence hunt              [4]  Network exposure
   [5]  Vulnerability check           [6]  AD + GPO (DC)
   [P]  Security policy               [F]  PII / sensitive files
   [X]  Software audit                [T]  Vendor tool audits
   [A]  Run ALL quick audits (1-6 + P) -> one report folder

  HARDEN    dry run first, you confirm each change
   [7]  Rotate passwords              [8]  Disable accounts
   [9]  Firewall allowlist            [10] Baseline hardening
   [11] IIS / PHP hardening           [12] AD account hardening
   [13] SQL Server hardening          [K]  Reset krbtgt

  RESPOND   an alert fired, now what
   [R]  Remove persistence            [O]  Log off sessions
   [E]  Event-log sweep               [I]  Incident worksheet

  BACKUP & LOGGING
   [B]  Backup this box               [S]  Per-service backup
   [L]  Setup logging

  [H] full help for a script   [?7] explain an option   [Q] quit
```

- The **header is a status board**. It shows the box's role and IPs, whether you're elevated, whether LIVE ALERTS are armed (and whether someone disabled them), and the newest alert.
- **Read-only** options run immediately and offer to save a report to `C:\ccdc\reports\`.
- **Changing** options always offer a `-WhatIf` dry run first and then confirm every action.
- **Monitors** (alerts watch, service loop, change loop) open in **their own window**, so the panel stays free.
- Not sure what an option does? Type `?` and the key (`?9`), or use `H` for the script's full header.

## 3. Competition day

1. On each Windows box: open the panel and press **`0`**. The guided run asks before each step: overview, backup, **LIVE ALERTS on**, users audit, persistence hunt, who's-here baseline, change baseline, scored-service baseline.
2. Keep the **BT ALERTS** window open on every box. When the scoring engine's IP shows up in an alert, trust it: `D` then `3`.
3. Then decide on: `7` rotate passwords (scored accounts go through a **Password Change Request** in the scoring portal first), `O` kick old sessions, `9` firewall, `10` baseline hardening, `L` logging.
4. When an alert fires: `D` then `5` (story of that IP), `R` remove persistence (evidence is kept), `I` incident worksheet, then file the incident report.

Full checklist: [`docs/first-15-minutes-windows.md`](docs/first-15-minutes-windows.md). Event-specific notes, such as the current team packet, go in [`docs/events/`](docs/events/).

---

## What's in the box

### Monitor
| Key | Script | What it does |
|---|---|---|
| D | `alerts\bt-alerts.ps1` | **LIVE ALERTS.** Event-triggered tasks fire within ~1 s on: RDP/untrusted network logon, spraying, Kerberoasting, user/group/password changes, new services and tasks, log clearing, Defender changes, tampering with the alerts. Each alert shows who, source IP/PC, logon type, a plain-English HOW, the attack CHAIN for that IP and role-correct DO NOW commands. `-Trust`, `-Block`, `-Chain <ip>`, `-Snooze`, `-Backfill`, self-test. Full doc: [`docs/live-alerts.md`](docs/live-alerts.md) |
| C | `hunt\Test-ScoredServices.ps1` | For every scored port: listening? right address? start mode? TCP connect? firewall allow/BLOCK? Then HTTP title/defacement/DB errors, DNS records vs baseline, LDAP, shares, RDP, sshd, scored-account lockout, hosts-file/portproxy/IPsec/clock/disk sabotage. `-Loop` checks every 60 s |
| W | `hunt\Watch-Changes.ps1` | Baselines users, groups, tasks, services, ports, Run keys, WMI, shares, firewall rules, Defender exclusions, hosts file, SSH keys, IFEO/Winlogon/LSA, software, web files (and on a DC: GPOs, SPNs, trusts), then diffs. Loop or scheduled task |
| N | `alerts\whoshere.ps1` | One screen: sessions, SMB, WinRM, logons, remote connections, odd ports, diff vs baseline |

### Audit (read-only)
| Key | Script | What it does |
|---|---|---|
| 1 | `recon\Get-BoxOverview.ps1` | OS/build, domain role, IPs, listeners → process, roles, services, hotfixes, likely scored services |
| 2 | `audit\Audit-Users.ps1` | Privileged groups, pw-never-expires, new accounts, SPNs, AS-REP roastable, passwords in descriptions, adminCount |
| 3 | `audit\Audit-Persistence.ps1` | Tasks, services, Run keys, startup, WMI, Winlogon, IFEO/sticky keys, AppInit, SSH keys, Defender exclusions, web shells, LSA packages, netsh helpers, hidden tasks, ServiceDll hijacks, PS profiles |
| 4 | `audit\Audit-Network.ps1` | Connections + process, firewall profiles, any/any rules, SMBv1, SMB signing, shares + ACLs, RDP NLA, WinRM |
| 5 | `audit\Audit-Vulns.ps1` | Zerologon, PrintNightmare, MS17-010, NoPAC, SMBGhost, LLMNR/NBT-NS, NTLMv1, Guest, WDigest, LSA protection, LAPS, AD CS ESC1, Defender |
| 6 | `audit\Audit-AD-GPO.ps1` | DC: GPO changes, SYSVOL, GPP cpassword, root ACL, DCSync holders, AdminSDHolder, delegation, krbtgt age |
| P | `audit\Audit-SecurityPolicy.ps1` | ~55 GPO/AD/DNS settings with SAFE / CAUTION / LEAVE, GPO path, check + fix commands ([reference](docs/security-policy-reference.md)) |
| F | `audit\Audit-SensitiveFiles.ps1`, `alerts\pii-hunt.ps1` | SSNs, Luhn-valid cards, keys, passwords in files; files readable by Everyone or under web roots/shares; SQL Server PII columns. Never prints the values |
| X | `audit\Audit-Software.ps1` | Remote-access tools, attack tools, junk, outdated software → inventory CSV for inject answers |
| T | `audit\Invoke-AuditTools.ps1` | Runs staged Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith (winPEAS opt-in) and turns output into findings |

### Harden (dry run + confirm)
| Key | Script | What it does |
|---|---|---|
| 7 | `harden\Rotate-Passwords.ps1` | Random passwords, shown once, never saved; scored accounts excluded |
| 8 | `harden\Disable-Accounts.ps1` | Disable (not delete) accounts, rollback script |
| 9 | `harden\Set-Firewall.ps1` | All profiles on, default-deny inbound, scored ports open to any source, keeps your session, auto-rollback task |
| 10 | `harden\Harden-Baseline.ps1` | SMBv1, SMB signing, LLMNR/NBT-NS, WDigest, LSA protection, spooler on DC, audit policy, script block logging, Defender, IFEO, RDP NLA, Guest, MachineAccountQuota (each skippable) |
| 11 | `harden\Harden-IIS-PHP.ps1` | Back up IIS/web roots, WP `DISALLOW_FILE_EDIT`, config ACLs, WP admins/plugins, php.ini checks |
| 12 | `harden\Harden-AD.ps1` | DC: clear no-preauth, reversible encryption, password-not-required, DES-only (with rollback); report roastable / unconstrained delegation |
| 13 | `harden\Harden-MSSQL.ps1` | sa, sysadmins, weak SQL logins, linked servers; turn off xp_cmdshell, Ole Automation, ad hoc queries, CLR, remote DAC |
| K | `harden\Reset-Krbtgt.ps1` | DC: one krbtgt reset per run, replication check, enforced wait before the second |

### Respond
| Key | Script | What it does |
|---|---|---|
| R | `hunt\Remove-Persistence.ps1` | Numbered list of removable persistence; each pick is exported + hashed with creator and source IP, then disabled / quarantined, with an undo command |
| O | `harden\Disconnect-Sessions.ps1` | List, then log off RDP/console, SMB, WinRM, SSH sessions of named users (or everyone but you) |
| E | `hunt\Watch-Events.ps1` | Look back N minutes through the event logs: account/group changes, tasks, services, logons, spraying, tampering, web server spawning a shell, DCSync, Zerologon, roasting, GPO edits. Each with source IP |
| I | `hunt\New-IncidentReport.ps1` | Ranks candidate attacker IPs and writes a facts-only worksheet: timeline, removals with hashes, live sessions, IIS requests |

### Backup & logging
| Key | Script | What it does |
|---|---|---|
| B | `backup\Backup-Box.ps1` | Registry, tasks, firewall, users; DC: GPOs, DNS, LDIF (ntds.dit IFM only with `-IncludeAdIfm`); IIS config + web roots |
| S | `services\Invoke-AllServices.ps1` | Detects each installed service (AD, DNS, DHCP, IIS, SQL, MySQL, SMB, FTP, RDP, WinRM, SSH, VNC, SNMP, OpenVPN, NFS, mail...) and backs up / documents / verifies it. Restore: `services\<Service>.ps1 -Action Restore` |
| L | `logging\Setup-Logging.ps1` | Audit policy, log sizes, PowerShell logging, Sysmon (if staged), Winlogbeat/NXLog to Graylog/syslog |

### Where things land
`C:\ccdc\reports\` reports · `C:\ccdc\logs\` action logs with undo commands · `C:\ccdc\backups\` backups ·
`C:\ccdc\evidence\` + `C:\ccdc\quarantine\` what was removed · `C:\bt\` live alerts (`alerts.log`, `alerts-full.log`)

---

## Rules every script follows
1. **Generic.** No hard-coded IPs, hostnames, domains or accounts. Box facts go in an optional config or in docs, never in code.
2. **Explainable.** Header: purpose, reads, changes, undo, manual equivalent.
3. **Audit and change are separate.** `recon/` and `audit/` are read-only. Changing scripts support `-WhatIf` and ask y/N per action unless `-Force`.
4. **Never write passwords to disk.** Shown once, set through ADSI, never on a command line, no transcripts.
5. **Never touch scored services or accounts automatically.** Scored-account changes go through the Password Change Request process. Nothing auto-blocks IPs.
6. **Log everything** (actions, not secrets) to `C:\ccdc\logs\` with undo commands. **Back up before changing** to `C:\ccdc\backups\<timestamp>\`.
7. **Compatible:** Windows PowerShell 5.1 (alerts: 4.0+), no external modules, any display language, GUI or Server Core.
8. **Scannable output:** RED = likely malicious, YELLOW = review, GREEN = ok.

## Optional config
Everything works with no config. To pre-fill scored ports, scored accounts and admin sources, run
`copy config\example.great-cretaceous.json config\ccdc.json` and edit it from the team packet (`config/ccdc.json` is gitignored, and it never holds passwords).

## Before the event
- Stage third-party tools on a trusted machine: `tools\Get-CcdcTools.ps1` (Sysinternals, Sysmon, PingCastle, Locksmith, Hayabusa). Verify on a box with `-Verify`. See [`tools/README.md`](tools/README.md).
- Practise the panel on a VM, and run the alerts self-test (`D` then `8`).

## Folder map
```
CCDC-Toolkit.bat            double-click: opens the panel (asks for admin)
install.ps1                 one-line download + install
windows/
  Launch-Toolkit.ps1        the panel
  lib/CCDC-Common.ps1       shared helpers: findings, logging, -WhatIf, backups, config, event parsing
  alerts/                   LIVE ALERTS bundle (standalone, installs to C:\bt, one-paste deploy)
  recon/ audit/             read-only
  harden/                   changes state (-WhatIf, confirm, backups)
  hunt/                     monitors and incident response
  backup/ logging/ services/
config/  docs/  tools/  legacy/
```

## Maintaining
- Lint: `pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows` (parse + PS 5.1 compatibility + PSScriptAnalyzer when installed).
- After editing anything in `windows/alerts/`, rebuild the paste with `python3 tools/build-alert-paste.py`.
- Notes for AI assistants and new contributors: [`CLAUDE.md`](CLAUDE.md).
