# CCDC Blue Team Toolkit: Windows

One panel for defending a Windows box during CCDC. **Audit first**, snapshot everything, change only what you
decide to, and roll back anything that breaks. Live alerts tell you the moment Red Team acts. Every script opens
with a header that says what it does, what it reads, what it changes, how to undo it, and the manual commands it
automates, so newer members can learn from it.

> Scope: **Windows**. Linux is planned.

---

## 1. Get it onto a box

| Situation | Do this |
|---|---|
| **Box has internet** | Admin PowerShell: `irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 \| iex`. Installs to `C:\ccdc\toolkit`, locks the folder to admins, opens the panel. |
| **No internet** | Copy this folder over (RDP drive, share, USB) and **double-click `CCDC-Toolkit.bat`**. It asks for admin, unblocks the files and opens the panel. |
| **Only want alerts, fast** | Open `windows\alerts\bt-deploy-PASTE.txt`, copy all, paste into an Admin PowerShell. |

### Supported Windows
| Windows | Works |
|---|---|
| Server 2016 / 2019 / 2022 / 2025, Windows 10 / 11 | Everything |
| Server 2012 / 2012 R2, Windows 8.1 | Everything (alerts need 2012 R2+). Patch-based CVE checks are "probably", see the vuln script header |
| Server 2008 R2, Windows 7 **with WMF 3.0+** | Designed to work (not yet tested on one): panel, audits, snapshots, hardening. Built-in stand-ins replace the network and local-group cmdlets these versions lack. No live alerts |
| PowerShell 2 only | The launcher says so and points to the manual commands |

GUI or Server Core, domain controller, member or standalone, any display language (well-known SIDs and audit GUIDs, never English names).

## 2. The panel

```
==============================================================================
  CCDC BLUE TEAM TOOLKIT v3.1                                           10:04
==============================================================================
  HOST    WEB01  Windows Server 2022 Standard  |  Member server
  IP      10.0.0.10
  RIGHTS  Administrator
  ALERTS  14 detections armed, watch window open
  LAST    10:02:11 NEW USER svc_backup by Administrator from 10.0.0.66 ...
  SNAPS   ORIGINAL 09:01, 4 total, latest 09:58 before-Harden-Baseline
------------------------------------------------------------------------------
  START  [0] First 15 minutes (guided)  overview, backup, alerts, audits, baselines

  MONITOR   keep these running in their own windows
   [D]  LIVE ALERTS                   [C]  Service health 
   [N]  Who is on this box

  SNAPSHOT  what changed, and put it back
   [S]  Take snapshot                 [W]  What changed?
   [U]  Undo changes

  AUDIT     read-only, safe any time
   [1]  Box overview                  [2]  Users & admins
   [3]  Persistence hunt              [4]  Network exposure
   [5]  Vulns (CVE check)             [6]  AD + GPO (DC)
   [7]  Security policy               [8]  PII / sensitive files
   [9]  Software audit                [E]  Event-log sweep
   [T]  Vendor tool audits
   [A]  Run ALL quick audits (1-7) -> one report folder

  HARDEN    dry run first, you confirm each change
   [10] Rotate passwords              [11] Disable accounts
   [12] Firewall allowlist            [13] Baseline hardening
   [14] IIS / PHP hardening           [15] AD account hardening
   [16] SQL Server hardening          [17] Reset krbtgt (DC)

  RESPOND   an alert fired, now what
   [R]  Remove persistence            [X]  Log off sessions
   [I]  Incident worksheet

  BACKUP & LOGGING
   [B]  Backup this box               [K]  Per-service backup
   [L]  Setup logging

  [H] full help for a script   [?13] explain an option   [Q] quit
```

- The **header is a status board**. It shows the box's role and IPs, whether you're elevated, whether LIVE ALERTS are armed (or were disabled), the newest alert, and the snapshots.
- **Read-only** options run immediately and offer to save a report to `C:\ccdc\reports\`.
- **Changing** options offer a `-WhatIf` dry run, **take a snapshot**, then confirm every action.
- **Monitors** open in **their own window**, so the panel stays free.

## 3. Snapshot, compare, roll back

The first time the panel opens on a box (elevated) it saves the **ORIGINAL** snapshot: how the box was before anyone
touched it. Every changing option takes another snapshot first. A snapshot holds:

- **Registry security settings:** LSA/NTLM, SMB, WDigest, RDP, UAC, Winlogon, Run keys, IFEO, Point and Print, LLMNR/NBT-NS, PowerShell logging, Defender policy, Netlogon, LDAP signing and more.
- **Services:** every one, with start mode, state, binary path and account.
- **Accounts:** users and enabled state, privileged group members, shares and share permissions.
- **Other state:** hosts file, Defender settings and exclusions, firewall rules and profiles (plus a full `netsh` export), audit policy, and local security policy (password and lockout policy, user rights).

| Key | What it does |
|---|---|
| **W** → 1 | Every setting that changed since the ORIGINAL, each marked **[toolkit: script time]** or **NOT BY THE TOOLKIT** (a teammate by hand, or Red Team) |
| **W** → 3 | New users / tasks / services / Run keys / listeners / SSH keys since the change baseline (attacker footprints) |
| **5** | The vuln check compares NOW with the ORIGINAL. It shows what is **FIXED** (and by which script) and what **REGRESSED** (was fixed, open again) |
| **U** | Pick a snapshot, pick the changes (`1,4,7`, `3-9`, `all`, or a category), put them back. Each item asks y/N, is backed up and logged, and a "before-restore" snapshot makes the restore itself undoable. New users and services are **disabled**, never deleted. Whole-area restores: **F** firewall, **P** audit policy, **S** security policy |

## 4. Competition day

1. On each Windows box: open the panel (the ORIGINAL snapshot is saved) and press **`0`**. The guided run asks before each step: snapshot, overview, backup, **LIVE ALERTS on**, **vuln check**, users, persistence, baselines.
2. Keep the **BT ALERTS** window open on every box. When the scoring engine's IP shows up in an alert, trust it: `D` → `3`.
3. Close what `5` found, starting with what can't break scoring: `13` baseline hardening. Re-run `5` to see the CHANGE column.
4. Passwords: `10` (scored accounts go through a **Password Change Request** in the scoring portal first), then `X` to kick old sessions. Then `12` firewall.
5. Something broke? `W` → `1` shows what changed, `U` puts it back. An alert fired? `D` → `5` (story of that IP), `R` remove persistence, `I` incident worksheet.

Full checklist: [`docs/first-15-minutes-windows.md`](docs/first-15-minutes-windows.md). Event notes: [`docs/events/`](docs/events/).

---

## What's in the box

### Monitor
| Key | Script | What it does |
|---|---|---|
| D | `alerts\bt-alerts.ps1` | **LIVE ALERTS.** Event-triggered tasks fire within about 1 s on: RDP or untrusted network logon, spraying, Kerberoasting, user/group/password changes, new services and tasks, log clearing, Defender changes, tampering with the alerts. Each alert shows who, source IP/PC, logon type, a plain-English HOW, the attack CHAIN for that IP and DO NOW commands. [`docs/live-alerts.md`](docs/live-alerts.md) |
| C | `hunt\Test-ScoredServices.ps1` | Service health for each port: listening? right address? start mode? connect? firewall? Then HTTP title/defacement/DB errors, DNS vs baseline, LDAP, shares, RDP, sshd, scored-account lockout, hosts/portproxy/IPsec/clock/disk sabotage. Loop mode |
| N | `alerts\whoshere.ps1` | One screen: sessions, SMB, WinRM, logons, remote connections, odd ports, diff vs baseline |

### Snapshot
| Key | Script | What it does |
|---|---|---|
| S W U | `backup\Snapshot-State.ps1` | Take / Compare / Restore (see section 3) |
| W → 3-5 | `hunt\Watch-Changes.ps1` | Attacker-footprint baseline and diff: users, groups, tasks, services, ports, Run keys, WMI, shares, firewall, Defender exclusions, hosts, SSH keys, IFEO/Winlogon/LSA, software, web files; on a DC GPOs, SPNs, trusts. Loop or scheduled task |

### Audit (read-only)
| Key | Script | What it does |
|---|---|---|
| 1 | `recon\Get-BoxOverview.ps1` | OS/build, domain role, IPs, listeners → process, roles, services, hotfixes, listening services |
| 2 | `audit\Audit-Users.ps1` | Privileged groups, pw-never-expires, new accounts, SPNs, AS-REP roastable, passwords in descriptions, adminCount |
| 3 | `audit\Audit-Persistence.ps1` | Tasks, services, Run keys, startup, WMI, Winlogon, IFEO/sticky keys, AppInit, SSH keys, Defender exclusions, web shells, LSA packages, netsh helpers, hidden tasks, ServiceDll hijacks, PS profiles |
| 4 | `audit\Audit-Network.ps1` | Connections + process, firewall profiles, any/any rules, SMBv1, SMB signing, shares + ACLs, RDP NLA, WinRM |
| 5 | `audit\Audit-Vulns.ps1` | **Zerologon, PrintNightmare, EternalBlue, SMBGhost, BlueKeep, SIGRed, noPac, PetitPotam/ESC8, Certifried, MS14-068, HiveNightmare, Follina, ProxyLogon/ProxyShell, IPv6 RCE (CVE-2024-38063), LDAPNightmare, SMB NTLM reflection (CVE-2025-33073)**, LDAP/SMB signing, NTLMv1, LLMNR/NBT-NS, WDigest, LSA protection, anonymous/Guest, AlwaysInstallElevated/UAC, RDP NLA, Defender, patch age, AD CS ESC1. NOW / BEFORE / CHANGE columns |
| 6 | `audit\Audit-AD-GPO.ps1` | DC: GPO changes, SYSVOL, GPP cpassword, root ACL, DCSync holders, AdminSDHolder, delegation, krbtgt age |
| 7 | `audit\Audit-SecurityPolicy.ps1` | ~55 GPO/AD/DNS settings with SAFE / CAUTION / LEAVE, GPO path, check + fix commands ([reference](docs/security-policy-reference.md)) |
| 8 | `audit\Audit-SensitiveFiles.ps1`, `alerts\pii-hunt.ps1` | SSNs, Luhn-valid cards, keys, passwords in files; files readable by Everyone or under web roots/shares; SQL Server PII columns. Never prints the values |
| 9 | `audit\Audit-Software.ps1` | Remote-access tools, attack tools, junk, outdated software → inventory CSV for inject answers |
| E | `hunt\Watch-Events.ps1` | Look back N minutes through the event logs: account/group changes, tasks, services, logons, spraying, tampering, web server spawning a shell, DCSync, Zerologon, roasting, GPO edits. Each with source IP |
| T | `audit\Invoke-AuditTools.ps1` | Runs staged Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith (winPEAS opt-in) and turns output into findings |

### Harden (dry run + snapshot + confirm)
| Key | Script | What it does |
|---|---|---|
| 10 | `harden\Rotate-Passwords.ps1` | Random passwords, shown once, never saved; scored accounts excluded |
| 11 | `harden\Disable-Accounts.ps1` | Disable (not delete) accounts, rollback script |
| 12 | `harden\Set-Firewall.ps1` | All profiles on, default-deny inbound, scored ports open to any source, keeps your session, auto-rollback task |
| 13 | `harden\Harden-Baseline.ps1` | SMBv1, SMB signing, LLMNR/NBT-NS, WDigest, LSA protection, spooler on DC, audit policy, script block logging, Defender, IFEO, RDP NLA, Guest, MachineAccountQuota (each skippable) |
| 14 | `harden\Harden-IIS-PHP.ps1` | Back up IIS/web roots, WP `DISALLOW_FILE_EDIT`, config ACLs, WP admins/plugins, php.ini checks |
| 15 | `harden\Harden-AD.ps1` | DC: clear no-preauth, reversible encryption, password-not-required, DES-only (with rollback); report roastable / unconstrained delegation |
| 16 | `harden\Harden-MSSQL.ps1` | sa, sysadmins, weak SQL logins, linked servers; turn off xp_cmdshell, Ole Automation, ad hoc queries, CLR, remote DAC |
| 17 | `harden\Reset-Krbtgt.ps1` | DC: one krbtgt reset per run, replication check, enforced wait before the second |

### Respond
| Key | Script | What it does |
|---|---|---|
| R | `hunt\Remove-Persistence.ps1` | Numbered list of removable persistence; each pick is exported + hashed with creator and source IP, then disabled / quarantined, with an undo command |
| X | `harden\Disconnect-Sessions.ps1` | List, then log off RDP/console, SMB, WinRM, SSH sessions of named users (or everyone but you) |
| I | `hunt\New-IncidentReport.ps1` | Ranks candidate attacker IPs and writes a facts-only worksheet: timeline, removals with hashes, live sessions, IIS requests |

### Backup & logging
| Key | Script | What it does |
|---|---|---|
| B | `backup\Backup-Box.ps1` | Registry, tasks, firewall, users; DC: GPOs, DNS, LDIF (ntds.dit IFM only with `-IncludeAdIfm`); IIS config + web roots |
| K | `services\Invoke-AllServices.ps1` + `services\<Service>.ps1` | Detects each installed service (AD, DNS, DHCP, IIS, SQL, MySQL, SMB, FTP, RDP, WinRM, SSH, VNC, SNMP, OpenVPN, NFS, mail...) and backs up / documents / verifies it; restore one service at a time |
| L | `logging\Setup-Logging.ps1` | Audit policy, log sizes, PowerShell logging, Sysmon (if staged), Winlogbeat/NXLog to Graylog/syslog |

### Where things land
`C:\ccdc\snapshots\` snapshots · `C:\ccdc\reports\` reports · `C:\ccdc\logs\` action logs with undo commands ·
`C:\ccdc\backups\` backups · `C:\ccdc\evidence\` + `C:\ccdc\quarantine\` what was removed · `C:\bt\` live alerts

---

## Rules every script follows
1. **Generic.** No hard-coded IPs, hostnames, domains or accounts. Box facts go in an optional config or in docs, never in code.
2. **Explainable.** Header: purpose, reads, changes, undo, manual equivalent.
3. **Audit and change are separate.** `recon/` and `audit/` are read-only. Changing scripts support `-WhatIf` and ask y/N per action unless `-Force`.
4. **Never write passwords to disk.** Shown once, set through ADSI, never on a command line, no transcripts. Snapshots record secret registry values as "present" only.
5. **Never touch scored services or accounts automatically.** Scored-account changes go through the Password Change Request process. Nothing auto-blocks IPs.
6. **Snapshot, log, back up.** Snapshot before changing, log every action (never secrets) to `C:\ccdc\logs\` with undo commands, back up files and registry keys to `C:\ccdc\backups\<timestamp>\`.
7. **Compatible:** Windows PowerShell 3+ (5.1 recommended; alerts 4.0+), no external modules, any display language, GUI or Server Core.
8. **Scannable output:** RED = likely malicious / vulnerable, YELLOW = review, GREEN = ok.

## Optional config
Everything works with no config. To pre-fill scored ports, scored accounts and admin sources, run
`copy config\example.great-cretaceous.json config\ccdc.json` and edit it from the team packet (`config/ccdc.json` is gitignored, and it never holds passwords).

## Before the event
- Stage third-party tools on a trusted machine: `tools\Get-CcdcTools.ps1` (Sysinternals, Sysmon, PingCastle, Locksmith, Hayabusa). Verify on a box with `-Verify`. See [`tools/README.md`](tools/README.md).
- Practise on a VM: open the panel, press `0`, run the alerts self-test (`D` → `8`), make a change with `13`, then try `W` → `1` and `U`.

## Folder map
```
CCDC-Toolkit.bat            double-click: opens the panel (asks for admin)
install.ps1                 one-line download + install
windows/
  Launch-Toolkit.ps1        the panel
  lib/CCDC-Common.ps1       shared helpers: findings, logging, -WhatIf, backups, config, snapshots, registry
  lib/Compat.ps1            stand-ins for cmdlets older Windows lacks
  alerts/                   LIVE ALERTS bundle (standalone, installs to C:\bt, one-paste deploy)
  recon/ audit/             read-only
  backup/                   Snapshot-State (snapshot / compare / restore), Backup-Box
  harden/                   changes state (-WhatIf, confirm, backups)
  hunt/                     monitors and incident response
  logging/ services/
config/  docs/  tools/
```

## Maintaining
- Lint: `pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows` (parse + PS 5.1 compatibility + PSScriptAnalyzer when installed).
- After editing anything in `windows/alerts/`, rebuild the paste with `python3 tools/build-alert-paste.py`.
- Notes for AI assistants and new contributors: [`CLAUDE.md`](CLAUDE.md).
