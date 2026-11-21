# CCDC Blue Team Toolkit (v2): Windows

Scripts for CCDC Blue Team work (WRCCDC-style) and for teaching newer club members.
Every script is meant to be read: each one opens with a header saying **what it's for, what it reads, what it changes, how to undo it, and the manual commands it automates.**

> Scope right now: **Windows only.** Linux scripts are planned for later. The original v1 scripts live unchanged in [`legacy/`](legacy/README.md).

## Quick start
1. Copy the repo to the box (USB / share). If Windows marks the files as downloaded:
   `Get-ChildItem -Recurse .\CCDC_Scripts | Unblock-File`
2. **Right-click `windows\Launch-Toolkit.bat` → Run as administrator.** This opens the panel:
   ```
     READ-ONLY (safe any time)
     [1]  Box overview        [2] Users & admins   [3] Persistence hunt
     [4]  Network exposure    [5] Vuln check       [6] AD + GPO (DC only)
     [P]  Security policy     GPO/AD/DNS settings safe to turn on + where to set them
     [T]  Vendor tool audits  (Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith)
     [A]  Run ALL read-only audits (1-6 + P)  -> C:\ccdc\reports\
     CHANGES THE BOX (dry run offered first)
     [7]  Rotate passwords    [8] Disable accounts [9] Firewall allowlist
     [10] Baseline hardening  [11] IIS / PHP hardening
     BACKUP / LOGGING / HUNT
     [B]  Backup   [S] Per-service backup   [L] Setup logging   [W] Watch for changes
     DETECT (first 5 minutes)
     [D]  LIVE ALERTS         instant popup: who / from where / how + attack chain
     [H]  Explain a script    [Q] Quit
   ```
3. Follow [`docs/first-15-minutes-windows.md`](docs/first-15-minutes-windows.md).

**Before the event:** stage the third-party tools once on a trusted machine with `tools\Get-CcdcTools.ps1`
(Sysinternals, Sysmon, PingCastle, Locksmith, Hayabusa). On a box, run `tools\Get-CcdcTools.ps1 -Verify` before you use them. See [`tools/README.md`](tools/README.md).

Scripts can also be run directly, e.g. `.\windows\audit\Audit-Users.ps1 -OutFile C:\ccdc\reports\users.csv`.
`Get-Help <script> -Full` shows the header.

## Config
`config/example.great-cretaceous.json` describes the practice pod (lab: 192.168.100.0/24): hostnames, IPs, likely scored ports, scored accounts, Graylog IP. **No passwords, ever.**
At competition: `copy config\example.great-cretaceous.json config\ccdc.json`, edit the subnet/IPs from the team packet. `config/ccdc.json` is gitignored.
Scripts match this box by hostname. Everything still works without a config; you just pass ports etc. as parameters.

## Folder map
```
windows/
  Launch-Toolkit.ps1/.bat   the panel
  lib/CCDC-Common.ps1       shared: findings, logging, -WhatIf/confirm, backups, config
  recon/  audit/            READ-ONLY
  harden/                   changes state: -WhatIf, confirm per action, -Force, backups
  alerts/                   LIVE ALERTS bundle (standalone, installs to C:\bt, one-paste deploy)
  backup/  logging/  hunt/
  services/                 one script per service (AD, DNS, IIS, SQL, SMB, RDP...): info, backup, restore
config/                     example config (no secrets)
docs/                       first-15-minutes, per-box pages, incident response, teaching guide, toolkit-review
tools/                      Get-CcdcTools.ps1: download + hash-verify third-party tools (+ lint scripts,
                            build-alert-paste.py)
legacy/                     v1 scripts, unchanged
```

## Hard rules (every script follows these)
1. **Explainable.** Header block: purpose, reads, changes, undo, manual equivalent. Comments on anything non-obvious.
2. **Audit vs change are separate.** `recon/` and `audit/` are read-only. `harden/` supports `-WhatIf`, asks y/N per action unless `-Force`.
3. **Never write passwords to disk.** Rotation generates or prompts, applies, shows once on screen, then clears it. No `Start-Transcript`. Passwords are set via ADSI, never on a command line.
4. **Never touch scored accounts blindly.** Rotation takes `-Exclude`, auto-skips config `scoredAccounts` and service-looking names, and warns that scored users need a Password Change Request.
5. **Log everything** (actions, not secrets) to `C:\ccdc\logs\`, with undo commands.
6. **Back up before changing**: files and registry keys go to `C:\ccdc\backups\<timestamp>\` first.
7. **Compatible:** Windows PowerShell 5.1, no external modules (ActiveDirectory/GroupPolicy/DnsServer used only if present). No internet at runtime.
8. **Scannable output:** RED = likely malicious/critical, YELLOW = review, GREEN = ok. `-OutFile` saves a report (`.csv` or text).

## Script table
| Script | Read-only / Changes | What it does |
|--------|---------------------|--------------|
| `recon\Get-BoxOverview.ps1` | Read-only | Hostname, OS/build, domain role, IPs, listeners → process, roles, services, hotfixes, likely scored services |
| `audit\Audit-Users.ps1` | Read-only | Local/domain users, privileged groups (DA/EA/Schema/DnsAdmins/Backup Ops/RDP), pw-never-expires, new accounts, SPNs, AS-REP roastable, passwords in descriptions, adminCount |
| `audit\Audit-Persistence.ps1` | Read-only | Tasks, services, Run keys, startup, WMI, Winlogon, IFEO/sticky keys, AppInit, SSH keys/config, Defender exclusions, System32 changes, web shells, LSA packages, netsh helpers, hidden tasks, ServiceDll hijacks, PS profiles |
| `audit\Audit-Network.ps1` | Read-only | Connections + process, firewall profiles, any/any rules, SMBv1, SMB signing, shares + ACLs, RDP NLA, WinRM |
| `audit\Audit-Vulns.ps1` | Read-only | Zerologon, PrintNightmare, MS17-010, NoPAC, SMBGhost, LLMNR/NBT-NS, NTLMv1, anonymous/Guest, WDigest, LSA protection, LAPS, AD CS ESC1, Defender |
| `audit\Audit-SecurityPolicy.ps1` | Read-only | ~55 GPO / AD / DNS security settings (reversible-encryption passwords, WDigest, LM hashes, anonymous access, NTLM, SMB/LDAP signing, zone transfers, insecure DNS updates...): current value, SAFE / CAUTION / LEAVE, the GPO path to set it, and check + fix commands. Reference table: [`docs/security-policy-reference.md`](docs/security-policy-reference.md) |
| `audit\Invoke-AuditTools.ps1` | Read-only | Runs the staged vendor tools (Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith; winPEAS opt-in) and turns their output into findings |
| `audit\Audit-AD-GPO.ps1` | Read-only (DC) | GPOs + recent changes, SYSVOL changes, GPP cpassword, root ACL, DCSync holders, AdminSDHolder, delegation, krbtgt age |
| `harden\Rotate-Passwords.ps1` | **Changes** | Random passwords for local/domain users, exclude list, shown once, never saved |
| `harden\Disable-Accounts.ps1` | **Changes** | Disable (not delete) accounts, rollback script |
| `harden\Set-Firewall.ps1` | **Changes** | All profiles on, default-deny inbound, allowlist (scored ports open to any source), keeps your session, auto-rollback task |
| `harden\Harden-Baseline.ps1` | **Changes** | SMBv1, SMB signing, LLMNR/NBT-NS, WDigest, LSA protection, spooler on DC, audit policy, script block logging, Defender, IFEO removal, RDP NLA, Guest off, MachineAccountQuota=0 (each skippable) |
| `harden\Harden-IIS-PHP.ps1` | **Changes** (wp-config only) | Backup IIS/web roots, WP DISALLOW_FILE_EDIT, config ACL checks, WP admins/plugins, MediaWiki/php.ini checks |
| `backup\Backup-Box.ps1` | Writes backup folder only | Registry, tasks, firewall, users; DC: GPOs, DNS, LDIF (ntds.dit IFM only with `-IncludeAdIfm`); IIS config + web roots |
| `logging\Setup-Logging.ps1` | **Changes** | Audit policy, log sizes, PowerShell logging, Sysmon (if staged), Winlogbeat/NXLog → Graylog |
| `hunt\Watch-Changes.ps1` | Read-only (writes snapshots) | Baseline users/groups/tasks/services/ports/Run keys/WMI/shares, then diff every N minutes |
| `alerts\bt-alerts.ps1` | **Changes** (audit policy, tasks, C:\bt ACL) | Event-triggered alerts within ~1 s: RDP/untrusted network logon, spraying, Kerberoasting, user/group/password changes, services, tasks, log clearing, Defender, tampering. Each alert: who, source IP/PC, logon type, plain-English HOW, attack CHAIN for that IP, role-correct DO NOW commands. `-Trust`, `-Block`, `-Chain <ip>`, `-Snooze`, `-Backfill`. Full doc: [`docs/live-alerts.md`](docs/live-alerts.md) |
| `alerts\bt-selftest.ps1` | Temporary (self-cleaning) | Fires every detection for real and reports PASS/FAIL with which link broke |
| `alerts\whoshere.ps1` | Read-only | "Who's on this box": sessions, SMB, WinRM, logons, connections, odd ports, diff vs baseline |
| `alerts\pii-hunt.ps1` | Read-only | Card numbers (Luhn), SSNs, national IDs, passwords in files; open shares; SQL Server PII columns, sysadmins, xp_cmdshell |

**Live alerts without the repo:** paste `windows\alerts\bt-deploy-PASTE.txt` into an Admin PowerShell (regenerate it with `python3 tools/build-alert-paste.py` after editing any alert script).

## Linting
`pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows` (parse + PS 5.1 compatibility + PSScriptAnalyzer when installed).
