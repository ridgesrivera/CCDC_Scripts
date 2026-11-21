# Toolkit review: what each script is worth at competition

Reviewed 2026-11-14 against the Great Cretaceous pod (`config/example.great-cretaceous.json`):
**3 Windows boxes** (trex DC 2016, fossil Win10, fernbank IIS 2022) and **6 Linux boxes** (pangea, laboratory, hatchery, hellcreek, badlands, tarpit).

How it was checked: every `.ps1` parsed (also as Windows PowerShell 5.1 reads BOM-less files, as ANSI), PSScriptAnalyzer with the
Server 2016 / PS 5.1 compatibility profile, and a line-by-line read of the logic. Nothing here was run on a real Windows box, so
**run each script once in the lab before the event.**

## Biggest gap: Linux
Two thirds of the pod is Linux and the repo has **no Linux scripts**. hatchery (MySQL, which both fernbank sites depend on), hellcreek (Keycloak SSO),
tarpit (our Graylog) and pangea (the router: if it breaks, every scored service breaks) all need a first-15-minutes plan.
Stopgap: `tools\Get-CcdcTools.ps1 -IncludeLinux` stages pspy + Lynis to copy over. A `linux/` folder with the same audit/harden/backup split is the next big job.

## Ratings
**Essential** = run on every relevant box. **Useful** = run when it applies. **Situational** = keep for other pods; auto-skips here.

### Core (`windows\`)
| Script | Rating | Notes |
|--------|--------|-------|
| `Launch-Toolkit` | Essential | The panel. New `[T]` option for vendor tools |
| `recon\Get-BoxOverview` | Essential | First 60 seconds on any box; flags config-scored ports with nothing listening |
| `audit\Audit-Users` | Essential | DA/EA membership, AS-REP/Kerberoast, passwords in descriptions, recent accounts |
| `audit\Audit-Persistence` | Essential | **Expanded:** LSA packages (memssp/mimilib), netsh helpers, hidden scheduled tasks (SD deleted), svchost ServiceDll hijacks, PowerShell profiles, BootExecute |
| `audit\Audit-Network` | Essential | Live connections → process, any/any firewall rules, SMB/RDP/WinRM exposure |
| `audit\Audit-Vulns` | Essential | **Expanded:** SMBGhost (matters on fossil if it's 1903/1909), NTLMv1/LM, anonymous enumeration, Guest, AD CS ESC1 with enrollment-rights check |
| `audit\Audit-AD-GPO` | Essential (trex) | **Fixed:** "all extended rights" ACEs (DCSync-capable) were not flagged; gPLink parsing now case-insensitive |
| `audit\Audit-SecurityPolicy` | Essential | **New.** GPO/AD/DNS settings with SAFE / CAUTION / LEAVE, GPO path and check/fix commands; `-Reference` regenerates `docs/security-policy-reference.md` |
| `audit\Invoke-AuditTools` | Useful | **New.** Autoruns, Sigcheck, AccessChk, Hayabusa, PingCastle, Locksmith (winPEAS opt-in) → findings |
| `harden\Rotate-Passwords` | Essential | **Fixed (serious):** if clearing "must change at next logon" failed *after* the password was set, the new password was never shown, so you were locked out of that account. Now it's always shown, and the follow-up step is best-effort |
| `harden\Disable-Accounts` | Essential | Fine as is |
| `harden\Set-Firewall` | Essential | **Fixed (serious):** scored ports that are also admin ports (RDP 3389 on trex/fossil, SSH 22 on fossil) were limited to `adminSources`; if the scoring engine isn't in that range, those checks fail. They now stay open to Any |
| `harden\Harden-Baseline` | Essential | **New modules:** `RequireRdpNla`, `DisableGuest`, `MachineAccountQuotaZero` (DC) |
| `harden\Harden-IIS-PHP` | Essential (fernbank) | WP admins via PHP CLI, DISALLOW_FILE_EDIT, config ACLs |
| `backup\Backup-Box` | Essential | **Changed:** ntds.dit IFM is now opt-in (`-IncludeAdIfm`). A hash dump sitting on disk is what the packet's "recovered passwords" penalty is about |
| `logging\Setup-Logging` | Useful | Needs Sysmon staged (`Get-CcdcTools.ps1` does it) and Winlogbeat/NXLog staged by hand to reach Graylog on tarpit |
| `hunt\Watch-Changes` | Essential | **Fixed:** `-Mode Diff` with no baseline crashed; now says to take one |

### Per-service (`windows\services\`)
| Relevant here | Situational (auto-skip on this pod) |
|---------------|-------------------------------------|
| ActiveDirectory, DNS, GroupPolicy (trex) · IIS (fernbank) · RDP, OpenSSH (fossil) · WinRM, WindowsFirewall, ScheduledTasks, SMB_FileShares, W32Time, PrintSpooler (all) · ADCS (trex, if a CA exists) | DHCP, FTP, NFS, MSSQL, Mail, Exchange, VNC, OpenVPN, SNMP, WebServers_NonIIS, MySQL (our MySQL is on Linux hatchery) |

**Fixed:** `MySQL.ps1` put the DB password on the `mysql`/`mysqldump` command line. That's visible in process lists and logged in event 4688,
which `Setup-Logging` turns on. It now uses the `MYSQL_PWD` environment variable of the script's own process.
**Fixed (2026-11-21):** `Invoke-AllServices` no longer uses `Start-Transcript`; it writes only its summary table to the log.

### `legacy\` (removed 2026-11-21)
The v1 scripts were removed; real-time alerting is now `windows\alerts`. They are still in git history (`git show 371e3c5:legacy/`).

## Third-party tools
See [`tools/README.md`](../tools/README.md). Short version: **stage** Sysinternals (Autoruns/Sigcheck/AccessChk), Sysmon, PingCastle, Locksmith and Hayabusa.
winPEAS is useful but opt-in: Defender quarantines it, its output can hold credentials, and most of what it finds is already covered by `[T]` AccessChk, `[3]` and `[5]`.

## Season booklet review (2026-11-16): what was added and what is still open

The WRCCDC '26 prep booklet names where the points went: **SLA penalties were larger than all Red Team deductions**, persistence cost 1,100 at Quals,
default + reused credentials were ~40% of Red Team losses at Regionals, anonymous access / data leakage 700, and incident reports earn nothing without a source IP.

| Booklet finding | Script |
|-----------------|--------|
| Persistence scored per hour; removal only counts if proven | `hunt\Remove-Persistence` (evidence first), `hunt\Watch-Changes -InstallTask` (hunting on a schedule) |
| "Detection habits": new users, group changes, tasks, logons from outside the team range | `hunt\Watch-Events` |
| Incident reports need a source IP, within minutes | `hunt\New-IncidentReport`; every alert/removal carries the session's source IP |
| "The service is red but looks fine to me" ladder; firewall rules dropping packets; scored account password changed; DNS records destroyed | `hunt\Test-ScoredServices` |
| PII / card data found and restricted in the first hour | `audit\Audit-SensitiveFiles` |
| Remote-access tools (unauthenticated VNC), unnecessary-software and remote-access audit injects | `audit\Audit-Software` |
| PingCastle top findings: AS-REP, Kerberoast, reversible encryption | `harden\Harden-AD` |
| MSSQL was the most expensive host (xp_cmdshell, sa) | `harden\Harden-MSSQL` |
| Domain-wide persistence, golden tickets | `harden\Reset-Krbtgt` |
| Sessions survive a password change | `harden\Disconnect-Sessions` |

**How these were checked:** parsed + PSScriptAnalyzer (PS 5.1 profile), and run end to end on Linux PowerShell against stubbed Windows cmdlets and fabricated events
(alert rules, source-IP correlation, firewall-rule parsing, HTTP checks, card/SSN matching, the removal flow). **None has run on real Windows yet.**
Lab-test each one before the repo freeze, in this order: `Test-ScoredServices`, `Watch-Events`, `Remove-Persistence -WhatIf` then for real on a planted task/service/Run key/WMI subscription, `Harden-AD -WhatIf`, `Reset-Krbtgt` on the lab DC, `Harden-MSSQL -WhatIf`.
Things to confirm in the lab: firewall event field values (Action 2 = block), DNS Server audit event IDs 513/516, hidden-task removal permissions, WMI subscription removal, `msg.exe` pop-ups from the scheduled task.

### Still open (scriptable, not done)
- **Per-application default credentials**: a checklist/driver for WordPress admins, MySQL on Windows, FTP users, Tomcat, hMailServer etc. (the #1 Red Team loss). Today only SQL Server and AD are covered.
- **Second DC build** (Quals inject 03): `Install-ADDSDomainController` wrapper + the five proof commands.
- **DNS zone auto-restore**: `Test-ScoredServices` detects missing records; restoring is still `services\DNS.ps1 -Action Restore` by hand.
- **GPO diff against the first-hour backup** (file-level compare of SYSVOL vs `Backup-GPO`); today only version numbers and 5136 edits are watched.
- **Onboarding / offboarding script** (create or disable a user across AD + shares, with session-termination proof): seven injects asked for it.
- **Box sheet / asset inventory export**: one CSV row per host (OS, IP, ports, services, admins) for the inventory inject.
- **Proxy CA install + Wazuh agent enrollment** helper for Qualifiers/Regionals (`http://10.0.0.20/`).
- **Hyper-V host check** (guests, virtual switch, checkpoints) for boxes that host other scored boxes.
- **Linux**: still the biggest gap overall.
