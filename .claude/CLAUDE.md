# CLAUDE.md: notes for Claude Code working in this repo

(Lives in `.claude/` so it is not downloaded to competition boxes. `dev/`, `.claude/`, `install.ps1` and the alerts
paste are `export-ignore` in `.gitattributes`: the GitHub zip and install.ps1 deliver ONLY the live toolkit.
New non-live files go in `dev/`.)

Ridge's CCDC (WRCCDC) Blue Team toolkit, Windows first. Used under time pressure by students during
competition, and for teaching newer club members. Read `README.md` (hard rules, folder map) first.

## Non-negotiables
- **Generic, never tuned to one environment.** No hard-coded IPs, hostnames, domains or account names in
  scripts. Box-specific facts go in `config/*.json` or docs, never in code. Competition environments change
  every event; a script that only works on the practice lab is a bug.
- **Any Windows box:** Windows PowerShell **3.0+** (5.1 recommended; `lib/Compat.ps1` stands in for cmdlets
  2008 R2 / Win7 lack) and, for `windows/alerts/`, **4.0+** (Server 2012 R2). No PowerShell 7 syntax (`?.`, `??`, `&&`, `||`, ternary). No external modules at runtime.
  GUI and Server Core. Any display language: use audit-subcategory **GUIDs** and **well-known SIDs**,
  never English group or policy names.
- **Read-only vs change are separate** (see README hard rules 2-6). State-changing scripts support
  `-WhatIf`, confirm per action, back up first, log with undo commands.
- **Never write passwords to disk**, never put them on a command line, never `Start-Transcript`.
- **Never touch scored services or scored accounts automatically.** Scored-account password changes go
  through the competition's Password Change Request process (Quotient). Nothing auto-blocks IPs.
- **Every script opens with the header**: `.SYNOPSIS` + `.DESCRIPTION` with PURPOSE / WHAT IT READS /
  WHAT IT CHANGES / HOW TO UNDO / MANUAL EQUIVALENT. The panel's `[H]` shows it via `Get-Help`.
- **Writing style for docs and output:** plain English, short sentences, no em dashes. Docs are read by
  beginners; explain *why* each step matters and what attack it stops.
- **Competition rule:** inject responses must be written by the team. Tools and their raw output are fine
  as evidence; never generate inject prose.

## Layout you'll touch most
```
CCDC-Toolkit.bat             root launcher -> windows/Launch-Toolkit.bat (self-elevates, unblocks, opens panel)
install.ps1                  one-line download/installer (irm ... | iex) -> C:\ccdc\toolkit
windows/Launch-Toolkit.ps1   the panel: $menu table (Key/Sec/Name/File/RO/Desc) + Get-ScriptParams + Invoke-Entry;
                             status header (Get-AlertStatus), [0] first-15 = START-ONLY steps (Invoke-FirstSteps),
                             submenus: D Invoke-LiveAlerts, X Invoke-KickMenu, 11 Invoke-FirewallMenu, 12 Invoke-WalkthroughMenu
windows/lib/CCDC-Common.ps1  shared helpers for recon/audit/harden/... (NOT used by windows/alerts): findings, logging,
                             Invoke-CcdcChange, backups, registry catalog (Get-CcdcRegCatalog), snapshots
windows/lib/Compat.ps1       stand-ins for Get-NetTCPConnection / Get-NetIPAddress / Get-LocalGroupMember on old Windows
windows/backup/Snapshot-State.ps1  Take / Compare / Restore. The panel auto-takes ORIGINAL on first run and a snapshot
                             before every changing entry (except $noAutoSnapshot). Compare attributes each change to
                             the toolkit by matching CHANGED lines in C:\ccdc\logs (Get-CcdcToolkitChanges).
windows/harden/Harden-Walkthrough.ps1  THE hardening tool: data-driven $steps (reg steps: Key/Name/Value/Default,
                             custom: Check/Apply). Every apply writes structured undo data to C:\ccdc\hardening-undo.csv
                             (never code). On a DC reg steps also go into GPO 'CCDC Hardening' (Domain Controllers OU).
windows/harden/Set-Firewall.ps1  BASIC firewall: allow all listening ports, block other inbound, safety timer, -Revert.
windows/hunt/Find-Attacks.ps1  Red Team response: logon attempts on every service + attack checks, each with steps.
windows/hunt/Find-Beacons.ps1  C2 beacon scan (sampled connections, pipes, DNS cache).
windows/harden/Repair-Defender.ps1  Defender back on: feature, service, policy switches, settings, exclusions, verify.
windows/hunt/Repair-DNS.ps1  DNS outage: diagnose (stopped/disabled/crashed/zone/firewall), standard fixes, verify.
windows/hunt/Kick-Block.ps1  kick user (log off + disable) / block IP (in+out), journal C:\ccdc\kick-block.csv, undo.
windows/audit/Audit-Vulns.ps1  each check = Applies + Eval(param $S) run against live state AND a snapshot. Only read
                             registry keys that are inside Get-CcdcRegCatalog, or the BEFORE column shows '?'
windows/alerts/              LIVE ALERTS bundle: standalone on purpose (see below)
dev/tools/build-alert-paste.py   regenerates windows/alerts/bt-deploy-PASTE.txt
dev/tools/lint/Test-PsSyntax.ps1 parse + PS 5.1 compatibility lint
dev/docs/live-alerts.md          design, detections, limits, test status, lessons learned for the alerts
docs/events/                 per-event notes from team packets (box roles, scoring, penalties). Docs only, never code
```

## windows/alerts: how it works (read dev/docs/live-alerts.md for detail)
- `bt-alerts.ps1 -Install` sets 7 audit subcategories by GUID, raises the Security log to 512 MB, auto-trusts
  the installer's RDP IP, locks `C:\bt` to Administrators + SYSTEM, and registers one **event-triggered
  scheduled task per detection** (`BT-Alert-<key>`, SYSTEM). Each task runs `bt-alerts.ps1 -Key <key>`.
- The `-Key` path reads the newest matching event, traces `SubjectLogonId` -> the 4624 logon (IP, PC, type,
  auth package), builds the CHAIN from `C:\bt\alerts.log` (same IP, last 60 min) and writes:
  `alerts.log` (one line, the format the chain and self-test parse), `alerts-full.log` (block), msg.exe popup.
- `-Watch` tails `alerts-full.log` and runs the heartbeat every 30 s (tasks present/enabled/pointing at the
  script, script SHA256 held in memory, EventLog + Schedule services, audit policy every 5 min via
  `auditpol /backup`). It disables QuickEdit and owns `C:\bt\watch.pid`.
- Detections live in the `$Triggers` table (key -> log, XPath, noisy). Handlers live in the final `switch ($Key)`.
  **To add a detection:** add a `$Triggers` entry, add a handler that calls `Send-Alert`, add an audit GUID to
  `$AuditMap` if needed, add a self-test case, update dev/docs/live-alerts.md, rebuild the paste.
- **Why standalone:** the whole bundle must deploy from one clipboard paste onto a box with nothing on it.
  Do not make it dot-source `CCDC-Common.ps1` or depend on other repo files. Keep it bare-bones and
  low-overhead (no sound, no tray icons, no background loops besides `-Watch`).

## Panel keys (v3.2)
MONITOR D N · RED TEAM RESPONSE E X R F I · SNAPSHOT S W U · AUDIT 1-8 A · HARDEN 10-16 (16 = Defender) · BACKUP B P L · 0 first-15 · ?<key> · H help.
Ridge's direction: keep it small (replace, don't add), no scoring guesswork / points language in output, everything that
can break a service must be reversible, first-15 does start-of-competition steps ONLY.
Docs reference these keys; update README, docs/first-15-minutes-windows.md and docs/events/* when they change.

## Gotchas already paid for (do not reintroduce)
- No line in an alert script may start with `'@` (ends the paste here-string). ASCII only. The builder checks.
- Never name a function after a built-in alias (`h`, `r`, `gc`, `ls`...). `H` broke whoshere once.
- Inside `switch` within `ForEach-Object`, `$_` is the switch value. Use `foreach ($r in ...)`.
- `net user <u> <pw>` prompts Y/N for passwords longer than 14 chars and hangs. Use ADSI or <=14 chars in tests.
- With Guest enabled, a fake-username logon becomes Guest (no 4625). Spray tests use a real user + wrong password.
- Defender cmdlets throw 0x800106ba when Defender is off: check `Get-MpComputerStatus` and SKIP.
- Windows usually logs no 4702 when a task is **disabled**; only the heartbeat catches that.
- `msg.exe` max 255 chars; it doesn't exist on Home editions. `query.exe` same.
- `Set-Service` doesn't take arrays on 5.1. `Get-FileHash` is 4.0+ (fine).
- Console QuickEdit freezes `-Watch` on click; it's disabled in-window via SetConsoleMode.
- `$h1.Keys + $h2.Keys` throws (KeyCollection has no op_Addition). Use `@($h1.Keys) + @($h2.Keys)`.
- A native argument like `/file:(Join-Path ...)` is passed as TWO arguments. Build the string first: `"/file:$path"`.
- Aliases beat functions: never name a helper `r`, `h`, `gc`, `gi`, `gp`, `sc`, `ls`.... Check: compare `function` names against `Get-Alias` output.
- Persistence noise rules live in lib (Get-CcdcPersistSeverity, Test-CcdcMsSigned, Test-CcdcTaskIsNoise): shared by
  Audit-Persistence and Remove-Persistence. Hide Microsoft-signed / Windows-internal / toolkit items; never hide content
  that matches the bad-command or script-outside-Windows rules.
- Output rule (Ridge): condensed, grouped, few false flags. One line per problem; long lists go to the report file.
- Throttle keys in `alert-state.json` must be cleared by the self-test (regex near the top of bt-selftest.ps1)
  when you add a new throttle prefix.

## Testing
- No Windows here? Run `python3 dev/tools/build-alert-paste.py` (checks paste safety) and, if `pwsh` exists,
  `pwsh -File dev/tools/lint/Test-PsSyntax.ps1 -Path windows`. Then say plainly that it is **untested on Windows**.
- Real test: on a Windows VM, panel `[D]` -> `[1]` (or the paste), keep the watch window open, run
  `C:\bt\bt-selftest.ps1`. Current baseline on a Server 2022 DC: **25 PASS / 1 FAIL (Guest enabled = real
  finding)**, Defender SKIP if disabled. Any new FAIL is a regression until proven otherwise.
- Manual checks the self-test can't do: RDP reconnect (RDP LOGON), network logon from a second machine not
  in trusted.txt (NETWORK LOGON + CHAIN), Kerberoast from Kali against a DC, log clearing (destroys evidence).

## Backlog (ask Ridge before starting; he prefers small, tested steps)
1. Run the self-test on a **domain member server** and a **standalone** box; record results in dev/docs/live-alerts.md.
2. Live-test untrusted network logon, Kerberoast and the CHAIN/LIKELY patterns from a Kali box.
3. CHAIN links by IP only. Consider also linking by account (who) for SYSTEM/webshell activity, without noise.
4. `netlogon` only fires on NTLM (keeps DCs quiet). Consider a low-noise Kerberos rule (e.g. type 3 from IPs
   never seen before) if it can stay quiet on a busy DC.
5. Roles: `D` bt-alerts = live; `E` Find-Attacks = look-back + response steps; `N` whoshere = every way in, now;
   `W` Watch-Changes = footprint diff. Consider adding live triggers to bt-alerts for what only Find-Attacks sees
   (DCSync 4662, web server spawning a shell, Zerologon 5827-5829).
6. `pii-hunt.ps1` overlaps `audit/Audit-SensitiveFiles.ps1`; panel `8` offers both (deep file scan vs quick hunt incl. SQL Server).
9. Snapshot restore covers registry/services/users/groups/shares/hosts/Defender/firewall/audit/secpol. Not covered:
   scheduled tasks and WMI persistence (use `R` Remove-Persistence), IIS/app config (use `K` per-service restore).
7. Linux equivalents (auditd / journald based), same output format.
8. Add `dev/tools/lint` coverage for the paste rules (no `'@` lines, ASCII) so CI catches them.
