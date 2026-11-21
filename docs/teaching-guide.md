# Teaching Guide: Windows toolkit

Club rule: **nobody runs a script they can't explain.** So every demo goes:
1. **Manual first.** Show the built-in commands (each script's header lists them under *MANUAL EQUIVALENT*).
2. **Then the script.** Show it does the same thing, faster and with colour.
3. **Then the code.** Open the script and find the line that produced one finding.

Lab: the Great Cretaceous mirror on 192.168.100.0/24. Snapshot the VMs before any harden demo.
Before a session, plant a few things for students to find (see "Plant list" at the bottom).

---

## Session 1: Recon and the panel (30 min)
- **Manual:** `hostname`, `ipconfig /all`, `netstat -ano | findstr LISTENING`, `tasklist /FI "PID eq 1234"`.
- **Script:** panel `[1]` Get-BoxOverview. Point at the "Likely scored services" section.
- **Code:** the `$wellKnown` port table, and how listeners are mapped to processes by PID.
- **Discuss:** Why is a listener running from `C:\Users\Public` RED? Why does a DC listen on so many ports?

## Session 2: Users and admins (45 min)
- **Manual:** `net user`, `net localgroup administrators`, `net group "Domain Admins" /domain`.
- **Script:** `[2]` Audit-Users.
- **Code:** the LDAP filter `memberOf:1.2.840.113556.1.4.1941:=` (recursive membership) and the `userAccountControl` bit masks.
- **Discuss:**
  - What is Kerberoasting? Why is an SPN on a *privileged* account RED but on a normal one YELLOW?
  - Why does the script show a password found in a description on screen but never write it to the log?
  - What does `adminCount=1` on a non-admin mean?

## Session 3: Passwords (30 min)
- **Manual:** `net user Administrator *` (the `*` prompts, so nothing lands on the command line).
- **Script:** `[10]` Rotate-Passwords with **dry run** first, then for real on a lab account.
- **Code:** `New-CcdcPassword`: RNG vs `Get-Random`, rejection sampling, why `$ % ^ &` and quotes are excluded.
- **Discuss:**
  - Why not `net user bob NewPass123!`? (hint: 4688 command-line logging, process lists)
  - What is a Password Change Request and why do scored accounts need one?
  - Why does the script refuse to work silently if PowerShell transcription is on?

## Session 4: Persistence hunt (60 min, the fun one)
- **Manual:** `schtasks /query /fo LIST /v`, `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `Get-WmiObject -Namespace root\subscription -Class __EventConsumer`.
- **Script:** `[3]` Audit-Persistence on the planted box. Students race to explain every RED.
- **Demo the sticky-keys backdoor** on a lab VM: set the IFEO Debugger for sethc.exe to cmd.exe, press Shift 5x at the RDP login screen, then remove it with `[13] -Only RemoveIfeoDebuggers`.
- **Discuss:** Why does NLA matter for sticky keys? Why remove persistence only after preserving evidence?

## Session 5: Change control and the firewall (45 min)
- **Concepts:** `-WhatIf`, per-action confirmation, backups, undo hints in the log. Open a `C:\ccdc\logs\*.log` file and read it together.
- **Manual:** `netsh advfirewall show allprofiles`, `netsh advfirewall export`.
- **Script:** `[12]` Set-Firewall. Let it schedule the rollback, *deliberately* don't type YES, and watch it revert.
- **Discuss:** Why doesn't "default inbound = Block" break the DC? What does `-DisableOtherInboundRules` change?

## Session 6: Hardening, logging, watch loop (45 min)
- `[13]` Harden-Baseline module by module: what attack does each one stop? (Responder → LLMNR/NBT-NS, mimikatz → WDigest/LSA protection, PrintNightmare → spooler)
- `[L]` Setup-Logging, then generate events (failed logon, new user) and find them in Event Viewer / Graylog.
- `[W]` → `[5]` change baseline, add a user, `[W]` → `[3]` diff.
- `[S]` snapshot, turn on WDigest by hand, `[W]` → `[1]` shows it as NOT BY THE TOOLKIT, `[5]` shows WDigest as REGRESSED, `[U]` puts it back.

## Session 7: Incident response tabletop (45 min)
Walk through `docs/incident-response.md` scenarios A-C on a planted box and write the incident report using the template.

---

## Plant list (lab only!)
- Local admin `support2`; domain user in Domain Admins created "today"
- Scheduled task under `\Microsoft\Windows\` running `powershell -enc ...` from `C:\Users\Public`
- Run key pointing to `C:\ProgramData\updater.exe`
- IFEO Debugger on `utilman.exe`
- Defender exclusion for `C:\Windows\Temp`
- `wp-content\uploads\2024\img.php` containing `eval($_POST['x'])` (a harmless test string is fine)
- A user whose description is `temp pw: FakeLabPw-1` (obviously fake; the audit flags the "pw:" pattern)
- An SPN on a Domain Admin account (`setspn -S http/fake trex\someadmin`)

Remove every plant after the session. `Watch-Changes.ps1` against a pre-plant baseline is a good way to check.
