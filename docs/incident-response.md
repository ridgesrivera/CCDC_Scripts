# Incident Response: "It's hour 3 and we found something"

Same five steps for every finding: **Contain → Preserve → Remove → Verify → Document.**
Do preserve *before* remove: the evidence is what earns points on an incident report inject.

Start an IR note on paper (or the team doc) right away: **time found, box, who found it, what you saw.**

---

## A. Rogue admin account (e.g. `hacker` in Domain Admins)

| Step | Do | Command |
|------|----|---------|
| Contain | Disable it (don't delete) | `harden\Disable-Accounts.ps1 -Users hacker` |
| Contain | Kick live sessions | `quser` then `logoff <ID>` |
| Preserve | Record who created it and when | `audit\Audit-Users.ps1` (Security log 4720/4728/4732 section) · `Get-ADUser hacker -Properties whenCreated,memberOf` |
| Remove | Take it out of privileged groups | `Remove-ADGroupMember "Domain Admins" hacker` / `net localgroup administrators hacker /delete` |
| Remove | Assume it saw everything: rotate the creds it could have read | `harden\Rotate-Passwords.ps1 -Group "Domain Admins"` |
| Verify | Look for what it left behind | `audit\Audit-Persistence.ps1`, `audit\Audit-AD-GPO.ps1` (DCSync rights, GPO edits, AdminSDHolder) |
| Verify | Watch for it coming back | `hunt\Watch-Changes.ps1 -Loop` |

If it had Domain Admin, also plan a **krbtgt double reset** (golden tickets survive password changes):
reset krbtgt → wait for replication (single DC: a few minutes) → reset again. Use Microsoft's
`New-KrbtgtKeys.ps1` if available, or `Set-ADAccountPassword krbtgt -Reset` twice. Tell the captain first:
existing Kerberos tickets get invalidated and services may hiccup.

## B. Web shell (e.g. `C:\inetpub\wwwroot\wp-content\uploads\x.php`)

| Step | Do | Command |
|------|----|---------|
| Contain | Stop it executing **without** taking the site down: move it out of the web root | `New-Item C:\ccdc\quarantine -ItemType Directory -Force; Move-Item <file> C:\ccdc\quarantine\` |
| Preserve | Hash + timestamps + first lines | `Get-FileHash <file>; Get-Item <file> \| fl *Time*; Get-Content <file> -TotalCount 20` |
| Preserve | Find the request that dropped/used it | `Select-String -Path C:\inetpub\logs\LogFiles\W3SVC*\*.log -Pattern 'x.php'` → note the source IP |
| Remove | Check for siblings (they rarely plant one) | `audit\Audit-Persistence.ps1` (web shell section), files with the same timestamp |
| Remove | Close the hole: how did it get there? | WP admin compromised? → reset WP admin passwords, `harden\Harden-IIS-PHP.ps1` (DISALLOW_FILE_EDIT, plugin list) |
| Verify | Site still scores, shell is gone | browse the site, check the scoreboard, request the old URL (expect 404) |

Don't keep a working web shell in quarantine under a web root. `C:\ccdc\quarantine` is outside IIS.

## C. Unknown scheduled task / service

| Step | Do | Command |
|------|----|---------|
| Contain | Disable (not delete) | `Disable-ScheduledTask -TaskName <n> -TaskPath <p>` · `Stop-Service <s>; Set-Service <s> -StartupType Disabled` |
| Preserve | Export the definition | `Export-ScheduledTask -TaskName <n> -TaskPath <p> > C:\ccdc\quarantine\task.xml` · `sc.exe qc <s>` |
| Preserve | Hash the binary/script it runs | `Get-FileHash <path>`, then move a copy to quarantine |
| Remove | Delete once preserved | `Unregister-ScheduledTask -TaskName <n> -Confirm:$false` · `sc.exe delete <s>` |
| Verify | Check the other persistence spots and the creating account | `audit\Audit-Persistence.ps1`; Security log 4698 (task created) / 4697 (service installed) |

## Document for the inject
Incident reports are usually graded on: **what happened, when, which systems, how detected, what you did, how you'll prevent it.**
Pull facts from:
- `C:\ccdc\logs\*.log`: every action our scripts took, with timestamps and undo commands
- `C:\ccdc\reports\`: audit output showing the finding
- Rollback files (`*_rollback.ps1`, `*_reenable.ps1`): exactly what was changed
- Event IDs worth quoting: 4624/4625 logons, 4720 user created, 4728/4732/4756 group adds, 4698 task created, 4697/7045 service installed, 4104 PowerShell script block, Sysmon 1/3/11

Template:
```
Time detected : 13:42      Box: fernbank (.37)      Found by: <name>
What          : PHP web shell at wp-content\uploads\x.php (SHA256 ...)
How detected  : Audit-Persistence.ps1 web shell check
Source        : 10.x.x.x per IIS log, first request 13:05
Actions       : 13:44 quarantined; 13:50 reset WP admin passwords; 13:55 DISALLOW_FILE_EDIT
Impact        : none to scoring (site stayed up)
Prevention    : file edit disabled, uploads folder blocked from executing PHP, watch loop running
```
