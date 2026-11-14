# legacy/: toolkit v1 (kept unchanged for reference)

These are the original scripts, moved here with `git mv` so their history is preserved. They still work:
`legacy\00_LAUNCH.ps1` finds its siblings via `$PSScriptRoot`.

Prefer the v2 toolkit in `windows\` (`windows\Launch-Toolkit.bat`). Known differences/limits of v1:
- Audit scripts also change things (e.g. `01_UserAudit` removes admins, `03_ServiceAudit` disables services). v2 separates audit from change.
- `02_PasswordReset` applies one typed password to every account, including krbtgt. v2 generates unique random passwords and excludes scored/service accounts.
- `09_NonWinServices` uses PowerShell 7 syntax (`?.`) and fails on Windows PowerShell 5.1.
- Logs go to `C:\CCDC_Logs` / `C:\BlueTeam`. v2 uses `C:\ccdc\logs`.

| v1 script | Closest v2 replacement |
|-----------|------------------------|
| 00_LAUNCH | windows\Launch-Toolkit.ps1 |
| 01_UserAudit | audit\Audit-Users.ps1 (+ harden\Disable-Accounts.ps1) |
| 02_PasswordReset | harden\Rotate-Passwords.ps1 |
| 03_ServiceAudit | recon\Get-BoxOverview.ps1, audit\Audit-Network.ps1 |
| 04_Backup | backup\Backup-Box.ps1 |
| 05_PIIScanner | *(no v2 equivalent yet)* |
| 06_HiddenFiles | audit\Audit-Persistence.ps1 (web shells, System32); ADS scan not ported |
| 07_ADSecurity | audit\Audit-Users.ps1, audit\Audit-AD-GPO.ps1 |
| 08_Firewall | harden\Set-Firewall.ps1 |
| 09_NonWinServices | harden\Harden-IIS-PHP.ps1 (PHP part) |
| Invoke-PersistenceHunt | audit\Audit-Persistence.ps1 |
| Invoke-PersistenceRemoval | harden\Harden-Baseline.ps1 -Only RemoveIfeoDebuggers + docs\incident-response.md |
| Invoke-AttackResponse / Invoke-ThreatMonitor | hunt\Watch-Changes.ps1 covers state drift; real-time event alerting not ported |
