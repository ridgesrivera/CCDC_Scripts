# windows/alerts: Live Alerts

Instant alerts when Red Team acts on a Windows box: who did it, from which IP and PC, how they got in,
what that IP did before (attack chain), and the commands to undo it. Standalone on purpose: installs to
`C:\bt` and deploys from one paste.

| File | What it is |
|---|---|
| `bt-alerts.ps1` | The alert tool (`-Install`, `-Watch`, `-Trust`, `-Block`, `-Chain`, `-Snooze`, `-Backfill`, `-Remove`) |
| `bt-selftest.ps1` | Fires every detection for real, PASS/FAIL, self-cleaning |
| `whoshere.ps1` | One-screen "who's on this box" + diff vs baseline (read-only) |
| `pii-hunt.ps1` | PII in files, shares and SQL Server (read-only) |
| `bt-deploy-PASTE.txt` | All four scripts + install in one paste. **Generated**: `python3 tools/build-alert-paste.py` |

Deploy: panel `[D]` -> `[1]`, or paste `bt-deploy-PASTE.txt` into an Admin PowerShell.
Then keep the **BT ALERTS** window open and `-Trust` the scorer IP when it appears.

Full design, every detection, limits and test status: [`docs/live-alerts.md`](../../docs/live-alerts.md).
