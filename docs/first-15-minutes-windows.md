# First 15 Minutes: Windows

Open the panel: **double-click `CCDC-Toolkit.bat`** (it asks for admin).
No copy on the box yet? Admin PowerShell: `irm https://raw.githubusercontent.com/ridgesrivera/CCDC_Scripts/main/install.ps1 | iex`

> Golden rule: **a broken service hurts more than a slightly insecure one.**
> Before every change, ask: "Could this stop users or our checks from connecting?" Everything the toolkit
> changes can be undone: `W` shows what changed, `U` / `12 -> 3` / `11 -> 2` put it back.

## Minutes 0-5: press `[0]` (zero)

It does these, in order, asking before each one:

| Step | What | Why |
|---|---|---|
| 1 | **Snapshot** | Records how the box looked before anyone touched it, so you can see and undo any later change |
| 2 | **Backup** | **DC**: Active Directory (GPOs, DNS zones, AD objects). **Web server**: IIS config and web roots. Nothing else for now |
| 3 | **LIVE ALERTS on** | You see Red Team the moment they log on, add a user, make a task... Keep the watch window open |
| 4 | **Ways in, ports, SSH keys** | Every open port with its program; odd or risky ones flagged. Every SSH key on the box. Who is connected now |
| 5 | **Admin users** | Who is in admin groups that should not be; roastable accounts; passwords in descriptions |
| 6 | **PII** | Card numbers, SSNs, passwords in files and SQL Server: restrict or move them |
| 7 | **Vulnerability check** | What Red Team can walk straight into (Zerologon, PrintNightmare, EternalBlue, relay, cleartext passwords) |

## Minutes 5-15: by hand, in this order

| # | Do this | Panel | Careful |
|---|---|---|---|
| 1 | **Rotate admin passwords** (Administrator, Domain Admins). Write them on paper | `10` | Scored / service accounts: Password Change Request first. A service account used by another box breaks that box |
| 2 | **Kick unknown admins** that step 5 flagged: log off + disable | `X` → `1` | Disable, never delete. Ask the team before touching an account you don't recognise but that might be a service |
| 3 | **Hardening walkthrough**: apply the SAFE steps, read CAUTION ones | `12` | DANGER = evidence says it will break something: skip it |
| 4 | **Basic firewall**: keeps everything that's listening open, blocks other inbound | `11` → `1` | Test a NEW RDP connection before typing YES. It auto-reverts in 3 min if you don't |

## After 15 minutes

| When | Do this | Panel |
|---|---|---|
| Next | Persistence hunt (tasks, services, Run keys, web shells) and remove what's bad | `3`, then `R` |
| Next | Find PII / card data / passwords in files | `7` |
| Any time something looks wrong | **Find attacks**: names the attack and lists what to do | `E` |
| DNS stopped answering | **Fix DNS**: standard fixes, then tells you what is left | `F` |
| Defender off / an exclusion was added | **Defender on**: brings it back and verifies | `16` |
| Alert about an IP or user | Kick the user, block the IP | `X` |
| Something broke after a change | See what changed, put it back | `W` → `1`, then `U` |
| Hourly | C2 beacon scan, who is on the box | `8`, `N` |

## Don'ts
- Don't reboot a box mid-round without telling the captain.
- Don't delete accounts. Disable them (re-enable is instant).
- Don't write passwords in a file or a chat. Paper, handed to the captain.
- Don't run a script you can't explain: `?` plus the key (e.g. `?12`) explains it.
