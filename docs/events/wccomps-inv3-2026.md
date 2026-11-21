# WCComps 2026 Invitational 3 ("Flokid"): Windows notes

What the team packet says about the environment, and how the toolkit fits it. **The scripts stay generic**:
nothing here is in the code.

## The environment (from the packet)
| | |
|---|---|
| Internal network | `192.168.220.0/24` |
| From outside | `10.100.1XX.Y` (XX = team number) is 1:1 NAT to `192.168.220.Y` through the OpenWRT router (`.2`) |
| Windows boxes | **Server 2022**: food ordering service (`.10`). **Server 2019**: Active Directory (`.79`) |
| Other boxes | Linux: fileshare, Gitea, Wabbit, help site, tickets, home manager, POS. The packet warns there may be **unlisted boxes**: inventory early |
| Protocols in use | RDP, SSH, SNMP, SMTP, IMAP, POP3, VNC, OpenVPN, HTTP/HTTPS, Telnet, DNS, NFS, SMB, FTP |
| Credentials | Box credentials at 9:00 via Discord. Scored-account password changes go through **the scoring portal** |
| Router | Team-managed OpenWRT. Not a Windows box: out of scope for this toolkit. Do not block the scoring engine |

## What it means for us
- **Traffic from the scoring engine and customers comes from outside the NAT.** In LIVE ALERTS it appears as an untrusted network logon on a steady rhythm against the same accounts. Once you are sure it is the checker, trust it: `D` → `3`.
- **The basic firewall (`11`) keeps every listening service open to any source**, so it does not cut off the checker or customers.
- **The DC's service accounts may be used by the Linux boxes** (Gitea, help site, tickets often bind to AD). Rotating such an account breaks that box. `2` lists service accounts (SPNs); ask before rotating them.
- **LDAP signing** in the walkthrough (`12`) will show DANGER if the DC has seen unsigned binds: that is those Linux apps. Leave it off.
- **Injects are written by you.** The packet says AI-written inject text scores zero. Toolkit output (reports, screenshots) is fine as evidence; the words must be yours. PDFs named like `inject04_team13.pdf`.

## Per box

### Active Directory box (Server 2019)
1. `0`: snapshot, backup (GPOs, DNS zones, AD objects), alerts on, who is on, users, vulns.
2. `10` rotate Domain Admins first (not service accounts until you know what uses them). `X` kick admins that are not your team.
3. `12` walkthrough: on a DC it also does Guest, Pre-Windows 2000 group, machine account quota, DNS zone transfers, risky account flags. All go into one GPO and can be undone.
4. `6` AD + GPO audit. If the domain was compromised (DCSync, ntds.dit): `15` reset krbtgt twice.
5. DNS: every other box depends on it. Do not restrict zone transfers if a secondary DNS server exists.

### Food ordering box (Server 2022)
1. `0`: the backup includes the IIS config and web roots automatically. `P` → `2` also backs up the database if it is SQL Server / MySQL.
2. `7` PII hunt: customer orders, names, addresses, cards most likely live here.
3. `13` IIS / PHP hardening; `14` SQL hardening if SQL Server (sa, xp_cmdshell).
4. `E` regularly: web shells (the web server starting cmd / powershell) and web login guessing (IIS 401s) show up there.

## All day
- LIVE ALERTS windows open on both boxes; `E` when anything looks off; `8` and `N` every hour.
- Discord voice channel monitored: Orange Team checks come through Discord and tickets.
- Incident reports: `D` → `5` (story of an IP), `I` (incident worksheet), evidence from `R`.
