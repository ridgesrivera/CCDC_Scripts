# WCComps 2026 Invitational 3 ("Flokid"): Windows brief

What the team packet tells us, and how to use the toolkit with it. **The scripts stay generic.** Nothing
here is in the code. This page only says which panel options matter most for this environment.

## The environment (from the packet)
| | |
|---|---|
| Internal network | `192.168.220.0/24` |
| External (NAT) | `10.100.1XX.Y` (XX = team number) is 1:1 NAT to `192.168.220.Y`, done by the OpenWRT router (`.2`) |
| Windows boxes | **Server 2022**: food ordering service (`.10`). **Server 2019**: Active Directory (`.79`) |
| Other boxes | Alpine fileshare, Rocky (Gitea), Lubuntu (Wabbit), Ubuntu (help site), Alpine (tickets), Fedora (home manager), Mint (POS). The packet warns there may be **unlisted boxes**: inventory early |
| Protocols in play | RDP, SSH, SNMP, SMTP, IMAP, POP3, VNC, OpenVPN, HTTP/HTTPS, Telnet, DNS, NFS, SMB, FTP |
| Scoring | ~10 services (plus or minus 2), checked every **2-4 min**. **SLA penalty after 5 failed checks**, so you have roughly 10-20 minutes to fix a down service |
| Credentials | Box creds at 9:00 via Discord. Scored services listed in the scoring portal (Quotient). Scored-account password changes go through **the scoring portal**, not tickets |
| Router | Team-managed OpenWRT. A router reset is **-100 points**. Don't block the scoring engine. Not a Windows box, so it's out of scope for this toolkit |

## What this means for us

**1. Scoring traffic comes from outside the NAT.**
Scored connections arrive from the scoring engine's address, not from `192.168.220.x`. So:
- In LIVE ALERTS, the scorer shows up as an "untrusted network logon". Check it's the scoring engine (it logs in to scored accounts on a steady 2-4 minute rhythm), then **`D` → `3` Trust** it on every box so it stops paging you.
- The firewall allowlist (`12`) already keeps scored ports open to **any** source. Keep it that way. Admin ports (RDP/WinRM) are limited to this subnet plus your live session. If teammates come in over the NetBird VPN from another address, run `N` (who is on this box) to see their IP, then add it as an admin source.

**2. Down time is expensive. Watch services continuously.**
Run `C` in loop mode (new window) on both Windows boxes once the scoreboard is green, and save the baseline first (`C` → `3`). It says *why* a service is down (stopped, wrong bind address, firewall rule, defaced page, DB error).

**3. The penalties tell us what to protect.**
| Red Team action | Points | Toolkit |
|---|---|---|
| Admin on a box | -100 | `D` alerts, `10` rotate, `O` kick sessions, `R` remove persistence |
| User/password dump (SAM, AD hashes) | -50 | DC: `6` (DCSync holders), `15` Harden-AD, `5` vulns (Zerologon, NoPAC). Alerts flag Kerberoasting |
| Customer PII (name + address + card) | **-200** | `8` on the food-ordering box, both modes (files, and SQL Server if present) |
| Credit card numbers | -50 | `8` (Luhn-checked) |
| Sensitive files / config | -25 | `8`, `14` (config file permissions) |

**4. Incident reports earn points back.** File them in the ticket portal with detail. Use `D` → `5` (story of an IP), `I` (incident worksheet), and the evidence records from `R`.

**5. Injects: you write them.** The packet says AI-generated inject text scores **zero**. Toolkit output (reports, CSVs, screenshots) is fine as evidence. The prose must be your own. Injects must be PDFs named like `inject04_team13.pdf`. `9` (software audit) gives a CSV that helps with "inventory" style injects.

## Per-role plan

### Active Directory box (Server 2019)
1. `0` guided run: alerts on, backup (GPOs, DNS, LDIF), baselines.
2. `6` AD + GPO and `7` security policy. Then `15` Harden-AD (pre-auth, reversible encryption).
3. `10` rotate **Domain Admins** first. **Careful:** the Linux boxes (Gitea, help site, ticketing) may authenticate against AD with a bind/service account. Rotating it breaks their scored logins. Find bind accounts in `2` (service-looking names, SPNs) and leave them until you know what uses them.
4. Keep DNS healthy: it's almost certainly scored, and every other box depends on it. `C` checks DNS answers against the baseline.
5. If the domain was compromised: `17` reset krbtgt (twice, with the enforced wait).

### Food ordering box (Server 2022)
1. `0` guided run. `1` overview shows what the app is (IIS? another web server? which database?).
2. `K` → `2` per-service backup **before** touching the app (IIS config, web root, database dump).
3. `8` PII hunt: this box most likely holds customer orders, names, addresses and cards.
4. `14` IIS/PHP hardening if IIS. `16` SQL hardening if SQL Server (sa, xp_cmdshell). MySQL: `services\MySQL.ps1`.
5. `C` loop with the site URL. It catches defacement and "database connection error" pages.

## Timeline reminders
- 9:00: VPN up, credentials in Discord. Run `0` on both Windows boxes immediately.
- First hour: PII hunt, passwords (scored accounts through the scoring portal), firewall, inventory any unlisted boxes.
- All day: alert windows open, `C` loops running, Discord voice channel monitored (Orange Team checks come through Discord and tickets).
