# fernbank: IIS + PHP (Windows Server 2022): WordPress + MediaWiki

**IP (practice):** .37

## Role
Public web apps. Scoring likely checks HTTP/HTTPS and probably page content or a login on WordPress and MediaWiki.

## Dependencies (the big one)
- **Both databases live on hatchery (MySQL, .76).** `wp-config.php` (`DB_HOST`, `DB_USER`, `DB_PASSWORD`) and `LocalSettings.php` (`$wgDBserver`, `$wgDBuser`, `$wgDBpassword`) hold those creds.
- If the Linux team changes a DB user's password on hatchery, **you must update the matching config file here at the same time**, or both scored sites go down. Agree on timing over voice before either side changes anything.
- `Harden-IIS-PHP.ps1` prints DB host/user/name (never the password) so you can see this dependency.

## Top risks
1. Web shells (Red Team uploads `.php`/`.aspx`) → `[3]` web shell section; PHP inside `wp-content\uploads` is always RED.
2. WP admin with packet password / Red Team-created admin → `[11]` lists admins (registered in last 3 days = RED). Reset passwords in wp-admin (WP users aren't Windows users).
3. Theme/plugin editor used to plant code → `[11]` adds `DISALLOW_FILE_EDIT`.
4. Malicious must-use plugin (`wp-content\mu-plugins`) → `[11]` flags every one.
5. `wp-config.php` writable by IIS_IUSRS → `[11]` checks ACLs.

## Careful with
- Writing PHP files from PowerShell 5.1: `Set-Content -Encoding UTF8` adds a BOM and breaks PHP. The script uses BOM-less writes; do the same if you edit by hand (Notepad on 2022 saves UTF-8 without BOM by default).
- `disable_functions` in php.ini can break WordPress/MediaWiki. Change one thing, then reload the sites.
- Firewall: 80/443 open to everyone; RDP only from admin sources.

## First moves
`[1]` → `[7]` local Administrator → `[11]` (backup + WP hardening) → `[3]` → `[9]` → `[B]`.
