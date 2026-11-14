# windows/services/: one script per Windows service

Each script covers one Windows service or role and does four things:

1. **Info**: what the service is, which Windows service names it uses, its binary, signature, run-as account and service DACL. It lists the ports it should use and what is actually listening, live connections grouped by remote IP, and the inbound firewall rules that cover those ports. It finishes with service-specific checks for red team activity, how red team abuses the service, and hardening steps.
2. **Backup**: writes to `C:\ccdc\backups\services\<Service>\<yyyyMMdd_HHmmss>\`. The folder is locked to Administrators and SYSTEM. Every backup includes the service's registry definition, `sc qc`, the service DACL, failure actions, a `MANIFEST.csv` of SHA256 hashes, and `BACKUP_INFO.json`.
3. **Restore**: restores from the latest backup, or from the folder given with `-RestoreFrom`. It verifies the backup hashes first and asks you to type `YES`. Most scripts also list what red team **added** since the backup: new users, shares, tasks, GPOs, firewall rules, keys.
4. **Verify**: re-hashes the latest backup to show whether someone tampered with it.

Every script is safe to run on any box. If its service is not installed, it prints `[SKIP]` and exits.

## Quick start (first 15 minutes)

```powershell
# elevated PowerShell, from the repo folder
Set-ExecutionPolicy -Scope Process Bypass -Force
cd .\windows\services

.\Invoke-AllServices.ps1 -Action Detect            # what's on this box?
.\Invoke-AllServices.ps1                           # back up everything that's present
.\Invoke-AllServices.ps1 -OffboxPath \\<teambox>\share   # ...and copy it off the box
.\Invoke-AllServices.ps1 -Action Info              # full write-up of every service -> C:\ccdc\logs
```

For a single service:

```powershell
.\DNS.ps1                   # Info + Backup (default -Action All)
.\DNS.ps1 -Action Info
.\DNS.ps1 -Action Backup
.\DNS.ps1 -Action Restore   # latest backup, asks YES
.\DNS.ps1 -Action Restore -RestoreFrom C:\ccdc\backups\services\DNS\20261114_091500
.\DNS.ps1 -Action Verify
```

`-Force` skips the YES prompts. `-BackupRoot D:\somewhere` changes the backup location.

`windows\Launch-Toolkit.ps1` has a menu option **[S]** under BACKUP / LOGGING / HUNT. It asks which action you want (detect, back up, info, verify) and, for a backup, an optional off-box path, then runs `Invoke-AllServices.ps1`.

These scripts complement `..\backup\Backup-Box.ps1`. Backup-Box takes one quick snapshot of the whole box. These scripts go service by service and can also restore.

## Scripts

| Script | Service / role | Ports | What gets backed up | Restore |
|---|---|---|---|---|
| `ActiveDirectory.ps1` | AD DS on a DC (NTDS, Kdc, Netlogon, DFSR, ADWS) | 53, 88, 135, 389, 445, 464, 636, 3268/9, 9389 | Users, groups, memberships, OUs and computers as CSV; LDIF; ACL baseline of the domain root and AdminSDHolder; SYSVOL. With `-IncludeNTDS` it also takes an ntds.dit IFM copy, and with `-SystemStateTarget E:` a wbadmin system state backup | Undeletes from the Recycle Bin, recreates missing OUs, groups and users, re-adds memberships, flags **new** privileged-group members |
| `DNS.ps1` | DNS Server | 53, 135 | Each zone exported as a file and as a records CSV; zone metadata; forwarders; `System32\dns`; registry | Reloads zones from files and converts them back to AD-integrated; restores forwarders |
| `DHCP.ps1` | DHCP Server | 67/68 UDP, 547, 647 | `Export-DhcpServer -Leases`, `Backup-DhcpServer`, netsh export | `Import-DhcpServer` |
| `GroupPolicy.ps1` | GPOs (run on a DC) | 445, 389 | `Backup-GPO -All`, HTML report, **links**, permissions, NETLOGON scripts | `Restore-GPO`/`Import-GPO`, relinks, flags **new** GPOs |
| `ADCS.ps1` | Certificate Authority (CertSvc) | 135, 80/443 | CA database and private key (password protected), CA registry config, templates, CRLs | `Restore-CARoleService` |
| `IIS.ps1` | IIS (W3SVC/WAS) | 80, 443, 8080, 8172 | appcmd backup, inetsrv config, every site's physical path, app pools, bindings, SSL bindings. With `-ExportCertsPassword` it also exports the certificates as .pfx | `appcmd restore backup` plus content. `-Mirror` deletes files that are not in the backup (removes webshells) |
| `FTP.ps1` | IIS FTP and FileZilla Server | 21, 20, 990, 14147/8 | FTP site config and FTP roots, FileZilla XML config | Content and config |
| `SMB_FileShares.ps1` | File shares (LanmanServer) | 445, 139 | Share definitions (registry and XML), share permissions, NTFS ACLs, **share contents** (`-SkipContent`, `-MaxShareGB`) | Recreates shares, resets permissions to the backup, restores files, flags **new** shares |
| `NFS.ps1` | Server for NFS | 2049, 111 | NFS share definitions, permissions, contents | Recreates shares and permissions |
| `MSSQL.ps1` | SQL Server (all instances) | 1433, 1434 | COPY_ONLY `.bak` of every database, logins, roles, sp_configure, Agent jobs. Uses .NET SqlClient, so it works on Server Core | `RESTORE DATABASE ... WITH REPLACE` (`-Database x` for one database) |
| `MySQL.ps1` | MySQL/MariaDB (XAMPP, WAMP, standalone) | 3306 | `mysqldump --all-databases` plus one dump per database, my.ini | Imports one database or all |
| `Mail.ps1` | hMailServer, IIS SMTP, MailEnable | 25, 465, 587, 110, 995, 143, 993 | Config, mailboxes, built-in DB (briefly stops hMailServer unless `-NoStop`) | Files and service restart |
| `Exchange.ps1` | Exchange Server | 25, 443, 587, 110/143... | Connectors, accepted domains, virtual directories, mailboxes and permissions, transport rules, certificates, front-end files. `-ExportMailboxesTo \\unc` queues PST exports | None (config reference only) |
| `WebServers_NonIIS.ps1` | Apache/XAMPP/WAMP, nginx, Tomcat | 80, 443, 8080, 8009, 8443 | conf folders, doc roots / htdocs / webapps, php.ini | Content and config (`-Mirror`) |
| `RDP.ps1` | Remote Desktop (TermService) | 3389 | Terminal Server registry, RDP group members, user rights, hashes of the sticky-keys binaries | Registry; flags **new** RDP users |
| `WinRM.ps1` | WinRM / PS Remoting | 5985, 5986 | WSMAN registry, listeners, PSSession configurations | Registry; flags **new** endpoints |
| `OpenSSH.ps1` | OpenSSH Server | 22 | `ProgramData\ssh` (config and host keys), every authorized_keys file | Puts the exact key files back; flags unknown key files |
| `VNC.ps1` | TightVNC, UltraVNC, RealVNC, TigerVNC | 5900, 5800 | Registry / ultravnc.ini | Registry / ini |
| `OpenVPN.ps1` | OpenVPN | 1194 | config, config-auto, easy-rsa pki | Files |
| `SNMP.ps1` | SNMP Service | 161/162 UDP | Communities, permitted managers, traps | Exact registry restore (removes communities red team added) |
| `WindowsFirewall.ps1` | Defender Firewall (MpsSvc) | none | `netsh advfirewall export` (.wfw) and rules CSV | `netsh advfirewall import`; lists rules that will be removed |
| `ScheduledTasks.ps1` | Task Scheduler | 135 | Every task as XML, CSV baseline, Tasks folder, TaskCache | Re-registers deleted or changed tasks; offers to **disable new tasks** |
| `PrintSpooler.ps1` | Print Spooler | 445, 135, 9100 | PrintBrm export, printer registry and policies | PrintBrm restore |
| `W32Time.ps1` | Windows Time | 123 UDP | W32Time registry | Registry and resync |

## Things to know

- **Back up before you harden.** Run `WindowsFirewall.ps1 -Action Backup` before `..\harden\Set-Firewall.ps1`. Then a bad rule takes one command to undo.
- **Copy backups off the box.** Red team with admin can delete `C:\ccdc\backups`. Use `-OffboxPath`, or copy the folder to your jump box.
- **Some backups contain secrets:** `ActiveDirectory.ps1 -IncludeNTDS` (every password hash), the ADCS CA key, OpenSSH host keys, IIS .pfx files, OpenVPN keys. Your packets list "recovery of user IDs and passwords from a team system (AD with hashes, SAM file)" at **-50 points**. Only create these when you need them, keep them off the box or encrypted, and delete them when you're done.
- **Database scripts need credentials** when integrated auth doesn't work:
  `.\MSSQL.ps1 -SqlUser sa -SqlPassword '...'` and `.\MySQL.ps1 -DbUser root -DbPassword '...'`.
  `Invoke-AllServices.ps1` accepts the same parameters and passes them on.
- **ADCS asks for a password** to protect the CA key, unless you pass `-KeyPassword`.
- **Restore is per service on purpose.** Look at what Info says before you restore. After every restore, **check the scoring engine**.
- **Do not touch the competition's VPN or scoring agent** (for example NetBird, `C:\ProgramData\netbird`). It is how the scoring engine and your team reach the box.
- Local accounts and the SAM are not a "service", so `..\audit\Audit-Users.ps1` covers them. Registry Run keys and persistence are covered by `..\audit\Audit-Persistence.ps1`.

## Adding a new service

Copy any small script (for example `SNMP.ps1`) and edit the `$Def` hashtable: `Name`, `Title`, `ServiceNames`, `Description`, `Ports`, `KeyPaths`, `RedTeam`, `Hardening`, `Detect`, `InfoExtra`, `Backup`, `Restore`. Everything else (port, connection and firewall checks, locked backup folder, manifest, verify, YES prompt) comes from `_ServiceCommon.ps1`. Keep files **ASCII-only**: Windows PowerShell 5.1 reads UTF-8 files without a BOM as ANSI.
