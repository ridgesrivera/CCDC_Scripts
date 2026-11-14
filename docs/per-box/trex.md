# trex: Domain Controller (Windows Server 2016)

**IP (practice):** .12 · **Domain:** GREAT / great.local

## Role
Domain controller and DNS for the whole pod. If trex is down, domain logins on fossil/fernbank fail, Keycloak federation on hellcreek fails, and name resolution may fail pod-wide.

## Likely scored
DNS (53), LDAP (389/636), Kerberos (88), SMB (445), maybe RDP (3389). Confirm against the packet.

## Dependencies (don't break these)
- **Keycloak on hellcreek** probably binds to LDAP here with a service account (look for names like `keycloak`, `ldap`, `svc_*`). Changing its password breaks SSO unless the bind credential in Keycloak (User Federation → LDAP) is updated at the same moment. `Rotate-Passwords.ps1` auto-skips service-looking names for this reason.
- Domain users the scoring engine logs in with (on fossil RDP/SSH, etc.) need a **Password Change Request** first.
- Firewall: `Set-Firewall.ps1` auto-adds AD ports on a DC, including RPC dynamic 49152-65535. Don't remove them.

## Top risks
1. Default/packet creds on Domain Admins → rotate first (`[7]`, `-Group "Domain Admins"`).
2. Rogue DA / DCSync rights / GPO backdoor → `[2]`, `[6]`.
3. Zerologon / NoPAC / PrintNightmare (old 2016 patch level) → `[5]`; `[10] -Only DisableSpoolerOnDC`.
4. krbtgt (golden tickets) → if Red Team had DA, reset krbtgt **twice** with time for replication between (see incident-response.md). Coordinate: it can briefly disrupt Kerberos.
5. AS-REP/Kerberoastable accounts → `[2]` flags them.

## First moves
`[1]` → `[7]` (Domain Admins) → `[2]` → `[B]` (IFM + GPO + DNS) → `[6]` → `[3]` → `[9]` → `[10]`.
