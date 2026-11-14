# fossil: Windows 10 workstation

**IP (practice):** .20

## Role
User workstation, probably domain-joined to GREAT. Scoring likely logs in over **RDP (3389)** and **SSH (22, OpenSSH Server)**.

## Dependencies
- Domain logins need trex (DC + DNS) reachable.
- The scoring user (local or domain) must keep working. Don't rotate it without a PCR, and don't remove it from Remote Desktop Users.

## Top risks
1. Shared local Administrator password (no LAPS) → rotate local Administrator (`[7]`, `-Scope Local -Users Administrator`).
2. `C:\ProgramData\ssh\administrators_authorized_keys` with a Red Team key = passwordless admin SSH → `[3]` lists every key.
3. Sticky keys / utilman backdoor on the RDP login screen → `[3]`, then `[10] -Only RemoveIfeoDebuggers`; NLA check in `[4]`.
4. Defender disabled or excluded paths → `[3]` (exclusions), `[5]` (status), `[10] -Only EnableDefenderRealtime`.

## Careful with
- `Set-Firewall.ps1`: 22 and 3389 are scored here (they're in config), so the script opens them to **any** source rather than only admin sources, because the scoring engine must reach them. If you pass `-AllowTcp` by hand, include 22 and 3389. Since they're open, protect them with strong passwords + NLA (`[10] -Only RequireRdpNla`).
- Editing `sshd_config`: back it up first and run `sshd -t` before restarting the service.
