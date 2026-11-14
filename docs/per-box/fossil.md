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
- `Set-Firewall.ps1`: keep 22 and 3389 allowed (they're in config). sshd is auto-detected and added to admin ports, but if SSH is *scored* it must be open to the scoring engine. Keep it in `-AllowTcp` / config scored ports, not only in admin sources.
- Editing `sshd_config`: back it up first and run `sshd -t` before restarting the service.
