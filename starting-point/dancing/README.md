# Hack The Box — Dancing

| Field | Value |
|---|---|
| Platform | Hack The Box — Starting Point (Tier 0) |
| Name | Dancing |
| Difficulty | Very Easy |
| Category | SMB / Windows |
| OS | Windows |
| Date | 2026-10-17 |
| Tags | #smb #null-session #windows #enumeration |

## TL;DR
> A single exposed service: SMB on port 445. The `WorkShares` share is reachable through a **null session** (no authentication), and the flag file sits inside a user's folder on it. No exploit involved — just enumeration and an access-control misconfiguration.

---

## Recon

Only one port to look at, so a targeted scan with version detection and default scripts:

```bash
nmap -sCV -p445 10.129.53.112 -oN nmap/smb
```

```
445/tcp open  microsoft-ds  (workgroup: WORKGROUP)
```

**What stands out.** Port 445 is SMB (Server Message Block). On a Windows host it's the natural starting point: before hunting for exploits, the cheapest thing to try is whether the server grants **anonymous access** to its shares. Plenty of misconfigured SMB services expose read access without asking for credentials, so it's always worth checking first.

## Enumeration

### SMB — listing the shares

`smbclient`'s `-L` flag lists the exported shares; `-N` forces an attempt with no password (null session):

```bash
smbclient -L //10.129.53.112/ -N
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
WorkShares      Disk
```

**The reasoning.** The first three (`ADMIN$`, `C$`, `IPC$`) are default Windows administrative shares: always present and not reachable without privileges, so I discard them immediately. `WorkShares` is the **custom** one — non-standard, added by whoever set the machine up. It's the only share worth trying anonymously.

### Anonymous access to WorkShares

```bash
smbclient //10.129.53.112/WorkShares -N
```

The connection succeeds with no password: the share accepts a null session. From there, I browse the contents with FTP-like commands:

```
smb: \> ls
  Amy.J      D    0  ...
  James.P    D    0  ...

smb: \> cd James.P
smb: \James.P\> ls
  flag.txt   A   32  ...
```

Two user-named folders; `James.P` contains `flag.txt`.

## Foothold / Initial access

There's no real "exploit" here: the initial access **is** the misconfiguration. The share allows reading files without authentication, so it's enough to download the file:

```
smb: \James.P\> get flag.txt
```

```bash
cat flag.txt
```

```
HTB{REDACTED}
```

> The flag is intentionally redacted — flags are never published in writeups.

## Privilege escalation

Dancing exposes a **single flag** (user flag) and has no privilege-escalation path: the goal is to demonstrate anonymous SMB access. No shell on the system, no root/SYSTEM to reach.

## Defender's view
> 📌 Root cause and prevention.

The vulnerability is an **SMB share reachable without authentication** (null/guest session) that exposes user files. How to prevent it:

- **Disable guest/anonymous access** to SMB. On Windows, set `RestrictNullSessAccess = 1`, remove shares from the `NullSessionShares` list, and disable the Guest account.
- **Apply least privilege** on the share ACLs: only the users/groups that actually need it, at the minimum required access level.
- **Never place sensitive data in broadly readable shares.** A "work" share should not hold personal files or secrets accessible to anyone on the network.
- **Monitoring**: alert on SMB connections using null sessions and on access to sensitive shares.

Fix verification: re-running `smbclient -L //<host>/ -N` and `smbclient //<host>/WorkShares -N` should return `NT_STATUS_ACCESS_DENIED`.

## Lessons learned
- On a Windows host with only port 445 open, the very first attempt is anonymous SMB access: it's free and often decisive.
- Telling default administrative shares (`$`) apart from custom ones right away saves time: attention always goes to what was added manually.
- `smbclient` behaves like an FTP client (`ls`, `cd`, `get`, `mget`): handy to keep in mind for moving quickly inside a share.

## References
- Microsoft — *Network access: Restrict anonymous access to Named Pipes and Shares*
- `man smbclient`
- HTB Starting Point — Dancing

---

### Vulnerability detail

| Field | Value |
|---|---|
| Title | Anonymous (null session) access to an SMB share exposing user files |
| Severity | High *(CVSS 4.0 score to be verified — see below)* |
| CWE | CWE-306 — Missing Authentication for Critical Function |
| Asset | `10.129.53.112` — `WorkShares` share (SMB/445) |
| CVSS 4.0 vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |

**Vector justification** (non-obvious metrics):
- **PR:N** — no privileges required: access is granted through a null session, with no credentials.
- **VC:H** — high confidentiality impact: arbitrary files on the share can be read, including user data.
- **VI:N / VA:N** — the observed access is read-only: no modification and no availability impact.
- **SC/SI/SA:N** — impact stays confined to the vulnerable component; it does not propagate to other systems.

**CWE.** CWE-306 chosen (missing authentication on a critical function: share access requires no authentication). CWE-284 (Improper Access Control) would be an alternative, but CWE-306 is more specific because the flaw is the total absence of authentication, not an overly permissive ACL.
