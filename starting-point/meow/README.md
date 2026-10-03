# Hack The Box — Meow

| Field | Value |
|---|---|
| Platform | Hack The Box (Starting Point) |
| Name | Meow |
| Difficulty | Very Easy |
| OS | Linux |
| Date | 2026-10-03 |
| Tags | #telnet #default-credentials #linux |

## TL;DR
> Open Telnet on port 23 → log in as `root` with a blank password → read the flag. No exploit needed: the box is a lesson in how dangerous an unauthenticated default account is.

## Recon
A full TCP service scan shows a single open port:

```
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
```

```bash
nmap -sC -sV <target-ip>
```

Telnet (port 23) is the only entry point, so that is where enumeration starts. Telnet is a legacy, unencrypted protocol that exposes a remote command-line interface: everything, credentials included, travels in plain text, which is why SSH (port 22) has replaced it almost everywhere.

## Enumeration
### Telnet (23/tcp)
With only Telnet exposed, the obvious thing to test is authentication. On minimalist or embedded Linux targets the `root` account is often left configured with no password. Connecting and trying `root` with an empty password is the first check.

## Foothold
The box authenticates `root` over Telnet with a blank password — no exploitation required, just a login with a default, passwordless administrative account.

1. Connect to the Telnet service:
   ```bash
   telnet <target-ip>
   ```
2. At the login prompt enter `root` as the username.
3. At the password prompt press Enter (blank password).

Access is immediate, and as root:

```bash
whoami
# root
cat /root/flag.txt
# HTB{REDACTED}
```

## Privilege escalation
Not applicable. The Telnet login already lands directly on the `root` account, so there is no privilege boundary left to cross.

## Defender's view
- **Blank root password over Telnet.** Root cause: a default administrative account left with no password. Prevention: enforce a password/key policy and never ship or leave accounts with empty passwords; an authentication-attempt monitor would have flagged the passwordless login.
- **Telnet exposed at all.** Root cause: an unencrypted legacy protocol kept in service. Prevention: disable Telnet and move to SSH, so credentials and session traffic are encrypted in transit.
- **Remote root login allowed.** Root cause: direct remote administrative access. Prevention: forbid remote root login; require an unprivileged user to authenticate first and escalate locally.

## Lessons learned
The simplest path is worth trying before reaching for any exploit: an open legacy service plus a default account is a complete attack chain on its own. Next time, as soon as a scan shows a lone admin-oriented service, test default and blank credentials first. New takeaway: Telnet's `Linux telnetd` banner is itself a signal that the box may be deliberately misconfigured.

## References
- HTB Starting Point — Meow (official writeup)
- Telnet protocol — RFC 854
