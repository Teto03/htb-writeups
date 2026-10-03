# Hack The Box — Fawn

| Field | Value |
|---|---|
| Platform | Hack The Box (Starting Point) |
| Name | Fawn |
| Difficulty | Very Easy |
| OS | Linux |
| Date | 2026-10-03 |
| Tags | #ftp #anonymous-login #linux |

## TL;DR
> Anonymous FTP login is enabled on port 21 → connect as `anonymous` with a blank password → download `flag.txt` with `get`. No exploit needed: the box shows how an anonymous FTP share leaks files to anyone.

## Recon
A full TCP service scan shows a single open port:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
```

```bash
nmap -sC -sV <target-ip>
```

FTP (port 21) is the only entry point. The `ftp-anon` script has already done most of the work: it reports that anonymous login is allowed and even lists a `flag.txt` sitting in the share. The scan also flags that both control and data connections are plain text — credentials and files travel unencrypted.

## Enumeration
### FTP (21/tcp)
The nmap output confirms anonymous access and a readable `flag.txt`. The next step is simply to connect and retrieve it.

## Foothold
Anonymous FTP is enabled, so anyone can log in without valid credentials and read the files in the share — no exploitation required.

1. Connect to the FTP service:
   ```bash
   ftp <target-ip>
   ```
2. At the `Name:` prompt enter `anonymous`.
3. At the password prompt press Enter (blank password).
4. List the contents and download the flag:
   ```bash
   ftp> ls
   ftp> get flag.txt
   ftp> bye
   ```

The file is now on the local machine. Read it:

```bash
cat flag.txt
# HTB{REDACTED}
```

Note: FTP does not give a shell on the target. `get` copies the file from the server to the attacking machine, and `cat` is run locally.

## Privilege escalation
Not applicable. The objective is a single file readable through anonymous FTP; there is no shell and no privilege boundary to cross.

## Defender's view
- **Anonymous FTP login allowed.** Root cause: the FTP server accepts the `anonymous` account without authentication. Prevention: disable anonymous login (`anonymous_enable=NO` in vsftpd) and require authenticated accounts with least-privilege access to the shared directory.
- **Sensitive file exposed in the share.** Root cause: a readable file left in a world-accessible FTP root. Prevention: never place sensitive data in an anonymously accessible path; apply correct file permissions and directory scoping.
- **Plaintext control and data channels.** Root cause: plain FTP transmits everything unencrypted. Prevention: use FTPS or migrate to SFTP so credentials and transfers are encrypted in transit.

## Lessons learned
Read the scanner output before reaching for anything else: `nmap`'s NSE scripts (`ftp-anon` here) can hand you the whole attack path, including the file to grab. Next time, when a scan lists files or confirms anonymous access, act on that directly instead of enumerating further. New takeaway: FTP access is file access, not shell access — the flag comes down with `get`, not with `cat` on the target.

## References
- HTB Starting Point — Fawn (official writeup)
- vsftpd documentation — `anonymous_enable` configuration directive
- FTP protocol — RFC 959
