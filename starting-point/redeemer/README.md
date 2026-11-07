# Hack The Box — Redeemer

| Field | Value |
|---|---|
| Platform | Hack The Box — Starting Point (Tier 0) |
| Name | Redeemer |
| Difficulty | Very Easy |
| Category | Redis / database misconfiguration |
| OS | Linux |
| Date | 2026-10-17 |
| Tags | #redis #unauthenticated #database #enumeration |

## TL;DR
> The only exposed service is Redis, on the non-standard port 6379, with **no authentication**. Connecting with `redis-cli` is enough to browse the databases and read the flag straight out of a key. No exploit — just a network-exposed datastore that trusts anyone who can reach it.

---

## Recon

A first default scan is misleading:

```bash
nmap -sC -sV 10.129.136.187 -oN nmap/initial
```

```
All 1000 scanned ports on 10.129.136.187 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
```

**What stands out.** The host is up (it replies with RST to every probe) but nothing shows. That's not a dead end: `nmap` by default only scans the top 1000 ports, and this box puts its service on a high, non-standard port. So I scan the full range:

```bash
nmap -p- --min-rate 5000 10.129.136.187 -oN nmap/all
```

```
PORT     STATE SERVICE
6379/tcp open  redis
```

Port 6379 is Redis, an in-memory key-value datastore. Redis has **no authentication by default**, so the first thing to check is whether it accepts an unauthenticated connection.

## Enumeration

### Redis (port 6379)

Targeted scan to confirm the service and grab the version:

```bash
nmap -sV -p6379 10.129.136.187 -oN nmap/detail
```

```
6379/tcp open  redis  Redis key-value store 5.0.7
```

The `redis-cli` utility is the standard client for interacting with a Redis server. It connects without credentials:

```bash
redis-cli -h 10.129.136.187
```

**The reasoning.** A Redis instance reachable over the network with no `requirepass` set means any client can issue commands. The goal is to find where the data (the flag) lives. Redis organizes keys into numbered databases; `info` reports how many databases hold keys, `dbsize` counts keys in the current one, and `keys *` lists them.

```
10.129.136.187:6379> info server          # redis_version:5.0.7
10.129.136.187:6379> select 0             # switch to database index 0
10.129.136.187:6379> dbsize               # -> (integer) 4
10.129.136.187:6379> keys *               # list the 4 keys
```

## Foothold / Initial access

There is no memory-corruption or code-execution step: the access **is** the misconfiguration. With an unauthenticated session established, reading the key that holds the flag is a single command:

```
10.129.136.187:6379> get flag
```

```
HTB{REDACTED}
```

> The flag is intentionally redacted.

## Privilege escalation

Redeemer exposes a **single flag** retrieved directly from Redis and has no privilege-escalation path: the objective is to demonstrate unauthenticated access to the datastore. No shell on the host is obtained.

## Defender's view
> 📌 Root cause and prevention.

The vulnerability is a **Redis instance exposed to the network with no authentication**. Anyone able to reach port 6379 gets full read/write control over the datastore. How to prevent it:

- **Require authentication.** Set `requirepass <strong-password>` (or, better, Redis ACLs from 6+). An unauthenticated datastore on the network is the root cause here.
- **Do not bind Redis to public interfaces.** Set `bind 127.0.0.1 ::1` and keep `protected-mode yes` so it isn't reachable from outside the host unless explicitly intended.
- **Network segmentation / firewall.** Port 6379 should never be reachable from untrusted networks; restrict it to the application hosts that need it.
- **Treat this as more than a data leak.** An unauthenticated Redis is not only readable: an attacker can also write keys, flush the database, and in many setups escalate to **remote code execution** (writing an SSH key or cron job to disk via `CONFIG SET dir/dbfilename`, or loading a malicious module). The confidentiality impact seen here is the mildest possible outcome.

Fix verification: after setting `requirepass`, `redis-cli -h <host>` followed by any command should return `NOAUTH Authentication required`; from an untrusted network, the port should not be reachable at all.

## Lessons learned
- The key lesson of this box: when the default scan finds nothing but the host is alive, **always run `nmap -p-`** before concluding there's no attack surface. Services on high ports exist precisely to teach this.
- Knowing a service's default security posture pays off: Redis ships without authentication, so an unauthenticated-access attempt is the obvious first move, not an afterthought.
- `redis-cli` as a one-shot command (`redis-cli -h <ip> <cmd>`) does not keep session state — `select` only persists inside an interactive session or via the `-n <db>` flag.

## References
- Redis — *Security* documentation (authentication, `protected-mode`, `bind`)
- `man redis-cli`
- HTB Starting Point — Redeemer

---

### Vulnerability detail

| Field | Value |
|---|---|
| Title | Unauthenticated, network-exposed Redis instance |
| Severity | High *(CVSS 4.0 score to be verified — see below)* |
| CWE | CWE-306 — Missing Authentication for Critical Function |
| Asset | `10.129.136.187` — Redis (TCP/6379) |
| CVSS 4.0 vector | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

**Vector justification** (non-obvious metrics):
- **PR:N / UI:N** — no credentials and no user interaction: an unauthenticated client connects directly.
- **VC:H** — full read access to the datastore contents.
- **VI:H** — the same unauthenticated session can write and delete keys (`SET`, `DEL`, `FLUSHALL`): integrity of the stored data is fully at the attacker's discretion.
- **VA:H** — the attacker can flush or shut down the datastore, denying the service to legitimate users.
- **SC/SI/SA:N** — scored for the directly demonstrated impact (contained to Redis). The documented escalation to host RCE would raise the subsequent-system metrics, but it requires further, environment-dependent steps and is noted in the Defender's view rather than assumed here.

**CWE.** CWE-306 (missing authentication on a critical function: the datastore accepts commands with no authentication). CWE-284 (Improper Access Control) is the broader alternative, but CWE-306 is more specific because authentication is entirely absent, not merely misconfigured.
