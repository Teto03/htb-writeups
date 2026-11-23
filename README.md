# Hack The Box — Write-ups

My offensive and defensive security practice on [Hack The Box](https://www.hackthebox.com), documented with a focus on **method**: what I enumerated, why I chose each step, and how the issue could have been prevented or detected.

## Scope

Only content that HTB allows to be published: **Starting Point machines, retired machines and retired Sherlocks**. Nothing about active content. Flags, hashes and credentials are always redacted.

## Machines

| Date | Name | Section | OS | Difficulty | Key techniques |
|---|---|---|---|---|---|
| 2026-10-03 | [Meow](starting-point/meow/README.md) | Starting Point | Linux | Very Easy | Telnet, blank root password |
| 2026-10-03 | [Fawn](starting-point/fawn/README.md) | Starting Point | Linux | Very Easy | FTP, anonymous login |
| 2026-10-17 | [Dancing](starting-point/dancing/README.md) | Starting Point | Windows | Very Easy | SMB, null session, share enumeration |
| 2026-10-17 | [Redeemer](starting-point/redeemer/README.md) | Starting Point | Linux | Very Easy | Redis, full port scan, unauthenticated access |
| 2026-11-07 | [Cap](machines/cap/README.md) | Machines | Linux | Easy | IDOR, pcap analysis, cleartext FTP creds, password reuse, `cap_setuid` privesc |

## Sherlocks

| Date | Name | Category | Difficulty | Artefacts | Key techniques |
|---|---|---|---|---|---|
| 2026-11-23 | [Brutus](sherlocks/brutus/README.md) | DFIR | Very Easy | `auth.log`, `wtmp` | SSH brute force, session reconstruction, persistence via local account |

## Repository layout

```text
.
├── starting-point/<name>/   Starting Point machines
├── machines/<name>/         retired machines
├── sherlocks/<name>/        retired Sherlocks
└── templates/
    ├── machine.md           write-up template for machines
    └── sherlock.md          write-up template for Sherlocks
```

Each folder holds the write-up in `README.md`, plus `nmap/` (scan output) for machines and `images/` for screenshots where needed. Downloaded files, artefacts and loot are never committed (see `.gitignore`).

## License

Write-ups are released under [CC BY 4.0](LICENSE).

## Disclaimer

For educational purposes only. All techniques were used exclusively against HTB lab environments. Do not use them on systems you are not authorized to test.
