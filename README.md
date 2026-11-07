# Hack The Box — Write-ups & Notes

My offensive security practice on [Hack The Box](https://www.hackthebox.com), documented with a focus on **method**: what I enumerated, why I chose each step, and how the issue could have been prevented (*Defender's view* section in every write-up).

## Scope and rules

Only content that HTB allows to be published: **retired machines, Starting Point machines and Tier 0 Academy modules**. Nothing about active machines, challenges or Sherlocks. Flags, hashes and credentials are always redacted.

## Index

| Date | Name | Type | OS | Difficulty | Key techniques |
|---|---|---|---|---|---|
| 2026-10-03 | [Meow](starting-point/meow/README.md) | Starting Point | Linux | Very Easy | telnet, default credentials (blank root password) |
| 2026-10-03 | [Fawn](starting-point/fawn/README.md) | Starting Point | Linux | Very Easy | FTP, anonymous login |
| 2026-10-17 | [Dancing](starting-point/dancing/README.md) | Starting Point | Windows | Very Easy | SMB, null session, share enumeration |
| 2026-10-17 | [Redeemer](starting-point/redeemer/README.md) | Starting Point | Linux | Very Easy | Redis, full port scan, unauthenticated access |
| 2026-11-07 | [Cap](machines/cap/README.md) | Machine | Linux | Easy | IDOR, pcap analysis, cleartext FTP creds, password reuse, `cap_setuid` privesc |

## Structure

- `starting-point/` — Starting Point machines (one folder per machine, write-up in `README.md`)
- `machines/` — retired machines (same layout)
- `academy-tier0/` — notes from Tier 0 Academy modules
- `_template.md` — write-up template

## Disclaimer

For educational purposes only. All techniques were used exclusively against HTB lab environments. Do not use them on systems you are not authorized to test.
