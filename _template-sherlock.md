# Hack The Box — Sherlock: <Name>

> ⛔ PRIVATE — do not publish before the Sherlock is retired (remove this line when it is).

| Field | Value |
|---|---|
| Platform | Hack The Box — Sherlocks |
| Name | <Name> |
| Difficulty | <Very Easy / Easy / Medium / Hard / Insane> |
| Category | <DFIR / SOC / Malware Analysis / Threat Intelligence / ...> |
| Artefacts | <e.g. auth.log + wtmp / PCAP / EVTX / memory dump / KAPE triage> |
| Date | <YYYY-MM-DD> |
| Tags | <e.g. #evtx #brute-force #persistence> |

## TL;DR

> Two or three sentences: what happened, how you proved it, which artefacts were decisive.

## Scenario

<The scenario in your own words: who was attacked, what was noticed, what you were asked to find out.>

## Artefacts and triage

| File | Type | SHA-256 | Notes |
|---|---|---|---|
| `<file>` | <EVTX / PCAP / ...> | `<hash>` | <what it contains, time range> |

**Tools:** <chainsaw, tshark, Volatility 3, EZ Tools, ...>

**Time zone:** all timestamps in this writeup are UTC.

## Investigation

### Task 1 — <question>

**Approach.** What you looked for, where, and why there.

```bash
<command>
```

```text
<trimmed output — only the relevant lines>
```

**Answer:** `<answer>`

<!-- Repeat one subsection per task. If a task needed a wrong turn before the right one, say so in a line: it shows method. -->

## Attack timeline (UTC)

| Time (UTC) | Event | Source artefact |
|---|---|---|
| <YYYY-MM-DD HH:MM:SS> | <event> | <file / event ID / packet no.> |

## Indicators of compromise

| Type | Value | Context |
|---|---|---|
| IP | `<x.x.x.x>` | <role in the attack> |
| SHA-256 | `<hash>` | <file name> |
| Account | `<user>` | <created / abused> |

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| <Initial Access> | <T1110 — Brute Force> | <task / artefact> |

## Detection and response

> For each stage of the attack: which log source showed it, which alert or rule would have caught it earlier, and how it could have been prevented (hardening, configuration, monitoring).

## Lessons learned

- <What slowed you down and what you would check first next time.>
- <New tool or technique.>

## References

- <Documentation, event ID references, articles used.>
