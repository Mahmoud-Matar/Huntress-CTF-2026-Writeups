# Fail Open Friday — Day 28

Challenge ID: `web-exploitation-day-24-fail-open-friday`
Category: Web Exploitation

This report uses the format from [RyanNgCT’s CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template). It documents the Mastery route solved here; live Day 28 status also marks Single Solve and Time Trial complete, but their earlier attempt evidence was not available in this session, so no details are inferred for those modes.

## Mastery — CORRECT

- Attempt: `160cd068-b2ac-41ef-9213-c4515ef5521c`
- Started: `2026-10-28T20:23:31.092Z`
- Timer: untimed (`run_for_time: false`; no deadline)
- Completion: `2026-10-30`; Game Master flag: `bb7fb86565a0a9f88650f9d39f02c934`
- Verification: personal status returned `CORRECT` and all five answer IDs (`proof-1` through `proof-5`) accepted; the Day 28 list marks the route solved.

The challenge prompt reads: “The remote policy decoder is part of an access decision. A valid public decision is documented in the application; investigate what happens when that decision cannot be decoded.” On this preserved attempt, `proof-1`, `proof-2`, `proof-3`, and `proof-5` were already accepted. Only Target 4 / `proof-4` remained.

## Target 4 — step-by-step reproduction

The assigned host was `https://f842ef298dc7fa4a7c2e266a8789d3fcc4dcbc533c55e5fb.2026.huntress.ctf.games/`. Its root redirected to `/reader.php`, which rendered the “Stay in Your Directory” runbook app. The page linked `start.php`, `collect.php`, and `report.php` through a `doc` query parameter. The page copy—“Please return runbooks to their proper directory”—and the document-viewer parameter suggested checking whether the include stayed within its intended directory.

Request the assigned objective file through the same `doc` parameter:

```bash
curl -sS --get \
  --data-urlencode 'doc=../../../../run/huntress/objective.txt' \
  'https://f842ef298dc7fa4a7c2e266a8789d3fcc4dcbc533c55e5fb.2026.huntress.ctf.games/reader.php'
```

The client URL-encodes the slashes in the query value. The server returned HTTP `200`, `Content-Type: text/html; charset=UTF-8`, and the normal page wrapper with the included objective text rendered in the document viewer. Extract the exact proof from the response body:

```text
proof_2f084e95be5545f1943da34ab62b08bb
```

Submit it under `proof-4`:

```json
{"op":"submit","challenge":"web-exploitation-day-24-fail-open-friday/mastery","answers":{"proof-4":"proof_2f084e95be5545f1943da34ab62b08bb"}}
```

The Game Master returned `CORRECT` with the flag shown above. A follow-up status check confirmed all five accepted proofs. This reproduction reads the challenge’s mounted objective file only; it does not access system, configuration, or credential files.
