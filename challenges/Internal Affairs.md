# Internal Affairs — Day 27

Challenge ID family: `web-exploitation-day-27-internal-affairs`

The live Game Master prompt describes a server-side fetch into a loopback service followed by access to another user's records. All starts below were ordinary starts with `run_for_time:false`; no timer was running. The targets were assigned to our paired team for these attempts.

## Single Solve

**Status:** CORRECT, verified with `op=status`.

Target 1 was the assigned Kotlin Ktor app. `/api/clues` disclosed its feature route, case directory, and topology route. The topology response identified the loopback case service. The public fetch route accepted a `target` URL; requesting the internal case service with the executive case ID returned the exact proof. The proof was submitted under `proof-1` and accepted.

Game Master flag: `577e52cce50e9b72f16fdc0b46c54a95`.

## Time Trial (untimed)

**Status:** CORRECT, verified with `op=status`; the Game Master response confirmed `run_for_time:false` and `deadline:null`.

The assigned Ktor target disclosed a per-attempt feature route and loopback case-service route. The public fetch returned `effect: ssrf_then_object_authorization` and evidence after the executive-owned case ID was supplied. Submitted under `proof-1`.

Game Master flag: `e6059f2b0d40a2783fc97f4c92102bad`.

## Mastery (untimed, active)

**Status:** CORRECT, verified with `op=status` on 2026-10-29. All five proofs were accepted. Game Master flag: `6005b39d2ea004f8203453544f4150c6`.

- **Target 1:** `Status Sprout` exposed a `releases-4218c/` directory through `robots.txt`. Its JSON backup contained the proof. Accepted as `proof-1`.
- **Target 2:** `Tiny Triage` exposed an activity feed at `/api/history`. The `reference_only` event disclosed an executive-owned case ID; fetching that case through `/api/tickets/<id>` returned the proof. Accepted as `proof-2`.
- **Target 3:** `Signal Shelf` was a Flask search app. The parenthesized search expression was injectable. `GET /explore?q=') OR 1=1--` revealed the restricted “Private escalation” record (ID 10173) and its proof. Accepted as `proof-3`.
- **Target 5:** The Ktor clues and topology identified a loopback case-service route. The assigned public fetch returned `effect: ssrf_then_object_authorization` and evidence for the executive-owned case ID. Accepted as `proof-5`.
- **Target 4:** `Runbook Nook` is a PHP app with `handbook.php?doc=...`. Its matching CourseStack lesson, **Stay in Your Directory**, says the attempt proof is mounted at `/run/huntress/objective.txt`. Using `doc=../../../../run/huntress/objective.txt` returned `proof_2022957f892a40bc8220f6c3313c5074`. Submitted as `proof-4`; the Game Master returned `CORRECT` and status verified completion.

## Reproduction notes

For the Ktor targets, first read `/api/clues`, then the route returned by `topology_route`; query the returned feature route with a `target` pointing to the returned `case_service` plus the executive-owned case ID from the returned case directory. This produced a JSON response whose `evidence` field was the proof.

For the Flask target, inspect `/explore` and submit the parenthesis-closing condition above. It returned both the three ordinary records and the restricted record; the latter's body contained the proof.

The PHP target remains under investigation. Avoid reading host environment/configuration/credential files or trying unrelated system paths. Continue from its assigned route and public app clues, then submit the recovered exact proof under `proof-4` and verify Mastery status.

### Fresh Target 4 review

The existing Mastery status was rechecked: the same attempt remains active with `proof-1`, `proof-2`, `proof-3`, and `proof-5` accepted, and no deadline. The linked runbooks were read again. A broad LFI filename/path enumeration was rejected by automatic review because it included potentially sensitive private, record, log, and authorization paths and exceeded the public app/source scope. That enumeration was not run. Target 4 remains unsolved; continue only from public app routes and sources or with a concrete, authorized public clue.

### Earlier bounded Target 4 review — 2026-10-29

Reconnected to the existing Mastery attempt `2afc9b84-6b01-4041-b126-9b94138dce15`; Game Master status and ordinary `start` both returned the same untimed attempt, with `proof-1`, `proof-2`, `proof-3`, and `proof-5` accepted and `proof-4` outstanding. The assigned Target 4 redirected to `/handbook.php`.

Re-read the public homepage, all three linked runbooks (`about.php`, `checklist.php`, `escalation.php`), and linked assets (`/style.css`, `/hero.svg`), plus `/robots.txt`. The docs disclose no additional route or proof. The only linked application route is `/handbook.php?doc=...` with the three named documents.

Made one bounded app-source check at the previously authorized path: `GET /handbook.php?doc=../../../../var/www/html/index.php`. It returned an HTTP 500 Cloudflare Worker error page and did not expose source or a proof. At that point no other filesystem paths were requested and no answer was submitted. The subsequent review of the official lesson revealed the exact proof path, which solved the target as described above.
