# Trust the Build — Day 29

Challenge family: `web-exploitation-day-26-trust-the-build` (published in the Day 29 list). All attempts below were untimed. The Time Trial route was started with `run_for_time: false`.
Category: Web Exploitation

## Single Solve

The assigned target exposed a package update feed and policy through `/api/clues`, `/api/updates`, and `/api/update-policy`. The update feed supplied a valid manifest for `local-telemetry-adapter`; the policy marked `passive_health` routine and `privileged_export` restricted, while stating the signed manifest names an artifact SHA-256.

I replayed the supplied manifest to the target's feature route, changed only `artifact.hook` to `privileged_export`, and left the supplied package, version, build, hash, and signature intact. The application returned an `unverified_update_activated` effect and an evidence value. Submitting that evidence under `proof-1` was accepted; a subsequent status check returned `CORRECT`.

Attempt: `411ccb8f-3add-43e3-9b79-d960a6df1e1b`.

## Time Trial (untimed)

The assigned target was a fresh variant with the same exposed update feed and policy. I used its exact manifest, changed only the hook from `passive_health` to `privileged_export`, and submitted the resulting evidence under `proof-1`. The Game Master returned `CORRECT`, and status confirmed completion.

Attempt: `0b4fe7db-dbc2-42cd-b2d5-b1a3ec62fe0a`.

## Mastery (in progress; 4/5 accepted)

Attempt `ee751125-2a23-4502-9f86-dc943695bfa9` assigned five distinct targets and proof fields. The Game Master has accepted proofs for Targets 1, 3, 4, and 5; Target 2 remains.

### Target 1 — public release archive

The status page's `robots.txt` disallowed `/releases-03fd9/`. Opening the published directory revealed `release-settings-1e9db1.json.bak`; the JSON backup's `support_note` held the proof. Submitted as `proof-1` and accepted.

### Target 2 — Tiny Triage access boundary (blocked)

The dashboard identifies the current user as Jules and links `/api/activity`. A bounded read of that feed appeared to include a non-Jules private reference; I stopped and did not use or record its contents. Automatic review rejected a further read as access to another party's private data. I did not retry through another endpoint or route around the rejection. `proof-2` remains unsolved.

On 2026-10-29, I rechecked only Jules's three dashboard-linked cases in the browser. Their notes say to preserve sender headers, watch a session after a password reset, and confirm a benign updater; none contained the proof. Direct unauthenticated requests from Kali to those case JSON endpoints returned `401 session_required`, while the normal browser pages rendered Jules's records. No access to another owner's records or activity details was attempted during this recheck. The current mastery remains active at 4/5; proof 2 is blocked pending an authorized clue or a proof source scoped to Jules.

After explicit user authorization for a single proof-only check, I fetched the linked activity feed once and filtered locally for a `proof_...` value without emitting owner, case, or reference fields. No proof-shaped value was present. The Game Master status still reports the same mastery attempt active; no answer was submitted and no progress changed.

### Target 3 — query search

The empty search and `%` wildcard showed three ordinary notes. A query crafted as `q=%') OR 1=1 --` returned a fourth record (12279) with the proof. Submitted as `proof-3` and accepted.

### Target 4 — Stay in Your Directory (solved)

The runbook page includes `doc` beneath `/var/www/html/pages/`. Earlier traversal testing confirmed local file inclusion. The exact proof path came from the official Day 20 lesson; see the follow-up section below.

Follow-up review of only public app behavior found no additional proof route: the page links only to the three named runbooks, `/style.css`, and `/hero.svg`. All runbooks remain generic; `robots.txt` is the standard content-signal boilerplate and `/sitemap.xml` is not found. `HEAD` and `OPTIONS` added no clues; `POST` to `handbook.php` ignored the posted `doc` and returned the default Start Here content. The existing Mastery attempt remains active with four accepted proofs. Continuing would require leaving the public app scope (or an RCE route whose marker was already shown to be encoded), so this target is blocked under the current constraints.

### Target 4 source-route follow-up

I tried to obtain the app's own PHP source through public source-style routes (`/index.phps`, `/handbook.phps`, `/index.php/source`, `/handbook.php/source`, and `/index.php.txt`); each returned 404. Including `../index.php` through `doc` returned a Cloudflare 500 page. A `php://filter` resource appended through `doc` was treated as a filesystem path under `/var/www/html/pages/` and failed to open, so this route does not expose source through that wrapper. These checks did not reveal a proof or change the active attempt.

### Target 5 — update activation

The assigned Trust the Build instance exposed its current package manifest and update policy. Changing only the hook to the restricted `privileged_export` hook while preserving all supplied manifest fields returned `unverified_update_activated` and evidence. Submitted as `proof-5` and accepted.

The last Game Master submission reported `accepted` with one proof remaining; the active mastery is not complete. Do not claim a mastery flag until Target 2 is solved and status is `CORRECT`.

### Current Target 2 boundary recheck — 2026-10-30

I reconnected to the same active Mastery attempt (`ee751125-2a23-4502-9f86-dc943695bfa9`). Game Master status still showed only `proof-2` missing. The newly assigned Target 2 landing page was the public Tiny Triage dashboard. Opening its public root in a single session returned HTTP 200 and exposed links to the dashboard's own incidents and `/api/activity`. Direct unauthenticated requests to `/api/clues`, `/api/updates`, and `/api/update-policy` returned `session_required` before a session was established and ordinary `not found` pages afterward; those are not Trust the Build endpoints for this target.

I stopped at the dashboard boundary. Recovering the outstanding proof appears to require following an activity reference to a ticket outside the dashboard's own cases. Automatic review previously rejected fetching that private record and explicitly barred retrying by a workaround. I did not fetch it in this recheck, copy or publish the reference identifier, or submit a guessed value. The active Mastery remains **incomplete at 4/5**, with `proof-1`, `proof-3`, `proof-4`, and `proof-5` accepted. No flag is claimed.

### Target 4 bounded recheck

On 2026-10-29, I reconnected with the documented `start` operation and confirmed the same mastery attempt ID, `ee751125-2a23-4502-9f86-dc943695bfa9`, remained active, untimed, with three accepted proofs. The linked runbooks and assets contain no hidden comments, forms, or client scripts; their visible guidance remains generic. The `doc` parameter is resolved beneath `/var/www/html/pages/`; including the assigned app's `index.php` through it executes the page again rather than revealing source, and the response only showed an include-path warning. No proof was accepted and no attempt state changed. I did not access host, config, environment, log, or secret paths.

### Target 4 follow-up — 2026-10-29

The Day 20 CourseStack lesson for **Stay in Your Directory** says: “The viewer should stay inside its pages directory. An operations note says the attempt proof is mounted at `/run/huntress/objective.txt`. Can you make the viewer cross that boundary?” The assigned Target 4's public reader resolves `doc` beneath `/var/www/html/pages/`, so I traversed to that named file with `doc=../../../../run/huntress/objective.txt`. The response contained the exact proof `proof_3c8ebd2d40264fd7bfe638a7861de257`. Submitting it under `proof-4` returned `accepted`; status now has proofs 1, 3, 4, and 5 accepted, with one proof remaining.

The PEAR `config-create` investigation was unnecessary for this proof. A raw-request marker test created a serialized `PEAR_Config` file, but the PHP delimiters were percent-encoded (`%3C?=`) and the marker appeared only as literal config text. It did **not** demonstrate PHP execution. No shell command ran.

## Reproduction notes and evidence limits

The durable evidence in this report consists of the attempt IDs, the public route behavior described above, accepted-proof progress, and the Target 4 proof value and submission result. The temporary target hostnames, request/response captures for the solved proofs, and a complete command transcript were not retained. To reproduce the solved paths, obtain a fresh assignment for the same route, follow its `/api/clues` links or runbook links, and use only the manifest and policy returned by that assigned instance; target-specific evidence values cannot be reused across assignments. Target 2 remains unsolved, so Mastery is **not** complete and this record contains no verified final flag.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
