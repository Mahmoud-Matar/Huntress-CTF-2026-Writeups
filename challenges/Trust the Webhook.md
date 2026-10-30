# Trust the Webhook — Day 19

## Single Solve — confirmed complete

- Route: `web-exploitation-day-19-trust-the-webhook`.
- Attempt: `661c2224-3ca8-4e16-a756-bf0b045023e9`; started 2026-10-26T14:12:40.201Z; untimed.
- Prompt: the app trusts the events it receives; the assignment asks for the proof from Target 1. The target is a live Starlette app and has no downloadable archive.
- Resumed the existing attempt after status reported its prior target had stopped. Game Master issued a fresh target under the same attempt.
- Read the public workspace notes at `/api/clues`: `feature_route` was `/dispatch-3940be`, `event_type` was `case.promoted`, `owner_scope` was `executive`, and the current role was `analyst`.
- Posted a forged event to the advertised dispatch route. A body carrying the event and executive scope along with plausible event metadata was accepted without a valid webhook signature. The endpoint returned `effect: forged_event_consumed` and proof `proof_b5fd3a1cb5f24e10a84832bfc0bb5882`.
- Submitted the proof under answer ID `proof-1`. Game Master returned `CORRECT` with flag `51e595eae980012d518f85df1d7b60e5`. Follow-up personal status returned `CORRECT`, and the fresh Day 26 list marked the route solved.

The issue is that the dispatch handler trusted caller-controlled event claims, allowing an analyst to forge an executive-scope promotion event.

## Time Trial — confirmed complete

- Route: `web-exploitation-day-19-trust-the-webhook/time_trial`.
- Attempt: `b893c89a-0caa-41d0-a773-fdca99448a60`; regular untimed scored variant (`run_for_time: false`), no deadline; fresh variant.
- Target 1 exposed a rotated dispatch route at `/submit-908250`. Its `/api/clues` response again named the `case.promoted` event and `executive` owner scope.
- Sent a forged event with those live values and plausible event metadata. The route returned `effect: forged_event_consumed` and proof `proof_32e07863d04843d3a4575e85c3d2c4c1`.
- Submitted under `proof-1`; Game Master returned `CORRECT` with flag `8909187ccc0cf59705e88c755b9791c4`. Follow-up status returned `CORRECT`, and the Day 26 list marked the route solved.

## Mastery — confirmed complete

- Route: `web-exploitation-day-19-trust-the-webhook/mastery`.
- Attempt: `ad15d10e-2023-44ef-bf96-88669db4078f`; regular untimed scored variant (`run_for_time: false`), no deadline; four targets and four exact-text proof fields.
- Target 1 was a Node.js “Service Postcard” site. The crawler policy pointed to `/archives-0d486/`; its directory listing exposed `deployment-notes-f4dfec.json.bak`, whose `support_note` held proof 1: `proof_43e28935a65a4125b023b580db14eb0a`.
- Target 2 was “Case Crate.” After establishing the expected case session by viewing case `5587`, `/api/history` revealed a reference-only executive case (`14957`). Reading that case directly returned proof 2 in its note: `proof_1b23b824b32f4b98a117c0b8e3dc8ff6`.
- Target 3 was the “Query Me This” search app. The search value was interpolated into a SQL `LIKE` expression. The query `%') OR 1=1-- ` closed the expression and made the condition true, exposing the restricted “Incident commander note,” record `14448`; its body was proof 3: `proof_72caae21de2d4b9c9a9beb9a48db7d26`.
- Target 4 was a Starlette “Delivery Desk.” `/api/clues` supplied the active route `/action-3cb495`, event type `case.promoted`, owner scope `executive`, and current role `analyst`. Posting a forged event to that route returned `effect: forged_event_consumed` and proof 4: `proof_ec43af40f7a748c1acc02a36ccfc4eca`.
- Submitted all four proofs under `proof-1` through `proof-4`. Game Master returned `CORRECT`; personal status confirmed `CORRECT` with all four answer IDs accepted. The attempt was completed by Jinzo.

## Reproducing the webhook proof

For the Single Solve, fetch `/api/clues` from the assigned target and use its current `feature_route`, event type, owner scope, and role values; the route was `/dispatch-3940be`, with event type `case.promoted`, scope `executive`, and caller role `analyst`. Submit a caller-created promotion event to that advertised route without a valid webhook signature. The recorded success condition is a response containing `effect: forged_event_consumed` and the returned proof, which is submitted under `proof-1`. The Time Trial rotates the route to `/submit-908250`, so re-read its clues rather than reusing the Single Solve URL.

The exact successful JSON body and any required headers were not preserved in this report. That omission prevents byte-for-byte replay from the write-up alone; do not invent a request schema from the summary. Use the live target's public clue response to reconstruct the request and confirm the effect/proof response before submission. Mastery targets 1–3 are documented with their observed routes and records; target 4's proof was the forged-event response from its own `/api/clues` route.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
