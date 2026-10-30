# Double Spent — Day 27

The Game Master describes the challenge as spending one credit twice by racing concurrent requests. Targets below were issued to this team's attempts. No bearer token is recorded here.

## Single Solve

- Route: `web-exploitation-day-21-double-spent`
- Attempt: `b2cccbf3-e176-4cda-ba00-3f51a6143ade` (untimed)
- The first assigned target expired after its inactivity window. Game Master status returned `cleaned`, and reconnecting issued a fresh target under the same attempt.
- On the fresh target, `/api/clues` identified the assigned feature route `/execute-bdb3f6` and audit route `/audit-ad790f`.
- Sent two empty `application/x-www-form-urlencoded` POSTs concurrently to the feature route, synchronized with a barrier. Both succeeded; one response observed `credits: -1`, demonstrating the race allowed the one-credit balance to be spent twice.
- The assigned audit route confirmed `effect: single_credit_spent_twice` and returned the proof submitted as `proof-1`.
- Game Master submission and subsequent personal status both returned `CORRECT`.
- Flag: `ca23f254f439d2a726cf89990921a801`

### Reproduce the Single Solve race

1. Start or resume the route and read `/api/clues` on that assigned target. Use the feature and audit paths returned by that target; the recorded Single Solve paths were `/execute-bdb3f6` and `/audit-ad790f`.
2. Prepare two empty POST requests to the feature route with `Content-Type: application/x-www-form-urlencoded`. Release both requests concurrently, using a barrier so neither is intentionally sent only after the other has completed.
3. Check the feature responses for the balance effect. The recorded run showed `credits: -1`, consistent with both requests passing the one-credit check before either decrement was visible.
4. Request the assigned audit route and confirm it reports `effect: single_credit_spent_twice`. Submit the proof returned by that audit under `proof-1` and verify the Game Master status for the same attempt.

The target is attempt-specific; on a new variant, rediscover the paths from `/api/clues` instead of reusing these recorded names. The local report preserves the observed result but not a request transcript or exact proof response, so it does not claim a byte-for-byte replay of the expired target.

## Time Trial

- Route: `web-exploitation-day-21-double-spent/time_trial`
- Attempt: `546c2227-77ef-40a5-a19a-697f2bcb47d9`
- Ranked run requested with `run_for_time: true`; server deadline was `2026-10-27T20:14:38.569Z`.
- On the assigned target, `/api/clues` identified `/submit-7b98c3` and `/callback-060613`. Two synchronized concurrent form POSTs produced the overspend, and the callback confirmed `single_credit_spent_twice`.
- Submitted the returned proof under `proof-1` before the deadline. Game Master submission and personal status returned `CORRECT`; Hall of Fame eligibility was true.
- Flag: `7df821690537e15b0551948ec70db960`

## Mastery

- Route: `web-exploitation-day-21-double-spent/mastery`
- Attempt: `7b5edb71-33c0-4684-8f0c-8706dee07ef6` (untimed)
- The Game Master assigned four targets and answer IDs `proof-1` through `proof-4`.
- Target 1's public `robots.txt` disclosed a deployment archive. Its listed backup file contained the proof submitted as `proof-1`.
- Target 2's dashboard linked to a workspace activity feed. The feed exposed case ID `16782`; fetching its case JSON through the dashboard session returned the proof submitted as `proof-2`.
- Target 4 was a Double Spent Rails app. Two concurrent form POSTs to its `/api/clues`-identified feature route caused the one-credit balance to reach `-1`; its audit route returned the proof submitted as `proof-4`.
- Game Master accepted and saved `proof-1`, `proof-2`, and `proof-4`, with one answer remaining.
- Target 3 is a Signal Shelf search app. The page exposed a single search form, `GET /explore?q=...`; it had no app JavaScript, and its linked stylesheet was presentation-only. The ordinary search returned three public notes.
- A narrowly scoped SQL injection probe on that assigned search parameter used `q=%') OR ('1'='1`. Unlike a normal query, it returned a fourth, restricted record titled “Executive timeline,” with record ID `16395` and proof `proof_7f1c7180d6294126854df37ea6903aad`. The proof was submitted as `proof-3`.
- Game Master submission and subsequent personal status returned `CORRECT`, with all four answer IDs accepted.
- Flag: `006cd0f6852ecfb3effde8ebaf6943ea`

*Writeup structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
