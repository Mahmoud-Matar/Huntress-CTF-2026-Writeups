# Serialized Offender — Day 26

## Single Solve — confirmed complete

- Route: `web-exploitation-day-20-serialized-offender`.
- Attempt: `fdf79bb1-58cc-4e2c-8fdc-4c010b8c2c75`; untimed single solve.
- The Game Master prompt described a session represented as a blob whose contents were trusted after reshaping. The target was a live Quarkus application, with no downloadable artifact.
- `/api/clues` identified the protected route `/process-e04a42` and the format guide `/api/state-format`. The format guide specified a JSON `state` field containing base64url-encoded UTF-8 JSON; its sample was `{"user":"analyst","role":"analyst"}`.
- The state was client-controlled and unsigned. Encoding `{"user":"administrator","role":"administrator"}` as base64url and posting it in the `state` field caused the protected route to return `effect: serialized_role_trusted` and proof `proof_ee06e40c1ecb4259a43856b4b6750615`.
- Submitted the proof under `proof-1`. Game Master returned `CORRECT` with flag `ca59f4761f0de56ba9d18388d7da1acd`; personal status confirmed `CORRECT` and accepted `proof-1`. The attempt was completed by Jinzo.

The boundary failure was trusting an unsigned, client-supplied serialized role for authorization. The attacker only needed to encode the expected administrator claim in the documented format.

## Time Trial — confirmed complete

- Route: `web-exploitation-day-20-serialized-offender/time_trial`.
- Attempt: `199348f4-2e9c-457f-a319-3e430c92b3b5`; regular untimed scored run (`run_for_time: false`), no deadline, as returned by the Game Master.
- The fresh Quarkus target's `/api/clues` returned route `/action-d34380`; `/api/state-format` again documented base64url-encoded UTF-8 JSON in the `state` request field.
- Encoded `{"user":"administrator","role":"administrator"}` in that format and posted it to the live route. The application returned `effect: serialized_role_trusted` and proof `proof_34d884778e9e4fafbec15862d25c6cc6`.
- Submitted under `proof-1`. Game Master returned `CORRECT` with flag `8f9675822b67ba1dc77fc741c94d1313`; personal status confirmed `CORRECT` and accepted `proof-1`. The attempt was completed by Jinzo.

## Mastery — confirmed complete

- Route: `web-exploitation-day-20-serialized-offender/mastery`.
- Attempt: `232302ee-0507-431f-aac8-36b0be978170`; regular untimed scored run (`run_for_time: false`), no deadline; four target proofs.
- Target 1, “Tiny Uptime,” disallowed `/snapshots-06adc/` in `robots.txt` but exposed that path as a directory index. Its `deployment-notes-bef17e.json.bak` backup contained proof 1: `proof_91b9f1a3cca14eeba95a51d73ca1902a`.
- Target 2, “Incident Picnic,” set a `case_session` on the home page and exposed a reference-only executive case ID (`17752`) in `/api/timeline`. After opening an ordinary ticket to establish the session, `/api/tickets/17752` returned the restricted case and proof 2: `proof_2f32b0affe1f4e3792c4dc3630d97d6d`.
- Target 3, “Signal Shelf,” had an injectable search query at `/explore`. The payload `%') OR 1=1-- ` exposed a restricted record, `13431`, whose body was proof 3: `proof_6acdba2ceb84491c881f0b9d5504068d`.
- Target 4, “State Suitcase,” documented `/action-fcc7c3` and the unsigned base64url JSON state format through `/api/clues` and `/api/state-format`. Posting the encoded state `{"user":"administrator","role":"administrator"}` returned `effect: serialized_role_trusted` and proof 4: `proof_bec7390a542d47ceac3f90268e7cdd25`.
- Submitted all four proofs under `proof-1` through `proof-4`. Game Master returned `CORRECT` with flag `10e67d9630aeac3218db9ab8f55f96ee`; personal status confirmed `CORRECT` with all four answer IDs accepted. The attempt was completed by Jinzo.
