# Forwarded Misgivings — Day 27

Challenge ID: `web-exploitation-day-23-forwarded-misgivings`
Category: Web Exploitation

This report records the assigned team's completed routes. The format is based on [RyanNgCT’s CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template). Each mode used its own Game Master assigned targets; hostnames and proof values are variant-specific.

## Result

Single Solve and Time Trial were previously confirmed `CORRECT`. Mastery was completed on 2026-10-30. Its attempt `931cceef-f5b5-4a8b-b1ac-547c3e53f292` was untimed (`run_for_time: false`, no deadline). Four of five answers had already been accepted on that preserved attempt; recovering and submitting Target 4’s `proof-4` completed it. The Game Master returned `CORRECT` with flag `585feeb596bbb0a280a9233e8e0cd86f`. A subsequent personal status check returned `CORRECT` and all five accepted answer IDs.

## Challenge idea

The prompt was: “The app believes whatever the proxy whispers in its ear. Whisper the right header and stroll down the protected path as an insider.” It points to trusting proxy-supplied client identity. On the Micronaut targets, the public `/api/clues` endpoint named the feature route and described a `trusted_reverse_proxy` deployment. Sending `X-Forwarded-For: 127.0.0.1` to that route made the app treat the request as internal and reveal the proof. The Mastery bundle also included a separate PHP document-reader target; its proof came from the mounted objective file through the reader’s `doc` include parameter.

## Single Solve — confirmed `CORRECT`

Assigned target: `https://3e5d5fd7e80aeb7c5590345346e3d057b89c688ae77017d1.2026.huntress.ctf.games/`

1. Request `/api/clues` to identify feature route `/action-19a740`.
2. Send a GET to `/action-19a740` with `X-Forwarded-For: 127.0.0.1`.
3. Extract the exact proof from the response and submit it as `proof-1`.

The Game Master returned `CORRECT`, and personal status confirmed completion.

## Time Trial — untimed, confirmed `CORRECT`

This route was started with `run_for_time: false`; there was no deadline or running timer.

Assigned target: `https://37d464202346a8819ccaf6777454442a5af375cec84660e7.2026.huntress.ctf.games/`

1. Request `/api/clues`; it identified feature route `/inspect-2d6a00`.
2. Send a GET to `/inspect-2d6a00` with `X-Forwarded-For: 127.0.0.1`.
3. Submit the exact response proof as `proof-1`.

The Game Master returned `CORRECT`, and personal status confirmed completion.

## Mastery — confirmed `CORRECT`

The answer format for each question was exact text under `proof-1` through `proof-5`. The attempt was resumed after it had stopped; the Game Master retained the four previously accepted answer IDs. Only the remaining `proof-4` value had to be submitted to finish the route.

### Previously accepted bundle answers

These steps and values were recorded from the team's assigned Mastery attempt and accepted before the final proof-4 submission.

| Answer | Reproduction | Accepted proof |
|---|---|---|
| `proof-1` | Target 1: request `/robots.txt`, follow its listed `/releases-5a1cf/` directory, then read `release-settings-cc32b2.json.bak`; the JSON `support_note` field contains the proof. | `proof_7a5ec3adabc549d481e10535a147fd8d` |
| `proof-2` | Target 2: establish a session by opening `/`, then follow the app’s `/api/activity` reference in the same session to the corresponding ticket endpoint. The response note contains the proof. Do not reuse another session’s cookie. | `proof_f6f1c5c9acbe4758bf986ea124d0632a` |
| `proof-3` | Target 3: request `/lookup?q=%25%27)%20OR%201%3D1--` (decoded query `q=%') OR 1=1--`). The response includes the restricted record whose content contains the proof. | `proof_9eb314b8937e49fd9274dea26f178bb1` |
| `proof-5` | Target 5: request `/api/clues` to get `/submit-f092e3`; GET that route with `X-Forwarded-For: 127.0.0.1` and extract the proof from the JSON response. | `proof_75875ab7087e44a3b9aa1f576f4d7297` |

Those four answers were already accepted by Game Master status when this attempt was resumed. A fresh recheck of Target 5 confirmed the same header behavior: `/api/clues` returned feature route `/submit-f092e3`, role `analyst`, and deployment `trusted_reverse_proxy`; the feature route returned HTTP 200 JSON with `effect: proxy_trust_admin_bypass` and `evaluated_client: 127.0.0.1`. The fresh proof was not resubmitted because `proof-5` was already accepted.

### Final Target 4 reproduction — `proof-4`

Target 4 was the “Stay in Your Directory” PHP runbook reader. Its root redirected to `/handbook.php`, and the linked runbooks showed that the reader accepts a `doc` query parameter. Requesting the challenge’s mounted objective file through that include returned the proof in the document-viewer section of an HTTP 200 HTML response:

```bash
curl -sS --get \
  --data-urlencode 'doc=../../../../run/huntress/objective.txt' \
  'https://5270838b5f302b049196a237ff7ad7cbee4f789e6b4a1d9a.2026.huntress.ctf.games/handbook.php'
```

The exact body value was `proof_527e5ae29eaf4ac1bc04457c4461786c`. Submit that value as `proof-4`:

```json
{"op":"submit","challenge":"web-exploitation-day-23-forwarded-misgivings/mastery","answers":{"proof-4":"proof_527e5ae29eaf4ac1bc04457c4461786c"}}
```

The Game Master returned `CORRECT` with flag `585feeb596bbb0a280a9233e8e0cd86f`. The follow-up personal status confirmed all five proof IDs accepted. The request read only the challenge’s mounted objective file; it did not access system, configuration, or credential files.
