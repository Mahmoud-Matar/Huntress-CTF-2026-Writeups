# SQLite Assumptions — Day 12 Single Solve

- **Challenge ID:** `mobile-android-day-12-sqlite-assumptions`
- **Attempt:** `d6394f88-b039-4e95-8bff-e4a7799b69e2`
- **Prompt:** “Reconstruct authorization from a synthetic SQLite cache and prove server-side impact.”
- **Question:** For case `MOB-12-4B4FA1A323` in package `com.huntress.mobile.d12.v4b4fa1a3235d`, submit only the exact backend answer code returned for this case.
- **Answer field:** `answer`; format `ANS-` followed by exactly 16 uppercase hexadecimal characters.
- **Artifact:** `sqlite_assumptions.apk`, 12,704 bytes; SHA-256 `dc892f6eb26966909fcfbfe26bd21dff96723ee5bace2e99dc0a0813e0d0e8d1`.
- **Result:** Game Master returned `CORRECT`; follow-up status confirmed the same attempt as `CORRECT`.
- **Flag:** `306157bf9709d08f7c1bee7a329e8f4c`

## Analysis

Downloaded the APK from this attempt’s Game Master capability and verified its SHA-256. I listed the ZIP members and decompiled the manifest and all three DEX classes with Apktool; no app code or sample was executed. The package contains `AndroidManifest.xml`, `classes.dex`, and `assets/huntress_puzzle.json`, with no SQLite database file in the APK.

The public asset declares schema `huntress.mobile.puzzle.v1`, day 12, and codec `hex`. Decoding its `data` value as hex yields `ANS-039F0D9071111050`. `ChallengeActivity` accepts `answer` and `case_id` through an intent or the exported `huntress12://sqlite-assumptions/unlock` deep link, then constructs a request to a local mobile evidence endpoint using those values. This confirms the answer/proof is supplied by client-controlled app state. The app source also contains an endpoint credential; it is intentionally omitted from this report.

The local evidence endpoint (`127.0.0.1:19090`) was not reachable from either Kali or REMnux, and the corresponding path on the public Game Master host returned `not_found`. I therefore did not claim an independently observed backend response. The artifact-derived code matched the required format, and the Game Master accepted it as the answer for this exact attempt.

## Submission

Submitted the decoded code under the exact `answer` field. Game Master returned `CORRECT`; the subsequent status request confirmed completion with no pending scoring state.

## Time Trial

- **Challenge ID:** `mobile-android-day-12-sqlite-assumptions/time_trial`
- **Attempt:** `fff7e3ba-3505-4c56-a7ed-abc64eb92fc0`
- **Timer:** Legacy timed route; 50-second deadline `2026-10-23T06:51:56.269Z`. The submission and status confirmation completed before expiry.
- **Case / package:** `MOB-12-8D9A4D87D5`; `com.huntress.mobile.d12.v8d9a4d87d5ad`.
- **Artifact:** `sqlite_assumptions.apk`, 12,704 bytes; SHA-256 `7e9d44988c0e3da40ed6f0d3080a2b5a13f9fddf7080d6670bf6962808303116`.
- **Finding:** The `huntress_puzzle.json` asset used the same `huntress.mobile.puzzle.v1` hex encoding. Decoding the exact downloaded bytes yielded `ANS-668B39E20D9A458F`, which was submitted under `answer`.
- **Result:** Game Master returned `CORRECT`; follow-up status confirmed the timed attempt as `CORRECT`.
- **Flag:** `ab50b570e25c35a3fb004bdf7ef7bf6e`

The APK again showed a client-controlled deep-link/intent path forwarding the supplied answer and case ID to a local evidence endpoint. That endpoint was not reachable from Kali or REMnux in this environment, so the accepted code comes from static artifact decoding rather than an independently observed backend response.

## Mastery — three-set bundle

- **Challenge ID:** `mobile-android-day-12-sqlite-assumptions/mastery`
- **Attempt:** `5695a106-0828-42b0-8d70-faac934f46bb`
- **Timer:** Legacy timed route; 110-second deadline `2026-10-23T06:53:59.559Z`. Submission and status confirmation completed before expiry.
- **Assignment:** Three APKs and three answer fields (`set1.answer`, `set2.answer`, `set3.answer`). Each assigned hash matched the downloaded APK. I read each asset on REMnux and decoded its declared hex payload, then constructed the three exact values from those bytes.

| Set | Case | Package | APK SHA-256 | Decoded answer |
| --- | --- | --- | --- | --- |
| 1 | `MOB-12-9006E9D3DE` | `com.huntress.mobile.d12.v9006e9d3de47` | `56eb8230c2b51ce50d4d83f7893f75ef2eca67c0c443eacc93f63fe60b1832f3` | `ANS-CF8DBD28FC3C61A7` |
| 2 | `MOB-12-2A713A3720` | `com.huntress.mobile.d12.v2a713a37204e` | `3ecd4d483190f7a7569c2eb40c4566a755f663cc9b2787057088298902895551` | `ANS-43D00DCBA9762EF1` |
| 3 | `MOB-12-1E85E25BBA` | `com.huntress.mobile.d12.v1e85e25bbab8` | `0e96089ef67c4f2fe2b17ff7d837ac7d95c15efe3f48a8182504296b1e72a1b8` | `ANS-A08AC2B1A2B70E61` |

- **Result:** All three values were submitted under the exact answer IDs. Game Master returned `CORRECT`; follow-up status confirmed the same attempt as `CORRECT`.
- **Flag:** `ec9700b5ffe50c7ed13617e8a748a603`

As in Single Solve and Time Trial, the APKs expose the code in client-readable hex data and pass client-controlled values through a deep-link/intent path. The local evidence endpoint was not reachable from this environment; the three artifact-derived values were accepted by the Game Master.
