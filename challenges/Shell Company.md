# Shell Company

## Single Solve

- **Challenge ID:** `web-exploitation-day-16-shell-company`
- **Curriculum day shown by the API:** 16; the route was published in the Day 25 list and Day 25 course chapter.
- **Attempt:** `f8fb6277-de89-4cc9-a66f-62c98d5ef9b1`
- **Mode:** Single Solve, untimed
- **Target:** Game Master-assigned Target 1
- **Answer field:** `proof-1`

### Analysis

The public course lesson described a single dynamic target and directed players to retrieve its live instructions through the Game Master. The assigned target presented a Gin-based analyst workspace. Its `/api/clues` response identified `/process-38db5f` as the feature route and `path` as the input parameter, with `/app/static` as an example.

The feature endpoint returned the result of a worker command. Supplying `/app/static; id` in `path` caused the target to execute the additional command and include its output, confirming shell command injection. The command ran as the unprivileged `arena` account. I then used that injection to read `/run/huntress/objective.txt`, which returned the target-specific proof.

### Result

Submitted the recovered proof under `proof-1`. The Game Master returned `CORRECT`, and a follow-up status check confirmed the attempt.

- **Flag:** `5fbbb7c3da0b4fd7641650f4f841e392`

## Time Trial

- **Challenge ID:** `web-exploitation-day-16-shell-company/time_trial`
- **Attempt:** `d62c6c1f-5b97-4aa0-9100-c6f66ca1e8a1`
- **Mode:** Time Trial, untimed (`run_for_time:false`, no deadline)
- **Assigned target:** Target 1, a fresh target instance
- **Answer field:** `proof-1`

### Analysis and result

The fresh target's `/api/clues` response mapped the `path` parameter to `/execute-500cbc`. I repeated the confirmed shell injection against this assigned instance and read its `/run/huntress/objective.txt`, which supplied the proof for this attempt. The Game Master returned `CORRECT`; a follow-up status request confirmed the result.

- **Flag:** `8671f7aeacdd2bc28e29435011530f63`

## Mastery

- **Challenge ID:** `web-exploitation-day-16-shell-company/mastery`
- **Attempt:** `a962eb54-6887-4e41-9a59-2c048245a43c`
- **Mode:** Mastery, untimed (`run_for_time:false`, no deadline)
- **Answer fields:** `proof-1` through `proof-4`

### Assigned target findings

The Game Master assigned four fresh targets. I inspected each target independently and used the evidence available in that instance:

| Target | Finding | Proof source |
| --- | --- | --- |
| 1 | `robots.txt` disclosed an archive path. The archive contained a deployment backup with a `support_note` proof. | `proof_53d95947502a4f2bb315896dbb749046` |
| 2 | The dashboard issued a session cookie. Its activity feed referenced case `17329` as moved outside the workspace; the case JSON endpoint returned the restricted record and proof. | `proof_ae26f2f0c051475a8ffa488198820d6e` |
| 3 | `/healthz` identified a Flask SQLite search app. A boolean-based blind SQL injection in the `q` parameter exposed a fourth `articles` row omitted from the three visible search results. I limited extraction to that row's ID and summary. | `proof_59d3d3a7ff0148dcbd44f33774cf9092` |
| 4 | `/api/clues` mapped `path` to the assigned Gin command route. A semicolon injection ran a command as the unprivileged `arena` user and read the target objective proof. | `proof_212626d5c48c4535a983d108b868c530` |

### Result

All four proofs were accepted across the bundle. The Game Master returned `CORRECT`, and a follow-up personal status check confirmed the mastery attempt.

- **Flag:** `64fb9eae204428841cbce145accadb14`
