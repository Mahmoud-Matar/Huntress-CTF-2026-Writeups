# Resolver Revolt

## Challenge

Resolver Revolt asks you to discover the target application's schema and reach a protected reference through an authorization boundary that is enforced inconsistently. The prompt emphasizes changing the protocol surface while the underlying access-control flaw remains the same.

## Single Solve

The assigned GraphQL.js app published a feature route and a protected case reference in `/api/clues`. GraphQL introspection on the feature route exposed `caseIndex` and `case(id: ID!)`, along with the `Case.note` field. Querying the reference marked `reference only` in the index through `case(id)` returned its note despite the analyst role.

- Submitted answer: `proof_4a6245b2c1df4bb8b1fc14c86f2077ea`
- Game Master result: `CORRECT`
- Completion flag: `3c2628cf94303b04eb582ea80bed108f`

## Time Trial

The untimed Time Trial used a fresh Graph Garden instance and a different feature route and case reference. Introspection was not necessary after learning the schema: querying the `case` resolver for the reference exposed the executive follow-up note.

- Submitted answer: `proof_fc55ce8e97504a41bf34ae3c8bc537c2`
- Run was untimed (`run_for_time: false`); no ranked deadline was active.
- Game Master result: `CORRECT`
- Completion flag: `c644cf692494b169de949de0ed778496`

## Mastery Mode

The untimed Mastery bundle assigned four targets across different web surfaces:

1. **Target 1 — Status Sprout:** `robots.txt` identified a deployment archive. Its directory index exposed a backup JSON file containing `proof_1ed494e7acaa4f50976c9e2b36bfca35`.
2. **Target 2 — Pocket SOC:** `/api/activity` retained a reference to an executive case outside Riley's workspace. Fetching that ID from `/api/incidents/10134` returned `proof_9567c15efc4b4dfdb601ea7279e4600d`.
3. **Target 3 — Search Party:** The `/explore?q=` search interpolated the query into SQL. The input `') OR 1=1 --` returned the restricted Executive timeline record, containing `proof_c64a21e490ed452890ef6c8221006597`.
4. **Target 4 — Query Constellation:** The GraphQL feature route exposed `caseIndex` and `case(id)`. The index listed reference 14902 as `reference only`, but the `case` resolver returned its note `proof_4eb2efc5f545416eacaf9e5acfe21bb9` to the analyst.

All four exact proofs were submitted together under `proof-1` through `proof-4`.

- Run was untimed (`run_for_time: false`); no ranked deadline was active.
- Game Master result: `CORRECT`
- Completion flag: `3df499693275df8c3d174e2356a3936e`

## Takeaways

- Enforce record authorization in every resolver and API handler that returns protected fields; an index's visibility marker is not an access-control check.
- Do not leave deployment backups under a publicly served directory.
- Parameterize search queries rather than embedding user input into SQL.
