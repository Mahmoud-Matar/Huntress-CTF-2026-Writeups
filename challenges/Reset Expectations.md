# Reset Expectations

## Challenge

Reset Expectations is a web exploitation challenge about a password recovery flow that trusts an account identifier supplied at redemption time. The target advertises a Symfony analyst workspace and exposes its route inventory through `/api/clues` and account recovery details through `/api/recovery`.

## Single Solve

The assigned app exposed a self-service analyst account and a non-self-service executive account. I requested a recovery token for the analyst account, then submitted that token to the redemption route while changing `account_id` to the executive account. The redemption endpoint accepted the mismatch and returned the required evidence.

- Submitted answer: `proof_2ed4dc2cc52841cbbb1259f9a031c21a`
- Game Master result: `CORRECT`
- Completion flag: `b1bc917cd051070cc4fa1e741d72efdb`

## Time Trial

The untimed Time Trial issued a fresh target with the same account-binding flaw but different per-target IDs and token. I read the target's recovery guide, requested a token for its analyst account, and redeemed it against the executive account ID.

- Submitted answer: `proof_a1b79a44114b4d97a0390ecb1a2ff0b7`
- Run was untimed (`run_for_time: false`); no ranked deadline was active.
- Game Master result: `CORRECT`
- Completion flag: `72e3c6b8d9e6a3535666d0e91952ce1f`

## Mastery Mode

The untimed Mastery bundle assigned four fresh targets using several different authorization mistakes:

1. **Target 1 — Status Sprout:** `robots.txt` disclosed a release directory. Its browsable index exposed `environment-copy-ef6f12.json.bak`, which contained the support proof `proof_2db5a5c4b24443148769e72996e721da`.
2. **Target 2 — Tiny Triage:** The session was signed in as Riley. `/api/events` retained a reference to executive case 13987 despite the case having moved outside the workspace. Fetching `/api/tickets/13987` returned the restricted case note `proof_352fe12405b2407c9098885704beaa88`.
3. **Target 3 — Search Party:** The `/lookup?q=` search concatenated input into a SQL expression. The query `') OR 1=1 --` returned all rows, including the private escalation record 17499, whose content was `proof_ea709c0df2514052b6383b8c29263656`.
4. **Target 4 — Recovery Nook:** As in Single Solve, a token issued for the analyst account was accepted when the redemption request named the executive account. The endpoint returned `proof_a1a26751c07947aca0c418fddc0179f0`.

All four exact proofs were submitted together under `proof-1` through `proof-4`.

- Run was untimed (`run_for_time: false`); no ranked deadline was active.
- Game Master result: `CORRECT`
- Completion flag: `c491f6239ce426d9601517b5b3f52369`

## Takeaways

- Bind a reset token to the account for which it was issued; do not trust a second account identifier supplied at redemption.
- Check authorization on the record API itself, not only on the dashboard or case navigation.
- Build search queries with parameters rather than interpolating user-controlled input into SQL.
- Keep deployment backups and their containing directories out of public web roots.
