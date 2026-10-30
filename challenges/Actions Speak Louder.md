# Actions Speak Louder

## Day 21 · Single Solve

- Challenge ID: `script-analysis-day-21-github-actions-persistence`
- Attempt: `cca39981-f577-4e9f-b504-b55efd7d284d`
- Timer: none; this was the untimed static route.
- Assigned archive: `evidence.zip` (CourseStack lesson filename: `actions_speak_louder.zip`)
- Archive SHA-256: `e005f70c2a553e72ce46d151f6aaa431f2b7b717991002b7643c971c19d046`
- Archive password: `infected`

## Analysis

The archive was downloaded from the assigned Game Master attempt and its SHA-256 was checked before extraction. I inspected the files statically; I did not execute the scripts. The archive contains inert script-analysis fixtures across PowerShell, JScript, Batch, VBScript, Python packaging formats, Node.js, Bash, and a large set of polyglot language samples.

### Reproduce the analysis sequence

1. Obtain the archive for the same mode and compare its SHA-256 with the value in that mode's metadata above. Do not reuse an archive from another mode: each route assigns its own bytes.
2. Extract the archive with the published password `infected`. Treat the scripts as evidence; do not run them.
3. Use the existing static decoder [tools/solve_fetch_quest_day17.py](../tools/solve_fetch_quest_day17.py) and answer-map builder [tools/build_actions_louder_answers.py](../tools/build_actions_louder_answers.py) against the extracted evidence. The analysis records these helper names, but not their command-line argument syntax, so no invocation is guessed here.
4. For each sample, derive the descriptor from its actual encoding and map the recovered values to the exact question IDs and formats returned for that attempt. In particular, inspect the JScript recovery operations before parsing its literal bytes, and classify Batch expansion/control flow from the descriptor reconstruction statement rather than nearby envelope or separator lines.
5. Validate each field against the mode's Game Master response. The accepted corrections recorded below are useful checks against common misclassifications, but they do not replace analysis of a different variant.

The questions ask for the reconstructed descriptor fields: ordered behavior steps, role, ATT&CK mapping, adapter, synthetic campaign and host identifiers, stage count, file/URL indicators, host and stage profiles, obfuscation profile, language handoff, and several language-specific syntax details. I used the existing static decoder in [tools/solve_fetch_quest_day17.py](../tools/solve_fetch_quest_day17.py) and added [tools/build_actions_louder_answers.py](../tools/build_actions_louder_answers.py) to map decoded fields to the exact question IDs. For the JScript `host-context.js` sample, its literal byte array is reversed in the recovery function and reversed again by the decoder; those static transformations cancel, so the JSON can be parsed directly from the bytes without running the script.

The Batch questions required distinguishing the expansion and control flow of the descriptor reconstruction statement from unrelated host-envelope and separator lines. The Node.js persistence sample decodes to `build_schedule,register_descriptor`, uses a cron descriptor, and points to `/etc/cron.d/node-3fdba8`, so its specific ATT&CK mapping is `T1053.003` (Cron).## Result

The assignment contained 1,373 answer fields. The Game Master accepted the answers under their exact returned IDs; after correcting the Batch classifications and the Node.js cron sub-technique, the submission returned `CORRECT` with flag `944f1fa252bcb8f65cf9878a6ee557bc`. A fresh Day 21 list/status audit confirmed this Single Solve route is complete and has no pending scoring.

## Day 21 · Time Trial

- Challenge ID: `script-analysis-day-21-github-actions-persistence/time_trial`
- Attempt: `f9aed53c-18f1-42d5-846d-3458def51914`
- Timer: untimed regular run; no ranked timer was requested.
- Assigned archive: `evidence.zip`
- Archive SHA-256: `efe0a6184897d12e3ab1ac6be96bb0223f68037feffbc9cd4eb99eea1481e7d8`
- Archive password: `infected`

I reused the static descriptor workflow against this attempt's fresh archive and rebuilt all 1,373 answers from its assigned bytes. The changed Batch samples showed why expansion and control-flow answers must be read from each assigned variant: the statement could use CALL-double, percent, delayed, or FOR-indirect expansion, while an enclosing wrapper could be a subroutine, conditional, dispatch label, or direct execution. The Game Master accepted the answer fields and returned `CORRECT` with flag `1ef1cb72ed5ec56e2a0281e29063564e`. A fresh Day 21 status audit confirmed completion with no pending scoring.

## Day 21 · Mastery

- Challenge ID: `script-analysis-day-21-github-actions-persistence/mastery`
- Attempt: `a00d25e4-df3f-4ee7-8179-817f662b57d6`
- Timer: untimed regular run; no ranked timer was requested.
- Assigned archive: `script-analysis-day-21-github-actions-persistence-mastery.zip`
- Archive SHA-256: `8c69f307eda09ee75c2d1c00ee4f67748f14a933273a029646c31edcd92e2611`
- Archive password: `infected`

The mastery archive contained five assigned evidence sets and 6,865 answer fields. I extracted each set and statically reconstructed the answers from its own bytes, then checked every returned answer ID and enum/integer format before submission. The first combined submission exposed one incorrect Batch control-flow classification. In set 1, `impact-plan.cmd` initializes `HUNTRESS_READY` before the descriptor reconstruction, so the accepted control wrapper was `if_guard`. After correcting that field, Game Master status returned `CORRECT` with flag `27b8a11e2e6437216da6aad11bc5600f`. The route status was rechecked after submission.

*Writeup structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helpers: [`tools/build_actions_louder_answers.py`](../tools/build_actions_louder_answers.py), [`tools/solve_fetch_quest_day17.py`](../tools/solve_fetch_quest_day17.py), [`tools/build_actions_louder_mastery_answers.py`](../tools/build_actions_louder_mastery_answers.py).
