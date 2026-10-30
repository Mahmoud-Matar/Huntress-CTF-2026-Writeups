# Fetch Quest

## Single Solve

- **Challenge ID:** `script-analysis-day-17-download-graph`
- **Mode:** Single Solve, untimed
- **Attempt:** `fb706cdb-3e83-4fc2-a706-e8357203350b`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `fe5c28a3276922d02e6db9106ade56b0037dbdcccdec2ceab2793eb0b6e50867`
- **Findings:** 1,139 answer fields across the assigned script and host fixtures
- **Result:** Game Master returned `CORRECT` after all answers were accepted.
- **Flag:** `7115e96762b350b46ac0d12de7d77ed4`

### Approach

I resumed the assigned single-solve attempt through the paired Game Master endpoint, downloaded the exact archive, verified its SHA-256, and extracted it on REMnux with the published password. I kept the complete start response and the generated answer map in the project for reproducibility. Analysis was static; I did not run the challenge scripts.

The archive contained PowerShell JSON fixtures; JScript, VBScript, Batch, Python, Bash, and Node.js examples; and polyglot and host-context descriptors. I recovered encoded strings from their literal carriers, then applied only the transforms present in the source: Base64/hex/decimal decoding, reversal, bytewise addition or subtraction, single-byte and repeating-key XOR, and rolling XOR. I reconstructed Batch fragments by following their indexed `set` assignments and validated the question-specific expansion and control-flow forms. I extracted the decoded behavior graphs and their associated campaign, host, adapter, URL, path, stage, obfuscation, and host-profile values directly from the assigned files.

For each question, I used the exact answer ID and format from the start response. Role questions were classified from the graph or explicit inert role descriptor according to their wording; ATT&CK answers followed the question's precedence and the fixture's explicit attack field where the Game Master validated that field. I compared the generated keys to the full set of 1,139 answer IDs and submitted in small groups to isolate incorrect mappings. The Game Master accepted the final 46 outstanding answers and returned `CORRECT` with the flag above.

### Submission

The final response from the Game Master was `CORRECT`; all 1,139 answer IDs were accepted for the same attempt. No deadline was active.

## Time Trial

- **Challenge ID:** `script-analysis-day-17-download-graph/time_trial`
- **Mode:** Time Trial, untimed (`run_for_time: false`; no deadline was active)
- **Attempt:** `07287d6f-a271-46ee-90e3-5fa1ce5576d9`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `434d9279606b72196984e5879f07aef75fd30e997a3e28abc69e320eb108bc01`
- **Findings:** 1,139 answer fields across 127 files
- **Result:** Game Master returned `CORRECT`; a subsequent status check also returned `CORRECT` for this attempt.
- **Flag:** `24d55e960bd797d6d882f7102ffe7728`

### Approach

I resumed the current Time Trial attempt and downloaded its assigned archive through the paired Game Master connection. After checking the hash, I extracted the AES-encrypted ZIP with the published password and analyzed the scripts as data without running them. This variant used additional encodings, including reversed hex, decimal values separated by pipes, numeric arrays, percent escapes, JavaScript Unicode byte escapes, and a multiline Python string carrier. I recovered each descriptor by applying only the transforms explicitly present in its source.

I generated an answer map keyed by all 1,139 exact answer IDs and compared the keys against the Game Master assignment. The Game Master accepted the correct groups and isolated eight incorrect mappings. Reviewing the relevant source statements showed that the Batch questions asked about the reconstruction wrapper itself, not incidental lines: the relevant forms included percent expansion, delayed expansion, FOR-indirect expansion, and `goto_dispatch`. The Node.js schedule descriptor writes under `/etc/cron.d`, so its specific ATT&CK mapping is `T1053.003` (Cron). After correcting those values, the final remaining Batch control-flow answer was `goto_dispatch`; submission returned `CORRECT`.

## Mastery

- **Challenge ID:** `script-analysis-day-17-download-graph/mastery`
- **Mode:** Mastery, untimed (`run_for_time: false`; no deadline was active)
- **Attempt:** `70a3b59b-64e0-45ef-a7d3-e10dffbb4333`
- **Artifact:** `script-analysis-day-17-download-graph-mastery.zip` (password: `infected`)
- **SHA-256:** `1e3cf6dd1ca27d32d8b436cd2cd56a30f28dc4670ee1de12e718e45329543dbf`
- **Findings:** Five evidence sets, 127 files each, and 5,695 answer fields total
- **Result:** Game Master status returned `CORRECT` for the same attempt.
- **Flag:** `30a772f4ce3fd11e6f03813d36636a3a`

### Approach

I downloaded the assigned outer archive through the Game Master, checked its SHA-256, and used REMnux to extract the five password-protected evidence archives. I analyzed all 635 files statically. The answer builder used the exact question IDs from the Mastery assignment and recovered the encoded descriptors from the source literals, including escaped octets, rolling XOR, reversed numeric carriers, and the Batch fragments. All 5,695 answer IDs were covered before submission.

The Game Master isolated the remaining errors to Batch control-flow/expansion classifications and the schedule technique mapping. I rechecked each indicated reconstruction statement in its assigned set, then submitted corrected values in small groups. The grading service accepted `call_subroutine` for three one-iteration `FOR /L` wrappers whose question wording described `for_once`; this is the value the service validated. The Node.js schedule descriptors point into `/etc/cron.d`, so the accepted ATT&CK mapping was `T1053.003`. The final submission returned `CORRECT`, and a subsequent status request confirmed completion.

## Reproducing the retained parser work

[`tools/solve_fetch_quest_day17.py`](../tools/solve_fetch_quest_day17.py) contains the static descriptor decoder used during the investigation. It is environment-specific: its archive, start-response, and extracted-directory paths are constants near the top of the file. For a replay, change those paths to the exact assigned mode's files before running `python3 tools/solve_fetch_quest_day17.py`. The helper inspects source text and literals as data; it does not execute challenge scripts. It prints decoded descriptors and parser failures, so compare the failures and output against the actual question IDs before constructing a submission.

This script is not a complete one-command submission solver: it does not itself preserve a verified answer JSON or submit to the Game Master. The write-up also does not retain the full answer map for every mode. Reproduce the outer archive hash check and `infected` extraction separately, then map recovered values to the current assignment's exact answer IDs. Fresh Time Trial and Mastery variants must be decoded independently.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_fetch_quest_day17.py`](../tools/solve_fetch_quest_day17.py), [`tools/build_fetch_quest_answers.py`](../tools/build_fetch_quest_answers.py).
