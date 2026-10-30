# Make It Make Sense — Day 29

Challenge family: Script Analysis, Makefile variant diff (`script-analysis-day-29-makefile-variant-diff`). The archive password was `infected`. All work used our assigned artifacts, downloaded from the Game Master and analyzed statically on REMnux; no supplied scripts were executed.

## Single Solve

- Attempt: `7144dad1-2614-4ec9-b464-ddee0c9b5568`
- Result: Game Master returned `CORRECT`.
- Archive SHA-256: `0ba75808186d63e2269cd7d69f2d6d2835cd6425300ce2aa9a389204218a1525`

The guided evidence was unpacked and each Makefile/build-chain variant was reconstructed from the supplied files. We decoded the layered payloads and joined their recovered fragments, then compared the resulting build steps, language chains, indicators, and behavior descriptions. Answers were submitted under the exact API-provided answer IDs.

## Time Trial

- Attempt: `6ad2efee-cde5-41ab-a32b-697e9f56eb04`
- Mode: untimed (`run_for_time: false`; no deadline)
- Result: Game Master returned `CORRECT`.
- Archive SHA-256: `2d381898a343392a6722db36a959acc4be58d7fdcfee3491122034c4c9728764`

The assigned archive contained a fresh set of variants. The same static reconstruction process was applied, with parser refinements for language-specific payload formats and chained scripts. A first broad submission exposed parser edge cases; correcting those derivations and resubmitting the precise answer IDs completed the route.

## Mastery

- Attempt: `263e101d-3082-40ae-ae8e-bbb2307e4b13`
- Mode: untimed (`run_for_time: false`; no deadline)
- Result: Game Master returned `CORRECT`; verified again with `GET ?op=status&challenge=script-analysis-day-29-makefile-variant-diff/mastery`.
- Archive SHA-256: `87af5a45dd0ebd7a6c81a2d0295f550f0d3129ef893f04ea0a7a86fcad79e5a2`

The Mastery bundle contained 13 evidence sets and 23,829 answer fields. The analysis recovered the layered Makefile and language-chain data from the assigned files, then derived all fields from their corresponding source material. Answers were submitted incrementally by set and family so incorrect mappings could be isolated without replacing the active attempt.

Two parser edge cases mattered:

1. A Batch indicator parser treated a later reconstruction assignment (`item9=!item0!!item1!!item2!!item3!`) as another source fragment. The actual indicator was the URL reconstructed from the preceding fragments: `https://60996881e1.example.invalid/upload`.
2. Batch style classifications require reading the active control flow and variable-expansion form, rather than classifying only the first visible assignment. In particular, a one-iteration `for /l` loop calling a recovery subroutine classified as `call_subroutine`, and delayed expansion may appear in assignments to differently named destination variables or behind an `if` guard. The corrected style labels were checked individually against the Game Master.

All remaining Batch fields then validated, and the final corrected style answer completed Mastery. The archive hash above identifies this exact assigned variant.

## Reproduction notes and evidence limits

The three archive hashes, attempt IDs, result states, transformation families, and the two Batch edge cases above are the evidence retained in this project. The assigned archives, per-answer JSON, and parser are not present here, so the exact fragments, generated answer map, and full command transcript cannot be reproduced from this write-up alone. In particular, the illustrative URL and style examples above are not substitutes for the missing artifact bytes. A fully repeatable rerun needs the same assigned archives and a saved parser that maps each exact Game Master answer ID to its value; the original service `CORRECT` results are recorded above.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
