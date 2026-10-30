# Ashes to Assets — Day 25 Single Solve

## Result

The Day 25 Single Solve route `script-analysis-day-25-phoenix-stage-chain` is **CORRECT** for Jinzo's team. The untimed attempt was `b6d55c93-c43b-4b23-870e-bb2bea5ba067`; Game Master status confirmed completion at 2026-10-25 19:23:15 UTC. There was no running deadline. The assigned `evidence.zip` SHA-256 was `16a0930e89b42ac708a641e48a27754158f937a7a6ae3336ab518eb0617020dc`. It contained 167 files and was opened with the published password `infected`.

The assignment asked for 1,571 answer fields across the PowerShell, JScript, CMD/BAT, VBScript, Python, Bash, Node.js, and polyglot fixtures. The Game Master accepted every field and returned `CORRECT`.

## Analysis

I treated the archive as inert source and data. I did not run its scripts. After extracting the exact assigned bytes, I built a static answer map from the source files and their declared encodings:

- Decoded the `HUNTRESS_ANALYSIS_V1` encoded headers and split fragments, then parsed the recovered key/value descriptors.
- Reconstructed PowerShell base64 JSON and followed each script's declared ordered operation graph.
- Read JScript packed text/byte arrays, reversals and XOR transforms; then inspected the `eval(recover_...)` assignment and only the recovered object's `steps`, `adapter`, `values`, and `stageCount` accesses for the syntax questions.
- Joined CMD/BAT fragment variables according to the actual reconstruction statement, distinguishing percent, delayed, CALL-double, and FOR-indirect expansion from unrelated output and separator lines.
- Decoded VBScript `Material_*` and `Codec_*` constants and classified the recovery wrapper from the source control flow.
- Statically decoded the Python, Bash, and Node.js descriptors and retained the exact packaging, syntax, carrier, adapter, and indicator fields.

The answer map was grouped by source artifact. When a group was rejected, I submitted its fields individually and corrected only the field the Game Master rejected. This exposed two useful details in the fixtures: some polyglot descriptors intentionally carry explicit `role` and `attack` values that differ from a shallow graph-only guess, and some staged chains end in `dispatch_process` rather than `handoff_script`. I used the exact decoded descriptor fields where present and the complete ordered graph where they were absent. For the Python process-dispatch specimens, the accepted technique was `T1059.006`; the cron descriptor route accepted `T1053.003`.

## Validation

The final personal status response named the same attempt ID and returned `CORRECT`, with `solved_by.name` set to `Jinzo`. No separate flag was returned by this multi-answer route. The archive hash above identifies the exact assigned evidence used for the solve.

# Ashes to Assets — Day 25 Time Trial

## Result

The `script-analysis-day-25-phoenix-stage-chain/time_trial` route is **CORRECT** for Jinzo's team. The attempt ID was `d660358d-1f57-4ac7-b97b-77c6386d7c92`, started at 2026-10-25 19:24:59 UTC, and completed at 2026-10-25 19:48:30 UTC. The route ran untimed (`run_for_time:false`), so no countdown was active. The assigned `evidence.zip` SHA-256 was `93ef846673ea497924b414da9bcd1e591a28a306512470252c1685e7b9bc9b8a`. The archive password published by the challenge was `infected`.

The Game Master required 1,625 answer fields spanning the archive's script and polyglot fixtures. All fields were accepted, and the final status returned `CORRECT` with `solved_by.name` set to `Jinzo`.

## Analysis

I worked from the exact assigned archive, extracted it on REMnux, and treated every script as inert data. I did not execute the specimens. I decoded each fixture's declared material and codec, reconstructed its analysis descriptor, and mapped those values to the corresponding Game Master answer IDs. Analysis covered PowerShell JSON, JScript packed descriptors and ordered steps, CMD/BAT and VBScript reconstruction wrappers, and the Python, Bash, Node.js, and polyglot descriptors.

For wrapper questions, I classified the actual reconstruction path rather than nearby separator or decoy code. This mattered for batch files: the control-flow label could come from a subroutine call even when a loop also reconstructed the descriptor. For VBScript, the wrapper labels followed the control flow inside `Recover_*` (including one-pass loops and error guards). JScript step arrays had to be submitted as ordered tokens joined by `>`.

The Game Master's field-level feedback corrected several initial misses. PowerShell collection questions wanted the first staged filename from the collection list; the URL field came from the decoded URL value. For graph classification, the complete terminal intent controlled the role: a multistage profile/acquire/write chain ending in `dispatch_process` was `staged_chain`. ATT&CK answers used the interpreter-specific subtechnique when dispatch was the selected terminal behavior, including Python `T1059.006`, VBScript `T1059.005`, and Node.js `T1059.007`; the cron persistence specimen used `T1053.003`.

## Validation

The Game Master accepted all 1,625 fields and the personal status endpoint returned `CORRECT` for the same attempt. The archive hash above identifies the exact evidence used. No flag or pairing credential is included in this report.


# Ashes to Assets — Day 25 Mastery

## Result

The `script-analysis-day-25-phoenix-stage-chain/mastery` route is **CORRECT** for Jinzo's team. The attempt ID was `31a34f3c-20a7-4e94-bc4f-cb8fb7715e16`, started at 2026-10-25 19:50:02 UTC, and completed at 2026-10-25 20:27:21 UTC. It ran untimed (`run_for_time:false`), with no countdown. The assigned archive SHA-256 was `5167050fc98cd430af0391c54246f30b24e7b6f3e73d9b86049b268a4ae8e599`; its published password was `infected`.

The archive held nine nested evidence sets, with 14,625 answer fields in total across the script and polyglot fixtures. The Game Master accepted every field and the final personal status returned `CORRECT`, with `solved_by.name` set to `Jinzo`.

## Analysis

I extracted and analyzed the assigned archive on REMnux as inert source and data; I did not execute its scripts. I statically decoded the Elixir/Phoenix configuration chain and each nested language fixture, including PowerShell base64 JSON, JScript packed material, CMD/BAT fragments, VBScript codecs, and Python, Bash, Node.js, and polyglot descriptors. I mapped each decoded value to the exact answer ID supplied by the Game Master.

The main correction was to follow each decoded ordered behavior graph through its terminal action. That resolved the role and ATT&CK fields, including distinctions among benign configuration returns, staging, file writes, uploads, process dispatch, cron persistence, and encryption impact. For batch and VBScript style fields, I checked the source statement that actually reconstructed the descriptor and its surrounding wrapper, then submitted the graph topology, control-flow wrapper, and expansion or codec labels in the requested order. PowerShell tertiary indicators were selected from the decoded sample data: mutex, collection user agent, or encrypted-file extension according to the sample.

## Validation

The Game Master returned `CORRECT` for attempt `31a34f3c-20a7-4e94-bc4f-cb8fb7715e16`. No separate flag was returned for this multi-answer route. The archive hash above identifies the exact assigned evidence; no pairing credential is included in this report.
