# Web of Lies — solution write-up

## Challenge and result

- **ID:** `script-analysis-day-24-jsp-webshell-source`
- **Mode:** Single Solve; untimed.
- **Attempt:** `8c19c5b4-dd3c-4528-94a9-8dd79aa552cf`
- **Artifact:** `/home/remnux/files/samples/weboflies_evidence.zip`
- **SHA-256:** `6239594b109301fa09b96af0ff3665ae13f262447f08b0d5129178aacd3c712f`
- **Archive password:** `infected`
- **Scope:** 161 files and 1,516 answer fields.
- **Result:** Game Master returned `CORRECT`; all answer fields were accepted.
- **Flag:** `11001c7cef1afdbcd6ce8c28fa9bb032`

## Method

I verified the archive hash, extracted it into `/home/remnux/files/samples/weboflies_evidence`, and analyzed the samples as inert static-analysis fixtures. I did not run the scripts. The evidence set spans PowerShell, JScript, Batch, VBScript, Python, Bash, Node.js, and additional host and polyglot examples.

For encoded descriptors, I followed the transformation declared in each sample and reconstructed the original fields from the bytes. Across the set, this included Base64, hexadecimal strings and arrays, escaped octets, single-byte and repeating-key XOR, byte addition/subtraction, reversal, and split markers. I used the recovered descriptors to fill exact campaign IDs, URLs, paths, adapters, host profiles, encoding profiles, stage profiles, stage counts, next-language fields, and ordered behavior steps. I submitted answers in artifact-sized groups so a rejected group could be isolated and corrected without confusing its fields with other samples.

The host and polyglot files contain misleading labels and metadata combinations. For those records, I decoded the complete `HUNTRESS_ANALYSIS_V1` descriptor and used the exact recorded role and attack fields, alongside the exact indicators and graph fields. For example, some records label a source `staged_chain` and `T1059` even when their recorded graph is `decode_configuration > return_configuration`. The Game Master accepted the decoded descriptor values for those fields; filenames or a fresh guess from the apparent behavior were insufficient.

For the separate Node.js and Bash operation-graph samples, I reconstructed the declared operation plans and followed the question's graph precedence. Two corrections were needed: the Bash staged chain terminates in `dispatch_process`, and its exact cron path is `/etc/cron.d/update-e1c8a1c276`; the Node.js schedule descriptor maps to cron persistence (`T1053.003`). The Game Master confirmed accepted progress as submissions were completed, then returned `CORRECT` after the final 16 fields were submitted.

## Validation

The final submission covered all 1,516 API-provided answer IDs. A follow-up Game Master status request for the same attempt returned `result: CORRECT` in `single_solve` mode. The attempt had no deadline, and no VPN target was involved.

## Time Trial — regular untimed run

- **ID:** `script-analysis-day-24-jsp-webshell-source/time_trial`
- **Mode:** Time Trial; the assigned run was untimed (`run_for_time: false`, no deadline).
- **Attempt:** `8ff67be4-d929-4dc6-86c5-596480a6289f`
- **Artifact:** `/home/remnux/files/samples/weboflies_time_trial_evidence.zip`
- **SHA-256:** `67d43f9c8bf53fce69a77b45c444f382769ff3e1688e54ac0ae910f7a8ba28df`
- **Archive password:** `infected`
- **Scope:** 162 extracted files and 1,560 answer fields.
- **Result:** Game Master returned `CORRECT`; all answer fields were accepted.
- **Flag:** `9a7426dc008da369668f816af82fbdef`

I kept the active Time Trial attempt and analyzed its assigned archive on REMnux without executing the scripts. The samples carried the same broad language families as the Single Solve, plus a much larger set of JSP polyglot descriptors. I decoded the layered polyglot markers and each language's declared byte transformation, then reconstructed the campaign, indicators, ordered operation graph, stage profile/count, and handoff fields. I checked generated role and ATT&CK labels against each question's complete behavior-graph precedence and exact technique format. This caught differences such as PowerShell collection indicators being embedded in a list, and terminal staged chains in Python and Node.js needing their language-specific Command and Scripting Interpreter sub-techniques.

I submitted the already verified answer groups first, then isolated the remaining language fields by family and narrowed invalid groups to individual IDs. Static inspection resolved the final role, secondary-indicator, and ATT&CK corrections. The Game Master accepted the final 11 fields and returned `CORRECT`. A follow-up status request confirmed the same attempt ID and `time_trial` mode. The attempt was untimed, so no stopwatch was running and no VPN target was involved.

## Mastery — eight-set regular untimed run

- **ID:** `script-analysis-day-24-jsp-webshell-source/mastery`
- **Mode:** Mastery; regular untimed (`run_for_time: false`, no deadline).
- **Attempt:** `b2d11c93-0c2d-40ce-aa71-8434d0c644e6`
- **Artifact:** `/tmp/day24mastery.zip`
- **SHA-256:** `389462f46758f6759d39ea44b9052d2f6e830353e681293846c242089564322b`
- **Archive password:** `infected`
- **Scope:** 8 evidence sets, 1,296 extracted files, and 12,480 answer fields (1,560 per set).
- **Result:** Game Master returned `CORRECT`; the follow-up status returned `CORRECT`, and the refreshed Day 24 list marked this route solved.
- **Flag:** `9637e73ad5299d07906f283f5da30feb`

I analyzed all eight assigned sets as inert source and descriptor data on REMnux; I did not execute the scripts. I reconstructed the language-specific descriptors and checked the resulting role, ATT&CK technique, campaign, indicator, ordered steps, and style fields against each question. For the large JSP/polyglot subset, I decoded the layered `HUNTRESS_ANALYSIS_V1` markers and used the recovered descriptors rather than inferring answers from filenames.

Several parser edge cases needed explicit correction before the final submission. Batch reconstruction lines sometimes included the final variable-expansion expression as if it were another descriptor fragment, so I removed that residue from the actual indicator while retaining the reconstructed file path or host ID. I also added static support for the Bash `decimal_space|reverse_bytes` and `decimal_space|add_modulo_256` codecs; these recovered missing descriptor fields without running the samples. The grader's saved `accepted_ids` let me find and repair the one unresolved Batch style label and verify progress by evidence set. After the final fields were accepted, a follow-up status check confirmed completion.
