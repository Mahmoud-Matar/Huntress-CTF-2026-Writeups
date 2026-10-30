# Press Start to Decode

## Route and result

- Challenge: **Press Start to Decode** (`script-analysis-day-23-game-resource-loader`)
- Mode: Single Solve, untimed
- Attempt: `c887cf61-f06a-4b42-9b6c-10a62907da78`
- Game Master result: **CORRECT**, confirmed by personal `op=status`
- Flag: `b0ed9001472a9eb358526e1070d9b56b`
- Assigned archive: `evidence.zip`, SHA-256 `0e6b2bb25abd2bbf6e42fc8620b9dd8a5dc07118e9d84bd308347679c62d5e55`
- Archive password: `infected`
- Contents: 157 files; extracted size 288,625 bytes

## Approach

The prompt describes layered GDScript resource loading and asks for exact indicators, behavior classifications, and relationships among stages. The assigned archive was downloaded for this attempt, its SHA-256 was checked against the Game Master response, and the ZIP integrity was checked with the published password. All 157 files were inspected as data; the supplied scripts were not executed.

I built the answer map from the attempt's 1,461 exact answer IDs and their question/artifact mappings. Static parsing recovered embedded JSON, descriptor strings, arrays, and codec parameters, then applied only the literal operations visible in source (Base64, hex, byte reversal, XOR, and arithmetic transforms). Batch, JScript, VBScript, Bash, Python, NodeJS, polyglot, and host-container samples each needed their own source-aware decoding or classification. For command-shell and ATT&CK questions, I followed each question's explicit precedence and ignored unrelated wrapper, separator, and plan text.

The Game Master accepted individual findings incrementally. It rejected the initial complete set, which exposed errors in some ATT&CK and command-flow classifications. I narrowed those to exact answer IDs, corrected them from the decoded behavior and source syntax, and continued submitting until the service returned **CORRECT**. The final status and the Day 23 list both marked Single Solve complete.

## Key recovered evidence

The PowerShell resource sample contains a Base64-encoded JSON object whose short keys map to a resource-hijacking scenario. Its exact URL is `https://6f8d01cbfe.example.invalid/bfd9be8acd14.dat`, wallet indicator is `wallet_9cb9d464d2a9ea80013aee90621a6ece`, and mutex is `Global\HuntressLab_b6afa401ea79`. The other two PowerShell samples similarly yielded the collection and impact indicators directly from their decoded JSON.

The GDScript samples carry `HUNTRESS_ANALYSIS_V1` descriptors encoded as hex. The staged-chain sample decodes to a three-stage descriptor with a `decode_embedded → write_file → dispatch_process` behavior graph, a `hex_base64` obfuscation profile, and a VBScript next-stage language. This provides a concrete example of correlating the fields across a loader family rather than treating each encoded string as an isolated answer.

For the remaining corpus, the descriptors exposed exact campaign identifiers, URLs, file paths, adapters, host/container profiles, encoding carriers, stage counts, and ordered behavior steps. JScript samples use packed strings or byte arrays with explicit reverse/XOR transforms; batch samples reconstruct values through fragments and different expansion forms; VBScript and Python samples declare codec/carrier metadata; Bash samples include both decoded behavior plans and advanced syntax specimens; NodeJS and the larger polyglot/host sets expose their fields through inert encoded descriptors.

## Sample hashes

These hashes are for the principal PowerShell and GDScript evidence files inside the assigned archive:

| File | SHA-256 |
| --- | --- |
| `resource-sample.ps1` | `3f17409d71f8c3e96ae0a7d34ca8fd74945b4ca6e041bf851050ade7cc3ec106` |
| `collection-sample.ps1` | `b04beb9452e0d769ec78df4718a665c8b00bb5a99f91b0d0e62e76aa6f321c7b` |
| `impact-sample.ps1` | `02128aa555ffff34a95933a968d81410e944fed2695310933c102eece2ae0044` |
| `polyglot-gdscript-staged-chain.gd` | `0104d9ceb40d5f17c611f961ed373cf90ca77a74d537430212df522f435d8c32` |

## Reproduction

The static parser used to recover encoded descriptors is in [solve_fetch_quest_day17.py](../tools/solve_fetch_quest_day17.py). The Day 23 answer builder is [build_press_start_answers.py](../tools/build_press_start_answers.py); it reads the current attempt JSON and extracted archive under `/tmp/day23-press-start/`, writes a local answer map, and never accesses the Game Master token. Submission was performed separately through the paired Kali Game Master connection.

## Time Trial · untimed regular route

- Challenge: **Press Start to Decode** (`script-analysis-day-23-game-resource-loader/time_trial`)
- Mode: Time Trial route, regular untimed attempt (`run_for_time: false`; no deadline)
- Attempt: `a1225823-87c3-47d7-a0de-352a09418bf5`
- Game Master result: **CORRECT**, confirmed by personal `op=status`
- Flag: `b8f37c5e8021e61118448efe9767eb43`
- Assigned archive: `evidence.zip`, SHA-256 `c360d36ff5f6d754b1e85de870f80b645df235292d520e9ff88034b41d103a7b`
- Archive password: `infected`
- Contents: 157 files; extracted size 369,671 bytes
- Questions: all 1,495 exact answer IDs from the attempt's start response

The attempt used a fresh regular-pool variant. I transferred the assigned archive through the authenticated Kali connection, verified its SHA-256 on REMnux, and analyzed all extracted source as inert data. The reusable static parser was extended to understand the additional `LYR` layered encodings and descriptor layouts. The answer builder was then run against the exact Time Trial question set and files, with a completeness check confirming 1,495 answers for 1,495 answer IDs and no blank values.

The Game Master rejected the first complete submission. Incremental validation isolated eight incorrect fields: five Batch syntax summaries and three ATT&CK mappings. Re-reading the exact source showed that a labeled `CALL` remains the control-flow wrapper even inside a one-iteration `FOR`; ordinary adjacent `%variable%` references are percent expansion, while `CALL SET` performs the second expansion. The NodeJS and Python dispatch specimens recorded their interpreter-specific ATT&CK IDs (`T1059.007` and `T1059.006`). After correcting these source-derived values, the service returned **CORRECT** and personal status confirmed completion. Day 23's list was fetched twice afterward; it now marks this route solved, with Press Start Mastery and Trust Issues as the next unresolved routes in API order.

For this attempt the answer builder used `/tmp/day23-press-start-time.json` and `/tmp/day23-time-trial/` as input paths. The bearer token remained private on Kali.

## Mastery · untimed regular route

- Challenge: **Press Start to Decode** (`script-analysis-day-23-game-resource-loader/mastery`)
- Mode: Mastery, regular untimed attempt (`run_for_time: false`; no deadline)
- Attempt: `7e0c583f-c931-496f-9227-2d7ff801bb36`
- Game Master result: **CORRECT**, confirmed by personal `op=status`
- Flag: `05f533743da3bc6739d3499132ffbf1b`
- Assigned archive: `script-analysis-day-23-game-resource-loader-mastery.zip`, SHA-256 `d43408380ddca72a6a104fe180ec61df2c12bdf9a764339f767f7211f93df2f9`
- Contents: seven AES-encrypted evidence archives, each opened with `infected`; each contained 157 source files
- Questions: all 10,465 exact answer IDs across seven new task sets

I checked every archive member path before extraction, then unpacked the seven nested archives with 7-Zip and the published password. The bytes and question map were transferred privately from Kali to REMnux; the outer archive hash matched the Game Master value. I extended the static parser for JScript callback-based rolling-XOR and reverse transforms, and generalized the answer builder to select each file from its corresponding set rather than accidentally mixing repeated filenames across sets. The builder produced a complete map with one nonblank answer for every question ID.

The initial full submission was rejected. Incremental validation isolated incorrect Batch style summaries and a PowerShell mutex field. Source review showed that a `FOR` loop calling `SET` over indexed fragments uses indirect expansion; the control-flow summary must reflect the actual guard or labeled subroutine, and collection/resource/impact tertiary indicators must be selected by their decoded value type (user agent, mutex, or encrypted extension). Correcting these source-derived fields cleared the remaining findings. The Game Master returned **CORRECT**, and personal status confirmed the attempt. Two fresh Day 23 lists then showed Press Start complete in all three modes and Trust Issues first unresolved.

The final answer set was generated from `/tmp/day23-mastery-start.json` and `/tmp/day23-mastery/sets/` by [build_press_start_answers.py](../tools/build_press_start_answers.py). The updated reusable parser is [solve_fetch_quest_day17.py](../tools/solve_fetch_quest_day17.py). The bearer token remained private on Kali.

## Tools and scripts

Project helpers: [`tools/build_press_start_answers.py`](../tools/build_press_start_answers.py), [`tools/solve_fetch_quest_day17.py`](../tools/solve_fetch_quest_day17.py).
