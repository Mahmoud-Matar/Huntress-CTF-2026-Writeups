# Same Same, But Different — solution write-up

## Challenge

**Day 16, Script Analysis — Same Same, But Different** (`script-analysis-day-16-obfuscation-equivalence`)

The task was to reconstruct inert script descriptors across several obfuscation families, classify each ordered behavior graph, recover its indicators, and answer language and batch-syntax questions. All three routes were completed for the current team.

## Method

I downloaded the exact Game Master archive for each mode, verified its SHA-256, and extracted the nested archives with the published password `infected`. I analyzed source and embedded data statically on REMnux; I did not execute the scripts.

The main workflow was to identify each sample's material constant, read its codec and loader/decoder, then reproduce those byte operations in their stated order. The fixtures used forms such as custom-alphabet Base64, decimal and hexadecimal byte arrays, reversed text or byte sequences, XOR (including repeating-key and rolling XOR), and modular byte arithmetic. Several descriptors were split across source fragments, so I concatenated the literal fragments and checked the reconstruction expression in the source. For Python bytecode-carrier examples, I recovered the descriptor from the visible material and decoder, then read the declared syntax, obfuscation, carrier, and Windows-chain profiles from the static fixture.

For behavior questions, I followed the decoded `steps` in order and applied the exact precedence in each question. In particular, staged chains ending in script handoff and relays ending in next-stage dispatch take priority over earlier acquisition steps where the rubric says so. I treated the `HUNTRESS_ANALYSIS_V1` comments and separator or host-envelope commands as possible decoys: answers came from the active reconstruction code and the descriptor fields. Batch expansion and control-flow answers came from the statement that rebuilds the descriptor and the wrapper that reaches that statement, rather than unrelated `echo`, `goto`, or error-checking noise.

The Mastery route contains five evidence sets with 1,095 answer fields each. I grouped submissions by source artifact, then isolated the few rejected fields individually. The final accepted fields came from correcting the staged-chain roles and interpreter mappings, removing fragment markers from exact values, and classifying batch `goto` dispatch wrappers correctly.

## Assigned archive hashes

| Mode | Attempt ID | SHA-256 |
| --- | --- | --- |
| Single Solve | `c61abbb5-de8e-49c5-a8ad-87906f01de5a` | `be61ff1436f7c9ed9036ecf2623877472086c08cae4dc86faed91dab9ae31c76` |
| Time Trial | `9fcdd29d-55df-473a-ab88-3be6db9705a9` | `a9244ef6d1c6ca018b8ef521a61212c132284557a6799a83b6e70dcd0d764d32` |
| Mastery | `686d30dc-2355-4cc6-9a4a-3363e5699d6d` | `015a5f259b10a3a63d008d3e8febd8e673d18a8fec8cb22ce807278ead0e817d` |

## Results

- **Single Solve:** Game Master status is `CORRECT`. Flag: `5fdbca957347cb0fcaa276ebdf3c6469`.
- **Time Trial:** Game Master status is `CORRECT`. This was an untimed scored run (`run_for_time: false`; no deadline). Flag: `435c59e12c00ac8e991e6123d1e89a45`.
- **Mastery:** all 5,475 fields were accepted and Game Master status is `CORRECT`. This was also untimed (`run_for_time: false`; no deadline). Flag: `e12e4f088ca6d3eac5c22f45df8682ed`.

After completion, two identical Day 16 list responses showed all three Same Same, But Different modes solved. The first unsolved route in the ordered list is **Wasm Up** (`binary-reverse-engineering-day-16-webassembly-optimization-equivalence`).

## Reproduction limits and checks

The stored write-up preserves the three outer archive hashes, flags, and the accepted interpretation rules, but it does not include a complete answer JSON or retained decoder script. For a full replay, use the exact archive for the selected mode, extract nested archives with `infected`, and regenerate all fields from that mode's files. Validate field IDs against that attempt's start response and keep the five Mastery sets separate. The role and technique rules in this report are interpretive checks; values from the Single Solve must not be copied to a fresh variant.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
