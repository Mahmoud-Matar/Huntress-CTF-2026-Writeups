# Fraternal Twins — Day 29

**Challenge ID:** `binary-reverse-engineering-day-29-variant-diffing`  
**Prompt:** “Two binaries, same source, different compiler moods. Diff the variants, account for every optimization, and prove they're semantically the same program.”

All three routes were solved from the assigned `evidence.zip` files and verified by the Game Master as `CORRECT`. The Time Trial and Mastery were run untimed (`run_for_time: false`); neither had a deadline.

| Mode | Attempt ID | Assigned archive SHA-256 | Result |
|---|---|---|---|
| Single Solve | `3bc0352e-88d3-4d45-8d5a-01d6f3b68b47` | `54198f2cc3fd2f8f00bee312366a5c9832956aff82ad0c5e653399a64d2fdc24` | `CORRECT` |
| Time Trial | `c1febd5b-0a01-49a4-b403-d21c4f50c19d` | `10d8a1c855b63477aec69d9f7396956e797360b17218bd249791d6b08d3c6ebf` | `CORRECT` |
| Mastery | `bf849480-1e37-4a0b-b8d5-0673d634bccf` | 13 assigned archives; hashes below | `CORRECT` |

## Method

I downloaded each archive through the paired Game Master connection and verified its SHA-256 before extraction. The ZIP password was `infected`. Analysis was performed against the extracted bytes on REMnux.

For the cumulative sets, I used a static parser to answer the artifact-derived fields directly from each set’s files: archive member hashes and central-directory order; ELF headers, sections, symbols, and symbol-table predicates; PE/COFF symbols, CLR metadata, and HCFG records; JAR manifests and class files; WebAssembly data; and embedded configuration records. HCFG values were decoded with the one-byte XOR key and checked against the recorded CRC32 before using their JSON properties. The Mastery contained 13 sets and 5,278 answer fields; I generated one answer per exact Game Master answer ID and submitted the complete set.

## Corrections that mattered

- In Single Solve, the Day 13 symbol count is **771** when counting the parser’s nonempty `SHT_SYMTAB` entries; including dynamic-symbol-table entries gives a different count and is not what the question asks.
- The Day 23 decoy predicate is **true**. The lowercase text `decoy` occurs as UTF-16LE bytes at an odd file offset. Decoding the whole file as UTF-16LE from offset zero misses that unaligned sequence; searching the raw bytes for the UTF-16LE encoding finds it.
- The Day 10 section-count field was answered from the executable’s actual section table. Most assigned variants carried a PE despite the prompt’s ELF wording, so I read the PE section count for those files; the ELF variant was parsed as ELF.
- In the Day 29 Time Trial O0/O3 pair, focused disassembly found the sole `.text` byte change at `0x4024e9`: the immediate length passed to `fb_StrInit` changes from `0x0c` to `0x0a`. The referenced `.data` string changes from `unoptimized` to `optimized` (the lengths include the terminating NUL). The decoded HCFG objects match, and this code change labels the build variant rather than changing the configuration or the program’s challenge-relevant behavior.

## Mastery archive hashes

Each hash corresponds to the matching `setN-evidence.zip` assignment, in Game Master order.

| Set | SHA-256 |
|---:|---|
| 1 | `8c896a4ceb7d90aaadf2d8e95ed4aebf82586a6bb6488c56cdd13be6b7f1f449` |
| 2 | `723f9953c2e8f04014370d8cd0491b485065c146bdf88394463297e64f800d41` |
| 3 | `6855b3f300f3f0ff630e592012964d5a7d4abeba6b59ff23258fbdd0be541c8f` |
| 4 | `6a1986821cf3a59758d1f63ff7cc0c309ea8bc9042d74e3fd418f9753842d7c6` |
| 5 | `b0c0b268fe74e2cd4de2701080236789ee94415b1d45c81b2a6123202f06cfab` |
| 6 | `5092fd52e28e4899bad2f87179f2ce683e404e6dfd6b006973f6978b6253b2ac` |
| 7 | `1e4f3d8f7fef92beab0a21f43e01a98360539e6f2867bd6cedb301fc34ffe5ec` |
| 8 | `799bc815c37ef147029811ed028238c753190f7c8f1eef059f0ac02739d6e058` |
| 9 | `eec616d862f37254f3b528365da98ac5bd45983ca63037fb6b2ab09b1f61666a` |
| 10 | `4942735f045f9219f642039607f6bbeb07db22c9bfa2cd1f0615291ac8ae4f3f` |
| 11 | `089d22dabc03d6c8f8206abe6b5a825d305f30b9e7a50f1a88d57dea14597144` |
| 12 | `8352159097842784e45653a567e4a9dd6cabe198cf78d778052b0c562e2c09a9` |
| 13 | `7eb95ec969f366f2d28041f4fda0ef83b8e05472cfb7301e9ea1025184d5f10d` |

## Verification

After submission, `GET ?op=status` returned `CORRECT` for Single Solve, Time Trial, and Mastery. A fresh Day 29 list also marked all three Fraternal Twins routes as solved.

## Reproduction notes and evidence limits

The original assigned ZIP files and answer-generation parser are not retained alongside this report. The archive hashes above identify the exact inputs used, but this page is not a stand-alone solver. To repeat the analysis with those archives, verify and unpack each ZIP, then parse its files statically. For the Day 29 O0/O3 comparison, inspect the `.text` difference near virtual address `0x4024e9` and follow the two `fb_StrInit` calls to the referenced `.data` strings. The preserved observations are `0x0c` versus `0x0a` for the length immediate and `unoptimized` versus `optimized` for the NUL-terminated strings. Decode and CRC32-check the HCFG records independently before concluding that the challenge-relevant configurations match.

The remaining answer tables and exact parser invocation were not preserved, so they cannot be reconstructed reliably from this document alone. The three completed modes and their service-side `CORRECT` results are supported by the attempt IDs and verification notes above; this report does not claim a locally rerun answer builder.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
