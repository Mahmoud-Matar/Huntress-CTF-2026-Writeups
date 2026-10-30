# Compiler Says What — Day 27

## Status

- **Single Solve:** CORRECT; the Game Master status endpoint also reported `CORRECT`.
- **Time Trial:** CORRECT; the Game Master status endpoint also reported `CORRECT`. This route supports `run_for_time`; the attempt was deliberately started with `run_for_time: false`, so it was untimed and was not a ranked run.
- **Mastery:** CORRECT; the Game Master status and Day 27 challenge list both confirm completion. The existing attempt `f7e021bc-ff57-4193-bf18-d5710b8da6c9` was resumed throughout; no new attempt or retry was started. Sets 1–6 already had 1,944 accepted fields. During set 7 validation, one false predicate was corrected: every crash-trace frame (`stageThree`, `stageTwo`, `stageOne`) appears in the primary classfile method-name set, so `crash_frames_match_methods` is true. Sets 7–10 were then accepted (324 fields each), and set 11's final submission returned `CORRECT`.

## Challenge scope

The Single Solve and Time Trial assignments each provided an `evidence.zip` with 37 members spanning `d01` through `d27`. The challenge asked for 324 fields per assignment, including per-artifact SHA-256 values and findings about file formats, compiler/runtime markers, symbol tables, metadata, configuration records, and related binary structures. Mastery assigned 11 new evidence sets with the same 324-field structure per set.

## Confirmed solves

| Mode | Assigned artifact | SHA-256 | Result |
| --- | --- | --- | --- |
| Single Solve | `evidence.zip` | `1e70c3609f6e77d406f0b23f55dd68b9a9ca09b5950fc1e8ec3478037327fbb0` | CORRECT; status verified |
| Time Trial (untimed) | `evidence.zip` | `7569e46485aa2698b6b5efe5b9dabf6cbc2a37b08cccc33c8d542c8433a30563` | CORRECT; status verified |

## Method

The encrypted archives were opened with the challenge-published password `infected`. All findings were derived from the bytes in the assigned archives, preserving the archive member order where the questions specified it. The analysis parsed ELF headers, section tables, symbol tables and embedded records; PE headers and COFF symbols; CLR metadata; Java class-file structures; WebAssembly sections; and configuration data encoded in HCFG carriers. The HCFG records were decoded according to their carrier and XOR rules, then checked against their CRC32 values. Per-file SHA-256 answers were calculated directly from the extracted files.

The Day 27 compiler-attribution questions were answered by comparing the GCC and TCC samples’ ELF metadata, symbols and embedded configurations. Variant-specific values were taken from each assigned archive rather than copied from an earlier mode. For example, Day 2’s Time Trial sample was a PE/COFF binary rather than the ELF form seen in Single Solve, so its C++ type-information, vtable and method-symbol findings were read from the COFF symbol table. The submissions were sent using the exact answer IDs returned by the Game Master. Partial submissions were used to isolate and correct mismatched fields before the final CORRECT result for each verified mode.

## Mastery progress record

The active Mastery attempt supplied 11 assigned `evidence.zip` sets, each with 324 answer fields. All archive hashes matched the Game Master's artifact metadata. The verified progression was 1,944 fields already accepted across sets 1–6, followed by accepted sets 7, 8, 9, and 10; the accepted-count responses reduced the remaining fields to 1,296, 972, 648, and 324 respectively. Set 11's final submission returned `CORRECT`, and a subsequent status request returned `result: CORRECT`; the live Day 27 list now marks Mastery solved.

| Delivery | Assigned `evidence.zip` SHA-256 | Result |
| --- | --- | --- |
| 1 | `54516e3e82dfeef8746579c76ae005e1f90173d58b778b97a96712c6ed6f665e` | Accepted before resuming |
| 2 | `f03aa4e356c4bd9a2f7b2658b4a73df2d73e4fda9e9c1d5223db1f0ce0243a6f` | Accepted before resuming |
| 3 | `7a24c7fe91b5f9fd4bfe814dfe8e7817ca17970bd1c0ca39afbce1e0725f91cd` | Accepted before resuming |
| 4 | `afb0d32a85b97bd22f840b4eb54e7aba6d4bd1d131d51faed50475856076f676` | Accepted before resuming |
| 5 | `290fa3f7783cc176314581acc87da6a85b37665dc8c4a805058fa227c4f7a099` | Accepted before resuming |
| 6 | `25f22f30be03bc285153e04ed74077f73251d60fcfe7603ad79e1175fbdff432` | Accepted before resuming |
| 7 | `0028e73a1e4bc669497349f09848b330b03a9f4e4b21f676fe6e56527c7de65e` | Accepted after correcting the Day 26 crash-frame predicate |
| 8 | `4cfe15a6bb510a1c42eefecb7ca7b0976535df7d3514d82cc7cc3d51105a5e5e` | Accepted |
| 9 | `33b14ecac177389c192ba03ae8dd7a968c333cb516c87cd19c5b9057390c6399` | Accepted |
| 10 | `2fb3c6eb2dfcaad673c6e8a21e4f75561c03ff20330e181c0135d7a73a9a7aed` | Accepted |
| 11 | `aa02279493cdbae7c977d4a0b95ed8c5823ccaa3687478287b5fe4eb142bb0ce` | CORRECT; Mastery complete |

The set 7 bundle's first rejection had two formatting issues in the generated candidate map: JSON-array answers used Python list syntax, and boolean enum answers used capitalized `True`/`False`. After normalizing those fields to valid JSON and lowercase booleans, 323 fields were accepted. The sole remaining mismatch was the crash-frame predicate; reading the exact JAR's primary classfile showed all three trace frame names in its method table, and submitting `true` completed set 7. Sets 8–11 then validated in full 324-field batches.
