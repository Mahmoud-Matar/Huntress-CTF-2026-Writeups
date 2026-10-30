# Decoder Ring — Day 17

## Single Solve

**Route:** `binary-reverse-engineering-day-17-encoded-configuration-recovery`  
**Attempt:** `4210e23e-d7a1-43d5-8941-bd375da44799`  
**Artifact:** `evidence.zip` (20 delivered members across Days 1–17)  
**SHA-256:** `da29170f6db0ec03ec712bf944b838c0ad607147468b2cff5ebd2afc6ffd5a1c`  
**Result:** Game Master returned `CORRECT`  
**Flag:** `381079dc18ca914ee994e4bbf8e824c3`

The archive password was `infected`. I verified the downloaded archive against the Game Master's SHA-256, extracted it on REMnux, and performed static analysis on the exact members. None of the samples were executed.

## Method

I treated each `dNN--` specimen according to its final-byte format. ELF headers supplied class, machine, entry point, and section tables; `.symtab` entries were parsed in their table order, and the Day 1 `recover_code` function decoded to `mov eax, 8100; ret`. The Day 1 marker came from `.huntress` as UTF-8 with trailing NUL bytes removed.

HCFG records use a 12-byte header: `HCFG`, version, XOR key, little-endian payload length, and little-endian CRC32. I XOR-decoded each payload and accepted it only when its CRC32 and UTF-8 JSON both validated. The JSON supplied the campaign, domain, mutex, and URL fields.

The carrier varied by specimen. I read records from named `.hcfg` sections in the relevant ELF files, scanned the managed PE bytes for Day 3, decoded Base64 carriers for Days 8, 9, 11, and 13, and extracted Base64 constants from the manifest main classes in the Day 6 and 7 JARs. Day 12 stored a literal record in `.data`; disassembly referenced its exact start address (`0x4153f0`), identifying it as a raw constant array. Day 16's records were in WebAssembly data segments. Day 17's literal record was at file offset `207432` in `.rodata` and had no decoder cross-reference, so it was classified as raw storage.

For Day 3, I mapped the PE CLR metadata directory to the `BSJB` metadata root and read the declared version string (`v4.0.30319`). For the JARs, I parsed each ZIP central directory for compression methods, then parsed the manifest's main-class bytecode structure to recover method names and access flags. Day 7's central directory includes `kotlin/coroutines/Continuation.class`.

Two details needed exact interpretation during validation. The Day 1 symbol answer includes nonempty `SHT_SYMTAB` names only, excluding `.dynsym`. Day 8 asks for ELF class as a decimal bit width, so its answer is `64`, not the label `ELF64`. After correcting those, the Game Master accepted the remaining answer fields and returned `CORRECT`.

## Time Trial

**Route:** `binary-reverse-engineering-day-17-encoded-configuration-recovery/time_trial`  
**Attempt:** `517b1877-6a6d-4ce8-b6ff-33adee7060d1`  
**Mode:** regular untimed run (`run_for_time:false`; no deadline)  
**Artifact:** `evidence.zip`  
**SHA-256:** `a557602c4f02a2b32581a8e598a637f2a12f147e727829a2f478e57bdfc318b6`  
**Result:** Game Master returned `CORRECT`  
**Flag:** `397478ee0ff7028a9b3823eb08126fd8`

The second assignment used the same 17-day specimen layout with a fresh variant set. I verified its archive hash, extracted it with `infected`, and regenerated the 204-field answer map from this attempt's files. This set included a PE Day 2 binary, Go PE Day 4, and PE Day 10, so I parsed the COFF symbol table and PE section table alongside the ELF, JAR, and WebAssembly formats. The COFF traversal resolved long symbol names through the string table, skipped auxiliary records, and preserved section prefixes such as `.text$` and `.rdata$`.

The Base64-carrier specimens used printable runs beginning with the Base64 encoding of `HCFG` (`SENGRw`). The first submission exposed a prefix-detection error on four days; I corrected the detector, resubmitted those fields, and the Game Master returned `CORRECT`. That confirmed the value of validating every storage path against the exact assigned bytes and using the judge's accepted IDs before advancing.

## Mastery

**Route:** `binary-reverse-engineering-day-17-encoded-configuration-recovery/mastery`  
**Attempt:** `21264e0b-028d-42d3-98d6-6629d343939c`  
**Mode:** regular untimed run (`run_for_time:false`; no deadline)  
**Assignments:** five evidence sets, 204 fields each (1,020 total)  
**Result:** Game Master returned `CORRECT`  
**Flag:** `dac6520da683139056cb8455364e2371`

Each delivery was downloaded with its own capability, checked against the corresponding start-response SHA-256, and extracted separately with `infected`:

| Set | `evidence.zip` SHA-256 |
| --- | --- |
| 1 | `e27694903364231e8d878fa3dcf4692daf0f2883f7473f9c8984bd830446b36a` |
| 2 | `913e5ed2e076a1ded9b2e1c69a508100749f0f04dbeb77d429146936e8a2d4cd` |
| 3 | `43e6d22c985406b39a3503f8ea9a2c1e0ab7ccca67cf08c8f8602edb20519d24` |
| 4 | `7165aeb0d869e92fbbea70fd1828063170041d02c18b02cb7baa624e4c9516aa` |
| 5 | `dc1a463d03b396bd23b9c95c111601f3e31a2b4ed8451461b1cbe0ca40db7026` |

I generated one 204-answer map per set, then added the exact `set1.` through `set5.` prefixes from the Game Master's answer IDs and checked that all 1,020 required IDs were present exactly once. The first submission isolated two wrong Day 10 section predicates. Sets 2 and 4 use ELF files whose parsed section tables include `.hcfg`; both answers are `true`. After correcting those two fields, the Game Master returned `CORRECT`.

## Reproducing the HCFG checks

For any assigned variant, first verify the outer archive hash and extract with `infected`; retain archive order because member-hash answers are ordinal. Identify each member format from its magic bytes, then locate the carrier specified by that field: named ELF section, raw bytes, Base64 data, JAR Main-Class constants, PE/CLI metadata, or WebAssembly data segment. Decode only the identified carrier. For HCFG, require the 12-byte `HCFG` header, XOR the stated-length payload with the one-byte key, compare CRC32 with the stored little-endian value, and only then parse JSON. Report file offsets for raw carriers and carrier-string offsets for Base64 as separate coordinate systems.

Useful checkpoints in this Single Solve are the Day 12 `.data` carrier at `0x4153f0`, the Day 17 raw record at file offset `207432` in `.rodata`, and the Day 18 record at offset `8512`. The raw Day 17 record has no decoder cross-reference, which supports the `raw` classification. The Day 1 symbol question counts nonempty `SHT_SYMTAB` entries and excludes `.dynsym`; Day 8's bit-width format is decimal `64`.

A complete runnable parser and the full per-field answer JSON are not retained alongside this report. Replaying the complete 204-field Time Trial or 1,020-field Mastery therefore requires its own assigned archive and question IDs; the recorded facts above are cross-checks, not complete answer maps.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
