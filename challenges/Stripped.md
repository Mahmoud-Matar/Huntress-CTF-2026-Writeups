# Stripped

## Single Solve

- **Challenge ID:** `binary-reverse-engineering-day-15-assembly-and-symbol-loss`
- **Mode:** Single Solve (untimed)
- **Attempt:** `669f07ea-5ef9-4333-a62a-60bf279781f8`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `fccc17b2de5a684728d010e203ed5db4de32f50d657c3ab440f3916078221385`
- **Findings:** 150 across the bundled Day 1–15 evidence members
- **Result:** Game Master status returned `CORRECT`; all 150 answer IDs were accepted.
- **Flag:** `a06b8325355367b9356d395340a25de0`

### Approach

I resumed the assigned Single Solve attempt, downloaded its archive through the paired Game Master connection, and verified the archive SHA-256 before analysis. I extracted it with the published `infected` password. The questions depend on archive member order, so I used the ZIP central-directory order for the per-day member hashes and kept the two Day 15 ELF files distinct.

I analyzed the files statically on REMnux. For ELF samples, I read the ELF headers, section tables, symbol tables, and entry points directly; for Day 1, I disassembled the named `recover_code` symbol and submitted its two instructions in order. The C++ ELF's mangled symbols confirmed the requested `DiscoveryEngine` RTTI and vtable predicates. For the managed Day 3 PE, I parsed the COFF machine field, CLI header, metadata root, and embedded configuration record; its metadata version was `v4.0.30319`.

I validated each HCFG record by reading its version, XOR key, payload length, and CRC32 from the record header, XOR-decoding the payload, checking the CRC, and parsing the resulting JSON. I followed the carrier specified for each day: the `.hcfg` ELF section, raw bytes in Go and Rust binaries, Base64 constants in the Java Main-Class constant pools, raw or Base64 carriers in later ELF samples, and the literal record in the Day 15 stripped ELF. I also read the JAR central directories to report their distinct ZIP compression methods. No challenge binary or script was executed.

The Day 15 stripped and symbolized samples both parsed as x86-64 ELF files (`e_machine` 62). I used the named `stripped.elf` for its two HCFG fields and handled the `symbolized.elf` member separately for its hashes and machine metadata.

### Submission

I submitted all 150 values under the exact answer IDs returned by the active attempt. The Game Master returned `CORRECT`, and a follow-up `op=status` confirmed the same attempt, all 150 accepted IDs, and the flag recorded above.

## Time Trial (untimed scoring run)

- **Challenge ID:** `binary-reverse-engineering-day-15-assembly-and-symbol-loss/time_trial`
- **Mode:** Time Trial; untimed (`run_for_time:false`, no deadline)
- **Attempt:** `1b82baf4-52d3-451d-a0ad-8c0d751688d6`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `29511dbd9d6b5062deef6fa2209b5e15a2c3eaad973415de92b51aafa4ae6a03`
- **Findings:** 150 across the bundled Day 1–15 evidence members
- **Result:** Game Master submission and follow-up status both returned `CORRECT`.
- **Flag:** `adc9abaf7451efd841b21fbd7eab0c75`

### Approach

The Time Trial route supplied a fresh artifact with 31 regular variants remaining. Per its guidance, the default start was untimed and still eligible for scoring; no ranked timer was requested. I downloaded the archive from the authenticated Game Master endpoint, verified its SHA-256, and extracted it on REMnux with the published password. I reused the static parser from Single Solve, parameterized to read this attempt's archive, extracted directory, and exact start-response question IDs. This produced all 150 answers from this variant's actual bytes, including member-order hashes, ELF and PE/CLI metadata, validated HCFG records, JAR compression methods, and the Day 15 stripped/symbolized ELF metadata. I checked that the generated answer IDs exactly matched the start response before submitting.

The Game Master accepted all answers. A follow-up `op=status` confirmed the same attempt ID, Time Trial mode, `CORRECT`, and the flag above.

## Mastery (untimed scoring run)

- **Challenge ID:** `binary-reverse-engineering-day-15-assembly-and-symbol-loss/mastery`
- **Mode:** Mastery; untimed (`run_for_time:false`, no deadline)
- **Attempt:** `cbc57cc8-1da0-4c79-80a0-56b2af70e2c8`
- **Artifacts:** five fresh `evidence.zip` deliveries, each protected with `infected`
- **Archive SHA-256 values, in delivery order:**
  1. `69a5e22a9a0952f8480222491358dcf1cc3f31e9e20915555b5a81839b521c13`
  2. `ca0e6852f91cdb90e9851bb55eb8acc9a0b7d8e2c0ef5b62060d3821e4054a91`
  3. `c753ab6422c69bdf821fdec16abda8022fa91aa4a92ebd2446845e8183dc9a50`
  4. `93a6a011dc5dddbfc1f5c865fd6d7f95a66d25d835e2e9f6698494e73ae273d6`
  5. `7c8dee3a931129333c9e609baee6c409f8da12178cdbb525054fe8a0f114c736`
- **Findings:** 750 across five deliveries (150 each)
- **Result:** Game Master submission and follow-up status both returned `CORRECT`; all 750 answer IDs were present in the confirmed attempt.
- **Flag:** `fc5f3a7b33d377340580062a3809d12e`

### Approach

I downloaded all five assigned archives through the authenticated Game Master endpoint and checked each SHA-256 against the start response before extracting them on REMnux with the published password. I split the 750 exact answer IDs into five 150-question groups, then ran the same static parser separately against each delivery's actual extracted bytes. The parser used ZIP central-directory order, ELF and PE section/header data, PE/CLI metadata, COFF/ELF symbol tables, HCFG CRC validation and decoding, Java class constants, and JAR compression metadata. The five generated answer groups were merged only after their combined keys exactly matched all 750 IDs returned by the Game Master.

An initial batch exposed a parser gap: two deliveries use a PE specimen for Day 10, so its `hcfg` section predicate must inspect PE section names as well as ELF section names. I added PE section-table handling, regenerated every set, confirmed both PE cases, and resubmitted the full batch. No challenge binaries or scripts were executed.

The Game Master returned `CORRECT`. A follow-up status check confirmed the same Mastery attempt, all 750 answer IDs, and the flag above.

## Reproducing the analysis

The retained helper is [`tools/solve_stripped_day15.py`](../tools/solve_stripped_day15.py); it generates answers from the assigned archive and the matching start response, rather than from values copied out of this report. The helper expects the archive's decrypted members to be extracted into one directory. For a new delivery, first extract it with the password published by the Game Master, then set `STRIPPED_ROOT`, `STRIPPED_ARCHIVE`, `STRIPPED_START`, and `STRIPPED_OUT` to that delivery's extracted directory, archive, start-response JSON, and output JSON. Run `python3 tools/solve_stripped_day15.py`. It checks that every question ID in the start response has an answer and prints the inferred formats, campaign, HCFG offsets, and Day 1 disassembly for review. Do not reuse an answer JSON from another route or variant.

For the Day 15 pair specifically, identify `stripped.elf` and `symbolized.elf` by their archive member names, not by whichever file sorts first. Read both ELF headers for `e_machine`; parse the stripped file's raw HCFG record and validate the CRC before using its JSON fields. The symbolized member supplies its own format and machine answers. The parser preserves ZIP central-directory member order for the archive-hash questions.

The archived report preserves the accepted flags and the parser, but not the complete start-response question text or a downloadable artifact capability. A full fresh replay therefore needs the player's assigned archive and that attempt's start response from the Game Master.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_stripped_day15.py`](../tools/solve_stripped_day15.py).
