# Wasm Up — solution write-up

## Day 16 Single Solve

- Challenge ID: `binary-reverse-engineering-day-16-webassembly-optimization-equivalence`
- Attempt: `ec7e80ee-c8d1-4280-b8f9-43fd901560f2`
- Mode: Single Solve, untimed; no deadline was active.
- Prompt: “WebAssembly runs in a sandbox, but the sandbox has doors: imports, memory, indirect calls. Map every door in this module and inventory what passes through.”
- Artifact: `evidence.zip`, SHA-256 `7f397030ca0b65b9dbeaf822470f53b13680d0cf6adf4c51685084c9d66c2a70`
- Archive password: `infected`.
- Result: Game Master returned `CORRECT` and flag `986b33d22e786627ec4159063fb15fd2`.

The assignment contained 160 answer fields for the bundled Day 1–16 evidence. The 19 archive members were kept in central-directory order, and the archive hash matched the Game Master before extraction. The archive used AES encryption, so I extracted it with 7-Zip and the published password. No specimen was executed.

## Analysis

I parsed the ELF headers, section tables, symbol tables, and relevant symbol disassembly directly from the assigned bytes. I read the managed PE machine field and CLR metadata version, inspected the JAR manifests, class constant pools, and ZIP compression methods, and extracted each requested HCFG carrier according to its field instructions. This included literal records, the Day 13 Base64 carrier, section-specific records, and the stripped Day 15 specimen. Every HCFG payload was bounds-checked, XOR-decoded with its header key, verified against the header CRC32, and parsed as UTF-8 JSON only after validation.

For Day 16, both `d16--` members were valid WebAssembly modules (`wasm32`). I parsed their section streams and confirmed the compact module's HCFG record from a data-section payload. Its validated configuration was:

- Campaign: `BR16-000`
- Domain: `node-000.day16.example.invalid`
- URL: `https://node-000.day16.example.invalid/api/BR16-000`
- Mutex: `Global\\HuntressBR16_000`
- HCFG CRC32: `0xf6cf27e5`
- XOR key: `0xc1`

The answer map contained exactly the 160 answer IDs returned for this attempt, with no missing or empty fields. The Game Master accepted the submission as `CORRECT`; a follow-up status request confirmed the same attempt and flag.

## Time Trial

- Attempt: `9b6b10ac-f499-41da-bbd6-e4b4c72658f5`
- Run type: untimed scored variant (`run_for_time: false`); no deadline was active.
- Artifact: `evidence.zip`, SHA-256 `28238b1a7979d055366176ce7107a72eee64f5b50477c96740ca53b7b458c455`
- Result: Game Master returned `CORRECT` and flag `fe461f7889c42e1e83173c7fdd5adf8f`.

I verified the assigned archive hash, extracted the archive with 7-Zip and `infected`, and reran the static parser against this variant's bytes. The answer map matched all 160 answer IDs exactly. A status request confirmed the same attempt as `CORRECT` with no timer deadline.

## Mastery

- Attempt: `2fa16943-3e68-4ce3-b40f-4edb24b39be7`
- Run type: untimed scored variant (`run_for_time: false`); no deadline was active.
- Five `evidence.zip` archives; each hash matched the Game Master's assignment:
  1. `d4806cdc35f939aa2d0deb768645d8347d9e550546a17b9ec56bfd00c77067b4`
  2. `86da1580cc6d52043993192b32f2550e79d81ed6a90b7c5b02bbfbb9f0363d47`
  3. `3485af2becc95a0699715aa1317d871e3474abecaf4a5945b1fda3a40a9ce3ee`
  4. `fd0c588bc2633bc78618a58da12c7957b070be043c90ec145517cf26a11dc355`
  5. `60fe1f1bd1bd6fc4374fbebd221be02fdf4c1bdab4a245863d96cd424e0b3616`
- Result: Game Master returned `CORRECT` and flag `57c361eeeae9504459ce3133eda9db7c`.

Each archive was extracted with 7-Zip and `infected`, then analyzed independently with the same static parsers. I recomputed every variant-specific value from that set rather than reusing values from another set. The combined submission contained all 800 set-qualified answer IDs exactly once, with no missing or empty values. The Game Master accepted the submission, and a follow-up status request confirmed the same attempt and flag.

## Reproducing the Day 16 fields

1. Start from the archive for the mode being reproduced, verify its SHA-256 against that mode's recorded value, and extract it with `infected`. Preserve ZIP central-directory order for member-indexed hashes.
2. Confirm each `d16--` file begins with the WebAssembly magic and version bytes (`00 61 73 6d 01 00 00 00`). Walk the section stream as `section-id`, unsigned LEB128 payload length, and payload; do not execute the module.
3. Select the module named by the question. The compact module carries an HCFG record in a data-segment payload; the direct module's requested campaign and domain come from its own assigned bytes. Do not substitute the compact module's configuration for the direct module's fields.
4. Validate an HCFG candidate before trusting it: check the `HCFG` marker and 12-byte header, read the version and XOR key, decode the little-endian payload length and CRC32, XOR each payload byte with the key, verify CRC32, then parse UTF-8 JSON. The validated compact record is campaign `BR16-000`, domain `node-000.day16.example.invalid`, URL `https://node-000.day16.example.invalid/api/BR16-000`, mutex `Global\HuntressBR16_000`, CRC32 `0xf6cf27e5`, XOR key `0xc1`.
5. Map each value to the exact answer IDs returned for that mode. For Mastery, keep the five sets independent and prefix each set's answers with the exact `setN.` namespace. Compare the generated ID set against the assignment before submitting.

The report retains archive hashes and confirmed flags, but not the WebAssembly parser or all per-question answer maps. Reproducing every scored field requires the corresponding assigned archive and start response; the summary values above are validation checkpoints, not substitutes for those bytes.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
