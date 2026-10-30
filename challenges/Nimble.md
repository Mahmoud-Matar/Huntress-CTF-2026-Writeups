# Nimble

## Single Solve

### Result

The Game Master accepted all 90 answer fields as `CORRECT`. A follow-up status check confirmed the same attempt and all 90 accepted fields. The run was untimed.

### Assignment and artifact

- Challenge ID: `binary-reverse-engineering-day-09-nim-generated-runtime`
- Attempt: `9938c118-284b-45d1-aab2-fe8594e55568`
- Prompt: “Nim compiles down to C, but the generated names give it away. Learn to spot Nim's runtime fingerprints hiding inside C-shaped clothing.”
- Archive: `evidence.zip`
- Archive SHA-256: `27042a0f28d31f93d7de4554f3a49456f1ba28f65fec3df44ec0e407c698d73a`
- Archive size: 31,479,735 bytes; 10 encrypted members, extracted with the published password `infected` using 7-Zip.
- The archive hash matched the Game Master's assignment before extraction. No challenge binary was executed.

### Analysis

The archive supplied evidence for Days 1–9. The Day 1–8 fields were reconstructed from the assigned members with the existing static parser used for the earlier Swift Justice analysis. It inspected ELF headers, section and symbol tables, the managed PE metadata root, Java archive contents, and CRC-valid HCFG records. File hashes were calculated from the exact extracted members.

For Day 9, I parsed the ELF header directly: the sample is ELF64, little-endian, `ET_EXEC`, with machine value 62 (`x86-64`). The question's specified scan checked non-overlapping Base64-alphabet runs in file order. At byte offset 30,696, the first decoded run began with an HCFG record whose bounds and CRC32 validated. XOR-decoding its payload with the record's one-byte key produced UTF-8 JSON. The extracted Day 9 values were:

- Sample SHA-256: `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad`
- Campaign: `BR09-000`
- Domain: `node-000.day09.example.invalid`
- Mutex: `Global\\HuntressBR09_000`
- URL: `https://node-000.day09.example.invalid/api/BR09-000`
- HCFG CRC32: `0x9614e1a8`
- Encoded carrier offset: `30696`

The final map had exactly the 90 answer IDs returned for this attempt, with no missing, extra, or empty fields.

### Submission

- Game Master result: `CORRECT`
- Flag: `8eecc9103ea9317a2dfa79165aba1d13`

## Time Trial

### Result

The Time Trial assignment was completed as a scored, untimed run: the route returned `run_for_time: false` and no deadline. The Game Master accepted all 90 fields as `CORRECT`, and status confirmed the same attempt.

### Assignment and artifact

- Attempt: `394e8928-a4f3-4c53-b194-7a5764c4ef2c`
- Archive: `evidence.zip`
- Archive SHA-256: `89a052b3b876408394d7c91498b2e6426ce687af932e9817cf5e267d12067375`
- The archive again contained 10 encrypted evidence members and was extracted with 7-Zip and the published `infected` password. No sample was executed.

### Variant-specific finding

The D01 `recover_code` function returned a different constant from Single Solve. Disassembly of the assigned ELF showed `mov eax,0x1fa7` followed by `ret`; carrying over the earlier variant's `0x1fa4` caused the first full answer map to be rejected. After correcting that field and rechecking all 90 IDs, the full map was accepted.

The D09 member was ELF64 for x86-64. The first valid Base64-carried HCFG record began at byte offset `30696`; CRC32 validation succeeded after XOR-decoding the payload. Its values were:

- Sample SHA-256: `fa1f633cb2720336f57339a64896196e868a860d9db0a441667bea98162a85f2`
- Campaign: `BR09-005`
- Domain: `node-005.day09.example.invalid`
- Mutex: `Global\\HuntressBR09_005`
- URL: `https://node-005.day09.example.invalid/api/BR09-005`
- HCFG CRC32: `0xcf3af12d`
- Encoded carrier offset: `30696`

### Submission

- Game Master result: `CORRECT`
- Flag: `02f289919caeae6aa669ecb922164e36`

## Mastery

### Result

The untimed Mastery attempt completed with all 450 fields accepted as `CORRECT`. A follow-up status request confirmed the same attempt and all five sets.

### Assignment and artifacts

- Attempt: `a209411e-ec33-44a4-972a-fae99787de37`
- Mode: Mastery, untimed (`run_for_time: false`, no deadline)
- Five `evidence.zip` archives; every archive SHA-256 matched its assigned Game Master value before extraction.
- Archive SHA-256 values, in delivery order:
  1. `97c5fc08376412e105c55be1b1f300f8e324769f5d76bdf42eca1ecc73da2400`
  2. `808f57b7c36d5277153166e7f427fd67d520d1e23e505cd5e164d01040afce18`
  3. `2aeb86950b504931fd23697c3b627cfd8bab998a9f74b4e7c538a4b1551cf400`
  4. `57bcbb904bfefa42a43fc31bfaeb1026d8496ac81ffc0d84cf91f5d6b3ca4a21`
  5. `9dcfb01b30003e697599db5e801b630b7d6082936954e56eefe29deb1e856ece`

### Analysis

All five archives were decrypted with 7-Zip and the published `infected` password. The static parser was applied separately to each delivery. It extracts ELF and PE metadata, managed-runtime metadata, symbol tables, Java archive contents, and HCFG records. D01's constant-return function was disassembled from each exact sample. Set 1's D01 ELF had no `.symtab`, so its required symbol and disassembly arrays were both empty; the other sets contained `recover_code` returns of `0x1fac`, `0x1faf`, `0x1fb1`, and `0x1fb3` in delivery order.

Each D09 ELF was checked as ELF64/x86-64. The first CRC-valid Base64-carried HCFG record began at byte offset `30696` in every set. Per-set results:

| Set | D09 sample SHA-256 | Campaign | HCFG CRC32 |
| --- | --- | --- | --- |
| 1 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` | `BR09-003` | `0xa10eee2b` |
| 2 | `6d742be643831355f824f040a5d40c462401266c9180196410044afd5a0ebf4f` | `BR09-002` | `0x05281695` |
| 3 | `adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69` | `BR09-001` | `0x32321916` |
| 4 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` | `BR09-000` | `0x9614e1a8` |
| 5 | `fcb63ec6f82f6fe79057707734000c1e1edc847c79e9e3e9dca5287e76b6d5b3` | `BR09-007` | `0x5c060610` |

The combined answer map matched the 450 exact IDs returned for this assignment, with no missing, extra, or empty values.

### Submission

- Game Master result: `CORRECT`
- Flag: `45423b081035ddba5f7ac7458919822d`
