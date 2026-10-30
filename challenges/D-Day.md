# D-Day — Huntress CTF 2026, Day 11

## Challenge

D-Day is a static binary-analysis challenge built around generated “collection” binaries. Each archive contains eleven specimens, from ELF and PE executables to Java JARs. The task is to trace metadata and runtime-generated templates back to their embedded HCFG collection configuration and report the requested file, header, section, symbol, and configuration facts.

The assigned archives were password-protected with `infected`. All analysis was performed on the exact downloaded bytes; no specimen was executed.

## Reproduction approach

1. Download the archive assigned to the selected mode and verify its SHA-256 against the table below before extracting it. Use the published archive password `infected`. Keep a copy of the ZIP central-directory order: questions for `d01--` through `d11--` identify members by that order, not by a newly sorted filename list.
2. For each member, identify its container before reading fields. ELF questions come from the ELF header, section table, symbol table, entry point, and (where asked) the `recover_code` bytes. PE questions come from PE/COFF headers, section headers, and the COFF symbol table. JAR questions come from `META-INF/MANIFEST.MF`, class constant pools, and the ZIP central directory's compression-method values.
3. Recover each HCFG record only from the carrier named by that question. Check that the record fits within the file, XOR the payload using the key from its header, verify the decoded bytes against the header CRC32, then parse valid UTF-8 JSON. A record in a PE or ELF section must be located using that file's section table; the offset of an encoded carrier is the offset of its first Base64 character, not the offset of the decoded JSON.
4. Compute requested member digests over the exact stored member bytes. Preserve central-directory order when identifying which member is “1”, “2”, and so on.
5. Build the submission using the exact answer IDs and answer formats returned for that attempt. For Mastery, keep the three sets separate while analyzing them, then map them to the matching `set1.`, `set2.`, and `set3.` answer IDs. In set 2, the PE section table located `.hcfg`; the COFF symbol table supplied the RTTI/vtable predicates.
6. Submit and use the Game Master result as the acceptance check. All three routes returned `CORRECT`; the repeated Day 11 list confirmed completion.

The original analysis used a small Python parser, but its source and a complete answer transcript are not preserved in this report. The procedure above records the analysis decisions and validation steps; the missing parser is a reproducibility gap, so exact numeric answers must be recomputed from the assigned archive bytes rather than inferred from this prose.

## Results

| Mode | Attempt | Assigned archive SHA-256 | Game Master result | Flag |
| --- | --- | --- | --- | --- |
| Single Solve | `8b493694-1ba0-47a2-b31d-eb0f4f6baed0` | `1032f43152771a2710bc991bdc3f317fbd047539745ce3e8ac516770ac7cf9aa` | CORRECT | `3dd60691fde7675a3c13b8c80362212d` |
| Time Trial | `6acd8c03-636c-42ff-9d18-18e6464a540d` | `6fe9a80742d6ba5e8194e1bb5ca991742874a4d1b5d8a0523805bdcd7cd229e4` | CORRECT in about 41 seconds of the 80-second limit | `1a8313d74659fc2eb3c607dbe721fb13` |
| Mastery | `0cd5d01f-909c-45fb-bf08-4b21c29236e2` | Three archives listed below | CORRECT within the 200-second limit | `a33382adc06a9f68246ea3c71105e4a9` |

Mastery archive hashes:

- Set 1: `6fe9a80742d6ba5e8194e1bb5ca991742874a4d1b5d8a0523805bdcd7cd229e4`
- Set 2: `46b9b57c323903431242b32b59ea59387c70c23a6b154936fc925be4edd1582b`
- Set 3: `d2ed64c4e468ae692cdc1b2ca77cf19d2b1f37ee896c4c410b776f9ea95d1985`

Game Master returned `CORRECT` for all three modes, and a repeated Day 11 listing showed all D-Day routes solved for the player identity.

*Writeup organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
