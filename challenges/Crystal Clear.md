# Crystal Clear — Single Solve

## Result

Completed the Day 13 **Crystal Clear** single-solve route on 2026-10-23. The Game Master confirmed `CORRECT`, with all 130 answer IDs accepted. The route was untimed and used attempt `386b5d5f-d011-4537-885d-91d7c3a66e97`.

- Challenge ID: `binary-reverse-engineering-day-13-crystal-dns-configuration`
- Prompt: “Crystal compiles to native code with a distinctive shine. Fingerprint the runtime, then follow the DNS labels — this one has somewhere it wants to resolve.”
- Assigned archive: `evidence.zip`
- Archive SHA-256: `73abd7b3e6d4e11d6daeb64366713d4e5cd699986bb8fb7f16af4b701ccbc070`
- Archive password: `infected` (extraction only)
- Completion flag: `0430a60cd29aa76433734b7633ea20a4`

The complete player-facing assignment, all 130 prompts and answer formats, and the artifact details are preserved in [Crystal Clear assignment.md](<assignments/Crystal%20Clear%20assignment.md>).

## Method

Downloaded the assigned archive through the authenticated Game Master connection on Kali and verified its SHA-256 before extraction. Extracted the archive with the published password, then analyzed the members as data; none of the challenge binaries were executed. Kali was used for the authenticated Game Master requests and archive handling. REMnux statically inspected the transferred Day 1 ELF; the remaining members were parsed on Kali because the REMnux MCP could not access Kali's filesystem directly.

The archive contains 14 members covering Days 1–13. The challenge asks for member hashes, executable/container fingerprints, selected ELF symbol/section data and predicates, managed PE metadata, ZIP compression methods, HCFG values, and HCFG carrier offsets. HCFG records use the specified 12-byte header, XOR-decoded JSON payload, and CRC32 check. Carriers varied by day: a native `.hcfg` section, raw embedded bytes, Base64 text, or Base64 embedded in a class-file constant pool. Each decoded record was checked against its CRC before its values were used.

The Day 1 ELF was statically confirmed as ELF64, little-endian x86-64 `ET_EXEC`, entry point `0x401040`, with a `.symtab` section. Its `recover_code` function contains `mov $0x1fa4,%eax; ret`. The symbol and section answers were emitted as JSON arrays in their original table order.

## Per-member findings

| Day | Member SHA-256 | Container / architecture | HCFG campaign | Domain | CRC32 |
|---|---|---|---|---|---|
| 1 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` | ELF64, x86-64 | — | — | — |
| 2 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | ELF | BR02-000 | `node-000.day02.example.invalid` | `0x6149aa00` |
| 3 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` | PE/CLI, Machine `0x14c`, metadata `v4.0.30319` | BR03-000 | `node-000.day03.example.invalid` | `0xcb6cf23f` |
| 4 | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` | ELF, x86-64 | BR04-000 | `node-000.day04.example.invalid` | `0x2b747600` |
| 5 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` | ELF, x86-64 | BR05-000 | `node-000.day05.example.invalid` | `0x8f37c323` |
| 6 | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` | JAR; compression methods `[0,8]` | BR06-000 | `node-000.day06.example.invalid` | `0x121bc931` |
| 7 | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` | JAR; compression methods `[0,8]` | BR07-000 | `node-000.day07.example.invalid` | `0xcf3ea232` |
| 8 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` | ELF64, x86-64 | BR08-000 | `node-000.day08.example.invalid` | `0x6a033bfd` |
| 9 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` | ELF, x86-64 | BR09-000 | `node-000.day09.example.invalid` | `0x9614e1a8` |
| 10 | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` | ELF, x86-64; `.hcfg` section present | BR10-000 | `node-000.day10.example.invalid` | `0xceda03ad` |
| 11 | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` | ELF, x86-64 | BR11-000 | `node-000.day11.example.invalid` | `0x03663005` |
| 12 | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` | ELF, x86-64 | BR12-000 | `node-000.day12.example.invalid` | `0xe4fc81f8` |
| 13 | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` | ELF, x86-64 | BR13-000 | `node-000.day13.example.invalid` | `0xa69b7e61` |

For each decoded configuration, the mutex was `Global\HuntressBR<day>_000`, and the URL was `https://node-000.day<day>.example.invalid/api/BR<day>-000`, with the day formatted as two digits. HCFG version and XOR keys, exact offsets, and all per-field values were submitted under the attempt's exact answer IDs and are available in the Game Master's accepted answer set.

## Submission and verification

The initial full batch exposed one mismatch during partial-credit isolation: Day 8 asks for ELF class as the base-10 bit width, so the correct answer is the string `64`, not the label `ELF64`. After correcting that field, the Game Master returned `CORRECT`. A follow-up status request confirmed `result: CORRECT` and `accepted_ids` contained all 130 answer IDs.

## Time Trial — untimed regular variant

Completed the Time Trial route as an untimed regular run, following the route guidance that `run_for_time: false` still awards the flag and CourseStack points. This preserved the separate ranked pool; the start response marked this as a fresh regular variant and returned no deadline.

- Attempt: `b6550f81-5b94-4e87-8a6b-64ad755e7ec4`
- Started: `2026-10-23T07:22:15.369Z`
- Archive SHA-256: `e1ff50bf9722442c7d971008b54bf0ec58ab207abd6984f907ce9800cd3a26cd`
- Questions: same 130 player-facing questions and answer IDs as the Single Solve assignment above.
- Result: Game Master returned `CORRECT`; a follow-up status check confirmed all 130 IDs accepted.
- Completion flag: `0a425ab00cc32f3d9a4ea5eb0b1f6164`

The archive was downloaded through the authenticated Game Master connection on Kali, SHA-256 verified, and extracted with the published archive password. All members were analyzed statically. The challenge variation changed multiple container types and the embedded configuration values, so I recomputed the member hashes and findings from this attempt's exact files.

| Day | Member SHA-256 | Container | HCFG campaign | Domain | CRC32 | Carrier offset |
|---|---|---|---|---|---|---|
| 1 | `6413a43702b377d079202f0c95be1ffc93861d7a14fefae01e4bd7d1fc32e54e` | ELF64, x86-64 | — | — | — | — |
| 2 | `1db6cd34482281e61ef34dd5695745b9370549e63a5241afbc7c5f9bda911cfc` | PE; RTTI and vtable symbols present | BR02-001 | `node-001.day02.example.invalid` | `0xffdeebbe` | `.hcfg` section |
| 3 | `d1493de4b3d5c8a5db1440a94b5204644cdba19853d894722c47a82d1c65ad17` | PE/CLI, Machine `0x14c`, metadata `v4.0.30319` | BR03-006 | `node-006.day03.example.invalid` | `0x3afd7b39` | embedded bytes |
| 4 | `cdb3fc656aa538e62e1ee567055921e0ef2b9140b419e8325ffd7c594659ccd1` | PE (Go executable) | BR04-003 | `node-003.day04.example.invalid` | `0x53bcb283` | embedded bytes |
| 5 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` | ELF, x86-64 | BR05-000 | `node-000.day05.example.invalid` | `0x8f37c323` | embedded bytes |
| 6 | `3946fb7a66d6a47d0d7d9d553e229999e845834537ab522a1b64fc8211b0a3b6` | JAR; methods `[0,8]` | BR06-001 | `node-001.day06.example.invalid` | `0xb63d318f` | Main-Class constant pool |
| 7 | `2febb8701f76f617bedc8d80ef398aab87472c6209fd5881c0dfea2d70dc6e93` | JAR; methods `[0,8]` | BR07-002 | `node-002.day07.example.invalid` | `0x5c02550f` | Main-Class constant pool |
| 8 | `c31d49dbf7740c71c2990d667353f33e449927deb9caa4cc704aaba624c6467b` | ELF64, x86-64 | BR08-003 | `node-003.day08.example.invalid` | `0x5d19347e` | Base64 carrier |
| 9 | `9c30b74048a654312b88f319878f4cbb52f5e633e3b1e7776248285876f8d4e2` | ELF, x86-64 | BR09-004 | `node-004.day09.example.invalid` | `0x6b1c0993` | `30696` |
| 10 | `30477f3a7b1fc911c732d8dbf68362e9d28d0c20102aa32b41b2c1e0b04fbae1` | PE, x86-64; HCFG section present | BR10-006 | `node-006.day10.example.invalid` | `0xa0ee1cab` | embedded bytes |
| 11 | `4db31f97b3ce1b44553e5ed8ef14c17aa10a91203ecd954dd532dcf81054196e` | ELF, x86-64 | BR11-006 | `node-006.day11.example.invalid` | `0x6d522f03` | `368272` |
| 12 | `0f49a991fbba928a9bc167bdb09bcd8b81c580a3e30ca4e427f331fd0acd1d4f` | ELF, x86-64 | BR12-007 | `node-007.day12.example.invalid` | `0x2eee6640` | `82928` |
| 13 | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` | ELF, x86-64 | BR13-000 | `node-000.day13.example.invalid` | `0xa69b7e61` | `560188` |

Day 8's ELF class field was submitted as the required base-10 bit width, `64`. The per-day mutex and URL values follow the exact decoded configuration fields, and the remaining header keys, versions, predicates, symbol/section fields, and offsets were submitted under their exact answer IDs.

## Mastery — five assigned sets

Completed Mastery on the untimed regular route. The Game Master assigned five fresh `evidence.zip` archives, each covering the same 130 Day 1–13 question schema. The set-prefixed questions produced 650 required answer fields. No timer was started (`run_for_time: false`); the route guidance confirmed an untimed correct solve still awards the flag and points.

- Attempt: `244a3d9c-16f3-406b-9605-c9cead9dd426`
- Started: `2026-10-23T07:28:12.381Z`
- Result: `CORRECT`; status confirmed all 650 answer IDs accepted.
- Completion flag: `c0530bea2ef9511e393796ecff065c5a`

| Set | Archive SHA-256 | Campaigns for Days 2–13, in order |
|---|---|---|
| 1 | `d364faff9fa7ea0aa7ab51158b2f51db9e77578ac872a88177031a62cebb793d` | BR02-003, BR03-003, BR04-001, BR05-001, BR06-000, BR07-007, BR08-006, BR09-005, BR10-006, BR11-003, BR12-002, BR13-001 |
| 2 | `a2d9ce85240f5eadf916c4836dcf741daf537981d95d095c5309514f2e1b2564` | BR02-003, BR03-002, BR04-005, BR05-004, BR06-005, BR07-006, BR08-007, BR09-000, BR10-000, BR11-002, BR12-003, BR13-004 |
| 3 | `d8857cbbb84bbc2f4f11d5f2c91310785ef141e6990c273eaab5425dd3ddc065` | BR02-004, BR03-001, BR04-002, BR05-007, BR06-002, BR07-005, BR08-000, BR09-003, BR10-003, BR11-001, BR12-004, BR13-007 |
| 4 | `ea9b9cb81889df3a8aada08bda7001fa442764032f4462ada0e715edf558387c` | BR02-004, BR03-000, BR04-006, BR05-002, BR06-007, BR07-004, BR08-001, BR09-006, BR10-005, BR11-000, BR12-005, BR13-002 |
| 5 | `f752d69f5fd7160117cd118b0dd0077684d150f2d150fab62360013503d0a50f` | BR02-005, BR03-007, BR04-003, BR05-005, BR06-004, BR07-003, BR08-002, BR09-001, BR10-000, BR11-007, BR12-006, BR13-005 |

Each archive hash matched the Game Master's value before extraction. The Day 1 specimen was stripped in every set: its section table has no `.symtab`, so the correct SHT_SYMTAB name array and `recover_code` disassembly are both `[]`, and the `.symtab` predicate is `false`. Other members changed container type across sets, so I classified each final file from its ELF, PE, or JAR structure before applying the day-specific parsing rule. For each configuration I validated the decoded JSON against the HCFG CRC32; where requested, I also recorded the XOR key, HCFG version, ZIP methods, and the exact raw/Base64 carrier offset.

The embedded domains, mutexes, and URLs follow the exact values in each HCFG JSON object. Across the five sets their campaign suffixes also identify the corresponding `node-NNN` labels in the table; all individual fields were submitted with the exact set-prefixed answer IDs returned by this attempt.
