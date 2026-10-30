# Rust Belt

## Challenge

- **ID:** `binary-reverse-engineering-day-05-rust-runtime-shapes`
- **Mode:** Single Solve (untimed)
- **Attempt:** `8f5eebd8-c533-4fcd-8619-74e9082ae9bb`
- **Game Master result:** `CORRECT`
- **Flag:** `8bd6509f79bed40883050db2b158b192`
- **Prompt:** Rust leaves its own fingerprints: mangled symbols with a distinct accent, panic strings that confess, trait objects hiding in plain sight. Learn the accent.
- **Artifact:** [Download evidence.zip](https://2026.huntress.ctf.games/?op=download&capability=bb423507a6c04c12bc0567a7027be57a2fc969ba693b4b1fa891fc331c670fac) — SHA-256 `7735cc0254a9665fe465af53400aec47f7d59c089488e3b95fb454c556fd2958`; password `infected`.
- **Archive members:** `d01--sample.elf`, `d02--sample.elf`, `d03--sample.dll`, `d03--sample.runtimeconfig.json`, `d04--sample.elf`, and `d05--sample.elf`.

## Method

The encrypted archive was downloaded from the paired Game Master endpoint and extracted with the published password. I used file identification, GNU `readelf`, `objdump`, `objcopy`, and a small Python parser. The supplied binaries were only inspected; none was executed.

For Day 1, the ELF header, section table, and `.symtab` were read directly. The `recover_code` symbol disassembled to a constant load into EAX followed by `ret`. For Day 2, I extracted the exact `.hcfg` section. For the managed Day 3 PE, I read the COFF Machine field and CLR metadata-root version string. For Days 3–5, I searched the applicable final bytes for HCFG records, XOR-decoded the bounded payload, checked CRC32, and parsed the UTF-8 JSON only after validation.

## Artifact member hashes

| Member | SHA-256 |
|---|---|
| `d01--sample.elf` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |
| `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |

## Findings

- **Day 1 ELF:** ELF64, x86-64, little-endian, `ET_EXEC`; 28 section names in header order (the mandatory null section has an empty name); `recover_code` returns constant `0x1fa4`.
- **Day 2 specimen:** ELF64. Valid HCFG payload decoded with XOR key `0x31`; CRC32 `0x6149aa00`.
- **Day 3 specimen:** PE/CLI managed assembly, I386 machine, CLR metadata version `v4.0.30319`. The archive also includes a runtime configuration support file. HCFG was CRC-validated before reading its configuration fields.
- **Day 4 specimen:** ELF, x86-64. HCFG CRC32 `0x2b747600`.
- **Day 5 specimen:** ELF, x86-64. HCFG CRC32 `0x8f37c323`.

## Submission

All 40 fields were submitted under the exact answer IDs from the start response. The Game Master returned `CORRECT`, confirming the answer set and awarding flag `8bd6509f79bed40883050db2b158b192`.

## Time Trial

- **Challenge ID:** `binary-reverse-engineering-day-05-rust-runtime-shapes/time_trial`
- **Attempt:** `913e22fa-ce47-4305-8bd7-06672d26711f`
- **Deadline:** 50 seconds; submitted before the server deadline.
- **Artifact:** `evidence.zip`, SHA-256 `3848d4bb8a2fe39be295def1b127bf9b2b41adb20b7b394823c315f8c24d2ac0` (password: `infected`).
- **Game Master result:** `CORRECT`.
- **Flag:** `a5f804355614f48063808d9c7f87d7ca`

| Day member | SHA-256 |
|---|---|
| `d01--sample.elf` | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.elf` | `9ba8446ac7824ed2acd4a12b8c490fb6c0f198bcd0fdd662da7d61a9eb30b1c2` |
| `d02--sample.exe` | `91aa8fa8f1747817e5ce3e597c2b7cfd4b051c536f2a7484983d3cfce1525658` |
| `d03--sample.dll` | `c092951f59c6187bc8cd9ae0be744df836808ef08c131739c3c3c7ce43479cbf` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `ada21c58b8026680f48b84620117cb88daf50757e03bb0ec99d1092e7b233932` |
| `d04--sample.exe` | `82599eee6ceae6147c7cb342b5277b79e2deacebae33be8164234277dd6a4c4e` |
| `d05--sample.elf` | `2f292a4d3eeff638ab215e19f814f514d5b8f78fef0f14c039701a70bbeaf0ef` |

This route rotated the artifact values and added companion executable members. I regenerated the answers from the current archive rather than reusing Single Solve values. The first validation attempt exposed a changed `recover_code` immediate; the next retry derived the disassembly from that binary and the Game Master accepted all 40 fields. Header, symbol, CLR metadata, and CRC-validated HCFG parsing stayed offline and did not execute the specimens.

## Mastery

- **Challenge ID:** `binary-reverse-engineering-day-05-rust-runtime-shapes/mastery`
- **Attempt:** `8287e330-6563-44d3-967f-4ca7a51a475f`
- **Mode:** Mastery; one 80-second server deadline across two sets.
- **Artifacts:** two `evidence.zip` files, password `infected`.
  - Set 1 SHA-256: `ced8ad3a13290dec67441fd598cfeadd1df6c1959c2de70884174d535572727f`
  - Set 2 SHA-256: `61761604c1a69d959c6a7b6c1f0302311d388eae4ae46ab4eb9f88aa1b2807ae`
- **Game Master result:** `CORRECT`; all 80 answer fields were accepted.
- **Flag:** `8c326fb08f870b8eb76a866caf0433f8`

The two mastery sets did not use the same containers: one included ELF inputs, while the other supplied PE inputs for Day 2 and Day 4. I selected the actual member format from the bytes, hashed the first matching member in archive order, decoded HCFG from the ELF `.hcfg` section or from a CRC-valid PE record as appropriate, and compared the generated answer IDs against the server's list before submitting. The Game Master returned `CORRECT` before the shared deadline.

## Complete player-facing questions and answers

The full assignment's question text, answer format, and the accepted value submitted for every field are recorded below.

### `d01_artifact_sha256_1`

- Question: In evidence.zip, Use all d01-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1, where members are the d01-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`

### `d01_analysis_elf_class`

- Question: In evidence.zip, Use all d01-- members in ZIP central-directory order. Read ELF EI_CLASS and submit ELF32 or ELF64 exactly.
- Format: `{"kind":"enum","accepted_values":["ELF32","ELF64"]}`
- Answer: `ELF64`

### `d01_analysis_machine`

- Question: For the requested delivered binary, report the processor architecture identified by its executable-header machine field. A normalized architecture name, a standard tool or symbolic label, or the equivalent decimal or hexadecimal machine code is accepted.
- Format: `{"kind":"pattern","syntax":"executable-header machine architecture label or its equivalent decimal or hexadecimal code; common file, readelf, and objdump labels are accepted"}`
- Answer: `x86-64`

### `d01_analysis_section_names`

- Question: For the bundled Day 1 ELF, submit the section names in section-header-table order as a JSON array of strings. The mandatory null section at index 0 has an empty name; including or omitting that one leading empty string is accepted. Do not substitute the section type NULL for its empty name.
- Format: `{"kind":"json","syntax":"JSON array of section-name strings in section-header-table order; an optional leading empty string represents section index 0"}`
- Answer: `[".interp",".note.gnu.property",".note.ABI-tag",".hash",".gnu.hash",".dynsym",".dynstr",".gnu.version",".gnu.version_r",".rela.dyn",".init",".text",".fini",".rodata",".huntress",".eh_frame_hdr",".eh_frame",".init_array",".fini_array",".dynamic",".got",".got.plt",".data",".bss",".symtab",".strtab",".shstrtab"]`

### `d01_analysis_symbols`

- Question: In evidence.zip, Use all d01-- members in ZIP central-directory order. Submit every nonempty SHT_SYMTAB symbol name in symbol-table entry order as a JSON string array; preserve duplicates.
- Format: `{"kind":"json","syntax":"compact valid JSON array with exact values and order; no Markdown or explanatory text"}`
- Answer: `["crt1.o","__abi_tag","variant-000.c","marker","crtstuff.c","deregister_tm_clones","register_tm_clones","__do_global_dtors_aux","completed.0","__do_global_dtors_aux_fini_array_entry","frame_dummy","__frame_dummy_init_array_entry","crtstuff.c","__FRAME_END__","_DYNAMIC","__GNU_EH_FRAME_HDR","_GLOBAL_OFFSET_TABLE_","__libc_start_main@GLIBC_2.34","data_start","_edata","_fini","__data_start","__gmon_start__","__dso_handle","_IO_stdin_used","recover_code","_end","_dl_relocate_static_pie","_start","__bss_start","main","__TMC_END__","_init"]`

### `d01_analysis_disassembly`

- Question: In the bundled Day 1 ELF, find the recover_code FUNC symbol in the symbol table and disassemble its bytes. Submit its decoded instructions in execution order as a JSON array of strings, without addresses or byte columns. If that symbol is absent, submit []. Unrelated format example: ["nop","ret"]. A stripped ELF (one without a .symtab section) has no recover_code symbol, even if the function's code is still present and can be found by disassembly; it still takes [].
- Format: `{"kind":"json","syntax":"JSON array of instruction strings in execution order; an empty array if the recover_code symbol is absent. Intel or AT&T spelling of the same constant-return instructions is accepted."}`
- Answer: `["mov $0x1fa4,%eax","ret"]`

### `d01_analysis_elf_type`

- Question: For the bundled Day 1 ELF, report the ELF header e_type value. The standard ELF symbolic constant, the GNU readelf label, or the equivalent decimal or hexadecimal e_type code is accepted.
- Format: `{"kind":"pattern","syntax":"ELF e_type symbolic constant, readelf label, or equivalent decimal or hexadecimal code"}`
- Answer: `ET_EXEC`

### `d01_analysis_endianness`

- Question: For the bundled Day 1 ELF, report the byte order identified by the ELF EI_DATA field. A plain byte-order name, the GNU readelf description, the ELF symbolic constant, or the equivalent decimal or hexadecimal EI_DATA code is accepted.
- Format: `{"kind":"pattern","syntax":"ELF byte-order name, readelf description, EI_DATA symbolic constant, or equivalent decimal or hexadecimal code"}`
- Answer: `little endian`

### `d02_artifact_sha256_1`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1, where members are the d02-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7`

### `d02_analysis_format`

- Question: For the Day 2 C++ specimen in the bundled archive, identify its executable container from the final bytes. Submit ELF for an Executable and Linkable Format specimen or PE for a Windows Portable Executable specimen; letter case and a more specific ELF32, ELF64, PE32, or PE32+ label are accepted.
- Format: `{"kind":"pattern","syntax":"ELF or PE; letter case is ignored and ELF32, ELF64, PE32, PE32+, or Portable Executable are accepted when they identify the same container"}`
- Answer: `ELF64`

### `d02_analysis_config_campaign`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level campaign property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `BR02-000`

### `d02_analysis_config_domain`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level domain property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `node-000.day02.example.invalid`

### `d02_analysis_config_mutex`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level mutex property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `Global\HuntressBR02_000`

### `d02_analysis_config_url`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level url property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `https://node-000.day02.example.invalid/api/BR02-000`

### `d02_analysis_config_crc32_hex`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Read the little-endian uint32 at HCFG header bytes 8..11 and render it as 0x plus exactly eight lowercase hexadecimal digits.
- Format: `{"kind":"pattern","syntax":"lowercase hexadecimal with a 0x prefix; preserve the field's required zero padding; no whitespace or explanatory text"}`
- Answer: `0x6149aa00`

### `d02_analysis_xor_key_hex`

- Question: In evidence.zip, Use all d02-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Render header byte 5 as 0x plus exactly two lowercase hexadecimal digits.
- Format: `{"kind":"pattern","syntax":"lowercase hexadecimal with a 0x prefix; preserve the field's required zero padding; no whitespace or explanatory text"}`
- Answer: `0x31`

### `d03_artifact_sha256_1`

- Question: In evidence.zip, Use all d03-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1, where members are the d03-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d`

### `d03_artifact_sha256_2`

- Question: In evidence.zip, Use all d03-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 2, where members are the d03-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3`

### `d03_analysis_format`

- Question: For the bundled Day 3 managed binary, identify its combined executable-container and managed-runtime format classification. Submit one compound token containing both parts, not just the generic container label. A tool-specific container label such as a bitness-qualified form is accepted when it identifies the same container. Unrelated syntax example: sample_vm.
- Format: `{"kind":"pattern","syntax":"one container_runtime token; PE, PE32, or PE32+ may name the same container and CLI, CLR, or .NET may name the managed part; underscore, slash, hyphen, or space separators and letter case are accepted"}`
- Answer: `PE_CLI`

### `d03_analysis_machine`

- Question: For the bundled Day 3 managed PE binary, report the processor architecture identified by the PE/COFF Machine field. A normalized architecture name, a standard tool or symbolic label, or the equivalent decimal or hexadecimal Machine code is accepted.
- Format: `{"kind":"pattern","syntax":"PE/COFF Machine architecture label or its equivalent decimal or hexadecimal code; common file, objdump, and IMAGE_FILE_MACHINE labels are accepted"}`
- Answer: `I386`

### `d03_analysis_metadata_version`

- Question: In evidence.zip, Use the unique d03-- primary managed assembly whose basename starts d03-- and ends .dll; .runtimeconfig.json and dependency DLL members are delivery support only. Read the CLR metadata-root version string at BSJB + 16 using its declared length, remove trailing NUL bytes, and submit the exact text.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `v4.0.30319`

### `d03_analysis_config_campaign`

- Question: In evidence.zip, Use the unique d03-- primary managed assembly whose basename starts d03-- and ends .dll; .runtimeconfig.json and dependency DLL members are delivery support only. Scan the managed PE final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level campaign property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `BR03-000`

### `d03_analysis_config_domain`

- Question: In evidence.zip, Use the unique d03-- primary managed assembly whose basename starts d03-- and ends .dll; .runtimeconfig.json and dependency DLL members are delivery support only. Scan the managed PE final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level domain property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `node-000.day03.example.invalid`

### `d03_analysis_config_mutex`

- Question: In evidence.zip, Use the unique d03-- primary managed assembly whose basename starts d03-- and ends .dll; .runtimeconfig.json and dependency DLL members are delivery support only. Scan the managed PE final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level mutex property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `Global\HuntressBR03_000`

### `d04_artifact_sha256_1`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1, where members are the d04-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f`

### `d04_analysis_architecture`

- Question: For the requested delivered binary, report the processor architecture identified by its executable header. A normalized architecture name, a standard tool or symbolic label, or an equivalent standard machine code is accepted.
- Format: `{"kind":"pattern","syntax":"processor architecture name, standard tool or symbolic label, or equivalent executable-header machine code"}`
- Answer: `x86-64`

### `d04_analysis_format`

- Question: For the requested specimen in the bundled archive, identify its executable container from the final bytes. Submit an ELF or PE container label; letter case and a more specific ELF32, ELF64, PE32, PE32+, or Portable Executable label are accepted when they identify the same container.
- Format: `{"kind":"pattern","syntax":"ELF or PE executable-container label; bitness-qualified standard labels and letter-case differences are accepted"}`
- Answer: `ELF`

### `d04_analysis_config_campaign`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Scan the Go executable final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level campaign property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `BR04-000`

### `d04_analysis_config_domain`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Scan the Go executable final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level domain property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `node-000.day04.example.invalid`

### `d04_analysis_config_mutex`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Scan the Go executable final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level mutex property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `Global\HuntressBR04_000`

### `d04_analysis_config_url`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Scan the Go executable final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level url property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `https://node-000.day04.example.invalid/api/BR04-000`

### `d04_analysis_config_crc32_hex`

- Question: In evidence.zip, Use all d04-- members in ZIP central-directory order. Scan the Go executable final bytes for literal HCFG magic and accept only a record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Read the little-endian uint32 at HCFG header bytes 8..11 and render it as 0x plus exactly eight lowercase hexadecimal digits.
- Format: `{"kind":"pattern","syntax":"lowercase hexadecimal with a 0x prefix; preserve the field's required zero padding; no whitespace or explanatory text"}`
- Answer: `0x2b747600`

### `d05_artifact_sha256_1`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1, where members are the d05-- members in ZIP central-directory order (1-based).
- Format: `{"kind":"pattern","syntax":"exactly 64 lowercase hexadecimal characters; no prefix, whitespace, or explanatory text"}`
- Answer: `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247`

### `d05_analysis_architecture`

- Question: For the requested delivered binary, report the processor architecture identified by its executable header. A normalized architecture name, a standard tool or symbolic label, or an equivalent standard machine code is accepted.
- Format: `{"kind":"pattern","syntax":"processor architecture name, standard tool or symbolic label, or equivalent executable-header machine code"}`
- Answer: `x86-64`

### `d05_analysis_format`

- Question: For the requested specimen in the bundled archive, identify its executable container from the final bytes. Submit an ELF or PE container label; letter case and a more specific ELF32, ELF64, PE32, PE32+, or Portable Executable label are accepted when they identify the same container.
- Format: `{"kind":"pattern","syntax":"ELF or PE executable-container label; bitness-qualified standard labels and letter-case differences are accepted"}`
- Answer: `ELF`

### `d05_analysis_config_campaign`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level campaign property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `BR05-000`

### `d05_analysis_config_domain`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level domain property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `node-000.day05.example.invalid`

### `d05_analysis_config_mutex`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level mutex property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `Global\HuntressBR05_000`

### `d05_analysis_config_url`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG JSON object's top-level url property, without JSON quotes.
- Format: `{"kind":"exact_text","syntax":"exact case-sensitive artifact-derived text only; no quotes or explanatory text"}`
- Answer: `https://node-000.day05.example.invalid/api/BR05-000`

### `d05_analysis_config_crc32_hex`

- Question: In evidence.zip, Use all d05-- members in ZIP central-directory order. Scan each literal HCFG occurrence in the Rust ELF and accept the first record whose bounds, CRC32, and decoded JSON validate. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte key, verify CRC32, then parse the decoded UTF-8 JSON. Read the little-endian uint32 at HCFG header bytes 8..11 and render it as 0x plus exactly eight lowercase hexadecimal digits.
- Format: `{"kind":"pattern","syntax":"lowercase hexadecimal with a 0x prefix; preserve the field's required zero padding; no whitespace or explanatory text"}`
- Answer: `0x8f37c323`

