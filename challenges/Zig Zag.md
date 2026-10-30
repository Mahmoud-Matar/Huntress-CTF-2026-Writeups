# Zig Zag — Day 10

## Single Solve

- **Route:** `binary-reverse-engineering-day-10-zig-cross-platform-services`
- **Mode:** Single Solve, untimed; no deadline was returned.
- **Attempt:** `9b505480-2789-4f05-bb96-01a3cd888370` (started 2026-10-23 01:57:59.951 UTC)
- **Prompt:** “Zig promises one binary for every platform. Compare the ELF and PE service descriptors side by side and prove they're the same program wearing different uniforms.”
- **Archive:** `evidence.zip`, API SHA-256 `adfe4db049e19fe859744d6bec81c696950f7905f530fd40ba1755197d35e259`; downloaded from the authenticated artifact operation at `/?op=download&capability=92d742e0a7c14ee196af99ee847e5df73bfcb6b142b14a8fb2539e159bcd053a` and analyzed on REMnux.
- **Archive password:** the challenge's published `infected`.
- **Result:** `CORRECT`; all 100 answer IDs were accepted. CourseStack returned flag `72415cb0987bc5b53cd068ab6d72e070`.

## Method and findings

The archive contains ten groups (`d01--` through `d10--`). I verified the archive hash, extracted the exact assigned bytes, and used static parsing on REMnux: ELF headers and section/symbol tables, PE/.NET metadata, JAR manifests and ZIP methods, and the HCFG records. No challenge binaries were executed.

The formats span ELF, PE32 CLR, and JAR. Each HCFG record was validated using its length, one-byte XOR key, and CRC32 before decoding the UTF-8 JSON. The records expose the per-sample campaign, reserved domain, mutex, URL, and CRC32. The complete artifact-derived answer map is included below by answer ID.

| Group | API member SHA-256 | Key findings |
|---|---|---|
| d01 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` | ELF64, x86-64; `ET_EXEC`; little-endian; entry `0x401040`; `.symtab` present; `recover_code` returns `0x1fa4`. |
| d02 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | ELF with C++ typeinfo and vtable; campaign `BR02-000`. |
| d03 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d`; runtime config `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | PE32 CLR, machine `i386`, metadata `v4.0.30319`; campaign `BR03-000`. |
| d04 | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` | x86-64 ELF; campaign `BR04-000`. |
| d05 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` | x86-64 ELF; campaign `BR05-000`. |
| d06 | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` | JAR; observed ZIP methods `[0,8]`; campaign `BR06-000`. |
| d07 | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` | JAR; observed ZIP methods `[0,8]`; campaign `BR07-000`. |
| d08 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` | ELF64, x86-64; campaign `BR08-000`. |
| d09 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` | x86-64 ELF; campaign `BR09-000`; winning Base64 HCFG carrier starts at byte offset `30696`. |
| d10 | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` | x86-64 ELF; `.hcfg`-containing section predicate true; campaign `BR10-000`. |

The analyzer initially labeled d08's ELF class as `ELF64`; the API question requires the decimal bit width, so the accepted answer is `64`. Submitting d01–d07 first, correcting d08, then submitting d08–d10 confirmed all 100 findings. The d09 byte offset is submitted as the base-10 string `30696`, matching the Game Master answer representation.

## Submitted answers

```json
{
  "d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "d02_artifact_sha256_1": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
  "d03_artifact_sha256_1": "a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d",
  "d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "d04_artifact_sha256_1": "d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f",
  "d05_artifact_sha256_1": "4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247",
  "d06_artifact_sha256_1": "6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c",
  "d07_artifact_sha256_1": "13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b",
  "d08_artifact_sha256_1": "a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529",
  "d09_artifact_sha256_1": "5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad",
  "d10_artifact_sha256_1": "9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7",
  "d01_analysis_elf_class": "ELF64",
  "d01_analysis_machine": "x86-64",
  "d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "d01_analysis_elf_type": "ET_EXEC",
  "d01_analysis_endianness": "ELFDATA2LSB",
  "d01_analysis_entry_point": "0x401040",
  "d01_analysis_has_symtab": "true",
  "d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "d02_analysis_format": "ELF",
  "d02_analysis_has_cpp_typeinfo": "true",
  "d02_analysis_has_cpp_vtable": "true",
  "d02_analysis_config_campaign": "BR02-000",
  "d02_analysis_config_domain": "node-000.day02.example.invalid",
  "d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "d02_analysis_config_crc32_hex": "0x6149aa00",
  "d02_analysis_xor_key_hex": "0x31",
  "d03_analysis_format": "PE32_CLR",
  "d03_analysis_machine": "i386",
  "d03_analysis_metadata_version": "v4.0.30319",
  "d03_analysis_config_campaign": "BR03-000",
  "d03_analysis_config_domain": "node-000.day03.example.invalid",
  "d03_analysis_config_mutex": "Global\\HuntressBR03_000",
  "d03_analysis_config_url": "https://node-000.day03.example.invalid/api/BR03-000",
  "d03_analysis_config_crc32_hex": "0xcb6cf23f",
  "d04_analysis_architecture": "x86-64",
  "d04_analysis_format": "ELF",
  "d04_analysis_config_campaign": "BR04-000",
  "d04_analysis_config_domain": "node-000.day04.example.invalid",
  "d04_analysis_config_mutex": "Global\\HuntressBR04_000",
  "d04_analysis_config_url": "https://node-000.day04.example.invalid/api/BR04-000",
  "d04_analysis_config_crc32_hex": "0x2b747600",
  "d04_analysis_hcfg_version": "1",
  "d04_analysis_xor_key_hex": "0x51",
  "d05_analysis_architecture": "x86-64",
  "d05_analysis_format": "ELF",
  "d05_analysis_config_campaign": "BR05-000",
  "d05_analysis_config_domain": "node-000.day05.example.invalid",
  "d05_analysis_config_mutex": "Global\\HuntressBR05_000",
  "d05_analysis_config_url": "https://node-000.day05.example.invalid/api/BR05-000",
  "d05_analysis_config_crc32_hex": "0x8f37c323",
  "d05_analysis_hcfg_version": "1",
  "d05_analysis_xor_key_hex": "0x61",
  "d06_analysis_format": "JAR",
  "d06_analysis_compression_methods": "[0,8]",
  "d06_analysis_config_campaign": "BR06-000",
  "d06_analysis_config_domain": "node-000.day06.example.invalid",
  "d06_analysis_config_mutex": "Global\\HuntressBR06_000",
  "d06_analysis_config_url": "https://node-000.day06.example.invalid/api/BR06-000",
  "d06_analysis_config_crc32_hex": "0x121bc931",
  "d06_analysis_hcfg_version": "1",
  "d06_analysis_xor_key_hex": "0x71",
  "d07_analysis_format": "JAR",
  "d07_analysis_compression_methods": "[0,8]",
  "d07_analysis_config_campaign": "BR07-000",
  "d07_analysis_config_domain": "node-000.day07.example.invalid",
  "d07_analysis_config_mutex": "Global\\HuntressBR07_000",
  "d07_analysis_config_url": "https://node-000.day07.example.invalid/api/BR07-000",
  "d07_analysis_config_crc32_hex": "0xcf3ea232",
  "d07_analysis_hcfg_version": "1",
  "d07_analysis_xor_key_hex": "0x31",
  "d08_analysis_architecture": "x86-64",
  "d08_analysis_format": "ELF",
  "d08_analysis_machine": "x86-64",
  "d08_analysis_elf_class": "64",
  "d08_analysis_config_campaign": "BR08-000",
  "d08_analysis_config_domain": "node-000.day08.example.invalid",
  "d08_analysis_config_mutex": "Global\\HuntressBR08_000",
  "d08_analysis_config_url": "https://node-000.day08.example.invalid/api/BR08-000",
  "d08_analysis_config_crc32_hex": "0x6a033bfd",
  "d09_analysis_architecture": "x86-64",
  "d09_analysis_format": "ELF",
  "d09_analysis_machine": "x86-64",
  "d09_analysis_config_campaign": "BR09-000",
  "d09_analysis_config_domain": "node-000.day09.example.invalid",
  "d09_analysis_config_mutex": "Global\\HuntressBR09_000",
  "d09_analysis_config_url": "https://node-000.day09.example.invalid/api/BR09-000",
  "d09_analysis_config_crc32_hex": "0x9614e1a8",
  "d10_analysis_architecture": "x86-64",
  "d10_analysis_format": "ELF",
  "d10_analysis_machine": "x86-64",
  "d10_analysis_has_hcfg_section": "true",
  "d10_analysis_config_campaign": "BR10-000",
  "d10_analysis_config_domain": "node-000.day10.example.invalid",
  "d10_analysis_config_mutex": "Global\\HuntressBR10_000",
  "d10_analysis_config_url": "https://node-000.day10.example.invalid/api/BR10-000",
  "d10_analysis_config_crc32_hex": "0xceda03ad",
  "d09_analysis_hcfg_offset": "30696"
}
```

## Time Trial

- **Route:** `binary-reverse-engineering-day-10-zig-cross-platform-services/time_trial`
- **Mode:** Time Trial; the legacy route started timed by default. The server deadline was 2026-10-23 02:31:40.210 UTC (80 seconds after start).
- **Attempt:** `47bcbee8-5810-45c2-906c-d0053bb84ddc`, started 2026-10-23 02:30:20.210 UTC.
- **First attempt:** attempt `9926bbd6-f54d-474d-97a5-4ef7a07f42f0` expired while I was still deriving PE-specific fields; it awarded no completion. The next retry used one fresh variant.
- **Archive:** `evidence.zip`, SHA-256 `76d1b0d1fe96da55155d85aac4a670c7cb1574db8af48b4225748f87201f7b6f`; artifact path `/?op=download&capability=39ba272790ab41878c3fcbb5867f74b45a2a5df898294e18bfd315ca7ff18507`.
- **Result:** `CORRECT`; Game Master accepted the full set and returned flag `7f56df2f066e8b74baa4cca7ffdcbfc8`.

The 100-question variant used a different mix of ELF, PE, .NET, Go, and JAR members. I verified the downloaded archive SHA-256, extracted it with the published password, then parsed executable headers, sections and HCFG records on REMnux. For PE groups, I read the native section table, decoded `.hcfg` at the section raw-data offset where requested, and validated record bounds and CRC32 before XOR decoding. The accepted d08 answer is the decimal ELF bit width `64`; the d10 CRC32 is zero-padded to eight lowercase hex digits.

| Group | Sample SHA-256(s) | Findings |
|---|---|---|
| d01 | `d6ce6aebf869d863bcf29eb053fc45eb1eeadb95c9166c484d44c47becdb840f` | ELF64 x86-64 |
| d02 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | PE x86-64; DiscoveryEngine RTTI and vtable predicates true |
| d03 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9`; `runtime config d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | PE32 CLR / i386 |
| d04 | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` | PE32+ Go executable; HCFG in final bytes |
| d05 | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` | ELF x86-64 |
| d06 | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` | JAR; compression methods [0,8] |
| d07 | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` | JAR; compression methods [0,8] |
| d08 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` | ELF64 x86-64 |
| d09 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` | ELF x86-64; HCFG carrier offset 30696 |
| d10 | `78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae` | PE32+; HCFG section predicate true |

### Accepted answer map

```json
{
  "d01_artifact_sha256_1": "d6ce6aebf869d863bcf29eb053fc45eb1eeadb95c9166c484d44c47becdb840f",
  "d02_artifact_sha256_1": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
  "d03_artifact_sha256_1": "74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9",
  "d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "d04_artifact_sha256_1": "812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6",
  "d05_artifact_sha256_1": "327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624",
  "d06_artifact_sha256_1": "1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19",
  "d07_artifact_sha256_1": "a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f",
  "d08_artifact_sha256_1": "a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529",
  "d09_artifact_sha256_1": "d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d",
  "d10_artifact_sha256_1": "78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae",
  "d01_analysis_elf_class": "ELF64",
  "d01_analysis_machine": "x86-64",
  "d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-001.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "d01_analysis_elf_type": "ET_EXEC",
  "d01_analysis_endianness": "ELFDATA2LSB",
  "d01_analysis_entry_point": "0x401040",
  "d01_analysis_has_symtab": "true",
  "d01_analysis_disassembly": "[\"mov eax,0x1fa5\",\"ret\"]",
  "d02_analysis_format": "ELF",
  "d02_analysis_has_cpp_typeinfo": "true",
  "d02_analysis_has_cpp_vtable": "true",
  "d02_analysis_config_campaign": "BR02-000",
  "d02_analysis_config_domain": "node-000.day02.example.invalid",
  "d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "d02_analysis_config_crc32_hex": "0x6149aa00",
  "d02_analysis_xor_key_hex": "0x31",
  "d03_analysis_format": "PE32_CLR",
  "d03_analysis_machine": "i386",
  "d03_analysis_metadata_version": "v4.0.30319",
  "d03_analysis_config_campaign": "BR03-001",
  "d03_analysis_config_domain": "node-001.day03.example.invalid",
  "d03_analysis_config_mutex": "Global\\HuntressBR03_001",
  "d03_analysis_config_url": "https://node-001.day03.example.invalid/api/BR03-001",
  "d03_analysis_config_crc32_hex": "0x55fbb381",
  "d04_analysis_architecture": "x86-64",
  "d04_analysis_format": "ELF",
  "d04_analysis_config_campaign": "BR04-006",
  "d04_analysis_config_domain": "node-006.day04.example.invalid",
  "d04_analysis_config_mutex": "Global\\HuntressBR04_006",
  "d04_analysis_config_url": "https://node-006.day04.example.invalid/api/BR04-006",
  "d04_analysis_config_crc32_hex": "0xdae5ff06",
  "d04_analysis_hcfg_version": "1",
  "d04_analysis_xor_key_hex": "0x57",
  "d05_analysis_architecture": "x86-64",
  "d05_analysis_format": "ELF",
  "d05_analysis_config_campaign": "BR05-007",
  "d05_analysis_config_domain": "node-007.day05.example.invalid",
  "d05_analysis_config_mutex": "Global\\HuntressBR05_007",
  "d05_analysis_config_url": "https://node-007.day05.example.invalid/api/BR05-007",
  "d05_analysis_config_crc32_hex": "0x4525249b",
  "d05_analysis_hcfg_version": "1",
  "d05_analysis_xor_key_hex": "0x68",
  "d06_analysis_format": "JAR",
  "d06_analysis_compression_methods": "[0,8]",
  "d06_analysis_config_campaign": "BR06-002",
  "d06_analysis_config_domain": "node-002.day06.example.invalid",
  "d06_analysis_config_mutex": "Global\\HuntressBR06_002",
  "d06_analysis_config_url": "https://node-002.day06.example.invalid/api/BR06-002",
  "d06_analysis_config_crc32_hex": "0x81273e0c",
  "d06_analysis_hcfg_version": "1",
  "d06_analysis_xor_key_hex": "0x73",
  "d07_analysis_format": "JAR",
  "d07_analysis_compression_methods": "[0,8]",
  "d07_analysis_config_campaign": "BR07-005",
  "d07_analysis_config_domain": "node-005.day07.example.invalid",
  "d07_analysis_config_mutex": "Global\\HuntressBR07_005",
  "d07_analysis_config_url": "https://node-005.day07.example.invalid/api/BR07-005",
  "d07_analysis_config_crc32_hex": "0x9610b2b7",
  "d07_analysis_hcfg_version": "1",
  "d07_analysis_xor_key_hex": "0x36",
  "d08_analysis_architecture": "x86-64",
  "d08_analysis_format": "ELF",
  "d08_analysis_machine": "x86-64",
  "d08_analysis_elf_class": "64",
  "d08_analysis_config_campaign": "BR08-000",
  "d08_analysis_config_domain": "node-000.day08.example.invalid",
  "d08_analysis_config_mutex": "Global\\HuntressBR08_000",
  "d08_analysis_config_url": "https://node-000.day08.example.invalid/api/BR08-000",
  "d08_analysis_config_crc32_hex": "0x6a033bfd",
  "d09_analysis_architecture": "x86-64",
  "d09_analysis_format": "ELF",
  "d09_analysis_machine": "x86-64",
  "d09_analysis_config_campaign": "BR09-003",
  "d09_analysis_config_domain": "node-003.day09.example.invalid",
  "d09_analysis_config_mutex": "Global\\HuntressBR09_003",
  "d09_analysis_config_url": "https://node-003.day09.example.invalid/api/BR09-003",
  "d09_analysis_config_crc32_hex": "0xa10eee2b",
  "d10_analysis_architecture": "x86-64",
  "d10_analysis_format": "ELF",
  "d10_analysis_machine": "x86-64",
  "d10_analysis_has_hcfg_section": "true",
  "d10_analysis_config_campaign": "BR10-007",
  "d10_analysis_config_domain": "node-007.day10.example.invalid",
  "d10_analysis_config_mutex": "Global\\HuntressBR10_007",
  "d10_analysis_config_url": "https://node-007.day10.example.invalid/api/BR10-007",
  "d10_analysis_config_crc32_hex": "0x04c8e415",
  "d09_analysis_hcfg_offset": "30696"
}
```




## Mastery Mode

The Mastery route was completed on the fresh attempt `6a8e11b3-ceea-4f68-8837-2113e3577a5f`. Its shared deadline was 2026-10-23 02:44:36.759 UTC. The Game Master returned `CORRECT`; CourseStack completion was confirmed in status, and two consecutive Day 10 lists show all three Zig Zag modes solved. Completion flag: `c62d08c59818539dc53c38a54a78fdef`.

I downloaded all three assigned `evidence.zip` archives through the authenticated Game Master connection, extracted them with the published password `infected`, and checked the downloaded file hashes before analysis:

- Set 1: `ccf70b0b44eb10eb2cef69b833c709f1b2b6d9cebb18259efa6d372b35161a6e`
- Set 2: `bd58685bde07f5592ce1b77359a1a325c20b591c242268265c7ec15b0c24c706`
- Set 3: `d048b677462ddecf0c503dddedbbc904f273ad8fca0aef9421eeaf4512e28cff`

The parser reused for the earlier modes inspected the exact extracted bytes, preserved each set's answer IDs, and derived all 300 responses across ten daily specimens per set. It handled ELF and PE headers, ordered ELF symbol and section data, CLR metadata, and HCFG records carried directly or through encoded data. The full submitted answer map follows as compact JSON:

```json
{"set1.d01_artifact_sha256_1":"a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b","set1.d02_artifact_sha256_1":"e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7","set1.d03_artifact_sha256_1":"74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9","set1.d03_artifact_sha256_2":"d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3","set1.d04_artifact_sha256_1":"812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6","set1.d05_artifact_sha256_1":"327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624","set1.d06_artifact_sha256_1":"1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19","set1.d07_artifact_sha256_1":"a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f","set1.d08_artifact_sha256_1":"a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529","set1.d09_artifact_sha256_1":"d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d","set1.d10_artifact_sha256_1":"78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae","set1.d01_analysis_elf_class":"ELF64","set1.d01_analysis_machine":"x86-64","set1.d01_analysis_section_names":"[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]","set1.d01_analysis_symbols":"[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]","set1.d01_analysis_elf_type":"ET_EXEC","set1.d01_analysis_endianness":"ELFDATA2LSB","set1.d01_analysis_entry_point":"0x401040","set1.d01_analysis_has_symtab":"true","set1.d01_analysis_disassembly":"[\"mov eax,0x1fa4\",\"ret\"]","set1.d02_analysis_format":"ELF","set1.d02_analysis_has_cpp_typeinfo":"true","set1.d02_analysis_has_cpp_vtable":"true","set1.d02_analysis_config_campaign":"BR02-000","set1.d02_analysis_config_domain":"node-000.day02.example.invalid","set1.d02_analysis_config_mutex":"Global\\HuntressBR02_000","set1.d02_analysis_config_url":"https://node-000.day02.example.invalid/api/BR02-000","set1.d02_analysis_config_crc32_hex":"0x6149aa00","set1.d02_analysis_xor_key_hex":"0x31","set1.d03_analysis_format":"PE32_CLR","set1.d03_analysis_machine":"i386","set1.d03_analysis_metadata_version":"v4.0.30319","set1.d03_analysis_config_campaign":"BR03-001","set1.d03_analysis_config_domain":"node-001.day03.example.invalid","set1.d03_analysis_config_mutex":"Global\\HuntressBR03_001","set1.d03_analysis_config_url":"https://node-001.day03.example.invalid/api/BR03-001","set1.d03_analysis_config_crc32_hex":"0x55fbb381","set1.d04_analysis_architecture":"x86-64","set1.d04_analysis_format":"ELF","set1.d04_analysis_config_campaign":"BR04-006","set1.d04_analysis_config_domain":"node-006.day04.example.invalid","set1.d04_analysis_config_mutex":"Global\\HuntressBR04_006","set1.d04_analysis_config_url":"https://node-006.day04.example.invalid/api/BR04-006","set1.d04_analysis_config_crc32_hex":"0xdae5ff06","set1.d04_analysis_hcfg_version":"1","set1.d04_analysis_xor_key_hex":"0x57","set1.d05_analysis_architecture":"x86-64","set1.d05_analysis_format":"ELF","set1.d05_analysis_config_campaign":"BR05-007","set1.d05_analysis_config_domain":"node-007.day05.example.invalid","set1.d05_analysis_config_mutex":"Global\\HuntressBR05_007","set1.d05_analysis_config_url":"https://node-007.day05.example.invalid/api/BR05-007","set1.d05_analysis_config_crc32_hex":"0x4525249b","set1.d05_analysis_hcfg_version":"1","set1.d05_analysis_xor_key_hex":"0x68","set1.d06_analysis_format":"JAR","set1.d06_analysis_compression_methods":"[0,8]","set1.d06_analysis_config_campaign":"BR06-002","set1.d06_analysis_config_domain":"node-002.day06.example.invalid","set1.d06_analysis_config_mutex":"Global\\HuntressBR06_002","set1.d06_analysis_config_url":"https://node-002.day06.example.invalid/api/BR06-002","set1.d06_analysis_config_crc32_hex":"0x81273e0c","set1.d06_analysis_hcfg_version":"1","set1.d06_analysis_xor_key_hex":"0x73","set1.d07_analysis_format":"JAR","set1.d07_analysis_compression_methods":"[0,8]","set1.d07_analysis_config_campaign":"BR07-005","set1.d07_analysis_config_domain":"node-005.day07.example.invalid","set1.d07_analysis_config_mutex":"Global\\HuntressBR07_005","set1.d07_analysis_config_url":"https://node-005.day07.example.invalid/api/BR07-005","set1.d07_analysis_config_crc32_hex":"0x9610b2b7","set1.d07_analysis_hcfg_version":"1","set1.d07_analysis_xor_key_hex":"0x36","set1.d08_analysis_architecture":"x86-64","set1.d08_analysis_format":"ELF","set1.d08_analysis_machine":"x86-64","set1.d08_analysis_elf_class":"64","set1.d08_analysis_config_campaign":"BR08-000","set1.d08_analysis_config_domain":"node-000.day08.example.invalid","set1.d08_analysis_config_mutex":"Global\\HuntressBR08_000","set1.d08_analysis_config_url":"https://node-000.day08.example.invalid/api/BR08-000","set1.d08_analysis_config_crc32_hex":"0x6a033bfd","set1.d09_analysis_architecture":"x86-64","set1.d09_analysis_format":"ELF","set1.d09_analysis_machine":"x86-64","set1.d09_analysis_config_campaign":"BR09-003","set1.d09_analysis_config_domain":"node-003.day09.example.invalid","set1.d09_analysis_config_mutex":"Global\\HuntressBR09_003","set1.d09_analysis_config_url":"https://node-003.day09.example.invalid/api/BR09-003","set1.d09_analysis_config_crc32_hex":"0xa10eee2b","set1.d10_analysis_architecture":"x86-64","set1.d10_analysis_format":"ELF","set1.d10_analysis_machine":"x86-64","set1.d10_analysis_has_hcfg_section":"true","set1.d10_analysis_config_campaign":"BR10-007","set1.d10_analysis_config_domain":"node-007.day10.example.invalid","set1.d10_analysis_config_mutex":"Global\\HuntressBR10_007","set1.d10_analysis_config_url":"https://node-007.day10.example.invalid/api/BR10-007","set1.d10_analysis_config_crc32_hex":"0x04c8e415","set1.d09_analysis_hcfg_offset":"30696","set2.d01_artifact_sha256_1":"a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b","set2.d02_artifact_sha256_1":"f639696c8515236773e209fdc7ab0f69148f949e5a7e329f6bf94b5b790930bc","set2.d03_artifact_sha256_1":"9686e6dab1cf8713d440188ef0d943421541ddfece686b8e18aa72802395fadf","set2.d03_artifact_sha256_2":"d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3","set2.d04_artifact_sha256_1":"5e098c4f9719028367d27121599e34bd3f1bfcaa328a3cd689a8eb0364dc1920","set2.d05_artifact_sha256_1":"cb390c7dcb224aca2c23bdef306130dd5fd51ec6b6b47a7df3180a334c12c6a3","set2.d06_artifact_sha256_1":"dfb3b646b06ff9349775677c1533a244541acfba5834106fd2739634532650b4","set2.d07_artifact_sha256_1":"13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b","set2.d08_artifact_sha256_1":"80ba7e1ab243b4dca46d0b9bc93e6f6fe39dc7ec9eafb34da9bfc99c36aa146d","set2.d09_artifact_sha256_1":"6d742be643831355f824f040a5d40c462401266c9180196410044afd5a0ebf4f","set2.d10_artifact_sha256_1":"966d069e1f332bcaeb3b451d7a08f5fe6f502a0cc67c268ff6a8ba0a5210f326","set2.d01_analysis_elf_class":"ELF64","set2.d01_analysis_machine":"x86-64","set2.d01_analysis_section_names":"[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]","set2.d01_analysis_symbols":"[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]","set2.d01_analysis_elf_type":"ET_EXEC","set2.d01_analysis_endianness":"ELFDATA2LSB","set2.d01_analysis_entry_point":"0x401040","set2.d01_analysis_has_symtab":"true","set2.d01_analysis_disassembly":"[\"mov eax,0x1fa4\",\"ret\"]","set2.d03_analysis_format":"PE32_CLR","set2.d03_analysis_machine":"x86-64","set2.d03_analysis_metadata_version":"","set2.d03_analysis_config_campaign":"BR10-007","set2.d03_analysis_config_domain":"node-007.day10.example.invalid","set2.d03_analysis_config_mutex":"Global\\HuntressBR10_007","set2.d03_analysis_config_url":"https://node-007.day10.example.invalid/api/BR10-007","set2.d03_analysis_config_crc32_hex":"0x04c8e415","set2.d05_analysis_architecture":"x86-64","set2.d05_analysis_format":"ELF","set2.d05_analysis_config_campaign":"BR05-006","set2.d05_analysis_config_domain":"node-006.day05.example.invalid","set2.d05_analysis_config_mutex":"Global\\HuntressBR05_006","set2.d05_analysis_config_url":"https://node-006.day05.example.invalid/api/BR05-006","set2.d05_analysis_config_crc32_hex":"0xe103dc25","set2.d05_analysis_hcfg_version":"1","set2.d05_analysis_xor_key_hex":"0x67","set2.d06_analysis_format":"JAR","set2.d06_analysis_compression_methods":"[0,8]","set2.d06_analysis_config_campaign":"BR06-003","set2.d06_analysis_config_domain":"node-003.day06.example.invalid","set2.d06_analysis_config_mutex":"Global\\HuntressBR06_003","set2.d06_analysis_config_url":"https://node-003.day06.example.invalid/api/BR06-003","set2.d06_analysis_config_crc32_hex":"0x2501c6b2","set2.d06_analysis_hcfg_version":"1","set2.d06_analysis_xor_key_hex":"0x74","set2.d07_analysis_format":"JAR","set2.d07_analysis_compression_methods":"[0,8]","set2.d07_analysis_config_campaign":"BR07-000","set2.d07_analysis_config_domain":"node-000.day07.example.invalid","set2.d07_analysis_config_mutex":"Global\\HuntressBR07_000","set2.d07_analysis_config_url":"https://node-000.day07.example.invalid/api/BR07-000","set2.d07_analysis_config_crc32_hex":"0xcf3ea232","set2.d07_analysis_hcfg_version":"1","set2.d07_analysis_xor_key_hex":"0x31","set2.d08_analysis_architecture":"x86-64","set2.d08_analysis_format":"ELF","set2.d08_analysis_machine":"x86-64","set2.d08_analysis_elf_class":"64","set2.d08_analysis_config_campaign":"BR08-005","set2.d08_analysis_config_domain":"node-005.day08.example.invalid","set2.d08_analysis_config_mutex":"Global\\HuntressBR08_005","set2.d08_analysis_config_url":"https://node-005.day08.example.invalid/api/BR08-005","set2.d08_analysis_config_crc32_hex":"0x332d2b78","set2.d09_analysis_architecture":"x86-64","set2.d09_analysis_format":"ELF","set2.d09_analysis_machine":"x86-64","set2.d09_analysis_config_campaign":"BR09-002","set2.d09_analysis_config_domain":"node-002.day09.example.invalid","set2.d09_analysis_config_mutex":"Global\\HuntressBR09_002","set2.d09_analysis_config_url":"https://node-002.day09.example.invalid/api/BR09-002","set2.d09_analysis_config_crc32_hex":"0x05281695","set2.d09_analysis_hcfg_offset":"30696","set2.d02_analysis_format":"PE","set2.d02_analysis_has_cpp_typeinfo":"true","set2.d02_analysis_has_cpp_vtable":"true","set2.d02_analysis_config_campaign":"BR02-006","set2.d02_analysis_config_domain":"node-006.day02.example.invalid","set2.d02_analysis_config_mutex":"Global\\HuntressBR02_006","set2.d02_analysis_config_url":"https://node-006.day02.example.invalid/api/BR02-006","set2.d02_analysis_config_crc32_hex":"0x90d82306","set2.d02_analysis_xor_key_hex":"0x37","set2.d04_analysis_architecture":"x86-64","set2.d04_analysis_format":"PE32+","set2.d04_analysis_config_campaign":"BR04-000","set2.d04_analysis_config_domain":"node-000.day04.example.invalid","set2.d04_analysis_config_mutex":"Global\\HuntressBR04_000","set2.d04_analysis_config_url":"https://node-000.day04.example.invalid/api/BR04-000","set2.d04_analysis_config_crc32_hex":"0x2b747600","set2.d04_analysis_hcfg_version":"1","set2.d04_analysis_xor_key_hex":"0x51","set2.d10_analysis_architecture":"x86-64","set2.d10_analysis_format":"PE32+","set2.d10_analysis_machine":"x86-64","set2.d10_analysis_has_hcfg_section":"true","set2.d10_analysis_config_campaign":"BR10-007","set2.d10_analysis_config_domain":"node-007.day10.example.invalid","set2.d10_analysis_config_mutex":"Global\\HuntressBR10_007","set2.d10_analysis_config_url":"https://node-007.day10.example.invalid/api/BR10-007","set2.d10_analysis_config_crc32_hex":"0x04c8e415","set3.d01_artifact_sha256_1":"a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b","set3.d02_artifact_sha256_1":"a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2","set3.d03_artifact_sha256_1":"14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef","set3.d03_artifact_sha256_2":"d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3","set3.d04_artifact_sha256_1":"173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5","set3.d05_artifact_sha256_1":"359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c","set3.d06_artifact_sha256_1":"e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1","set3.d07_artifact_sha256_1":"7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c","set3.d08_artifact_sha256_1":"f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48","set3.d09_artifact_sha256_1":"adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69","set3.d10_artifact_sha256_1":"bc5ae6af7c14106ed6652574359285d97590e1d232a7b8be6151d6e915e4face","set3.d01_analysis_elf_class":"ELF64","set3.d01_analysis_machine":"x86-64","set3.d01_analysis_section_names":"[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]","set3.d01_analysis_symbols":"[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]","set3.d01_analysis_elf_type":"ET_EXEC","set3.d01_analysis_endianness":"ELFDATA2LSB","set3.d01_analysis_entry_point":"0x401040","set3.d01_analysis_has_symtab":"true","set3.d01_analysis_disassembly":"[\"mov eax,0x1fa4\",\"ret\"]","set3.d02_analysis_format":"ELF","set3.d02_analysis_has_cpp_typeinfo":"true","set3.d02_analysis_has_cpp_vtable":"true","set3.d02_analysis_config_campaign":"BR02-001","set3.d02_analysis_config_domain":"node-001.day02.example.invalid","set3.d02_analysis_config_mutex":"Global\\HuntressBR02_001","set3.d02_analysis_config_url":"https://node-001.day02.example.invalid/api/BR02-001","set3.d02_analysis_config_crc32_hex":"0xffdeebbe","set3.d02_analysis_xor_key_hex":"0x32","set3.d03_analysis_format":"PE32_CLR","set3.d03_analysis_machine":"i386","set3.d03_analysis_metadata_version":"v4.0.30319","set3.d03_analysis_config_campaign":"BR03-007","set3.d03_analysis_config_domain":"node-007.day03.example.invalid","set3.d03_analysis_config_mutex":"Global\\HuntressBR03_007","set3.d03_analysis_config_url":"https://node-007.day03.example.invalid/api/BR03-007","set3.d03_analysis_config_crc32_hex":"0xa46a3a87","set3.d04_analysis_architecture":"x86-64","set3.d04_analysis_format":"ELF","set3.d04_analysis_config_campaign":"BR04-007","set3.d04_analysis_config_domain":"node-007.day04.example.invalid","set3.d04_analysis_config_mutex":"Global\\HuntressBR04_007","set3.d04_analysis_config_url":"https://node-007.day04.example.invalid/api/BR04-007","set3.d04_analysis_config_crc32_hex":"0x4472beb8","set3.d04_analysis_hcfg_version":"1","set3.d04_analysis_xor_key_hex":"0x58","set3.d05_analysis_architecture":"x86-64","set3.d05_analysis_format":"ELF","set3.d05_analysis_config_campaign":"BR05-005","set3.d05_analysis_config_domain":"node-005.day05.example.invalid","set3.d05_analysis_config_mutex":"Global\\HuntressBR05_005","set3.d05_analysis_config_url":"https://node-005.day05.example.invalid/api/BR05-005","set3.d05_analysis_config_crc32_hex":"0xd619d3a6","set3.d05_analysis_hcfg_version":"1","set3.d05_analysis_xor_key_hex":"0x66","set3.d06_analysis_format":"JAR","set3.d06_analysis_compression_methods":"[0,8]","set3.d06_analysis_config_campaign":"BR06-004","set3.d06_analysis_config_domain":"node-004.day06.example.invalid","set3.d06_analysis_config_mutex":"Global\\HuntressBR06_004","set3.d06_analysis_config_url":"https://node-004.day06.example.invalid/api/BR06-004","set3.d06_analysis_config_crc32_hex":"0xef13210a","set3.d06_analysis_hcfg_version":"1","set3.d06_analysis_xor_key_hex":"0x75","set3.d07_analysis_format":"JAR","set3.d07_analysis_compression_methods":"[0,8]","set3.d07_analysis_config_campaign":"BR07-003","set3.d07_analysis_config_domain":"node-003.day07.example.invalid","set3.d07_analysis_config_mutex":"Global\\HuntressBR07_003","set3.d07_analysis_config_url":"https://node-003.day07.example.invalid/api/BR07-003","set3.d07_analysis_config_crc32_hex":"0xf824adb1","set3.d07_analysis_hcfg_version":"1","set3.d07_analysis_xor_key_hex":"0x34","set3.d08_analysis_architecture":"x86-64","set3.d08_analysis_format":"ELF","set3.d08_analysis_machine":"x86-64","set3.d08_analysis_elf_class":"64","set3.d08_analysis_config_campaign":"BR08-002","set3.d08_analysis_config_domain":"node-002.day08.example.invalid","set3.d08_analysis_config_mutex":"Global\\HuntressBR08_002","set3.d08_analysis_config_url":"https://node-002.day08.example.invalid/api/BR08-002","set3.d08_analysis_config_crc32_hex":"0xf93fccc0","set3.d09_analysis_architecture":"x86-64","set3.d09_analysis_format":"ELF","set3.d09_analysis_machine":"x86-64","set3.d09_analysis_config_campaign":"BR09-001","set3.d09_analysis_config_domain":"node-001.day09.example.invalid","set3.d09_analysis_config_mutex":"Global\\HuntressBR09_001","set3.d09_analysis_config_url":"https://node-001.day09.example.invalid/api/BR09-001","set3.d09_analysis_config_crc32_hex":"0x32321916","set3.d10_analysis_architecture":"x86-64","set3.d10_analysis_format":"ELF","set3.d10_analysis_machine":"x86-64","set3.d10_analysis_has_hcfg_section":"true","set3.d10_analysis_config_campaign":"BR10-004","set3.d10_analysis_config_domain":"node-004.day10.example.invalid","set3.d10_analysis_config_mutex":"Global\\HuntressBR10_004","set3.d10_analysis_config_url":"https://node-004.day10.example.invalid/api/BR10-004","set3.d10_analysis_config_crc32_hex":"0x33d2eb96","set3.d09_analysis_hcfg_offset":"30696"}
```
