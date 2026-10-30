# Pascal's Wager — Day 12 Single Solve

- **Challenge ID:** `binary-reverse-engineering-day-12-pascal-archive-stager`
- **Mode:** Single Solve, untimed; deadline `null`.
- **Attempt:** `70c2f2ba-2eb0-482d-8c77-eedf3f211715`
- **Prompt:** Pascal is betting you won't read its record layouts. Take the wager: unpack the archive stager's structures and read the configuration straight from memory's own filing cabinet.
- **Artifact:** `evidence.zip`, 31,930,773 bytes; SHA-256 `268ef143d563c083c3a6a57e8d06bde5ed476f32279e32338500da88ba129029`.
- **Archive password:** `infected`.
- **Download:** fetched from the authenticated Game Master artifact operation using the paired Kali credential; the credential was not copied into this report.
- **Result:** Game Master returned `CORRECT`; follow-up status confirmed this attempt as `CORRECT`.
- **Flag:** `60b2959e168697229cc41469526f074c`

## Analysis

The archive was AES-encrypted. I verified its SHA-256 against the Game Master response, extracted it on REMnux with the published password, and analyzed the exact extracted bytes without executing the specimens. It contains 13 members: the `d01--` through `d12--` specimens plus the Day 3 runtime configuration. The assignment asked 120 fields, ten for each day group; the submitted map matched all 120 returned answer IDs exactly.

I parsed ELF headers, section tables, and SHT_SYMTAB entries in archive order; disassembled `recover_code` from its exact ELF bytes; parsed the Day 3 PE/CLI machine field and CLR metadata root; and inspected the JAR manifests, main-class constant pools, and ZIP compression methods. For each HCFG record, I checked bounds, decoded the payload with the record’s one-byte XOR key, verified CRC32, and only then parsed the UTF-8 JSON. I followed the per-question carrier rules, including the Day 2 `.hcfg` section, Day 9 and Day 11 Base64 carriers, Day 10 section-name predicate, and Day 12 literal HCFG record.

## Extracted member hashes

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |
| `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| `d06--sample.jar` | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` |
| `d07--sample.jar` | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| `d08--sample.elf` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| `d10--sample.elf` | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` |
| `d11--sample.elf` | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| `d12--sample.elf` | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` |

## Findings by specimen

| Group | Format | Architecture / machine | Artifact-derived findings |
| --- | --- | --- | --- |
| d01 | `ELF64` | `EM_X86_64` | 28 section names; 33 nonempty SHT_SYMTAB names; `recover_code` ["mov eax,0x1fa4","ret"] |
| d02 | `ELF64` | `—` | campaign `BR02-000`; CRC32 `0x6149aa00`; domain `node-000.day02.example.invalid`; mutex `Global\HuntressBR02_000`; URL `https://node-000.day02.example.invalid/api/BR02-000`; XOR key `0x31` |
| d03 | `PE32_CLR` | `IMAGE_FILE_MACHINE_I386` | campaign `BR03-000`; CRC32 `0xcb6cf23f`; domain `node-000.day03.example.invalid`; mutex `Global\HuntressBR03_000`; URL `https://node-000.day03.example.invalid/api/BR03-000`; CLR metadata v4.0.30319 |
| d04 | `ELF64` | `x86-64` | campaign `BR04-000`; CRC32 `0x2b747600`; domain `node-000.day04.example.invalid`; mutex `Global\HuntressBR04_000`; URL `https://node-000.day04.example.invalid/api/BR04-000`; XOR key `0x51`; HCFG version `1` |
| d05 | `ELF64` | `x86-64` | campaign `BR05-000`; CRC32 `0x8f37c323`; domain `node-000.day05.example.invalid`; mutex `Global\HuntressBR05_000`; URL `https://node-000.day05.example.invalid/api/BR05-000`; XOR key `0x61`; HCFG version `1` |
| d06 | `JAR` | `—` | campaign `BR06-000`; CRC32 `0x121bc931`; domain `node-000.day06.example.invalid`; mutex `Global\HuntressBR06_000`; URL `https://node-000.day06.example.invalid/api/BR06-000`; XOR key `0x71`; HCFG version `1`; ZIP methods [0,8] |
| d07 | `JAR` | `—` | campaign `BR07-000`; CRC32 `0xcf3ea232`; domain `node-000.day07.example.invalid`; mutex `Global\HuntressBR07_000`; URL `https://node-000.day07.example.invalid/api/BR07-000`; XOR key `0x31`; HCFG version `1`; ZIP methods [0,8] |
| d08 | `ELF64` | `x86-64` | campaign `BR08-000`; CRC32 `0x6a033bfd`; domain `node-000.day08.example.invalid`; mutex `Global\HuntressBR08_000`; URL `https://node-000.day08.example.invalid/api/BR08-000`; ELF class 64 bits |
| d09 | `ELF64` | `x86-64` | campaign `BR09-000`; CRC32 `0x9614e1a8`; domain `node-000.day09.example.invalid`; mutex `Global\HuntressBR09_000`; URL `https://node-000.day09.example.invalid/api/BR09-000`; winning Base64 carrier offset 30696 |
| d10 | `ELF64` | `x86-64` | campaign `BR10-000`; CRC32 `0xceda03ad`; domain `node-000.day10.example.invalid`; mutex `Global\HuntressBR10_000`; URL `https://node-000.day10.example.invalid/api/BR10-000`; section-name `hcfg` predicate true |
| d11 | `ELF64` | `x86-64` | campaign `BR11-000`; CRC32 `0x03663005`; domain `node-000.day11.example.invalid`; mutex `Global\HuntressBR11_000`; URL `https://node-000.day11.example.invalid/api/BR11-000`; winning Base64 carrier offset 368272 |
| d12 | `elf` | `x86-64` | campaign `BR12-000`; CRC32 `0xe4fc81f8`; domain `node-000.day12.example.invalid`; mutex `Global\HuntressBR12_000`; URL `https://node-000.day12.example.invalid/api/BR12-000`; literal HCFG offset 82928 |

## Submitted answer map

The complete answer map is included below so every returned answer ID and submitted value can be audited against the archive.

```json
{
  "d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "d01_analysis_elf_class": "ELF64",
  "d01_analysis_machine": "EM_X86_64",
  "d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "d01_analysis_elf_type": "ET_EXEC",
  "d01_analysis_endianness": "ELFDATA2LSB",
  "d01_analysis_entry_point": "0x401040",
  "d01_analysis_has_symtab": "true",
  "d02_artifact_sha256_1": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
  "d02_analysis_format": "ELF64",
  "d02_analysis_config_campaign": "BR02-000",
  "d02_analysis_config_domain": "node-000.day02.example.invalid",
  "d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "d02_analysis_config_crc32_hex": "0x6149aa00",
  "d02_analysis_xor_key_hex": "0x31",
  "d02_analysis_has_cpp_typeinfo": "true",
  "d02_analysis_has_cpp_vtable": "true",
  "d03_artifact_sha256_1": "a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d",
  "d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "d03_analysis_format": "PE32_CLR",
  "d03_analysis_machine": "IMAGE_FILE_MACHINE_I386",
  "d03_analysis_metadata_version": "v4.0.30319",
  "d03_analysis_config_campaign": "BR03-000",
  "d03_analysis_config_domain": "node-000.day03.example.invalid",
  "d03_analysis_config_mutex": "Global\\HuntressBR03_000",
  "d03_analysis_config_url": "https://node-000.day03.example.invalid/api/BR03-000",
  "d03_analysis_config_crc32_hex": "0xcb6cf23f",
  "d04_artifact_sha256_1": "d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f",
  "d04_analysis_architecture": "x86-64",
  "d04_analysis_format": "ELF64",
  "d04_analysis_config_campaign": "BR04-000",
  "d04_analysis_config_domain": "node-000.day04.example.invalid",
  "d04_analysis_config_mutex": "Global\\HuntressBR04_000",
  "d04_analysis_config_url": "https://node-000.day04.example.invalid/api/BR04-000",
  "d04_analysis_config_crc32_hex": "0x2b747600",
  "d04_analysis_hcfg_version": "1",
  "d04_analysis_xor_key_hex": "0x51",
  "d05_artifact_sha256_1": "4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247",
  "d05_analysis_architecture": "x86-64",
  "d05_analysis_format": "ELF64",
  "d05_analysis_config_campaign": "BR05-000",
  "d05_analysis_config_domain": "node-000.day05.example.invalid",
  "d05_analysis_config_mutex": "Global\\HuntressBR05_000",
  "d05_analysis_config_url": "https://node-000.day05.example.invalid/api/BR05-000",
  "d05_analysis_config_crc32_hex": "0x8f37c323",
  "d05_analysis_hcfg_version": "1",
  "d05_analysis_xor_key_hex": "0x61",
  "d06_artifact_sha256_1": "6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c",
  "d06_analysis_format": "JAR",
  "d06_analysis_config_campaign": "BR06-000",
  "d06_analysis_config_domain": "node-000.day06.example.invalid",
  "d06_analysis_config_mutex": "Global\\HuntressBR06_000",
  "d06_analysis_config_url": "https://node-000.day06.example.invalid/api/BR06-000",
  "d06_analysis_config_crc32_hex": "0x121bc931",
  "d06_analysis_hcfg_version": "1",
  "d06_analysis_xor_key_hex": "0x71",
  "d06_analysis_compression_methods": "[0,8]",
  "d07_artifact_sha256_1": "13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b",
  "d07_analysis_format": "JAR",
  "d07_analysis_config_campaign": "BR07-000",
  "d07_analysis_config_domain": "node-000.day07.example.invalid",
  "d07_analysis_config_mutex": "Global\\HuntressBR07_000",
  "d07_analysis_config_url": "https://node-000.day07.example.invalid/api/BR07-000",
  "d07_analysis_config_crc32_hex": "0xcf3ea232",
  "d07_analysis_hcfg_version": "1",
  "d07_analysis_xor_key_hex": "0x31",
  "d07_analysis_compression_methods": "[0,8]",
  "d08_artifact_sha256_1": "a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529",
  "d08_analysis_architecture": "x86-64",
  "d08_analysis_elf_class": "64",
  "d08_analysis_format": "ELF64",
  "d08_analysis_machine": "EM_X86_64",
  "d08_analysis_config_campaign": "BR08-000",
  "d08_analysis_config_domain": "node-000.day08.example.invalid",
  "d08_analysis_config_mutex": "Global\\HuntressBR08_000",
  "d08_analysis_config_url": "https://node-000.day08.example.invalid/api/BR08-000",
  "d08_analysis_config_crc32_hex": "0x6a033bfd",
  "d09_artifact_sha256_1": "5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad",
  "d09_analysis_architecture": "x86-64",
  "d09_analysis_format": "ELF64",
  "d09_analysis_machine": "EM_X86_64",
  "d09_analysis_config_campaign": "BR09-000",
  "d09_analysis_config_domain": "node-000.day09.example.invalid",
  "d09_analysis_config_mutex": "Global\\HuntressBR09_000",
  "d09_analysis_config_url": "https://node-000.day09.example.invalid/api/BR09-000",
  "d09_analysis_config_crc32_hex": "0x9614e1a8",
  "d09_analysis_hcfg_offset": "30696",
  "d10_artifact_sha256_1": "9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7",
  "d10_analysis_architecture": "x86-64",
  "d10_analysis_format": "ELF64",
  "d10_analysis_machine": "EM_X86_64",
  "d10_analysis_config_campaign": "BR10-000",
  "d10_analysis_config_domain": "node-000.day10.example.invalid",
  "d10_analysis_config_mutex": "Global\\HuntressBR10_000",
  "d10_analysis_config_url": "https://node-000.day10.example.invalid/api/BR10-000",
  "d10_analysis_config_crc32_hex": "0xceda03ad",
  "d10_analysis_has_hcfg_section": "true",
  "d11_artifact_sha256_1": "a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675",
  "d11_analysis_architecture": "x86-64",
  "d11_analysis_format": "ELF64",
  "d11_analysis_machine": "EM_X86_64",
  "d11_analysis_config_campaign": "BR11-000",
  "d11_analysis_config_domain": "node-000.day11.example.invalid",
  "d11_analysis_config_mutex": "Global\\HuntressBR11_000",
  "d11_analysis_config_url": "https://node-000.day11.example.invalid/api/BR11-000",
  "d11_analysis_config_crc32_hex": "0x03663005",
  "d11_analysis_hcfg_offset": "368272",
  "d12_artifact_sha256_1": "8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b",
  "d12_analysis_architecture": "x86-64",
  "d12_analysis_format": "elf",
  "d12_analysis_machine": "EM_X86_64",
  "d12_analysis_config_campaign": "BR12-000",
  "d12_analysis_config_domain": "node-000.day12.example.invalid",
  "d12_analysis_config_mutex": "Global\\HuntressBR12_000",
  "d12_analysis_config_url": "https://node-000.day12.example.invalid/api/BR12-000",
  "d12_analysis_config_crc32_hex": "0xe4fc81f8",
  "d12_analysis_hcfg_offset": "82928"
}
```


## Time Trial — ranked window expired; practice continuation completed

- **Challenge ID:** `binary-reverse-engineering-day-12-pascal-archive-stager/time_trial`
- **Ranked attempt:** `ebea868e-1bf4-433f-a5bd-5c54f484f3e2`; the legacy route started timed by default with an 80-second server deadline (`2026-10-23T06:40:12.520Z`). The artifact endpoint stalled during the ranked window, and the Game Master later confirmed that attempt as `expired`.
- **Practice attempt:** `7233f687-c4dc-40ef-9d23-93494a207241`; started after expiration with no deadline. Its assigned download was fetched from that attempt's status capability before submitting.
- **Artifact:** `evidence.zip`; SHA-256 `7dff5db96dee39f0b86ab7ef45d9160a103358a31fbf15c0b777d7818b0439b8` (31,930,795 bytes). The archive password was `infected`. The practice attempt reported the same hash and the downloaded bytes matched it.
- **Analysis:** On REMnux, extracted the archive without running any specimen. Reused a static parser for ELF/PE metadata, Java class constants and ZIP methods, and HCFG structure decoding. The parser matched every one of the 120 current answer IDs, derived SHA-256 from each exact archive member, and verified HCFG CRC32 before reading the JSON. The fresh variant changed member contents; for example the extracted configs now include campaigns `d02 BR02-000, d03 BR03-001, d04 BR04-006, d05 BR05-007, d06 BR06-002, d07 BR07-005, d08 BR08-000, d09 BR09-003, d10 BR10-007, d11 BR11-001, d12 BR12-004.
- **Submission:** The Game Master initially rejected submission with `download_required`; after downloading the practice attempt's own artifact capability and confirming its SHA-256, resubmission returned `CORRECT`. A follow-up status check confirmed the practice attempt as `CORRECT` with no scoring-pending status.
- **Flag:** `5663d4fec2f95bd8aff958bade6b3718`

### Extracted member hashes

| Member group | SHA-256 |
| --- | --- |
| `d01--member 1` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--member 1` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--member 1` | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| `d03--member 2` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--member 1` | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` |
| `d05--member 1` | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| `d06--member 1` | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| `d07--member 1` | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| `d08--member 1` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--member 1` | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| `d10--member 1` | `78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae` |
| `d11--member 1` | `e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6` |
| `d12--member 1` | `b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a` |


### Submitted answer map

```json
{
  "d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "d01_analysis_elf_class": "ELF64",
  "d01_analysis_machine": "EM_X86_64",
  "d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "d01_analysis_elf_type": "ET_EXEC",
  "d01_analysis_endianness": "ELFDATA2LSB",
  "d01_analysis_entry_point": "0x401040",
  "d01_analysis_has_symtab": "true",
  "d02_artifact_sha256_1": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
  "d02_analysis_format": "ELF64",
  "d02_analysis_config_campaign": "BR02-000",
  "d02_analysis_config_domain": "node-000.day02.example.invalid",
  "d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "d02_analysis_config_crc32_hex": "0x6149aa00",
  "d02_analysis_xor_key_hex": "0x31",
  "d02_analysis_has_cpp_typeinfo": "true",
  "d02_analysis_has_cpp_vtable": "true",
  "d03_artifact_sha256_1": "74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9",
  "d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "d03_analysis_format": "PE32_CLR",
  "d03_analysis_machine": "IMAGE_FILE_MACHINE_I386",
  "d03_analysis_metadata_version": "v4.0.30319",
  "d03_analysis_config_campaign": "BR03-001",
  "d03_analysis_config_domain": "node-001.day03.example.invalid",
  "d03_analysis_config_mutex": "Global\\HuntressBR03_001",
  "d03_analysis_config_url": "https://node-001.day03.example.invalid/api/BR03-001",
  "d03_analysis_config_crc32_hex": "0x55fbb381",
  "d04_artifact_sha256_1": "812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6",
  "d04_analysis_architecture": "x86-64",
  "d04_analysis_format": "ELF64",
  "d04_analysis_config_campaign": "BR04-006",
  "d04_analysis_config_domain": "node-006.day04.example.invalid",
  "d04_analysis_config_mutex": "Global\\HuntressBR04_006",
  "d04_analysis_config_url": "https://node-006.day04.example.invalid/api/BR04-006",
  "d04_analysis_config_crc32_hex": "0xdae5ff06",
  "d04_analysis_hcfg_version": "1",
  "d04_analysis_xor_key_hex": "0x57",
  "d05_artifact_sha256_1": "327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624",
  "d05_analysis_architecture": "x86-64",
  "d05_analysis_format": "ELF64",
  "d05_analysis_config_campaign": "BR05-007",
  "d05_analysis_config_domain": "node-007.day05.example.invalid",
  "d05_analysis_config_mutex": "Global\\HuntressBR05_007",
  "d05_analysis_config_url": "https://node-007.day05.example.invalid/api/BR05-007",
  "d05_analysis_config_crc32_hex": "0x4525249b",
  "d05_analysis_hcfg_version": "1",
  "d05_analysis_xor_key_hex": "0x68",
  "d06_artifact_sha256_1": "1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19",
  "d06_analysis_format": "JAR",
  "d06_analysis_config_campaign": "BR06-002",
  "d06_analysis_config_domain": "node-002.day06.example.invalid",
  "d06_analysis_config_mutex": "Global\\HuntressBR06_002",
  "d06_analysis_config_url": "https://node-002.day06.example.invalid/api/BR06-002",
  "d06_analysis_config_crc32_hex": "0x81273e0c",
  "d06_analysis_hcfg_version": "1",
  "d06_analysis_xor_key_hex": "0x73",
  "d06_analysis_compression_methods": "[0,8]",
  "d07_artifact_sha256_1": "a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f",
  "d07_analysis_format": "JAR",
  "d07_analysis_config_campaign": "BR07-005",
  "d07_analysis_config_domain": "node-005.day07.example.invalid",
  "d07_analysis_config_mutex": "Global\\HuntressBR07_005",
  "d07_analysis_config_url": "https://node-005.day07.example.invalid/api/BR07-005",
  "d07_analysis_config_crc32_hex": "0x9610b2b7",
  "d07_analysis_hcfg_version": "1",
  "d07_analysis_xor_key_hex": "0x36",
  "d07_analysis_compression_methods": "[0,8]",
  "d08_artifact_sha256_1": "a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529",
  "d08_analysis_architecture": "x86-64",
  "d08_analysis_elf_class": "64",
  "d08_analysis_format": "ELF64",
  "d08_analysis_machine": "EM_X86_64",
  "d08_analysis_config_campaign": "BR08-000",
  "d08_analysis_config_domain": "node-000.day08.example.invalid",
  "d08_analysis_config_mutex": "Global\\HuntressBR08_000",
  "d08_analysis_config_url": "https://node-000.day08.example.invalid/api/BR08-000",
  "d08_analysis_config_crc32_hex": "0x6a033bfd",
  "d09_artifact_sha256_1": "d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d",
  "d09_analysis_architecture": "x86-64",
  "d09_analysis_format": "ELF64",
  "d09_analysis_machine": "EM_X86_64",
  "d09_analysis_config_campaign": "BR09-003",
  "d09_analysis_config_domain": "node-003.day09.example.invalid",
  "d09_analysis_config_mutex": "Global\\HuntressBR09_003",
  "d09_analysis_config_url": "https://node-003.day09.example.invalid/api/BR09-003",
  "d09_analysis_config_crc32_hex": "0xa10eee2b",
  "d09_analysis_hcfg_offset": "30696",
  "d10_artifact_sha256_1": "78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae",
  "d10_analysis_architecture": "x86-64",
  "d10_analysis_format": "ELF64",
  "d10_analysis_machine": "EM_X86_64",
  "d10_analysis_config_campaign": "BR10-007",
  "d10_analysis_config_domain": "node-007.day10.example.invalid",
  "d10_analysis_config_mutex": "Global\\HuntressBR10_007",
  "d10_analysis_config_url": "https://node-007.day10.example.invalid/api/BR10-007",
  "d10_analysis_config_crc32_hex": "0x04c8e415",
  "d10_analysis_has_hcfg_section": "true",
  "d11_artifact_sha256_1": "e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6",
  "d11_analysis_architecture": "x86-64",
  "d11_analysis_format": "ELF64",
  "d11_analysis_machine": "EM_X86_64",
  "d11_analysis_config_campaign": "BR11-001",
  "d11_analysis_config_domain": "node-001.day11.example.invalid",
  "d11_analysis_config_mutex": "Global\\HuntressBR11_001",
  "d11_analysis_config_url": "https://node-001.day11.example.invalid/api/BR11-001",
  "d11_analysis_config_crc32_hex": "0xa740c8bb",
  "d11_analysis_hcfg_offset": "368272",
  "d12_artifact_sha256_1": "b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a",
  "d12_analysis_architecture": "x86-64",
  "d12_analysis_format": "elf",
  "d12_analysis_machine": "EM_X86_64",
  "d12_analysis_config_campaign": "BR12-004",
  "d12_analysis_config_domain": "node-004.day12.example.invalid",
  "d12_analysis_config_mutex": "Global\\HuntressBR12_004",
  "d12_analysis_config_url": "https://node-004.day12.example.invalid/api/BR12-004",
  "d12_analysis_config_crc32_hex": "0x19f469c3",
  "d12_analysis_hcfg_offset": "82928"
}
```


## Mastery — three-set bundle

- **Challenge ID:** `binary-reverse-engineering-day-12-pascal-archive-stager/mastery`
- **Mode and timer:** Mastery; the legacy route started timed by default with a 200-second deadline (`2026-10-23T06:48:49.850Z). The attempt completed before its deadline.
- **Attempt:** `0ccb2e32-c534-4752-b254-90112158cc3c`
- **Assignment:** Three evidence archives, 360 questions total (120 per delivery). Each response key used the exact `set1.`, `set2.`, or `set3.` answer ID returned by the Game Master.
- **Password:** `infected`.
- **Analysis:** Downloaded each attempt-specific capability and verified all three archive hashes before extraction. Extracted on REMnux and reused the static ELF/PE/JAR/HCFG parser per set. For every archive, the parser produced all 120 corresponding values; it decoded HCFG records only after checking bounds and CRC32. No specimens were executed. The archive variants produced distinct member hashes and configuration records; campaign IDs were: **Set 1:** BR02-000, BR03-001, BR04-006, BR05-007, BR06-002, BR07-005, BR08-000, BR09-003, BR10-007, BR11-001, BR12-004. **Set 2:** BR02-000, BR03-000, BR04-002, BR05-002, BR06-007, BR07-004, BR08-001, BR09-006, BR10-001, BR11-000, BR12-005. **Set 3:** BR02-001, BR03-007, BR04-007, BR05-005, BR06-004, BR07-003, BR08-002, BR09-001, BR10-004, BR11-007, BR12-006. 
- **Submission:** Exact 360 answer IDs matched the active attempt; Game Master returned `CORRECT`. A follow-up status check confirmed the same attempt as `CORRECT`, with no scoring-pending status.
- **Flag:** `0858604544140477d8a5b2b9854cc003`

### Evidence archive hashes

| Set | Archive | Size | SHA-256 |
| --- | --- | ---: | --- |
| 1 | `evidence.zip` | 31930795 bytes | `7dff5db96dee39f0b86ab7ef45d9160a103358a31fbf15c0b777d7818b0439b8` |
| 2 | `evidence.zip` | 32037635 bytes | `d783591d6ee56a6858698b68ea92581f5358cfb5e079fe9495d28321086451e5` |
| 3 | `evidence.zip` | 31930794 bytes | `918161e4e528dd88b9e6a4e61098009ee74c1d96f80ff9c23d0b865d8060f31a` |


### Extracted member hashes

| Set | Member group | SHA-256 |
| --- | --- | --- |
| 1 | `d01-- member 1` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| 1 | `d02-- member 1` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| 1 | `d03-- member 1` | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| 1 | `d03-- member 2` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 1 | `d04-- member 1` | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` |
| 1 | `d05-- member 1` | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| 1 | `d06-- member 1` | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| 1 | `d07-- member 1` | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| 1 | `d08-- member 1` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| 1 | `d09-- member 1` | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| 1 | `d10-- member 1` | `78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae` |
| 1 | `d11-- member 1` | `e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6` |
| 1 | `d12-- member 1` | `b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a` |
| 2 | `d01-- member 1` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| 2 | `d02-- member 1` | `9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f` |
| 2 | `d03-- member 1` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| 2 | `d03-- member 2` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 2 | `d04-- member 1` | `bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97` |
| 2 | `d05-- member 1` | `2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33` |
| 2 | `d06-- member 1` | `8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f` |
| 2 | `d07-- member 1` | `11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8` |
| 2 | `d08-- member 1` | `a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097` |
| 2 | `d09-- member 1` | `31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c` |
| 2 | `d10-- member 1` | `a449342f396af68e11825293fa1a678651251fbf1b9cd7bdb8cb5ab303d98071` |
| 2 | `d11-- member 1` | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| 2 | `d12-- member 1` | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| 3 | `d01-- member 1` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| 3 | `d02-- member 1` | `a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2` |
| 3 | `d03-- member 1` | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| 3 | `d03-- member 2` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 3 | `d04-- member 1` | `173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5` |
| 3 | `d05-- member 1` | `359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c` |
| 3 | `d06-- member 1` | `e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1` |
| 3 | `d07-- member 1` | `7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c` |
| 3 | `d08-- member 1` | `f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48` |
| 3 | `d09-- member 1` | `adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69` |
| 3 | `d10-- member 1` | `bc5ae6af7c14106ed6652574359285d97590e1d232a7b8be6151d6e915e4face` |
| 3 | `d11-- member 1` | `ef6e36955793c0d41966e2727c80417c136cefc9f18b98285917ace224455617` |
| 3 | `d12-- member 1` | `fd116e0e351a96ca5c2071249e9c6cc684bd8859fde8e71ea201b1bc4f7c815a` |


### Submitted answer map

```json
{
  "set1.d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "set1.d01_analysis_elf_class": "ELF64",
  "set1.d01_analysis_machine": "EM_X86_64",
  "set1.d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "set1.d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "set1.d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "set1.d01_analysis_elf_type": "ET_EXEC",
  "set1.d01_analysis_endianness": "ELFDATA2LSB",
  "set1.d01_analysis_entry_point": "0x401040",
  "set1.d01_analysis_has_symtab": "true",
  "set1.d02_artifact_sha256_1": "e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7",
  "set1.d02_analysis_format": "ELF64",
  "set1.d02_analysis_config_campaign": "BR02-000",
  "set1.d02_analysis_config_domain": "node-000.day02.example.invalid",
  "set1.d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "set1.d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "set1.d02_analysis_config_crc32_hex": "0x6149aa00",
  "set1.d02_analysis_xor_key_hex": "0x31",
  "set1.d02_analysis_has_cpp_typeinfo": "true",
  "set1.d02_analysis_has_cpp_vtable": "true",
  "set1.d03_artifact_sha256_1": "74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9",
  "set1.d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "set1.d03_analysis_format": "PE32_CLR",
  "set1.d03_analysis_machine": "IMAGE_FILE_MACHINE_I386",
  "set1.d03_analysis_metadata_version": "v4.0.30319",
  "set1.d03_analysis_config_campaign": "BR03-001",
  "set1.d03_analysis_config_domain": "node-001.day03.example.invalid",
  "set1.d03_analysis_config_mutex": "Global\\HuntressBR03_001",
  "set1.d03_analysis_config_url": "https://node-001.day03.example.invalid/api/BR03-001",
  "set1.d03_analysis_config_crc32_hex": "0x55fbb381",
  "set1.d04_artifact_sha256_1": "812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6",
  "set1.d04_analysis_architecture": "x86-64",
  "set1.d04_analysis_format": "ELF64",
  "set1.d04_analysis_config_campaign": "BR04-006",
  "set1.d04_analysis_config_domain": "node-006.day04.example.invalid",
  "set1.d04_analysis_config_mutex": "Global\\HuntressBR04_006",
  "set1.d04_analysis_config_url": "https://node-006.day04.example.invalid/api/BR04-006",
  "set1.d04_analysis_config_crc32_hex": "0xdae5ff06",
  "set1.d04_analysis_hcfg_version": "1",
  "set1.d04_analysis_xor_key_hex": "0x57",
  "set1.d05_artifact_sha256_1": "327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624",
  "set1.d05_analysis_architecture": "x86-64",
  "set1.d05_analysis_format": "ELF64",
  "set1.d05_analysis_config_campaign": "BR05-007",
  "set1.d05_analysis_config_domain": "node-007.day05.example.invalid",
  "set1.d05_analysis_config_mutex": "Global\\HuntressBR05_007",
  "set1.d05_analysis_config_url": "https://node-007.day05.example.invalid/api/BR05-007",
  "set1.d05_analysis_config_crc32_hex": "0x4525249b",
  "set1.d05_analysis_hcfg_version": "1",
  "set1.d05_analysis_xor_key_hex": "0x68",
  "set1.d06_artifact_sha256_1": "1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19",
  "set1.d06_analysis_format": "JAR",
  "set1.d06_analysis_config_campaign": "BR06-002",
  "set1.d06_analysis_config_domain": "node-002.day06.example.invalid",
  "set1.d06_analysis_config_mutex": "Global\\HuntressBR06_002",
  "set1.d06_analysis_config_url": "https://node-002.day06.example.invalid/api/BR06-002",
  "set1.d06_analysis_config_crc32_hex": "0x81273e0c",
  "set1.d06_analysis_hcfg_version": "1",
  "set1.d06_analysis_xor_key_hex": "0x73",
  "set1.d06_analysis_compression_methods": "[0,8]",
  "set1.d07_artifact_sha256_1": "a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f",
  "set1.d07_analysis_format": "JAR",
  "set1.d07_analysis_config_campaign": "BR07-005",
  "set1.d07_analysis_config_domain": "node-005.day07.example.invalid",
  "set1.d07_analysis_config_mutex": "Global\\HuntressBR07_005",
  "set1.d07_analysis_config_url": "https://node-005.day07.example.invalid/api/BR07-005",
  "set1.d07_analysis_config_crc32_hex": "0x9610b2b7",
  "set1.d07_analysis_hcfg_version": "1",
  "set1.d07_analysis_xor_key_hex": "0x36",
  "set1.d07_analysis_compression_methods": "[0,8]",
  "set1.d08_artifact_sha256_1": "a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529",
  "set1.d08_analysis_architecture": "x86-64",
  "set1.d08_analysis_elf_class": "64",
  "set1.d08_analysis_format": "ELF64",
  "set1.d08_analysis_machine": "EM_X86_64",
  "set1.d08_analysis_config_campaign": "BR08-000",
  "set1.d08_analysis_config_domain": "node-000.day08.example.invalid",
  "set1.d08_analysis_config_mutex": "Global\\HuntressBR08_000",
  "set1.d08_analysis_config_url": "https://node-000.day08.example.invalid/api/BR08-000",
  "set1.d08_analysis_config_crc32_hex": "0x6a033bfd",
  "set1.d09_artifact_sha256_1": "d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d",
  "set1.d09_analysis_architecture": "x86-64",
  "set1.d09_analysis_format": "ELF64",
  "set1.d09_analysis_machine": "EM_X86_64",
  "set1.d09_analysis_config_campaign": "BR09-003",
  "set1.d09_analysis_config_domain": "node-003.day09.example.invalid",
  "set1.d09_analysis_config_mutex": "Global\\HuntressBR09_003",
  "set1.d09_analysis_config_url": "https://node-003.day09.example.invalid/api/BR09-003",
  "set1.d09_analysis_config_crc32_hex": "0xa10eee2b",
  "set1.d09_analysis_hcfg_offset": "30696",
  "set1.d10_artifact_sha256_1": "78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae",
  "set1.d10_analysis_architecture": "x86-64",
  "set1.d10_analysis_format": "ELF64",
  "set1.d10_analysis_machine": "EM_X86_64",
  "set1.d10_analysis_config_campaign": "BR10-007",
  "set1.d10_analysis_config_domain": "node-007.day10.example.invalid",
  "set1.d10_analysis_config_mutex": "Global\\HuntressBR10_007",
  "set1.d10_analysis_config_url": "https://node-007.day10.example.invalid/api/BR10-007",
  "set1.d10_analysis_config_crc32_hex": "0x04c8e415",
  "set1.d10_analysis_has_hcfg_section": "true",
  "set1.d11_artifact_sha256_1": "e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6",
  "set1.d11_analysis_architecture": "x86-64",
  "set1.d11_analysis_format": "ELF64",
  "set1.d11_analysis_machine": "EM_X86_64",
  "set1.d11_analysis_config_campaign": "BR11-001",
  "set1.d11_analysis_config_domain": "node-001.day11.example.invalid",
  "set1.d11_analysis_config_mutex": "Global\\HuntressBR11_001",
  "set1.d11_analysis_config_url": "https://node-001.day11.example.invalid/api/BR11-001",
  "set1.d11_analysis_config_crc32_hex": "0xa740c8bb",
  "set1.d11_analysis_hcfg_offset": "368272",
  "set1.d12_artifact_sha256_1": "b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a",
  "set1.d12_analysis_architecture": "x86-64",
  "set1.d12_analysis_format": "elf",
  "set1.d12_analysis_machine": "EM_X86_64",
  "set1.d12_analysis_config_campaign": "BR12-004",
  "set1.d12_analysis_config_domain": "node-004.day12.example.invalid",
  "set1.d12_analysis_config_mutex": "Global\\HuntressBR12_004",
  "set1.d12_analysis_config_url": "https://node-004.day12.example.invalid/api/BR12-004",
  "set1.d12_analysis_config_crc32_hex": "0x19f469c3",
  "set1.d12_analysis_hcfg_offset": "82928",
  "set2.d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "set2.d01_analysis_elf_class": "ELF64",
  "set2.d01_analysis_machine": "EM_X86_64",
  "set2.d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "set2.d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "set2.d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "set2.d01_analysis_elf_type": "ET_EXEC",
  "set2.d01_analysis_endianness": "ELFDATA2LSB",
  "set2.d01_analysis_entry_point": "0x401040",
  "set2.d01_analysis_has_symtab": "true",
  "set2.d02_artifact_sha256_1": "9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f",
  "set2.d02_analysis_format": "PE32+",
  "set2.d02_analysis_config_campaign": "BR02-000",
  "set2.d02_analysis_config_domain": "node-000.day02.example.invalid",
  "set2.d02_analysis_config_mutex": "Global\\HuntressBR02_000",
  "set2.d02_analysis_config_url": "https://node-000.day02.example.invalid/api/BR02-000",
  "set2.d02_analysis_config_crc32_hex": "0x6149aa00",
  "set2.d02_analysis_xor_key_hex": "0x31",
  "set2.d02_analysis_has_cpp_typeinfo": "true",
  "set2.d02_analysis_has_cpp_vtable": "true",
  "set2.d03_artifact_sha256_1": "a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d",
  "set2.d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "set2.d03_analysis_format": "PE32_CLR",
  "set2.d03_analysis_machine": "IMAGE_FILE_MACHINE_I386",
  "set2.d03_analysis_metadata_version": "v4.0.30319",
  "set2.d03_analysis_config_campaign": "BR03-000",
  "set2.d03_analysis_config_domain": "node-000.day03.example.invalid",
  "set2.d03_analysis_config_mutex": "Global\\HuntressBR03_000",
  "set2.d03_analysis_config_url": "https://node-000.day03.example.invalid/api/BR03-000",
  "set2.d03_analysis_config_crc32_hex": "0xcb6cf23f",
  "set2.d04_artifact_sha256_1": "bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97",
  "set2.d04_analysis_architecture": "x86-64",
  "set2.d04_analysis_format": "PE32+",
  "set2.d04_analysis_config_campaign": "BR04-002",
  "set2.d04_analysis_config_domain": "node-002.day04.example.invalid",
  "set2.d04_analysis_config_mutex": "Global\\HuntressBR04_002",
  "set2.d04_analysis_config_url": "https://node-002.day04.example.invalid/api/BR04-002",
  "set2.d04_analysis_config_crc32_hex": "0xcd2bf33d",
  "set2.d04_analysis_hcfg_version": "1",
  "set2.d04_analysis_xor_key_hex": "0x53",
  "set2.d05_artifact_sha256_1": "2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33",
  "set2.d05_analysis_architecture": "x86-64",
  "set2.d05_analysis_format": "ELF64",
  "set2.d05_analysis_config_campaign": "BR05-002",
  "set2.d05_analysis_config_domain": "node-002.day05.example.invalid",
  "set2.d05_analysis_config_mutex": "Global\\HuntressBR05_002",
  "set2.d05_analysis_config_url": "https://node-002.day05.example.invalid/api/BR05-002",
  "set2.d05_analysis_config_crc32_hex": "0x1c0b341e",
  "set2.d05_analysis_hcfg_version": "1",
  "set2.d05_analysis_xor_key_hex": "0x63",
  "set2.d06_artifact_sha256_1": "8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f",
  "set2.d06_analysis_format": "JAR",
  "set2.d06_analysis_config_campaign": "BR06-007",
  "set2.d06_analysis_config_domain": "node-007.day06.example.invalid",
  "set2.d06_analysis_config_mutex": "Global\\HuntressBR06_007",
  "set2.d06_analysis_config_url": "https://node-007.day06.example.invalid/api/BR06-007",
  "set2.d06_analysis_config_crc32_hex": "0xd8092e89",
  "set2.d06_analysis_hcfg_version": "1",
  "set2.d06_analysis_xor_key_hex": "0x78",
  "set2.d06_analysis_compression_methods": "[0,8]",
  "set2.d07_artifact_sha256_1": "11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8",
  "set2.d07_analysis_format": "JAR",
  "set2.d07_analysis_config_campaign": "BR07-004",
  "set2.d07_analysis_config_domain": "node-004.day07.example.invalid",
  "set2.d07_analysis_config_mutex": "Global\\HuntressBR07_004",
  "set2.d07_analysis_config_url": "https://node-004.day07.example.invalid/api/BR07-004",
  "set2.d07_analysis_config_crc32_hex": "0x32364a09",
  "set2.d07_analysis_hcfg_version": "1",
  "set2.d07_analysis_xor_key_hex": "0x35",
  "set2.d07_analysis_compression_methods": "[0,8]",
  "set2.d08_artifact_sha256_1": "a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097",
  "set2.d08_analysis_architecture": "x86-64",
  "set2.d08_analysis_elf_class": "64",
  "set2.d08_analysis_format": "ELF64",
  "set2.d08_analysis_machine": "EM_X86_64",
  "set2.d08_analysis_config_campaign": "BR08-001",
  "set2.d08_analysis_config_domain": "node-001.day08.example.invalid",
  "set2.d08_analysis_config_mutex": "Global\\HuntressBR08_001",
  "set2.d08_analysis_config_url": "https://node-001.day08.example.invalid/api/BR08-001",
  "set2.d08_analysis_config_crc32_hex": "0xce25c343",
  "set2.d09_artifact_sha256_1": "31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c",
  "set2.d09_analysis_architecture": "x86-64",
  "set2.d09_analysis_format": "ELF64",
  "set2.d09_analysis_machine": "EM_X86_64",
  "set2.d09_analysis_config_campaign": "BR09-006",
  "set2.d09_analysis_config_domain": "node-006.day09.example.invalid",
  "set2.d09_analysis_config_mutex": "Global\\HuntressBR09_006",
  "set2.d09_analysis_config_url": "https://node-006.day09.example.invalid/api/BR09-006",
  "set2.d09_analysis_config_crc32_hex": "0xf820feae",
  "set2.d09_analysis_hcfg_offset": "30696",
  "set2.d10_artifact_sha256_1": "a449342f396af68e11825293fa1a678651251fbf1b9cd7bdb8cb5ab303d98071",
  "set2.d10_analysis_architecture": "x86-64",
  "set2.d10_analysis_format": "PE32+",
  "set2.d10_analysis_machine": "IMAGE_FILE_MACHINE_AMD64",
  "set2.d10_analysis_config_campaign": "BR10-001",
  "set2.d10_analysis_config_domain": "node-001.day10.example.invalid",
  "set2.d10_analysis_config_mutex": "Global\\HuntressBR10_001",
  "set2.d10_analysis_config_url": "https://node-001.day10.example.invalid/api/BR10-001",
  "set2.d10_analysis_config_crc32_hex": "0x6afcfb13",
  "set2.d10_analysis_has_hcfg_section": "true",
  "set2.d11_artifact_sha256_1": "a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675",
  "set2.d11_analysis_architecture": "x86-64",
  "set2.d11_analysis_format": "ELF64",
  "set2.d11_analysis_machine": "EM_X86_64",
  "set2.d11_analysis_config_campaign": "BR11-000",
  "set2.d11_analysis_config_domain": "node-000.day11.example.invalid",
  "set2.d11_analysis_config_mutex": "Global\\HuntressBR11_000",
  "set2.d11_analysis_config_url": "https://node-000.day11.example.invalid/api/BR11-000",
  "set2.d11_analysis_config_crc32_hex": "0x03663005",
  "set2.d11_analysis_hcfg_offset": "368272",
  "set2.d12_artifact_sha256_1": "3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde",
  "set2.d12_analysis_architecture": "x86-64",
  "set2.d12_analysis_format": "elf",
  "set2.d12_analysis_machine": "EM_X86_64",
  "set2.d12_analysis_config_campaign": "BR12-005",
  "set2.d12_analysis_config_domain": "node-005.day12.example.invalid",
  "set2.d12_analysis_config_mutex": "Global\\HuntressBR12_005",
  "set2.d12_analysis_config_url": "https://node-005.day12.example.invalid/api/BR12-005",
  "set2.d12_analysis_config_crc32_hex": "0xbdd2917d",
  "set2.d12_analysis_hcfg_offset": "82928",
  "set3.d01_artifact_sha256_1": "a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b",
  "set3.d01_analysis_elf_class": "ELF64",
  "set3.d01_analysis_machine": "EM_X86_64",
  "set3.d01_analysis_section_names": "[\"\",\".interp\",\".note.gnu.property\",\".note.ABI-tag\",\".hash\",\".gnu.hash\",\".dynsym\",\".dynstr\",\".gnu.version\",\".gnu.version_r\",\".rela.dyn\",\".init\",\".text\",\".fini\",\".rodata\",\".huntress\",\".eh_frame_hdr\",\".eh_frame\",\".init_array\",\".fini_array\",\".dynamic\",\".got\",\".got.plt\",\".data\",\".bss\",\".symtab\",\".strtab\",\".shstrtab\"]",
  "set3.d01_analysis_symbols": "[\"crt1.o\",\"__abi_tag\",\"variant-000.c\",\"marker\",\"crtstuff.c\",\"deregister_tm_clones\",\"register_tm_clones\",\"__do_global_dtors_aux\",\"completed.0\",\"__do_global_dtors_aux_fini_array_entry\",\"frame_dummy\",\"__frame_dummy_init_array_entry\",\"crtstuff.c\",\"__FRAME_END__\",\"_DYNAMIC\",\"__GNU_EH_FRAME_HDR\",\"_GLOBAL_OFFSET_TABLE_\",\"__libc_start_main@GLIBC_2.34\",\"data_start\",\"_edata\",\"_fini\",\"__data_start\",\"__gmon_start__\",\"__dso_handle\",\"_IO_stdin_used\",\"recover_code\",\"_end\",\"_dl_relocate_static_pie\",\"_start\",\"__bss_start\",\"main\",\"__TMC_END__\",\"_init\"]",
  "set3.d01_analysis_disassembly": "[\"mov eax,0x1fa4\",\"ret\"]",
  "set3.d01_analysis_elf_type": "ET_EXEC",
  "set3.d01_analysis_endianness": "ELFDATA2LSB",
  "set3.d01_analysis_entry_point": "0x401040",
  "set3.d01_analysis_has_symtab": "true",
  "set3.d02_artifact_sha256_1": "a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2",
  "set3.d02_analysis_format": "ELF64",
  "set3.d02_analysis_config_campaign": "BR02-001",
  "set3.d02_analysis_config_domain": "node-001.day02.example.invalid",
  "set3.d02_analysis_config_mutex": "Global\\HuntressBR02_001",
  "set3.d02_analysis_config_url": "https://node-001.day02.example.invalid/api/BR02-001",
  "set3.d02_analysis_config_crc32_hex": "0xffdeebbe",
  "set3.d02_analysis_xor_key_hex": "0x32",
  "set3.d02_analysis_has_cpp_typeinfo": "true",
  "set3.d02_analysis_has_cpp_vtable": "true",
  "set3.d03_artifact_sha256_1": "14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef",
  "set3.d03_artifact_sha256_2": "d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3",
  "set3.d03_analysis_format": "PE32_CLR",
  "set3.d03_analysis_machine": "IMAGE_FILE_MACHINE_I386",
  "set3.d03_analysis_metadata_version": "v4.0.30319",
  "set3.d03_analysis_config_campaign": "BR03-007",
  "set3.d03_analysis_config_domain": "node-007.day03.example.invalid",
  "set3.d03_analysis_config_mutex": "Global\\HuntressBR03_007",
  "set3.d03_analysis_config_url": "https://node-007.day03.example.invalid/api/BR03-007",
  "set3.d03_analysis_config_crc32_hex": "0xa46a3a87",
  "set3.d04_artifact_sha256_1": "173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5",
  "set3.d04_analysis_architecture": "x86-64",
  "set3.d04_analysis_format": "ELF64",
  "set3.d04_analysis_config_campaign": "BR04-007",
  "set3.d04_analysis_config_domain": "node-007.day04.example.invalid",
  "set3.d04_analysis_config_mutex": "Global\\HuntressBR04_007",
  "set3.d04_analysis_config_url": "https://node-007.day04.example.invalid/api/BR04-007",
  "set3.d04_analysis_config_crc32_hex": "0x4472beb8",
  "set3.d04_analysis_hcfg_version": "1",
  "set3.d04_analysis_xor_key_hex": "0x58",
  "set3.d05_artifact_sha256_1": "359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c",
  "set3.d05_analysis_architecture": "x86-64",
  "set3.d05_analysis_format": "ELF64",
  "set3.d05_analysis_config_campaign": "BR05-005",
  "set3.d05_analysis_config_domain": "node-005.day05.example.invalid",
  "set3.d05_analysis_config_mutex": "Global\\HuntressBR05_005",
  "set3.d05_analysis_config_url": "https://node-005.day05.example.invalid/api/BR05-005",
  "set3.d05_analysis_config_crc32_hex": "0xd619d3a6",
  "set3.d05_analysis_hcfg_version": "1",
  "set3.d05_analysis_xor_key_hex": "0x66",
  "set3.d06_artifact_sha256_1": "e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1",
  "set3.d06_analysis_format": "JAR",
  "set3.d06_analysis_config_campaign": "BR06-004",
  "set3.d06_analysis_config_domain": "node-004.day06.example.invalid",
  "set3.d06_analysis_config_mutex": "Global\\HuntressBR06_004",
  "set3.d06_analysis_config_url": "https://node-004.day06.example.invalid/api/BR06-004",
  "set3.d06_analysis_config_crc32_hex": "0xef13210a",
  "set3.d06_analysis_hcfg_version": "1",
  "set3.d06_analysis_xor_key_hex": "0x75",
  "set3.d06_analysis_compression_methods": "[0,8]",
  "set3.d07_artifact_sha256_1": "7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c",
  "set3.d07_analysis_format": "JAR",
  "set3.d07_analysis_config_campaign": "BR07-003",
  "set3.d07_analysis_config_domain": "node-003.day07.example.invalid",
  "set3.d07_analysis_config_mutex": "Global\\HuntressBR07_003",
  "set3.d07_analysis_config_url": "https://node-003.day07.example.invalid/api/BR07-003",
  "set3.d07_analysis_config_crc32_hex": "0xf824adb1",
  "set3.d07_analysis_hcfg_version": "1",
  "set3.d07_analysis_xor_key_hex": "0x34",
  "set3.d07_analysis_compression_methods": "[0,8]",
  "set3.d08_artifact_sha256_1": "f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48",
  "set3.d08_analysis_architecture": "x86-64",
  "set3.d08_analysis_elf_class": "64",
  "set3.d08_analysis_format": "ELF64",
  "set3.d08_analysis_machine": "EM_X86_64",
  "set3.d08_analysis_config_campaign": "BR08-002",
  "set3.d08_analysis_config_domain": "node-002.day08.example.invalid",
  "set3.d08_analysis_config_mutex": "Global\\HuntressBR08_002",
  "set3.d08_analysis_config_url": "https://node-002.day08.example.invalid/api/BR08-002",
  "set3.d08_analysis_config_crc32_hex": "0xf93fccc0",
  "set3.d09_artifact_sha256_1": "adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69",
  "set3.d09_analysis_architecture": "x86-64",
  "set3.d09_analysis_format": "ELF64",
  "set3.d09_analysis_machine": "EM_X86_64",
  "set3.d09_analysis_config_campaign": "BR09-001",
  "set3.d09_analysis_config_domain": "node-001.day09.example.invalid",
  "set3.d09_analysis_config_mutex": "Global\\HuntressBR09_001",
  "set3.d09_analysis_config_url": "https://node-001.day09.example.invalid/api/BR09-001",
  "set3.d09_analysis_config_crc32_hex": "0x32321916",
  "set3.d09_analysis_hcfg_offset": "30696",
  "set3.d10_artifact_sha256_1": "bc5ae6af7c14106ed6652574359285d97590e1d232a7b8be6151d6e915e4face",
  "set3.d10_analysis_architecture": "x86-64",
  "set3.d10_analysis_format": "ELF64",
  "set3.d10_analysis_machine": "EM_X86_64",
  "set3.d10_analysis_config_campaign": "BR10-004",
  "set3.d10_analysis_config_domain": "node-004.day10.example.invalid",
  "set3.d10_analysis_config_mutex": "Global\\HuntressBR10_004",
  "set3.d10_analysis_config_url": "https://node-004.day10.example.invalid/api/BR10-004",
  "set3.d10_analysis_config_crc32_hex": "0x33d2eb96",
  "set3.d10_analysis_has_hcfg_section": "true",
  "set3.d11_artifact_sha256_1": "ef6e36955793c0d41966e2727c80417c136cefc9f18b98285917ace224455617",
  "set3.d11_analysis_architecture": "x86-64",
  "set3.d11_analysis_format": "ELF64",
  "set3.d11_analysis_machine": "EM_X86_64",
  "set3.d11_analysis_config_campaign": "BR11-007",
  "set3.d11_analysis_config_domain": "node-007.day11.example.invalid",
  "set3.d11_analysis_config_mutex": "Global\\HuntressBR11_007",
  "set3.d11_analysis_config_url": "https://node-007.day11.example.invalid/api/BR11-007",
  "set3.d11_analysis_config_crc32_hex": "0xc974d7bd",
  "set3.d11_analysis_hcfg_offset": "368272",
  "set3.d12_artifact_sha256_1": "fd116e0e351a96ca5c2071249e9c6cc684bd8859fde8e71ea201b1bc4f7c815a",
  "set3.d12_analysis_architecture": "x86-64",
  "set3.d12_analysis_format": "elf",
  "set3.d12_analysis_machine": "EM_X86_64",
  "set3.d12_analysis_config_campaign": "BR12-006",
  "set3.d12_analysis_config_domain": "node-006.day12.example.invalid",
  "set3.d12_analysis_config_mutex": "Global\\HuntressBR12_006",
  "set3.d12_analysis_config_url": "https://node-006.day12.example.invalid/api/BR12-006",
  "set3.d12_analysis_config_crc32_hex": "0x8ac89efe",
  "set3.d12_analysis_hcfg_offset": "82928"
}
```
