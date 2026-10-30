# Table Manners — solution write-up

This write-up records the **Single Solve** for Table Manners (challenge ID `binary-reverse-engineering-day-03-managed-configuration`). The set contained 24 findings drawn from three executable samples and their metadata. The Game Master confirmed the submission with `CORRECT`.

## Challenge and artifact

The challenge prompt was:

> A .NET binary is a database wearing a trench coat. Read the CLI metadata tables — methods, strings, signatures — and find where the configuration is stashed. `ilspycmd` and `strings` are your friends.

This was an untimed Single Solve with no deadline. The assigned `evidence.zip` had SHA-256:

`2abb2511a2f71414bd3a2f18074f5701e8c3f5be78f1fecdd9ae7c6cdbaeec5c`

The archive password published for the challenge was `infected`. Its four encrypted members, in central-directory order, were:

| Member | Purpose | SHA-256 |
| --- | --- | --- |
| `d01--sample.elf` | Day 1 ELF metadata and `recover_code` disassembly | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | Day 2 container identification and `.hcfg` configuration | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | Day 3 managed PE metadata and embedded HCFG configuration | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | Day 3 runtime support file; included in the requested second Day 3 member hash | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

## Method

I downloaded the assigned archive through the authenticated Game Master connection and checked its SHA-256 before analysis. Python's standard `zipfile` module could not extract the archive's compression method, so I used `7z` with the published password. I then calculated SHA-256 over each extracted member.

For the Day 1 file, `readelf` identified the ELF header and section table. I read the `.symtab` entries in table order, preserving nonempty names and duplicates, and disassembled the `recover_code` symbol with `objdump`.

For Day 2, I used the ELF section table to locate `.hcfg` and read the record beginning at byte zero of that section. The HCFG header provides a one-byte XOR key, payload length, and CRC-32. I XOR-decoded the payload, checked the CRC, and parsed the resulting JSON.

For Day 3, I read the PE/COFF machine value and optional-header format, found the CLR metadata root (`BSJB`) to recover its version string, and scanned the DLL for HCFG records. The one record with valid bounds and CRC-32 decoded to JSON.

## Findings submitted

### Day 1 ELF

- SHA-256: `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`
- Class: `ELF64`
- Machine: `x86-64` (ELF machine value 62)
- ELF type: `ET_EXEC`
- Byte order: `little endian`
- Section names, in section-header-table order:

  ```json
  ["", ".interp", ".note.gnu.property", ".note.ABI-tag", ".hash", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".init", ".text", ".fini", ".rodata", ".huntress", ".eh_frame_hdr", ".eh_frame", ".init_array", ".fini_array", ".dynamic", ".got", ".got.plt", ".data", ".bss", ".symtab", ".strtab", ".shstrtab"]
  ```

- Nonempty `.symtab` names, in entry order:

  ```json
  ["crt1.o", "__abi_tag", "variant-000.c", "marker", "crtstuff.c", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "completed.0", "__do_global_dtors_aux_fini_array_entry", "frame_dummy", "__frame_dummy_init_array_entry", "crtstuff.c", "__FRAME_END__", "_DYNAMIC", "__GNU_EH_FRAME_HDR", "_GLOBAL_OFFSET_TABLE_", "__libc_start_main@GLIBC_2.34", "data_start", "_edata", "_fini", "__data_start", "__gmon_start__", "__dso_handle", "_IO_stdin_used", "recover_code", "_end", "_dl_relocate_static_pie", "_start", "__bss_start", "main", "__TMC_END__", "_init"]
  ```

- `recover_code` instructions, in execution order:

  ```json
  ["mov    $0x1fa4,%eax", "ret"]
  ```

### Day 2 ELF and HCFG

- SHA-256: `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7`
- Container: `ELF`
- HCFG version: `1`
- XOR key: `0x31`
- Decoded payload CRC-32: `0x6149aa00` (validated)
- Campaign: `BR02-000`
- Domain: `node-000.day02.example.invalid`
- Mutex: `Global\\HuntressBR02_000`
- URL: `https://node-000.day02.example.invalid/api/BR02-000`

### Day 3 managed PE and HCFG

- DLL SHA-256: `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d`
- Runtime configuration SHA-256: `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3`
- Format: `PE32_CLI`
- PE/COFF machine: `i386` (`0x014c`)
- CLR metadata version: `v4.0.30319`
- HCFG version: `1`
- XOR key: `0x41`
- Decoded payload CRC-32: `0xcb6cf23f` (validated)
- Campaign: `BR03-000`
- Domain: `node-000.day03.example.invalid`
- Mutex: `Global\\HuntressBR03_000`

## Submission result

I submitted all 24 fields using the exact answer IDs from the Game Master. The response was:

```text
CORRECT
```

The completion flag was `ed9a671161cc36b513b6944654fee64d`.

## Time Trial

The live Game Master route was timed by default and advertised a 50-second limit. I started the Time Trial, downloaded its assigned archive, verified the archive SHA-256 from the start response, extracted it with `7z` and the published password, and submitted the 24 requested findings under the exact answer IDs. The Game Master returned `CORRECT`; a follow-up status request also returned `CORRECT` for `time_trial`.

The Time Trial archive SHA-256 was:

`48695bdad8ae30b71e8e50c34b2b355d83d111317cbdf6db77f668aba5d3bdd3`

The timed variant's member hashes were:

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `f397fea32cc514940dad2f8e6b6258df0bbbe7e4eba2e4cecb185e74597df844` |
| `d02--sample.elf` | `018d4f5fe9eeb93de91d43101effb31e2da31e3606622da433653d35f333e6f5` |
| `d03--sample.dll` | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

The Day 2 `.hcfg` record decoded with key `0x36`; its CRC-32 was `0xe810e785` and validated. The submitted configuration values were:

- Campaign: `BR02-005`
- Domain: `node-005.day02.example.invalid`
- URL: `https://node-005.day02.example.invalid/api/BR02-005`
- Mutex: `Global\\HuntressBR02_005`

The Day 3 PE was `PE32_CLI`, with machine `i386` and CLR metadata version `v4.0.30319`. Its unique CRC-valid HCFG record decoded with key `0x48` and CRC-32 `0xa46a3a87`. The submitted configuration values were:

- Campaign: `BR03-007`
- Domain: `node-007.day03.example.invalid`
- Mutex: `Global\\HuntressBR03_007`

The Time Trial completion flag was `a439ad3195ec2ab86f90321dbf529a58`.

## Mastery

Mastery assigned two `evidence.zip` deliveries and required 48 answers, with `set1.` and `set2.` prefixes on the answer IDs. The route had one ranked variant and an 80-second deadline. That ranked attempt expired before the submission was accepted. With no fresh ranked variant remaining, I followed the Game Master's guidance and continued the same assignment in untimed practice mode. I downloaded both practice artifacts, verified their hashes, analyzed each set, and submitted all 48 answers. The Game Master returned `CORRECT`, and the mastery status check confirmed completion.

The two mastery archive hashes were:

- Delivery 1: `20827c1d49f9f1ff12d7618df7c76f7d9a6b5c277c039f85444b376beb12798c`
- Delivery 2: `f465f3185cd9ee4836a2516513eee2d81a5ecacaca07e7c01da58c32a93bb905`

### Set 1

- Day 1 ELF SHA-256: `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`
- Day 2 ELF SHA-256: `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7`
- Day 2 format: `ELF64`; HCFG key `0x31`; validated CRC-32 `0x6149aa00`
- Day 2 configuration: campaign `BR02-000`, domain `node-000.day02.example.invalid`, URL `https://node-000.day02.example.invalid/api/BR02-000`, mutex `Global\\HuntressBR02_000`
- Day 3 DLL SHA-256: `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9`
- Day 3 runtimeconfig SHA-256: `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3`
- Day 3 format and machine: `PE32_CLI`, `i386`; metadata version `v4.0.30319`
- Day 3 configuration: campaign `BR03-001`, domain `node-001.day03.example.invalid`, mutex `Global\\HuntressBR03_001`; HCFG key `0x42`; validated CRC-32 `0x55fbb381`

### Set 2

- Day 1 ELF SHA-256: `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`
- Day 2 PE SHA-256: `9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f`
- Day 2 format: `PE32+`; HCFG key `0x31`; validated CRC-32 `0x6149aa00`
- Day 2 configuration: campaign `BR02-000`, domain `node-000.day02.example.invalid`, URL `https://node-000.day02.example.invalid/api/BR02-000`, mutex `Global\\HuntressBR02_000`
- Day 3 DLL SHA-256: `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d`
- Day 3 runtimeconfig SHA-256: `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3`
- Day 3 format and machine: `PE32_CLI`, `i386`; metadata version `v4.0.30319`
- Day 3 configuration: campaign `BR03-000`, domain `node-000.day03.example.invalid`, mutex `Global\\HuntressBR03_000`; HCFG key `0x41`; validated CRC-32 `0xcb6cf23f`

The practice completion flag was `60a0bd81480b02a80ed420d98e296b3a`.
