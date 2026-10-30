# Go Fish — Single Solve write-up

This write-up records the Day 4 **Go Fish** Single Solve, challenge ID `binary-reverse-engineering-day-04-go-runtime-fingerprints`. The task covered metadata from ELF and managed PE samples, embedded HCFG configurations, and a Go ELF specimen. The route was untimed.

## Assignment and artifact

The Game Master assigned `evidence.zip` for attempt `b3d823fa-e599-460f-ba26-cd834adc431c`. I downloaded the archive through the paired Game Master connection and verified its SHA-256 before extraction:

`9de95ba6514247032ed7abe376718efaecdd9a444277731a8392ea34342b2032`

The archive was AES-encrypted and extracted with the challenge password `infected`. Its members, in central-directory order, were:

1. `d01--sample.elf`
2. `d02--sample.elf`
3. `d03--sample.dll`
4. `d03--sample.runtimeconfig.json`
5. `d04--sample.elf`

I analyzed the extracted files on REMnux without executing them. The SHA-256 values were:

| Member | Purpose | SHA-256 |
| --- | --- | --- |
| `d01--sample.elf` | Day 1 ELF header, sections, symbol table, and `recover_code` disassembly | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | Day 2 ELF container and `.hcfg` configuration | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | Day 3 managed PE metadata and embedded HCFG record | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | Day 3 runtime support file and second `d03--` member hash | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | Go ELF architecture, format, and embedded HCFG configuration | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |

The Day 3 hash questions explicitly use the `d03--` members in archive order, so the DLL is member 1 and the runtime configuration is member 2.

## Analysis method

I used `file`, `readelf`, and `objdump` for ELF and PE identification and metadata. `readelf -W -S` avoids truncating long section names; `readelf -W -s` preserves full symbol names. For the Go file, `file` identified a stripped, statically linked ELF64 x86-64 executable. The `go` command was not installed on REMnux, so I used the ELF header and embedded strings for the requested format and configuration fields. No dynamic analysis was required by the questions.

The HCFG record format is:

| Offset | Meaning |
| --- | --- |
| `0..3` | ASCII `HCFG` magic |
| `4` | Format version |
| `5` | One-byte XOR key |
| `6..7` | Little-endian payload length |
| `8..11` | Little-endian CRC-32 of decoded payload |
| `12..` | Payload, XORed byte-by-byte with the key |

After decoding, I checked the payload length, verified CRC-32, and parsed the UTF-8 JSON. For Day 2, the HCFG record starts at byte zero of the ELF section named exactly `.hcfg`. For Days 3 and 4, I scanned the binary bytes for `HCFG` and retained only records with valid bounds, CRC-32, and JSON.

## Findings submitted

### Day 1 ELF

The file is ELF64, little-endian, x86-64, and `ET_EXEC`. Its `recover_code` function is a constant return:

```asm
mov $0x1fa4,%eax
ret
```

The section names, in section-header order, were:

```json
["", ".interp", ".note.gnu.property", ".note.ABI-tag", ".hash", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".init", ".text", ".fini", ".rodata", ".huntress", ".eh_frame_hdr", ".eh_frame", ".init_array", ".fini_array", ".dynamic", ".got", ".got.plt", ".data", ".bss", ".symtab", ".strtab", ".shstrtab"]
```

The nonempty `.symtab` names, in table-entry order with duplicates preserved, were:

```json
["crt1.o", "__abi_tag", "variant-000.c", "marker", "crtstuff.c", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "completed.0", "__do_global_dtors_aux_fini_array_entry", "frame_dummy", "__frame_dummy_init_array_entry", "crtstuff.c", "__FRAME_END__", "_DYNAMIC", "__GNU_EH_FRAME_HDR", "_GLOBAL_OFFSET_TABLE_", "__libc_start_main@GLIBC_2.34", "data_start", "_edata", "_fini", "__data_start", "__gmon_start__", "__dso_handle", "_IO_stdin_used", "recover_code", "_end", "_dl_relocate_static_pie", "_start", "__bss_start", "main", "__TMC_END__", "_init"]
```

### Day 2 ELF and configuration

The Day 2 specimen is ELF64. The `.hcfg` record at offset `0x2180` has version `1`, XOR key `0x31`, and CRC-32 `0x6149aa00`. The decoded configuration fields submitted were:

- Campaign: `BR02-000`
- Domain: `node-000.day02.example.invalid`
- URL: `https://node-000.day02.example.invalid/api/BR02-000`
- Mutex: `Global\HuntressBR02_000`

### Day 3 managed PE and configuration

The primary Day 3 sample is a PE32 managed assembly, classified as `PE32_CLI`; its PE/COFF machine is `i386`, and the CLR metadata version is `v4.0.30319`. Its CRC-valid HCFG record uses key `0x41` and has CRC-32 `0xcb6cf23f`. The decoded configuration fields were:

- Campaign: `BR03-000`
- Domain: `node-000.day03.example.invalid`
- Mutex: `Global\HuntressBR03_000`

### Day 4 Go ELF and configuration

The Day 4 specimen is a stripped, statically linked ELF64 x86-64 executable. The HCFG record was found at file offset `0x1baa60`; it has version `1`, XOR key `0x51`, and CRC-32 `0x2b747600`. The decoded configuration fields were:

- Campaign: `BR04-000`
- Domain: `node-000.day04.example.invalid`
- URL: `https://node-000.day04.example.invalid/api/BR04-000`
- Mutex: `Global\HuntressBR04_000`

## Submission result

The assignment contained 32 answer IDs. For fields whose requested format was a JSON array, I submitted the array as compact JSON text under the exact Game Master answer ID. The Game Master returned `CORRECT`; a follow-up status check also returned `CORRECT`.

Completion flag:

`7d3f65b04683b41c06a5a3da7520f35e`

The personal Game Master bearer token remained in Kali's private token file and is not included here.

## Time Trial

The Time Trial was a fresh 50-second ranked attempt, ID `2d6870f2-77ea-4eca-b9e6-e58ed848c069`, with deadline `2026-10-22T18:37:45.583Z`. I downloaded its own assigned archive, verified its SHA-256, extracted it with `infected`, and submitted all 32 findings before the deadline.

The Time Trial archive SHA-256 was:

`d569989cccff74265d8b28e8d6cdbd24f410c837131eb2d0547d084e2166ac3b`

The assigned members had these SHA-256 values:

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `ac142f9f015d85bb93bf061ba47e842a36f9e7afdf8936c40ee0fb2d237be6bf` |
| `d02--sample.elf` | `a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2` |
| `d03--sample.dll` | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5` |

The file formats and most Day 1 metadata matched the Single Solve, while the per-variant values changed. The Day 1 source marker was `variant-009.c`; `recover_code` returned `0x1fad` (`mov $0x1fad,%eax; ret`). The Day 2 HCFG record used XOR key `0x32` and CRC-32 `0xffdeebbe`, with campaign `BR02-001`, domain `node-001.day02.example.invalid`, URL `https://node-001.day02.example.invalid/api/BR02-001`, and mutex `Global\\HuntressBR02_001`.

The Day 3 sample remained a PE32 CLI assembly for `i386`, with metadata version `v4.0.30319`. Its HCFG record used key `0x48` and CRC-32 `0xa46a3a87`; the decoded values were campaign `BR03-007`, domain `node-007.day03.example.invalid`, and mutex `Global\\HuntressBR03_007`.

The Day 4 specimen was a stripped, statically linked ELF64 x86-64 Go binary. Its HCFG record at offset `0x1baa60` used key `0x58` and CRC-32 `0x4472beb8`; the decoded values were campaign `BR04-007`, domain `node-007.day04.example.invalid`, URL `https://node-007.day04.example.invalid/api/BR04-007`, and mutex `Global\\HuntressBR04_007`.

The Game Master returned `CORRECT` on submission and again on the follow-up status request. The Time Trial flag was:

`8335931944615289c4f988e5db3ac073`

## Mastery

Mastery assigned two independent `evidence.zip` archives in one 80-second timed attempt, ID `cda352b5-bf1d-4378-bf9e-0b52b2e1bd30`, with deadline `2026-10-22T18:40:40.888Z`. I checked each downloaded archive against its Game Master SHA-256 and extracted both with `infected` into separate directories.

| Set | Archive SHA-256 |
| --- | --- |
| Set 1 | `93537bddeb841b4b712483d4a1c484bdede885532d3d141cd356e850929ebafd` |
| Set 2 | `a7630c86ca22c9173a2b8624dad91f2cd792d57898b72dbea7534a0ffe8879b2` |

Both sets reused the Day 1 ELF findings from Single Solve: SHA-256 `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`, ELF64, little-endian x86-64, `ET_EXEC`, and `recover_code` returning `0x1fa4`. The section-name and symbol arrays were unchanged from the Single Solve findings above.

The variant-specific findings were:

| Finding | Set 1 | Set 2 |
| --- | --- | --- |
| Day 2 SHA-256 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | `9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f` |
| Day 2 format | `ELF64` | `PE32+` |
| Day 2 HCFG key / CRC-32 | `0x31` / `0x6149aa00` | `0x31` / `0x6149aa00` |
| Day 3 DLL SHA-256 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| Day 3 runtimeconfig SHA-256 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| Day 3 configuration | `BR03-001`, `node-001.day03.example.invalid`, `Global\\HuntressBR03_001` | `BR03-000`, `node-000.day03.example.invalid`, `Global\\HuntressBR03_000` |
| Day 4 binary SHA-256 | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` | `bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97` |
| Day 4 format / architecture | `ELF64`, `x86-64` | `PE32+`, `x86-64` |
| Day 4 configuration | `BR04-006`, `node-006.day04.example.invalid`, `https://node-006.day04.example.invalid/api/BR04-006`, `Global\\HuntressBR04_006`, CRC-32 `0xdae5ff06` | `BR04-002`, `node-002.day04.example.invalid`, `https://node-002.day04.example.invalid/api/BR04-002`, `Global\\HuntressBR04_002`, CRC-32 `0xcd2bf33d` |

The Day 3 assemblies in both sets were PE32 CLI for `i386`, with CLR metadata version `v4.0.30319`. Set 1's HCFG key and CRC-32 were `0x42` and `0x55fbb381`; Set 2's were `0x41` and `0xcb6cf23f`. Day 2 configuration values were campaign `BR02-000`, domain `node-000.day02.example.invalid`, URL `https://node-000.day02.example.invalid/api/BR02-000`, and mutex `Global\\HuntressBR02_000` in both sets.

I submitted all 64 findings under the exact `set1.` and `set2.` answer IDs. The Game Master returned `CORRECT`, and a follow-up status check confirmed completion. This was the only ranked Mastery variant; status reported zero fresh variants remaining. The Mastery flag was:

`03cf12d19d4b7a72cedd6989adf939be`
