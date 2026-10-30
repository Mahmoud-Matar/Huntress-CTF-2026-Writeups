# Pool Party

## Challenge and result

- **ID:** `binary-reverse-engineering-day-06-java-bytecode-loader`
- **Mode:** Single Solve (untimed).
- **Prompt:** “Every Java class file carries its own phone book: the constant pool. Names, methods, invocations — it's all in there. Dive in and take attendance.”
- **Attempt:** `1637ea7f-2af8-4ffc-b999-2ec5004619fb`
- **Artifact:** [Download evidence.zip](https://2026.huntress.ctf.games/?op=download&capability=39c278c5fe2748968ccc019d0a89c2440aae9ba10e5e440c953b2c4715dd8386) — SHA-256 `4b53424fe8100cd94955133eb857dd1aa2c8a5062908933206467df9812648ea`; password `infected`.
- **Result:** `CORRECT`.
- **Flag:** `9e1562065a219c0974af11bb9aa2c8ee`.

The archive contains seven files: Day 1 and Day 2 ELF samples, a Day 3 managed PE assembly and runtime configuration, a Day 4 Go ELF, a Day 5 Rust ELF, and a Day 6 JAR. The archive hash was checked against the Game Master's value. I extracted the encrypted members with the published password and analyzed all files statically; no specimen was executed.

## Method

For the Day 1 ELF, I parsed the ELF header, section table, and `.symtab` in file order, then disassembled only the `recover_code` symbol. For the Day 2 ELF, I read the `.hcfg` section at its start. I read the CLR metadata root in the Day 3 PE and located the valid HCFG record in the assembly bytes. For the Go and Rust ELF files, I scanned literal `HCFG` occurrences and accepted records only when their bounds, XOR-decoded payload, CRC32, and JSON validated. For Day 6, I read the JAR manifest's `Main-Class`, parsed its class-file constant pool, and decoded the Base64-shaped UTF-8 constant whose bytes contained a valid HCFG record.

I matched all generated answer keys against the Game Master's answer IDs. The first batch was rejected because the Day 3 machine label `Intel 386` did not match its accepted form; the PE/COFF machine field is `0x014c`, and `i386` was accepted. The other 47 fields were accepted and saved, followed by the corrected machine field, which completed the challenge.

## Reproduction steps

Run these commands from a fresh work directory after downloading the linked artifact. The expected archive hash is shown above; compare it before extraction. Keep the extracted members inert and inspect them as data.

```bash
mkdir -p /tmp/pool-party
cd /tmp/pool-party
sha256sum evidence.zip
7z l -pinfected evidence.zip
7z x -pinfected evidence.zip -oextracted
find extracted -type f -print0 | xargs -0 sha256sum
```

Then proceed through the archive by its `dNN--` member names:

1. For `d01--sample.elf`, record the ELF header and section names, inspect `.symtab` in entry order, and disassemble only `recover_code`. Preserve duplicate symbols when the question requests the table contents.
2. For `d02--sample.elf`, inspect the ELF section table and locate `.hcfg`. For `d03--sample.dll`, identify PE/CLI from the PE headers, read the CLR metadata-root version, and scan for bounded HCFG records. The runtimeconfig JSON is a separate archive member and its hash must remain the second Day 3 member hash.
3. For the Day 4 and Day 5 ELF specimens, scan for literal `HCFG` markers. Keep a record only if its declared payload fits in the file, XOR decoding produces the declared CRC-32, and the bytes parse as UTF-8 JSON.
4. For the Day 6 JAR, inspect `META-INF/MANIFEST.MF` to find `Main-Class`, inspect that class's constant pool, and decode the Base64-shaped UTF-8 constant containing the CRC-valid HCFG record.
5. Map those independently recovered values to the exact answer IDs from the attempt. If a grouped submission is rejected, split by evidence group and test the disputed field against the underlying header rather than reusing a value from another mode.

The reused HCFG fields for this artifact are recorded in the table below. For Day 3, `i386` (PE/COFF machine `0x014c`) is the verified accepted architecture answer; the descriptive string `Intel 386` was rejected. This is a useful format lesson: submit the normalized architecture represented by the actual machine field.

## Recovered answers

| Set | SHA-256 of requested member | Format / architecture | Decoded configuration |
|---|---|---|---|
| Day 1 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` | ELF64, x86-64, little-endian, `ET_EXEC` | `recover_code`: `mov $0x1fa4,%eax`; `ret` |
| Day 2 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | ELF | Campaign `BR02-000`; domain `node-000.day02.example.invalid`; mutex `Global\HuntressBR02_000`; URL `https://node-000.day02.example.invalid/api/BR02-000`; CRC32 `0x6149aa00`; XOR key `0x31` |
| Day 3 | DLL `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d`; runtimeconfig `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | PE/CLI, i386; CLR metadata version `v4.0.30319` | Campaign `BR03-000`; domain `node-000.day03.example.invalid`; mutex `Global\HuntressBR03_000` |
| Day 4 | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` | ELF64, x86-64 | Campaign `BR04-000`; domain `node-000.day04.example.invalid`; mutex `Global\HuntressBR04_000`; URL `https://node-000.day04.example.invalid/api/BR04-000`; CRC32 `0x2b747600` |
| Day 5 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` | ELF64, x86-64 | Campaign `BR05-000`; domain `node-000.day05.example.invalid`; mutex `Global\HuntressBR05_000`; URL `https://node-000.day05.example.invalid/api/BR05-000`; CRC32 `0x8f37c323` |
| Day 6 | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` | JAR | Campaign `BR06-000`; domain `node-000.day06.example.invalid`; mutex `Global\HuntressBR06_000`; URL `https://node-000.day06.example.invalid/api/BR06-000`; HCFG version `1`; CRC32 `0x121bc931` |

The Day 1 section names, in section-header order, were `"", .interp, .note.gnu.property, .note.ABI-tag, .hash, .gnu.hash, .dynsym, .dynstr, .gnu.version, .gnu.version_r, .rela.dyn, .init, .text, .fini, .rodata, .huntress, .eh_frame_hdr, .eh_frame, .init_array, .fini_array, .dynamic, .got, .got.plt, .data, .bss, .symtab, .strtab, .shstrtab`. The nonempty `.symtab` names in entry order were `crt1.o`, `__abi_tag`, `variant-000.c`, `marker`, `crtstuff.c`, `deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`, `completed.0`, `__do_global_dtors_aux_fini_array_entry`, `frame_dummy`, `__frame_dummy_init_array_entry`, `crtstuff.c`, `__FRAME_END__`, `_DYNAMIC`, `__GNU_EH_FRAME_HDR`, `_GLOBAL_OFFSET_TABLE_`, `__libc_start_main@GLIBC_2.34`, `data_start`, `_edata`, `_fini`, `__data_start`, `__gmon_start__`, `__dso_handle`, `_IO_stdin_used`, `recover_code`, `_end`, `_dl_relocate_static_pie`, `_start`, `__bss_start`, `main`, `__TMC_END__`, `_init`.

## Time Trial

- **Mode:** Time Trial; 50-second server-enforced deadline.
- **Attempt:** `c6457cbe-b563-44b2-b5f8-ca296229191a`
- **Artifact:** fresh `evidence.zip` — SHA-256 `987e5602ef379e7cc317188f91ffd4483aa7f957f68aa7feaaac64c5fc8bc323`.
- **Result:** `CORRECT`.
- **Flag:** `0cd60afdfa2e097cfe9d28c2ab7c88e0`.

The trial used a fresh set of Day 1–6 samples. I verified the archive hash and reran the same static parsers. The Day 3 PE/COFF field is machine `0x014c`; `i386` is the accepted architecture answer. All fields were accepted before the deadline.

## Mastery

- **Mode:** Mastery; two sets under one 80-second server-enforced deadline.
- **Attempt:** `6907665f-68c5-4052-a280-baf2a03ad04d`
- **Artifacts:** two fresh `evidence.zip` files:
  - Set 1 SHA-256: `ff4e489cea5001f6f6f27c5a1fcc84cfb0971f4fc44d091f8da613c5a12c99c6`
  - Set 2 SHA-256: `2fead2acdfa77a96a27edbb1532fa793b2e8cbf323307e4ce6bb452cb5d50361`
- **Result:** `CORRECT`; all 96 fields (48 per set) were accepted.
- **Flag:** `a60cd50466842f2c4f6362adc4865357`.

The second set used PE rather than ELF for the Day 2 and Day 4 specimens. I parsed the PE/COFF headers and section table, including the `.hcfg` section for Day 2, and scanned the Day 4 PE bytes for the CRC-valid HCFG record. The remaining artifacts used the same static methods described above. Both archives matched their API-provided hashes, and I checked that the generated `set1.*` and `set2.*` answer keys exactly matched all 96 IDs before submitting. No binaries were executed.

---

Write-up structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).
