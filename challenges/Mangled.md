# Mangled — solution write-up

This write-up covers the **Single Solve**, **Time Trial**, and **Mastery** modes of Mangled. The challenge asks for static analysis of a C specimen and a C++ specimen: hashes and metadata from the C file, plus the C++ executable format, configuration embedded in a custom section, and C++ symbols.

## Approach used for both modes

I started and resumed each mode through the Game Master, then downloaded the assigned `evidence.zip` for that exact attempt. The archive password given in the challenge is `infected`. I extracted each attempt into its own directory with `7z` so files from different variants could not get mixed together. I calculated hashes from the extracted files rather than copying bytes or relying on filenames.

For the C specimen, I used `sha256sum`, `readelf -h` and `readelf -S` to identify the file hash, ELF machine, and whether a symbol table was present. I dumped the `.huntress` section with `objcopy` to read the marker. I used `objdump -d -Mintel` to locate `recover_code` and read its immediate return value, converting the hexadecimal immediate to decimal for submission.

For the C++ specimen, I checked the file magic to determine whether it was PE or ELF, and used `nm` and `c++filt` to inspect the mangled method, vtable, and RTTI symbols. I extracted its `.hcfg` section with `objcopy`. The section contains a short header followed by XOR-obfuscated JSON; I identified the single-byte key, decoded the JSON, and verified its CRC-32. The decoded configuration supplied the campaign, domain, URL, and mutex values.

The challenge prompt mentions Windows and PE imports, but the assigned Time Trial variant's C++ specimen was actually ELF. I used the bytes of that assigned specimen to answer the format question rather than inferring the format from the prompt.

## Reproduction workflow

The retained notes include the successful Time Trial and Mastery archive hashes and findings, but not the Single Solve archive hash, extracted member names, per-file hashes, or the original decoder source. The commands below reproduce the recorded archive-integrity and native-binary inspection steps. Use the filenames shown by `7z l`; do not reuse a specimen from another mode, because each mode can assign different bytes.

```bash
mkdir -p /tmp/mangled-time-trial
cd /tmp/mangled-time-trial
sha256sum evidence.zip
7z l -pinfected evidence.zip
7z x -pinfected evidence.zip -oextracted
find extracted -type f -print0 | xargs -0 sha256sum
```

For an extracted C sample, inspect its container, sections, symbols, marker section, and `recover_code` without executing it:

```bash
file path/to/c-sample
readelf -h path/to/c-sample
readelf -SW path/to/c-sample
readelf -sW path/to/c-sample | grep -E 'recover_code|marker'
objdump -d -Mintel --disassemble=recover_code path/to/c-sample
objcopy --dump-section .huntress=marker.bin path/to/c-sample
xxd -g1 marker.bin
```

For the C++ sample, identify the actual container before interpreting its sections and symbols. The recorded workflow used:

```bash
file path/to/cpp-sample
objdump -h path/to/cpp-sample
nm -a path/to/cpp-sample | tee symbols.raw.txt
c++filt < symbols.raw.txt
objcopy --dump-section .hcfg=hcfg.bin path/to/cpp-sample
xxd -g1 hcfg.bin
```

Check the original symbol names as well as their demangled forms: vtable and typeinfo symbols carry ABI prefixes such as `_ZTV`, `_ZTI`, and `_ZTS`. Decode the `.hcfg` payload according to its header and verify its CRC-32 before parsing the JSON. The existing notes do not retain a standalone HCFG decoder, so this write-up reports the validated values but does not claim the code block above completes that decode by itself.

For the successful Time Trial, `sha256sum evidence.zip` should report `0ee294dc8cc1f392b6bdcbfd82e5ce32248a366ed61c382503d58ff81d2efa89`. That assigned specimen is ELF despite the Windows-focused prompt; the observed file bytes, not the prompt wording, determine the format answer.

## Single Solve

I completed the untimed static set using the same artifact-first workflow: download the assigned archive, extract it with the published password, analyze the exact C and C++ files, and submit the requested findings under their Game Master answer IDs. The Game Master confirmed completion and returned flag:

`5c650a1176e13a5cbc49d011ad1993b8`

The Single Solve artifact's per-file hashes and field values were not retained in the working notes, so I have not copied values from the later Time Trial variant into this section. Each mode can be assigned different bytes.

## Time Trial

The final successful run used a fresh assigned variant. The archive SHA-256 was:

`0ee294dc8cc1f392b6bdcbfd82e5ce32248a366ed61c382503d58ff81d2efa89`

The validated C findings were:

- SHA-256: `6413a43702b377d079202f0c95be1ffc93861d7a14fefae01e4bd7d1fc32e54e`
- Marker: `BR01-CATALOG-015`
- Symbol table present: `true`
- `recover_code`: `8115` (the function returns hexadecimal `0x1fb3`)
- Machine answer accepted by the Game Master: `x86-64`

The validated C++ findings were:

- SHA-256: `9ba8446ac7824ed2acd4a12b8c490fb6c0f198bcd0fdd662da7d61a9eb30b1c2`
- Format: `ELF`
- XOR key: `0x37`
- Decoded configuration CRC-32: `0x90d82306`
- Campaign: `BR02-006`
- Domain: `node-006.day02.example.invalid`
- URL: `https://node-006.day02.example.invalid/api/BR02-006`
- Mutex: `Global\\HuntressBR02_006`
- Vtable and typeinfo present: `true`
- Mangled score symbol: `_ZNK15DiscoveryEngine5scoreEPKc`
- Vtable symbol: `_ZTV15DiscoveryEngine`

The Game Master returned `CORRECT` for the Time Trial and awarded flag:

`d53b0db1aadfbd52ed33a327d7bfb7de`

## Mastery Mode

Mastery assigned two independent evidence archives and prefixed each answer ID with `set1.` or `set2.`. I verified each downloaded archive against the SHA-256 returned by the Game Master, then extracted and analyzed each set separately. The first timed run expired before completion, and the Game Master reported no fresh ranked variants remaining. Following its guidance, I continued the same two-set assignment in practice mode. I downloaded the practice attempt's own archive links before submitting, as required by the service.

### Set 1

- Archive SHA-256: `6a35d7872fea9031c98e32cad6978b6fabd1fa87afe0c83c22e43baba530074d`
- C SHA-256: `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b`
- C marker: `BR01-CATALOG-000`; symbol table: `true`; recovered code: `8100`; machine answer: `x86-64`
- C++ SHA-256: `1db6cd34482281e61ef34dd5695745b9370549e63a5241afbc7c5f9bda911cfc`
- C++ format: `PE32+`; XOR key: `0x32`; configuration CRC-32: `0xffdeebbe`
- Campaign: `BR02-001`; domain: `node-001.day02.example.invalid`; URL: `https://node-001.day02.example.invalid/api/BR02-001`
- Mutex: `Global\\HuntressBR02_001`; vtable and typeinfo present: `true`
- Mangled score symbol: `.text$_ZNK15DiscoveryEngine5scoreEPKc`
- Vtable symbol: `.rdata$_ZTV15DiscoveryEngine`

### Set 2

- Archive SHA-256: `027b47a60553a81f17c507da14d64d2db60a2e923c1fb8e628ae002fbcd8b9e1`
- C SHA-256: `803b860cb2bcf0046e32dd5ad87fe880371241519f0578b3c93533786b8f9ecd`
- C marker: `BR01-CATALOG-005`; symbol table: `true`; recovered code: `8105`; machine answer: `x86-64`
- C++ SHA-256: `018d4f5fe9eeb93de91d43101effb31e2da31e3606622da433653d35f333e6f5`
- C++ format: `ELF`; XOR key: `0x36`; configuration CRC-32: `0xe810e785`
- Campaign: `BR02-005`; domain: `node-005.day02.example.invalid`; URL: `https://node-005.day02.example.invalid/api/BR02-005`
- Mutex: `Global\\HuntressBR02_005`; vtable and typeinfo present: `true`
- Mangled score symbol: `_ZNK15DiscoveryEngine5scoreEPKc`
- Vtable symbol: `_ZTV15DiscoveryEngine`

For the PE specimen in Set 1, GNU `nm` includes the section prefix in the symbols the Game Master expects, so the submitted values include `.text$` and `.rdata$`. The ELF specimen in Set 2 uses the plain Itanium ABI names. A clean extraction directory also mattered: an earlier extraction left a stale PE file in place, producing the wrong SHA-256. Re-extracting the practice archive into a fresh directory yielded the hash that validated.

The Game Master returned `CORRECT` for Mastery in practice mode and returned flag:

`b588043208c1d292f6f9d329eef9bf94`

## Notes

The key detail that cost time was the exact answer representation for `c_machine`: `readelf` printed `Advanced Micro Devices X86-64`, but the accepted answer was `x86-64`. Submitting answers one field at a time exposed that mismatch while preserving the other validated answers. The pairing token was read privately from Kali's token file and was not included in this report.

---

Write-up structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).
