# Swift Justice — Single Solve

## Result

The Game Master accepted the full answer set and returned `CORRECT`. The same attempt is confirmed correct by a follow-up status request.

## Assignment

- Challenge: ⚙️ Swift Justice
- Challenge ID: `binary-reverse-engineering-day-08-swift-network-configuration`
- Mode: Single Solve, untimed; no deadline was active.
- Attempt: `157bcbd3-95a8-4b8c-92e4-a415f764d3c3`
- Prompt: “Swift binaries speak in protocols and hide their networking in plain sight. Follow the symbols to the URL configuration and see where this one phones home.”
- Artifact: `evidence.zip`
- SHA-256: `074a2b8d2d69f0b7e55c4d48ef2ea04ff65532bde069e23da4e9f1d3cd325085`

The archive contained nine members: one sample each for `d01` through `d08`, plus the Day 3 `.runtimeconfig.json`. The downloaded archive hash matched the Game Master. The files were analyzed statically and no sample was run.

## What the API asked for

The Single Solve contract contained 80 answer fields, ten for each day group. The fields requested:

- **D01:** ELF hash, class, machine, ordered section names, symbol names, `recover_code` disassembly, ELF type, byte order, entry address, and `.symtab` presence.
- **D02:** ELF hash and format, HCFG campaign/domain/mutex/URL/CRC/XOR key, and C++ RTTI/vtable symbol predicates.
- **D03:** hashes of the assembly and runtime config, managed PE/.NET format and machine, CLR metadata version, and HCFG campaign/domain/mutex/URL/CRC.
- **D04–D05:** ELF hash, architecture and format, plus HCFG campaign/domain/mutex/URL/CRC/version/XOR key.
- **D06–D07:** JAR hash and format, HCFG campaign/domain/mutex/URL/CRC/version/XOR key, and distinct ZIP compression methods.
- **D08:** ELF hash, architecture/class/format/machine, and HCFG campaign/domain/mutex/URL/CRC.

## Analysis

I verified the archive hash, listed its members in central-directory order, and parsed each delivered file from its exact bytes. ELF headers, sections, symbols, and HCFG data were read without executing the binaries. For D01, the `.symtab` entries were preserved in table order, including duplicate names; `recover_code` disassembled to `mov eax,0x1fa4` followed by `ret`.

The D02 HCFG record was read from the section named exactly `.hcfg`. The PE/CLI metadata version for D03 came from the CLR metadata root (`v4.0.30319`). The JAR Main-Class constant pools were inspected for Base64 strings containing CRC-valid HCFG records. For D08, I checked literal HCFG occurrences first, then decoded qualifying Base64 runs as instructed. Each decoded HCFG payload was XORed with its one-byte key, and its CRC32 was checked before reading the JSON fields.

The decoded network configuration for D08 was:

- Campaign: `BR08-000`
- Domain: `node-000.day08.example.invalid`
- URL: `https://node-000.day08.example.invalid/api/BR08-000`
- Mutex: `Global\\HuntressBR08_000`
- HCFG CRC32: `0x6a033bfd`
- XOR key: `0x41`

The answer map contained exactly the 80 API-provided IDs, with no missing, extra, or empty values. The Game Master accepted it as `CORRECT`.

## Verification

Two repeated `GET ?op=list&day=8` checks now agree: all 15 Day 8 routes are solved.

---

# Swift Justice — Time Trial

## Result

The Game Master accepted all 80 answer fields as `CORRECT` within the server-enforced 80-second run.

## Assignment

- Mode: Time Trial; the clock was running.
- Attempt: `014655ef-343c-442e-981e-0cf4ea16ce24`
- Deadline: `2026-10-23T00:39:32.692Z`
- Artifact: `evidence.zip`
- SHA-256: `c3729ad696566889de0cef8f00f6bf7489b60cf547119d05ee82e96e0a5ac662`

## Analysis

I downloaded and verified the assigned archive, extracted it with the published `infected` password, then reused the static parser from Single Solve to collect the exact 80 answer fields. The assigned D08 configuration pointed to `https://node-004.day08.example.invalid/api/BR08-004`. The complete answer map matched the IDs returned for this attempt and was accepted before the deadline.

---

# Swift Justice — Mastery

## Result

The Game Master accepted all 400 fields across five evidence sets as `CORRECT`. A follow-up status request confirmed the route complete.

## Assignment

- Mode: Mastery; one shared 320-second server timer was active.
- Completed attempt: `7bc20d1c-429b-44e9-87d0-9bcee529adff`
- Deadline: `2026-10-23T00:50:13.655Z`
- Five `evidence.zip` archives, each containing the Day 1–8 specimens and the Day 3 runtime config.
- SHA-256 values, in assigned set order:
  1. `c53a311a73d52869f8a20e627fbe5b67971ed704df19c4c3c9a40b051abac868`
  2. `4f76e53652d0ead3f7f751c780c2d6578b6c71e0cb82d02bfc90552b6965f644`
  3. `b76a0ddb2d30ea816a0dcff8128be44715334718186d480af4c59b97034e1ef4`
  4. `88fdd5bf70bd0dc76124218a889a60d38e2f8898f0c178737cb01d7ee3294012`
  5. `a415e6b9e2e15dee8130d98a995ecd292cf7c02073f0788c058ee15781fcb988`

## Analysis

Each archive hash was checked against the Game Master response before extraction. The same static parser was applied to every set, covering ELF and PE headers, symbols, CLI metadata, HCFG records, Java class constant pools, and ZIP compression methods. On these mastery variants, the Day 1 ELF had no `.symtab`; accordingly, the symbol list and `recover_code` disassembly were both `[]`. This was verified from the section table and symbol table rather than inferred from the earlier route.

The parser produced 80 fields per set. Before submission, the combined 400-key map was checked against the exact `answer_ids` returned by the mastery attempt and checked for empty values. The full map was submitted to the Game Master and returned `CORRECT`. Two repeated `GET ?op=list&day=8` requests then showed no unsolved Day 8 routes.
