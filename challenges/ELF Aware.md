# ELF Aware

> Writeup organization adapted from [RyanNgCT/CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template), with attribution. The analysis and results below are specific to our assigned Huntress CTF attempt.

## Challenge details

- **Day / category:** Day 1, Binary / ELF orientation
- **Game Master ID:** `binary-reverse-engineering-day-01-c-elf-orientation/time_trial`
- **Mode:** Time Trial, ranked timer enabled by this legacy route
- **Successful attempt:** `ac69ba41-9d7a-4b8b-87c1-76e12677e307`
- **Timer:** started 2026-10-30 02:36:24.835 UTC; deadline 2026-10-30 02:37:14.835 UTC
- **Prompt:** “Before you can reverse anything, you have to learn to read. These plain C binaries are your primer: headers, section tables, symbol tables. Start with `readelf -h -S` and work your way down.”
- **Assigned archive:** [`evidence.zip`](data/artifacts/elf-aware/elf-aware-time-trial-evidence.zip), SHA-256 `36e3a9c3134850856e6fe3719e9ddf99d4c0f22e6cbca94a50d5b8550231bcff`
- **Result:** Game Master returned `CORRECT`; the personal status endpoint confirmed the same result.

## Goal and approach

The attempt contained four ELF executables and asked for nine values from each: ELF class, byte order, machine label, type, marker, `.symtab` presence, exported symbol, the return value of `recover_code` when present, and entry point. The archive was downloaded through the paired Game Master connection and inspected from those exact bytes. To stay inside the 50-second run, I used Kali to retrieve and parse the archive, then kept a portable parser in the project for replay and review. I transferred the downloaded archive into the project and verified that its SHA-256 matched the Game Master response. None of the ELF files were executed.

The important answer-format detail is that the Game Master expects concise normalized values. GNU `readelf` describes byte order as “2's complement, little endian,” architecture as “Advanced Micro Devices X86-64,” and ELF type as “EXEC (Executable file).” For this route the accepted values were `little`, `x86-64`, and `ET_EXEC` respectively. The marker, section, and symbol fields came from the assigned file itself.

## Reproduction steps

1. Fetch the assigned `evidence.zip` from the current Time Trial attempt using the authenticated Game Master `op=artifact` operation. Keep the bearer in a private environment or token file; do not paste it into the command line or writeup. Verify the ZIP hash before analysis:

   ```bash
   sha256sum evidence.zip
   # 36e3a9c3134850856e6fe3719e9ddf99d4c0f22e6cbca94a50d5b8550231bcff  evidence.zip
   unzip -l evidence.zip
   unzip -o evidence.zip -d elf-aware
   ```

2. Inspect each file's header, sections, and symbols. `readelf` provides the raw evidence; the answer labels in the table below use the service's accepted normalization.

   ```bash
   for f in elf-aware/slot-*.elf; do
       echo "=== $f ==="
       sha256sum "$f"
       readelf -h -S "$f"
       readelf -sW "$f"
       strings -a "$f" | grep -E '^BR01-'
       objdump -d "$f" | grep -A3 -E '<(recover_code|inspect_section)>:'
   done
   ```

3. For `elf_class`, read `EI_CLASS` (or the `Class:` row): value `2` means `ELF64`. For byte order, read `EI_DATA`; value `1` means little-endian, submitted as `little`. For `e_machine == 62`, submit the route's normalized machine label `x86-64`. Decode `e_type == 2` as `ET_EXEC`. The entry point is the `e_entry` value, rendered as lowercase hexadecimal with `0x`.

4. Check whether the section table contains `.symtab`; that gives the `has_symtab` boolean. Read the custom defined global function from `readelf -sW` for `exported_symbol`. The `BR01-...` string in each assigned file supplies its marker.

5. For a `recover_code` symbol, inspect its instructions without running the binary. In this set, the function loaded an immediate constant into `eax` and returned. Convert the immediate from hexadecimal to base 10 because the Game Master requested an integer. For example, `mov $0x1ca3,%eax; ret` yields `7331`. Where the requested `recover_code` field is absent, submit the literal `none`.

6. The project helper performs the extraction and prints a JSON answer map from an assigned `evidence.zip` (or a mastery archive whose members use the `m-slot-` prefix):

   ```bash
   python3 tools/solve_elf_aware.py evidence.zip
   ```

   It requires `readelf` and `objdump`, reads the archive only, and never executes the ELF files or contacts the Game Master. The exact answer IDs are `slot0_...` through `slot3_...`; preserve the IDs returned by the start response when submitting.

7. Submit the answer map to `POST /?op=submit` as `{"challenge":"binary-reverse-engineering-day-01-c-elf-orientation/time_trial","answers":{...}}` through the paired Game Master connection. The successful run submitted one answer field per request so an exact-label mismatch could be isolated without discarding already accepted fields. The service returned `CORRECT`, and a subsequent personal status check returned `result: CORRECT` for attempt `ac69ba41-9d7a-4b8b-87c1-76e12677e307`.

## Findings from the assigned variant

The archive contained four files. `slot-0.elf`, `slot-1.elf`, and `slot-2.elf` were byte-identical in this variant; `slot-3.elf` differed. Member hashes are included so the exact set can be checked after download.

| Slot | File SHA-256 | Class | Endianness | Machine | Type | Marker | `.symtab` | Exported symbol | `recover_code` | Entry point |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| 0 | `1a77ad2615a5e7b2ae7deb48ac0071d525981b2c1d10065f95426a26208119d5` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-IMMEDIATE-RECOVERY` | `true` | `recover_code` | `7331` | `0x401030` |
| 1 | `1a77ad2615a5e7b2ae7deb48ac0071d525981b2c1d10065f95426a26208119d5` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-IMMEDIATE-RECOVERY` | `true` | `recover_code` | `7331` | `0x401030` |
| 2 | `1a77ad2615a5e7b2ae7deb48ac0071d525981b2c1d10065f95426a26208119d5` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-IMMEDIATE-RECOVERY` | `true` | `recover_code` | `7331` | `0x401030` |
| 3 | `5098bda9538efc474e224fab8918dec9aa6f80996b213ffa78791aa923ebedbe` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-SYMBOL-ORIENTATION` | `true` | `recover_code` | `1337` | `0x401030` |

## Submitted values

The complete accepted answer map, grouped by slot:

```text
slot0: ELF64 | little | x86-64 | ET_EXEC | BR01-IMMEDIATE-RECOVERY | true | recover_code | 7331 | 0x401030
slot1: ELF64 | little | x86-64 | ET_EXEC | BR01-IMMEDIATE-RECOVERY | true | recover_code | 7331 | 0x401030
slot2: ELF64 | little | x86-64 | ET_EXEC | BR01-IMMEDIATE-RECOVERY | true | recover_code | 7331 | 0x401030
slot3: ELF64 | little | x86-64 | ET_EXEC | BR01-SYMBOL-ORIENTATION | true | recover_code | 1337 | 0x401030
```## Flag and lesson

- **Accepted flag:** `68503bbbd589eebb0e99c3ff63d6877f`
- **Validation:** Game Master submission returned `CORRECT`; the follow-up status request returned `result: CORRECT`.
- **Lesson:** distinguish tool display strings from the challenge's normalized answer values. Parse the ELF fields from bytes, then submit the exact labels the route expects. For executable code, disassemble the function and convert the immediate according to the answer format rather than guessing from its marker.

## Reproducibility notes

The assigned archive and each member hash identify the exact successful variant. The values above came from the downloaded archive and the accepted Game Master response. The answer map is variant-specific; another retry may deliver different binaries and must be analyzed from its own archive. Do not reuse this flag or answer map for a new variant.

## Mastery Mode

The Day 1 Single Solve route was already `CORRECT` before this pass (attempt `6877057e-8c3c-4539-8e2c-f0850a604feb`, started 2026-10-01); I did not replace that completed team result. After the Time Trial was confirmed, Mastery was the next unresolved route. Its prior attempt was expired and the ranked pool was exhausted (`unique_attempts_remaining: 0`), so I followed the Game Master's guidance and used untimed `practice`, which preserves the last assigned material and can still complete the mode.

- **Route ID:** `binary-reverse-engineering-day-01-c-elf-orientation/mastery`
- **Attempt:** `22fbeb6d-40d1-4296-9581-a5c9405a6f2b`
- **Timer:** none; this was untimed practice after the ranked pool was exhausted.
- **Set 1 archive:** [`evidence.zip`](data/artifacts/elf-aware/elf-aware-mastery-set-1-evidence.zip), SHA-256 `248adc691e1802a77d1ba1bd3bf93fb80625e922407bb765581dfd07eebb2df1`
- **Set 2 archive:** [`evidence.zip`](data/artifacts/elf-aware/elf-aware-mastery-set-2-evidence.zip), SHA-256 `28835efd00658d47cb179e1ecc6a05740a0c46e3b68fd7f4074164ec4525b184`

I downloaded both archives from the same practice attempt, transferred the exact bytes to REMnux, verified both hashes, and ran [tools/solve_elf_aware.py](../tools/solve_elf_aware.py) on each. Each set contains four ELF samples and uses the same nine field names as the Time Trial, prefixed by `set1.` or `set2.`. The answer-ID pattern is `setN.slotM_field`.

| Set / slot | Member SHA-256 | Class | Endianness | Machine | Type | Marker | `.symtab` | Exported symbol | `recover_code` | Entry point |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| 1 / 0 | `5098bda9538efc474e224fab8918dec9aa6f80996b213ffa78791aa923ebedbe` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-SYMBOL-ORIENTATION` | `true` | `recover_code` | `1337` | `0x401030` |
| 1 / 1 | `fe00f21a2e5f24729b722f595398f68e9045602b78888b143594c3d61b045f89` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-SECTION-BEACON` | `true` | `inspect_section` | `none` | `0x401030` |
| 1 / 2 | `1a77ad2615a5e7b2ae7deb48ac0071d525981b2c1d10065f95426a26208119d5` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-IMMEDIATE-RECOVERY` | `true` | `recover_code` | `7331` | `0x401030` |
| 1 / 3 | `1a77ad2615a5e7b2ae7deb48ac0071d525981b2c1d10065f95426a26208119d5` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-IMMEDIATE-RECOVERY` | `true` | `recover_code` | `7331` | `0x401030` |
| 2 / 0 | `0334283017d279785eebf542e3ff3f7ac3fad36c2db8a216499f31a1d8db4385` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-STRIPPED-PROFILE` | `false` | `none` | `none` | `0x401030` |
| 2 / 1 | `0334283017d279785eebf542e3ff3f7ac3fad36c2db8a216499f31a1d8db4385` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-STRIPPED-PROFILE` | `false` | `none` | `none` | `0x401030` |
| 2 / 2 | `fe00f21a2e5f24729b722f595398f68e9045602b78888b143594c3d61b045f89` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-SECTION-BEACON` | `true` | `inspect_section` | `none` | `0x401030` |
| 2 / 3 | `0334283017d279785eebf542e3ff3f7ac3fad36c2db8a216499f31a1d8db4385` | `ELF64` | `little` | `x86-64` | `ET_EXEC` | `BR01-STRIPPED-PROFILE` | `false` | `none` | `none` | `0x401030` |

The whole 72-field answer map was submitted in one untimed request. The Game Master returned `CORRECT` with flag `9be7289b8b6baa473e5fe8af13dd1f24`, and the subsequent personal status check confirmed `result: CORRECT` for this attempt.

## Tools and scripts

Project helper: [`tools/solve_elf_aware.py`](../tools/solve_elf_aware.py).
The reproduction steps also use the system utilities `readelf` and `objdump`; they are prerequisites and are not bundled in this repository.
