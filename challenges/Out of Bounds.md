# Out of Bounds

## Day 25 · Single Solve

- Route: `binary-reverse-engineering-day-25-synthetic-vulnerability-root-cause`
- Attempt: `3bffb11a-4efa-4571-96e3-d08cc1aa12b9`
- Started: 2026-10-25 20:28:24 UTC; untimed
- Archive SHA-256: `ef43ba0a05535d07ffd75f17fd04aface573ed397077f630a4bc1802809dd067`
- Day 25 corrected JAR SHA-256: `cc14d96c8bd784dfcaae87b602ea5bc576d213ad3b8a4c70bc26f2de83982553`
- Day 25 vulnerable JAR SHA-256: `8fab8d498c6695c8605689d13e72e2d798e0a242c214d0313146cf429a0c5eac`

The assigned archive contained 25 days of cross-format binary evidence and 300 exact answer fields. I verified the archive hash before extraction and used the published password `infected`. I kept the specimens inert and parsed their bytes with Python’s standard library plus static ELF/PE tools; no challenge binaries were executed.

The analysis covered ELF headers, sections, symbol tables and function bytes; PE/COFF machine and CLI metadata; Java JAR central directories and classfile constant pools; WebAssembly sections; and HCFG records. For HCFG, I checked payload bounds, XOR-decoded the payload, and accepted records only when the CRC32 and JSON were valid. I also decoded the Day 19 PK19 overlay and verified its unpacked SHA-256, and parsed the Day 20 RS20 resource and scratch layout. Special cases were checked against the assigned bytes, including Day 12’s HCFG record in `.data` with a code reference to that exact record, and the Day 22 primary assembly’s PE machine field.

I submitted the exact answer IDs from the Game Master. Accepted batches left three fields to correct; those fields were isolated and rechecked against the relevant executable metadata and data layout. The Game Master then returned `CORRECT`, with all 300 answer IDs accepted. The personal status endpoint confirmed `CORRECT` and recorded solver `Jinzo` at 2026-10-25 20:37:07 UTC.

Flag: `bc560215f9a9b366e909be9064eb56aa`

## Day 25 · Time Trial (untimed scoring run)

- Route: `binary-reverse-engineering-day-25-synthetic-vulnerability-root-cause/time_trial`
- Attempt: `825da670-e0f5-44b7-ba5d-e72b46f69e1c`
- Started: 2026-10-25 20:39:28 UTC; `run_for_time: false`; no countdown or deadline
- Archive SHA-256: `eb37b3ec3c321761426b7242f9f283727f05ea96b1f57271806515db4d1d39fd`

I reused the same static-analysis workflow against this fresh assigned archive and verified its SHA-256 before extraction. The 300 answer fields were submitted in per-day batches; the Game Master accepted every batch and returned `CORRECT`. Personal status confirmed all 300 fields accepted and recorded solver `Jinzo` at 2026-10-25 20:40:24 UTC.

Flag: `49daf1c7170867de5c62f175652ec44d`

## Day 25 · Mastery (untimed scoring run)

- Route: `binary-reverse-engineering-day-25-synthetic-vulnerability-root-cause/mastery`
- Attempt: `74452800-9c27-4096-b326-3897580d0436`
- Started: 2026-10-25 20:41:09 UTC; `run_for_time: false`; no countdown or deadline
- Nine assigned archive SHA-256 values, in delivery order:
  1. `66e3eabb1a8704e0cbc6a7374ce4f2845ffbe6b7f74b7a655e7eb4e65c4223ff`
  2. `4116318c3d5526028f2585623f704d8c3cabd9f718a6cb12a12d55ba9b53a962`
  3. `0e785aa1800d1375731bd01c09d28a2061417d6c0464ee65ff1512a4a893c9a1`
  4. `3f082f20d2edf3ecef74f8b8ce52b441354b61abf37e979ed6f40381b0e01b04`
  5. `14e715448172932342f92e40c25a647fdfbc94bccfa1698f4f0be4ad3de59d15`
  6. `1025010ff8855d2b4c0999af688eaf39bd38464ea4e733ab37611985b5026875`
  7. `ad972f97f963cb282e1dabebd3345026c6001b44cd290e86e332eafd8cd8bd27`
  8. `233d8ca261a4dfd17cca8d0e04ef53821f7a9d64cb7596e212a4977391f92240`
  9. `3de14e1f84ba254cebaf08161b8b1186823fb7c178bd7284096a290d3d89f9ea`

The mastery assignment contained nine fresh deliveries with 300 fields each. I verified every archive hash before extraction and solved each delivery from its own bytes, applying the same static ELF, PE/CLI, JAR/classfile, WebAssembly, HCFG, PK19 and RS20 parsing used for Single Solve and Time Trial. I submitted each 300-field set under its exact `setN.` answer IDs. The Game Master accepted all nine sets; final personal status confirmed `CORRECT` with all 2,700 fields accepted and recorded solver `Jinzo` at 2026-10-25 20:45:51 UTC.

Flag: `696842e625b6d02f268737808a37750b`
