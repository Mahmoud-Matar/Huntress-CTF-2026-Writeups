# Shared Custody

## Day 21 · Single Solve

- Challenge ID: `binary-reverse-engineering-day-21-shared-library-boundaries`
- Attempt: `2e3d77ff-6146-46e4-a1bf-cfa2368e0b9f`
- Timer: untimed Single Solve.
- Assigned archive: `evidence.zip`
- Archive SHA-256: `d3a058e89fa984b84b9d8ef4486f260c004d2fd45d0a2c4526ce86123ae8a794`
- Archive password: `infected`

### Analysis

The assignment contained 25 AES-encrypted ZIP members and 252 exact answer fields covering the samples labeled Day 1 through Day 21. I verified the downloaded archive hash, then parsed the assigned members statically; no challenge binaries were executed. The answer map was built from the exact Game Master question IDs and formats with [tools/solve_shared_custody.py](../tools/solve_shared_custody.py).

The static pass covered ELF headers, section tables, symbol tables, the Day 1 `recover_code` function bytes, C++ RTTI/vtable symbols, PE/CLI metadata, Go and Rust markers, Java JAR central-directory and classfile metadata, WebAssembly sections and data segments, and CRC-verified HCFG records. For each HCFG record, the parser checked the length, XOR-decoded payload, CRC32, and JSON before using any values. It also handled the Day 19 `PK19` transform and Day 20 `RS20` resource/scratch layout with their stated hash and bounds checks.

Two fields needed correction after Game Master validation. Day 4's predicate is a case-sensitive search for `runtime.main` in the final sample bytes. Day 12's valid HCFG record is at file offset 82,928 inside `.data`; the disassembly contains an instruction referencing its exact virtual address, which meets the route's `raw_const_array` classification. The corrected full answer set was accepted.

### Result

Game Master status returned `CORRECT` with flag `94ade3a677f3a5d330ec397fef25fe6c`. The status was checked after the submission request timed out client-side, and it confirms the attempt is complete.

## Day 21 · Time Trial

- Challenge ID: `binary-reverse-engineering-day-21-shared-library-boundaries/time_trial`
- Attempt: `c2980d07-c42c-4641-ba32-70083a593982`
- Timer: untimed regular run (`run_for_time_supported: true`; ranked timing was not requested).
- Assigned archive: `evidence.zip`
- Archive SHA-256: `4965e7785adc72a35c9fad37548fd7daca22531321785399eedab95c9bd21f97`

I repeated the same static-analysis workflow against this attempt's newly assigned archive, verified its hash, and generated all 252 answers from its own bytes. The Game Master accepted the submission and status recheck returned `CORRECT` with flag `b1fe1f7d61242a2d8163c1cddd5884a4`.

## Day 21 · Mastery

- Challenge ID: `binary-reverse-engineering-day-21-shared-library-boundaries/mastery`
- Attempt: `3a9d7607-173c-4b33-b278-a4343200003f`
- Timer: untimed regular run (`run_for_time_supported: true`; no ranked timer was requested).
- Questions: 1,260 across five assigned evidence sets.

| Set | Archive SHA-256 |
| --- | --- |
| 1 | `46c1bea028d5dbe8efb7010c21eba47bfd3ed88513cf1dccafe4726f4a9c2e85` |
| 2 | `e5912591c20873d30e4dcb4d9ed16959eb3ed6322abe7e00b2822aabb3c880f4` |
| 3 | `50255d9c1080991d1119b43ad5355e7239d6ec8e799d45bd747d2f5114451a7a` |
| 4 | `3433c836e8407e550a3b161cfb88037578b1d81160228646b098fdaeb3052d4e` |
| 5 | `9ce964a58fb7061c0cadadc922832fa61c561dc0d75212414dfd35fb36df80bc` |

Each archive hash was checked before analysis. I generated a separate 252-answer map per set from its exact encrypted archive and merged the maps under the Game Master's exact `set1`–`set5` answer IDs. Game Master accepted the complete submission; a status recheck returned `CORRECT` with flag `8af29c46c9d257e895cdcf4efd51f430`.

## Tools and scripts

Project helper: [`tools/solve_shared_custody.py`](../tools/solve_shared_custody.py).
