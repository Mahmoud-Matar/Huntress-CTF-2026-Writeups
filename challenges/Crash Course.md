# Crash Course

## Day 26 · Single Solve

Route: `binary-reverse-engineering-day-26-crash-triage`  
Attempt: `e197d013-028a-449e-9b4c-036f74454e71`  
Started: 2026-10-26 14:03:57 UTC; untimed.

The player supplied the complete public CourseStack lesson, including password `infected`. The lesson awards 2 points for Single Solve, 3 for Time Trial, and 5 for Mastery, with optional ranked limits of 80 and 660 seconds. This run uses ordinary untimed scoring.

[Assigned evidence archive](data/crash-course-single-evidence.zip)  
SHA-256: `fd52a098241e1d9b99c54da530b9185a29dc8269ee56edc3d36c237f2381b1e3`

[Complete assignment, questions, formats, and guidance](assignments/Crash%20Course%20assignment.md)

The archive contains 35 members and 312 required findings spanning Days 1–26. Analysis was static: ELF headers, section and symbol tables, PE/CLI metadata, WebAssembly data segments, JAR classfile constant pools, and HCFG records. HCFG recovery checked bounds, XOR decoding, CRC32 and JSON. PK19 and RS20 overlays were checked against their stored hashes. Both Day 24 and Day 25 role configs were decoded and compared for equality. No challenge code was executed.

Day 26 JAR SHA-256: `cb614301daacaf60485acad7abdd00887450366f4a131b4b554fe7c5b7f42d05`. Its manifest names `Day26Variant000`. The crash trace reports `IllegalStateException` with frames `stageThree`, `stageTwo`, `stageOne`; all are present in the primary class's 10-method table. The recovered HCFG has version 1, XOR key `0xb1`, CRC32 `0xfd5b48eb`, campaign `BR26-000`, and domain `node-000.day26.example.invalid`.

The initial full answer set was rejected. Validation isolated a parser error in three managed metadata fields: a CLI header offset was substituted for its runtime-version string. After correction, all 312 findings were accepted. Submission and personal status both returned `CORRECT`, without pending scoring.

Flag: `07989604ed4c1e245095317fe4c55b12`.

[Static answer builder](../tools/solve_crash_course.py) · [Derived answers](data/crash-course-single-answers.json)

## Day 26 · Time Trial (untimed scoring)

Route: `binary-reverse-engineering-day-26-crash-triage/time_trial`  
Attempt: `c4c1e1cf-e152-43db-aba4-2f2c0cbbae68`  
Started: 2026-10-26 14:14:18 UTC; `run_for_time: false`, no deadline, no Hall of Fame eligibility.

[Assigned archive](data/crash-course-tt-evidence.zip)  
SHA-256: `26728800b133646ec0a374880122c80e9d6d1bc8079c0ab9250600315ab0d809`

The same static workflow derived all 312 answers from the fresh assigned bytes. The complete batch was accepted on its first valid submission; personal status confirmed `CORRECT`, without pending scoring. Day 26 JAR SHA-256: `eefe8279a9bc57a191ff4f3b2c4396b7374110266b16946ecc9b66557f94238f`. Its fault frame is `stageThree`; all three trace frames match the 10-method primary class.

Flag: `bdf1afd836bf2290d3f1158817eccdc0`.

## Day 26 · Mastery (untimed scoring)

Route: `binary-reverse-engineering-day-26-crash-triage/mastery`  
Attempt: `69ab59b2-e874-441f-ae0c-6cd313df84f3`  
Started: 2026-10-26T14:15:21.843Z; `run_for_time: false`, no deadline.

[Complete assignment and all 3,120 questions](data/crash-course-mastery/start.md)

All ten assigned archive SHA-256 values were verified before extraction:

1. [Set 1 archive](data/crash-course-mastery/set1/evidence.zip): `068f48841d5b81ce05f653febf01a9ba67b5fa2a48064f1441ef268b92ad8a64`
2. [Set 2 archive](data/crash-course-mastery/set2/evidence.zip): `9192fe8d2da264f37c021f03ea3492c762ac819dfd75a4be084e56411455cd00`
3. [Set 3 archive](data/crash-course-mastery/set3/evidence.zip): `a439e0d94a44167b1844eecb3adb24555ac8ef3b86452f755b44dc20ef6ca6e8`
4. [Set 4 archive](data/crash-course-mastery/set4/evidence.zip): `ebe16827ad11568af0215032b9784dd4b5b366500b4bc4e10dac0c7456985697`
5. [Set 5 archive](data/crash-course-mastery/set5/evidence.zip): `53acb111c65925fb25fc2393540e511f78932913fcd57dfb6b9e2114d6443d22`
6. [Set 6 archive](data/crash-course-mastery/set6/evidence.zip): `51be7a29a1e9b5b03723e8a1466de4c8facabe5319e9ed76e98005274c9cc449`
7. [Set 7 archive](data/crash-course-mastery/set7/evidence.zip): `4edacaadb72735fc43cf9d070f6fd670d2274ceb6fc9fef6f9ccefab0f23e592`
8. [Set 8 archive](data/crash-course-mastery/set8/evidence.zip): `b06fad06e8cf51f292553e1652662944068999c0741dd349c6a9357ae51f627a`
9. [Set 9 archive](data/crash-course-mastery/set9/evidence.zip): `006447e9c077153677ece6f1371864b7ad398fdb2e3e577699ff9f02e6c50b79`
10. [Set 10 archive](data/crash-course-mastery/set10/evidence.zip): `fa830e6805ce4490058a027d8d38c3911c9de9215b4d09b8b1a85879bbf48a7f`

Every mastery set was analyzed independently from its verified assigned bytes using the static parser. The combined 3,120-field submission was below the 4 MiB request limit and was accepted in one batch. Submission and personal status both returned `CORRECT`, without pending scoring.

Flag: `16495402fdf775b9c2a9297fcc194978`.

All three Crash Course modes are complete: 312 Single Solve findings, 312 Time Trial findings, and 3,120 Mastery findings (3,744 total).

## Tools and scripts

Project helper: [`tools/solve_crash_course.py`](../tools/solve_crash_course.py), [`tools/solve_crash_mastery.py`](../tools/solve_crash_mastery.py).
