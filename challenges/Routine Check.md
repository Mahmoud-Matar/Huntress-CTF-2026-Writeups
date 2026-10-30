# Routine Check

## Challenge and result

- **ID:** `binary-reverse-engineering-day-07-kotlin-staging-logic`
- **Mode:** Single Solve; untimed.
- **Attempt:** `37ed7346-34d8-4ca7-97f3-e7b035f5d657`
- **Prompt:** “Kotlin coroutines don't run — they suspend, resume, and hop between states. Reconstruct the state machine from the metadata and figure out what this one was staging.”
- **Artifact:** [Download evidence.zip](https://2026.huntress.ctf.games/?op=download&capability=d665fc8183bf4e41bec6c9e723675fa5f254c76295a0444daded63c1bab067d5) — SHA-256 `0709de6588e6ec7c6b06b7e1a65b1076e15c02f29d19595945de21f3c070131a`; password `infected`.
- **Result:** `CORRECT`.
- **Flag:** `9b2d4dd2634cd0dc673bd66e1223af0a`.

The archive contains the prior Day 1–6 binary samples plus `d07--sample.jar`. I verified the archive hash and extracted it with the published password. No sample was executed.

## Method and recovered Day 7 values

I reused the verified static parsers for the ELF, PE/CLI, and prior JAR members. For the Kotlin JAR, I read `META-INF/MANIFEST.MF` to find `Main-Class`, parsed that class file's constant pool, and Base64-decoded the long UTF-8 constant containing the HCFG record. I accepted the record only after checking its bounds and CRC32, then XOR-decoded and parsed the JSON payload.

| Field | Answer |
|---|---|
| Member SHA-256 | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| Format | `JAR` |
| Campaign | `BR07-000` |
| Domain | `node-000.day07.example.invalid` |
| Mutex | `Global\HuntressBR07_000` |
| URL | `https://node-000.day07.example.invalid/api/BR07-000` |
| HCFG CRC32 | `0xcf3ea232` |
| HCFG version | `1` |

All 56 answer fields matched the Game Master's IDs and were accepted.

## Time Trial

- **Mode:** Time Trial; 50-second server deadline.
- **Attempt:** `9875f325-cd5b-4ee4-9e4e-8a864b9511d9`
- **Fresh artifact SHA-256:** `6f7870bc21aa3c67966c28be9e79507bc52c3aeb33d62489314fee892fd1e17d`.
- **Result:** `CORRECT`; all 56 fields were accepted before the deadline.
- **Flag:** `e49c3422c33eb2a2369412fc2b681d21`.

The same static header, section, metadata, and JAR constant-pool parsers were applied to the fresh delivery. The downloaded archive matched its API-provided hash before extraction.

## Mastery

- **Mode:** Mastery; two sets under one 80-second server deadline.
- **Attempt:** `b61286a3-276d-41d3-b729-8bf037457e52`
- **Artifacts:** two `evidence.zip` files:
  - Set 1 SHA-256: `2d60c897e252afb3dfcd4ba3ecd3052fda0aa8ebf98bea4294b164f1187ee0f7`
  - Set 2 SHA-256: `04ee69fe8463ac722385f043945e0bdee6460dbc20b4c7e34090539fcad3b8a8`
- **Result:** `CORRECT`; all 112 fields (56 per set) were accepted before the deadline.
- **Flag:** `fcabbb6137e5721e796c116dd20f4283`.

Each set's archive matched its API-provided hash. I ran the same static ELF, PE/CLI, and JAR constant-pool analysis on both deliveries, prefixed the results with the set identifiers, and checked all 112 keys against the assignment before submission.
