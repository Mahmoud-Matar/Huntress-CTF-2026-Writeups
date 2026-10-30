# Back at You — Huntress CTF 2026, Day 12

## Challenge

This warmup asks for the answer slug at the end of an assigned text blob. Each line is encoded separately; decode the whole blob and read its final non-empty line.

## Solution

For Single Solve, the assigned `blob.txt` SHA-256 was `e1143dc727cac903c8456ddb1f85c91ab88c48da6650a1bb4be1cd5c571c2ac9`. Reversing the exact file bytes produced the final instruction, ending with `zesty-sunset-quartz-65`; Game Master accepted that slug.

For Time Trial, the assigned `blob.txt` SHA-256 was `3f4c1210fd9f4124521e09a4f4c45b7b9ee5aa80683a9913c539287abb972ef2`. Reversing its line produced `jaunty-banner-dune-97`, accepted in about 2.6 seconds of the 30-second limit.

Mastery supplied 58 files (`blob-01.txt` through `blob-58.txt`) in one ZIP archive with SHA-256 `e287ad6ea20e523c1b184114603d9730550a5933d063805e83c70d824b38c502`. Each numbered line used its corresponding encoding: Base64, ROT13, hexadecimal, binary, decimal ASCII, octal ASCII, URL encoding, numeric HTML entities, JSON Unicode escapes, Base32, Base64, and reversed text. Decoding each line and concatenating the pieces reconstructed the instruction and that file’s unique slug. I submitted the 58 values under the exact `set1.message` through `set58.message` answer IDs.

## Results

| Mode | Attempt | Game Master result | Flag |
| --- | --- | --- | --- |
| Single Solve | `188d4a0e-a89d-4d4d-9354-8ae23f594de1` | CORRECT | `ee181ba23faf9ff490cb78a134b5ecf0` |
| Time Trial | `ee7187ac-0bc2-41fd-ac47-c6faa3f7c0b2` | CORRECT within 30 seconds | `ec6618480771422ef06e1699df62132e` |
| Mastery | `453b136e-e0a3-46da-aca7-1c1fba932620` | CORRECT within 75 seconds | `c4631504e399e6b8e11b6b1d94730662` |

Repeated Day 12 listings and per-mode status checks confirmed all three Back at You routes solved for the player identity.
