# Rotten Base

## Day 29 — Single Solve

- **Route:** `warmups-day-29` (Single Solve; untimed)
- **Attempt:** `4002306e-45c7-4dbd-a1d6-213be879352c`
- **Prompt:** “Sixty-four invited thirteen over. Things got scrambled.”
- **Assigned artifact:** `blob.txt`
- **SHA-256:** `936089f8e7105cafa048bd6886a37f8f0db1f54708c2254faeefbd9dda51b9ad`

### Analysis

Downloaded the assigned blob through the authenticated Game Master endpoint and verified the SHA-256 before analysis. The hint points to Base64 (64) and ROT13 (13). Base64 decoding first produces binary-looking bytes, so applying ROT13 to the Latin-1 representation reveals the text. Reversing the order does not produce the instruction.

The final non-empty decoded line instructs submitting a three-word hyphenated slug followed by a two-digit suffix. Submitted that exact slug under answer ID `message`.

### Result

Game Master submission returned `CORRECT`; a follow-up status query for the exact route also returned `CORRECT` for this attempt. No timer was active.

## Day 29 — Time Trial (untimed scoring run)

- **Route:** `warmups-day-29/time_trial`
- **Attempt:** `64825f1b-b983-49b5-a49d-0ddec255b244`
- **Timer:** Off (`run_for_time` was false); this route supports optional ranked timing, but no ranked timer was requested.
- **Assigned artifact:** `blob.txt`
- **SHA-256:** `9b8050065d0fd84d8fd044d0256619ae7d8e4421f8492b3b25d980aef94588c0`

### Analysis and result

Fetched the attempt-specific artifact from the Game Master and verified its hash. The transformations differ in order from the Single Solve variant: applying ROT13 to the Base64 text first, then Base64-decoding the result, produces the instruction and answer slug. Submitted the exact slug under `message`. Submission and follow-up route status both returned `CORRECT`.

## Day 29 — Mastery (untimed scoring run)

- **Route:** `warmups-day-29/mastery`
- **Attempt:** `72c6a7ca-de4d-4343-9e03-3412f1bd6475`
- **Timer:** Off (`run_for_time` was false); the route supports optional ranked timing, but no ranked timer was requested.
- **Assigned archive:** `warmups-day-29-mastery.zip` (143 blobs / 143 answer fields)
- **SHA-256:** `e5bf12c2c31e0d17cd7774a7385e2fc715d892f097400558c71ad5c65bb88bdd`

### Analysis and result

Downloaded the assigned archive and verified its hash on Kali, then transferred those exact bytes to REMnux for static decoding. The ZIP contained 143 unencrypted `blob-XX.txt` files. Each blob used numbered fragments in different encodings. The decoded fragments include Base64, ROT13, hexadecimal, binary, decimal and octal character codes, URL and HTML escapes, JavaScript escapes, Base32, reverse text, Atbash, Caesar, Morse-to-hex, UTF-16, gzip/zlib, ASCII85, run-length text, Unicode code points, Brainfuck, Ook, reversed hexadecimal, and ROT13 followed by Base64.

A script applied the identified transforms to the assigned bytes, reconstructed each slug, and validated all 143 values against the returned format (`three lowercase words separated by hyphens, followed by a hyphen and two digits`). Submitted the 143 exact values in one batch under their corresponding `setN.message` answer IDs. The Game Master submission returned `CORRECT`; a follow-up status query for this route returned `CORRECT` for the same attempt.

## Reproduction notes and evidence limits

The two single-file variants can be decoded with Python's standard library from the current directory containing the assigned `blob.txt`:

```python
from base64 import b64decode
from codecs import decode as text_decode
from pathlib import Path

raw = Path("blob.txt").read_bytes()

# Single Solve: Base64 first; Latin-1 preserves each decoded byte as a
# one-to-one character so ROT13 can be applied without discarding bytes.
single_text = text_decode(b64decode(raw).decode("latin-1"), "rot_13")
print(single_text)

# Time Trial: ROT13 the ASCII Base64 text first, then decode Base64.
trial_b64 = text_decode(raw.decode("ascii"), "rot_13")
trial_bytes = b64decode(trial_b64)
print(trial_bytes.decode("utf-8", errors="replace"))
```

For each result, inspect the final non-empty line and submit the exact slug as `message`; this page does not retain those slugs, so it cannot reproduce the flags themselves. The 143-file Mastery archive and original decoder are also absent. Its transform families and format check survive in this report, but the per-file transform map and 143 decoded answers do not. The recorded Mastery result is the past Game Master `CORRECT`, not a new local rerun.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
