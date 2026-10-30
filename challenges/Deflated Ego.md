# Deflated Ego

## Day 22 · Single Solve

- Challenge ID: `warmups-day-22`
- Attempt: `bf1afd18-87d0-41b2-b2eb-796c5ff5e3eb`
- Timer: untimed.
- Assigned artifact: `blob.txt`
- Artifact SHA-256: `fbf0cb9c85acb73b495afcc72be97077753da140cc44236c4b6c72f8ed794fcf`

The blob was Base64-encoded zlib data. After Base64 decoding and fully inflating it, the final non-empty line instructed submission of `tidy-cloud-tulip-70`. The Game Master accepted that value and a status recheck returned `CORRECT` with flag `c69da8bf50be6ddee44c1e840f1ca45f`.

### Reproduce the decode

Put the assigned `blob.txt` in the current directory and run this with Python 3. It checks the assigned bytes first, then Base64-decodes and fully inflates the zlib stream. Looking at the final non-empty decoded line avoids mistaking intermediate compressed text for the answer:

```bash
sha256sum blob.txt
python3 - <<'PY'
import base64
import zlib
from pathlib import Path

encoded = Path("blob.txt").read_bytes().strip()
decoded = zlib.decompress(base64.b64decode(encoded))
lines = [line.strip() for line in decoded.decode("utf-8").splitlines() if line.strip()]
print("final non-empty line:", lines[-1])
PY
```

For this Single Solve artifact, `sha256sum` should report `fbf0cb9c85acb73b495afcc72be97077753da140cc44236c4b6c72f8ed794fcf`, and the final line is `tidy-cloud-tulip-70`. Submit that decoded line, without the label or surrounding explanation, under the answer ID returned by the Game Master. This is local decoding evidence; the accepted result and flag below are the separate server-side verification.

## Day 22 · Time Trial

- Challenge ID: `warmups-day-22/time_trial`
- Attempt: `505f61be-90e8-4656-8773-46e97db45cd2`
- Timer: no deadline was returned; the attempt was untimed.
- Assigned artifact: `blob.txt`
- Artifact SHA-256: `a34e35ad23ea6c8fc037bebb5f160266001ac02f4e080edbede5e43a2f23c5d2`

I verified the fresh blob's SHA-256, Base64-decoded it, and inflated the zlib stream. Its final non-empty line instructed submission of `merry-raven-marble-32`. The Game Master accepted it; status returned `CORRECT` with flag `2a1355f8e572731ea391bc01f800773f`.

The same script above reproduces this route when run in a directory containing its assigned `blob.txt`; the expected SHA-256 for this distinct artifact is `a34e35ad23ea6c8fc037bebb5f160266001ac02f4e080edbede5e43a2f23c5d2`, and its final non-empty decoded line is `merry-raven-marble-32`. The Time Trial attempt was untimed, so there was no deadline to race.

## Day 22 · Mastery

- Challenge ID: `warmups-day-22/mastery`
- Attempt: `51c649a1-fa04-479b-8ad2-95f4f9fd837e`
- Timer: untimed; ordinary start, no deadline returned.
- Assigned archive: `warmups-day-22-mastery.zip`
- Archive SHA-256: `919e7169dbe4c2fd21158fc754c9616ac143273ff095b02af256be5f2a6e4d4e`
- Contents: 108 text blobs (`blob-01.txt` through `blob-108.txt`), opened with the published archive password `infected`.

Each blob contains 22 numbered fragments. I decoded them in order: Base64, ROT13, hexadecimal, binary ASCII, decimal ASCII, octal ASCII, URL encoding, numeric HTML entities, JSON Unicode escapes, Base32, padded Base64, reversal, Atbash, Caesar shift, ROT47, Morse-to-hex, five-bit groups converted to hexadecimal nibbles, three-rail fence, UTF-16LE, UTF-16BE, Base64 plus gzip, and Base64 plus zlib. Concatenating the decoded fragments reconstructs the instruction and the unique slug for that set. The script verified all 108 values against the required `word-word-word-00` format before submission.

The Game Master accepted all 108 answers. A personal status recheck returned `CORRECT` with flag `03f28b2d64a67430cf9b710f6f6c76b3`.

For independent reproduction, extract the assigned archive using the published password `infected`, then apply the 22 transformations in the listed order to each blob's numbered fragments. Keep the fragment order intact, concatenate the decoded pieces for a blob, and use its final non-empty line as that set's submission value. The recorded evidence does not preserve the full per-fragment solver implementation or extracted blob bytes, so this report intentionally documents the verified transform sequence and server result rather than presenting unverified solver code.

*Writeup structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
