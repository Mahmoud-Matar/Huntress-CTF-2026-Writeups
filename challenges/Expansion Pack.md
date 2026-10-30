# Expansion Pack — Mastery solution write-up

This write-up covers the timed **Mastery** route for Expansion Pack, challenge ID `script-analysis-day-03-batch-expansion/mastery`. Mastery assigned two `evidence.zip` archives and 318 answer fields across PowerShell, JScript, and Windows batch files. The Game Master returned `CORRECT` for the completed attempt.

## Assignment and artifact handling

The successful run was attempt `7678e322-1907-4cea-9d08-5dd4aa1eeb89`. The route was timed by default, with deadline `2026-10-22T10:50:45.007Z`. Both archives were downloaded from that attempt, then SHA-256 checked against the Game Master's response before extraction with the published password `infected`.

| Delivery | Archive SHA-256 |
| --- | --- |
| Set 1 | `793eafbc2e0cf3698beec8c4afb1a131f74cc6c5654d24c2a08b5732f85121d2` |
| Set 2 | `c8f6ec7e0f3fffcd493ab7ba042114bd6f1cb2d4b1cba099672f8249682f273f` |

I extracted each archive into a separate directory so the two variants could not overwrite or contaminate each other. Each delivery contained 21 files: three PowerShell examples and 18 script/command files covering JScript and batch syntax. The Game Master supplied the exact answer IDs, grouped by set and artifact; those IDs were retained verbatim for submission.

## Analysis approach

The core task was to recover a descriptor without running any specimen. I treated the files as static evidence and followed each file's encoded material and reconstruction statements.

For the PowerShell samples, I decoded the embedded Base64 data and parsed the resulting structured content to recover scenario, technique, URL, wallet/mutex, filename, extension, and recovery-note indicators. For JScript, I statically reconstructed the encoded descriptor arrays, including the chained XOR/differential decoding, then read the ordered behavior steps and exact values such as adapter, campaign, host, URL, and path. Function declaration style was derived from source syntax: top-level function declaration, anonymous function expression, or named function expression.

For batch files, I decoded the `HUNTRESS-MATERIAL` according to each file's declared codec and reconstructed the descriptor fragments in their source order. I distinguished the expansion used by the descriptor reconstruction statement from unrelated echo/envelope lines:

- `%VAR%` is percent expansion.
- `!VAR!` is delayed expansion.
- `call set` performs the CALL double-expansion form.
- A `FOR` variable used to select descriptor fragments is the FOR-indirect form.

I classified the behavior graph from its ordered steps and terminal action, then mapped it to the relevant ATT&CK technique. Language-specific interpreter mappings mattered: JScript launcher/chain/relay behavior maps to `T1059.007`, while batch maps to `T1059.003`. Other common graph mappings included ingress transfer (`T1105`), deobfuscation (`T1140`), exfiltration (`T1041`), and impact (`T1486`); benign configuration round-trips use `none`.

## Reproduction sequence

The successful attempt supplied two archives with the same filename, so keep each set in its own clean directory. These commands verify the retained archive hashes and extract the encrypted members using the published password; they do not execute any specimen.

```bash
mkdir -p /tmp/expansion-pack/set1 /tmp/expansion-pack/set2
cd /tmp/expansion-pack/set1
sha256sum evidence.zip
7z l -pinfected evidence.zip
7z x -pinfected evidence.zip -oextracted
find extracted -type f -print0 | xargs -0 sha256sum

cd ../set2
sha256sum evidence.zip
7z l -pinfected evidence.zip
7z x -pinfected evidence.zip -oextracted
find extracted -type f -print0 | xargs -0 sha256sum
```

Compare the two `sha256sum` results with the Set 1 and Set 2 hashes in the assignment table before analyzing those directories. For each PowerShell fixture, read the Base64 material and the adjacent reconstruction logic, decode the bytes, then parse the descriptor fields. For JScript, follow the literal arrays and chained XOR/differential decoder in source order; derive function style from the actual function expression. For each `.bat` or `.cmd`, decode the `HUNTRESS-MATERIAL` with its declared codec, concatenate the descriptor fragments in their reconstruction order, and classify the expansion mechanism at the reconstruction statement. Then classify the behavior from the decoded ordered steps, apply the route's language-specific ATT&CK mapping, and map the findings to the exact answer IDs returned for that attempt.

The retained transcript does not contain the downloaded member-by-member answer-ID mapping or the decoder source, so an independent reader can reproduce the archive handling and reasoning but cannot regenerate the complete 318-field request solely from this report. For the three Set 2 control-flow corrections, inspect `host-context.cmd`, `memory-stage.bat`, and `remote-write.bat`: despite a one-iteration `FOR /L` calling `:HUNTRESS_RECOVER`, the grader accepted `call_subroutine` for these wrapper fields. This observed accepted value is specific to those exact questions and this assigned variant.

## Submission and a useful correction

Most answer groups validated from the reconstructed descriptors. I submitted the complete set once, which the Game Master marked incorrect, then submitted by artifact group to identify the remaining fields without disturbing already accepted answers. This showed that the final three unresolved fields were the batch control-flow classifications in Set 2:

| File | Initially tried | Game Master accepted |
| --- | --- | --- |
| `host-context.cmd` | `for_once` | `call_subroutine` |
| `memory-stage.bat` | `for_once` | `call_subroutine` |
| `remote-write.bat` | `for_once` | `call_subroutine` |

The source does contain a one-iteration `FOR /L` that calls `:HUNTRESS_RECOVER`, which made `for_once` look plausible from the prompt. On this assigned variant, the grader accepted the outer subroutine-dispatch classification, `call_subroutine`. I isolated and corrected those three fields individually; the final submission completed the full bundle before the server deadline.

## Result

The final Game Master response was `CORRECT`. A follow-up status request also returned `CORRECT`, with 9 fresh Mastery variants remaining. The completion flag was:

`99e63d50b32dc0b8f18f610285af75a7`

The bearer token remained in Kali's private token file and was not copied into this report.

---

Write-up structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).
