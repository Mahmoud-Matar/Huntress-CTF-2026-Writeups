# Crumb Trail

## Single Solve

- **Challenge ID:** `script-analysis-day-15-credential-store-clues`
- **Mode:** Single Solve (untimed)
- **Attempt:** `42a7e544-d7d8-47dc-a633-df82f5e5dbcf`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `3f603de468657d5f7cd2e6f89311f8456f0b0f78e785e3394b14c8055aa282a5`
- **Result:** Game Master returned `CORRECT`.
- **Flag:** `131a1c04ae466db36ad6864c8c7b951e`

### Approach

I downloaded the assigned archive from the Game Master and verified its SHA-256 before extracting it. The archive contained inert Windows and cross-platform script fixtures plus synthetic browser-store artifacts. I treated the files as data and analyzed the source and embedded descriptors without executing the specimens.

The first three PowerShell samples established the challenge's core distinction: classify the scenario, map each credential-access path to the matching synthetic browser-store artifact, and identify the reference to a store that was absent. I read the source paths and indicators directly, then checked the related code fixtures against those artifacts rather than treating every credential-shaped string as proof of access.

Most of the archive encodes small pipe-delimited descriptors. I followed each fixture's declared loader and decoder from source, then parsed fields such as `steps`, `adapter`, `campaign_id`, and the relevant path, URL, or filename. The encodings included hex and base64 forms, byte offsets, single-byte and rolling XOR, repeating-key XOR, reversed byte sequences, and fragments joined or transformed by language-specific syntax. For each specimen, I mapped the decoded ordered behavior graph to its role and ATT&CK technique using the wording of that specimen's question. I also recovered the syntax and obfuscation labels from the source expressions themselves.

For the Python fixtures, I parsed literal material and reproduced the documented byte transforms in a separate analysis script; I did not import or execute the challenge modules. For Bash, VBScript, and Node fixtures, I likewise extracted the material and applied the visible decoder logic as data transformations. This made exact indicators reproducible and avoided transcription errors across the 1,026 answer fields.

### Submission

I submitted the recovered values under the exact answer IDs returned by the active attempt. The Game Master reported partial accepted progress while the remaining fields were resolved, then returned `CORRECT` once all required findings were accepted. The returned flag is recorded above.

## Time Trial

- **Challenge ID:** `script-analysis-day-15-credential-store-clues/time_trial`
- **Mode:** Time Trial (untimed regular run; `run_for_time` was `false`, so no countdown was running)
- **Attempt:** `5a135992-521a-4994-94b2-6ac1b1ab3482`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `02861860d38c92bacd0e30b162409a0e6be00e6d996aa58a3d56c5a50bde6cf7`
- **Result:** Game Master returned `CORRECT`; status confirmed the same attempt as complete.
- **Flag:** `d9fc194ebabcdba43e4d4a2f38887d48`

### Approach

I resumed the existing attempt rather than starting or retrying, preserving its assigned archive and attempt ID. The attempt had 1,026 answer fields; 809 were already accepted. I statically decoded the remaining Bash descriptors from their embedded `Material` and `Codec` values, then parsed the ordered steps, adapters, campaign IDs, and indicators. For the advanced Bash samples, I recovered the feature, syntax primitive, campaign ID, stage count, and analysis steps. I did not execute any challenge script.

The final 77 fields described inert host wrappers in WSF, HTA, SCT, PHP webshell, Lua OpenResty, and Perl CGI containers. I decoded the declared B64, hex, hex-wrapped base64, and fragmented-hex descriptors and used their exact values for the host profile, encoding profile, stage profile, next language, indicators, and ordered steps. I submitted these fields individually after a grouped request exposed an ATT&CK classification mismatch; each accepted field reduced the Game Master's remaining count. The HTA wrapper's encoded attack value was `T1105`, while the other host-wrapper attack fields validated as `T1059`.

### Submission

The Game Master accepted all remaining findings and returned `CORRECT`. The follow-up status request confirmed the attempt ID and completed result. The challenge list was fetched twice afterward; both passes agreed that Crumb Trail Mastery is the next unresolved Day 15 route.

## Mastery

- **Challenge ID:** `script-analysis-day-15-credential-store-clues/mastery`
- **Mode:** Mastery (untimed; `run_for_time` was `false`, so no countdown was running)
- **Attempt:** `c7b33c26-5d64-4791-9c31-ebd4e5d03ee1`
- **Artifact:** `script-analysis-day-15-credential-store-clues-mastery.zip` (password: `infected`)
- **SHA-256:** `0accb9fdc13dc44c5574d03928f87440bbdba8d10ac6a97cd5ba6966aee541a5`
- **Findings:** 5,130 across five evidence sets
- **Result:** Game Master status returned `CORRECT`; team completion was confirmed.
- **Flag:** `7ca8ed1e59873ceda38ad0667f1cd43b`

### Approach

I resumed the existing attempt and downloaded the assigned archive, then verified its SHA-256 before extracting it. I analyzed the scripts as inert source and reconstructed each descriptor from the operations shown in the file; I did not execute the challenge scripts. The five sets included PowerShell, Python, JScript, Bash, VBScript, Node.js, and Batch fixtures, plus synthetic browser-store artifacts.

For the final JScript findings, I statically parsed the source arrays and packed strings, then applied each visible decoder: repeating-key XOR, rolling XOR, fixed byte offsets, base64, percent-encoded bytes, colon-separated hex, and hyphen-separated decimal bytes. I parsed the resulting JSON descriptors to recover ordered behavior steps, adapters, campaign identifiers, URLs and paths, file extensions, note names, and next-stage names. I classified roles and ATT&CK techniques using each question's stated precedence, and classified function, invocation, and property-access styles from the source syntax. For Batch, I classified the wrapper that actually caused reconstruction to run, following the question's distinction for loop and subroutine nesting.

I submitted the recovered values under the exact answer IDs from the active attempt. The Game Master accepted the findings and the subsequent status request confirmed the attempt as `CORRECT` with all 5,130 questions completed.

## Reproduction limits

The report records archive hashes, result flags, and the static decoding decisions, but does not preserve the full answer maps, a reusable solver source file, or the complete question/answer-ID transcript. It therefore supports reproducing the analysis method, not re-submitting all 1,026 Single Solve fields solely from this page. A replay requires the matching assigned archive and start response. Recreate each descriptor from its own source-level material and decoder in operation order, then map decoded fields to the current question IDs; do not copy the accepted values across modes or mastery sets because those are fresh variants.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
