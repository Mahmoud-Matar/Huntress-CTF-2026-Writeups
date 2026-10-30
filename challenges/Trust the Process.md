# Trust the Process — Single Solve

## Challenge

- **Day:** 14
- **Route:** Single Solve
- **Challenge ID:** `script-analysis-day-14-msbuild-trusted-project-abuse`
- **Attempt:** `49e5d4e9-a656-49c0-aead-c8fd7b0148e6`
- **Artifact:** `evidence.zip` (password: `infected`)
- **SHA-256:** `98b763891adf3fabc82a97dbec0cb2db4e24c44c68f15df09607997af0e07c6d`
- **Result:** accepted (`CORRECT`)

## Approach

1. Verify the assigned `evidence.zip` against the recorded SHA-256, then extract it with password `infected`. Keep the specimens inert: the solve used source and embedded data, not script execution.
2. For each specimen, locate its material constant and the decoder or reconstruction expression that consumes it. Apply the declared byte transforms in source order, then parse the recovered descriptor. Preserve compound field names and the order of values; the rejected first answer map had collapsed compound names and used the wrong delimiter for ordered steps.
3. Map each recovered descriptor field to the exact question and answer ID returned for the active attempt. The assignment covered behavior roles, ordered steps, indicators, host/language details, and wrapper/control-flow classifications across PowerShell, JScript, Batch, VBScript, Python, Bash, Node.js, and polyglot samples.
4. Submit in smaller groups when validation identifies remaining errors. Compare rejected fields against both the question wording and the active reconstruction statement instead of revising already accepted answers.
5. For `staged-handoff.bat`, inspect the statement that builds the descriptor: it concatenates four fragments with `set` in a `FOR` loop body. That statement executes directly; the loop does not call a subroutine and is not a one-item iteration. The accepted `batch-chain-control` value is therefore `direct`.

No solver source or exact command transcript is retained in this report, so the evidence supports the reasoning and the disputed classification but not a fully runnable reconstruction of all answers. The assigned archive and answer IDs are required to reproduce the entire submission.

## Decisive control-flow finding

In `staged-handoff.bat`, the descriptor reconstruction occurs in the body of a `FOR` loop that calls `set` to concatenate four fragments. The loop body performs the reconstruction directly; it does not route that statement through a subroutine, and the loop has four items rather than a one-item iteration. The accepted value for `batch-chain-control` was therefore `direct`.

## Submission and verification

After correcting that final field, the Game Master returned `CORRECT` for the Single Solve. The final completion flag was `dc6bf03fdfdd2ec048580a8d372670e5`.

## Time Trial

The first Time Trial attempt was started with the ranked timer enabled (attempt `52649e47-162b-4b6e-a53b-05f58c14e646`, 50-second deadline). It expired before the answer batch arrived. I then requested a fresh untimed Time Trial variant (attempt `7b692c17-6d0e-4361-9e5a-ca5b29b9aeed`) and analyzed its downloaded archive, SHA-256 `74ec464e62c0508dbdede55d9739926a7bcfdb062f53436014e01e0c7a50c8c9`.

For this variant, the descriptor decoder formats varied across the specimens. I reconstructed the descriptors from each file's inert byte material and visible transform, including rolling XOR in the JScript dropper, split batch fragments, Bash hex and decimal material, escaped Node.js octets, and percent-encoded script data. I submitted all 971 findings under the exact returned answer IDs. The Game Master returned `CORRECT`; this untimed retry completes and scores the Time Trial route, but it does not count as a ranked timed finish. Its completion flag was `8929f89b1d83daff1eb3c857c91a8b1b`.

## Mastery

The Mastery route used attempt `2447ddd8-d789-4909-b4f5-7812aca6c948` and one untimed bundle with five assigned evidence archives. The fifth archive was `script-analysis-day-14-msbuild-trusted-project-abuse-mastery.zip`, SHA-256 `f562e5b6325309b72973c5cb672807ceaae780d20790dba766f61eb4f7a11265`.

I solved the bundle statically from the assigned bytes. The set included 4,855 answer fields; I extracted each archive, reconstructed the encoded descriptors and script behavior, and submitted the fields using the exact IDs from the Mastery start response. The Game Master returned `CORRECT`, with completion flag `eed3a7c58182b9190cc8ef5a8651c1af`.

*Writeup organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
