# White Box Key Recovery

## Day 29 — Single Solve

- **Route:** `mobile-android-day-29-white-box-key-recovery`
- **Attempt:** `24557212-cb20-458a-a235-1e6835e0ad7a` (untimed)
- **Case:** `MOB-29-2898E911C6`, package `com.huntress.mobile.d29.v2898e911c6dc`
- **Artifact:** `white_box_key_recovery.apk`
- **SHA-256:** `0d6896623fa3755fcc48b67f6c9a72cfcda9baaa75d10794c0b94e0d1c25d532`
- **Submitted code:** `ANS-AB1D78DC8BA4D98C`

### Analysis and result

Downloaded the assigned APK through the Game Master and verified its SHA-256 before static analysis on REMnux. Its `assets/huntress_puzzle.json` supplied a 20-byte hexadecimal data string and key `41`. Reversing the byte-wise table transformation gave each byte as `(cipher_byte - key - 3 * index) mod 256`; the result matched the required `ANS-` prefix and 16 uppercase hexadecimal characters. The DEX also identified the challenge-owned table control and showed the app forwarding a supplied answer for backend evidence. No APK was run.

Submitted the decoded code under `answer`. Submission and a follow-up status query both returned `CORRECT`.

## Day 29 — Time Trial (untimed scoring run)

- **Route:** `mobile-android-day-29-white-box-key-recovery/time_trial`
- **Attempt:** `3b5bc6be-678b-4d11-a61b-59c4bfc80ec0`
- **Timer:** Off (`run_for_time` was false); no ranked timer was requested.
- **Case:** `MOB-29-2F150B1E8B`, package `com.huntress.mobile.d29.v2f150b1e8b6b`
- **Artifact:** `white_box_key_recovery_time_trial.apk`
- **SHA-256:** `504f5922c231ab0597c9a1bba181b646e7560eafa4628dbcd1f0f50ac42b2627`
- **Submitted code:** `ANS-3F3675ECB5A05D1F`

### Analysis and result

The assigned asset declared codec `analysis`, so I decompiled the DEX and traced `Release.code()` back through the token calculation. The code builds a 16-entry table, performs eight rounds of table lookup and 64-bit mixing, then applies the final transforms and formats the result as `ANS-` plus 16 uppercase hex digits. JADX left one register unresolved in the table expression; I checked the smali and preserved the actual dataflow: the lookup byte comes from the high byte of the state after XOR with the selected table entry. An initial reconstruction used the pre-XOR state and was rejected; the corrected static reproduction produced the submitted code. I compiled the decompiled arithmetic with a small local harness and a stub Android context; the APK itself was not executed.

Submission and follow-up status both returned `CORRECT`.

## Day 29 — Mastery (untimed scoring run)

- **Route:** `mobile-android-day-29-white-box-key-recovery/mastery`
- **Attempt:** `307a6de1-dcf5-4a58-8de5-a8ab95734423`
- **Timer:** Off (`run_for_time` was false); no ranked timer was requested.
- **Assigned deliveries:** 13 APK/APKS artifacts, one code per set.

| Set | Case | Artifact SHA-256 | Submitted code |
| --- | --- | --- | --- |
| 1 | `MOB-01-23CDB65FF4` | `681a8e1af27b2ebd53a9f2cb6d91b6b26a5ed8cfeb653e3ba389a2ce6888fc34` | `ANS-1FC9D80D0ACF6D8C` |
| 2 | `MOB-03-4162379A49` | `10ef11eabfcdce0ac7de1a94915ec469fdca6d238788acca82402863c4ab0993` | `ANS-53540A1DB193125A` |
| 3 | `MOB-07-B457827B2C` | `42eba2beefa37cd39b2521bf98be7239677573ab888a7c124c7ecd25f6d07a5f` | `ANS-A2CF1A434C1A1703` |
| 4 | `MOB-09-9E0CCB79AD` | `a4c25af74bcf910d57212c8fd672b6a188c744f967554bf4d94255f2070729b0` | `ANS-358C5616FED62F98` |
| 5 | `MOB-10-011658EA37` | `91c1ccc0efa3e03057d56bdac8b0748738a8005f8acc6bb313ffa15edfcdd28a` | `ANS-BD00D25D7CB1C39B` |
| 6 | `MOB-13-3384ED5C0E` | `ff4e537237d8ed78aaff852114ad581a42beeb1019ca35eda746a336fc6ad2bd` | `ANS-C4147ACDABFE3EEC` |
| 7 | `MOB-15-37C16C65A2` | `7bd1cbab4699fbecebada0b1d478d16c0cfbfb392d35f2a0163433d9d27746df` | `ANS-4D5AB96B6DC9F07F` |
| 8 | `MOB-18-1D85738CA2` | `ee66bd8dce25d1a62df8c6261cc182267f3bdaac22524b4cdc57d83348da8fc5` | `ANS-2AF8ABC687246913` |
| 9 | `MOB-19-9EDC878D66` | `bc51bb1a20ca14e8f93665a6917e6821360ed705fbec0c80989158e6bb784fbe` | `ANS-3E23A3F3C6A0833C` |
| 10 | `MOB-23-DBCDB0EAF9` | `66da699a073615615047b9ca8c387c8204fa9b325b1aa1a4ab13e085753edaf9` | `ANS-96D07974AE86906D` |
| 11 | `MOB-24-2B94AD31B2` | `a23a7740f7a9ae7c7238fb4f4f8f9f9f4fed45b0fdb037e43e9d5f7b1bec25bb` | `ANS-7E1F51CFF5D3F187` |
| 12 | `MOB-26-A36AD36879` | `98e16a5320df0b72d933d8c910979c33ad3e213f5d2fd78be26d4cf6aaa19f28` | `ANS-905987457E062813` |
| 13 | `MOB-29-1748BFEB2B` | `9f833e3b5e31e56c1796202ade53edb30197807bda12425cd03b5d00763179f7` | `ANS-D5D05236248BEB43` |

### Analysis and result

Downloaded all 13 assigned deliveries through the Game Master and checked each file against its returned hash. The APKs were decompiled and their arithmetic was reconstructed from the DEX. I compiled only the decompiled challenge-owned methods into temporary local Java harnesses; I did not install or execute the APKs. Where JADX lost register names in obfuscated expressions, I used smali to recover the values and ordering. The set 7 JNI operation was reproduced from a static disassembly of the APK's bundled x86-64 library. Set 9's reflective dispatch was resolved to its selected methods. Set 12's split-aware code read the assigned feature split's 16-byte asset through a local stub context pointing only to that extracted challenge artifact.

Submitted all 13 values together using `set1.answer` through `set13.answer`. The Game Master returned `CORRECT`; a follow-up status query confirmed all 13 IDs accepted for this attempt.

## Reproduction notes and evidence limits

The report preserves the assigned artifact hashes and submitted codes, but the APK/APKS files, decompiled smali, and temporary Java harnesses are not present in this project. For the Single Solve, the documented inverse is byte-wise: for zero-based byte index `i`, compute `(cipher_byte - key - 3*i) mod 256`; then verify the result has the expected `ANS-` plus 16-uppercase-hex shape. The exact JSON cipher string and complete Time Trial/Mastery algorithm inputs are not preserved, so this write-up cannot independently regenerate all submitted codes. The prior harness results are reported from the retained account, not freshly rerun from unavailable APKs.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
