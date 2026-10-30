# Split Decision — Day 26

## Single Solve — investigation in progress

- Route: `mobile-android-day-26-split-decision`
- Attempt: `7aeb2f37-646d-4b03-bd3b-c0c62545e767`
- Started: 2026-10-26T14:03:56.446Z. Untimed; no deadline.
- Case: `MOB-26-BE982536CB`
- Package: `com.huntress.mobile.d26.vbe982536cbed`
- Answer field: `answer`; exact `ANS-` plus 16 uppercase hexadecimal characters.
- Assignment: Reassemble evidence distributed across base and configuration splits. Submit only the exact backend answer code returned for this case.
- Local assigned artifact: [single.apks](data/artifacts/day26-split-decision/single.apks)
- Archive SHA-256: `98b2c4c91ede6808501aede0045d98f34bed1a1809938061d20a5a2f1dee1449`

Downloaded the assigned archive through the paired Game Master on Kali, transferred its exact bytes to REMnux, and independently verified SHA-256. Archive contains `base.apk` and `feature.apk`. No challenge code was executed.

Static analysis with Python zipfile and JADX found `assets/huntress_puzzle.json` in the base and `assets/huntress_feature.json` in the feature. Base declares codec `split`, parts `["", "ANS-7", "E37D13"]`, and order `[2,0,1]`. Feature supplies `part_index: 0` and part `4754DEA01`. These are puzzle inputs, not a backend-validated answer.

`ChallengeActivity.onCreate` reads `answer` and `case_id` from Intent extras or URI query parameters, then constructs an evidence request to an Android-loopback service at port 19090, attempt `d26-f254936e04f790f6`, passing case_id, the APK-provided client parameter, and proof. The loopback address belongs to the intended Android environment; it is not evidence that this service is available on REMnux or Kali.

Public CourseStack lesson text is unavailable in the current chat/browser environment. Requested the complete public lesson or accessible URL as required by AGENTS.md. Preserve this untimed attempt. No submission has been made; no completion or points claimed. Time Trial and Mastery were verified unstarted.

## Single Solve — confirmed complete

- Resumed the existing attempt `7aeb2f37-646d-4b03-bd3b-c0c62545e767`, started 2026-10-26T14:03:56.446Z; untimed.
- Re-verified the assigned `single.apks` SHA-256: `98b2c4c91ede6808501aede0045d98f34bed1a1809938061d20a5a2f1dee1449`.
- Read `assets/huntress_puzzle.json` from `base.apk`: the three indexed pieces were `""`, `"ANS-7"`, and `"E37D13"`, with the permutation `[2,0,1]`. Read `assets/huntress_feature.json` from `feature.apk`: its `part_index: 0` supplies `4754DEA01` for the empty base slot.
- Applied the permutation as destination positions for the indexed pieces: index 1 fills position 0, index 2 fills position 1, and index 0 fills position 2. This reconstructs `ANS-7E37D134754DEA01`, matching the required `ANS-` plus 16 uppercase hexadecimal characters.
- Submitted under the exact answer ID `answer`; Game Master returned `CORRECT` with flag `592521b158612d20f913dd902f872997`. A follow-up status returned `CORRECT`, and the fresh Day 26 list marked the route solved.

## Time Trial — confirmed complete

- Route: `mobile-android-day-26-split-decision/time_trial`; attempt `c4e1017c-eb88-4c39-beeb-92e409a0dfcc`; untimed scored attempt (`run_for_time: false`), no deadline.
- Downloaded `split_decision_time_trial.apks` through the paired Game Master and verified SHA-256 `6cedb3399706d58e1d39f3ceb9f76aa65ac9feec04e7c5e4e1c7bf49aefce9d6`.
- The bundle contains `base.apk` and `feature.apk`. JADX and apktool were used for static inspection only; no APK was executed. The base DEX computes a token from Probe, Guard, Core, and Mix transformations, then combines that value with two big-endian 64-bit words read from the feature split's 16-byte `assets/huntress_feature.bin`.
- Reimplemented the Java `long` arithmetic with explicit 64-bit wrapping and logical shifts in Python, then applied the final transform and formatted the resulting 64-bit value as 16 uppercase hex digits. The answer was `ANS-2DF27FDEEFEF5A67`.
- Submitted under answer ID `answer`; Game Master returned `CORRECT` with flag `02f2b10cbdc3d4df79a1ff821c3b49ac`. Follow-up status returned `CORRECT`, and the Day 26 list marked the route solved.
- The exact assigned bundle is preserved at `artifacts/day26-split-decision/time_trial.apks`.

## Mastery — confirmed complete

- Route: `mobile-android-day-26-split-decision/mastery`; attempt `40da09b7-2cf9-4f3b-8f0d-d85a1c466939`; untimed scored attempt (`run_for_time: false`), no deadline.
- The assignment contained ten cases. All ten artifacts were downloaded from the authenticated Game Master and SHA-256 checked:

  | Set | Artifact | SHA-256 | Recovered answer |
  | --- | --- | --- | --- |
  | 1 | `split_decision_mastery_01.apk` | `bdbdab34d724eebc01f5276a802a24607be046c1390cea9b138f20c375e85fa3` | `ANS-4743B308D15CEEB1` |
  | 2 | `split_decision_mastery_02.apk` | `94f90352719de7d6c58baa22a0c42ed18640aaa4d65d75ecc309ad58934d5563` | `ANS-9FE593AEC83411BA` |
  | 3 | `split_decision_mastery_03.apk` | `54a2f23c3cd9efe8251143ed26944c15de14b5627094d58c69556bbe61b4d27d` | `ANS-9D6EBB4F865FC627` |
  | 4 | `split_decision_mastery_04.apk` | `8b02513c302c65553afb7f9719990aa899d669dd348d2dacc7b3e201aca54ae3` | `ANS-2B8DD1C36F06B1EB` |
  | 5 | `split_decision_mastery_05.apk` | `1883d02c7f9cd8eed176d096608c60131ad70fc9914463cf298d3092748c446f` | `ANS-8AC2EA10F31D3DD6` |
  | 6 | `split_decision_mastery_06.apk` | `7a811843b6b558d2b344a2e4041c3d5896c149e477db256531bf610738eba019` | `ANS-5D1C012FB5043C83` |
  | 7 | `split_decision_mastery_07.apk` | `486d3a2ed81b0f316216d57d2da9542b823191589046314838870008af3cdc88` | `ANS-513D2BB727C07BCD` |
  | 8 | `split_decision_mastery_08.apk` | `cce9fa39988444942bb8706ba81e4f09d04cee448bf359605de09dcdada16acc` | `ANS-A1F06DCD2D94585B` |
  | 9 | `split_decision_mastery_09.apk` | `1bf8cef2953937ac1b12b8a8f916292410feca6155c77dab97cd102e1761fe55` | `ANS-FF5A119AB5199DBC` |
  | 10 | `split_decision_mastery_10.apks` | `a2d7c021f9c86c4c81af8d7929df44059d7fe78dc1515b88366b9e635ed355da` | `ANS-BD603675DE19471A` |

- JADX and apktool were used to inspect the DEX, manifests, assets, and native library statically. I compiled only the decompiled arithmetic classes into temporary local helpers with a stub Android context; no APK was installed or run. For set 6, I statically inspected the x86-64 `libarena.so` symbols and disassembly, then reproduced the JNI arithmetic in the helper rather than loading the library.
- Recovered each case's code from its own assigned artifact, including Probe/Guard/Core/Mix transforms, the reflection dispatch in set 7, anti-debug gate in set 8, integrity signal in set 9, and base/feature split combination in set 10. The ten exact codes are listed above and were submitted under `set1.answer` through `set10.answer`.
- Game Master returned `CORRECT` with flag `7cd6c5aee7b1d835e02c1c6ec47100a2`. Follow-up status returned `CORRECT`; the Day 26 list marked the route solved.
- The verified artifacts are preserved as `artifacts/day26-split-decision/split_decision_mastery_01.apk` through `split_decision_mastery_10.apks`.
