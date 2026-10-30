# Integrity Signals

## Single Solve

- **Challenge ID:** `mobile-android-day-25-integrity-signals`
- **Attempt:** `5cb17ae9-38a6-4a17-9723-f6fe148f29f1`
- **Mode:** Single Solve, untimed
- **Assigned artifact:** `integrity_signals.apk`
- **SHA-256:** `799f97a4917a2232edeec0985720501412cf3cefe2f56143d427f0421562ea1d`
- **Answer field:** `answer`

### Analysis

Inspected the APK as a ZIP and extracted its puzzle JSON asset and DEX without executing the package. The asset declared a hex codec; decoding its data yielded the answer in the exact required `ANS-` plus 16 uppercase hexadecimal characters format.

Static DEX inspection showed that the challenge activity accepts the answer and case reference from intent extras or URI query parameters, then builds a WebView request to the challenge-owned evidence route. The client also contains a fixed client-side secret and proof parameter, exposing challenge-owned integrity material in the APK. The local service referenced by the APK was not listening in the Kali environment, so I relied on the assigned artifact for the candidate and the Game Master for authoritative validation.

### Result

Submitted the decoded value under `answer`. The Game Master returned `CORRECT`, and a follow-up status check confirmed the attempt was complete.

- **Flag:** `d3247455f055645833f837849e2e3168`

## Time Trial

- **Challenge ID:** `mobile-android-day-25-integrity-signals/time_trial`
- **Mode:** Time Trial; the route supports ranked timing.
- **Ranked attempt:** `9a42125a-0f8d-4448-acb1-d46f7dd76ad0`, deadline `2026-10-25T20:52:46.896Z`. This run expired before analysis was complete.
- **Scoring continuation:** Explicit untimed retry; fresh variant `95604014-bd57-4d9b-9fa6-0734760a801e`, no deadline.
- **Solved artifact:** `integrity_signals_time_trial.apk`
- **SHA-256:** `8f5be995c81c3eda6e5d9cf3020b1fdc6f3fff1fcaeacf33b4b2e215031a1b17`
- **Answer field:** `answer`

### Analysis

The timed variant used an APK with no embedded answer payload in its puzzle JSON. I extracted and statically inspected the assigned DEX. The release code derives a 64-bit proof through chained integer transforms; two helper routines recover 12-bit values by testing candidates against constants embedded in the DEX. I replicated those routines with 64-bit modular arithmetic, followed the release formatter, and produced the required `ANS-` code. The backend referenced by the APK is loopback-only and was unavailable from Kali and REMnux, so the Game Master was used to validate the computed code.

The timed run expired while I was tracing the transform. Following the live guidance, I retried with `run_for_time:false`; the Game Master issued a fresh regular variant and reported that it was not timed. The solved code was computed from that fresh artifact and submitted to that attempt.

### Result

The Game Master returned `CORRECT`. A follow-up personal status check confirmed completion.

- **Flag:** `6a0f96ef2f1b4b143c1bf2200a13b9f6`

## Mastery

- **Challenge ID:** `mobile-android-day-25-integrity-signals/mastery`
- **Attempt:** `7d548979-5376-4a53-bd12-d829b6f3d635`
- **Mode:** Mastery, untimed (`run_for_time:false`)
- **Answer fields:** `set1.answer` through `set9.answer`

### Assigned sets and findings

The Game Master assigned nine APKs across Days 1, 4, 7, 10, 14, 16, 19, 22, and 25. I checked each downloaded file against its Game Master SHA-256 and analyzed the DEX statically. The first five and sets 8–9 used the same core client-side transform pattern; set 6 added an x86-64 JNI routine, and set 7 used reflective dispatch into one of several DEX methods. I extended a small local DEX evaluator for the additional arithmetic, native routine, switch dispatch, and reflection behavior. I validated the evaluator against the previously accepted Time Trial build before relying on it for this bundle. No APK was executed.

| Set | Case | Assigned artifact | SHA-256 | Result |
| --- | --- | --- | --- | --- |
| 1 | `MOB-01-ACF210FF7F` | `integrity_signals_mastery_01.apk` | `324d29edbdfab28169291d29b11a133bff5e14d41c3592b6d1b9058d315a69fa` | `ANS-06A386AD98FB4EFA` |
| 2 | `MOB-04-6F03E030B5` | `integrity_signals_mastery_02.apk` | `a2097290b2d0553e56ee89ba2ef9a5f22054574001ca2c2935559b39163fbf67` | `ANS-E5F0F9877B4F456F` |
| 3 | `MOB-07-00EAE34C9D` | `integrity_signals_mastery_03.apk` | `b2d410e7f6fe7013557d576e502bb657a9b632d0982b68507cc3150d802fc466` | `ANS-D5701C9AB56225C8` |
| 4 | `MOB-10-6AC606FAAA` | `integrity_signals_mastery_04.apk` | `5817818a32425881af830638fc53a9d222cc58af5b9d423da9aa334c27de549c` | `ANS-97D5877BC0415691` |
| 5 | `MOB-14-BE94D694F4` | `integrity_signals_mastery_05.apk` | `d2495808e6e4622280795a83e49b2175834dcbfd56111a9e5cb9f49f0acdf734` | `ANS-130E96ACA3AF0675` |
| 6 | `MOB-16-F0E7EBF608` | `integrity_signals_mastery_06.apk` | `6488060b9ed40b939f3ef6d6394a7a00951fe955e8804b6e2e96ac30ac0dc3b4` | `ANS-033F4824BA0FDC95` |
| 7 | `MOB-19-E1C2DA46CD` | `integrity_signals_mastery_07.apk` | `67b7d727d495392e67d7381104bd6bed1d0258dba1854134c9a872603fcafa85` | `ANS-4C20113E77DD978C` |
| 8 | `MOB-22-54823F37D3` | `integrity_signals_mastery_08.apk` | `c2485a7fd1353d6fe624e5876a6dfeb3ab77b0656c884c3d236e84e81bd7f3c6` | `ANS-BACC25CDF092FDC0` |
| 9 | `MOB-25-2972DE8A5F` | `integrity_signals_mastery_09.apk` | `73f74181774d33b838ed507949b7fe3542e7a3480c874bc7035579666fb99c35` | `ANS-86759628B3FEE04C` |

### Result

Submitted all nine fields together to the assigned mastery attempt. The Game Master returned `CORRECT`; a follow-up `op=status` check also returned `CORRECT`, and the Day 25 list marked all three Integrity Signals modes solved by our identity.

- **Flag:** `40e8c4ed8b8e1999f54bd481c3d2aa9b`
