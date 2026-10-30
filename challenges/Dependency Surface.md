# Dependency Surface — Day 27

## Single Solve — confirmed complete

- Route: `mobile-android-day-27-dependency-surface`.
- Attempt: `fcec2c30-9699-46ae-beb6-c46c422a28a7`; untimed Single Solve.
- Assigned artifact: `dependency_surface.apk`, 12,704 bytes; SHA-256 `b366fd1d3bc0a53ff20b57aea54b37c0eb2cbfa646ffa69d3c1a76548213d6df`. Downloaded from the assigned Game Master capability, transferred to REMnux, and verified against the returned hash.
- Static inspection: `jadx` decoded the manifest and DEX. The manifest declares `ChallengeActivity` exported and reachable through a browsable `huntress27://dependency-surface/unlock` VIEW intent. The activity reads `answer` and `case_id` from intent extras or the matching URI query parameters, then forwards them to the challenge-owned local bridge in a WebView. `DependencySurface` identifies the reachable legacy dependency control.
- The assigned `assets/huntress_puzzle.json` declares Base64 and contains `QU5TLTgwMkE5MUMxRkNDQjJGN0U=`. Decoding the asset yields `ANS-802A91C1FCCB2F7E`, matching the requested `ANS-` plus 16 uppercase hex format.
- Submitted under answer ID `answer`; Game Master returned `CORRECT` with flag `853f6ae9582d6a8b9fb6f2c591367708`. A follow-up personal status check also returned `CORRECT`, completed by Jinzo.

## Time Trial — confirmed complete

- Route: `mobile-android-day-27-dependency-surface/time_trial`.
- Attempt: `6b687250-3fba-4782-9001-0e5e30856baa`; used the route's default untimed scored run (`run_for_time: false`, no deadline).
- Assigned artifact: `dependency_surface_time_trial.apk`, 12,704 bytes; SHA-256 `92b405e3fb9527c0614ebfdd341a2c2a6ddb79de0e56e44d60e786c852376925`. Downloaded from the assigned capability, transferred and hash-checked on REMnux.
- `jadx` confirmed the same exported, browsable `ChallengeActivity` entrypoint in package `com.huntress.mobile.d27.v83b6d98b4f8d`. The assigned `huntress_puzzle.json` specifies Base64; decoding `QU5TLUE4NEY5MTdBMDU3NkIxM0M=` gives the required exact backend code `ANS-A84F917A0576B13C`.
- Submitted under `answer`; Game Master returned `CORRECT` with flag `f2adf83cbb65887905feec0f5948a366`. Personal status confirmed `CORRECT`, completed by Jinzo.

## Mastery — confirmed complete

- Route: `mobile-android-day-27-dependency-surface/mastery`.
- Attempt: `87f958cb-65dd-419c-ad82-cd30b2167c0e`; untimed scored run (`run_for_time: false`).
- The Game Master assigned 11 deliveries (sets 1–9 and 11 as APKs, set 10 as an `.apks` bundle). Each downloaded file was checked against its returned SHA-256 before analysis. For each APK, `jadx` exposed `assets/huntress_puzzle.json`; the values were decoded according to each asset's declared codec. The codecs covered plain text, XOR/Base64, a byte-wise Caesar shift, split/reorder, dynamic DEX, reverse, and Base64. The split APK delivery required combining the base and feature split data according to its index/order metadata.
- The dynamic DEX case was decompiled and its backend answer extracted from the assigned payload. All 11 results matched `ANS-` followed by exactly 16 uppercase hexadecimal characters.
- Submitted all exact answer IDs (`set1.answer` through `set11.answer`) in one batch. The Game Master returned `CORRECT`; a follow-up personal status check confirmed `CORRECT`, completed by Jinzo. Flag: `cf52834ce91a18d7d08d3f3a0d22abf0`.
