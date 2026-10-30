# Node by Node

## Challenge and result

- **ID:** `script-analysis-day-07-node-operation-graphs`
- **Mode:** Single Solve; untimed.
- **Attempt:** `acb7d72b-3f39-428f-bc65-6c38ff4477fa`
- **Prompt:** “Eight Node.js operation graphs that will never execute. Spot the indirect expansions and token fragmentation, then sort each graph into its role — benign, staging, dropping, downloading, uploading, launching, scheduled, or multi-stage — from the final bytes alone.”
- **Artifact:** [Download evidence.zip](https://2026.huntress.ctf.games/?op=download&capability=5312e89706a8447e8a78b9cf312f56c77c7ab9eac34f4d1e8e4dc69582efa5cd) — SHA-256 `5e2cadf1264bbf1869647fab33b9f630d7ace1d513d4a21c0f7e400040c61038`; password `infected`.
- **Result:** `CORRECT`; all 469 fields were accepted.
- **Flag:** `a6f9d566529a382e037fe60fd9cbb43e`.

## Method

I verified the archive against the Game Master's SHA-256 and extracted it with the published password. The archive contains the established PowerShell, JScript, Batch, VBScript, Python, and Bash groups plus eight Node.js `.mjs` graphs. All samples were treated as untrusted data and were never executed.

For Node.js, I read each file's declared `Material_` representation and `Codec_` transform, decoded the bytes, and reconstructed the descriptor fields. Formats included Base64, hex, hex arrays, and escaped octets; transforms included identity, byte reversal, single-byte XOR, and rolling XOR. I classified each profile from its ordered `steps` graph and extracted the adapter, campaign, stage count, and profile-specific indicator. I also decoded the two extra Bash syntax fixtures, which describe analysis graphs rather than executable behavior.

The first combined submission exposed the scheduled-profile ATT&CK mismatch. Its `/etc/cron.d` indicator identifies cron persistence, so `T1053.003` was the accepted technique. I submitted that correction and the Game Master returned `CORRECT`.

## Node.js graph findings

| Profile | Role and ATT&CK | Adapter | Campaign | Indicator | Ordered steps |
|---|---|---|---|---|---|
| benign | `benign_utility`; `none` | `console_report` | `NODE-012384B0` | Host `host-012384b0906f` | `decode_configuration > return_configuration` |
| stager | `stager`; `T1105` | `http_then_module` | `NODE-B0D46D5D` | `https://node-b0d46d5d5c4e.example.invalid/api` | `acquire_remote > dispatch_memory` |
| dropper | `dropper`; `T1140` | `typed_array_to_file` | `NODE-24E94026` | `/tmp/huntress-node/.stage-24e94026ef45.mjs` | `decode_embedded > write_file` |
| downloader | `downloader`; `T1105` | `http_to_stream` | `NODE-AB68422D` | `https://node-ab68422d464e.example.invalid/api` | `acquire_remote > write_file` |
| uploader | `uploader`; `T1041` | `stream_pipeline` | `NODE-E383E02B` | `https://node-e383e02be4cf.example.invalid/api` | `read_file > transmit_remote` |
| launcher | `launcher`; `T1059.007` | `execfile_node` | `NODE-18570C55` | `/tmp/huntress-node/.stage-18570c550201.mjs` | `locate_local > dispatch_process` |
| persistence | `persistence_descriptor`; `T1053.003` | `systemd_descriptor` | `NODE-F4B47021` | `/etc/cron.d/node-f4b470` | `build_schedule > register_descriptor` |
| chain | `staged_chain`; `T1059.007` | `fetch_platform_fallback` | `NODE-4C260462` | Service `node-4c2604.service` | `profile_host > acquire_remote > write_file > change_mode > dispatch_process` |

The additional Bash fixtures decoded to:

- `indirect-expansion.sh`: feature `indirect_expansion`, primitive `parameter_indirection`, campaign `BASHX-F434AEA9`, one stage, steps `recognize_syntax > reconstruct_intent`.
- `token-fragmentation.sh`: feature `token_fragmentation`, primitive `array_token_construction`, campaign `BASHX-E4F52183`, one stage, steps `recognize_syntax > reconstruct_intent`.

## Time Trial

- **Mode:** Time Trial, regular untimed route (`run_for_time: false`; no deadline was returned).
- **Attempt:** `0bc8b541-c429-4c2c-9043-6a091d08c55e`
- **Fresh artifact SHA-256:** `c617e714ca1bb831a00a1b317b3c2a21e6c48b517d703266c290a1c9013f6d80`.
- **Result:** `CORRECT`; all 469 fields were accepted.
- **Flag:** `e36528c95abd25a37e4011eae05c7096`.

This delivery added JSON-number and Unicode-escape byte representations, modulo transforms, reverse-then-XOR, and repeating-key XOR. I extended the offline decoder to handle those declared forms, retained the answer-ID equality check, and submitted all language groups together. The archive hash matched the assignment before extraction.

## Mastery

- **Mode:** Mastery, regular untimed route (`run_for_time: false`; no deadline was returned).
- **Attempt:** `a13ca5ea-281f-4d4a-8ead-796814d77a1e`
- **Artifact:** one `script-analysis-day-07-node-operation-graphs-mastery.zip`, containing `evidence-01.zip` and `evidence-02.zip` — outer SHA-256 `17dea6e44cda5ecb66bddec5257bdf3085fdfe7f7beae3db1131dd4582b755fe`.
- **Result:** `CORRECT`; all 938 fields (469 per set) were accepted.
- **Flag:** `f1d976146547f511178253448c0ac6fe`.

Both nested archives were extracted and analyzed independently; their answer maps were prefixed with the set IDs and matched the 938 API IDs. Set 2's `relay-handoff.cmd` had an unconditional wrapper around a four-item `FOR` loop that uses `call set` for expansion. The question explicitly says to classify the wrapper that causes reconstruction; the accepted classification was `direct`, rather than `call_subroutine`. No sample was executed.
