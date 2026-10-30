# Mixed Signals — Day 26

Challenge family: `script-analysis-day-26-beam-message-flow`.

Description: An Erlang escript passes messages between processes, and some of its indicators look suspiciously familiar. Trace the message flow, and separate the true cross-language indicators from deterministic collision decoys planted to look like old friends.

All analysis used the current playthrough's downloaded bytes. No specimen was executed. The paired Game Master credential stayed private on Kali.

## Single Solve — confirmed complete

- Attempt: `03607ab0-a8c2-4b15-865e-5209a11999a0`; untimed, started 2026-10-26 14:04:45 UTC.
- Archive: [evidence.zip](data/artifacts/mixed-signals/single-evidence.zip), SHA-256 `f2c857779744caf0a2f99191e3bce6795ee8e839241a121e468fac48d7c8dce5`.
- [Complete assignment](data/artifacts/mixed-signals/Single%20Solve%20assignment.md): 1,615 exact answer IDs and question formats, with all API instructions.
- Extracted 171 files with the `infected` archive password documented in AGENTS.md. Recovered literal descriptors using Base64, hex, byte-array transforms, fragment assembly, and the layered encoding profiles recorded in the specimens. The JScript uploader required reversing its literal byte array then subtracting 2 modulo 256; its graph was `locate_local>prepare_transfer>upload_remote`.
- The API transport requires string values, even for integer-format answers. A submission containing JSON integers was rejected as invalid before grading.
- Grading required `if_guard` for the batch stager's guarded initialization. The two batch FOR /L wrappers were graded as `call_subroutine`, despite the current questions describing an outer one-item loop as `for_once`. Preserve that discrepancy when interpreting these answers.
- Full submission and subsequent personal status both returned `CORRECT` on 2026-10-26 at 14:13:18 UTC. No pending scoring status was returned.
- Flag: `a7e1956003c890822bfa94bf34288575`.
- [Validated answers](data/artifacts/mixed-signals/single-answers.json) and [decoded descriptors](data/artifacts/mixed-signals/single-answers-descriptors.json).

## Time Trial — confirmed complete, regular untimed run

- Route: `script-analysis-day-26-beam-message-flow/time_trial`.
- Attempt: `3ba82f36-122c-4879-9349-5e70db203df4`; started 2026-10-26 14:13:47 UTC, no deadline, `run_for_time:false`, no Hall of Fame eligibility.
- Fresh archive: [evidence.zip](data/artifacts/mixed-signals/tt-evidence.zip), SHA-256 `6f2df474831d313d4b7f9c301d4cc2ff36ba5b8451f6472d8391628a09bc3b41`.
- [Complete assignment](data/artifacts/mixed-signals/Time%20Trial%20assignment.md): 1,677 exact answer fields across 171 files.
- Decoded each renamed specimen independently. Reconstructed combined syntax-style fields and derived URL hosts, path leaves, campaign tokens, and behavior graphs from the assigned descriptors. No challenge script was executed.
- Full submission and personal status returned `CORRECT` on 2026-10-26 at 14:16:37 UTC. No pending scoring status was returned.
- Flag: `bd86ba22265e4fb7a7eb551a0386edad`.
- [Validated answers](data/artifacts/mixed-signals/tt-answers.json) and [decoded descriptors](data/artifacts/mixed-signals/tt-answers-descriptors.json).

## Reproduction

[tools/solve_mixed_signals.py](../tools/solve_mixed_signals.py) reuses the project's static parsers, adds the literal arithmetic transform, and handles both assignment schemas. It validates coverage of every assigned answer ID, enum membership, integer syntax, and string transport values. Run it with the start JSON, extracted artifact directory, and output answer JSON as its three arguments.

## Mastery — confirmed complete, regular untimed run

- Route: `script-analysis-day-26-beam-message-flow/mastery`.
- Attempt: `48836f12-d2f1-428b-9d8c-35350a1752a7`; started 2026-10-26 14:17:23 UTC, no deadline, `run_for_time:false`, no Hall of Fame eligibility.
- Fresh [assigned bundle](data/artifacts/mixed-signals/mastery-evidence.zip), SHA-256 `65d36ae26c5ec08c238244f66fc6af889deb57cae84ab9ab76f6162c509b8db2`.
- [Complete assignment](data/artifacts/mixed-signals/Mastery%20assignment.md): 16,770 answer fields across ten evidence sets, each containing 171 files. [Inner archive hashes](data/artifacts/mixed-signals/mastery-inner-hashes.json) preserve a SHA-256 for each assigned set.
- Applied the static decoder separately to all 1,710 files. Set 8 used a JScript `storedMaterial` hexadecimal array with XOR key 223; recovered its JSON directly without running its source.
- Combined all ten sets and verified exact answer-ID coverage and string transport types. The payload was approximately 1.1 MB, so all answers were submitted in one request.
- Full submission and subsequent personal status returned `CORRECT` on 2026-10-26 at 14:19:19 UTC. No pending scoring status was returned.
- Flag: `cda290fa5860a34b7f13106872b59641`.
- [Validated combined answers](data/artifacts/mixed-signals/mastery-answers.json); set-specific answers and decoded descriptors are retained alongside them.

Mixed Signals completion: **3/3 modes confirmed**. Time Trial and Mastery were regular untimed scored runs; ranked attempt pools were untouched. The existing Huntress progression automation was already active when this user-requested run began; its schedule was not changed.

## Tools and scripts

Project helper: [`tools/solve_mixed_signals.py`](../tools/solve_mixed_signals.py).
