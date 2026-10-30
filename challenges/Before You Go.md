# Before You Go — Day 26

## Single Solve — assignment retrieved, lesson pending

- Route: `metadata-forensics-day-26-before-you-go`
- Attempt: `5b643b1b-8a22-43c2-9a05-0bb44f2889be`
- Started: 2026-10-26 14:03:44.591 UTC; untimed, no deadline.
- Prompt: Prefetch evidence records what Windows prepared to execute even after filenames changed. Recover executable identities and connect execution traces to the correct hosts.
- Question: Determine `prefetch.executable_name` for `trace-001.pf`.
- Answer ID: `d26-prefetch-001-prefetch-executable-name`.
- Format: exact artifact-derived value, without quotes or explanatory text; literal `none` only when absent. Normalization: trim.
- Archive: [metadata-day-26-evidence.zip](data/artifacts/before-you-go/metadata-day-26-evidence.zip), 3943 bytes.
- Verified SHA-256: `de23c0842380e7db67a452debc91d6732d0e34072dd5f9bd4db8a7f07538eb0a`.
- Assigned download: https://2026.huntress.ctf.games/?op=download&capability=b65a5b7ad1a3462fbe03c2ac1b0e85fff70ae381b7824d6baf80fee576af50af (requires paired authentication).
- Archive member: `trace-001.pf`; preserved locally without execution.

The live day list was fetched twice and personal status checked twice. This route returned `start_required` before start. The user's requested focus is this challenge's three modes. No answer submitted and no points claimed.

Required public CourseStack lesson text is unavailable: no connected CourseStack browser, and Homebase 10.0.0.219 is unreachable from the workspace. Requested public lesson text from the user per AGENTS.md. Preserve current attempt pending that input.

Existing automation `huntress-ctf-day-8-progression` is ACTIVE, daily at 13:15 UTC. This work was manually initiated at the user's request; the schedule was not changed.

## Single Solve — confirmed complete

Resumed through the existing paired Game Master script at the user’s direction; the user instructed using Game Master in response to the unavailable CourseStack lesson. Decompressed MAM/XPRESS-Huffman using installed Dissect, checked the SCCA signature, read the 60-byte UTF-16LE executable field at offset 16: `CMD.EXE`. Game Master submission and status returned CORRECT. Flag: `beff5f61646f0b74bb249647e3c6abfe`.

## Time Trial — confirmed complete

Attempt `be47c062-362a-4811-a24e-603e4ae93706`, started 2026-10-26T14:13:07.931Z, regular untimed scored variant. Archive SHA-256: `7fb5160a3f7320efe39011f05324fa2ee73c19a65288d2dec1e493207aaf9f98`. Parsed all 23 assigned files statically and derived 31 answers with [tools/solve_before_you_go.py](../tools/solve_before_you_go.py). Read audio format from the M4A container despite its .wav filename. Parsed Mach-O universal architecture headers, EVTX record boundaries, registry root cell, and compressed Prefetch header (`OBSIDIAN4.EXE`). Initial batch rejected; per-field diagnostics accepted 29 fields and isolated ZIP list ordering and MSI GUID formatting. Sorted ZIP names lexically, and preserved MSI Property-table ProductCode including uppercase and braces. Final full batch and status returned CORRECT at 2026-10-26T14:19:13.043Z. Flag: `401bbf686d5e79fad28a6ded14102b88`. No pending scoring status. Full assignment and answer map are in artifacts/before-you-go/.

## Mastery — confirmed complete

- Route: `metadata-forensics-day-26-before-you-go/mastery`.
- Attempt: `88acffc8-ee6e-430e-8962-0b8f005de8d4`; started 2026-10-26 14:19:39.746 UTC; untimed, no deadline.
- Assignment archive SHA-256: `51d517f03abe64539f5e728174deecb30619e5da80f524b2a29ada9ecad7af58`.
- The archive contained ten nested evidence ZIPs and 310 answer fields. Downloaded bytes were hash-checked against the Game Master assignment and analyzed locally; answer IDs came from the active start response.
- Generated the answer set from the assigned files. The analysis covered note and roster hashes, binary magic, image dimensions, PDF and nested ZIP metadata, PE/ELF/Mach-O fields, .NET and MSI GUIDs, LNK targets, OOXML relationships, email headers, audio/video metadata, APK/JAR metadata, SQLite page sizes, EVTX counts, registry hive names, Prefetch executable names, and per-set SHA-256 ordering.
- The first full submission was rejected. Per-answer isolation found five wrong OOXML relationship arrays (sets 2, 3, 7, 8, and 9); the Game Master expected their external targets in lexicographic order. Corrected those values from the assigned DOCX relationship files, resubmitted them, and received `CORRECT`.
- A follow-up status request returned `CORRECT`; a fresh Day 26 list marked the mastery route and challenge solved.
- The current answer map is preserved at `/tmp/day26-before-mastery-answers.json`; the verified assignment is `artifacts/before-you-go/before-mastery.zip`.

## Tools and scripts

Project helper: [`tools/solve_before_you_go.py`](../tools/solve_before_you_go.py).
