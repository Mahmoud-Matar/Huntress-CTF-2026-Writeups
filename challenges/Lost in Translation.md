# Lost in Translation — Time Trial

## Result

The assigned Time Trial artifact was analyzed and all 615 answer fields were reconstructed from the downloaded bytes. The Game Master accepted the completed answer set and now reports this attempt as `CORRECT`. The existing pairing token worked when the `token` value was read from the JSON file and sent to the public Game Master endpoint; the earlier 401 came from treating the whole JSON document as the bearer credential. No token value is included in this report.

## Assignment and artifact

- Challenge: 📜 Lost in Translation
- Mode: Time Trial, started as an untimed regular attempt (`run_for_time: false`, no deadline)
- Attempt: `8e513ed3-cd45-4b75-87d0-85b2eb723d7a`
- Archive: `evidence.zip`
- SHA-256: `537201df52e7dc32f6926efa3e3fdc1cf69ea2431e5b0fd3f31caf137504475c`
- Extracted files: 75 (PowerShell, JScript/JavaScript, Batch, VBScript, Python, Bash, Node.js, and PHP)

The archive hash matched the Game Master's SHA-256 before extraction. The archive contained inert challenge fixtures and encoded descriptors; none of the samples were executed.

## Analysis

The task combines cross-language indicator normalization with source-role and behavior-graph classification. I parsed the encoded material from the original files, applied each fixture's declared representation and transform, and recovered the normalized descriptor fields. The analysis covered the shared resource/collection/impact samples, language-specific fixtures, Bash syntax variants, Node.js transforms, host/container examples, and PHP polyglots.

For the obfuscated PHP files, the comment metadata used several transport forms: plain hex, fragmented hex, Base64, and hex-wrapped Base64. I decoded those representations statically, then checked the resulting descriptor fields against the API's exact answer IDs. The normalized fields included role, ATT&CK mapping, adapter, campaign identifier, indicator values, stage count, ordered behavior steps, host profile, obfuscation profile, stage relationship, and next language where requested.

A final completeness check matched all 615 returned answer IDs to reconstructed values, with no missing or empty fields. This establishes that the artifact was decoded locally; only the Game Master's acceptance can establish a solve.

## Submission status

The authenticated request to `https://2026.huntress.ctf.games/` returned `CORRECT` for attempt `8e513ed3-cd45-4b75-87d0-85b2eb723d7a`. A follow-up list showed the Day 8 Time Trial as solved. Its mode was untimed (`run_for_time: false`, `deadline: null`), so no countdown was running. The pairing was not reset or rotated.

As a progression check, a fresh list filtered to Day 5 and later returned no unsolved published routes at the time of verification. The available list extended through Day 16; no newer day was published in that response.

## Mastery Mode

### Result

The untimed Mastery attempt completed successfully. The Game Master returned `CORRECT` for all five assigned sets. No deadline was active and no countdown was running.

### Assignment and artifact

- Challenge: 📜 Lost in Translation
- Mode: Mastery, untimed (`run_for_time: false`, no deadline)
- Attempt: `3b7dcbd9-e67d-434b-a233-bf801bbdfe71`
- Archive: `script-analysis-day-08-cross-language-iocs-mastery.zip`
- SHA-256: `e5fa3469dfd52bb261cff28785e086a06ddcae85f0675133edf235cc5a3c826d`
- Contents: five evidence sets, each with 615 required answer fields (3,075 total)

The archive hash matched the Game Master's value before extraction. Each inner evidence archive was extracted with the published password `infected`. The samples were treated as inert data and analyzed statically; none were executed.

### Analysis and validation

I reused the descriptor normalization approach from the earlier modes and decoded each set's assigned files from the downloaded bytes. The work covered the shared PowerShell indicators; JScript, Batch, and VBScript fixtures; recovered Python packages; Bash syntax examples; Node.js descriptors; PHP polyglots; and host/container metadata. Each representation and transform was reversed before mapping the descriptor into the exact API answer fields.

The API schema check found exactly 615 distinct expected fields per set. The first complete submission exposed several classification mistakes, which I isolated using incremental submissions. In particular, Batch `call set` is a CALL-double expansion form and does not by itself mean the control wrapper is a subroutine; a direct reconstruction line is `direct`. Node.js process dispatch maps to `T1059.007`, while a cron descriptor maps to `T1053.003`. The API accepted the corrected fields and all remaining groups.

### Submission status

The authenticated submission returned `CORRECT`, and a status check for this exact Mastery route confirmed the same attempt ID and correct result. Two repeated `GET ?op=list&day=8` checks showed Lost in Translation solved in all three modes. At that verification, the first unsolved route in API order was Swift Justice Single Solve (`binary-reverse-engineering-day-08-swift-network-configuration`).
