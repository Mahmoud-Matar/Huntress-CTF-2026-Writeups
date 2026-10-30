# AutoIt Takes Two — solution write-up

## Challenge

**Day 12, Script Analysis — AutoIt Takes Two** (`script-analysis-day-12-autoit-workflow-pair`)

The challenge asks us to correlate two inert workflow bundles and distinguish the genuine chain from the decoy. It rewards exact reconstruction of descriptors, behavior graphs, indicators, language-specific details, and the corresponding ATT&CK mapping.

## Method

1. Use the exact archive assigned to the active mode, verify its SHA-256 against the table below, and extract it with the published password `infected`. For a mode containing multiple workflow sets, keep each assigned set associated with its own answer-ID prefix.
2. Treat every specimen as inert source and data. Locate the encoded material and its codec declaration; reproduce the listed transformations in their stated order. The observed forms included Base64 followed by byte addition, XOR-decoded hexadecimal, reversed Base64 bytes, numeric arrays with rolling XOR, and escaped Unicode bytes.
3. Parse the recovered descriptor and preserve its exact values: ordered `steps`, adapter, campaign identifier, stage count, graph type, URLs and paths, next-stage names, and user-agent strings. Answer language-specific syntax questions by reading the relevant source statements, not by inferring from the file extension.
4. Classify the behavior by following the ordered graph to its terminal action. A `decode_embedded` followed by `write_file` is a dropper; a chain that acquires a remote stage, writes it, dispatches it, and hands off to another script is a staged chain. Apply the question's stated ATT&CK precedence: use the requested language-specific Command and Scripting Interpreter sub-technique for terminal script dispatch, ingress transfer where the rubric specifies it, and `none` for benign decode-and-return utilities.
5. Submit small answer batches under the exact answer IDs for the active attempt. The Game Master reports the remaining field count after each accepted batch; use that feedback to isolate rejected fields and revisit the corresponding source bytes or question rubric. This is how the incorrect classifications were corrected without replacing accepted answers.

The report preserves the archive hashes and the broad decoding/validation method, but not the full question-ID answer maps or solver source. Reproducing the complete answer sets therefore requires the original assignment response and its exact archive bytes; the mode-specific hashes and outcomes below are retained as evidence.

## Assigned archive hashes

| Mode | SHA-256 |
| --- | --- |
| Single Solve | `8fc31386a080f336c60844a0bc7a47fb3a8fe168d67a1756dc3cbf2b1b6c1215` |
| Time Trial | `7039fc2c80e421c8420162cbf0a290acb181735df40004165f13a410e66d4cd4` |
| Mastery | `02b683c3705822e6cceabb6034b67bd49abcd1e132a38baa0728d9af1846ce99` |

## Results

- **Single Solve:** completed and accepted. Flag: `3f3e2301f172302bc21ab80ffde40d9e`.
- **Time Trial:** the ranked timer expired before completion. I continued on the Game Master’s documented practice route, completed the assigned set, and received flag `4ed25c47e970af0c22e2244bfcd47ff7`. This is a completed mode, but it did not earn a ranked time or Hall of Fame result.
- **Mastery:** the ranked timer also expired before completion. I continued through the documented practice route, statically solved both assigned sets, and received flag `61fac62319d75dfad9fa2b03cdf79892`. This is a completed mode, but it did not earn a ranked time or Hall of Fame result.

*Writeup organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

The Game Master list showed all three modes solved for the Jinzo team after these completions.
