# Bind Over Matter — Single Solve

## Assignment

- Challenge: `script-analysis-day-10-wmi-persistence-reconstruction`
- Mode: Single Solve (untimed)
- Attempt: `4ef01305-0031-4519-9947-f1dc8b5697d5`
- Artifact: `evidence.zip` (85,552 bytes)
- SHA-256: `c21e43b382a0cc1a6082dc7d241bcd66a11b995e7f983ae3e62a397af756d475`
- Result: `CORRECT`, 753 of 753 answer fields accepted
- Flag: `e73e98eeca42d1786618c0ea72529198`

## Analysis

I downloaded the archive assigned to this attempt, checked its SHA-256, and extracted it with the published password `infected`. The 89 files were analyzed statically; none of the challenge scripts or binaries were executed.

The answer set spans several scripting and packaging formats. Encoded PowerShell data was decoded as Base64 JSON. JScript, Batch, VBScript, Python, Bash, and Node.js specimens were reconstructed from their embedded constants and declared codecs. PHP and Lua polyglot records were decoded from their text descriptors. I used the decoded ordered steps, adapters, campaign identifiers, indicators, and control-flow details to fill the exact answer IDs returned by the Game Master.

The four WMI/MOF fixtures each contain a custom `HuntressAnalysis_*` class with a string `Descriptor` instance under `root\\subscription`. Their descriptors use different encodings (hex/Base64, fragmented hex, plain hex, and Base64). Decoding those strings yielded the role, ATT&CK mapping, adapter, campaign, indicators, stage count, ordered steps, host profile, obfuscation profile, stage profile, and next language. These files did not contain `__EventFilter`, consumer, or `__FilterToConsumerBinding` instances, so their custom descriptor classes alone did not establish a working WMI event subscription.

Two additional Bash fixtures exercised here-document and here-string syntax. Their static descriptors both specified the analysis graph `recognize_syntax>reconstruct_intent`; the rubric accepts the parent Command and Scripting Interpreter technique `T1059` for these specimens.

## Submission

The first combined submission was rejected. I split the answer map by format to isolate the error. The Batch impact specimen’s `control` field was the only incorrect field: the reconstruction statement used CALL-double expansion, but was not inside a subroutine wrapper, so the correct control-flow classification was `direct`. After correcting it, all 753 exact answer IDs were accepted. The Game Master status endpoint confirmed the completed attempt.

## Time Trial

- Mode: Time Trial (the route starts timed by default)
- Successful attempt: `e3007896-afce-4038-930b-74494c03a9c1`
- Deadline: 2026-10-23 01:40:11.706 UTC
- Artifact SHA-256: `efb18ce3694ca6ca3c9ebf6596e27f449cb389279b8b30a3925caafd77515d74`
- Result: `CORRECT`, all 753 fields accepted and status verified
- Flag: `cc66fb48cc502a1c3b40a52ea8b0bdc6`

The first two fresh timed variants expired while I was adapting the parser to their changed JScript encodings. On the third variant, I statically decoded the artifact, checked its hash, generated and validated 752 answer fields locally, then submitted those fields and the remaining Batch control-flow answer before the deadline. For its Batch impact fixture, the descriptor reconstruction used `for_indirect` expansion and the outer control classification was `direct`.

## Mastery

- Mode: Mastery (two evidence sets under the shared 80-second timer)
- Successful attempt: `01077bc7-d299-47ef-b2c4-480453e82884`
- Deadline: 2026-10-23 01:57:05.878 UTC
- Artifact: `script-analysis-day-10-wmi-persistence-reconstruction-mastery.zip`
- Artifact SHA-256: `2be2b8c5ea9c8e5af46f5494809a74a47d9feee950f0f6d8787ce3d632b2800b`
- Evidence set 1 SHA-256: `8677133843b8dda359e54c9123f02db73c38076a24ed81821ba161a7d4e6d930`
- Evidence set 2 SHA-256: `1a6c5fb2317a716122fee3f9971b78ffea8dd64c91dac0f7a9c27863855abca0`
- Result: `CORRECT`, all 1,506 answer fields accepted; verified by `/status`
- Flag: `7911a9579d2c1728cd8462077aed9323`

I extracted both password-protected evidence sets with `infected` and reused the static reconstruction approach from the earlier modes. The mastery specimens included additional JScript codecs, including percent-encoded bytes with a repeating XOR key, reversed arrays with rolling XOR, and arithmetic transforms. I decoded the assigned bytes locally and submitted the two sets using the exact `set1.*` and `set2.*` answer IDs from the start response.

The first full batch exposed one wrong Batch control-flow classification. In set 1, the reconstruction path jumps to `:HUNTRESS_DISPATCH`, so the wrapper is `goto_dispatch`; set 2 reconstructs the descriptor directly and is `direct`. Correcting set 1 to `goto_dispatch` produced `CORRECT`. The Game Master status confirmed 1,506 of 1,506 accepted fields.
