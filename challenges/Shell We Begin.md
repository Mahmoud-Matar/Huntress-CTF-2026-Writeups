# Shell We Begin

## Challenge

- **ID:** `script-analysis-day-06-bash-behavior-graphs`
- **Mode:** Single Solve; untimed.
- **Attempt:** `1a511f85-c428-46d2-b7d6-773a9882f241`
- **Prompt:** Six Bash behavior graphs, none of which will ever run. Read them like a native: map the adapters, count the stages, tag the ATT&CK techniques, and pull the exact indicators hiding in the final bytes.
- **Artifact:** [Download evidence.zip](https://2026.huntress.ctf.games/?op=download&capability=406ff6c7e09b40d8a8f69ed07bd77799ee37678abdbe4bd29a0636fa0f7c76bc) — SHA-256 `41694eb79f07dd9fceba8e5b51955ccb38b9db91708d7c97d5ae57e7bf473387`; archive password `infected`.
- **Result:** `CORRECT`
- **Flag:** `9eb2b601ec91f90119d868abd0860741`

The archive includes six Bash behavior graph samples plus supporting PowerShell, JScript, Batch, VBScript, and Python samples. All sample contents were treated as untrusted data and inspected without executing them.

## Method

The encrypted ZIP was fetched from the paired Game Master endpoint and extracted with the published password. A static decoder reconstructed each sample's descriptor from its declared representation and transform: base64 chunks, decimal or reversed decimal bytes, percent-encoded hex, XOR, reverse-then-XOR, modulo subtraction, or identity. I parsed only bytes and source text; I did not invoke any sample's `Inspect`, `Plan`, recovery, or execution functions.

The behavior classification and ATT&CK technique came from the ordered decoded `steps` graph. For the Bash files, the command plan supplied the adapter, campaign and indicator values, stage count, and ordered graph. The Batch dropper's remaining control-flow field was verified against the Game Master's enum: `direct` was accepted for that wrapper.

The parser generated 399 answers and checked its key set against all 399 IDs returned by the Game Master before submission. The service accepted the Bash profiles and all six language/data groups, then returned `CORRECT`.

## Bash descriptors recovered

| Profile | Role | ATT&CK | Adapter | Campaign | Stages | Ordered steps |
|---|---|---|---|---|---:|---|
| benign | benign_utility | none | readonly_configuration | campaign-304d1b2abb | 1 | decode_configuration > return_configuration |
| stager | stager | T1105 | wget_stdout_pipe | campaign-8fe359fb1d | 1 | acquire_remote > dispatch_pipe |
| dropper | dropper | T1140 | printf_decode_redirect | campaign-eaa78515f3 | 1 | decode_embedded > write_file |
| downloader | downloader | T1105 | wget_output | campaign-521b2f4735 | 1 | acquire_remote > write_file |
| launcher | launcher | T1059.004 | sh_script | campaign-23de755f9c | 1 | locate_local > dispatch_process |
| chain | staged_chain | T1059.004 | wget_arch_fallback | campaign-9ea2805736 | 5 | profile_host > acquire_remote > write_file > change_mode > dispatch_process |

The Bash-specific indicators were recovered exactly: host ID `host-304d1b2abb`; stager URL `https://8fe359fb1d.example.invalid/cff17820.sh`; dropper path `/tmp/huntress-cache/.stage-eaa78515f3`; downloader URL `https://521b2f4735.example.invalid/69c19c13.sh`; launcher path `/tmp/huntress-cache/.stage-23de755f9c`; and chain cron path `/etc/cron.d/update-9ea2805736`.

## Complete player-facing fields

Each API question, answer format, and submitted value follows.
### `resource-scenario`

- Question: What scenario best describes resource-sample.ps1?
- Format: `{"kind":"enum","accepted_values":["resource_hijacking","synthetic_collection","synthetic_impact"]}`
- Submitted answer: `resource_hijacking`

### `resource-attack`

- Question: What is its primary MITRE ATT&CK technique ID?
- Format: `{"kind":"mitre_attack_id","syntax":"T#### or T####.###; use the literal none only when the question permits it"}`
- Submitted answer: `T1496`

### `resource-url`

- Question: What exact URL is embedded in the resource sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://51336654fb.example.invalid/c215189bfd47.dat`

### `resource-wallet`

- Question: What exact wallet indicator is embedded in the resource sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wallet_2f8057a173ee31ba6e269ca6b136f17a`

### `resource-mutex`

- Question: What exact mutex indicator is embedded in the resource sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Global\HuntressLab_1132ccf5a6c9`

### `collection-scenario`

- Question: What scenario best describes collection-sample.ps1?
- Format: `{"kind":"enum","accepted_values":["resource_hijacking","synthetic_collection","synthetic_impact"]}`
- Submitted answer: `synthetic_collection`

### `collection-attack`

- Question: For collection-sample.ps1, treat access to the browser credential store as the central behavior rather than ZIP staging or network transfer, and submit the corresponding MITRE ATT&CK technique ID. The broader Data from Local System technique is also accepted.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique ID for browser credential-store access; the broader Data from Local System technique ID is also accepted"}`
- Submitted answer: `T1555.003`

### `collection-url`

- Question: What exact URL is embedded in the collection sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://cdn-405e11ce57.example.invalid/ee8061900b04.bin`

### `collection-file`

- Question: What is the first exact filename indicator in the collection sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `update-405e11ce57.dat`

### `collection-user-agent`

- Question: What exact user-agent indicator is embedded in the collection sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Mozilla/5.0 HuntressLab/4.4`

### `impact-scenario`

- Question: What scenario best describes impact-sample.ps1?
- Format: `{"kind":"enum","accepted_values":["resource_hijacking","synthetic_collection","synthetic_impact"]}`
- Submitted answer: `synthetic_impact`

### `impact-attack`

- Question: What is its primary MITRE ATT&CK technique ID?
- Format: `{"kind":"mitre_attack_id","syntax":"T#### or T####.###; use the literal none only when the question permits it"}`
- Submitted answer: `T1486`

### `impact-extension`

- Question: What exact extension indicator is embedded in the impact sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `.locked-85bdb`

### `impact-note`

- Question: What exact recovery-note filename is embedded in the impact sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `RECOVERY-85bdbe5aff.txt`

### `impact-url`

- Question: What exact URL is embedded in the impact sample?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://85bdbe5aff.example.invalid/7d80ec48e793.dat`

### `jscript-benign-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `benign_utility`


### `jscript-benign-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `none`

### `jscript-benign-adapter`

- Question: What exact Windows adapter name does the reconstructed plan reference?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Scripting.Dictionary`

### `jscript-benign-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-ab778b353a`

### `jscript-benign-host`

- Question: What exact synthetic host identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `host-ab778b353a`

### `jscript-stager-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `jscript-stager-attack`

- Question: For the JScript stager whose descriptor steps are acquire_remote then dispatch_memory, treat the remote acquisition/transfer as the primary behavior. The memory-dispatch step identifies the stager role rather than overriding that primary mapping. Submit the corresponding MITRE ATT&CK technique ID; the artifact-faithful reflective-loading technique is also accepted.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique ID for the acquire_remote transfer; the reflective-loading technique ID is also accepted"}`
- Submitted answer: `T1105`

### `jscript-stager-adapter`

- Question: What exact acquisition adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `WinHttp.WinHttpRequest.5.1`

### `jscript-stager-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-28dcb70013`

### `jscript-stager-url`

- Question: What exact reserved-domain URL is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://28dcb70013.example.invalid/cf8e5bf9.dat`

### `jscript-dropper-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`

### `jscript-dropper-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `jscript-dropper-adapter`

- Question: What exact file adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `ADODB.Stream`

### `jscript-dropper-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-ab24a6b918`

### `jscript-dropper-path`

- Question: What exact synthetic output path is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-ab24a6b918.dat`


### `jscript-downloader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `downloader`

### `jscript-downloader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `jscript-downloader-adapter`

- Question: What exact acquisition adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `MSXML2.XMLHTTP.6.0`

### `jscript-downloader-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-135ac3985a`

### `jscript-downloader-url`

- Question: What exact reserved-domain URL is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://135ac3985a.example.invalid/8bd02d4a.dat`

### `jscript-launcher-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`

### `jscript-launcher-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.007`

### `jscript-launcher-adapter`

- Question: What exact process adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `regsvr32.exe`

### `jscript-launcher-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-3f8e0c467a`

### `jscript-launcher-path`

- Question: What exact local path is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-3f8e0c467a.dat`

### `jscript-chain-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`


### `jscript-chain-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.007`

### `jscript-chain-adapter`

- Question: What exact acquisition adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Microsoft.XMLHTTP`

### `jscript-chain-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-4d91a807dc`

### `jscript-chain-next-stage`

- Question: What exact PowerShell next-stage filename is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `resource-sample.ps1`

### `jscript-benign-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `named_expression`

### `jscript-benign-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `call`

### `jscript-benign-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `mixed`

### `jscript-stager-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `named_expression`

### `jscript-stager-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `apply`

### `jscript-stager-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `dot`

### `jscript-dropper-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `declaration`

### `jscript-dropper-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `direct`

### `jscript-dropper-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `bracket_literal`

### `jscript-downloader-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `named_expression`

### `jscript-downloader-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `apply`

### `jscript-downloader-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `dot`

### `jscript-launcher-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `declaration`

### `jscript-launcher-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `call`

### `jscript-launcher-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `mixed`

### `jscript-chain-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `declaration`

### `jscript-chain-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `apply`


### `jscript-chain-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `mixed`

### `jscript-uploader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `uploader`

### `jscript-uploader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1041`

### `jscript-uploader-adapter`

- Question: What exact outbound-transfer adapter or LOLBin is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `ConfigSecurityPolicy.exe`

### `jscript-uploader-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-410e1d460a`

### `jscript-uploader-url`

- Question: What exact reserved-domain upload destination is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://410e1d460a.example.invalid/a1e24934.dat`

### `jscript-uploader-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `named_expression`

### `jscript-uploader-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `direct`

### `jscript-uploader-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `bracket_literal`

### `jscript-impact-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `impact`

### `jscript-impact-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1486`

### `jscript-impact-adapter`

- Question: What exact content-transformation adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Scripting.FileSystemObject`

### `jscript-impact-extension`

- Question: What exact synthetic transformed-file extension is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `.locked-34c50253f9`

### `jscript-impact-note`

- Question: What exact synthetic recovery-note name is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `RECOVER-34c50253f9.txt`


### `jscript-impact-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `declaration`

### `jscript-impact-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `direct`

### `jscript-impact-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `bracket_literal`

### `jscript-relay-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `jscript-relay-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.007`

### `jscript-relay-adapter`

- Question: What exact acquisition adapter is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `WinHttp.WinHttpRequest.5.1`

### `jscript-relay-campaign`

- Question: What exact synthetic campaign identifier is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-934d8c751b`

### `jscript-relay-next-stage`

- Question: What exact JScript next-stage filename is reconstructed?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `local-dispatch.js`

### `jscript-relay-function-style`

- Question: Is the inspect function emitted as declaration, anonymous_expression, or named_expression?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `declaration`

### `jscript-relay-invocation-style`

- Question: Is descriptor recovery invoked with direct, call, or apply syntax?
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `direct`

### `jscript-relay-property-style`

- Question: Inside the specimen's inspect_* function, identify the variable assigned from eval(recover_*()). Classify only that recovered descriptor variable's accesses to steps, adapter, values, and stageCount as dot, bracket_literal, or mixed. Ignore .call/.apply and all properties or methods on other objects.
- Format: `{"kind":"enum","accepted_values":["dot","bracket_literal","mixed"]}`
- Submitted answer: `bracket_literal`

### `batch-benign-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `benign_utility`

### `batch-benign-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `none`

### `batch-benign-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `call`


### `batch-benign-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-aa0c0272ba`

### `batch-benign-host-id`

- Question: Recover the exact host_id indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `host-aa0c0272ba`

### `batch-benign-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `for_indirect`

### `batch-benign-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `call_subroutine`

### `batch-benign-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `linear`

### `batch-stager-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `batch-stager-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `batch-stager-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `certutil.exe`

### `batch-stager-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-d2ea5a7750`

### `batch-stager-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://d2ea5a7750.example.invalid/8d94b491.dat`

### `batch-stager-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `percent`

### `batch-stager-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `call_subroutine`

### `batch-stager-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cross_language`

### `batch-dropper-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`


### `batch-dropper-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `batch-dropper-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `certutil.exe`

### `batch-dropper-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-f3cc2ebbb8`

### `batch-dropper-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-f3cc2ebbb8.dat`

### `batch-dropper-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `for_indirect`

### `batch-dropper-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `call_subroutine`

### `batch-dropper-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cross_language`

### `batch-downloader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `downloader`

### `batch-downloader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `batch-downloader-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `curl.exe`

### `batch-downloader-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-9d8e6e34c0`

### `batch-downloader-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://9d8e6e34c0.example.invalid/a89f7ae7.dat`

### `batch-downloader-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `percent`

### `batch-downloader-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `errorlevel_guard`


### `batch-downloader-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `linear`

### `batch-uploader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `uploader`

### `batch-uploader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1041`

### `batch-uploader-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `makecab.exe`

### `batch-uploader-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-94bfa431c0`

### `batch-uploader-upload-url`

- Question: Recover the exact upload_url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://94bfa431c0.example.invalid/upload`

### `batch-uploader-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `percent`

### `batch-uploader-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `call_subroutine`

### `batch-uploader-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `fan_out`

### `batch-launcher-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`

### `batch-launcher-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.003`

### `batch-launcher-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `call`

### `batch-launcher-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-bff2286860`

### `batch-launcher-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-bff2286860.dat`


### `batch-launcher-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `for_indirect`

### `batch-launcher-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `call_subroutine`

### `batch-launcher-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `fallback_retry`

### `batch-impact-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `impact`

### `batch-impact-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1486`

### `batch-impact-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `for`

### `batch-impact-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-0ef0a62bc9`

### `batch-impact-note-name`

- Question: Recover the exact note_name indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `RECOVER-0ef0a62bc9.txt`

### `batch-impact-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `call_double`

### `batch-impact-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `if_guard`

### `batch-impact-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `fallback_retry`

### `batch-chain-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`


### `batch-chain-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.003`

### `batch-chain-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `rundll32.exe`

### `batch-chain-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-7fd93595dd`

### `batch-chain-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `stage-7fd93595dd.ps1`

### `batch-chain-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `percent`

### `batch-chain-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `goto_dispatch`

### `batch-chain-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `diamond`

### `batch-relay-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `batch-relay-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.003`

### `batch-relay-adapter`

- Question: Recover the exact native adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `rundll32.exe`

### `batch-relay-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-b02e7d6d8d`

### `batch-relay-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `stage-b02e7d6d8d.ps1`

### `batch-relay-expansion`

- Question: Classify only the expansion form used by the descriptor reconstruction statement. Ignore output, echo, host-envelope, and separator-noise lines that may use a different expansion form. Submit one of percent, delayed, call_double (the CALL-double form), or for_indirect (the FOR-indirect form). The displayed hyphenated spellings are accepted too.
- Format: `{"kind":"enum","accepted_values":["percent","delayed","call_double","for_indirect"]}`
- Submitted answer: `percent`

### `batch-relay-control`

- Question: Classify only the control-flow wrapper that causes the descriptor reconstruction statement to execute. If a one-item FOR loop invokes a subroutine containing that statement, classify the outer wrapper as for_once rather than call_subroutine. Ignore the inert --inspect/--plan host envelope, labels, separator-noise commands, and ordinary transfers outside that wrapper. Submit one of direct, goto_dispatch, call_subroutine, for_once, if_guard, or errorlevel_guard.
- Format: `{"kind":"enum","accepted_values":["direct","goto_dispatch","call_subroutine","for_once","if_guard","errorlevel_guard"]}`
- Submitted answer: `if_guard`

### `batch-relay-graph`

- Question: Identify the exact stage-graph topology.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `single`


### `vbscript-benign-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `benign_utility`

### `vbscript-benign-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `none`

### `vbscript-benign-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Scripting.FileSystemObject`

### `vbscript-benign-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-377552fd0e`

### `vbscript-benign-host-id`

- Question: Recover the exact host_id indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `host-377552fd0e`

### `vbscript-benign-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `reversed_decimal`

### `vbscript-benign-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `subtract_modulo_256`

### `vbscript-benign-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `while_once`

### `vbscript-stager-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `vbscript-stager-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `vbscript-stager-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Microsoft.XMLHTTP`

### `vbscript-stager-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-e794b0e9f2`

### `vbscript-stager-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://e794b0e9f2.example.invalid/8a5f2815.dat`

### `vbscript-stager-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `decimal_comma`


### `vbscript-stager-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `rolling_xor`

### `vbscript-stager-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `for_once`

### `vbscript-dropper-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`

### `vbscript-dropper-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `vbscript-dropper-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `ADODB.Stream`

### `vbscript-dropper-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-6f8c5ec2fb`

### `vbscript-dropper-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-6f8c5ec2fb.dat`

### `vbscript-dropper-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `base64_chunks`

### `vbscript-dropper-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `repeating_key_xor`

### `vbscript-dropper-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `for_once`

### `vbscript-downloader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `downloader`

### `vbscript-downloader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`


### `vbscript-downloader-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `WinHttp.WinHttpRequest.5.1`

### `vbscript-downloader-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-e0b7ce0cd9`

### `vbscript-downloader-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://e0b7ce0cd9.example.invalid/57c4077b.dat`

### `vbscript-downloader-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `decimal_comma`

### `vbscript-downloader-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `reverse_bytes`

### `vbscript-downloader-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `error_guard`

### `vbscript-uploader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `uploader`

### `vbscript-uploader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1041`

### `vbscript-uploader-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `MSXML2.ServerXMLHTTP.6.0`

### `vbscript-uploader-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-f9e7abd00c`

### `vbscript-uploader-upload-url`

- Question: Recover the exact upload_url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://f9e7abd00c.example.invalid/upload/5672fc20`

### `vbscript-uploader-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `hex_colon`

### `vbscript-uploader-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `identity`

### `vbscript-uploader-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `error_guard`

### `vbscript-launcher-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`


### `vbscript-launcher-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.005`

### `vbscript-launcher-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Shell.Application`

### `vbscript-launcher-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-4cb9673d2b`

### `vbscript-launcher-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:\Users\Public\HuntressLab\stage-4cb9673d2b.dat`

### `vbscript-launcher-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `decimal_comma`

### `vbscript-launcher-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `repeating_key_xor`

### `vbscript-launcher-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `for_once`

### `vbscript-impact-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `impact`

### `vbscript-impact-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1486`

### `vbscript-impact-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Scripting.FileSystemObject`

### `vbscript-impact-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-a9b2022559`

### `vbscript-impact-extension`

- Question: Recover the exact extension indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `.532da.locked`

### `vbscript-impact-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `hex_dash`

### `vbscript-impact-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `reverse_then_xor`


### `vbscript-impact-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `do_once`

### `vbscript-chain-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `vbscript-chain-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.005`

### `vbscript-chain-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `WinHttp.WinHttpRequest.5.1`

### `vbscript-chain-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-a8c25e702f`

### `vbscript-chain-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `resource-sample.ps1`

### `vbscript-chain-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `hex_compact`

### `vbscript-chain-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `repeating_key_xor`

### `vbscript-chain-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `error_guard`

### `vbscript-relay-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `vbscript-relay-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.005`

### `vbscript-relay-adapter`

- Question: Recover the exact WSH, COM, or LOLBin adapter named by the reconstructed plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `Microsoft.XMLHTTP`

### `vbscript-relay-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-3e27b38caa`


### `vbscript-relay-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `local-dispatch.vbs`

### `vbscript-relay-representation`

- Question: Identify the exact VBScript material representation.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `decimal_dash`

### `vbscript-relay-transform`

- Question: Identify the reversible byte-transform family only; do not append the key bytes. Submit one of identity, single_byte_xor, repeating_key_xor, add_modulo_256, subtract_modulo_256, reverse_bytes, rolling_xor, or reverse_then_xor. The exact artifact label with its pipe-delimited hexadecimal key bytes is also accepted when its family matches.
- Format: `{"kind":"enum","accepted_values":["identity","single_byte_xor","repeating_key_xor","add_modulo_256","subtract_modulo_256","reverse_bytes","rolling_xor","reverse_then_xor"]}`
- Submitted answer: `identity`

### `vbscript-relay-control`

- Question: Classify the control-flow wrapper around the descriptor decode call. Submit one canonical value: direct; for_once (For...Next executes once); do_once (Do...Loop exits after one pass); while_once (While...Wend executes once); select_case (Select Case dispatch); or error_guard (On Error Resume Next guards the call). The displayed VBScript syntax labels are accepted too.
- Format: `{"kind":"enum","accepted_values":["direct","for_once","do_once","while_once","select_case","error_guard"]}`
- Submitted answer: `for_once`

### `python-source-benign-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `benign_utility`

### `python-source-benign-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `none`

### `python-source-benign-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `mapping_proxy`

### `python-source-benign-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-402f78b59e`

### `python-source-benign-host-id`

- Question: Recover the exact host_id indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `host-402f78b59e`

### `python-source-benign-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `plain_functions`

### `python-source-benign-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `transform_only`

### `python-source-benign-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `raw_source`

### `python-source-benign-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `direct_python_exe`

### `python-pyc38-dropper-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`


### `python-pyc38-dropper-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `python-pyc38-dropper-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `tempfile_replace`

### `python-pyc38-dropper-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-042c86c973`

### `python-pyc38-dropper-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:/ProgramData/HuntressLab/.update-042c86c973.py`

### `python-pyc38-dropper-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `class_staticmethod`

### `python-pyc38-dropper-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `string_table`

### `python-pyc38-dropper-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `hash_based_pyc_38`

### `python-pyc38-dropper-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `renamed_interpreter`

### `python-current-pyc-launcher-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`

### `python-current-pyc-launcher-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-current-pyc-launcher-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `interpreter_argv`

### `python-current-pyc-launcher-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-955c73ae49`

### `python-current-pyc-launcher-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:/ProgramData/HuntressLab/.update-955c73ae49.py`

### `python-current-pyc-launcher-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `closure_factory`

### `python-current-pyc-launcher-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `chr_join`

### `python-current-pyc-launcher-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `hash_based_pyc_current`

### `python-current-pyc-launcher-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pythonw_hidden_console`


### `python-zipapp-relay-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `relay`

### `python-zipapp-relay-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-zipapp-relay-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `python_to_python`

### `python-zipapp-relay-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-916e2a5c03`

### `python-zipapp-relay-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyc38-recovered.py`

### `python-zipapp-relay-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `lambda_dispatch`

### `python-zipapp-relay-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `reversed_fragments`

### `python-zipapp-relay-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `zipapp_pyz`

### `python-zipapp-relay-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cmd_to_python`

### `python-wheel-stager-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `python-wheel-stager-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `python-wheel-stager-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `http_client_memory`

### `python-wheel-stager-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-26e9a1aa85`

### `python-wheel-stager-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://26e9a1aa85.example.invalid/1cc817ae.py`

### `python-wheel-stager-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `list_comprehension`


### `python-wheel-stager-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `format_map`

### `python-wheel-stager-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wheel_archive`

### `python-wheel-stager-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `powershell_to_python`

### `python-pyinstaller-onefile-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `downloader`

### `python-pyinstaller-onefile-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `python-pyinstaller-onefile-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `request_stream_to_path`

### `python-pyinstaller-onefile-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-4318986ef9`

### `python-pyinstaller-onefile-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://4318986ef9.example.invalid/3dd61621.py`

### `python-pyinstaller-onefile-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `generator_pipeline`

### `python-pyinstaller-onefile-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `fstring_fragments`

### `python-pyinstaller-onefile-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyinstaller_onefile`

### `python-pyinstaller-onefile-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `mshta_to_python`

### `python-pyinstaller-onedir-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `uploader`

### `python-pyinstaller-onedir-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1041`

### `python-pyinstaller-onedir-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `urllib_request_body`


### `python-pyinstaller-onedir-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-3060b697d4`

### `python-pyinstaller-onedir-upload-url`

- Question: Recover the exact upload_url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://3060b697d4.example.invalid/upload`

### `python-pyinstaller-onedir-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `dictionary_dispatch`

### `python-pyinstaller-onedir-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `lambda_indirection`

### `python-pyinstaller-onedir-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyinstaller_onedir`

### `python-pyinstaller-onedir-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `rundll32_predecessor`

### `python-py2exe-console-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`

### `python-py2exe-console-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-py2exe-console-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pythonw_argv`

### `python-py2exe-console-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-16aba51f87`

### `python-py2exe-console-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:/ProgramData/HuntressLab/.update-16aba51f87.py`

### `python-py2exe-console-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `match_case`

### `python-py2exe-console-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `closure_cells`

### `python-py2exe-console-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `py2exe_console`

### `python-py2exe-console-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `regsvr32_predecessor`

### `python-py2exe-service-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`


### `python-py2exe-service-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-py2exe-service-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cpython_loader_handoff`

### `python-py2exe-service-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-1fcf06cf66`

### `python-py2exe-service-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `resource-sample.ps1`

### `python-py2exe-service-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `walrus_binding`

### `python-py2exe-service-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `exception_routing`

### `python-py2exe-service-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `py2exe_windows_service`

### `python-py2exe-service-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `service_descriptor`

### `python-cxfreeze-executable-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `impact`

### `python-cxfreeze-executable-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1486`

### `python-cxfreeze-executable-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `os_walk_copy_plan`

### `python-cxfreeze-executable-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-78fe1c820e`

### `python-cxfreeze-executable-extension`

- Question: Recover the exact extension indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `.78fe1c820e.locked`

### `python-cxfreeze-executable-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `decorator_wrapper`

### `python-cxfreeze-executable-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `bytes_translation`

### `python-cxfreeze-executable-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cx_freeze_executable`

### `python-cxfreeze-executable-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `scheduled_task_descriptor`


### `python-cxfreeze-msi-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`

### `python-cxfreeze-msi-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `python-cxfreeze-msi-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `importlib_resource_write`

### `python-cxfreeze-msi-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-7fdd7cb453`

### `python-cxfreeze-msi-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `C:/ProgramData/HuntressLab/.update-7fdd7cb453.py`

### `python-cxfreeze-msi-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `iterator_protocol`

### `python-cxfreeze-msi-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `reflective_name_plan`

### `python-cxfreeze-msi-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cx_freeze_msi`

### `python-cxfreeze-msi-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `run_key_descriptor`

### `python-pyarmor-source-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `python-pyarmor-source-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `python-pyarmor-source-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `urllib_memory`

### `python-pyarmor-source-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-835862343d`

### `python-pyarmor-source-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://835862343d.example.invalid/b0e82f1e.py`

### `python-pyarmor-source-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `exception_expression`


### `python-pyarmor-source-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `marshal_envelope_plan`

### `python-pyarmor-source-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyarmor_obfuscated`

### `python-pyarmor-source-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wscript_to_python`

### `python-pyarmor-pyinstaller-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `python-pyarmor-pyinstaller-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-pyarmor-pyinstaller-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `cmd_python_handoff`

### `python-pyarmor-pyinstaller-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-20f0e7cdac`

### `python-pyarmor-pyinstaller-handoff-id`

- Question: Recover the exact handoff_id indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `PSPY-32B5959FF5CA83D0`

### `python-pyarmor-pyinstaller-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `dictionary_dispatch`

### `python-pyarmor-pyinstaller-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `reflective_name_plan`

### `python-pyarmor-pyinstaller-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyarmor_pyinstaller`

### `python-pyarmor-pyinstaller-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `powershell_to_python`

### `python-embedded-runtime-relay-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `relay`

### `python-embedded-runtime-relay-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.006`

### `python-embedded-runtime-relay-adapter`

- Question: Recover the exact Python, Windows, or predecessor adapter named by the operation plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `python_to_python`


### `python-embedded-runtime-relay-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-7c9b884c09`

### `python-embedded-runtime-relay-next-stage`

- Question: Recover the exact next_stage indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `pyarmor-pyinstaller-recovered.py`

### `python-embedded-runtime-relay-syntax`

- Question: Identify the exact native Python syntax structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `class_staticmethod`

### `python-embedded-runtime-relay-obfuscation`

- Question: Identify the exact Python obfuscation structure.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `marshal_envelope_plan`

### `python-embedded-runtime-relay-carrier`

- Question: Identify the exact source, bytecode, frozen, or protected carrier profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `embeddable_python_runtime`

### `python-embedded-runtime-relay-windows-chain`

- Question: Identify the exact Windows execution-chain profile.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `renamed_interpreter`

### `bash-benign-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `benign_utility`

### `bash-benign-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `none`

### `bash-benign-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `readonly_configuration`

### `bash-benign-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-304d1b2abb`

### `bash-benign-host-id`

- Question: Recover the exact host_id indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `host-304d1b2abb`

### `bash-benign-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `1`

### `bash-benign-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `decode_configuration>return_configuration`

### `bash-stager-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `stager`

### `bash-stager-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `bash-stager-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wget_stdout_pipe`


### `bash-stager-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-8fe359fb1d`

### `bash-stager-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://8fe359fb1d.example.invalid/cff17820.sh`

### `bash-stager-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `1`

### `bash-stager-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `acquire_remote>dispatch_pipe`

### `bash-dropper-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `dropper`

### `bash-dropper-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1140`

### `bash-dropper-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `printf_decode_redirect`

### `bash-dropper-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-eaa78515f3`

### `bash-dropper-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `/tmp/huntress-cache/.stage-eaa78515f3`

### `bash-dropper-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `1`

### `bash-dropper-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `decode_embedded>write_file`

### `bash-downloader-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `downloader`

### `bash-downloader-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1105`

### `bash-downloader-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wget_output`

### `bash-downloader-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-521b2f4735`

### `bash-downloader-url`

- Question: Recover the exact url indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `https://521b2f4735.example.invalid/69c19c13.sh`

### `bash-downloader-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `1`


### `bash-downloader-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `acquire_remote>write_file`

### `bash-launcher-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `launcher`

### `bash-launcher-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.004`

## Time Trial

- **Mode:** Time Trial; the 50-second timer was server-enforced.
- **Attempt:** `d0edb041-59c5-4438-8f2a-9a10f3173479`
- **Artifact:** `evidence.zip` — SHA-256 `b255b5d910af42cc1c95dddec6546031dc310d489f629c4ea1dcd9321f8331d5`; password `infected`.
- **Result:** `CORRECT`; all 399 fields were accepted.
- **Flag:** `83c6021de86268a027dcb5883c8dc2f7`

The first timed attempt expired while I was extending the static Bash byte decoder for the new declared representations and transforms. I used the explicit retry operation after expiration, then downloaded and checked the fresh archive and completed the same parser-and-answer-ID validation within the new deadline. The six Bash descriptors in this trial were benign utility, stager, dropper, downloader, launcher, and staged chain; their declared transforms were decoded as data and none of the samples were executed.

## Mastery

- **Mode:** Mastery; one shared 80-second server-enforced timer for two sets.
- **Attempt:** `e29564d0-cc03-4e72-b6c7-0b340b1a2228`
- **Artifacts:** two `evidence.zip` files, both password `infected`:
  - Set 1 SHA-256: `7fe1281e02c285cba1958d0a39c50ca411d85c009b034ec0e13b297675f9ce97`
  - Set 2 SHA-256: `76b16647e0783278ac96d1160df2927085006d7305637a7b661a66003a98e2dd`
- **Result:** `CORRECT`; all 798 fields (399 per set) were accepted.
- **Flag:** `3cd8ac6f42e35ba15272e8ec32af3c70`

The decoder was extended for the two sets' declared formats: decimal values separated by colons, compact hexadecimal, reversed decimal bytes, percent-encoded and dashed hex, and base64; transforms included modulo arithmetic, byte reversal, single/repeating-key XOR, reverse-then-XOR, and rolling XOR. For rolling XOR, each encoded byte is XORed with the previous encoded byte, beginning with the declared initial byte. I verified each downloaded archive against its API-provided hash, generated answers from decoded bytes and source text without running the samples, and matched the combined 798 answer keys exactly to the API's IDs before submission.

### `bash-launcher-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `sh_script`

### `bash-launcher-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-23de755f9c`

### `bash-launcher-file-path`

- Question: Recover the exact file_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `/tmp/huntress-cache/.stage-23de755f9c`

### `bash-launcher-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `1`

### `bash-launcher-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `locate_local>dispatch_process`

### `bash-chain-role`

- Question: Classify the decoded ordered behavior graph by its complete terminal intent. Use benign_utility for decode_configuration then return_configuration; stager for acquire_remote then memory/pipe dispatch; dropper for decode_embedded then write_file; downloader for acquire_remote then write_file; uploader for a graph ending in upload_remote or transmit_remote; launcher for locate_local then dispatch_process; impact for a transform ending in write_recovery_note; staged_chain for a multi-stage profile/acquire followed by write and terminal dispatch_process (with optional decode_embedded or change_mode steps) or for a graph ending in handoff_script; relay for decode_configuration then locate_interpreter then dispatch_next_stage; and persistence_descriptor for build_schedule then register_descriptor. Earlier preparation steps do not override the terminal graph.
- Format: `{"kind":"enum","accepted_values":["benign_utility","stager","dropper","downloader","uploader","launcher","impact","staged_chain","relay","persistence_descriptor"]}`
- Submitted answer: `staged_chain`

### `bash-chain-attack`

- Question: Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: a terminal handoff_script or dispatch_next_stage makes the staged chain or relay the specimen's language-specific Command and Scripting Interpreter sub-technique even when acquire_remote or decode_configuration appears earlier; otherwise decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer, decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration over the command-and-control channel, dispatch_process is the language-specific Command and Scripting Interpreter sub-technique, build_schedule followed by register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by write_recovery_note is encrypted-file impact. Incidental adapters, collection/encoding preparation, and file writes do not override that graph mapping. The parent Command and Scripting Interpreter technique is also accepted when a language-specific sub-technique is canonical. For a staged chain or relay, the earlier ingress-transfer technique is also accepted. For compatibility with the earlier ambiguous relay rubric, none is also accepted for a relay whose canonical answer is language-specific Command and Scripting Interpreter.
- Format: `{"kind":"pattern","syntax":"MITRE ATT&CK technique or language-specific sub-technique ID selected from the decoded ordered behavior graph by the stated precedence, or none for the benign graph"}`
- Submitted answer: `T1059.004`

### `bash-chain-adapter`

- Question: Recover the exact native Bash adapter named by the command plan.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `wget_arch_fallback`

### `bash-chain-campaign`

- Question: Recover the exact synthetic campaign identifier.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `campaign-9ea2805736`

### `bash-chain-cron-path`

- Question: Recover the exact cron_path indicator.
- Format: `{"kind":"exact_text","syntax":"exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value"}`
- Submitted answer: `/etc/cron.d/update-9ea2805736`

### `bash-chain-stage-count`

- Question: Recover the exact number of modeled stages.
- Format: `{"kind":"integer","syntax":"base-10 integer with no explanatory text"}`
- Submitted answer: `5`

### `bash-chain-steps`

- Question: Recover the ordered behavior graph using > separators.
- Format: `{"kind":"ordered_tokens","syntax":"exact tokens joined by > with no surrounding spaces or explanatory text"}`
- Submitted answer: `profile_host>acquire_remote>write_file>change_mode>dispatch_process`


