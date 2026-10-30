# Hatch Careful — Single Solve

## Result

- **Challenge ID:** `script-analysis-day-05-python-carrier-lab`
- **Mode:** Single Solve (untimed)
- **Attempt:** `3170b5ae-2684-4268-a972-d77536b51cb6`
- **Game Master result:** `CORRECT`; status confirmed all 357 answer IDs accepted.
- **Flag:** `d7f8da427f1e4b620a3cf74117cfe487`
- **Day 5 verification:** two fresh `GET ?op=list&day=5` responses both marked this route solved.

## Assignment and evidence

The assigned artifact was `evidence.zip`, downloaded from the Game Master for this attempt and checked against SHA-256 `0ad1ebe9953e7dde6d4ecdc54d7e4309d7547c9c7cb2bc842f51f4156169a599`. The published archive password was `infected`. Static extraction yielded 45 files: 4 PowerShell, 9 JScript, 9 batch/CMD, 9 VBScript, and 14 Python samples. The ZIP and each extracted sample’s SHA-256 are recorded below.

## Analysis method

I kept all challenge samples inert. I inspected their source and carrier structure, then decoded only the embedded configuration fragments. The wrapper comments named simple transforms such as Base64, hex pairs, reverse, XOR, rotation, and byte addition; I applied those transforms in a local parser to the exact extracted bytes. For Python sources and recovered stubs I used AST/literal inspection to identify syntax forms and reconstruct descriptor fields without importing or executing the samples. For batch files I reconstructed the split assignments and read the relevant control-flow wrapper statically.

Each decoded descriptor was reduced to its ordered steps, adapter, campaign/indicator values, stage count, and handoff. I classified the complete ordered graph by terminal intent, then mapped the primary behavior to the requested ATT&CK technique. Carrier, syntax, obfuscation, and Windows execution-chain questions were answered from the corresponding sample’s static structure and metadata. The Game Master accepted the answer set in profile-sized submissions; the final status reported 357 accepted IDs.

One rubric detail was checked against the service rather than assumed: it accepted `call_subroutine` for the two single-item loop wrappers (`remote-write.bat` and `staged-handoff.bat`), while the three guarded wrappers were accepted as `errorlevel_guard`.

## Python carrier findings

| Profile | Role | ATT&CK | Carrier | Syntax form | Obfuscation form | Windows chain |
|---|---|---|---|---|---|---|
| `source-benign` | `benign_utility` | `none` | `raw_source` | `plain_functions` | `transform_only` | `direct_python_exe` |
| `pyc38-dropper` | `dropper` | `T1140` | `hash_based_pyc_38` | `class_staticmethod` | `string_table` | `renamed_interpreter` |
| `current-pyc-launcher` | `launcher` | `T1059.006` | `hash_based_pyc_current` | `closure_factory` | `chr_join` | `pythonw_hidden_console` |
| `zipapp-relay` | `relay` | `T1059.006` | `zipapp_pyz` | `lambda_dispatch` | `reversed_fragments` | `cmd_to_python` |
| `wheel-stager` | `stager` | `T1105` | `wheel_archive` | `list_comprehension` | `format_map` | `powershell_to_python` |
| `pyinstaller-onefile` | `downloader` | `T1105` | `pyinstaller_onefile` | `generator_pipeline` | `fstring_fragments` | `mshta_to_python` |
| `pyinstaller-onedir` | `uploader` | `T1041` | `pyinstaller_onedir` | `dictionary_dispatch` | `lambda_indirection` | `rundll32_predecessor` |
| `py2exe-console` | `launcher` | `T1059.006` | `py2exe_console` | `match_case` | `closure_cells` | `regsvr32_predecessor` |
| `py2exe-service` | `staged_chain` | `T1059.006` | `py2exe_windows_service` | `walrus_binding` | `exception_routing` | `service_descriptor` |
| `cxfreeze-executable` | `impact` | `T1486` | `cx_freeze_executable` | `decorator_wrapper` | `bytes_translation` | `scheduled_task_descriptor` |
| `cxfreeze-msi` | `dropper` | `T1140` | `cx_freeze_msi` | `iterator_protocol` | `reflective_name_plan` | `run_key_descriptor` |
| `pyarmor-source` | `stager` | `T1105` | `pyarmor_obfuscated` | `exception_expression` | `marshal_envelope_plan` | `wscript_to_python` |
| `pyarmor-pyinstaller` | `staged_chain` | `T1059.006` | `pyarmor_pyinstaller` | `dictionary_dispatch` | `reflective_name_plan` | `powershell_to_python` |
| `embedded-runtime-relay` | `relay` | `T1059.006` | `embeddable_python_runtime` | `class_staticmethod` | `marshal_envelope_plan` | `renamed_interpreter` |

Across the whole archive, the validated graph roles included benign utility, stager, dropper, downloader, uploader, launcher, impact, staged chain, and relay. The PowerShell, JScript, batch/CMD, and VBScript questions supplied the remaining adapter, campaign, path, URL, graph, and wrapper findings; all were submitted under their exact answer IDs and accepted.

## Integrity appendix

Archive SHA-256: `0ad1ebe9953e7dde6d4ecdc54d7e4309d7547c9c7cb2bc842f51f4156169a599`

| Extracted file | SHA-256 |
|---|---|
| `collection-sample.ps1` | `50c792194f3c3eb564b9fc4a6b72924d220b3fce1971d7b5ce86ff3f68cc053b` |
| `current-pyc-recovered.py` | `fa3fe37169e05de5304a27f2865a93b55119d3ed9c3e5ca64900cc1014f2ae13` |
| `cxfreeze-msi-recovered.py` | `9ac19542d7a524c89ecbf585b1951fd68359c41359db269123ad1cd2ffd6e051` |
| `cxfreeze-recovered.py` | `da889251eceacf82af2cc8ed93597d51c7ccbb5728e7a8a5ee4825e0212f97c7` |
| `embedded-runtime-recovered.py` | `3cc3d79411ae7353d7e9f130f7349713fb086db069de317036ae329c832f469c` |
| `embedded-write.cmd` | `f25d2dbfa002db1fc455be78ec4581adef32bedb5005447a451c3f7169f5d16b` |
| `embedded-write.js` | `de2db0ad637e0805f266440565cc934bd47599b6ca7f8fd8f1dc7481d0123186` |
| `embedded-write.vbs` | `7a7cd02182c2a8f4492efdd48d2d1c3b2ccb8a531754e38a9f0932fe1902cfe9` |
| `host-context.cmd` | `e1842a68befe54d2080cecf9201c96de2a9e9ce7d0f0d6c82957a1937c56810a` |
| `host-context.js` | `b8bc3e113ab620a52e798e4b06d86e5dfce35aa184a6f1f3c9e38d7de6ead512` |
| `host-context.vbs` | `5013b854287464ed8ec70e39aaf4aac8d1fa8b11472aaf082a401929e34afcc0` |
| `impact-plan.cmd` | `a356a8166e7b9501a9e1a9f068b00e58260621e279b2372b1556ed36c1fa574c` |
| `impact-plan.js` | `7bdc02f5ee50b4b1ca8ce0ff33018ff12c53b9c17da2ea892defe82dee6b72fd` |
| `impact-plan.vbs` | `c78df10b0078c7ce2de8de0baefe8b380255a1ef1a767c64ec29a7f5236faf22` |
| `impact-sample.ps1` | `a4a1372477a5fb5edf6777749ea36599fd5bffb7b88df564f95b8a0a6cdd1fbb` |
| `invoke-python-stage.ps1` | `1456a4c69ede1c07ceab106b87602b84f82309dbe1d2178b79a8537022f6966b` |
| `local-dispatch.bat` | `6b4371dee6873ab1c5db506b43d06bb9c291237c3a8d5f512c99cd897a39c43d` |
| `local-dispatch.js` | `6b5aa714661ef0367d3a32c41ac217bf2bc630547727853dc39fbd2a43204dd0` |
| `local-dispatch.vbs` | `c85234d83030559b74c8e499e121aebec7a436d836bfe996212c95224d98ce28` |
| `memory-stage.bat` | `b13c814c858d49344e865355e612774443faea61d8a39fba5f2b9953bac2cb1c` |
| `memory-stage.js` | `69691fe4d3b23cc81f195d70d446ab81f359fc8e819e11290e46577c305b9fb5` |
| `memory-stage.vbs` | `8f829ab0a4547febfaed6b8ae9e5c6f83cd80bb91d053e1a458e28ea3e8c4f15` |
| `outbound-transfer.cmd` | `6d89809891b99ec2f136ac2ca85e9f2ccccc9681dfed28e979feb7ffff18ad75` |
| `outbound-transfer.js` | `4a5124f91691ed22458ec194aee91c1856594fa055cbdc28d89c9fb3fa0d3a09` |
| `outbound-transfer.vbs` | `64278564eb4949930e2df8cbb9b1c52ecc44b1a8cf6c581dd4f01a59dbb70813` |
| `py2exe-console-recovered.py` | `da2ef69337826c0fea44fa282602a1930f2246d5930a4467c11937cc7deec513` |
| `py2exe-service-recovered.py` | `fd6ddeb75b0df455dc918562af090ebbe57c0afec3d174eecb75a3b0e8dc2f35` |
| `pyarmor-pyinstaller-recovered.py` | `b3d46722540367f648b3f78278792e365b6097bbe4cf5f27eec6eb50db144073` |
| `pyarmor-source-recovered.py` | `727b8c1263b553f15f8e06816895c6491140f588f52f7b17a8577b6e874919fc` |
| `pyc38-recovered.py` | `0e24424d680fdebcf53b6961d7cab118cffbef60ac0392e007f323c93c714c4d` |
| `pyinstaller-onedir-recovered.py` | `ffd34cb8eb02f2edf52dc512e7250866b1fd1e971bbcc12950b1f36117ae0946` |
| `pyinstaller-onefile-recovered.py` | `8afc8d5608960e70b9122a32a7ffbb44a4e98e4593f8cab1a316b960bcadbcc4` |
| `relay-handoff.cmd` | `89f5a1ef6ba50c5d9b4ca6431caa6633cc86abdf5c76db65f140e7d9ade90f45` |
| `relay-handoff.js` | `469beea29f23ac645dce3e07ddf952f56df783bff87a1226beac06d0e5c8c130` |
| `relay-handoff.vbs` | `cdf5aca08efba3fcab46f2e098fc4fbeaf070cab4c164c81df0807927759cab0` |
| `remote-write.bat` | `d8fff901db93928f2330086ca760f7a2da4d0b5e828e46ccf19bf4f92d56a239` |
| `remote-write.js` | `394f0fad4baef0dceb427eb859b829eabc172646a02cd473c4dd544c9785cc23` |
| `remote-write.vbs` | `6d7ef787625a343953faedc9d0cb56eecc3d2059641ad420edfdcb97cd479d6d` |
| `resource-sample.ps1` | `ef01e8ea70607ffc27f202ff377837247af3423c3a9fb343db078e4bc84a217b` |
| `source-context.py` | `cc7792fa4eaed5e8a66daa65d0a40c8273f7b3b8d27129ba3173ad63df0b18e6` |
| `staged-handoff.bat` | `dbbc1658b1ee89b662e4c2db56c306c0f53b416fd28d21c27cf52a3e2edcf381` |
| `staged-handoff.js` | `106e52e313e0ff4e04fc86597f05bdbe59b4712ce7c5ba8205c98703c7504f0c` |
| `staged-handoff.vbs` | `e7eae49789d8b1be71aa0312de2411cd9080759bc3a846c3fb9f8d593f3b7ce0` |
| `wheel-recovered.py` | `bd88db6d77968c5c4dbeb040c2047b158b4cc7320f6c5d846242790da3ca2f69` |
| `zipapp-recovered.py` | `a1739bcdfbf5d27f44f714fcb0a768c4f96549bee2d5e4b30763c0d883567646` |

## Time Trial

- **Challenge ID:** `script-analysis-day-05-python-carrier-lab/time_trial`
- **Mode:** Time Trial; 50-second server deadline.
- **Successful attempt:** `f793abeb-ac25-4f4b-8337-7a63d98decad`
- **Artifact:** `evidence.zip`, SHA-256 `6cf28cf6bb5ac2822a7a233ef1a32937a6d731a196f03946a0ae25cfc68de99d` (password: `infected`).
- **Game Master result:** `CORRECT`; all 357 answer fields were accepted.
- **Flag:** `6d97c2cc2239b6cec6a5710dfe464094`

The timed set used the same 45-file structure as Single Solve but fresh encoded values and wrapper variants. I reused the static parser, validated every answer against the attempt's exact answer IDs, and submitted the seven language/resource groups before the deadline. No challenge scripts were executed. The Game Master accepted the final batch profile and returned `CORRECT`; two consecutive Day 5 list responses and a status check confirmed completion.

Timed variants introduced additional JScript transforms, including reverse-then-fixed-XOR, reverse-then-subtract, reverse-then-rolling-XOR, and reverse-then-repeating-key-XOR. The parser was extended to recognize those forms from the decoder code and packed bytes. Batch wrapper questions required classifying the statement that actually gates reconstruction, while ignoring unrelated host-envelope and separator logic; the successful answer set used the live route's `if_guard`, `errorlevel_guard`, `goto_dispatch`, and direct-control classifications as derived from the wrapper source.

## Mastery

- **Challenge ID:** `script-analysis-day-05-python-carrier-lab/mastery`
- **Mode:** Mastery; one 80-second server deadline for two 357-field sets.
- **Successful attempt:** `a52b96a3-84fa-4733-832d-9417c2cabfb6`
- **Artifacts:** two assigned `evidence.zip` files, both password-protected with `infected`.
  - Set 1 SHA-256: `5be49f32b026fbab8c92c1528b2d72eec2d42f5739aee4bd0202640939aa973a`
  - Set 2 SHA-256: `21d33860488fe3862924e70a4a9e6fd839f58f7eaa568f45f624d36ba82aeb3a`
- **Game Master result:** `CORRECT`; all 714 answer fields were accepted.
- **Flag:** `7e6bf42a773a38159947e1768802274a`

The mastery reused the static extraction pipeline from the earlier modes. I staged the parser and its decoder helper on Kali before retrying, then had Kali fetch the two assigned archives, extract them locally, decode the carriers as data, and submit answers under the exact `set1.*` and `set2.*` answer IDs. The scripts themselves were never executed.

The key correction was to classify the wrapper that directly causes reconstruction. A multi-item `FOR` loop invoking `CALL SET` is `call_subroutine`; a one-item loop that invokes a subroutine is `for_once`. Error-level guards, direct assignments, and other wrapper forms were distinguished from the inert `--inspect`/`--plan` envelope and separator noise. The Game Master accepted each set and status confirmed the mastery as complete.
