# Installer Script Chain — 📜 Next, Next, Finish

Challenge ID: `script-analysis-day-22-installer-script-chain`

The archive models a script-based installer chain with artifacts spanning shell, Python, JScript, batch, and VBScript. The task was to recover each inert descriptor and answer the route’s questions about the reconstructed behavior, handoffs, fields, and source-level decoding/control-flow patterns.

## Single Solve

- Attempt: `aab99b9e-7f11-4272-b3a6-6292f7d67128`
- Archive: `installer-script-chain-evidence.zip`
- SHA-256: `e7361c83519bbc6e113f2c97ead65f4b18930d29b34b6d34672f3b1b67e14880`
- Result: Game Master status `CORRECT`; all 1,417 answer fields were accepted.
- Flag: `f2b7736f4a9d0853fb3301699037490e`

## Time Trial (untimed)

This route advertised `run_for_time_supported`; I used the ordinary start, so no ranked timer ran and the attempt remained eligible for ordinary scoring.

- Attempt: `b393a29a-2704-46b0-b340-cd346ee811e6`
- Archive: `installer-script-chain-time-trial-evidence.zip`
- SHA-256: `047b274c527a4c389ef5f9d80ee76db784b0788dd1aca75a8fd80e4e6ce2c3f`
- Result: Game Master status `CORRECT`; all 1,417 answer fields were accepted.
- Flag: `2c3985ee023f664a8ce676d14e7772b7`

## Analysis method

I downloaded and verified each assigned archive, then extracted it with the published archive password `infected`. I inspected the scripts as text and reconstructed the data without executing any sample.

The reusable static parser is [tools/solve_installer_script_chain.py](../tools/solve_installer_script_chain.py). It handles the archive’s explicit codec markers, decodes the indicated Base64, hex, decimal, escaped, and fragment representations, and applies only the documented byte transforms such as reversal, XOR, and modulo addition or subtraction. It then parses recovered key/value descriptors and JSON fields. For source-specific questions, I inspected the inert decoder and inspect functions, batch reconstruction lines, and VBScript codec/control-flow declarations. I adjusted the parser and answer mapping for the Time Trial’s fresh variant rather than reusing its Single Solve data.

The Single Solve archive contained 153 files, including a supporting PowerShell handoff plan without a scored descriptor. The Time Trial archive likewise contained 153 files and 152 question-bearing descriptors. The Game Master validated the complete answer sets, including role and ATT&CK mappings, exact artifact-derived values, language handoffs, obfuscation details, and reconstruction syntax.

## Scope

Single Solve and Time Trial are confirmed complete. Mastery remains a separate route and has not been attempted as part of this report.

## Mastery (untimed)

The route assigned six evidence archives. I used the ordinary start, so no ranked clock ran.

- Attempt: `15943d8b-c1e6-48aa-8321-f6753cc09b4b`
- Outer archive: `installer-script-chain-mastery-evidence.zip`
- Outer SHA-256: `17210cf5a81450dfd688c0b3529f9f21299395a93bbfc13c92caf314b1580e1f`
- Result: Game Master status `CORRECT`; all 8,502 answer fields across six sets were accepted.
- Flag: `9117d8c82320171d2d97d5303da43215`

Nested evidence archive SHA-256 values:

| Set | Archive | SHA-256 |
| --- | --- | --- |
| 1 | `evidence-01.zip` | `7cd578d6fdb7b758993834e899393e690b86091ca3d2628421ba0299322d13a4` |
| 2 | `evidence-02.zip` | `2f1547a210666bede6cec43e1045bb6aeb5cabcc97d06a13f24a7e9c0a9f8e65` |
| 3 | `evidence-03.zip` | `6e6d12323b8b67b80440c8ef2ec1480ee157c131421077c1bb0495bc9a4e9b3f` |
| 4 | `evidence-04.zip` | `1a6316df632f60fdfc45a9aa1630285c473c7ad6e7055a42edf3c1c0e90026b4` |
| 5 | `evidence-05.zip` | `f05314df6979ba7359d0733c394b29a1479951a6a9efe1dcef6ebe0f6b0b8a8b` |
| 6 | `evidence-06.zip` | `70bf28a433147568110617a03f46a370f6b74f8382c15a3ccbf7ccab891a7dc4` |

I extracted the nested ZIPs with 7-Zip after checking their member paths. Each set contained 153 files: 152 scored samples and one supporting PowerShell handoff plan. The static parser recovered all 152 descriptors in every set. In addition to the encodings and transforms described above, this included space-separated decimal bytes, concatenated numeric arrays, percent-encoded bytes, and source-order reversal before a byte transform. The source-level classifications were derived independently for each set from its JScript inspect functions, batch reconstruction statements, and VBScript codec and control-flow declarations. No challenge script was run.

Single Solve, Time Trial, and Mastery are now confirmed complete.

## Tools and scripts

Project helper: [`tools/solve_installer_script_chain.py`](../tools/solve_installer_script_chain.py).
