# Bridge Troll — Day 22 Managed Native Bridge

## Solved route

- Route: Single Solve
- Game Master challenge ID: `binary-reverse-engineering-day-22-managed-native-bridge`
- Attempt: `75406c4d-ccbc-4489-a76c-403ed74c1adb`
- Timer: untimed; no deadline was returned
- Game Master result: `CORRECT`
- Flag: `7c57a0d7e1c4b60e6bb7b0a0a459fa25`
- Assigned archive: `evidence.zip`, 35,671,617 bytes
- Archive SHA-256: `67bd91bd42f63773dfb4eba19ac96e89bfd560abb7f26aabae0301854a384ce5`

## Method

The archive was downloaded through the paired Game Master endpoint, verified against the returned SHA-256, and unpacked with the published password `infected`. All samples were inspected statically. The answer builder is [solve_managed_native_bridge.py](../tools/solve_managed_native_bridge.py); it reads the archive central-directory order, uses the exact extracted bytes, parses ELF and PE headers, class files, JAR manifests, WebAssembly sections, CLR metadata, and the custom HCFG and overlay records.

For each HCFG record, the parser checked the `HCFG` header, decoded the payload by XORing with its one-byte key, verified the payload CRC32, and parsed the resulting UTF-8 JSON. Encoded carriers were decoded before validation. The PK19 overlay was unpacked with its byte transform and checked against its embedded SHA-256. The RS20 resource and scratch bounds were checked, and the scratch SHA-256 was verified. Java class methods and flags came from the classfile tables; no challenge code was executed.

## Findings

The assigned archive contained 28 members. Hashes below are SHA-256 values of the exact member bytes in Game Master ZIP central-directory order.

| Unit | Member | SHA-256 | Format / finding |
|---|---|---|---|
| d01 | `d01--sample.elf` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` | ELF64 x86-64; `.huntress` marker `BR01-CATALOG-000`; `recover_code` disassembles to `mov eax,0x1fa4; ret`, returning 8100 |
| d02 | `d02--sample.elf` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` | ELF64; C++ RTTI includes `_ZTI15DiscoveryEngine`; score symbol `_ZNK15DiscoveryEngine5scoreEPKc`; HCFG is in `.hcfg` |
| d03 | `d03--sample.dll` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` | PE/CLI, i386 machine, CLR metadata version `v4.0.30319` |
| d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | Runtime support metadata |
| d04 | `d04--sample.elf` | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` | Go ELF; HCFG decoded from the executable |
| d05 | `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` | Rust-mangled ELF; HCFG decoded from the executable |
| d06 | `d06--sample.jar` | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` | JAR; Main-Class methods parsed from the classfile; Base64 constant decodes to HCFG |
| d07 | `d07--sample.jar` | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` | JAR with coroutine runtime; HCFG recovered from its classfile/Base64 data |
| d08 | `d08--sample.elf` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` | ELF64; HCFG stored in Base64 carrier |
| d09 | `d09--sample.elf` | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` | ELF64; HCFG stored in Base64 carrier |
| d10 | `d10--sample.elf` | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` | ELF64; direct HCFG record |
| d11 | `d11--sample.elf` | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` | ELF64; HCFG stored in Base64 carrier |
| d12 | `d12--sample.elf` | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` | ELF64; HCFG in `.data`; an instruction references the exact record address, identifying a raw constant array |
| d13 | `d13--sample.elf` | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` | ELF64; HCFG stored in Base64 carrier |
| d14 | `d14--sample.elf` | `d93c0e4d52fc9111b9133ca56b8da3122c9b4186f967102c3bb5b0fe9fd3b617` | ELF64; HCFG is in the exact `.hcfg` section |
| d15 | `d15--sample-symbolized.elf` | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` | Symbolized ELF64 x86-64 |
| d15 | `d15--sample-stripped.elf` | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` | Stripped ELF64 x86-64; HCFG recovered without relying on symbols |
| d16 | `d16--sample-direct.wasm` | `d7b5f809180c62f5033830a3d53158db6eae315046fa6b50a3caed52155a5269` | wasm32; direct HCFG in a data segment |
| d16 | `d16--sample-compact.wasm` | `1c68c4062584495311c2f4894c3db30ba37e6372c17d8eede1e96a247751fdee` | wasm32; compact HCFG in a data segment |
| d17 | `d17--sample.elf` | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` | ELF64; direct HCFG record |
| d18 | `d18--sample.elf` | `00882cd984852d5cc186662a6cb7859c1cf465f7af60349bc5ffe89e3543a98e` | ELF64; direct HCFG record |
| d19 | `d19--sample.elf` | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` | ELF64; PK19 overlay at offset 10808, size 424 |
| d20 | `d20--sample.elf` | `ddd691e5065c08b8d0dd09aea1084199e76aa9f15a59b91150f31bf02db84c84` | ELF64; RS20 overlay at offset 1200888, HCFG resource size 380 |
| d21 | `d21--sample-loader.elf` | `a5fd9145ffc95a2dd330abf1e09404473527227fcba74062cc06ce3ee9cfb94e` | ELF64 loader; machine value 62 |
| d21 | `d21--sample-plugin.cmxs` | `e5d298e7ccf93c74941d8459d4b2c34b89ed46306d7661f7aa256384e3778d19` | ELF64 plugin; machine value 62; scored HCFG config is in the plugin |
| d22 | `d22--sample.dll` | `1ebccc9936901e808463f080e31c0ad79fa6dd4d9f3c9627059d9c485ac95ead` | PE/CLI, i386 machine, CLR metadata version `v4.0.30319`; HCFG at offset 15891 |
| d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` | Runtime support metadata |
| d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` | FSharp dependency; not the primary scored assembly |

The HCFG campaigns followed the archive labels `BR02-000` through `BR22-000`. Config records also supplied the per-unit domain, mutex, URL, CRC32, version, and XOR key wherever those fields were requested.

## Validation

All 264 exact answer IDs from the active start response were submitted to the Game Master. The service returned `CORRECT`; a subsequent status check confirmed the same attempt ID and returned the flag above. No target code was executed.

## Time Trial

- Game Master challenge ID: `binary-reverse-engineering-day-22-managed-native-bridge/time_trial`
- Attempt: `c2829f1a-0b8d-4cb4-b74c-cb2664deabf3`
- Timer: untimed regular scored run; `deadline` was null. Ranked timed play was not requested.
- Variant: fresh regular variant
- Game Master result: `CORRECT`
- Flag: `96d76d6d28e8ebc0df39c5e79a8f23a9`
- Assigned archive: `evidence.zip`, 35,777,944 bytes
- Archive SHA-256: `7e9515858de591d37ac6bea1481cf0256a90159eb6b576fe9fb8706e42335c4c`

The same static parser was applied to the new assigned bytes, and all 264 answer IDs were checked against this attempt's start response. This variant changed several containers: d02 and d04 were PE executables; d10 was PE with a section name containing `hcfg`; and d01 was stripped, so it had no symbol table or `recover_code` symbol. The d02 COFF table preserved the relevant decorated names, including `.text$_ZNK15DiscoveryEngine5scoreEPKc` and `.rdata$_ZTI15DiscoveryEngine`. Config campaigns identified fresh variants such as `BR02-007`, `BR03-002`, and `BR22-005`.

| Unit | Member | SHA-256 |
|---|---|---|
| d01 | `d01--sample.elf` | `e3054c3665c47935078e190906531272289c76d48bc31fdd986ae574c562af9c` |
| d02 | `d02--sample.exe` | `a957ead3928ad737463eafe9d9fb54e2c4d5b2434f3da59ffe69ae22f869ee0d` |
| d03 | `d03--sample.dll` | `68881a511297810b539f2ec38e71ca32e654e0634fb8db593b18019f0b50ed7b` |
| d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| d04 | `d04--sample.exe` | `8aca6919e036304e2bdcd8a755d8b6b9ffbcce7e8ff08e91df295a00184f8cbb` |
| d05 | `d05--sample.elf` | `40c48ec886b0765e77650bf5c68c2a9cf70fbd09eb9cf054362b38ecbcca62b5` |
| d06 | `d06--sample.jar` | `524d89a845a52ca8fc1988e048a0a298278ac184f1d1ee95b494df3cc5979bc1` |
| d07 | `d07--sample.jar` | `8678216a64ac4d785fe5e16d600d1a4b536da1b1262bd38f7578ad3a0535f1e5` |
| d08 | `d08--sample.elf` | `a89aa2ef902b580523afddef013b75c4eea6bd00db064cb4e79f49731f827f4a` |
| d09 | `d09--sample.elf` | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| d10 | `d10--sample.exe` | `0782de35b21e0d3ff9124e25a648580a0dfb5620f4a536f5b0ebd8c119da92eb` |
| d11 | `d11--sample.elf` | `2b08f579fb70ababe9452eb467789f3196aab6685ca296fbcf05b38430b9da3e` |
| d12 | `d12--sample.elf` | `05bc81871f90e5d2c3e3d317d3ae15ba3b60ae5c8e36d72ed4007b258a1753ee` |
| d13 | `d13--sample.elf` | `f3f506ecb9a43c322e85bb1880f612f46b9223ff9302c5953fae0c68bec9d88f` |
| d14 | `d14--sample.elf` | `227d0d7953f679acef2a7206c4bb5b6e6fab5164000b31ea3d1161fc1dc56048` |
| d15 | `d15--sample-symbolized.elf` | `7ca685986cdbf856045f7352029d4025cd86278b84fb30d311153149d3cfbb81` |
| d15 | `d15--sample-stripped.elf` | `c458f8def3bb0e9eeec20c3d2dfdefb0084dd7df568b8f410e2e5bbca0420159` |
| d16 | `d16--sample-direct.wasm` | `5dce8893d4be6893385db4c642179f6cccd6fd61f069426c3c87f65849962459` |
| d16 | `d16--sample-compact.wasm` | `2b25166f9ef2d5c331a131cb4db8fc4085c7e49721f1eb0c33a572287cf33e16` |
| d17 | `d17--sample.elf` | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` |
| d18 | `d18--sample.elf` | `261add139b2b7201da3c5323aa7482e6e6ec0e8b09604e3c9aef4f223e922d34` |
| d19 | `d19--sample.elf` | `32e143d9ac8069dd0c52ac59236bd2beb292c22573d9af470265e797a3dbbdde` |
| d20 | `d20--sample.elf` | `0a40c8f5809e61a472b3178145257ea0f0839de291403d8385b7a7d7d636b1c5` |
| d21 | `d21--sample-loader.elf` | `6aebaf471f34c00ab8f514ec57579821a1af6a0ce22576a58948fe4beecf185e` |
| d21 | `d21--sample-plugin.cmxs` | `0dfc5e17a9a27dc7bdae51f4f8562c87164bd0043bc52f88b612b63fae6a4b9d` |
| d22 | `d22--sample.dll` | `dca9b04785778e373825a598447cd58e027135cf2c39aef3a5b97c696b28c2c7` |
| d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |

A status check confirmed `CORRECT` for this exact attempt and returned the flag above.

## Mastery Mode

- Game Master challenge ID: `binary-reverse-engineering-day-22-managed-native-bridge/mastery`
- Attempt: `9218bd21-84cf-4d37-aa48-12be7f964f5a`
- Timer: untimed regular scored run; `deadline` was null.
- Assigned material: six distinct fresh `evidence.zip` archives, 1,584 questions and answer IDs total.
- Game Master result: `CORRECT`
- Flag: `59e84f3e3c5792888c9a4c8f7634af17`

Each delivery was downloaded through the assigned capability, verified against the start response SHA-256, extracted with the published archive password, and analyzed statically. The six answer namespaces (`set1.` through `set6.`) were kept tied to their respective archives. The same parsers were applied independently to each set; the 1,584 exact answer IDs were submitted together, and a status check confirmed `CORRECT` for this attempt. No samples were executed.

| Set | Archive size | Archive SHA-256 | HCFG campaigns (d02 / d22) |
|---:|---:|---|---|
| 1 | 35,777,922 bytes | `b728d5cc8e4e399a3d8678ffdc2e93d7e11bedeaefa0fc80369f59d19dddfbaf` | `BR02-000` / `BR22-007` |
| 2 | 35,671,064 bytes | `3073b04ba762788647eebae23f1795e3cd05cefb67bcc280d34980a6da5c1dd4` | `BR02-001` / `BR22-004` |
| 3 | 35,777,934 bytes | `dee28b4e89caae7f818f5b22cbb6511524014574ad70af838c68687924b9aa78` | `BR02-001` / `BR22-001` |
| 4 | 35,671,133 bytes | `0dba0112632f1d3e78bd269622d7ab8e301ada97b1b77bb664c306824f757636` | `BR02-002` / `BR22-006` |
| 5 | 35,777,977 bytes | `e9dc67f964fc512c32ef932c6f0f773e415c33461ea60edc35f20b690f3ae3cc` | `BR02-002` / `BR22-003` |
| 6 | 35,700,752 bytes | `217f7ec8552068388edce12a669adf59521a45ab301fb576e0fac574b97f8b25` | `BR02-001` / `BR22-000` |

The complete per-member SHA-256 inventory follows. Member ordering is the Game Master ZIP central-directory order.

| Set | Unit | Member | SHA-256 |
|---:|---:|---|---|
| 1 | d01 | `d01--sample.elf` | `bdf1ffed95afdba9ec25c2c7ecf20693451dceca392caae287a620d46c963c6c` |
| 1 | d02 | `d02--sample.exe` | `9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f` |
| 1 | d03 | `d03--sample.dll` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| 1 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 1 | d04 | `d04--sample.exe` | `bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97` |
| 1 | d05 | `d05--sample.elf` | `2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33` |
| 1 | d06 | `d06--sample.jar` | `8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f` |
| 1 | d07 | `d07--sample.jar` | `11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8` |
| 1 | d08 | `d08--sample.elf` | `a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097` |
| 1 | d09 | `d09--sample.elf` | `31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c` |
| 1 | d10 | `d10--sample.exe` | `a449342f396af68e11825293fa1a678651251fbf1b9cd7bdb8cb5ab303d98071` |
| 1 | d11 | `d11--sample.elf` | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| 1 | d12 | `d12--sample.elf` | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| 1 | d13 | `d13--sample.elf` | `4ecb696de15c3a498b666af287e62dedcb66fcc9161273a3cb11d6ea2f2138e0` |
| 1 | d14 | `d14--sample.elf` | `2a078d374fe8e8e5d2efd3bc698e39fdbfdb01d9cf27e2f8fb89b21db2e155aa` |
| 1 | d15 | `d15--sample-symbolized.elf` | `7e4a1f03afda5e39e564323afd20f662593c55503dc8689f5fb378f9b3c7834c` |
| 1 | d15 | `d15--sample-stripped.elf` | `64e80daffed5667511aa585242f2b6563ddb898f4a01ad627c13cd25149d9dc1` |
| 1 | d16 | `d16--sample-direct.wasm` | `f69c4caa17b6f3aa3e53fbefacee97354a52e179ba4463597353309c0caa0d53` |
| 1 | d16 | `d16--sample-compact.wasm` | `46c73e56a5c24b49fcea9ff7e498fc4c0886ef24a7590b86e491b6565e842ea9` |
| 1 | d17 | `d17--sample.elf` | `7eb52f45ab82772a1ee29f1c7c1f03e82d0c197e5c6545ff587316ef5924d98e` |
| 1 | d18 | `d18--sample.elf` | `933be5188c0c7a6f1cb15d9b3f30d423b0cbed3d913891acbaee20fa6f855e49` |
| 1 | d19 | `d19--sample.elf` | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |
| 1 | d20 | `d20--sample.elf` | `3031a2d4048edfb55fab0bdb34fa28149679f6705e7ffcb087666ff2e60bbb28` |
| 1 | d21 | `d21--sample-loader.elf` | `75d38b11c733ebf9d9d69775e7fa5ff7bb638a55876fab7160ad03c5ac3b5247` |
| 1 | d21 | `d21--sample-plugin.cmxs` | `f0ee6bb2029e7505ffb74872df6f7a9acae36110d49f7191dfe4665f803677c7` |
| 1 | d22 | `d22--sample.dll` | `0f8334fc61304cbbbf457c3144cffff72fb7a23b0b591e515e266d0eb12321c6` |
| 1 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 1 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| 2 | d01 | `d01--sample.elf` | `bdf1ffed95afdba9ec25c2c7ecf20693451dceca392caae287a620d46c963c6c` |
| 2 | d02 | `d02--sample.elf` | `a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2` |
| 2 | d03 | `d03--sample.dll` | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| 2 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 2 | d04 | `d04--sample.elf` | `173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5` |
| 2 | d05 | `d05--sample.elf` | `359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c` |
| 2 | d06 | `d06--sample.jar` | `e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1` |
| 2 | d07 | `d07--sample.jar` | `7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c` |
| 2 | d08 | `d08--sample.elf` | `f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48` |
| 2 | d09 | `d09--sample.elf` | `adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69` |
| 2 | d10 | `d10--sample.elf` | `bc5ae6af7c14106ed6652574359285d97590e1d232a7b8be6151d6e915e4face` |
| 2 | d11 | `d11--sample.elf` | `ef6e36955793c0d41966e2727c80417c136cefc9f18b98285917ace224455617` |
| 2 | d12 | `d12--sample.elf` | `fd116e0e351a96ca5c2071249e9c6cc684bd8859fde8e71ea201b1bc4f7c815a` |
| 2 | d13 | `d13--sample.elf` | `c0c173c2a2dcea0c59a4c1ae066ebfd4129025862f1573ae129be81b2c636a35` |
| 2 | d14 | `d14--sample.elf` | `262e170dd7399724c9e09cd25d959cc2260cde506f8ed322cd4d6f4093c64359` |
| 2 | d15 | `d15--sample-symbolized.elf` | `a9a77ce8add57e5856823ddb781731a067e100aee3b4638c3460a5e65cc4893a` |
| 2 | d15 | `d15--sample-stripped.elf` | `b02d268916d242f6e8e780cf49e5639d0c6840c4f376543a65c6429888663ab5` |
| 2 | d16 | `d16--sample-direct.wasm` | `bfc4ac0f057736e4f0a752c1ccbe35402e4e11eb890bf22c5689c8c0dbd734cb` |
| 2 | d16 | `d16--sample-compact.wasm` | `d532bf09c5b854cb01e4be023480690c54cfc5bb0797fd81ab2a8e5b50dbb97b` |
| 2 | d17 | `d17--sample.elf` | `128fbb2bf7d67db362a7f1f9bf27454e5398468cdf6b8b795e25e8c28d605e2a` |
| 2 | d18 | `d18--sample.elf` | `00882cd984852d5cc186662a6cb7859c1cf465f7af60349bc5ffe89e3543a98e` |
| 2 | d19 | `d19--sample.elf` | `d624ca9c4da82aae4aa06edb920fe2816a8bdd26e7f221680261a125b6c26879` |
| 2 | d20 | `d20--sample.elf` | `019377c48411d1ccf9a152a1a8874a983f1c7e4868baf9a2cc7cdf76e433af03` |
| 2 | d21 | `d21--sample-loader.elf` | `03d8a5400ead7d84419d876280c5eded23bc7ace16f07e8b2bf5b1e0b01cacf1` |
| 2 | d21 | `d21--sample-plugin.cmxs` | `8c30c3e7d9a01dbb06fd935a48333ea9ebf0ee4d1b4e84f882f618e64da9b7bf` |
| 2 | d22 | `d22--sample.dll` | `b426823a567c08893959f0a081b0779a2deea3ba9a7102d2f26714c3e4e17827` |
| 2 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 2 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| 3 | d01 | `d01--sample.elf` | `bdf1ffed95afdba9ec25c2c7ecf20693451dceca392caae287a620d46c963c6c` |
| 3 | d02 | `d02--sample.exe` | `1db6cd34482281e61ef34dd5695745b9370549e63a5241afbc7c5f9bda911cfc` |
| 3 | d03 | `d03--sample.dll` | `d1493de4b3d5c8a5db1440a94b5204644cdba19853d894722c47a82d1c65ad17` |
| 3 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 3 | d04 | `d04--sample.exe` | `cdb3fc656aa538e62e1ee567055921e0ef2b9140b419e8325ffd7c594659ccd1` |
| 3 | d05 | `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| 3 | d06 | `d06--sample.jar` | `3946fb7a66d6a47d0d7d9d553e229999e845834537ab522a1b64fc8211b0a3b6` |
| 3 | d07 | `d07--sample.jar` | `2febb8701f76f617bedc8d80ef398aab87472c6209fd5881c0dfea2d70dc6e93` |
| 3 | d08 | `d08--sample.elf` | `c31d49dbf7740c71c2990d667353f33e449927deb9caa4cc704aaba624c6467b` |
| 3 | d09 | `d09--sample.elf` | `9c30b74048a654312b88f319878f4cbb52f5e633e3b1e7776248285876f8d4e2` |
| 3 | d10 | `d10--sample.exe` | `30477f3a7b1fc911c732d8dbf68362e9d28d0c20102aa32b41b2c1e0b04fbae1` |
| 3 | d11 | `d11--sample.elf` | `4db31f97b3ce1b44553e5ed8ef14c17aa10a91203ecd954dd532dcf81054196e` |
| 3 | d12 | `d12--sample.elf` | `0f49a991fbba928a9bc167bdb09bcd8b81c580a3e30ca4e427f331fd0acd1d4f` |
| 3 | d13 | `d13--sample.elf` | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` |
| 3 | d14 | `d14--sample.elf` | `a40e5c597c04b4334547fe9a53aefb80e9a01d8bf64da9396cd2d135c22072ab` |
| 3 | d15 | `d15--sample-symbolized.elf` | `d51fd845d6a449a0b7ef3da6bb4c6b69a1b465ca9ed3ac333874d2852684572a` |
| 3 | d15 | `d15--sample-stripped.elf` | `e8090724f8ba9b74752b4f1af580f7955a27d0a9d56b89c89c51ba41ea7fab51` |
| 3 | d16 | `d16--sample-direct.wasm` | `4bc627247fc5bd9cf16d796476071b3228e8da9967c5fe49ac7e4e8ae27b7fbc` |
| 3 | d16 | `d16--sample-compact.wasm` | `3c8582b6dcf6d94546f0e981504817741bb8f034486c9a9ea4db304d7a969beb` |
| 3 | d17 | `d17--sample.elf` | `3142d154114a00f966fe20e60521591253d4312878d1df0567281cbd9e31a8b5` |
| 3 | d18 | `d18--sample.elf` | `1f21c023457428e6fc3d32d65c914c4a41fc5178eecc228e3f81d79ddd69091a` |
| 3 | d19 | `d19--sample.elf` | `d7fe99150a2a8c3db2b2ef7f455336be2b8fa10838997763900d41b4d8dd3bc9` |
| 3 | d20 | `d20--sample.elf` | `6d7a7d6403d5f30324e0e5502acdda8b4ee7fd07e138de85f3c7e6cc40431b50` |
| 3 | d21 | `d21--sample-loader.elf` | `a5fd9145ffc95a2dd330abf1e09404473527227fcba74062cc06ce3ee9cfb94e` |
| 3 | d21 | `d21--sample-plugin.cmxs` | `e5d298e7ccf93c74941d8459d4b2c34b89ed46306d7661f7aa256384e3778d19` |
| 3 | d22 | `d22--sample.dll` | `500b33c4aff9601bd54954c5c78a3a624db3104b99d3852ff623e71fbfc45ca4` |
| 3 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 3 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| 4 | d01 | `d01--sample.elf` | `bdf1ffed95afdba9ec25c2c7ecf20693451dceca392caae287a620d46c963c6c` |
| 4 | d02 | `d02--sample.elf` | `6e8892f0f754bc338514b114a9c37c77db44a2aecc6b38456056ddee7ea78c39` |
| 4 | d03 | `d03--sample.dll` | `c092951f59c6187bc8cd9ae0be744df836808ef08c131739c3c3c7ce43479cbf` |
| 4 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 4 | d04 | `d04--sample.elf` | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |
| 4 | d05 | `d05--sample.elf` | `2f292a4d3eeff638ab215e19f814f514d5b8f78fef0f14c039701a70bbeaf0ef` |
| 4 | d06 | `d06--sample.jar` | `7377670d5cf443d9d5eea89c9eb6de66aa3544515f0f7ff9c16188e6105367f5` |
| 4 | d07 | `d07--sample.jar` | `ca64873051662f85d361bf2c35d9260a6b47f4ebe58fbd4cbf42339630e64fe4` |
| 4 | d08 | `d08--sample.elf` | `0132020901b18a9b5ebd9ceb9f7b451b8a24b59d23cafc48005c611e105ad806` |
| 4 | d09 | `d09--sample.elf` | `fcb63ec6f82f6fe79057707734000c1e1edc847c79e9e3e9dca5287e76b6d5b3` |
| 4 | d10 | `d10--sample.elf` | `46cae7c39fb2a5e24b11182b0b87dff2d6d6b359e12940446f1a70bfb36808ff` |
| 4 | d11 | `d11--sample.elf` | `aee2f62d87a7606def759208b0da3bc4f86ed73c2fba78ca9c349c7e4f5a9012` |
| 4 | d12 | `d12--sample.elf` | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` |
| 4 | d13 | `d13--sample.elf` | `cd4ffc9d53f6932961c652922ec3e3734d838f9aeea2bef76db274b6019692d7` |
| 4 | d14 | `d14--sample.elf` | `d2edc1d5f3ec3ea98146f99431b16795e6f52fc6f30dd9b16803ffa85a5a77ed` |
| 4 | d15 | `d15--sample-symbolized.elf` | `6486d52593f13bd7fd29099967af86dc96ca9b03e226171947eb07166d3e0432` |
| 4 | d15 | `d15--sample-stripped.elf` | `2b34b2be1e67c97d5fc8d0723bcc4f189c82358fb32a7d524e659857ec1e4e8a` |
| 4 | d16 | `d16--sample-direct.wasm` | `36de54d4e986e929a842548ec478f70eaf2f086bfcf7c236c88877ea00faa0a5` |
| 4 | d16 | `d16--sample-compact.wasm` | `ac3666e5fe9833a02caa26c1fa85d16c394055904a399bf5784cd8721751a3c9` |
| 4 | d17 | `d17--sample.elf` | `924eb5fe93ef43b5af53343b01778f83ad5a414f3931d703c85591cb372f45e3` |
| 4 | d18 | `d18--sample.elf` | `eaf4966437e6b581a3e473685f3957f90bc9722bc8af19c7aee5e1eeeceebfcb` |
| 4 | d19 | `d19--sample.elf` | `68d6996d551ec6f58d0b63d88dfcd6bc3dd3665ba2e6603a043413defe66e52a` |
| 4 | d20 | `d20--sample.elf` | `ddd691e5065c08b8d0dd09aea1084199e76aa9f15a59b91150f31bf02db84c84` |
| 4 | d21 | `d21--sample-loader.elf` | `b08757591840b4bb669c8fa9af96b20b0cce4dc61454ca93def5e066a4e58cf5` |
| 4 | d21 | `d21--sample-plugin.cmxs` | `40f637250f9856174101156f822a6f93a86d49167918a3b61d1ba0c96fc3e707` |
| 4 | d22 | `d22--sample.dll` | `99f591d0954da412a43ef243ce6f78de9f8e262ab215e50ab8667b7e71944794` |
| 4 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 4 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| 5 | d01 | `d01--sample.elf` | `bdf1ffed95afdba9ec25c2c7ecf20693451dceca392caae287a620d46c963c6c` |
| 5 | d02 | `d02--sample.exe` | `7af806183a8db4bf71f0c3d6996718270cdd8286e4b0e0ae56bb8d5821822546` |
| 5 | d03 | `d03--sample.dll` | `9686e6dab1cf8713d440188ef0d943421541ddfece686b8e18aa72802395fadf` |
| 5 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 5 | d04 | `d04--sample.exe` | `82599eee6ceae6147c7cb342b5277b79e2deacebae33be8164234277dd6a4c4e` |
| 5 | d05 | `d05--sample.elf` | `cb390c7dcb224aca2c23bdef306130dd5fd51ec6b6b47a7df3180a334c12c6a3` |
| 5 | d06 | `d06--sample.jar` | `dfb3b646b06ff9349775677c1533a244541acfba5834106fd2739634532650b4` |
| 5 | d07 | `d07--sample.jar` | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| 5 | d08 | `d08--sample.elf` | `80ba7e1ab243b4dca46d0b9bc93e6f6fe39dc7ec9eafb34da9bfc99c36aa146d` |
| 5 | d09 | `d09--sample.elf` | `6d742be643831355f824f040a5d40c462401266c9180196410044afd5a0ebf4f` |
| 5 | d10 | `d10--sample.exe` | `641e93917631e4016d8b2470ca1649d990cab3106d4066f250607d5f56e5b827` |
| 5 | d11 | `d11--sample.elf` | `5c60e3ab9ef81f2d8a56a2cd8e89ef5dd6ec184941a1ddd4ab87d1ba63ec67f4` |
| 5 | d12 | `d12--sample.elf` | `bf571c0fd8dd9b09ae03878d6fabd0fffdb394fce94ce4d8bbff9703382bb48d` |
| 5 | d13 | `d13--sample.elf` | `7bafd20f812127b61304a8aae438e63595e7165e3c846820702dbc49af691b8e` |
| 5 | d14 | `d14--sample.elf` | `ddc8a5a851b28ae9bd10b4d3a477da6bf7b089a192ce4f4ea6becff04beb42a9` |
| 5 | d15 | `d15--sample-symbolized.elf` | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` |
| 5 | d15 | `d15--sample-stripped.elf` | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` |
| 5 | d16 | `d16--sample-direct.wasm` | `d4203d3f65d699c903d3d5fbcb856da8f1a30f3c333bda13150eb4dda9cb1ee5` |
| 5 | d16 | `d16--sample-compact.wasm` | `7e7586c784059d2d378f066f617d5e7155aff1e4b5ff844aabeb6b98402176f4` |
| 5 | d17 | `d17--sample.elf` | `f81f8e53671e3d9f0abb10efbfa2ad4bab76b908743755b3f4d81d02cff3150d` |
| 5 | d18 | `d18--sample.elf` | `269b906bb12b0bb7c2e63b07e9e713b3903b3765902f5cd73b36b763b3d0f89f` |
| 5 | d19 | `d19--sample.elf` | `82f3ba9ee310789359f4940e3e4febb66be48dbaeaf5e2b65d59e69cba1a5963` |
| 5 | d20 | `d20--sample.elf` | `ddf2402e0fd0cb300144f0de6690f27097d052e5a659da55f805c7755e47f31b` |
| 5 | d21 | `d21--sample-loader.elf` | `7e58d1742fd254675e8591ef74aa2f8f2cddc14f6214e00fa007cf438fc2bc55` |
| 5 | d21 | `d21--sample-plugin.cmxs` | `796e73abf07104d3e0b62a261df498da1afa28b855e5b35fce89a1d32aa90ae3` |
| 5 | d22 | `d22--sample.dll` | `6233be9b56875292bffcd63371d418914edb76e2f31082b8deb2ff782d1aa279` |
| 5 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 5 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| 6 | d01 | `d01--sample.elf` | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 6 | d02 | `d02--sample.elf` | `a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2` |
| 6 | d03 | `d03--sample.dll` | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| 6 | d03 | `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 6 | d04 | `d04--sample.exe` | `bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97` |
| 6 | d05 | `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| 6 | d06 | `d06--sample.jar` | `7377670d5cf443d9d5eea89c9eb6de66aa3544515f0f7ff9c16188e6105367f5` |
| 6 | d07 | `d07--sample.jar` | `2febb8701f76f617bedc8d80ef398aab87472c6209fd5881c0dfea2d70dc6e93` |
| 6 | d08 | `d08--sample.elf` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| 6 | d09 | `d09--sample.elf` | `9c30b74048a654312b88f319878f4cbb52f5e633e3b1e7776248285876f8d4e2` |
| 6 | d10 | `d10--sample.elf` | `81c73ffd89fae7757be533c7bda2c2124bf06af01fc304c53731ba10034e1c13` |
| 6 | d11 | `d11--sample.elf` | `aee2f62d87a7606def759208b0da3bc4f86ed73c2fba78ca9c349c7e4f5a9012` |
| 6 | d12 | `d12--sample.elf` | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| 6 | d13 | `d13--sample.elf` | `882efdb0a1011ce9858d15e511899e202c2e18c3a154fad97a6f43bf2caa28b7` |
| 6 | d14 | `d14--sample.elf` | `d93c0e4d52fc9111b9133ca56b8da3122c9b4186f967102c3bb5b0fe9fd3b617` |
| 6 | d15 | `d15--sample-symbolized.elf` | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` |
| 6 | d15 | `d15--sample-stripped.elf` | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` |
| 6 | d16 | `d16--sample-direct.wasm` | `f69c4caa17b6f3aa3e53fbefacee97354a52e179ba4463597353309c0caa0d53` |
| 6 | d16 | `d16--sample-compact.wasm` | `46c73e56a5c24b49fcea9ff7e498fc4c0886ef24a7590b86e491b6565e842ea9` |
| 6 | d17 | `d17--sample.elf` | `3142d154114a00f966fe20e60521591253d4312878d1df0567281cbd9e31a8b5` |
| 6 | d18 | `d18--sample.elf` | `933be5188c0c7a6f1cb15d9b3f30d423b0cbed3d913891acbaee20fa6f855e49` |
| 6 | d19 | `d19--sample.elf` | `68d6996d551ec6f58d0b63d88dfcd6bc3dd3665ba2e6603a043413defe66e52a` |
| 6 | d20 | `d20--sample.elf` | `5704897b87b2f4a772e09d6e8274c16ca8d983153a65c655075c506219646c47` |
| 6 | d21 | `d21--sample-loader.elf` | `6381708304fb6ccebe3dda6625efb684c3140b5fd93bf550f773d5ee65eca2ca` |
| 6 | d21 | `d21--sample-plugin.cmxs` | `5c41dd4d78c947e2db961875fe1a4d2862f6faba0faf4bbad82f0fd77bc93bbc` |
| 6 | d22 | `d22--sample.dll` | `1ebccc9936901e808463f080e31c0ad79fa6dd4d9f3c9627059d9c485ac95ead` |
| 6 | d22 | `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 6 | d22 | `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |

## Tools and scripts

Project helper: [`tools/solve_managed_native_bridge.py`](../tools/solve_managed_native_bridge.py).
