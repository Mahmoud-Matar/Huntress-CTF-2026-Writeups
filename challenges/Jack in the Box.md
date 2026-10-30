# Jack in the Box — Day 19 Single Solve

## Route and result

- **Challenge:** Jack in the Box
- **Challenge ID:** `binary-reverse-engineering-day-19-static-unpacking`
- **Mode:** Single Solve, untimed
- **Attempt:** `d11fab2b-df1a-4408-a99b-fcf122086270`
- **Assigned archive:** `evidence.zip`
- **Archive SHA-256:** `c706dcbf94c77216a4b1f731de8c9b2425eba5e2af46e58131051a405911fdc9`
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `c7f54572bf4b5fd2398c19b35fd6f7e9`

## Method and findings

I extracted the assigned archive with its published password and statically processed the 22 members. The first 18 specimen groups use the same header, section, symbol-table, classfile, WebAssembly, and HCFG parsing methods documented in the Flow State write-up. For Day 19, the requested ELF64 x86-64 member ends with a `PK19` overlay. Its overlay starts at byte 10808 and extends 424 bytes to end-of-file. The header declares a packed payload of 380 bytes.

I decoded each payload byte using `ror8(byte XOR k2, 3) XOR k1`, checked the SHA-256 stored in the overlay, and parsed the resulting HCFG record at unpacked offset 0. The record has version 1, CRC32 `0xd02e2211`, and campaign `BR19-000`; the validated values also identify `node-000.day19.example.invalid`, mutex `Global\HuntressBR19_000`, and URL `https://node-000.day19.example.invalid/api/BR19-000`. No challenge binary was executed.

## Archive member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | 16,640 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | 9,216 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |
| `d05--sample.elf` | 3,997,704 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| `d06--sample.jar` | 3,099 | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` |
| `d07--sample.jar` | 5,152,890 | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| `d08--sample.elf` | 67,264,576 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | 60,672 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| `d10--sample.elf` | 134,720 | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` |
| `d11--sample.elf` | 1,021,696 | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| `d12--sample.elf` | 100,976 | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` |
| `d13--sample.elf` | 749,208 | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` |
| `d14--sample.elf` | 17,304 | `d93c0e4d52fc9111b9133ca56b8da3122c9b4186f967102c3bb5b0fe9fd3b617` |
| `d15--sample-symbolized.elf` | 16,160 | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` |
| `d15--sample-stripped.elf` | 14,360 | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` |
| `d16--sample-direct.wasm` | 570 | `d7b5f809180c62f5033830a3d53158db6eae315046fa6b50a3caed52155a5269` |
| `d16--sample-compact.wasm` | 561 | `1c68c4062584495311c2f4894c3db30ba37e6372c17d8eede1e96a247751fdee` |
| `d17--sample.elf` | 1,393,288 | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` |
| `d18--sample.elf` | 16,544 | `00882cd984852d5cc186662a6cb7859c1cf465f7af60349bc5ffe89e3543a98e` |
| `d19--sample.elf` | 11,232 | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |

## Time Trial

- **Attempt:** `5fb0796d-46c5-4482-91ef-8219067f0045`
- **Mode:** Time Trial, untimed (`deadline: null`; `run_for_time` was not requested)
- **Assigned archive SHA-256:** `3038ee5fe91b8948619ee3e6bab7cfa0db6ee83189fca15d57c3671a51b59f3e`
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `4c33a4e10e8235415bf8064b51a69e8b`

The archive again contained 22 members. I recomputed each member hash and checked the new Day 19 `PK19` overlay against the digest embedded in its header before decoding the HCFG fields.

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `e3054c3665c47935078e190906531272289c76d48bc31fdd986ae574c562af9c` |
| `d02--sample.exe` | 279,699 | `9760313adb7452e3424d6830b75ee2947965d862d7d29e493c207c3f992c268f` |
| `d03--sample.dll` | 9,216 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | 1,956,352 | `bb5fcf8ad12b99c3e223a03b4120cb76a6b3f0784861ca49e9bb192f579bbd97` |
| `d05--sample.elf` | 3,997,704 | `2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33` |
| `d06--sample.jar` | 3,104 | `8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f` |
| `d07--sample.jar` | 5,152,892 | `11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8` |
| `d08--sample.elf` | 67,264,576 | `a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097` |
| `d09--sample.elf` | 60,672 | `31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c` |
| `d10--sample.exe` | 84,480 | `a449342f396af68e11825293fa1a678651251fbf1b9cd7bdb8cb5ab303d98071` |
| `d11--sample.elf` | 1,021,696 | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| `d12--sample.elf` | 100,976 | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| `d13--sample.elf` | 749,208 | `4ecb696de15c3a498b666af287e62dedcb66fcc9161273a3cb11d6ea2f2138e0` |
| `d14--sample.elf` | 17,304 | `2a078d374fe8e8e5d2efd3bc698e39fdbfdb01d9cf27e2f8fb89b21db2e155aa` |
| `d15--sample-symbolized.elf` | 16,160 | `7e4a1f03afda5e39e564323afd20f662593c55503dc8689f5fb378f9b3c7834c` |
| `d15--sample-stripped.elf` | 14,360 | `64e80daffed5667511aa585242f2b6563ddb898f4a01ad627c13cd25149d9dc1` |
| `d16--sample-direct.wasm` | 570 | `f69c4caa17b6f3aa3e53fbefacee97354a52e179ba4463597353309c0caa0d53` |
| `d16--sample-compact.wasm` | 561 | `46c73e56a5c24b49fcea9ff7e498fc4c0886ef24a7590b86e491b6565e842ea9` |
| `d17--sample.elf` | 1,393,288 | `7eb52f45ab82772a1ee29f1c7c1f03e82d0c197e5c6545ff587316ef5924d98e` |
| `d18--sample.elf` | 16,544 | `933be5188c0c7a6f1cb15d9b3f30d423b0cbed3d913891acbaee20fa6f855e49` |
| `d19--sample.elf` | 11,232 | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |


## Mastery Mode

- **Attempt:** `88017a9e-b14d-4dab-b981-e29967c702e5`
- **Mode:** Mastery, untimed (`deadline: null`; the timed option was not requested)
- **Assignment:** five evidence archives; 1,140 total answer fields across five sets
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `677439e833490521dc798a741f25ba1c`

Each encrypted archive was downloaded from the assigned capability URL and verified against the SHA-256 supplied by the Game Master. I extracted using the published `infected` password and analyzed the 22 files per set without executing the challenge binaries. The first 18 daily groups reuse the ELF, PE, managed assembly, JAR, WebAssembly, and HCFG parsing documented above. For Day 19, each `PK19` overlay begins at offset 10808, declares 380 packed bytes, and decodes with `ror8(byte XOR k2, 3) XOR k1`. The embedded digest validated the unpacked HCFG record at offset 0. The five validated campaigns were BR19-002, BR19-001, BR19-000, BR19-007, and BR19-006.

The first full submission was rejected. Per-set and recursive field checks isolated the errors to the Day 15 and Day 16 artifact hash fields. Those questions require the original ZIP central-directory order; sorting the filenames reversed the symbolized/stripped ELF pair and direct/compact WebAssembly pair. I recomputed those hashes in the archive’s original order, resubmitted the corrected fields, and received `CORRECT`.

### Set 1 — campaign `BR19-002`

- **Assigned archive SHA-256:** `39c597dc0190b0e5d142c00f4d996c54a4dc0ee57fd57dc5c3f3eae2e56f86b0`

| Archive member (central-directory order) | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.exe` | 279,699 | `46dcdb7977162f9a4973301e84735eeabcfb7347d4c1f3ccf9adce77e5d18ba9` |
| `d03--sample.dll` | 9,216 | `68881a511297810b539f2ec38e71ca32e654e0634fb8db593b18019f0b50ed7b` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | 1,956,352 | `ed5371dfd8fff9d535f4f03e2a2d99318a7447b3652f314db415e52e3434ad16` |
| `d05--sample.elf` | 3,997,704 | `40c48ec886b0765e77650bf5c68c2a9cf70fbd09eb9cf054362b38ecbcca62b5` |
| `d06--sample.jar` | 3,104 | `524d89a845a52ca8fc1988e048a0a298278ac184f1d1ee95b494df3cc5979bc1` |
| `d07--sample.jar` | 5,152,890 | `8678216a64ac4d785fe5e16d600d1a4b536da1b1262bd38f7578ad3a0535f1e5` |
| `d08--sample.elf` | 67,264,576 | `a89aa2ef902b580523afddef013b75c4eea6bd00db064cb4e79f49731f827f4a` |
| `d09--sample.elf` | 60,672 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| `d10--sample.exe` | 84,480 | `18c2de6dff6465842a9ed87597585a6d20ade3718519fdd237b1969bf26c0143` |
| `d11--sample.elf` | 1,021,696 | `2b08f579fb70ababe9452eb467789f3196aab6685ca296fbcf05b38430b9da3e` |
| `d12--sample.elf` | 100,976 | `05bc81871f90e5d2c3e3d317d3ae15ba3b60ae5c8e36d72ed4007b258a1753ee` |
| `d13--sample.elf` | 749,208 | `f3f506ecb9a43c322e85bb1880f612f46b9223ff9302c5953fae0c68bec9d88f` |
| `d14--sample.elf` | 17,304 | `227d0d7953f679acef2a7206c4bb5b6e6fab5164000b31ea3d1161fc1dc56048` |
| `d15--sample-symbolized.elf` | 16,160 | `7ca685986cdbf856045f7352029d4025cd86278b84fb30d311153149d3cfbb81` |
| `d15--sample-stripped.elf` | 14,360 | `c458f8def3bb0e9eeec20c3d2dfdefb0084dd7df568b8f410e2e5bbca0420159` |
| `d16--sample-direct.wasm` | 570 | `5dce8893d4be6893385db4c642179f6cccd6fd61f069426c3c87f65849962459` |
| `d16--sample-compact.wasm` | 561 | `2b25166f9ef2d5c331a131cb4db8fc4085c7e49721f1eb0c33a572287cf33e16` |
| `d17--sample.elf` | 1,393,288 | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` |
| `d18--sample.elf` | 16,544 | `261add139b2b7201da3c5323aa7482e6e6ec0e8b09604e3c9aef4f223e922d34` |
| `d19--sample.elf` | 11,232 | `32e143d9ac8069dd0c52ac59236bd2beb292c22573d9af470265e797a3dbbdde` |

### Set 2 — campaign `BR19-001`

- **Assigned archive SHA-256:** `61041f94ae0c48d8d6371bde594b1c65e2bbe29bda0bbafd40af62c2472182cd`

| Archive member (central-directory order) | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.elf` | 16,640 | `3fcf8f637cea918821000c09fc011e15615302270de70a4ceb6937965e13dfdf` |
| `d03--sample.dll` | 9,216 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `6010c6aacea52a9c0dab0cd9206ca309213eb8e7ccc46e0b729287ec9bd61ae5` |
| `d05--sample.elf` | 3,997,704 | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| `d06--sample.jar` | 3,101 | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| `d07--sample.jar` | 5,152,893 | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| `d08--sample.elf` | 67,264,576 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | 60,704 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| `d10--sample.elf` | 134,720 | `81c73ffd89fae7757be533c7bda2c2124bf06af01fc304c53731ba10034e1c13` |
| `d11--sample.elf` | 1,021,696 | `e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6` |
| `d12--sample.elf` | 100,976 | `b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a` |
| `d13--sample.elf` | 749,208 | `c1853767bde385a74c9e553fe7fcb50f9d127b3ea8211170a0a4168b192c39b0` |
| `d14--sample.elf` | 17,304 | `021b13160e53fb918186dc106d26ef95a18aeedc109425a3839a17fbf5ea93f4` |
| `d15--sample-symbolized.elf` | 16,160 | `aa74a880736ea29bfdbe8f531de3c9bd8815db1eaafbff9a05cdad4aaa8802ec` |
| `d15--sample-stripped.elf` | 14,360 | `0eda4bf4620832a21aba470df4d8c6e83bafa149ebe5cbb0c6792a5cf7bb9008` |
| `d16--sample-direct.wasm` | 570 | `d7b5f809180c62f5033830a3d53158db6eae315046fa6b50a3caed52155a5269` |
| `d16--sample-compact.wasm` | 561 | `1c68c4062584495311c2f4894c3db30ba37e6372c17d8eede1e96a247751fdee` |
| `d17--sample.elf` | 1,393,288 | `a9bcbf19bc8e44ffda433c0799bcd7e3417c4bf52292a1315e65b85eff929048` |
| `d18--sample.elf` | 16,544 | `36d7ada216b57cb52ef8d469d8acc62787741bb1ee3deb6a922995e9c2ad76b5` |
| `d19--sample.elf` | 11,232 | `90d27a82af22b386d617224e505ee9fbd3743189f10909306cb16bbd75cd102d` |

### Set 3 — campaign `BR19-000`

- **Assigned archive SHA-256:** `a2a26c0a1926d0041a9a4ecf3aba90463053fcf3902809c6f5c18ec322e99e5b`

| Archive member (central-directory order) | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.exe` | 279,699 | `23035f29831842e409d174d4692927ec4447336320f387767b6bb8839bc5ff8a` |
| `d03--sample.dll` | 9,216 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | 1,956,352 | `374cf375c5c4e50b15f30f942b79e962152f91c633ea83a45c7926266f458bda` |
| `d05--sample.elf` | 3,997,704 | `2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33` |
| `d06--sample.jar` | 3,104 | `8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f` |
| `d07--sample.jar` | 5,152,892 | `11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8` |
| `d08--sample.elf` | 67,264,576 | `a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097` |
| `d09--sample.elf` | 60,672 | `31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c` |
| `d10--sample.exe` | 84,480 | `fec19526d4bbca571dc9e80daa2fea0abbeec66f2fc198670c1e1ee7c2d57b15` |
| `d11--sample.elf` | 1,021,696 | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| `d12--sample.elf` | 100,976 | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| `d13--sample.elf` | 749,208 | `4ecb696de15c3a498b666af287e62dedcb66fcc9161273a3cb11d6ea2f2138e0` |
| `d14--sample.elf` | 17,304 | `2a078d374fe8e8e5d2efd3bc698e39fdbfdb01d9cf27e2f8fb89b21db2e155aa` |
| `d15--sample-symbolized.elf` | 16,160 | `7e4a1f03afda5e39e564323afd20f662593c55503dc8689f5fb378f9b3c7834c` |
| `d15--sample-stripped.elf` | 14,360 | `64e80daffed5667511aa585242f2b6563ddb898f4a01ad627c13cd25149d9dc1` |
| `d16--sample-direct.wasm` | 570 | `f69c4caa17b6f3aa3e53fbefacee97354a52e179ba4463597353309c0caa0d53` |
| `d16--sample-compact.wasm` | 561 | `46c73e56a5c24b49fcea9ff7e498fc4c0886ef24a7590b86e491b6565e842ea9` |
| `d17--sample.elf` | 1,393,288 | `7eb52f45ab82772a1ee29f1c7c1f03e82d0c197e5c6545ff587316ef5924d98e` |
| `d18--sample.elf` | 16,544 | `933be5188c0c7a6f1cb15d9b3f30d423b0cbed3d913891acbaee20fa6f855e49` |
| `d19--sample.elf` | 11,232 | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |

### Set 4 — campaign `BR19-007`

- **Assigned archive SHA-256:** `4d29dbae594f0dcef0349ef8a248d1a53e0fa44193388fb7a6d5b6f526233904`

| Archive member (central-directory order) | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.elf` | 16,640 | `018d4f5fe9eeb93de91d43101effb31e2da31e3606622da433653d35f333e6f5` |
| `d03--sample.dll` | 9,216 | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `cd23e68827ec02ea5be66e9ce4990ced14026acc9176d219e7f2d20c4f20b728` |
| `d05--sample.elf` | 3,997,704 | `359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c` |
| `d06--sample.jar` | 3,099 | `e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1` |
| `d07--sample.jar` | 5,152,891 | `7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c` |
| `d08--sample.elf` | 67,264,576 | `f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48` |
| `d09--sample.elf` | 60,648 | `adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69` |
| `d10--sample.elf` | 134,720 | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` |
| `d11--sample.elf` | 1,021,696 | `ef6e36955793c0d41966e2727c80417c136cefc9f18b98285917ace224455617` |
| `d12--sample.elf` | 100,976 | `fd116e0e351a96ca5c2071249e9c6cc684bd8859fde8e71ea201b1bc4f7c815a` |
| `d13--sample.elf` | 749,208 | `c0c173c2a2dcea0c59a4c1ae066ebfd4129025862f1573ae129be81b2c636a35` |
| `d14--sample.elf` | 17,304 | `262e170dd7399724c9e09cd25d959cc2260cde506f8ed322cd4d6f4093c64359` |
| `d15--sample-symbolized.elf` | 16,160 | `a9a77ce8add57e5856823ddb781731a067e100aee3b4638c3460a5e65cc4893a` |
| `d15--sample-stripped.elf` | 14,360 | `b02d268916d242f6e8e780cf49e5639d0c6840c4f376543a65c6429888663ab5` |
| `d16--sample-direct.wasm` | 570 | `bfc4ac0f057736e4f0a752c1ccbe35402e4e11eb890bf22c5689c8c0dbd734cb` |
| `d16--sample-compact.wasm` | 561 | `d532bf09c5b854cb01e4be023480690c54cfc5bb0797fd81ab2a8e5b50dbb97b` |
| `d17--sample.elf` | 1,393,288 | `128fbb2bf7d67db362a7f1f9bf27454e5398468cdf6b8b795e25e8c28d605e2a` |
| `d18--sample.elf` | 16,544 | `00882cd984852d5cc186662a6cb7859c1cf465f7af60349bc5ffe89e3543a98e` |
| `d19--sample.elf` | 11,232 | `d624ca9c4da82aae4aa06edb920fe2816a8bdd26e7f221680261a125b6c26879` |

### Set 5 — campaign `BR19-006`

- **Assigned archive SHA-256:** `08e5da0991f78a75cfd1e83e950a4274ef09023f8725c15581b5c203bb661014`

| Archive member (central-directory order) | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 14,208 | `d5f7d56bf4c6f87adb8ec59a5900e4d6391e14afebce32e8502610c8497a53fe` |
| `d02--sample.exe` | 279,699 | `bcba4c575a65c50fd93b83a9b4a8c640fd136de86673cae447e1359558052e5a` |
| `d03--sample.dll` | 9,216 | `d1493de4b3d5c8a5db1440a94b5204644cdba19853d894722c47a82d1c65ad17` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | 1,956,352 | `24bf0850bb4fd4f734d5d91dbf1762d96c5efa3bca9a0c6336f9c53d216cfdc0` |
| `d05--sample.elf` | 3,997,704 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| `d06--sample.jar` | 3,101 | `3946fb7a66d6a47d0d7d9d553e229999e845834537ab522a1b64fc8211b0a3b6` |
| `d07--sample.jar` | 5,152,894 | `2febb8701f76f617bedc8d80ef398aab87472c6209fd5881c0dfea2d70dc6e93` |
| `d08--sample.elf` | 67,264,576 | `c31d49dbf7740c71c2990d667353f33e449927deb9caa4cc704aaba624c6467b` |
| `d09--sample.elf` | 60,648 | `9c30b74048a654312b88f319878f4cbb52f5e633e3b1e7776248285876f8d4e2` |
| `d10--sample.exe` | 84,480 | `b12cc775f34f20d0b101fdc01cf958a06bbbc5bc2e297468f15793aba3f56f0a` |
| `d11--sample.elf` | 1,021,696 | `4db31f97b3ce1b44553e5ed8ef14c17aa10a91203ecd954dd532dcf81054196e` |
| `d12--sample.elf` | 100,976 | `0f49a991fbba928a9bc167bdb09bcd8b81c580a3e30ca4e427f331fd0acd1d4f` |
| `d13--sample.elf` | 749,208 | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` |
| `d14--sample.elf` | 17,304 | `a40e5c597c04b4334547fe9a53aefb80e9a01d8bf64da9396cd2d135c22072ab` |
| `d15--sample-symbolized.elf` | 16,160 | `d51fd845d6a449a0b7ef3da6bb4c6b69a1b465ca9ed3ac333874d2852684572a` |
| `d15--sample-stripped.elf` | 14,360 | `e8090724f8ba9b74752b4f1af580f7955a27d0a9d56b89c89c51ba41ea7fab51` |
| `d16--sample-direct.wasm` | 570 | `4bc627247fc5bd9cf16d796476071b3228e8da9967c5fe49ac7e4e8ae27b7fbc` |
| `d16--sample-compact.wasm` | 561 | `3c8582b6dcf6d94546f0e981504817741bb8f034486c9a9ea4db304d7a969beb` |
| `d17--sample.elf` | 1,393,288 | `3142d154114a00f966fe20e60521591253d4312878d1df0567281cbd9e31a8b5` |
| `d18--sample.elf` | 16,544 | `1f21c023457428e6fc3d32d65c914c4a41fc5178eecc228e3f81d79ddd69091a` |
| `d19--sample.elf` | 11,232 | `d7fe99150a2a8c3db2b2ef7f455336be2b8fa10838997763900d41b4d8dd3bc9` |

## Reproducing the Day 19 overlay decode

1. Verify the assigned archive's SHA-256 and extract the ZIP with `infected`. Keep the outer ZIP member order for ordinal hash fields.
2. Locate the final `PK19` overlay in the Day 19 ELF and parse the declared packed length and embedded SHA-256 from its header. Bound-check the full overlay before slicing it.
3. For each packed byte `b`, decode as `ror8(b XOR k2, 3) XOR k1`, using `k1` and `k2` from that overlay's header. Verify the decoded buffer against the header digest before parsing it.
4. Parse the HCFG record at offset zero in the decoded buffer: read version, XOR key, little-endian length and CRC32; XOR the payload, check CRC32, then parse JSON. The Single Solve record validated as campaign `BR19-000`, CRC32 `0xd02e2211`.
5. Recompute all per-member hashes and set-specific overlay values from that exact archive. Each Mastery set has its own overlay and campaign; do not re-use one set's decoded record for another.

The report contains the decoder formula and per-set data but does not retain the full standalone parser source. A clean-room replay needs each assigned archive from the relevant attempt.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
