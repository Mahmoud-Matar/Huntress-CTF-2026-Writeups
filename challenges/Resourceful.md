# Resourceful — Day 20

## Single Solve

- **Challenge ID:** `binary-reverse-engineering-day-20-resources-and-overlays`
- **Mode:** Single Solve (untimed)
- **Attempt:** `bae21524-2478-4a76-8e70-7237a9a09188`
- **Artifact:** `evidence.zip`
- **Archive SHA-256:** `411b817a4f8194d8398d8a29d2034604a631ff22a077ed1a1412c820fefc0610`
- **Result:** Game Master returned `CORRECT`; follow-up personal status confirmed `CORRECT` for all 240 answer IDs.
- **Flag:** `ed274754dc40cf25673a50bb7d81e1c6`

The prompt asked us to inspect resources, overlays, and data beyond the end of executable sections. The archive contains 23 encrypted members covering the Binary evidence from Days 1–20. I checked the outer archive hash before extracting it with 7-Zip and the published password `infected`. All analysis was static; no challenge executable was run.

## Analysis

I parsed ELF headers, section and symbol tables, Java class files and JAR central directories, PE/CLI metadata, and WebAssembly modules. The Day 1 `recover_code` bytes disassemble to `mov eax,0x1fa4; ret` (decimal return value `8100`). Day 2 contains the `DiscoveryEngine` RTTI and vtable symbols. The HCFG records were accepted only after checking their lengths, XOR-decoding their payloads, validating CRC32, and parsing the resulting JSON.

For Days 8, 9, 11, and 13, I located the Base64 carrier by scanning the specified printable runs and validating the decoded HCFG record. Day 12’s raw record is in a mapped data section with a decoder reference to its start (`raw_const_array`); Day 14’s record begins in `.hcfg` (`raw_hcfg_section`). The earlier raw and container questions were answered from the assigned bytes, including the .NET metadata version, JAR method tables and compression methods, and WebAssembly data.

The new overlay findings were validated against their record structures. Day 19’s final `PK19` overlay begins at byte `10808` and occupies `424` bytes; its decoded resource matched the embedded SHA-256 and contains a CRC-valid HCFG record for campaign `BR19-000`. Day 20’s final `RS20` resource overlay begins at byte `1200888`; its HCFG resource size is `380` bytes, the following scratch bytes match the overlay SHA-256, and the embedded HCFG record validates for campaign `BR20-000` (CRC32 `0x570dddce`).

One field-specific detail mattered: the Day 8 class question asks for ELF bit width as a base-10 integer, so the accepted value is `64`, while Day 1 explicitly requests `ELF64`. The final submission matched all 240 exact answer IDs returned by the active attempt.

## Archive member hashes

Hashes below were calculated from the decrypted member bytes, preserving the archive’s central-directory order for numbered member questions.

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
| `d20--sample.elf` | 1,201,351 | `ddd691e5065c08b8d0dd09aea1084199e76aa9f15a59b91150f31bf02db84c84` |

## Time Trial

- **Challenge ID:** `binary-reverse-engineering-day-20-resources-and-overlays/time_trial`
- **Mode:** Time Trial, untimed scored run (`run_for_time:false`); no deadline was active.
- **Attempt:** `27f86678-f4f1-4f7b-8d39-2a71807a67e5`
- **Artifact:** `evidence.zip`
- **Archive SHA-256:** `9e83bf1d504f1e32e291322624675529f11fa4ec13bc55b6f871aaac4832fc54`
- **Result:** Game Master submission and follow-up personal status returned `CORRECT` for all 240 answer IDs.
- **Flag:** `dca6d4843e59e3b3533766111a26391e`

The Time Trial's regular-play pool is untimed by default, and the live guidance confirmed that a correct untimed run still scores. This variant changed several earlier specimens to PE files. I parsed the Day 2 COFF symbol table in raw order, preserving the prefixes required by the questions (`.text$_ZNK15DiscoveryEngine5scoreEPKc` and `.rdata$_ZTI15DiscoveryEngine`). Day 4 was also a PE; its nine section names were read from the PE section table. The Day 8 ELF class field required the decimal bit width `64`. The overlay checks used the new variant's actual bytes, and the final `RS20` scratch digest and Day 19 `PK19` unpacked digest both validated.

I submitted the answers in day groups after matching the exact fields to the current assignment. All 240 IDs were accepted. No sample was executed.

### Archive member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `6413a43702b377d079202f0c95be1ffc93861d7a14fefae01e4bd7d1fc32e54e` |
| `d02--sample.exe` | 279,699 | `1db6cd34482281e61ef34dd5695745b9370549e63a5241afbc7c5f9bda911cfc` |
| `d03--sample.dll` | 9,216 | `d1493de4b3d5c8a5db1440a94b5204644cdba19853d894722c47a82d1c65ad17` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | 1,956,352 | `cdb3fc656aa538e62e1ee567055921e0ef2b9140b419e8325ffd7c594659ccd1` |
| `d05--sample.elf` | 3,997,704 | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| `d06--sample.jar` | 3,101 | `3946fb7a66d6a47d0d7d9d553e229999e845834537ab522a1b64fc8211b0a3b6` |
| `d07--sample.jar` | 5,152,894 | `2febb8701f76f617bedc8d80ef398aab87472c6209fd5881c0dfea2d70dc6e93` |
| `d08--sample.elf` | 67,264,576 | `c31d49dbf7740c71c2990d667353f33e449927deb9caa4cc704aaba624c6467b` |
| `d09--sample.elf` | 60,648 | `9c30b74048a654312b88f319878f4cbb52f5e633e3b1e7776248285876f8d4e2` |
| `d10--sample.exe` | 84,480 | `30477f3a7b1fc911c732d8dbf68362e9d28d0c20102aa32b41b2c1e0b04fbae1` |
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
| `d20--sample.elf` | 1,201,351 | `6d7a7d6403d5f30324e0e5502acdda8b4ee7fd07e138de85f3c7e6cc40431b50` |


## Mastery

- **Challenge ID:** `binary-reverse-engineering-day-20-resources-and-overlays/mastery`
- **Mode:** Mastery, untimed scored run (`run_for_time:false`); no deadline was active.
- **Attempt:** `c7152a4d-0f84-4c54-b602-caaca1a45d73`
- **Artifacts:** Five `evidence.zip` archives, each decrypted with the published password `infected` and analyzed without executing samples.
- **Result:** Game Master submission and follow-up status returned `CORRECT` for all 1,200 answer IDs.
- **Flag:** `6f6df9137c788409d807567cccbe31c1`

The five archive SHA-256 values, in delivery order, were:

1. `73b3f6be2d660c4722105222f5857a7b7ae1d892683c7a0214a02f70ba3910bc`
2. `9185aae0cb5bb3e1349939d254ac445d121abd32f7ba3bd381157ed6c2800a0f`
3. `2688152ecdfd6736ee91614bdc886182268dd825b4dd48c89d02b25ddab526fd`
4. `125c949627d7cadc018dabb73b95e667cc9ba8a0c647c17634681387ce446048`
5. `ad2e58247d25180f06cadd689348c018fc1a2bf63909ac99d5bad7ef09a8e4d6`

I reused the static Day 20 parser and processed every assigned archive independently. It covered ELF headers, symbols, and sections; PE sections, CLR metadata, and COFF symbols; Java class metadata; WASM; HCFG records and CRCs; and the PK19 and RS20 overlays. For all five variants, the PK19 overlay began at offset `10808` and occupied `424` bytes; the RS20 resource began at offset `1200888` and occupied `380` bytes. Campaign IDs varied by delivery: PK19 was `BR19-004`, `BR19-003`, `BR19-002`, `BR19-001`, `BR19-000`; RS20 was `BR20-001` through `BR20-005`. Each submission used the exact set-prefixed answer IDs returned by the assigned attempt.

The table below records the SHA-256 and byte length of each extracted member. Member names are alphabetized within each set for readability; ordinal hash answers were matched in the archive's central-directory order.

| Set | Archive member | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| 1 | `d01--sample.elf` | 15,616 | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 1 | `d02--sample.exe` | 279,699 | `7af806183a8db4bf71f0c3d6996718270cdd8286e4b0e0ae56bb8d5821822546` |
| 1 | `d03--sample.dll` | 9,216 | `9686e6dab1cf8713d440188ef0d943421541ddfece686b8e18aa72802395fadf` |
| 1 | `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 1 | `d04--sample.exe` | 1,956,352 | `82599eee6ceae6147c7cb342b5277b79e2deacebae33be8164234277dd6a4c4e` |
| 1 | `d05--sample.elf` | 3,997,704 | `cb390c7dcb224aca2c23bdef306130dd5fd51ec6b6b47a7df3180a334c12c6a3` |
| 1 | `d06--sample.jar` | 3,096 | `dfb3b646b06ff9349775677c1533a244541acfba5834106fd2739634532650b4` |
| 1 | `d07--sample.jar` | 5,152,890 | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| 1 | `d08--sample.elf` | 67,264,576 | `80ba7e1ab243b4dca46d0b9bc93e6f6fe39dc7ec9eafb34da9bfc99c36aa146d` |
| 1 | `d09--sample.elf` | 60,672 | `6d742be643831355f824f040a5d40c462401266c9180196410044afd5a0ebf4f` |
| 1 | `d10--sample.exe` | 84,480 | `641e93917631e4016d8b2470ca1649d990cab3106d4066f250607d5f56e5b827` |
| 1 | `d11--sample.elf` | 1,021,696 | `5c60e3ab9ef81f2d8a56a2cd8e89ef5dd6ec184941a1ddd4ab87d1ba63ec67f4` |
| 1 | `d12--sample.elf` | 100,976 | `bf571c0fd8dd9b09ae03878d6fabd0fffdb394fce94ce4d8bbff9703382bb48d` |
| 1 | `d13--sample.elf` | 749,208 | `7bafd20f812127b61304a8aae438e63595e7165e3c846820702dbc49af691b8e` |
| 1 | `d14--sample.elf` | 17,304 | `ddc8a5a851b28ae9bd10b4d3a477da6bf7b089a192ce4f4ea6becff04beb42a9` |
| 1 | `d15--sample-stripped.elf` | 14,360 | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` |
| 1 | `d15--sample-symbolized.elf` | 16,160 | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` |
| 1 | `d16--sample-compact.wasm` | 561 | `7e7586c784059d2d378f066f617d5e7155aff1e4b5ff844aabeb6b98402176f4` |
| 1 | `d16--sample-direct.wasm` | 570 | `d4203d3f65d699c903d3d5fbcb856da8f1a30f3c333bda13150eb4dda9cb1ee5` |
| 1 | `d17--sample.elf` | 1,393,288 | `f81f8e53671e3d9f0abb10efbfa2ad4bab76b908743755b3f4d81d02cff3150d` |
| 1 | `d18--sample.elf` | 16,544 | `269b906bb12b0bb7c2e63b07e9e713b3903b3765902f5cd73b36b763b3d0f89f` |
| 1 | `d19--sample.elf` | 11,232 | `82f3ba9ee310789359f4940e3e4febb66be48dbaeaf5e2b65d59e69cba1a5963` |
| 1 | `d20--sample.elf` | 1,201,351 | `ddf2402e0fd0cb300144f0de6690f27097d052e5a659da55f805c7755e47f31b` |
| 2 | `d01--sample.elf` | 15,616 | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 2 | `d02--sample.elf` | 16,640 | `20c1a73fe48ac8c693136aa9e5e880330fef33f7c8651ca5b5086f62880e8e40` |
| 2 | `d03--sample.dll` | 9,216 | `a2cfb3ce811c8385e731ccd3802ce6600cec36fd1079e57922d98c8380ff8935` |
| 2 | `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 2 | `d04--sample.elf` | 1,867,924 | `6db084b3957e37a2a56bd42a0db4dd53696be356f76e3e289267174423a62686` |
| 2 | `d05--sample.elf` | 3,997,704 | `d0e6feaecb5ad1f4094c5983770d5dd440a10259a3b7c26372e1b0764945d4ab` |
| 2 | `d06--sample.jar` | 3,099 | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` |
| 2 | `d07--sample.jar` | 5,152,884 | `67ed6158cfcdd409de3aa5d6f84e0f43cfcfec9ea39922cb7c2b70670f737167` |
| 2 | `d08--sample.elf` | 67,264,576 | `dbab8b60c071076a1d213d58588156f6b59e4002d8b5c5999807c60d6145cdbd` |
| 2 | `d09--sample.elf` | 60,672 | `fa1f633cb2720336f57339a64896196e868a860d9db0a441667bea98162a85f2` |
| 2 | `d10--sample.elf` | 134,720 | `2c9e157d70f50836b72118e2d8ee6d07b28a1a63838ae8a15e86ad709dcbdba9` |
| 2 | `d11--sample.elf` | 1,021,696 | `84e5ba6ae2d9b88af8896fa9f94b3b4ca604b81aa251a1c3cb8440eebc14a927` |
| 2 | `d12--sample.elf` | 100,976 | `eef755746d39bb4e99f6a9f2be0c38aa446a791ebe383fd3fdbe290243ce7ade` |
| 2 | `d13--sample.elf` | 749,208 | `882efdb0a1011ce9858d15e511899e202c2e18c3a154fad97a6f43bf2caa28b7` |
| 2 | `d14--sample.elf` | 17,304 | `d93c0e4d52fc9111b9133ca56b8da3122c9b4186f967102c3bb5b0fe9fd3b617` |
| 2 | `d15--sample-stripped.elf` | 14,360 | `e59f232b590dbf0eefb704784c612db27880cf9d05cbfc0fd8f256863ff2b4e8` |
| 2 | `d15--sample-symbolized.elf` | 16,160 | `003ec956a2961412004dcdd09baeaaa3a39677a5cad60119ecc56b9c4bd90d1a` |
| 2 | `d16--sample-compact.wasm` | 561 | `af2bbd613cd77fcf2ec7578df22d16424d3f63ad636705f0192a42861f6e2487` |
| 2 | `d16--sample-direct.wasm` | 570 | `1e5fdce6a8e2bb764e6542365332224b98d2520f51e6a49cd48d7e15547975d4` |
| 2 | `d17--sample.elf` | 1,393,288 | `ca195f36cf801dfa3884c3a1148eee629e2f8473cdb80cf65187aa90feedfb06` |
| 2 | `d18--sample.elf` | 16,544 | `0c1deae4cafbf60c38de478bce3d6e22c1f5f8c36d89da6c8bb869e3321973d6` |
| 2 | `d19--sample.elf` | 11,232 | `3ff9d4cfbe36bc9cec7bbba3d84c19f0ebdaeababbb9e79037e83d8eacf890c1` |
| 2 | `d20--sample.elf` | 1,201,351 | `428f44e79a6fdf6ba06c5a38c018596436b68445a66b25f507b4e38f6d8be735` |
| 3 | `d01--sample.elf` | 15,616 | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 3 | `d02--sample.exe` | 279,699 | `46dcdb7977162f9a4973301e84735eeabcfb7347d4c1f3ccf9adce77e5d18ba9` |
| 3 | `d03--sample.dll` | 9,216 | `68881a511297810b539f2ec38e71ca32e654e0634fb8db593b18019f0b50ed7b` |
| 3 | `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 3 | `d04--sample.exe` | 1,956,352 | `ed5371dfd8fff9d535f4f03e2a2d99318a7447b3652f314db415e52e3434ad16` |
| 3 | `d05--sample.elf` | 3,997,704 | `40c48ec886b0765e77650bf5c68c2a9cf70fbd09eb9cf054362b38ecbcca62b5` |
| 3 | `d06--sample.jar` | 3,104 | `524d89a845a52ca8fc1988e048a0a298278ac184f1d1ee95b494df3cc5979bc1` |
| 3 | `d07--sample.jar` | 5,152,890 | `8678216a64ac4d785fe5e16d600d1a4b536da1b1262bd38f7578ad3a0535f1e5` |
| 3 | `d08--sample.elf` | 67,264,576 | `a89aa2ef902b580523afddef013b75c4eea6bd00db064cb4e79f49731f827f4a` |
| 3 | `d09--sample.elf` | 60,672 | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| 3 | `d10--sample.exe` | 84,480 | `18c2de6dff6465842a9ed87597585a6d20ade3718519fdd237b1969bf26c0143` |
| 3 | `d11--sample.elf` | 1,021,696 | `2b08f579fb70ababe9452eb467789f3196aab6685ca296fbcf05b38430b9da3e` |
| 3 | `d12--sample.elf` | 100,976 | `05bc81871f90e5d2c3e3d317d3ae15ba3b60ae5c8e36d72ed4007b258a1753ee` |
| 3 | `d13--sample.elf` | 749,208 | `f3f506ecb9a43c322e85bb1880f612f46b9223ff9302c5953fae0c68bec9d88f` |
| 3 | `d14--sample.elf` | 17,304 | `227d0d7953f679acef2a7206c4bb5b6e6fab5164000b31ea3d1161fc1dc56048` |
| 3 | `d15--sample-stripped.elf` | 14,360 | `c458f8def3bb0e9eeec20c3d2dfdefb0084dd7df568b8f410e2e5bbca0420159` |
| 3 | `d15--sample-symbolized.elf` | 16,160 | `7ca685986cdbf856045f7352029d4025cd86278b84fb30d311153149d3cfbb81` |
| 3 | `d16--sample-compact.wasm` | 561 | `2b25166f9ef2d5c331a131cb4db8fc4085c7e49721f1eb0c33a572287cf33e16` |
| 3 | `d16--sample-direct.wasm` | 570 | `5dce8893d4be6893385db4c642179f6cccd6fd61f069426c3c87f65849962459` |
| 3 | `d17--sample.elf` | 1,393,288 | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` |
| 3 | `d18--sample.elf` | 16,544 | `261add139b2b7201da3c5323aa7482e6e6ec0e8b09604e3c9aef4f223e922d34` |
| 3 | `d19--sample.elf` | 11,232 | `32e143d9ac8069dd0c52ac59236bd2beb292c22573d9af470265e797a3dbbdde` |
| 3 | `d20--sample.elf` | 1,201,351 | `0a40c8f5809e61a472b3178145257ea0f0839de291403d8385b7a7d7d636b1c5` |
| 4 | `d01--sample.elf` | 15,616 | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 4 | `d02--sample.elf` | 16,640 | `3fcf8f637cea918821000c09fc011e15615302270de70a4ceb6937965e13dfdf` |
| 4 | `d03--sample.dll` | 9,216 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| 4 | `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 4 | `d04--sample.elf` | 1,867,924 | `6010c6aacea52a9c0dab0cd9206ca309213eb8e7ccc46e0b729287ec9bd61ae5` |
| 4 | `d05--sample.elf` | 3,997,704 | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| 4 | `d06--sample.jar` | 3,101 | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| 4 | `d07--sample.jar` | 5,152,893 | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| 4 | `d08--sample.elf` | 67,264,576 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| 4 | `d09--sample.elf` | 60,704 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| 4 | `d10--sample.elf` | 134,720 | `81c73ffd89fae7757be533c7bda2c2124bf06af01fc304c53731ba10034e1c13` |
| 4 | `d11--sample.elf` | 1,021,696 | `e8fbf29fffc66798c332156eca15887f375e0d59844f1076257afa29e9d245e6` |
| 4 | `d12--sample.elf` | 100,976 | `b38853d66292233f55b08274817f26718a9053889d8dfd0352f8dee1c912b12a` |
| 4 | `d13--sample.elf` | 749,208 | `c1853767bde385a74c9e553fe7fcb50f9d127b3ea8211170a0a4168b192c39b0` |
| 4 | `d14--sample.elf` | 17,304 | `021b13160e53fb918186dc106d26ef95a18aeedc109425a3839a17fbf5ea93f4` |
| 4 | `d15--sample-stripped.elf` | 14,360 | `0eda4bf4620832a21aba470df4d8c6e83bafa149ebe5cbb0c6792a5cf7bb9008` |
| 4 | `d15--sample-symbolized.elf` | 16,160 | `aa74a880736ea29bfdbe8f531de3c9bd8815db1eaafbff9a05cdad4aaa8802ec` |
| 4 | `d16--sample-compact.wasm` | 561 | `1c68c4062584495311c2f4894c3db30ba37e6372c17d8eede1e96a247751fdee` |
| 4 | `d16--sample-direct.wasm` | 570 | `d7b5f809180c62f5033830a3d53158db6eae315046fa6b50a3caed52155a5269` |
| 4 | `d17--sample.elf` | 1,393,288 | `a9bcbf19bc8e44ffda433c0799bcd7e3417c4bf52292a1315e65b85eff929048` |
| 4 | `d18--sample.elf` | 16,544 | `36d7ada216b57cb52ef8d469d8acc62787741bb1ee3deb6a922995e9c2ad76b5` |
| 4 | `d19--sample.elf` | 11,232 | `90d27a82af22b386d617224e505ee9fbd3743189f10909306cb16bbd75cd102d` |
| 4 | `d20--sample.elf` | 1,201,351 | `5704897b87b2f4a772e09d6e8274c16ca8d983153a65c655075c506219646c47` |
| 5 | `d01--sample.elf` | 15,616 | `c5e8e729a60299a45b9f55e9c4e57ed01cbc924b902d2e125db29d2665268cf4` |
| 5 | `d02--sample.exe` | 279,699 | `23035f29831842e409d174d4692927ec4447336320f387767b6bb8839bc5ff8a` |
| 5 | `d03--sample.dll` | 9,216 | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| 5 | `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| 5 | `d04--sample.exe` | 1,956,352 | `374cf375c5c4e50b15f30f942b79e962152f91c633ea83a45c7926266f458bda` |
| 5 | `d05--sample.elf` | 3,997,704 | `2edfa43c4d287a62b69fa1cdcd8be484e55c316bbaf50946fc6b687c51c1ac33` |
| 5 | `d06--sample.jar` | 3,104 | `8babd52a1a1d02a3ccf916f5ad52e687800b04a1f5bf6c7cd7f6a8c7675b197f` |
| 5 | `d07--sample.jar` | 5,152,892 | `11dbb9528cf20e34c8a2af9f540c83230f58de1cbeb9c11ff2a792d9d6e7a4a8` |
| 5 | `d08--sample.elf` | 67,264,576 | `a0b702bcaf4ac176ecfaf7febed5650904264a4e57dc022d124449746eab8097` |
| 5 | `d09--sample.elf` | 60,672 | `31ad7b00118cb2f62f98650aeb27e0dfddfbcb17b552c74bad7675bab6ac2b6c` |
| 5 | `d10--sample.exe` | 84,480 | `fec19526d4bbca571dc9e80daa2fea0abbeec66f2fc198670c1e1ee7c2d57b15` |
| 5 | `d11--sample.elf` | 1,021,696 | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| 5 | `d12--sample.elf` | 100,976 | `3b0259460c63bdde5ae17059504f1060d3cc60ae54e28b6acd911bacb19e1bde` |
| 5 | `d13--sample.elf` | 749,208 | `4ecb696de15c3a498b666af287e62dedcb66fcc9161273a3cb11d6ea2f2138e0` |
| 5 | `d14--sample.elf` | 17,304 | `2a078d374fe8e8e5d2efd3bc698e39fdbfdb01d9cf27e2f8fb89b21db2e155aa` |
| 5 | `d15--sample-stripped.elf` | 14,360 | `64e80daffed5667511aa585242f2b6563ddb898f4a01ad627c13cd25149d9dc1` |
| 5 | `d15--sample-symbolized.elf` | 16,160 | `7e4a1f03afda5e39e564323afd20f662593c55503dc8689f5fb378f9b3c7834c` |
| 5 | `d16--sample-compact.wasm` | 561 | `46c73e56a5c24b49fcea9ff7e498fc4c0886ef24a7590b86e491b6565e842ea9` |
| 5 | `d16--sample-direct.wasm` | 570 | `f69c4caa17b6f3aa3e53fbefacee97354a52e179ba4463597353309c0caa0d53` |
| 5 | `d17--sample.elf` | 1,393,288 | `7eb52f45ab82772a1ee29f1c7c1f03e82d0c197e5c6545ff587316ef5924d98e` |
| 5 | `d18--sample.elf` | 16,544 | `933be5188c0c7a6f1cb15d9b3f30d423b0cbed3d913891acbaee20fa6f855e49` |
| 5 | `d19--sample.elf` | 11,232 | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |
| 5 | `d20--sample.elf` | 1,201,351 | `3031a2d4048edfb55fab0bdb34fa28149679f6705e7ffcb087666ff2e60bbb28` |

## Reproducing the overlay analysis

The retained parser is [`tools/solve_resourceful_day20.py`](../tools/solve_resourceful_day20.py). Before running it, update its `START`, `ARCHIVE`, and `EXTRACT` constants near the top of the script to the start-response JSON, assigned archive, and extraction directory for the exact route. The existing defaults point to a prior temporary Flow State file name and should not be assumed to match a Resourceful assignment. The script verifies the archive SHA-256 against the start response, extracts with `infected`, computes each decrypted member hash in ZIP order, parses the requested ELF/PE/JAR/WASM metadata, and validates overlays and HCFG records. Run `python3 tools/solve_resourceful_day20.py` only after those paths are set; review the printed question/answer counts and missing IDs before relying on its output.

For the Day 19 and Day 20 overlays, locate the final `PK19` and `RS20` markers, validate their declared lengths and digests, and parse embedded HCFG data only after the record CRC passes. The report's `PK19` offset/size and `RS20` resource offset/size are checks for the recorded Single Solve variant; fresh mode variants must be recalculated from their own bytes.

The helper computes a candidate map from current inputs, but the full original start JSON and every submitted answer map are not preserved in this report. A verbatim re-submission therefore requires the exact assigned files and answer IDs from the selected attempt.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_resourceful_day20.py`](../tools/solve_resourceful_day20.py), [`tools/build_resourceful_day20_mastery_answers.py`](../tools/build_resourceful_day20_mastery_answers.py).
