# Flow State — Day 18 Single Solve

## Route and result

- **Challenge:** Flow State
- **Challenge ID:** `binary-reverse-engineering-day-18-control-flow-reconstruction`
- **Mode:** Single Solve, untimed
- **Attempt:** `a04c1693-283f-4588-9fb8-ae7f8d9a0223`
- **Assigned archive:** `evidence.zip`
- **Archive SHA-256:** `bca8aa7818f815e64423ab10904ede887c4468070c9781c62d5b63ae15592886`
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `05d6377d732cd985265ea421f74dd6ae`

The set contained 216 answer fields covering all specimens from Days 1–18. Submitting by day isolated an incorrect Day 15 group; its ELF machine fields required the numeric `e_machine` value `62`, rather than the equivalent architecture label. After correcting those two fields, the route completed.

## Method

I extracted the assigned ZIP with its published password, `infected`, and processed its members in archive order. ELF headers, section tables, and symbol tables were parsed directly; `objdump` was used to decode the Day 1 `recover_code` symbol. The Day 3 PE/CLI metadata root was read at `BSJB + 16`. For the Java archives, I parsed the manifest’s `Main-Class`, its classfile constant pool and method table, and the JAR central directory. For WebAssembly, I inspected the module bytes and its data payloads.

For HCFG records, I checked the header bounds, XOR-decoded payload, CRC32, and JSON before using any field. I distinguished literal records from printable Base64 carriers and used section and disassembly evidence to classify storage. I did not execute any challenge binary.

## Validated findings

- **Day 1:** ELF64, x86-64, `ET_EXEC`, little-endian, entry point `0x401040`; `.symtab` is present. The `.huntress` marker is `BR01-CATALOG-000`. `recover_code` decodes to `mov eax,0x1fa4; ret`, so its requested unsigned immediate is `8100`.
- **Day 2:** the ELF symbol table contains `DiscoveryEngine` RTTI/vtable entries. Its valid HCFG record is at file offset `8576`, version `1`, XOR key `0x31`, CRC32 `0x6149aa00`, campaign `BR02-000`.
- **Day 3:** the primary specimen is a managed PE/CLI assembly. Its metadata-root version and PE machine field were read from the DLL, and the attached runtime configuration was treated as a support file.
- **Days 4–7:** the Go and Rust ELF specimens and both JARs were classified from their actual metadata. JAR method-table, access-flag, compression-method, and coroutine-runtime questions were read from the classfiles and ZIP directory. Their campaigns were `BR04-000` through `BR07-000`.
- **Days 8–14:** carrier and storage findings were checked per specimen. Day 8, 9, 11, and 13 were printable Base64 carriers; Day 12 was a raw record in `.data` with code references resolving to its start (`raw_const_array`); Day 14’s literal record began in the `.hcfg` section (`raw_hcfg_section`). Day 10’s record was raw and outside a mapped file-backed section.
- **Day 15:** both ELF variants contain the same valid HCFG configuration, campaign `BR15-000`. The stripped and symbolized files were distinguished by their basenames. Each ELF reports machine value `62`.
- **Day 16:** both valid WebAssembly modules contain the same campaign `BR16-000`; the compact module’s requested fields were read from its HCFG payload, while the direct module supplied its requested campaign and domain.
- **Days 17–18:** raw HCFG records were validated at offsets `207432` and `8512`, respectively. The records report campaigns `BR17-000` and `BR18-000`; both are ELF64 x86-64. Day 18’s record has version `1`, XOR key `0x31`, and CRC32 `0xd55cf099`.

## Member hashes

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

## Time Trial

- **Attempt:** `259f3432-8a7b-4bb1-908c-737492546b35`
- **Timer:** server deadline `2026-10-23T13:21:45.754Z`; the 216-field submission completed before the deadline.
- **Assigned archive SHA-256:** `4c61827fde522c454a30ec7edff1fde56edaf3322fa828e3894be6bea92c4d90`
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `c39b26a2eae00dfae89a043ad51e8959`

I reused the static parsers and revalidated every answer against this attempt’s new archive. The archive kept Day 1 and Day 2 specimens unchanged and rotated several later samples; hashes were recomputed from the newly assigned members. The Day 15 machine fields use numeric ELF `e_machine` value `62`. No executable was run.

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | 16,640 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | 9,216 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` |
| `d05--sample.elf` | 3,997,704 | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| `d06--sample.jar` | 3,101 | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| `d07--sample.jar` | 5,152,893 | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| `d08--sample.elf` | 67,264,576 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | 60,704 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| `d10--sample.elf` | 134,720 | `78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae` |
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

## Mastery

- **Attempt:** `4cbd67b3-016f-4196-b8b9-e8cdfb66e60d`
- **Mode:** Mastery; one server-enforced timer across four evidence bundles
- **Timer:** started `2026-10-23T13:22:37.180Z`, deadline `2026-10-23T13:27:02.180Z`; all 864 fields were submitted before the deadline
- **Game Master result:** `CORRECT`; personal status confirmed `CORRECT`
- **Flag:** `b2fcd3b02ffb8db034ebf3c5af4056e1`

Each archive SHA-256 matched its start response. I extracted and analyzed all four bundles statically. The Day 2 and Day 4 specimens changed container type in sets 2 and 4, so I parsed PE/COFF sections and symbols for those bundles; the remaining methods covered ELF section and symbol tables, Java classfiles, WebAssembly, and CRC-validated HCFG payloads. The answers were grouped by set and submitted under the exact `setN.` answer IDs.

| Set | Evidence archive SHA-256 |
| ---: | --- |
| 1 | `4c61827fde522c454a30ec7edff1fde56edaf3322fa828e3894be6bea92c4d90` |
| 2 | `ff867565fd25b0b42852c7036e4b98feb6d694776fd3d5ca1adae630e5e438de` |
| 3 | `a5639e58b2d815e76cb1e88cc25e5d9ae4011a59988cf272ecc782192f13d987` |
| 4 | `4f86bf0be75e8894ce0bbe50e7929ca90f2516adb8f94a6b7f099a7c028e88bc` |

### Set 1 member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | 16,640 | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | 9,216 | `74077eccc618649b0afe48d00f9dc12908822a2ba117443ff1ad43d0fb7ee9c9` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `812219947ed7ccef255aaf7c9b80a3c43fa0ba5af90c216f7bd2fd869e2affe6` |
| `d05--sample.elf` | 3,997,704 | `327450a608b0fb9e40760b7bf22c2782e64f6cd250aac8141710c0816bb03624` |
| `d06--sample.jar` | 3,101 | `1798942bef6dc0f5a8474ef4b59cb0e17d4f52d9fada558e3f87323dd48ffb19` |
| `d07--sample.jar` | 5,152,893 | `a0def379f0da44b0dd1e4f1c8aa526f0b3a58ec4f648eda2f638f3ef6f33804f` |
| `d08--sample.elf` | 67,264,576 | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | 60,704 | `d808f50f64aa1f62ff1f373b650959e236d7e06d61b42da8a083ab512de4044d` |
| `d10--sample.elf` | 134,720 | `78100573f9ce5720234c0e57ea99e83bb17265a75dead4b3bb371c4fd57a38ae` |
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

### Set 2 member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
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

### Set 3 member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | 16,640 | `a133311c7526c803be7ba2aa5b50e692a7e5d54bb12ef1e56a75fdc9c1eea1d2` |
| `d03--sample.dll` | 9,216 | `14b2098595d278e857a1308e8e0e4652e45c9ba7c3d991299efe417ab0dd04ef` |
| `d03--sample.runtimeconfig.json` | 98 | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | 1,867,924 | `173e62bd4171c1f892b881c42ae2143dd1e87ebafc8ee0f0cda01aca60105ba5` |
| `d05--sample.elf` | 3,997,704 | `359817830f155a556404a48246949fc358a6ceee54717600c53f649906ce755c` |
| `d06--sample.jar` | 3,099 | `e7c805d7c36cea5b6463622a33a521139f38d9859a2e52399ae805f35e008fd1` |
| `d07--sample.jar` | 5,152,891 | `7982df2af3d182686a23aa05a00b90917aed92c958b4ae4d24ba9bc55387a87c` |
| `d08--sample.elf` | 67,264,576 | `f37526f9730db7a6157d5a3cc808ffe10f4bd9742c7b5051ad96513558ed8b48` |
| `d09--sample.elf` | 60,648 | `adf8f185f6839d31d0d85b2be3441156ecfd13b4061d999cae642f82ca8fea69` |
| `d10--sample.elf` | 134,720 | `bc5ae6af7c14106ed6652574359285d97590e1d232a7b8be6151d6e915e4face` |
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

### Set 4 member hashes

| Archive member | Bytes | SHA-256 |
| --- | ---: | --- |
| `d01--sample.elf` | 15,616 | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
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

## Reproduction checklist and evidence limits

1. Verify the selected mode's archive SHA-256, extract the assigned ZIP with `infected`, and preserve its central-directory order for ordinal member questions. Recompute member hashes from decrypted member bytes.
2. For each file, classify it from its magic and parse only the requested metadata: ELF headers and sections, ELF symbols, PE/CLI directories, JAR manifest/classfile structures, or WebAssembly sections. The numeric Day 15 `e_machine` is `62`; the accepted answer is the number rather than the architecture label.
3. For each HCFG field, locate the carrier named in the question, bounds-check the 12-byte header and payload, XOR with its one-byte key, verify CRC32, and parse JSON. In this Single Solve, Day 17's raw `.rodata` record starts at file offset `207432`, and Day 18's record starts at `8512`; the Day 18 header records version 1, key `0x31`, CRC32 `0xd55cf099`, and campaign `BR18-000`.
4. Derive answers from the exact current assignment and map by returned answer ID. Submit by day or by small groups so any rejected fields can be localized; the first submission's two Day 15 machine answers were the only recorded correction.

The report preserves the corrected field values and member hashes, but not the original parser, complete assignment transcript, or full answer JSON. For an exact replay, obtain the corresponding assigned archive and start response; do not treat another mode's archive as interchangeable.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
