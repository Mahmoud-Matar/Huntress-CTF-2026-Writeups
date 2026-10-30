# Trust Issues — Day 23 Single Solve

## Route and result

- **Challenge:** Trust Issues (`binary-reverse-engineering-day-23-anti-analysis-recognition`)
- **Mode:** Single Solve; untimed (`deadline: null`)
- **Attempt:** `5761261c-8967-4663-971c-dc0ed8846588`
- **Result:** Game Master returned `CORRECT`; a follow-up status check confirmed all 276 answer IDs accepted for this attempt. CourseStack now shows the Single Solve as **Correct** and Trust Issues at **1/3** modes.
- **Flag:** `77cdd21b405a9eeaacecdf057abc24db`

## Assigned evidence

The Game Master assigned `evidence.zip` (password `infected`). The archive SHA-256 is `e47cb97a509b9af4ced1ecc242f72ecd561b03d7d0f2300fe61965a7d4a0e924` (35,675,756 bytes). I verified this hash after downloading through the paired Game Master API, then extracted the archive on REMnux. The 30 extracted members and their SHA-256 values are:

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `a0d3aeddb90dccf579e0262704dc7d7c2828121d8cc988f085de169601737b9b` |
| `d02--sample.elf` | `e9ca3054b0689f60a9c41a758781fae1406e127e5bfcc866c51f78748fdfd0d7` |
| `d03--sample.dll` | `a98b993fefd2095f0f25e88171441559b0d07c7e02cf026581590da58eea073d` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `d5aa218b11ca0d94d7186c01a0eae9547ba88a0ec93f61ae2c1e9f964512182f` |
| `d05--sample.elf` | `4ac8f95bcaa5f6738e04ee5051fed2ea3d5a80e5a8a3d4e49295f2739bccc247` |
| `d06--sample.jar` | `6571ad6effab6285e2c024dd6da3158328ac275593a192b39912cebf1e99ae6c` |
| `d07--sample.jar` | `13238011183076ed4d2c689f4e46d51a95c895b5c45bd2a374dcaed75de7959b` |
| `d08--sample.elf` | `a700832ceed39fda0e930ba0ea330775c99e01fd710dde135e8957ecb0f8b529` |
| `d09--sample.elf` | `5c4536977a50717e92041d2a3304656c00e1c65dee2062200478010102b536ad` |
| `d10--sample.elf` | `9b0a03a27391eb4f97f6211955bc9b21acbe15418dc32da04c1aa6c2448e68c7` |
| `d11--sample.elf` | `a29a3f1dc0cf6d608145015adc402ae5569f472eef0368d6665d928a2b518675` |
| `d12--sample.elf` | `8d3b435126f7ca6b97e5f26020a301bf4804e28787ec468dc42446afa6f5a93b` |
| `d13--sample.elf` | `6d141b21fba163c13dd065dea5b38cbd5d3f495fd8d0a15e1ef0a5c9d754e0df` |
| `d14--sample.elf` | `d93c0e4d52fc9111b9133ca56b8da3122c9b4186f967102c3bb5b0fe9fd3b617` |
| `d15--sample-stripped.elf` | `b97e0d28b11036b69552c01d42107411b7fa55fd371d6797027f3c5742dc9c7e` |
| `d15--sample-symbolized.elf` | `83a58b2e4162ecd25360cd898ec7eb57b5e1fe820aa0c28c5df774176e104686` |
| `d16--sample-compact.wasm` | `1c68c4062584495311c2f4894c3db30ba37e6372c17d8eede1e96a247751fdee` |
| `d16--sample-direct.wasm` | `d7b5f809180c62f5033830a3d53158db6eae315046fa6b50a3caed52155a5269` |
| `d17--sample.elf` | `f1f7b4b2d98bcd3aefa754a3a673025b80e4c51e2cc65e3ea7b34ad52b70fe18` |
| `d18--sample.elf` | `00882cd984852d5cc186662a6cb7859c1cf465f7af60349bc5ffe89e3543a98e` |
| `d19--sample.elf` | `cf82c07ef9325c0a7012dd43e49182664513d57fa46eac312d26e98dc2231fbe` |
| `d20--sample.elf` | `ddd691e5065c08b8d0dd09aea1084199e76aa9f15a59b91150f31bf02db84c84` |
| `d21--sample-loader.elf` | `a5fd9145ffc95a2dd330abf1e09404473527227fcba74062cc06ce3ee9cfb94e` |
| `d21--sample-plugin.cmxs` | `e5d298e7ccf93c74941d8459d4b2c34b89ed46306d7661f7aa256384e3778d19` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `1ebccc9936901e808463f080e31c0ad79fa6dd4d9f3c9627059d9c485ac95ead` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `0e60f053879698cf097f7612a1c2c1a143095842a93cd3eaf5731495510c27f4` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

## Analysis

The assignment contained 276 guided findings spanning the Day 1–23 sample set. I analyzed the exact downloaded bytes on REMnux using a small Python parser (`[tools/solve_trust_issues.py](../tools/solve_trust_issues.py)`) plus ELF, PE/CLI, ZIP/JAR, Java classfile, WebAssembly, and static disassembly/xref inspection. No sample binaries were executed.

The parser decoded HCFG records by applying the one-byte XOR key, validating the stored CRC32, then parsing the UTF-8 JSON. It handled each delivery style from the corresponding question instructions: literal ELF records, Base64 strings in Java Main-Class constants, WebAssembly data segments, native overlays, and the managed plugin. The final Day 23 managed assembly is `pe_cli`, reports metadata version `v4.0.30319`, and has PE machine `I386`; its HCFG record is version 1 with CRC32 `0xeb13668a` and key `0x81`. The decoded Day 23 configuration uses campaign `BR23-000`, domain `node-000.day23.example.invalid`, mutex `Global\HuntressBR23_000`, and URL `https://node-000.day23.example.invalid/api/BR23-000`.

A first bulk submission was rejected. I used Game Master feedback to isolate six field-level mistakes, corrected them from the artifact and question wording, and resubmitted only those fields: Day 7's method-table count must come from the manifest Main-Class; Day 8's ELF class answer is the requested bit width; Day 12's HCFG lies in mapped `.data` and has an instruction cross-reference to its exact start; Day 20's RS20 resource-size field is at offset +8; and the PE machine values for Days 22 and 23 are accepted as lowercase `i386`. After those corrections, the route validated all 276 answers.

## Reproducible checks

- The answer builder produced exactly 276 string answers, matching the 276 answer IDs returned by the active attempt, with no missing or extra IDs.
- The Game Master status response for the same attempt returned `CORRECT` with all 276 IDs accepted.
- CourseStack shows the Single Solve submission as Correct. Time Trial and Mastery remain unstarted.


## Time Trial — untimed scored run

- **Attempt:** `56d16fa5-6f52-4a2b-b6f6-3c52fc2861dc`
- **Timer:** untimed; the Game Master guidance says Time Trial starts are untimed by default, and `deadline` was null.
- **Artifact:** `evidence.zip`, SHA-256 `55de2950a068092e8bf7b1b07430ceda03b252c9756d893f970dc6e28258c051` (35,679,945 bytes); password `infected`.
- **Result:** all 276 findings accepted; Game Master returned `CORRECT`, and a status recheck confirmed the same attempt. CourseStack now shows Time Trial as **Correct** and Trust Issues at **2/3** modes.
- **Flag:** `e4c109922c83d79ddd1d0f3bbe59c440`

The timed variant changed some requested representations while reusing the same broad analysis structure. I regenerated answers from this attempt's own start response and archive. For the Day 4 PE executable, I resolved the section names through its COFF string table. The validator also distinguished the Day 1 exact `ELF64` token from Day 8's requested decimal bit width, and required lowercase `i386` for the PE machine answers. No sample was executed.

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `7d948e005f63da2700c3f54c7f4dfb713ab7a87ff5dd2837bea5ae850c4c1ba8` |
| `d02--sample.elf` | `ab57372bc440d7d2541a9bdc841c60790032552f6fe4413a993803795ce88493` |
| `d03--sample.dll` | `20c402a23383e12411f564746bd7c6521c0e37bb19932ec46717c5f670aa8832` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | `3b9049ddb7146856cf166a8526261350614834c5a206a7fc91eb99691d8893df` |
| `d05--sample.elf` | `29f12e8c6b5e9b29a26e3a8d6d6f65078ed3ab51b0731f6978188704cb8f9488` |
| `d06--sample.jar` | `421fe09f02a004793948db64ab24bce8901e69f5ee684b7ba8d5750e9399b5b1` |
| `d07--sample.jar` | `a450f137d176153628dfac5e2792622cff1b07ce2e028ed6230fe8bed1981d8d` |
| `d08--sample.elf` | `931d239675ebbb4e38417667b0d3b5aa347781cddfe5e020db003772954b0ebd` |
| `d09--sample.elf` | `39b92e00cbffa37cca6fbec926e2dfdef444b19757a454d724fdc7fe265f828d` |
| `d10--sample.exe` | `e3ebb1042ac1f989c108cd93e354bc9beda145b12c478f725d4dae2e36c65606` |
| `d11--sample.elf` | `c4f8fb00ef7815773fb7b8b45cab4fcbbf0c160ce83b564417b99a1916116d63` |
| `d12--sample.elf` | `b23f8d7c6655585018f4eaefddf483daa60168d09e29f8e316a5c9a8cb2a58f6` |
| `d13--sample.elf` | `fceb14c5b1e7686d5eb3758bcc7353d15ab9bcdafd72f54e041aaa944be9430b` |
| `d14--sample.elf` | `191b137be42187a8f929d40ec2ded0650646a938535e531f8ed24c085a67c2fc` |
| `d15--sample-stripped.elf` | `49f83d055ae839575749d9276a05d9955914e2a99df8b94cd69af3a7a8e2e0ee` |
| `d15--sample-symbolized.elf` | `eeebd0cc25700e5df90fedb8fba62d7437316e9dd8b5a704540cdd282533316b` |
| `d16--sample-compact.wasm` | `4f5350e0e39a0291ed8db47a2dcea2636eca7fd677fd2339885465b722ba323e` |
| `d16--sample-direct.wasm` | `b15b722b98c677dd43b47bb32724ca751e66319f9688336d6da38b054a743392` |
| `d17--sample.elf` | `02ab8cb15be3226d739df1b98e1a62fbd22ee3c49792d1d0a2a8b0ebed0e3814` |
| `d18--sample.elf` | `0a9f8af2054a98e9864cd7e80636a499c3bc503427a74485e9e87b3e23a7f230` |
| `d19--sample.elf` | `eba8a081982a3f61de46e64e6b95a1de13aacd06a912f61a7597f092e94e0485` |
| `d20--sample.elf` | `dd7feda5d38958256eddd812127a2879df43c9a627f1a6f9572d44d92d0ff662` |
| `d21--sample-loader.elf` | `bcb3be4855870a85bd9e209ae880aa2634788686578caa051a20a501a62ad314` |
| `d21--sample-plugin.cmxs` | `aafb96d9adbecf95ddaa13ed53ec96a486cf1f3e9cd109f71067cd048d7fd154` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `eeefb42d05682b2144d8fc38b44b8a876347c2f172d740c156a7f7c65abbd961` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `a9c4be3d2d783a51e13ff7ecc494d7faf6ea8ad27f503db03e1396a67dc59ca2` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |


## Mastery — 7-set untimed bundle

- **Attempt:** `b991524e-6de6-4070-bfa5-b72f7ee76841`
- **Timer:** untimed; `deadline` was null.
- **Result:** all 1,932 findings accepted. The Game Master returned `CORRECT`, and a status recheck confirmed all 1,932 answer IDs for this attempt. CourseStack shows Mastery as **Correct**, completing Trust Issues at **3/3** modes.
- **Flag:** `dc582bc0767216c84f094327788bba26`

The bundle assigned seven independent `evidence.zip` archives. I downloaded each through its per-set Game Master capability, verified the SHA-256 against the start response, and extracted each into a separate directory on REMnux. The answer IDs were prefixed `set1.` through `set7.`; the generator normalized only the prefix for analysis and preserved the original IDs in the submission. The same static parsers covered all 23 sample families in every set. The 1,932 generated string answers exactly matched the 1,932 answer IDs. No challenge binary was executed.

| Set | evidence.zip SHA-256 |
| --- | --- |
| 1 | `a5b4f0f10d879b0ae3643d5b5de81592f8888f9f6a26ab6c9c55896b0abaa401` |
| 2 | `3e4eedba255235594679b38c6ea8b7acabd1780c9cf73a37334c7c941dba08e0` |
| 3 | `75a9341eac41a944b9bbe40ea7193613f7159cca0a3cb9dfebde3d1561878031` |
| 4 | `35711804ec34c951f0b4d29ed39c38c78c58b53c574bc69132153795d8c7fc57` |
| 5 | `a00f88796457976dff70f3d46322b948e4bbb68507ed2d440b0add2c871ab4ca` |
| 6 | `75c1ea2eace03f846a93b9a4a48e5eedee6c31fd59d1ac55583014fc40466fcb` |
| 7 | `8553a396f13b0fa35633af364bf8f5703cae8725281205e9b37cecdcec2283e8` |

The following hashes identify every extracted member, grouped by assigned set.

### Set 1

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `3870d68024a79dae9f7c45662d293cefec9a5c30bcabb55218d0c584951041fa` |
| `d02--sample.elf` | `a2c717cdc1ee5cab3124a588e5f72f6f457c07c7308bb3b6cc6bfeab5de904cf` |
| `d03--sample.dll` | `feb20b55faeaec06d82eeed63210fe55dec0019a9abdf2fe00a91b28939cfa90` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | `5d88f5145e48f66d296da9eb584d17b330f32941222724349a62aeb6aa5792fd` |
| `d05--sample.elf` | `c719f351ba3166024ffb4216a3a290a467df248b4795718d0e12934bebb140fc` |
| `d06--sample.jar` | `676269c129ed7d8669a5f8b680103fb0e5ab0e6b2b0236986d554fbf652496fc` |
| `d07--sample.jar` | `30a157476b44e23688f64a7592122e916aab717a50c15b1c1b8aa501c72afbff` |
| `d08--sample.elf` | `a61ef5d0d039b418465b9e5ef8ab708ec426ee1b6b1ee496916084e0d897f1b5` |
| `d09--sample.elf` | `0e42374a44369d52eaa4b08d9cb7d35b3d5e43a32a006a85a77b439fe369f6cf` |
| `d10--sample.elf` | `ddf41a41b4ac6a5b00bf47609ebb00b6662741df987edcb8333c69bd6c47a9b5` |
| `d11--sample.elf` | `6e3011039f08189ae70e7556e7c948b268621992496574cb166102993e90f888` |
| `d12--sample.elf` | `eb791ff239eee1d49d5da61dcf7c5649a9a533be5822aea629fcbb51d7899c15` |
| `d13--sample.elf` | `6cbb8609de83eb72eef38a119a9f9862522ef952a51e12601e84b1c380a706ad` |
| `d14--sample.elf` | `a0c48800a685b76de087162394f8fdc9472a6f57efa05e329de260f7439ce5aa` |
| `d15--sample-stripped.elf` | `fef0dd507a5b642e59a9bd09c83eb91343e7cda17315402f7eabf80fe680013f` |
| `d15--sample-symbolized.elf` | `a76305b5a792c5222ee423cf425873fa487bf4acc6bfab982a5c4a291120edc7` |
| `d16--sample-compact.wasm` | `eed5ac6a3a01a57eb09c186afaf87775eed35c4632609c11f604e494ac6b5cbc` |
| `d16--sample-direct.wasm` | `47125d19f196a41a50ea1d1c1e1c7b21ece6bb2a3916b87f8223c5ffb9c2b4dd` |
| `d17--sample.elf` | `0a1b247486d0b0f50a0d7741200bfb6272118bc15d009e62a53ce4c2f1dea207` |
| `d18--sample.elf` | `82e63443d9f7d0e1a853badf8e33bceb7c3c411f23c448a8be49936336359a17` |
| `d19--sample.elf` | `e21a7f7d314921a889fb3730384bc980d35eb884bdb7c7bb0ba0ef578b4db344` |
| `d20--sample.elf` | `a8b764d710196cb6ba6034b4dd3f2212b3d9514d355e9ba7d1ced880f164b766` |
| `d21--sample-loader.elf` | `3a4436933c9a85408457019bcbcb732989582b46c54f3fce292999f52c35677e` |
| `d21--sample-plugin.cmxs` | `98924d285bfbec4496a88c41c3c114bd998f34581c8336d3b98623278b79884f` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `0ab3bc83a670d4f38bc1aed8ff1b6402278d4d26a1137ab6e50d016d02ca82a8` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `43314be5f6e85f4d178c1afea77c6585e71a9bfb13efafd99aff4821e7d1aa51` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 2

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `0b2b5336b30f954dc19de06b17036d118e5459069686c528ee1044e8e42b0be1` |
| `d02--sample.exe` | `41929eae6a3ddbfabc6c6d5880cef69edabc9a64c4d9a2a717d784c46c293912` |
| `d03--sample.dll` | `26b9ae24b7c2c03e380f8354cc6a08f6a4232c5597614725eda0d5ed92275c52` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | `412a489af3ee15e5a09f41af4e360bb93bf1cbc57e3c92e36b4faf91b85afe4f` |
| `d05--sample.elf` | `d5f9eede8e2ed12cd020871d0d92dde99c64004bf215ef1fc1c3d95097f1b822` |
| `d06--sample.jar` | `693051878cd08c16481d228eba574024960c6ba3e9752301e77ba7e170d7fd3a` |
| `d07--sample.jar` | `bc65f523e38973b53449af4d8956f71469e7bc5489d411b9c968c4e20a0a5a24` |
| `d08--sample.elf` | `534df94d91d7068d7c76ed3f97127198324018566e7d405dff1f7636d3e1e366` |
| `d09--sample.elf` | `3c55344592a3ae3cc774abdefc68160c73261aa7b0e868519c4f08351a6f8d3a` |
| `d10--sample.elf` | `867698395948e1fea894c053ba629e30cc611bf7e5fdd5ed2d8e2431296ae4b5` |
| `d11--sample.elf` | `062c03d11b2ade2d2b05be6a61de53cfabab5c31a46e36d6dc965bad1298b265` |
| `d12--sample.elf` | `53bd51576b1de2287fd3eca87c9549bc7264781411ef3011e5501b32dd201658` |
| `d13--sample.elf` | `0d1812a8ea8080314b4c21968c51f043194580c13a944fd109687f271693c593` |
| `d14--sample.elf` | `979ec65ff543546f89a27a1139d637b96c1306e419c30166f56652f9376677ce` |
| `d15--sample-stripped.elf` | `de2a38c7c32b0e95bfa40b82809dba32db9067eb76e9c9a40d5403dbadae498a` |
| `d15--sample-symbolized.elf` | `5a72e86f60aa9f5e3f0235e2233ae5f7b3388f30868bcac2e585694968557b1b` |
| `d16--sample-compact.wasm` | `d2256966a4a696af30e89e5d35919458415f1770fd1271001cca4767ce0266e6` |
| `d16--sample-direct.wasm` | `5b556a3068a57c7180a9055a9e9e331ea92245255b7dfea15b9d5a0c031a0d56` |
| `d17--sample.elf` | `ea99084807350ea3dfb1005b0d5a0e6646d3c044c5915c3a9d6056c83500fd35` |
| `d18--sample.elf` | `364bc422a7d3d3fb605c1ed9c7c7ba2b843dc55ef86da4ea943e2687b63ccacf` |
| `d19--sample.elf` | `2b2cb4a451a1ead2ad6efa68fe59d25150b7551b6fae942f81a461c3eb7cc63e` |
| `d20--sample.elf` | `d98d1603c35a6af28b8d46011be93392f7128bb88a72f4d1c5213ddec6ca7b81` |
| `d21--sample-loader.elf` | `be2e35a9aa7266aecc45390febe7070ea34f523ac4037e7e4b6692024f88c0e0` |
| `d21--sample-plugin.cmxs` | `02acb1776f8b6b52efdbe6c858b45cd0ebfacb26c3cceaf1834ec5d0b42e2de4` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `4cbb7c33cb897a00d607733a7c22d184fdb4ee4c5b23ac24ecb7839b345a7708` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `32946e4f4351b95ea2636a9040cc11b06f00a7b9ef3ea05c450538034d975d65` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 3

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `ac1b1a49a30f0e791a808d3ec3911497c5cbd1dccff70044016bb6846075f88a` |
| `d02--sample.elf` | `c4a94f9134ec966db36859ea86927d6af87c44c4717d1b783f090928737f5af6` |
| `d03--sample.dll` | `e7191c88a05cc741c9587bbeef372a6ecfbb510e867ee29f519dc29782974c70` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `a30bde4b058e4aefd33a403b671a87b239eac91097f421ec133c8c25d088015d` |
| `d05--sample.elf` | `2fdf808763ddfb3e6a31224143e818187b3f46d64b844e66a017aa4bdf29609a` |
| `d06--sample.jar` | `130efe1d431b7b124e948a66025d2a17766375fbda81ca5c56795798100ace65` |
| `d07--sample.jar` | `14bb039264c0fd0c817955a37351ed9eacff25a61404d70c41658500c110d442` |
| `d08--sample.elf` | `7df08b197f5197955b9cd944c022bb389abb54ff4235183e7b16dacba3b62df5` |
| `d09--sample.elf` | `23267ca08bff1031288ae4f38aa194b41751f2b97ebf2b3211e17e772652ceca` |
| `d10--sample.exe` | `08a56c1187cea494c1ce6add82e44a08799a547c55abf02010b93bb4f872e028` |
| `d11--sample.elf` | `56c276ef4bf267e35ef022cdcc0b44206f4c38fa8af643fd1b9377ec4d0ead5a` |
| `d12--sample.elf` | `5e9d2d47062f0cbd028ade7a72f0509bf44cabf5babcb4557a176625315d2460` |
| `d13--sample.elf` | `dd6ed529136c8da00235cf15a50df692ebb05f642815193894cb70dec8554dac` |
| `d14--sample.elf` | `30bb18ef063dd442879b3a85ed9d68e891e1ad9a3afa5d01600da351e11cd5df` |
| `d15--sample-stripped.elf` | `db9350a87d5b47a0b9576c79d4dce93f1c45490d6a11814adaaa48c6e623aed7` |
| `d15--sample-symbolized.elf` | `122379b4cd2b6e3544a2e4181ef504a00f3099baafae24643df3a226b341edc1` |
| `d16--sample-compact.wasm` | `a9acc8741bf69ec8a7abc59b8e8a1254f6561dda76aa4dba93aad48b875c1399` |
| `d16--sample-direct.wasm` | `9cab0ab43ef4524eea1405c4f38c59a40da30bae41710061d6c76d0689788aa0` |
| `d17--sample.elf` | `6394da30214adcb783f09e3419b832f72daf4f2e3aa479a62f16103480d45244` |
| `d18--sample.elf` | `646b1a389cd2a67c560917fb67e672f94e9dcffda1e47f3d7162a1c4981e4729` |
| `d19--sample.elf` | `0a7e5f956f724978ad652f965f095ffacbaae3c4fc373806637ab8b50eedeb01` |
| `d20--sample.elf` | `5180841dc6b3556ccdd9a98fe4c04eaf2fe2f126b4b848fb152500e052ba8de5` |
| `d21--sample-loader.elf` | `dc26397e083896b4bc3059ad893fca367a70ab46b8154eead29296582e123c2e` |
| `d21--sample-plugin.cmxs` | `bf9914ea3326b5051cfc0d1fd1db731ab84f09a66a6755b5faa03d42834d43f2` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `991a8c7975af1d574b64d0add0352ae551de689442d91ccfb1299caa9be7ab00` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `a88352bfeffe4d0f1864c34b75a723f080d1709a5d4a2c32dc44ede87d33f55f` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 4

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `b04693248e5baccf950ff906ac0d194b6977f09c160fd68c772cf1cd1769d5b3` |
| `d02--sample.elf` | `97f8c0554aadddb20e9a97935fdf32389917d94d7ab90a53527e0c1b615bc5bd` |
| `d03--sample.dll` | `1fce84cb1380305c7aa05e3071c14bd4eeda299c287039b0ff82f8b4259ffcb0` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `da020ccc2544df72a7ecf027bb43caa9f339a253d5b221db2a8264d88f26114b` |
| `d05--sample.elf` | `f07d318b05f6fba36c0921142576f2fd660c16965d47b3f6ab6fcde23d98e5af` |
| `d06--sample.jar` | `99454222384c8b5b755958524f54d234e70a4dcd4945fe6aff6fe7278a171aa1` |
| `d07--sample.jar` | `5929a4e9e4e8a71ddf4c26d620e891a87dbc59a3eb4db08d1ed87ab2ca051e3b` |
| `d08--sample.elf` | `1289940f16be6a81c6f75c95030fa62c6084eea97bc3898583b73f7ca05dabc8` |
| `d09--sample.elf` | `5bf8a23e2afc9db0a9a5a0a53cdf645a8d67651413067f170ac839188918e8ae` |
| `d10--sample.exe` | `568ff39d8f6543ee37b8e8b0ae3ae1ed6ad439a21dafea09c5e260c63b882578` |
| `d11--sample.elf` | `4637df050cec7150e172806a647cfdd2836aca31b9646d846ec467dc4d469582` |
| `d12--sample.elf` | `4fadfcceaa5f9479c8ff6076ca2482c54351ec87b88894cf48b3fed26d9aa529` |
| `d13--sample.elf` | `06cfd5392f842bb8c4e1c3d8d3ded457dfaaa288ec9c3ce249e57ce438d77392` |
| `d14--sample.elf` | `72ad4134fe685d90481acd660e9246bc23d363ed00a1aba60fea8facbce217d0` |
| `d15--sample-stripped.elf` | `404792c4707de8a9ed9ad991d8776ca76410ef051485eb0dfcd5015ff6f5c2d6` |
| `d15--sample-symbolized.elf` | `abb2f86b97a07a993d05e3153a811af26775199691d4d17c7b91abbe3c234c88` |
| `d16--sample-compact.wasm` | `68b21f4b0933dee2509372db292570b5433cc34af5cb14d6e9ba9d9e7e5e9d36` |
| `d16--sample-direct.wasm` | `7739b67089764ec9f3f373c72da5009df4bec0da15a08675374b4ba469089737` |
| `d17--sample.elf` | `05218069fd79de17cd92081c9e51a0b4e01c6fccbd46e4ce1abc34493cc41479` |
| `d18--sample.elf` | `9c32bc3219125917edc12bb9db0caf0e6f5a0bdd8dfd08f1f3fb0771e6d9ed48` |
| `d19--sample.elf` | `f9c2e8a39f9db0df707a5a3243d67f0e37fc829270f5f582a8ea63a3176596a8` |
| `d20--sample.elf` | `e3b1397670bf44ea297e6f936d72d9fdc2c5fd7592b48cb410759fac7e7be389` |
| `d21--sample-loader.elf` | `1552e51fa4a9b07aee19c90726057336ba9d5e75a6726b73be7902698537ba6e` |
| `d21--sample-plugin.cmxs` | `4d2d6381ecc6184ddf478ef02f1fdd8cbd0bd11727ac715727db8a3d72b46635` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `61a721e1586c84994a05f24aef5a34983fc7e40e7d62366720d201f55316f194` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `7cd9e5e05d55f125646dbb46988684a70f882d453ad57de804cc14157396860c` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 5

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `4aa39985d5cd037b7825228b16bd9f60bdb68c69f9205079455af2d05e735ad4` |
| `d02--sample.elf` | `68146664566bb737b9f66f3719a43cf02c7f1a1ce4a0740ffdf17fdac81eecdd` |
| `d03--sample.dll` | `7b5abfb1c72f4159a09adc10cf2800315b1ea30a24d9537f932d1a8351a3c1b1` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.elf` | `a3bb9e523e890334fc889b5639ff67161213a99fde702ed604291aaff1147779` |
| `d05--sample.elf` | `c3cebbf4dbefae622dcf7f4c61bba479931f728fcdf104cb30dd4c4bb7f31885` |
| `d06--sample.jar` | `c38d3f1aa1300f141564d4f27c8a5045f9b78a8ebd75fb8a833e42fb88ad558f` |
| `d07--sample.jar` | `b05593886ae31f58f10e24c2a729fe96dae30fb4653e50d74e633daf2cb5a12a` |
| `d08--sample.elf` | `84978f4e3b70a90d2d66e7392e922d23ecde92dd4e8aef1bbda5969f6cb519be` |
| `d09--sample.elf` | `acb6afd693d9acc7c5ff8bbe05dbb30e64e1fa01ec14a7dcece98f6e024ed7a7` |
| `d10--sample.elf` | `9484e7aece5c7423419b8a135f9e3973fa52b6236a12ddf8f39dd4876d9bea78` |
| `d11--sample.elf` | `a5acc1da8bfb20237329935ac62a020b392b1f3b14d066fabfc016812e249edf` |
| `d12--sample.elf` | `4dd074b45eb53fba805eec7def94331a279bf560d41193d1d31e1a3a2e2e00c8` |
| `d13--sample.elf` | `e9fec4ce82a874844dcec3f18a85e64fbe0a8e1e7572d4b9d4d4af26897c190b` |
| `d14--sample.elf` | `74d4908e43400177efe3b58f78f6a8b2ddcf51855903515f396edb4afa1c40f6` |
| `d15--sample-stripped.elf` | `c481a7caa08073a915e0644ca61c87a1f0e1adc54686bd0df892a01f713ed24e` |
| `d15--sample-symbolized.elf` | `36f6b88bc5275256a27cea8226ba8a5817da5eb49ca399b3b846fb489363fff1` |
| `d16--sample-compact.wasm` | `fea8d56a579d18196776de4e98b4e49524ef287a36f110f035d79afdf5679b54` |
| `d16--sample-direct.wasm` | `70b8abd1b29d7b14942f55f1603e73693b7004d41f2176c85b125823d39efa87` |
| `d17--sample.elf` | `5e8d5d156de7f6bceea353e932b99070425a43fb4bfae9e7f08b430028f5b48b` |
| `d18--sample.elf` | `e9be0df0077984f6beb06d1bd967e63001afa7a879342b02150b32bb55002ba4` |
| `d19--sample.elf` | `f9e11355b8d09130a97ba8d255e4ec2317fc3096053aedc4cf3b5cf975842605` |
| `d20--sample.elf` | `88de04dda63b2824ce1f0278d7dc737907cd2c78641539caa8fa2498a96edae2` |
| `d21--sample-loader.elf` | `242ee6a330bb56cf869de5891abbe485d130fe6e1f0b48f0205e5a95f547f5cd` |
| `d21--sample-plugin.cmxs` | `de0f93ace05fc11a789e3e26db330dab177aae790d1121e6e9392f2fcd12a751` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `687a11753e72bdf3d54e880c979ca73c9fef449fe842e49ce7620e54fd1c2713` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `49a8b4d550129e898ab65eaa7a4c70e30ce9ef16d2ab2525244bef79f74c460d` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 6

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `246e5b95dd208135613d8f616c2456ab78698131613e27cae04b5406c1d7dd8b` |
| `d02--sample.elf` | `5f7ed0d815af23ca4eeec877d9cf9fa5125bbc078313f998dc153575fb3eb20f` |
| `d03--sample.dll` | `9235e20ec67736b88fdb88eb074dde8d410bf114998005d707cfd73fb1871773` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | `53ec80108ac6cf429237e8d444b698e00f93a75f446d6484f89d44190dc29c01` |
| `d05--sample.elf` | `c9280990ceeb306286012b7c7949e6d0bc83e4d647f075ff6fe61d95ed8e4722` |
| `d06--sample.jar` | `8ded4170fdca393da1d61d4e6190c6e8443717e7ed128e11f81e0e2cfdfa781c` |
| `d07--sample.jar` | `e84a8987dad7553bf1ac97f0d300bab295db66ac3c7de51efb5bd18532e38b5c` |
| `d08--sample.elf` | `c1cd9be730fffbb55470a7bb89201bc3818da46f99f7d1a8cf65d99249430575` |
| `d09--sample.elf` | `0dc4b4b1eb061f5a0a56626e3c2d3cce9e417fe56cbc05bff7138d8580aa0886` |
| `d10--sample.exe` | `3ac0bcb8b92e86abeb2845c1bd1bd058942959692f406d7b89976cb02617bf09` |
| `d11--sample.elf` | `11712faad6e2ec48e22f65bec1129de84773f8f55882082823a03d22de6ce198` |
| `d12--sample.elf` | `63aea7c5715324d5574f5cc42f155d89ac9734511a73993eebddb339d3abb495` |
| `d13--sample.elf` | `022961b6708a7dfb86687a5f4ef3f7b198a466d486a195e47dba9b3e570d6713` |
| `d14--sample.elf` | `07788173c6a990f2053a3c8fb9c88023fa56b088ce76e544d8e4051344767c48` |
| `d15--sample-stripped.elf` | `ca6c102c57361b099ec11f2200133e75f61f21ccca811ffc599d7b6a922976e2` |
| `d15--sample-symbolized.elf` | `29d1fe67b65c591a21d9be223ebdf3b5949d73112cc47d076bbdf5072ab85624` |
| `d16--sample-compact.wasm` | `f3323c567e641b98d92951b9c6da40b86aab38a6ddd116dd210298d4aac0bdea` |
| `d16--sample-direct.wasm` | `6b1e95f4b64b8eec5086822dba942c4136f427186590b39682fa27f60972a120` |
| `d17--sample.elf` | `4aa59c07f16d78b9cffb3815afa5c5a48f5254c5d3469b696d344e42f42707ba` |
| `d18--sample.elf` | `1b44b22245acbb5dc91440b1dddbc3bc87d3e88fdc5745705e7ae96503f953b0` |
| `d19--sample.elf` | `4ed467ec77fe1080b72f3ef449b381166daec41cabe5254919b8368dd5415db0` |
| `d20--sample.elf` | `0f4b92897d4e9e607b7a660a83489d9bfdd2942d8627bb21ebf17202cf3becae` |
| `d21--sample-loader.elf` | `8688f837f07a8e2504e05a4909dab8502990d6aee9fbb57485f1079369bc2860` |
| `d21--sample-plugin.cmxs` | `602709b6ae74db8852e596664a8840de85fbd3d20c2710345001e29234c44e58` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `fd171ab122d048095bf53270fe96b210ec92b45aacc5ce2defcb97c13f85bc4c` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `51548a7884936204c5a994ad91e05d50b5321bcd97c64124ab37ca3780be41c9` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |

### Set 7

| Member | SHA-256 |
| --- | --- |
| `d01--sample.elf` | `ccf78d1cb0324645bc769f034303d8ad91c9443fbc133a71bfcdf9f4fd61127e` |
| `d02--sample.elf` | `d04f179409cab0d1dc2d1a02969bf12c5d38444455acbec7fdd17a1a4f8a8410` |
| `d03--sample.dll` | `95893fb48ceae56d5a584f68f12655f73d711e3937623148dc3aaec3568dcab2` |
| `d03--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d04--sample.exe` | `4af81812df354a4a99f64ceff878d2072aa564885a52dafec94630d6b4d934b6` |
| `d05--sample.elf` | `f0c1924acf85075dd4589e35934e5c12885a871bff87c1d2f5455a68f6c611aa` |
| `d06--sample.jar` | `2ef3cc73efd1a2f2b6ff48043496550c0318f00519d7278c90519b4ff758a429` |
| `d07--sample.jar` | `e3653c952a14b08ad7707f2bb021c09247c8afb2425d45a69632a5f2960ddcf1` |
| `d08--sample.elf` | `4cb1cee7db14bf1502b71f664bc2db18d85eeeb5d9283c44c3edb40c9dede112` |
| `d09--sample.elf` | `233d44427f8bdc97e68793a105e57ca657974d8fa616f3f105ef38d7408c82a9` |
| `d10--sample.exe` | `45ae5a582862ea3dddc4083cefe9d3accb92e70abe41a7d67651f91a00d05200` |
| `d11--sample.elf` | `e3180b51489eafe881cb58f727aa7c2f4a574d4962993b796bbccc96c23f25e7` |
| `d12--sample.elf` | `0330991d54d88b6dea8ddfa164bb8ef4d5d97181dc2d279ab962eedf15daff59` |
| `d13--sample.elf` | `81b20a529e1357209847db558e89c51c20bfaca2e4ffb4f39e20f8b7f1ebdd5e` |
| `d14--sample.elf` | `3877b990a71ccda8292b3edf33bedae74c95d3164e2794102aa0430314b5be49` |
| `d15--sample-stripped.elf` | `de808ad051685b698692480818f2b3e9c02991c504b8e536e9793eb522d6cbbe` |
| `d15--sample-symbolized.elf` | `fc4e487047db6478141992c91bf1b8759d0852dc2e888bfe9e199eb2d4044052` |
| `d16--sample-compact.wasm` | `99e4b092286834f0beaedda7114138555b2861a672e33fe00200a51223f59aa4` |
| `d16--sample-direct.wasm` | `5d13186d2ed2bbb8a793a2d9ca2832a5df7a3ce0a7d3a51e4f940c84cc87cf57` |
| `d17--sample.elf` | `6e2a6f7427130316a6422182e905c1adbe322589f752c4308f56b2b0ae299f73` |
| `d18--sample.elf` | `ebaf0e66ae5a49477d6b8647e827d950477a488359418646e22c5f5e51c8e926` |
| `d19--sample.elf` | `c63cdd2f4eb63633211b28acf96e0b6e48c5b771a079dad94b4633bc91af3b8d` |
| `d20--sample.elf` | `eeb0697c79ff4bbaaf890d93b17dbdca48055d8b8ec8701a172ca04154c4d1de` |
| `d21--sample-loader.elf` | `cbbfc505ed6d2230f5d5edc3f78cbda0d072b150a708dc484dfe2dbc297b1064` |
| `d21--sample-plugin.cmxs` | `a5bdc09f8a80838cddbc287aceca8e6263646127696c8a8778309f2e0eb7487d` |
| `d22--FSharp.Core.dll` | `65b2ceb9bbef399efb507a7782093108bf6dbfe749096c44996af41b7577938c` |
| `d22--sample.dll` | `8157dde0334a0e9ccd34f1784e9686521595e207a75d6bee45cbafbf6967ed74` |
| `d22--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |
| `d23--sample.dll` | `0fdcb30de0027183caf53436bb890ef79daaf14fcd064756fdacac4340ca28db` |
| `d23--sample.runtimeconfig.json` | `d6109426b0081160c55c7a8229bd386ce28a065bddcf46d29153e0c708a06cf3` |


## Day 29 — Trust Issues (2026-10-29)

Completed all three assigned routes for the paired team. All submissions were untimed; the Time Trial and Mastery starts used the ordinary start operation, and both reported no deadline. Game Master status confirmed CORRECT for each route.

| Mode | Attempt | Assigned artifact SHA-256 | Result |
| --- | --- | --- | --- |
| Single Solve |  |  | CORRECT |
| Time Trial (untimed) |  |  | CORRECT |
| Mastery (untimed) |  |  | CORRECT |

### Method

The Single Solve archive contained . After verifying the archive SHA-256 and extracting with the published password , I used OpenSSL to compute the certificate SHA-256 fingerprint and submitted the 64 hexadecimal characters without colons.

The Time Trial archive contained 26 cross-format files and 34 requested fields. I verified the downloaded archive SHA-256, extracted it on REMnux, and parsed the metadata statically. The analysis used standard file/hash tools, ExifTool, OpenSSL, ZIP/XML and binary-header parsers, plus the existing Huntress metadata helper for EVTX, registry-hive, and Prefetch formats. The exact parser names represented by the blank fields in the original notes were not preserved. I did not execute any samples.

An initial full TT answer batch was rejected. Partial submissions isolated the mismatches without advancing the attempt: the external OOXML relationship targets needed lexical target ordering, and the disk partition start sequence came from the GPT entry rather than the protective MBR. The GPT partition begins at LBA 154. Corrected values plus the accepted fields completed the route.

Mastery supplied 13 nested evidence archives and 442 fields. I verified the outer archive SHA-256, extracted each assigned archive with the published archive password, and used the same static parsing approach per set. The exact password itself was not preserved in this Day 29 note. The per-set fields included note names and hashes, media/image and document metadata, ZIP members, PE/.NET/MSI/LNK/OOXML/email fields, ELF/Mach-O/APK/JAR metadata, SQLite page size, EVTX record counts, registry hive roots, Prefetch names, PCAP packet counts, GPT partition starts, X.509 fingerprints, and each set's SHA-256 ordering task. OOXML target arrays were sorted lexically; GPT starting LBAs were read from populated GPT entries.

### Game Master flags

- metadata-forensics-day-29-trust-issues: 
- metadata-forensics-day-29-trust-issues/time_trial: 
- metadata-forensics-day-29-trust-issues/mastery: 

### Day 29 evidence gaps

The retained Day 29 notes assert `CORRECT` for all three modes, but the attempt IDs, assigned archive hashes, password value, tool names in the blank fields, and final flags were not preserved in this section. No Day 29 archive or answer file is present beside this write-up. I have therefore left those missing values blank rather than copying Day 23's attempt data or guessing. The method summary records the reported metadata families and the two corrected Time Trial interpretations, but does not provide enough input data to regenerate the submitted answers or independently verify the three mode results from local artifacts.

*Write-up organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_trust_issues.py`](../tools/solve_trust_issues.py).
