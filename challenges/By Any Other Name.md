# By Any Other Name

## Single Solve

- **Route:** `script-analysis-day-11-native-api-semantics` — completed.
- **Attempt:** `afcf9c1b-e164-4afb-984a-2334ee707536`.
- **Archive SHA-256:** `6488fdbba520b4c959216273bd629e25c71d2af329c7cb697ee014136b0056c6`.
- **Result:** Game Master accepted the full 811-answer set.

## Time Trial

- **Route:** `script-analysis-day-11-native-api-semantics/time_trial` — completed and confirmed `CORRECT` by status and the repeated Day 11 list.
- **Attempt:** `5148fb28-366f-46d0-a19a-a5216e6702f0`.
- **Deadline:** `2026-10-23T04:01:59.025Z`.
- **Archive:** `evidence.zip`, SHA-256 `e3d1ae05862e0edd852fe28d0a07105de95cf9cc38c4b9ba6f7cefebedc6dc41`.
- **Flag:** `8c0a9c11bfa6da82f3dc8514cf9fd440`.

### Method

The assigned password-protected ZIP was downloaded from the authenticated Game Master artifact operation and extracted with the published password `infected`. The source scripts were analyzed as data; none were executed. A static mapper decoded each artifact's declared byte representation and transform, reconstructed its descriptor fields, derived the ordered behavior graph and mapped all 811 answer IDs to their exact submitted formats.

The Game Master accepted 808 fields from the initial map. Review of the three remaining batch control-flow questions showed that the important operation was the descriptor reconstruction itself: `memory-stage.bat` reconstructs directly, `local-dispatch.bat` calls a recovery subroutine, and `impact-plan.cmd` calls `set` through the recovery path. Submitting those three corrected classifications completed the route.

The static parser required several care points: decode only the declared artifact transform; keep ordered `steps` joined with `>`; remove batch caret escapes and ignore separator labels; choose the first filename from the collection indicator array; and classify control flow around the descriptor statement rather than unrelated loops inside helper functions. For VBScript, loops inside the decoder or after the decode call do not describe the wrapper around that call. The Python `mapping_proxy` adapter came from the decoded descriptor, not from the separate `report` operation name.

## Mastery

- **Route:** `script-analysis-day-11-native-api-semantics/mastery` — completed and confirmed `CORRECT` by status and the repeated Day 11 list.
- **Attempt:** `395ee8f6-dc88-4486-b524-fcd3a099e2a9`.
- **Deadline:** `2026-10-23T04:06:54.745Z`.
- **Outer archive:** `script-analysis-day-11-native-api-semantics-mastery.zip`, SHA-256 `131328dda701614c79cb24172784074cbed456394af978abfed4f8787a819112`.
- **Set 1 archive:** `evidence-01.zip`, SHA-256 `1fc14b67334b3902f6b6fd1b9a25aa10a661614f8b274c26d20ddfd7eec3de69`.
- **Set 2 archive:** `evidence-02.zip`, SHA-256 `a7194f69573a02c6900597b3fe2f439235cd9d700376b75a44f7e869021ec64b`.
- **Flag:** `b1a9f13f41786f7b8c90e8978a6be6ae`.

Each set contained 811 fields. The outer archive held two password-protected ZIPs, so each was extracted separately and its filenames were namespaced before analysis; this kept same-named artifacts from the two variants distinct. The Python source in set 1 declared a repeating-key XOR transform, which was applied to the literal byte array before parsing its descriptor. The initial static answer map validated 1,621 of 1,622 fields. The remaining `set1.batch-downloader-control` was `goto_dispatch`: execution jumps to the dispatch label before the four-item `FOR` loop reconstructs the descriptor. Submitting that final field completed Mastery.
