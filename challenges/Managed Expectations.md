# Managed Expectations — Huntress CTF 2026, Day 12

## Challenge

The task asks for each assigned .NET assembly’s module MVID (`dotnet.mvid_guid`). The assembly names and versions are not substitutes for the module identity; the GUID comes from the CLR metadata Module table.

## Reproduction

The submitted value is the assembly **module MVID**, not the assembly's display name or version. The MVID is stored in the CLR metadata Module table.

1. Save the assigned archive as `evidence.zip` and compare it with the SHA-256 listed for the chosen mode below. Extract it with the challenge's published password:

   ```sh
   sha256sum evidence.zip
   7z x -pinfected evidence.zip
   ```

2. Run `monodis --module` on the DLL named by the assignment. For example, the recorded Single Solve member is `managed-001.dll`:

   ```sh
   monodis --module managed-001.dll
   ```

3. Read the MVID from the Module table in the tool output. The Single Solve value was `21e410f3-c977-465c-80eb-6890ddd3085c`.

4. Normalize the GUID to lowercase canonical `8-4-4-4-12` form before submitting it under the exact answer field returned for that mode. The uppercase rendering from `monodis` was rejected; the lowercase canonical form was accepted.

The same procedure applies to the Time Trial and Mastery DLLs, using their exact assigned archive and member. The report records the corresponding DLL names and recovered MVIDs in the table below. No assembly execution is needed for this metadata question.

| Mode | Assigned archive SHA-256 | MVID answer(s) |
| --- | --- | --- |
| Single Solve | `9d3b4fc5a4894914b9e4598b8d3deaa501849486f755bec61b1e60ff24d8335d` | `managed-001.dll`: `21e410f3-c977-465c-80eb-6890ddd3085c` |
| Time Trial | `d8766f9e0de676d4a691d28df99a14440dc97cbc0b8eb16f57eb6ca72680bbd8` | `managed-002.dll`: `9e0e197f-d610-4ec9-bd1c-d28da985893a` |
| Mastery | `ff1847604dc4afa18288f04b25f393203b8e5787dec29cfea545ecd88eba9eca` | `managed-003.dll`: `2658bcc7-f07c-48b1-8cb9-2bb645f8680e`; `managed-004.dll`: `ecc37f87-9668-43c5-b9f4-011ee0d07c7c` |

## Results

| Mode | Attempt | Game Master result | Flag |
| --- | --- | --- | --- |
| Single Solve | `57b1c258-03a6-484c-be10-e92e73ebdf95` | CORRECT | `a43a17d9150114b07a2eb26e2f81c648` |
| Time Trial | `9b63e6f5-b414-465b-a71f-fbb701aad873` | CORRECT within 50 seconds | `059660772de5d45fd639f06fc49d11b3` |
| Mastery | `fc09b6c4-fcc0-4c46-9853-9fe2141e652e` | CORRECT within 80 seconds | `29eabe3461e7fff4d834347e595f573c` |

Repeated Day 12 listings and all three status checks confirmed every Managed Expectations route solved for the player identity.

*Writeup organization adapted from [RyanNgCT's CTF Writeup Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*
