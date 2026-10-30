# Zip Code — Day 13 Mastery

## Result

- **Route:** Script Analysis · Zip Code · Mastery
- **Challenge ID:** `script-analysis-day-13-archive-delivery-chain/mastery`
- **Attempt:** `83c66ff3-9f61-4aa1-9a60-f25aba82dd32` (resumed existing untimed attempt)
- **Game Master result:** `CORRECT`
- **Flag:** `460adf4e48260a210a41b2a996b2820d`
- **Artifact SHA-256:** `c5b663ba239d5e9f5e4d4587b009989846c2788db75ed5ec723bfe34a1eca33f`

## Challenge

The archive contains nested script-delivery evidence. The task is to reconstruct each file's role and handoff from its inert contents, without executing scripts, and identify the link in the chain that was not meant to be delivered.

## Analysis

The assigned outer ZIP was downloaded through the active Game Master attempt and hash-verified. It contained five nested evidence ZIPs. Each nested ZIP was password-protected with the published archive password `infected`; each contained a large set of inert script fixtures. All five sets were extracted and analyzed statically on REMnux. No specimen was run.

The fixtures use several forms of encoded descriptors: hex, decimal byte strings, Base64, percent-encoding, and split batch-file fragments. Their declared codecs specify transforms such as XOR, byte reversal, and modular arithmetic. I decoded those representations from the downloaded bytes and reconstructed the metadata fields, including ordered steps, adapter, campaign ID, URLs and paths, stage count, graph shape, and next-stage indicators. For JScript and VBScript, function bodies and literals were inspected statically. For Bash and Windows batch files, the inert inspect regions and descriptor-building statements were parsed without invoking them.

The mastery assignment contained 4,565 questions across five sets. I matched the generated answer map against all 4,565 exact answer IDs and checked enum values and numeric/text formats against the live Game Master question formats before submission. The first full submission left 111 items outstanding. The remaining work narrowed to descriptor-control classifications; the last three batch fixtures reconstructed their descriptor at a `HUNTRESS_DISPATCH` label reached by `goto`, so their control-flow answer was `goto_dispatch` (the `call set` inside the reconstruction loop is an expansion mechanism, not the outer control-flow wrapper). Submitting those corrections completed the attempt.

## Verification

The Game Master returned `CORRECT` for the active attempt. The archive hash above is the SHA-256 of the downloaded outer ZIP. All analysis was performed from the assigned archive and its nested members; no script was executed.
