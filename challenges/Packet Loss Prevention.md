# Packet Loss Prevention — Day 27## Result

Completed all three team routes for **Packet Loss Prevention**. The Game Master confirmed each submission as `CORRECT` and attributed completion to Jinzo.

| Mode | Attempt | Result |
|---|---|---|
| Single Solve | `8d3d3538-3965-4cc8-8255-9fcdd0dbe11a` | CORRECT |
| Time Trial (untimed scored variant) | `481776c5-7da9-495c-a8e4-1b4f13ee92b9` | CORRECT |
| Mastery (untimed scored variant) | `168f5f07-4869-4e8d-b1a0-96fde258909c` | CORRECT |

## Approach

The challenge combines a packet capture with host artifacts and metadata fields. I downloaded each assigned archive through the paired Game Master connection, verified the archive hashes, extracted it on REMnux, and derived answers from those bytes. The archive password was not needed for these ZIPs.

### Single Solve

The assigned archive was `metadata-day-27-evidence.zip` (SHA-256 `3aff14dbde990236abbb1cc9ffb5f71a96b910070e1854037854336fdddc5e32`). It contained `capture-001.pcap` (SHA-256 `4dbeed35c4df0dcd0caee9b2ee0357d95520ed2432df260fef5d4be40f57853d`). I checked the capture with Wireshark's `capinfos` and `tshark`; the file contains three frames. Submitting the decimal packet count `3` completed Single Solve.

To reproduce the packet-count portion after extracting the assigned archive, run:

```bash
sha256sum capture-001.pcap
capinfos capture-001.pcap
tshark -r capture-001.pcap -T fields -e frame.number | wc -l
```

The hash should match the value above, and the last command counts the emitted frame-number rows; the recorded capture has three. Submit `3` in the packet-count field returned for this attempt. This is the only Single Solve value reconstructed here; the other routes also asked for host-file metadata and synthesis fields, which are described in their respective mode notes below.

### Time Trial

The assigned `evidence.zip` was 677,446 bytes (SHA-256 `c9a3bdafdda81eff4a2f4707cf5f7c09ea2321435e2c9cbf926d18e4f352bcfd`). The live route supported timed play, but this attempt was started without `run_for_time:true`, so it was an untimed scored variant and no countdown was running.

I used the existing static metadata-analysis helper in [tools/solve_before_you_go.py](../tools/solve_before_you_go.py) and checked the packet-capture answer with `tshark`. A first batch exposed one formatting error: the external OOXML relationship targets must be sorted lexicographically, not by relationship ID. After correcting that JSON array, the Game Master returned CORRECT.

### Mastery

The assigned archive `metadata-forensics-day-27-packet-loss-prevention-mastery.zip` was 7,293,515 bytes (SHA-256 `c3546d4b02d91401749c9145f3aeadee0485f844e5fac84f16d998a75b55b872`). It contained eleven nested evidence archives, one per set. I safely extracted the eleven sets on REMnux and derived all 352 requested answers from the assigned bytes using the same metadata helper, extended to count each PCAP with `tshark`. I also sorted each OOXML external-target array lexicographically and generated each synthesis answer by hashing the named files and ordering their names by ascending SHA-256 digest.

Mastery supports timed play, but this attempt was also started as an untimed scored variant, so no countdown was running. The single 352-answer submission returned CORRECT, and a follow-up status request confirmed the result.

## Notes

The Time Trial and Mastery modes both accepted untimed scored runs under their current Game Master guidance. This writeup describes the assigned team artifacts and findings only.

*Writeup structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_before_you_go.py`](../tools/solve_before_you_go.py).
The capture inspection also uses the system utility `tshark`; it is a prerequisite and is not bundled in this repository.
