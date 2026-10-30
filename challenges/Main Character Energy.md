# Main Character Energy

## Day 22 · Single Solve

- Challenge ID: `metadata-forensics-day-22-main-character-energy`
- Attempt: `b64fffcd-5ee9-4fed-8e15-531db0b1d30f`
- Timer: untimed.
- Assigned archive: `metadata-day-22-evidence.zip`
- Archive SHA-256: `8cbaee5dd7800c8afd80ae9030b3fc419b965dd3b9f63ce2489cd4e96f64343a`

I extracted `application-001.jar` using the published archive password. Its `META-INF/MANIFEST.MF` declares `Main-Class: arena.evidence.ArtifactMain`. `javap -verbose` confirmed that `arena.evidence.ArtifactMain` exists and provides the required public static `main(String[])` entry point. The class file and manifest agree, so the `jar.main_class` answer is `arena.evidence.ArtifactMain`.

### Reproduce the Single Solve check

From the directory containing the assigned `metadata-day-22-evidence.zip`, extract the nested JAR and inspect its manifest and class metadata without launching the application:

```bash
unzip -P infected -p metadata-day-22-evidence.zip application-001.jar > /tmp/application-001.jar
unzip -p /tmp/application-001.jar META-INF/MANIFEST.MF
javap -verbose -classpath /tmp/application-001.jar arena.evidence.ArtifactMain
```

Read the `Main-Class` value from the manifest, then confirm that the named class is present and that the `javap` output shows the required entry-point signature. Here both checks identify `arena.evidence.ArtifactMain`; submit that exact class name using the answer ID and format supplied by the Game Master. The hash in the route metadata above identifies the archive bytes used for this result.

Game Master accepted the answer and the personal status recheck returned `CORRECT` with flag `9ac3b7fed00b194598276482d426b125`.

## Day 22 · Time Trial

- Challenge ID: `metadata-forensics-day-22-main-character-energy/time_trial`
- Attempt: `79ca1498-0dfe-4644-842e-b86103d92268`
- Timer: untimed regular attempt (`run_for_time:false`; no deadline returned).
- Assigned archive: `evidence.zip`
- Archive SHA-256: `d2914784efad3c587e46ec8e9a964b871b6b1145d208764b02767c4c4d4f2771`

The archive contains a cross-format metadata set. I checked the note bytes and BOM, hashes and size, JPEG/PNG dimensions, PDF version, nested ZIP directory, PE headers/version resources, .NET module MVID, MSI Property table, LNK target, OOXML external relationships, email headers, WAV format, MP4 track dimensions, ELF header, Mach-O CPU type, APK binary manifest, and JAR manifest/class. I also computed SHA-256 for the five named synthesis files and sorted their names by digest. The Mach-O field required the canonical CPU type value `0x0100000c` in the requested JSON array.

Game Master accepted the full answer set. The personal status recheck returned `CORRECT` with flag `4ae19507fce7cbf5240013c96e54009b`.

## Day 22 · Mastery

- Challenge ID: `metadata-forensics-day-22-main-character-energy/mastery`
- Attempt: `e14b2b86-df39-47b7-8f1c-4cbef9956825`
- Timer: untimed regular attempt (`run_for_time:false`; no deadline returned).
- Assigned archive: `metadata-forensics-day-22-main-character-energy-mastery.zip`
- Archive SHA-256: `2d62aaba9e084534d0c8919fa097adde412654535aa054ff730d2d1fc42a145d`
- Six nested evidence archives:
  - `evidence-01.zip`: `1536b7832dbd2b5c011f370452576254d00a2d6b8e220f4552787eea65445fe8`
  - `evidence-02.zip`: `407151a22ad160dd1039cf115d22c79d262ff8a1506f3c24b2d1dfea877bec8f`
  - `evidence-03.zip`: `e91a273ffc4291bd540683ca51d61f5aebb29b8cadc30df1b96e830823b1175b`
  - `evidence-04.zip`: `3d33fb6594267b98ba5b33624351c471d996aadc8c9cd708c6627cb6a5911a29`
  - `evidence-05.zip`: `9b5495ff30937402f511b6e9a0d1aeb757f86305037979489a8fe9d348d2995f`
  - `evidence-06.zip`: `3377a4711426fb5cae0fc959295bfa2d989e06141daff090732c727bd43cb0af`

The six archives each contain a cross-format metadata set. I extracted them with the published password, then used REMnux tools and a static parser to collect all 27 fields per set: file names and sizes, cryptographic hashes and byte prefixes, image and video dimensions, PDF and ZIP structure, PE metadata, .NET MVID, MSI ProductCode, shortcut target, OOXML external relationships, email Message-ID, audio codec, ELF machine, Mach-O CPU type, APK package, JAR main class, and each set's five-file SHA-256 ordering. The helper parser is [solve_main_character_energy.py](../tools/solve_main_character_energy.py). I mapped its 192 extracted values to the exact 162 answer IDs from the active assignment and submitted all six sets together.

Game Master accepted all 162 answers. The personal status recheck returned `CORRECT` with flag `ed9e91f626584f589cd11c860cc8690f`.

*Writeup structure adapted from RyanNgCT's [CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template).*

## Tools and scripts

Project helper: [`tools/solve_main_character_energy.py`](../tools/solve_main_character_energy.py).
