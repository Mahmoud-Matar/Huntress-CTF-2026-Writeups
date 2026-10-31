# SHA1-Hulud — Analysis Handoff

## Status

**Unsolved.** No candidate from this analysis was accepted by the Game Master, and there is no verified flag to report. The previous submitted candidate `d4211f153617b44572115bd39262af587e23ce50` was rejected; do not reuse it. The goal of this document is to preserve the evidence and experiments so a manual analyst can continue without repeating the same dead ends.

This is a record of static analysis and Speakeasy emulation performed on the assigned sample. Some runs used hooks, stubs, or loop acceleration to get past expensive or anti-analysis code. Those runs are diagnostic and must not be mistaken for faithful native execution.

## Challenge and assigned artifact

- **Challenge:** SHA1-Hulud (Day 30, Binary Reverse Engineering)
- **Challenge ID:** `binary-reverse-engineering-day-30-sha1-hulud`
- **Mode/attempt:** Single Solve; attempt `2cae085e-3f82-4781-b8ee-b77fa3969f0d`
- **Prompt:** “I made this challenge because I was really upset that TeamPCP dropped the ball with this payload name. Anyway, here's Wonder Wall! The password for this archive is `infected`.”
- **Assigned executable:** `/home/remnux/files/samples/day30-sha1-hulud/sha1-hulud.exe`
- **Executable size:** 632,320 bytes
- **Executable SHA-256:** `d95aca8c88d7fe5435a0c8de0d8841e8e826811ffc199c5c116966e2083ce6f4`
- **Encrypted ZIP SHA-256:** `d17ff6cd13b83a0ccad97caaffcd7c68d8d957f84479eae54fbfb88f2009e63e`
- **Archive password:** `infected` (archive password, not a challenge answer)
- **Format:** stripped 64-bit Rust PE; image base `0x140000000`; entry point `0x14007a5c4`; no PE resources or overlay were reported.

The executable SHA-1 is `527bdc9aa451adbcf1860325931854ad056a9bd9`; the ZIP SHA-1 is `08df83fcc19f4a52766b2dc8c172dd643fb1ff10`. These are file-identification values, not answers.

## Main conclusion so far

The console prompt is probably a decoy. The program prints `What is the flag?\n` and reads a line through `ReadConsoleW`. In the observed path the text was converted to UTF-8 and stored, but no comparison between that input and a fixed string was found. A test with `test-input` and another with `Wonder Wall!` followed the same observed flow. More significantly, the SHA-style routine later traced at `0x14001dfc0` receives an internal buffer (`RCX = RBP+0x7d0`, `RDX = -1`) rather than the console input pointer. This establishes that the traced integrity path hashes internal state; it does not prove that user input can never affect any other path.

The likely challenge is to understand an anti-analysis/self-integrity computation and the program's intended success condition. That condition has not been recovered. No hash guess is supported by evidence.

## Findings

### Strings and anti-analysis

A custom decoder near `0x14006397c` revealed registry, driver, and process-name checks. The decoded strings included:

```text
SOFTWARE
SYSTEM\CurrentControlSet\Services
\drivers
cheatengine
httpdebuggerpro.exe
pestudio.exe
hxd.exe
wireshark.exe
procexp.exe
tcpview.exe
autoruns.exe
scylla_x64.exe
cdb.exe
die.exe
procmon64.exe
ghidrarun.exe
scylla.exe
idaq64.exe
rehex.exe
processhacker.exe
x32dbg.exe
ida.exe
procexp64.exe
regmon.exe
ollydbg.exe
ida64.exe
procmon.exe
idaq.exe
fiddler.exe
systeminformer.exe
apimonitor
x64dbg.exe
filemon.exe
immunitydebugger.exe
windbg.exe
kd.exe
dnspy.exe
```

Other static references point to debugger/analysis detection, registry/service inspection, CPU vendor/brand strings, ACPI FACP data, `RDTSC`, thread context, `GetCurrentThreadId`, and vectored exception handling (VEH). These are clues to the anti-analysis environment and may feed integrity state; they are not themselves proof of the answer.

### Hashing and transformation routines

There are multiple routines and they should not be conflated:

- `0x140001080` was identified as a standard SHA-1 compression routine and was also called through a local C helper at `/tmp/libsha1fast.so` in a diagnostic experiment.
- `0x140010840` is a custom SHA-1-like 80-round routine with anti-analysis/self-modifying behavior around it. A C shortcut for its compression calculation is `/tmp/custom_sha1_fast.c`, compiled as `/tmp/libsha1fast.so`. It uses the state/context layout described below. Hooking this function skips surrounding native behavior and may lose side effects, flags, or volatile-register behavior.
- Other SHA-style routines were noted around `0x1400012a0` and `0x1400013d5`; earlier analysis examined them as a separate transformation stage. Do not assume these addresses are interchangeable with the two routines above.
- `0x14001dfc0` is an integrity/state transformation path called from several sites. Calls were observed from `0x140044975`, `0x140047e8e`, `0x1400480a4`, `0x1400577d6`, `0x1400582e4`, and `0x140059a4e`.

At the call from `0x140044975`, `RCX` points to `RBP+0x7d0` and `RDX` is `-1`. The routine mixes PE fields, GS/thread-related state, an INT3 address, and `R15`; copies 22 dwords from the supplied context to the stack; applies obfuscated transformations; then writes 64 generated bytes to RVA `0x1e3e8`. Those bytes are subsequently executed as self-modified code. This is the most concrete observed integrity mechanism, but its final success/failure predicate is still unknown.

At `0x14003d546`, the standard SHA-1 IV is initialized. A later pass near `0x14003d5a3` processes `[RBP+0x7d0]` with a length from `[RBP+0x6c8]`. Near `0x140041a00`, state is serialized, transformed near `0x140041a2f`, and a 64-byte block is rebuilt before a standard SHA call near `0x140041c33`. A byte comparison at `0x14003d307` (`cmp byte [rbx],0`) appears to be an empty-buffer/parser gate, not a terminal comparison with the answer.

### Custom SHA-style context

The shortcut for `0x140010840` assumes a context with five little-endian 32-bit state words at offset `+0`, a gap at `+0x14`, and sixteen little-endian 32-bit message words at `+0x18`. It computes an 80-round schedule using taps 16, 14, 9, and 3, and returns five working words; the native caller performs feed-forward. It matched blocks recorded from earlier diagnostic execution, but that only validates the arithmetic on those blocks, not the correctness of replacing the full native routine.

### Captured context and generated code

One accelerated diagnostic run reached the code-generation point around `0x14001e3e3`. The 88 bytes at `R15=0x12114b8` were captured as:

```text
0123456789abcdeffedcba9876543210f0e1d2c30000000013bef5d2b3c3261549ff540990d9c100a16e9a32c47e8fc49288010d54bda1b41f0f2e66000000842e66000000841f0f000000001f0f2e66000000842e660000
```

The prefix resembles the standard SHA-1 IV, followed by a gap and a 64-byte block. Registers at that point included:

```text
RAX=0x6af1ecfa26fb6581  RBX=0xb3d96e27c8415fab
RCX=0x1210bed           RDX=0xc3d2e1f0
RSI=0x8c47f1a52d6b93e7  RDI=0x6a1ed835c29f740b
R8 =0x14001e3e8          R9 =0x98badcfe
R10=0x6af1ecfbbdf951bd  R11=0xe22abff9daa5397d
R12=0x54a8fb91c4888f4b  R13=0xffffffffffffffff
R14=0x7e9090             R15=0x12114b8
RSP=0x1210bc0            RBP=0x090548f89841c800
```

In the long accelerated run, the generated bytes at RVA `0x1e3e8` began `7a 1b f7 c4 08 08 d9 7c ...`. Static code before the buffer performs `xor rax,r10`; the generated `7a 1b` is a short `JP` to `0x14001e405`, where `72 7a` is `JB`. With carry clear after the XOR, the path falls through to `HLT` at `0x14001e407`; Speakeasy stopped at `0x14001e408`. This is a failed/anti-analysis path in this emulation, not a flag.

## Expensive loop and what was accelerated

At `0x14004194d`, the executable runs a roughly 45-million-iteration loop over a `.text` source region. The observed parameters were approximately:

```text
source RDI = 0x140001000
source size RSI = 0x7e000
multiplier RBX = 0xf8714df9dba9a23d
iteration endpoint = 0x2aea540
```

Each iteration derives an offset from the high half of a multiply, reads an 8-byte source block (wrapping bytewise at the end), XORs it into `RCX`, multiplies/rotates/mixes the accumulator, increments `R9`, and writes 8 bytes at `[RBP+0x7d0]`. `/tmp/sha1_loop_accel.c` implements the loop and was compiled as `/tmp/libsha1loop.so`. Randomized checks and a 100-iteration emulator comparison matched the native loop. The accelerated 45-million-iteration result was `RCX=0xb41d7903e4b379aa`, with output block `cb49c1c11b4d31f1`.

This was the best-validated shortcut, but it only replaces that loop and resumes at `0x1400419c5`. It does not validate other hooks or the full emulated outcome.

## Emulation experiments and limits

The main tools were Speakeasy and local Python/C helpers. The emulator produced the prompt and then no further console output. A full run with the custom SHA shortcut and 45-million-iteration loop accelerator took about 63 seconds and halted around `RIP=0x14001e408`. The recorded final values were:

```text
RAX=0x6af1ecfa26fb6581  RBX=0xb3d96e27c8415fab
RCX=0x1210bed           RDX=0xc3d2e1f0
RSI=0x8c47f1a52d6b93e7  RDI=0x6a1ed835c29f740b
RSP=0x1210bc0            RBP=0x090548f89841c800
RIP=0x14001e408
```

The run had `first_SHA=8068`, `duplicate=8163`, and `INT3=79` events recorded. These counters are useful for comparing a reproduction, but the run is not a trustworthy final execution because multiple behaviors were stubbed or hooked.

A diagnostic skip from `0x14001e3e3` to `0x14001e428`, after capturing context, did not reveal an answer. It faulted at `0x140070452` on an invalid read from `0x7e9000` (`mov rbx,[rcx]`) in an MSVC exception-dispatch path checking exception code `0xe06d7363`. Treat this as an artifact of the forced path, not proof that the target naturally faults there.

A run without the `0x140010840` shortcut ended at Speakeasy sentinel `0xfeedf000` after about 2.34 seconds, with no useful output. It was not fully instrumented around intentional INT3/self-modification, so this is inconclusive and should not be interpreted as program behavior.

### Hooks/stubs that can invalidate the path

The diagnostic harnesses included assumptions that need to be revisited for a faithful run:

- `GetCurrentThreadId` was forced to `0x434`, with `GS:[0x48]` also set to `0x434`.
- `GetModuleHandleExW` returned the image base.
- Some VEH INT3 sites (including `0x14001e00c` and `0x14001088c`) were skipped by setting `R15` to the exception address and advancing RIP by one, based on an observed handler pattern.
- `NtReadFile` was serviced through Speakeasy's file manager with DLLs loaded from Wine.
- Rust allocation/reallocation sites at `0x14006f6c9` and `0x14005a3b1` were stubbed.
- **Especially questionable:** at `0x140065f03`, a harness set `RAX=0` and jumped to `0x140065f08`, bypassing a CALL to `0x140064323`. The target appears to be an obfuscated dynamic API resolver. This may skip relevant side effects or change the anti-analysis state. A manual continuation should resolve and model this call, not assume it returns zero.
- Replacing `0x140010840` with C code bypasses the surrounding self-modifying/anti-analysis behavior and may not preserve flags or volatile registers.

## Earlier transformation analysis (not yet connected to success)

An earlier pass modeled a transform around `0x1400013d5` over ten qwords at RVA `0x12a0`. The recorded formula was:

```text
x = RBP XOR (2 * RSI)
for each q[i]:
    x = ROR17(((x XOR q[i]) * RDI) mod 2^64)
x = x XOR (x >> 29)
x = (x OR 1) AND R13
```

For the then-captured registers (`RBP=0x090548f89841c801`, `RSI=0x8c47f1a52d6b93e7`, `RDI=0x6a1ed835c29f740b`, `R13=-1`) the derived key was `0xfd89afa81e9bb1cb`. Applying the recorded transform to a region near RVA `0x1560` produced prefix `55 06 fa d8 ee 01 90 f2 ...`, which did not decode as plausible x86 at the expected entry. Do not call this a recovered/decrypted executable; it may be the wrong source, key, or stage.

The section/file-hash guesses were also rejected: whole executable SHA-1, archive SHA-1, raw `.text` SHA-1 `d9d1c3612a3eb4b0c808636f71496837d09d5b8a`, and loaded-image `.text` padded to `0x7e000` SHA-1 `d1bca3eb58be57a840938981cf0c0fabf90dfd0e` did not validate.

## What did not work

1. **Guessing from the prompt or typing candidate phrases.** `Wonder Wall!`, `test-input`, and file/hash guesses did not produce success. The observed input path does not compare the prompt text directly.
2. **Submitting a file hash or section hash as the answer.** Rejected; these are identification data only.
3. **Skipping generated code after inspecting it.** This forced execution into an exception-dispatch fault and did not reveal the intended validation path.
4. **Treating the generated `HLT` as the answer check.** The observed bytes and emulator stop indicate an anti-analysis/failure branch, not a success result.
5. **Using only Speakeasy's default execution.** It prints the prompt and exits without useful findings; more importantly, emulator completion/termination is not proof of the target's native result.
6. **Using the C SHA hook as if it were the complete native routine.** It reproduces a compression calculation on captured blocks but bypasses important surrounding code.
7. **Running the REA/Ghidra headless decompiler.** REA was not successfully used to produce decompilation. Ghidra failed before analysis because its `java_home.save` under `/home/remnux/.config/ghidra/ghidra_12.1.4_PUBLIC/` was read-only and there was no TTY (`/tmp/ghidra_dump.log`). Do not claim this work has REA decompilation results.

No console output beyond the prompt was captured from the instrumented run. No useful `flag`, `Huntress`, `CTF{`, `Wonder`, or `Wall` strings were found in the captured emulated image. These negative observations are limited by the hooks and the captured memory regions.

## Scratch files and reproduction material

The following files were created under `/tmp`; they are scratch artifacts and may be removed by system cleanup. They are not committed tools and should be inspected before reuse:

```text
/tmp/sha1_full_dump_trace_long.py
/tmp/sha1_dump_trace.log
/tmp/sha1_full_accel5.py
/tmp/sha1_accel5.log
/tmp/sha1_loop_accel.c
/tmp/libsha1loop.so
/tmp/custom_sha1_fast.c
/tmp/libsha1fast.so
/tmp/sha1_final_capture2.py
/tmp/sha1_final_capture2.log
/tmp/sha1_native_sha.py
/tmp/sha1_native_sha.log
/tmp/sha1_native_diag.py
/tmp/sha1_native_diag.log
/tmp/sha1_skip_payload_probe.py
/tmp/sha1_skip_payload_probe.log
/tmp/sha1_skip_image.bin
/tmp/sha1_final_image.bin
/tmp/sha1_final_pc.bin
/tmp/sha1_final_regions.txt
/tmp/sha1_finalcheck.py
/tmp/sha1_finalcheck.out
/tmp/sha1_stageprobe.py
/tmp/sha1_inspect_second.py
/tmp/sha1_stagefollow120.py
/tmp/sha1_stageprobe_nativeveh.py
/tmp/sha1_disas.txt
/tmp/sha1-mainfunc.r2
/tmp/sha1_dynbytes.py
/tmp/sha1_dynveh.py
/tmp/sha1_trace.py
/tmp/ghidra_dump.log
```

Useful starting points are the trace and long-run harness, but read them first: they contain the hooks listed above. The assigned input binary is the authoritative artifact. Verify its SHA-256 before continuing:

```bash
sha256sum /home/remnux/files/samples/day30-sha1-hulud/sha1-hulud.exe
```

The exact scripts used for the latest diagnostic run were `/tmp/sha1_full_dump_trace_long.py` (with supporting helpers `/tmp/libsha1fast.so` and `/tmp/libsha1loop.so`). The context-skip probe was `/tmp/sha1_skip_payload_probe.py`. No production-ready solver was produced.

## Suggested manual continuation

These are research directions, not established answers. Preserve a clean baseline and compare every change against it.

1. **Re-run without bypassing the dynamic API resolver.** Inspect the exact call at `0x140065f03` into `0x140064323`, identify the resolved API and its outputs, then model it accurately. This is the clearest known weakness in the accelerated harness.
2. **Instrument VEH and self-modifying code instead of skipping it.** Record exception code, exception address, context register changes, handler return disposition, and bytes before/after writes. Track the 64-byte region at RVA `0x1e3e8` at every generation and execute it under a native debugger or a more faithful emulator.
3. **Compare native and emulated state at checkpoints.** If using a Windows VM, collect registers/memory at `0x1400419c5`, `0x14001dfc0`, `0x14001e3e3`, and the subsequent generated-code entry. Avoid changing more than one environmental input at a time.
4. **Determine what the 45-million-round loop is intended to bind.** The loop hashes/mixes bytes from `.text`, but the input region, loop seed, and relationship to later SHA stages need to be independently verified. Compare the output after modifying only a copy of one candidate source byte to test whether the result is a self-integrity checksum.
5. **Trace the ordinary success/failure branch.** Find the branch that awards or prints success after the generated code and exception flow. Do not infer success from the prompt, `HLT`, emulator exit, or a matching hash candidate.
6. **Revisit the earlier qword transform only after mapping its source/destination.** Confirm whether the data at RVA `0x12a0` is code, constants, or a runtime buffer, and determine which writes feed the transform. The earlier output was not valid code and may represent an incorrect stage assumption.
7. **Keep input handling in scope as a controlled variable.** Since the prompt is suspicious, compare several benign input strings while recording all reads and branches. The current evidence says the observed hash call uses internal context, but it does not prove the input is irrelevant to all code paths.

## Integrity and reporting notes

- Use only the assigned artifact for this attempt; do not reuse another team's files, flags, or artifacts.
- Keep the Game Master token out of scripts, logs, this report, and chat.
- The current status remains unsolved. Resume the existing attempt rather than starting a new one unless the Game Master instructs otherwise.
- When a genuine answer is found, submit it through the authenticated Game Master connection and record the actual response. Only mark the challenge solved if the service returns `CORRECT` (and note whether scoring is pending).
