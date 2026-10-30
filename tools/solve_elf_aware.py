#!/usr/bin/env python3
"""Extract the answer fields from an assigned ELF Aware evidence.zip.

This script only reads the downloaded ZIP and invokes readelf/objdump. It does
not execute any ELF files or make network requests. Requires binutils.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def parse_elf(data: bytes, path: Path) -> dict[str, str]:
    if data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError(f"{path.name}: unsupported ELF identification")
    bits = 32 if data[4] == 1 else 64
    endian = "<" if data[5] == 1 else ">"
    byte_order = "little" if endian == "<" else "big"
    e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
    e_entry = struct.unpack_from(endian + ("I" if bits == 32 else "Q"), data, 24)[0]

    elf_type = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(
        e_type, str(e_type)
    )
    # This is the concise architecture label used by the challenge answer field.
    machine = {
        3: "i386",
        40: "ARM",
        62: "x86-64",
        183: "AArch64",
        243: "RISC-V",
    }.get(e_machine, str(e_machine))

    ident_class = f"ELF{bits}"
    marker_match = re.search(rb"BR01-[A-Z0-9-]+", data)
    marker = marker_match.group().decode("ascii") if marker_match else "none"

    path.write_bytes(data)
    sections = run("readelf", "-SW", str(path))
    has_symtab = ".symtab" in sections
    symbols = run("readelf", "-sW", str(path))
    custom_symbols: list[str] = []
    for line in symbols.splitlines():
        match = re.search(
            r"\bFUNC\s+GLOBAL\s+DEFAULT\s+(?!UND\b)\S+\s+([A-Za-z_][A-Za-z0-9_]*)$",
            line,
        )
        if match and match.group(1) not in {
            "_edata", "_end", "_start", "main"
        }:
            custom_symbols.append(match.group(1))
    exported_symbol = next(
        (name for name in custom_symbols if name in {"recover_code", "inspect_section"}),
        custom_symbols[0] if custom_symbols else "none",
    )

    recover_code = "none"
    if exported_symbol == "recover_code":
        disassembly = run("objdump", "-d", str(path))
        match = re.search(
            r"<recover_code>:\s*\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+mov\s+\$0x([0-9a-f]+),%e?ax",
            disassembly,
        )
        if match:
            recover_code = str(int(match.group(1), 16))

    return {
        "elf_class": ident_class,
        "endianness": byte_order,
        "machine": machine,
        "elf_type": elf_type,
        "marker": marker,
        "has_symtab": str(has_symtab).lower(),
        "exported_symbol": exported_symbol,
        "recover_code": recover_code,
        "entry_point": hex(e_entry),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_zip", type=Path, help="Game Master-assigned evidence.zip")
    args = parser.parse_args()
    answer_map: dict[str, str] = {}
    with zipfile.ZipFile(args.evidence_zip) as archive, tempfile.TemporaryDirectory() as tmp:
        for slot in range(4):
            name = f"slot-{slot}.elf"
            if name not in archive.namelist():
                name = f"m-slot-{slot}.elf"
            fields = parse_elf(archive.read(name), Path(tmp) / name)
            answer_map.update({f"slot{slot}_{key}": value for key, value in fields.items()})
            print(f"{name}: {json.dumps(fields, sort_keys=True)}")
    print("\nGame Master answer map:")
    print(json.dumps(answer_map, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
