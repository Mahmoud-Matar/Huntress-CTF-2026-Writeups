#!/usr/bin/env python3
"""Extract the metadata answers from Day 22 Main Character Energy evidence sets."""

from __future__ import annotations

import email
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


def command(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()


def exif(file: Path, tag: str) -> str:
    return command("exiftool", "-s3", f"-{tag}", str(file))


def apk_package(file: Path) -> str:
    """Read the package attribute from Android's binary AndroidManifest.xml."""
    data = zipfile.ZipFile(file).read("AndroidManifest.xml")

    def u16(offset: int) -> int:
        return struct.unpack_from("<H", data, offset)[0]

    def u32(offset: int) -> int:
        return struct.unpack_from("<I", data, offset)[0]

    strings: list[str] = []
    offset = 8
    while offset < len(data):
        chunk_type, header_size, chunk_size = u16(offset), u16(offset + 2), u32(offset + 4)
        if chunk_type == 1:  # ResStringPool
            count, flags, strings_start = u32(offset + 8), u32(offset + 16), u32(offset + 20)
            utf8 = bool(flags & 0x100)
            starts = [u32(offset + header_size + 4 * i) for i in range(count)]

            def length8(pos: int) -> tuple[int, int]:
                first = data[pos]
                if first & 0x80:
                    return ((first & 0x7F) << 8) | data[pos + 1], pos + 2
                return first, pos + 1

            def length16(pos: int) -> tuple[int, int]:
                first = u16(pos)
                if first & 0x8000:
                    return ((first & 0x7FFF) << 16) | u16(pos + 2), pos + 4
                return first, pos + 2

            for relative in starts:
                pos = offset + strings_start + relative
                if utf8:
                    _, pos = length8(pos)
                    length, pos = length8(pos)
                    strings.append(data[pos : pos + length].decode("utf-8"))
                else:
                    length, pos = length16(pos)
                    strings.append(data[pos : pos + 2 * length].decode("utf-16le"))
        elif chunk_type == 0x0102:  # START_TAG
            name_index = u32(offset + 20)
            element = strings[name_index] if name_index < len(strings) else ""
            if element == "manifest":
                attribute_start, attribute_size = u16(offset + 24), u16(offset + 26)
                attribute_count = u16(offset + 28)
                pos = offset + 16 + attribute_start
                for _ in range(attribute_count):
                    name_index, raw_index = u32(pos + 4), u32(pos + 8)
                    value_type, value_data = data[pos + 15], u32(pos + 16)
                    name = strings[name_index]
                    if name == "package":
                        if raw_index != 0xFFFFFFFF:
                            return strings[raw_index]
                        if value_type == 3:
                            return strings[value_data]
                        raise ValueError("package attribute is not a string")
                    pos += attribute_size
        offset += chunk_size
    raise ValueError("manifest has no package attribute")


def pe_fields(file: Path) -> tuple[str, str, str]:
    raw = file.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    machine = struct.unpack_from("<H", raw, pe + 4)[0]
    optional = pe + 24
    entry_rva = struct.unpack_from("<I", raw, optional + 16)[0]
    original = exif(file, "OriginalFileName")
    return f"0x{machine:04x}", f"0x{entry_rva:08x}", original


def wav_codec(file: Path) -> str:
    raw = file.read_bytes()
    offset = 12
    while offset + 8 <= len(raw):
        name = raw[offset : offset + 4]
        size = struct.unpack_from("<I", raw, offset + 4)[0]
        if name == b"fmt ":
            fmt, channels, rate, byte_rate, align, bits = struct.unpack_from("<HHIIHH", raw, offset + 8)
            if fmt == 1:
                return "pcm_u8" if bits == 8 else f"pcm_s{bits}le"
            if fmt == 3:
                return f"pcm_f{bits}le"
            return f"format_{fmt}"
        offset += 8 + size + (size & 1)
    raise ValueError("WAV has no fmt chunk")


def macho_cpu(file: Path) -> str:
    raw = file.read_bytes()
    magic = raw[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        cpu = struct.unpack_from("<I", raw, 4)[0]
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        cpu = struct.unpack_from(">I", raw, 4)[0]
    else:
        raise ValueError(f"Unsupported Mach-O magic: {magic.hex()}")
    return json.dumps([f"0x{cpu:08x}"], separators=(",", ":"))


def one_set(root: Path) -> dict[str, str]:
    note = (root / "evidence-note.txt").read_bytes()
    copy = (root / "evidence-note-copy.txt").read_bytes()
    roster = (root / "roster.csv").read_bytes()
    inner_names = zipfile.ZipFile(root / "evidence-drop-001.zip").namelist()
    pe_machine, pe_entry, pe_original = pe_fields(root / "telemetry-agent-001.exe")
    mvid_out = command("monodis", "--module", str(root / "managed-001.dll"))
    mvid_match = re.search(r"\{([0-9A-Fa-f-]{36})\}", mvid_out)
    if not mvid_match:
        raise ValueError("Could not find .NET module MVID")
    property_table = command("msiinfo", "export", str(root / "installer-001.msi"), "Property")
    product_match = re.search(r"(?m)^ProductCode\t(\{[0-9A-Fa-f-]{36}\})$", property_table)
    if not product_match:
        raise ValueError("Could not find MSI ProductCode")
    lnk_target = exif(root / "shortcut-001.lnk", "LocalBasePath")
    rel_targets: list[tuple[str, str]] = []
    with zipfile.ZipFile(root / "document-15-001.docx") as docx:
        for name in docx.namelist():
            if not name.endswith(".rels"):
                continue
            xml = ET.fromstring(docx.read(name))
            for rel in xml:
                if rel.attrib.get("TargetMode") == "External":
                    rel_targets.append((rel.attrib.get("Id", ""), rel.attrib["Target"]))
    rel_targets.sort()
    eml = email.message_from_bytes((root / "message-001.eml").read_bytes())
    wav = wav_codec(root / "audio-001.wav")
    video_w, video_h = exif(root / "video-001.mp4", "ImageWidth"), exif(root / "video-001.mp4", "ImageHeight")
    jpeg_w, jpeg_h = exif(root / "camera-001.jpg", "ImageWidth"), exif(root / "camera-001.jpg", "ImageHeight")
    png_raw = (root / "panel-001.png").read_bytes()
    png_w, png_h = struct.unpack_from(">II", png_raw, 16)
    pdf_ver = re.match(rb"%PDF-([0-9.]+)", (root / "document-001.pdf").read_bytes()).group(1).decode()
    elf_machine = struct.unpack_from("<H", (root / "collector-001.elf").read_bytes(), 18)[0]
    apk = apk_package(root / "mobile-001.apk")
    jar_manifest = zipfile.ZipFile(root / "application-001.jar").read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
    jar_match = re.search(r"(?mi)^Main-Class:\s*(\S+)\s*$", jar_manifest)
    if not jar_match:
        jar_main = "none"
    else:
        jar_main = jar_match.group(1)
    synthesis_files = ["evidence-note.txt", "panel-001.png", "installer-001.msi", "audio-001.wav", "application-001.jar"]
    synthesis = sorted((hashlib.sha256((root / n).read_bytes()).hexdigest(), n) for n in synthesis_files)
    note_magic = note[:16].hex()
    roster_magic = roster[:16].hex()
    values = {
        "roster-filename": "roster.csv",
        "evidence-note-filename": "evidence-note.txt",
        "evidence-note-copy-filename": "evidence-note-copy.txt",
        "roster-size-bytes": str(len(roster)),
        "evidence-note-size-bytes": str(len(note)),
        "evidence-note-copy-size-bytes": str(len(copy)),
        "evidence-note-copy-md5": hashlib.md5(copy).hexdigest(),
        "roster-sha1": hashlib.sha1(roster).hexdigest(),
        "evidence-note-sha256": hashlib.sha256(note).hexdigest(),
        "roster-magic-prefix-hex-16": roster_magic,
        "evidence-note-magic-prefix-hex-16": note_magic,
        "evidence-note-text-utf8-bom-present": str(note.startswith(b"\xef\xbb\xbf")).lower(),
        "d04-jpeg-001-jpeg-sof-dimensions-pixels": f"{jpeg_w}x{jpeg_h}",
        "d05-png-001-png-ihdr-dimensions-pixels": f"{png_w}x{png_h}",
        "d06-pdf-001-pdf-header-version": pdf_ver,
        "d07-zip-001-zip-eocd-total-entries": str(len(inner_names)),
        "d07-zip-001-zip-central-directory-member-names": json.dumps(inner_names, separators=(",", ":")),
        "d09-pe-001-pe-coff-machine-u16-hex": pe_machine,
        "d09-pe-001-pe-address-of-entry-point-rva-hex": pe_entry,
        "d09-pe-001-pe-version-original-filename": pe_original,
        "d12-dotnet-001-dotnet-mvid-guid": mvid_match.group(1).lower(),
        "d13-msi-001-msi-product-code-guid": product_match.group(1),
        "d14-lnk-001-lnk-target-path-windows": lnk_target,
        "d15-ooxml-001-ooxml-external-relationship-targets": json.dumps([v for _, v in rel_targets], separators=(",", ":")),
        "d16-email-001-email-message-id": eml.get("Message-ID", "none"),
        "d17-audio-001-media-primary-audio-codec-name": wav,
        "d18-video-001-media-primary-video-dimensions": f"{video_w}x{video_h}",
        "d19-elf-001-elf-e-machine-u16-hex": f"0x{elf_machine:04x}",
        "d20-macho-001-macho-cpu-type-set": macho_cpu(root / "macos-001.bin"),
        "d21-apk-001-apk-package-name": apk,
        "d22-jar-001-jar-main-class": jar_main,
        "metadata-day-22-synthesis-sha256-order": json.dumps([n for _, n in synthesis], separators=(",", ":")),
    }
    return values


def main() -> None:
    base = Path("/tmp/main-character-energy-mastery")
    result: dict[str, str] = {}
    for i in range(1, 7):
        evidence = base / f"evidence-{i:02}.zip"
        root = base / f"set{i}"
        root.mkdir(exist_ok=True)
        with zipfile.ZipFile(evidence) as archive:
            archive.extractall(root)
        values = one_set(root)
        for key, value in values.items():
            result[f"set{i}.{key}"] = value
    out = base / "answers.json"
    out.write_text(json.dumps(result, separators=(",", ":")))
    print(json.dumps({"sets": 6, "answers": len(result), "answer_file": str(out), "sample": {k: result[k] for k in list(result)[:10]}}, separators=(",", ":")))


if __name__ == "__main__":
    main()
