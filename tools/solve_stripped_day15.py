#!/usr/bin/env python3
"""Statically extract the public findings requested by Stripped Day 15."""

import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import zipfile
import zlib

ROOT = os.environ.get("STRIPPED_ROOT", "/home/remnux/files/samples/stripped-day15")
ARCHIVE = os.environ.get("STRIPPED_ARCHIVE", "/home/remnux/files/samples/stripped-day15-evidence.zip")
START = os.environ.get("STRIPPED_START", "/home/remnux/files/samples/stripped-day15-start.json")
OUT = os.environ.get("STRIPPED_OUT", str(__import__("pathlib").Path(__file__).resolve().parents[1] / "challenges/data/stripped_day15_answers.json"))


def u16(data, off, endian="<"):
    return struct.unpack_from(endian + "H", data, off)[0]


def u32(data, off, endian="<"):
    return struct.unpack_from(endian + "I", data, off)[0]


def read_elf(data):
    if data[:4] != b"\x7fELF":
        return None
    cls, encoding = data[4], data[5]
    endian = "<" if encoding == 1 else ">"
    if cls == 2:
        etype, machine = u16(data, 16, endian), u16(data, 18, endian)
        entry = struct.unpack_from(endian + "Q", data, 24)[0]
        shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        shentsize, shnum, shstrndx = u16(data, 58, endian), u16(data, 60, endian), u16(data, 62, endian)
        fmt = endian + "IIQQQQIIQQ"
    else:
        etype, machine = u16(data, 16, endian), u16(data, 18, endian)
        entry = u32(data, 24, endian)
        shoff = u32(data, 32, endian)
        shentsize, shnum, shstrndx = u16(data, 46, endian), u16(data, 48, endian), u16(data, 50, endian)
        fmt = endian + "IIIIIIIIII"
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        fields = struct.unpack_from(fmt, data, off)
        if cls == 2:
            name, typ, flags, addr, fileoff, size, link, info, align, entsize = fields
        else:
            name, typ, flags, addr, fileoff, size, link, info, align, entsize = fields
        sections.append({"name_off": name, "type": typ, "offset": fileoff, "size": size, "link": link, "entsize": entsize, "addr": addr})
    shstr = sections[shstrndx]
    names = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for sec in sections:
        n = sec["name_off"]
        end = names.find(b"\0", n)
        sec["name"] = names[n:end if end >= 0 else len(names)].decode("utf-8", "replace") if n else ""
    return {"class": cls, "encoding": encoding, "endian": endian, "etype": etype, "machine": machine, "entry": entry, "sections": sections}


def elf_symbols(data, elf):
    names = []
    by_name = {}
    endian = elf["endian"]
    for sec in elf["sections"]:
        if sec["type"] != 2:  # SHT_SYMTAB only
            continue
        strsec = elf["sections"][sec["link"]]
        strings = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        size = sec["entsize"] or (24 if elf["class"] == 2 else 16)
        for i in range(sec["size"] // size):
            off = sec["offset"] + i * size
            if elf["class"] == 2:
                noff, info, other, shndx, value, symsize = struct.unpack_from(endian + "IBBHQQ", data, off)
            else:
                noff, value, symsize, info, other, shndx = struct.unpack_from(endian + "IIIBBH", data, off)
            if noff:
                end = strings.find(b"\0", noff)
                name = strings[noff:end if end >= 0 else len(strings)].decode("utf-8", "replace")
                if name:
                    names.append(name)
                    by_name.setdefault(name, []).append((value, symsize, info))
    return names, by_name


def pe_info(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    peoff = u32(data, 0x3c)
    if data[peoff:peoff + 4] != b"PE\0\0":
        return None
    machine = u16(data, peoff + 4)
    nsects = u16(data, peoff + 6)
    optsz = u16(data, peoff + 20)
    opt = peoff + 24
    magic = u16(data, opt)
    dd = opt + (112 if magic == 0x20b else 96)
    cli_rva = u32(data, dd + 14 * 8) if dd + 14 * 8 + 8 <= opt + optsz else 0
    secbase = opt + optsz
    sections = []
    for i in range(nsects):
        off = secbase + 40 * i
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, va, max(vsize, rsize), roff, rsize))

    def rva_to_off(rva):
        for _, va, span, roff, rsize in sections:
            if va <= rva < va + span:
                return roff + (rva - va)
        return None

    metadata_version = None
    if cli_rva:
        cli = rva_to_off(cli_rva)
        if cli is not None and cli + 16 <= len(data):
            md_rva = u32(data, cli + 8)
            md_off = rva_to_off(md_rva)
            if md_off is not None and data[md_off:md_off + 4] == b"BSJB":
                n = u32(data, md_off + 12)
                metadata_version = data[md_off + 16:md_off + 16 + n].rstrip(b"\0").decode("ascii", "replace")
    return {
        "machine": machine,
        "managed": bool(cli_rva and metadata_version),
        "metadata_version": metadata_version,
        "sections": [x[0] for x in sections],
        "section_details": sections,
        "symbol_table_offset": u32(data, peoff + 12),
        "symbol_count": u32(data, peoff + 16),
    }


def pe_symbols(data, pe):
    """Return nonempty COFF symbol names, preserving table order."""
    base, count = pe["symbol_table_offset"], pe["symbol_count"]
    if not base or not count or base + count * 18 + 4 > len(data):
        return []
    strings_off = base + count * 18
    strings_size = u32(data, strings_off)
    strings = data[strings_off:strings_off + strings_size]
    out, i = [], 0
    while i < count:
        off = base + i * 18
        raw = data[off:off + 8]
        if raw[:4] == b"\0\0\0\0":
            name_off = u32(raw, 4)
            end = strings.find(b"\0", name_off)
            name = strings[name_off:end if end >= 0 else len(strings)].decode("utf-8", "replace") if name_off else ""
        else:
            name = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
        if name:
            out.append(name)
        i += 1 + data[off + 17]
    return out


def valid_hcfg(buf, off):
    if off < 0 or buf[off:off + 4] != b"HCFG" or off + 12 > len(buf):
        return None
    version, key = buf[off + 4], buf[off + 5]
    n = u16(buf, off + 6)
    crc = u32(buf, off + 8)
    end = off + 12 + n
    if end > len(buf):
        return None
    plain = bytes(x ^ key for x in buf[off + 12:end])
    if zlib.crc32(plain) & 0xffffffff != crc:
        return None
    try:
        config = json.loads(plain.decode("utf-8"))
    except Exception:
        return None
    return {"version": version, "key": key, "crc": crc, "config": config, "offset": off, "raw": buf[off:end]}


def find_raw_hcfg(buf, search_anywhere=True):
    start = 0
    while True:
        off = buf.find(b"HCFG", start)
        if off < 0:
            return None
        item = valid_hcfg(buf, off)
        if item:
            return item
        start = off + 1


def b64_runs(buf):
    for m in re.finditer(rb"[A-Za-z0-9+/]{100,}={0,2}", buf):
        try:
            decoded = base64.b64decode(m.group(0), validate=True)
        except Exception:
            continue
        yield m.start(), decoded


def find_b64_hcfg(buf, prefix_only=False):
    for off, dec in b64_runs(buf):
        if prefix_only:
            x = valid_hcfg(dec, 0)
            if x:
                x["offset"] = off
                return x
        else:
            x = find_raw_hcfg(dec)
            if x:
                x["offset"] = off
                return x
    return None


def class_utf8_constants(class_bytes):
    if class_bytes[:4] != b"\xca\xfe\xba\xbe":
        return []
    count = u16(class_bytes, 8, ">")
    pos, out, i = 10, [], 1
    while i < count:
        tag = class_bytes[pos]
        pos += 1
        if tag == 1:
            n = u16(class_bytes, pos, ">"); pos += 2
            out.append(class_bytes[pos:pos + n].decode("utf-8", "replace")); pos += n
        elif tag in (3, 4): pos += 4
        elif tag in (5, 6): pos += 8; i += 1
        elif tag in (7, 8, 16, 19, 20): pos += 2
        elif tag in (9, 10, 11, 12, 17, 18): pos += 4
        elif tag == 15: pos += 3
        else: raise ValueError(f"unknown class constant tag {tag}")
        i += 1
    return out


def hcfg_from_jar(path):
    with zipfile.ZipFile(path) as jar:
        manifest = jar.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        main = re.search(r"(?im)^Main-Class:\s*([^\r\n]+)", manifest).group(1).strip()
        classfile = main.replace(".", "/") + ".class"
        constants = class_utf8_constants(jar.read(classfile))
        for text in constants:
            for m in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", text):
                try: decoded = base64.b64decode(m.group(0), validate=True)
                except Exception: continue
                x = valid_hcfg(decoded, 0)
                if x: return x
        raise ValueError(f"no valid HCFG constant in Main-Class {main}")


def get_file(day, ending=None):
    pref = f"d{day:02}--"
    files = sorted(x for x in os.listdir(ROOT) if x.startswith(pref))
    if ending:
        files = [x for x in files if x.endswith(ending)]
    if len(files) != 1:
        raise ValueError((day, ending, files))
    p = os.path.join(ROOT, files[0])
    return files[0], open(p, "rb").read()


def machine_arch(machine):
    return {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}.get(machine, str(machine))


with zipfile.ZipFile(ARCHIVE) as zf:
    # Outer archive uses WinZip AES; use 7-Zip's central-directory listing for order.
    listing = subprocess.check_output(["7z", "l", "-slt", ARCHIVE], text=True)
    order = []
    for block in listing.split("\n\n"):
        m = re.search(r"(?m)^Path = (d\d\d--[^\n]+)$", block)
        if m: order.append(m.group(1))

start = json.load(open(START))
answers = {}
days = {}
for day in range(1, 16):
    members = [n for n in order if os.path.basename(n).startswith(f"d{day:02}--")]
    if not members:
        raise ValueError(f"no central-directory members for day {day}")
    paths = {os.path.basename(n): os.path.join(ROOT, os.path.basename(n)) for n in members}
    datas = {name: open(path, "rb").read() for name, path in paths.items()}
    first_name = os.path.basename(members[0])
    first = datas[first_name]
    elf = read_elf(first)
    pe = pe_info(first)
    if first.startswith(b"PK\x03\x04"):
        fmt = "jar"
    elif first.startswith(b"\x7fELF"):
        fmt = "elf"
    elif pe:
        fmt = "pe_cli" if pe["managed"] else "pe"
    elif first.startswith(b"\0asm"):
        fmt = "wasm"
    elif first.startswith(b"NEKO"):
        fmt = "neko_bytecode"
    else:
        fmt = "unknown"
    record = None
    if day == 2:
        if elf:
            sec = next(s for s in elf["sections"] if s["name"] == ".hcfg")
            config_offset = sec["offset"]
        elif pe:
            sec = next(s for s in pe["section_details"] if s[0] == ".hcfg")
            config_offset = sec[3]
        else:
            raise ValueError("Day 2 specimen is neither ELF nor PE")
        record = valid_hcfg(first, config_offset)
    elif day == 3:
        record = find_raw_hcfg(first)
    elif day in (4, 5, 10, 12, 14, 15):
        if day == 15:
            stripped_name, stripped_data = get_file(15, "stripped.elf")
            record = find_raw_hcfg(stripped_data)
        else:
            record = find_raw_hcfg(first)
    elif day == 6 or day == 7:
        record = hcfg_from_jar(paths[first_name])
    elif day == 8:
        record = find_raw_hcfg(first) or find_b64_hcfg(first)
    elif day in (9, 11, 13):
        record = find_b64_hcfg(first, prefix_only=True)
    if day == 15:
        symbol_name, symbol_data = get_file(15, "symbolized.elf")
        symbol_elf = read_elf(symbol_data)
    if record:
        config = record["config"]
    else:
        config = {}
    days[day] = {"members": members, "first": first_name, "data": first, "elf": elf, "pe": pe, "format": fmt, "record": record, "config": config, "paths": paths, "datas": datas}

    # Member hashes, in the order specified by the question.
    for i, n in enumerate(members, 1):
        answers[f"d{day:02}_artifact_sha256_{i}"] = hashlib.sha256(datas[os.path.basename(n)]).hexdigest()
    for q in [q for q in start["questions"] if q["id"].startswith(f"d{day:02}_")]:
        qid = q["id"]
        if qid in answers:
            continue
        key = qid.removeprefix(f"d{day:02}_analysis_")
        if key == "elf_class":
            bits = 32 if elf["class"] == 1 else 64
            answers[qid] = f"ELF{bits}" if day == 1 else str(bits)
        elif key == "machine": answers[qid] = str((elf or {}).get("machine", (pe or {}).get("machine")))
        elif key == "architecture": answers[qid] = machine_arch((elf or {}).get("machine", (pe or {}).get("machine")))
        elif key in ("format", "stripped_format", "symbolized_format"):
            if day == 15:
                dat = stripped_data if "stripped" in key else symbol_data
                answers[qid] = "elf" if dat.startswith(b"\x7fELF") else "pe" if pe_info(dat) else "wasm" if dat.startswith(b"\0asm") else "jar" if dat.startswith(b"PK\x03\x04") else "neko_bytecode" if dat.startswith(b"NEKO") else "unknown"
            elif day == 3: answers[qid] = "pe_cli" if pe and pe["managed"] else fmt
            else: answers[qid] = fmt
        elif key == "elf_type": answers[qid] = {1:"ET_REL",2:"ET_EXEC",3:"ET_DYN",4:"ET_CORE"}.get(elf["etype"], str(elf["etype"]))
        elif key == "endianness": answers[qid] = "little endian" if elf["encoding"] == 1 else "big endian"
        elif key == "entry_point": answers[qid] = hex(elf["entry"])
        elif key == "section_names": answers[qid] = json.dumps([s["name"] for s in elf["sections"]], separators=(",", ":"))
        elif key == "symbols": answers[qid] = json.dumps(elf_symbols(first, elf)[0], separators=(",", ":"))
        elif key == "has_symtab": answers[qid] = str(any(s["name"] == ".symtab" for s in elf["sections"])).lower()
        elif key == "disassembly":
            names, syms = elf_symbols(first, elf)
            if "recover_code" not in syms: answers[qid] = "[]"
            else:
                out = subprocess.check_output(["objdump", "-d", "-M", "intel", "--disassemble=recover_code", paths[first_name]], text=True)
                ins = []
                for line in out.splitlines():
                    m = re.match(r"\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9.]*(?:\s+.*)?)\s*$", line)
                    if m: ins.append(" ".join(m.group(1).split()))
                answers[qid] = json.dumps(ins, separators=(",", ":"))
        elif key == "has_cpp_typeinfo":
            names = elf_symbols(first, elf)[0] if elf else pe_symbols(first, pe); answers[qid] = str(any(re.search(r"ZTI.*DiscoveryEngine", n) for n in names)).lower()
        elif key == "has_cpp_vtable":
            names = elf_symbols(first, elf)[0] if elf else pe_symbols(first, pe); answers[qid] = str(any(re.search(r"ZTV.*DiscoveryEngine", n) for n in names)).lower()
        elif key == "metadata_version": answers[qid] = (pe or {}).get("metadata_version")
        elif key.startswith("config_"):
            field = key.removeprefix("config_")
            if field in ("campaign", "domain", "mutex", "url"): answers[qid] = config.get(field)
            elif field == "crc32_hex": answers[qid] = f"0x{record['crc']:08x}"
        elif key.startswith("stripped_config_"):
            field = key.removeprefix("stripped_config_")
            if field in ("campaign", "domain"): answers[qid] = config.get(field)
        elif key == "hcfg_version": answers[qid] = record["version"]
        elif key == "xor_key_hex": answers[qid] = f"0x{record['key']:02x}"
        elif key == "compression_methods":
            with zipfile.ZipFile(paths[first_name]) as jar:
                answers[qid] = json.dumps(sorted({i.compress_type for i in jar.infolist()}), separators=(",", ":"))
        elif key == "hcfg_offset": answers[qid] = record["offset"]
        elif key == "has_hcfg_section":
            names = (
                [s["name"] for s in elf["sections"]]
                if elf
                else list((pe or {}).get("sections", []))
            )
            if day == 10: val = any("hcfg" in n for n in names)
            elif day == 14: val = ".hcfg" in names
            else: val = False
            answers[qid] = str(val).lower()
        elif key == "stripped_architecture": answers[qid] = "x86-64" if read_elf(stripped_data)["machine"] == 62 else "wasm32"
        elif key == "symbolized_architecture": answers[qid] = "x86-64" if symbol_elf["machine"] == 62 else "wasm32"
        elif key == "stripped_machine": answers[qid] = str(read_elf(stripped_data)["machine"])
        elif key == "symbolized_machine": answers[qid] = str(symbol_elf["machine"])

missing = [q["id"] for q in start["questions"] if q["id"] not in answers or answers[q["id"]] is None]
if missing:
    raise SystemExit("MISSING: " + ", ".join(missing))
answers = {k: str(v) for k, v in answers.items()}
outpath = OUT
json.dump(answers, open(outpath, "w"), indent=2)
print("answers", len(answers), "saved", outpath)
for d, data in days.items():
    print(f"d{d:02}", data["first"], "format", data["format"], "machine", (data["elf"] or {}).get("machine", (data["pe"] or {}).get("machine")), "hcfg", data["config"].get("campaign"), "offset", (data["record"] or {}).get("offset"))
print("D01 disassembly", answers["d01_analysis_disassembly"])
print("D15", answers["d15_analysis_stripped_format"], answers["d15_analysis_stripped_machine"], answers["d15_analysis_symbolized_format"], answers["d15_analysis_symbolized_machine"])
