#!/usr/bin/env python3
"""Statically recover Fetch Quest Day 17 fixture descriptors and answer fields."""

from __future__ import annotations

import ast
import base64
import json
import pathlib
import re
import ast
import urllib.parse
import zipfile


ROOT = pathlib.Path("/home/remnux/files/samples/fetch-quest-day17")
START = pathlib.Path(__file__).resolve().parents[1] / "challenges/data/fetch-quest-day17-start.json"
ARCHIVE = pathlib.Path("/home/remnux/files/samples/fetch-quest-day17-evidence.zip")
OUT = pathlib.Path(__file__).resolve().parents[1] / "challenges/data/fetch_quest_day17_answers.json"


def parse_codec_source(text: str) -> tuple[str | None, str | None]:
    # Read concatenated base64 literals as inert text. Several Python fixtures
    # split one material value across adjacent strings.
    codec = re.search(r"(?im)^\s*(?:(?:readonly|const|let|var)\s+)?(?:CODEC|Codec|codec)[_A-Za-z0-9]*\s*=\s*['\"]([^'\"]*)", text)
    grouped = re.search(r"(?ims)^\s*(?:(?:readonly|const|let|var)\s+)?(?:MATERIAL|Material|material)[_A-Za-z0-9]*\s*=\s*\((.*?)\)", text)
    if codec and grouped:
        chunks = re.findall(r"['\"]([^'\"]*)['\"]", grouped.group(1))
        if chunks:
            return codec.group(1), "".join(chunks)
    codec = re.search(r"(?im)^\s*(?:(?:readonly|const|let|var)\s+)?(?:CODEC|Codec|codec)[_A-Za-z0-9]*\s*=\s*['\"]([^'\"]*)", text)
    material = re.search(r"(?im)^\s*(?:(?:readonly|const|let|var)\s+)?(?:MATERIAL|Material|material)[_A-Za-z0-9]*\s*=\s*(.+?)\s*$", text)
    if codec and material:
        raw = material.group(1).strip().rstrip(";").strip()
        # Python bytes literals and numeric tuple/list carriers are parsed as data only.
        try:
            value = ast.literal_eval(raw)
            if isinstance(value, bytes):
                return codec.group(1), value
            if isinstance(value, (tuple, list)) and all(isinstance(x, int) for x in value):
                return codec.group(1), bytes(value)
            if isinstance(value, str):
                return codec.group(1), value
        except (SyntaxError, ValueError):
            pass
        return codec.group(1), raw.strip("'\"")
    # Batch fixtures publish the same static carrier and codec in inert comments.
    cm = re.search(r"(?im)^\s*(?:rem|#)\s*HUNTRESS-CODEC:\s*([^\r\n]+)", text)
    mm = re.search(r"(?im)^\s*(?:rem|#)\s*HUNTRESS-MATERIAL:\s*([^\r\n]+)", text)
    if cm and mm:
        return cm.group(1).strip(), mm.group(1).strip()
    return None, None


def decode_material(codec_text: str, material: str | bytes) -> bytes:
    parts = codec_text.split("|")
    carrier = parts[0]
    transform = parts[1] if len(parts) > 1 else "identity"
    key_text = parts[2] if len(parts) > 2 else ""
    if carrier == "xor_hex" and len(parts) == 2:
        transform, key_text = "single_byte_xor", parts[1]
    if isinstance(material, bytes):
        data = material
        if carrier == "reversed_integer_list": data = data[::-1]
    elif carrier in ("base64_literal", "base64_chunks", "urlsafe_base64", "reversed_base64", "split_fragments"):
        source = material[::-1] if carrier == "reversed_base64" else material
        data = (base64.urlsafe_b64decode if carrier == "urlsafe_base64" else base64.b64decode)(source)
    elif carrier == "reversed_text":
        source = material[::-1].lstrip("=")
        data = base64.b64decode(source + "=" * (-len(source) % 4))
    elif carrier in ("hex_dash", "hex_colon", "hex_pairs", "hex_literal", "hex_buffer", "reversed_hex", "xor_hex"):
        data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", material))
        if carrier == "reversed_hex":
            data = data[::-1]
    elif carrier == "hex_compact":
        data = bytes.fromhex(material)
    elif carrier in ("hex_escape", "escaped_octets"):
        data = bytes(int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", material))
    elif carrier == "unicode_escapes":
        data = bytes(int(x, 16) for x in re.findall(r"\\u00([0-9a-fA-F]{2})", material))
    elif carrier == "percent_hex":
        data = urllib.parse.unquote_to_bytes(material)
    elif carrier in ("decimal_csv", "decimal_comma", "decimal_colon", "decimal_bytes", "decimal_dash", "decimal_pipe", "decimal_space", "reversed_decimal"):
        sep = "," if carrier in ("decimal_csv", "decimal_comma", "reversed_decimal") else "." if carrier == "decimal_bytes" else "-" if carrier == "decimal_dash" else "|" if carrier == "decimal_pipe" else " " if carrier == "decimal_space" else ":"
        data = bytes(int(x) & 0xFF for x in material.split(sep) if x)
        if carrier == "reversed_decimal":
            data = data[::-1]
    elif carrier in ("integer_tuple", "json_numbers", "decimal_array", "hex_array"):
        value = json.loads(material) if carrier in ("json_numbers", "decimal_array", "hex_array") else ast.literal_eval(material)
        if carrier == "hex_array":
            data = bytes(int(x, 16) for x in value)
        else:
            data = bytes(value)
    elif carrier == "reversed_integer_list":
        try:
            vals = ast.literal_eval(material)
            data = bytes(reversed(vals))
        except (SyntaxError, ValueError):
            data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", material))
    else:
        raise ValueError(f"unsupported carrier {carrier}")

    if transform in ("", "identity"):
        pass
    elif transform in ("single_byte_xor", "xor_hex"):
        key = int(key_text or "0", 16)
        data = bytes(b ^ key for b in data)
    elif transform == "xor_5a":
        data = bytes(b ^ 0x5A for b in data)
    elif transform in ("repeating_key_xor",):
        keys = bytes(int(k, 16) for k in key_text.split(","))
        data = bytes(b ^ keys[i % len(keys)] for i, b in enumerate(data))
    elif transform == "rolling_xor":
        prior = int(key_text or "0", 16)
        decoded = []
        for b in data:
            decoded.append(b ^ prior)
            prior = b
        data = bytes(decoded)
    elif transform == "reverse_bytes":
        data = data[::-1]
    elif transform == "reverse_then_xor":
        key = int(key_text or "0", 16)
        data = bytes(b ^ key for b in data[::-1])
    elif transform in ("reverse_xor", "split_fragments_reverse_xor"):
        data = bytes(b ^ 0x5A for b in data[::-1])
    elif transform == "subtract_modulo_256":
        key = int(key_text or "0", 16)
        data = bytes((b + key) & 0xFF for b in data)
    elif transform == "add_modulo_256":
        key = int(key_text or "0", 16)
        data = bytes((b - key) & 0xFF for b in data)
    elif transform == "rotate_left":
        data = bytes(((b << 1) | (b >> 7)) & 0xFF for b in data)
    elif transform == "rotate_right":
        data = bytes(((b >> 1) | (b << 7)) & 0xFF for b in data)
    else:
        raise ValueError(f"unsupported transform {transform}")
    return data


def decode_lyr(chain: str, payload: str) -> str:
    value = payload
    for op in reversed(chain.split("_")):
        if op == "frag": value = value.replace(".", "")
        elif op == "rev": value = value[::-1]
        elif op == "hex": value = bytes.fromhex(value.replace(".", "")).decode("ascii")
        elif op == "b64": value = base64.b64decode(value + "=" * (-len(value) % 4)).decode("ascii")
        elif op == "b32": value = base64.b32decode(value.upper() + "=" * (-len(value) % 8)).decode("ascii")
        else: raise ValueError(f"unknown LYR layer {op}")
    return value


def static_descriptor(path: pathlib.Path) -> tuple[str | None, dict[str, str]]:
    text = path.read_text(errors="replace")
    # Day 23 composite fixtures layer text encodings; the marker lists the
    # encoding chain from the original descriptor outward, so decode in reverse.
    lyr = re.search(r"HUNTRESS_ANALYSIS_V1:LYR-([a-z0-9_]+)-([A-Za-z0-9+/=._-]+)", text)
    if lyr:
        import itertools
        ops, payload = lyr.group(1).split("_"), lyr.group(2)
        try:
            plain = decode_lyr(lyr.group(1), lyr.group(2))
            if plain.startswith("v=") or plain.startswith("{"):
                try:
                    obj = json.loads(plain)
                    fields = {k:(">".join(v) if isinstance(v,list) else str(v)) for k,v in obj.items()}
                except json.JSONDecodeError:
                    fields = dict(item.split("=",1) for item in plain.split("|") if "=" in item)
                if fields:
                    if "stageCount" in fields: fields["stage_count"] = fields["stageCount"]
                    return plain, fields
        except (ValueError, UnicodeDecodeError):
            pass
    if "HUNTRESS_ANALYSIS_V1:SPLIT" in text:
        block = re.search(r"(?is)HUNTRESS_ANALYSIS_V1_SPLIT[_A-Za-z0-9]*\s*=\s*\[(.*?)\]", text)
        chunks = re.findall(r"['\"]([^'\"]+)['\"]", block.group(1)) if block else []
        lyr = re.match(r"LYR-([a-z0-9_]+)-(.*)", chunks[0]) if chunks else None
        if lyr:
            payload = lyr.group(2) + "".join(chunks[1:])
            plain = decode_lyr(lyr.group(1), payload)
            return plain, dict(item.split("=", 1) for item in plain.split("|") if "=" in item)
        tag = re.match(r"(B64|HB64|HEX|FRAG)-(.*)", chunks[0]) if chunks else None
        if chunks and tag:
            payload = tag.group(2) + "".join(chunks[1:])
            if tag.group(1) == "B64":
                raw = base64.b64decode(payload)
            elif tag.group(1) == "HB64":
                raw = base64.b64decode(bytes.fromhex(payload).decode("ascii"))
            else:
                raw = bytes.fromhex(payload.replace(".", ""))
            plain = raw.decode("utf-8", "strict")
            return plain, dict(item.split("=", 1) for item in plain.split("|") if "=" in item)
    marker = re.search(r"HUNTRESS_ANALYSIS_V1:(HEX|B64|HB64|FRAG)-([A-Za-z0-9+/=_\-.]+)", text)
    if marker:
        kind, payload = marker.group(1), marker.group(2)
        if kind in ("HEX", "FRAG"):
            raw = bytes.fromhex(payload.replace(".", ""))
        elif kind == "HB64":
            raw = base64.b64decode(bytes.fromhex(payload).decode("ascii"))
        elif kind == "FRAG":
            raw = bytes.fromhex(payload.replace(".", ""))
        else:
            raw = base64.b64decode(payload)
        plain = raw.decode("utf-8", "strict")
        return plain, dict(item.split("=", 1) for item in plain.split("|") if "=" in item)
    # PowerShell samples store JSON as a literal base64 string and reconstruct it
    # through a small function; decode the documented static payload directly.
    ps = re.search(r"FromBase64String\('([^']+)'\)", text, re.I)
    if ps:
        try:
            plain = base64.b64decode(ps.group(1)).decode("utf-8")
            obj=json.loads(plain)
            fields={k:(">".join(v) if isinstance(v,list) else str(v)) for k,v in obj.items()}
            return plain, fields
        except Exception:
            pass
    if path.suffix.lower() in (".bat", ".cmd"):
        fragments = re.findall(r'(?im)^\s*set\s+"?([a-z_]+?)(\d+)=([^"\r\n]*)', text)
        if fragments:
            # Group only fragments sharing the same variable stem, not the final
            # concatenation/output variable which can itself have a numeric suffix.
            stems={stem.lower() for stem,_,_ in fragments}
            stem=max(stems,key=lambda x:sum(1 for a,_,_ in fragments if a.lower()==x))
            pieces=[(int(n),v) for s,n,v in fragments if s.lower()==stem and int(n)!=9]
            assembled = "".join(v.replace("^|", "|") for _, v in sorted(pieces))
            if "=" in assembled and "|" in assembled:
                return assembled, dict(item.split("=", 1) for item in assembled.split("|") if "=" in item)
    if path.name == "invoke-python-stage.ps1" or "$HandoffId" in text:
        fields={}
        for key,pat in (("handoff_id",r"\$HandoffId\s*=\s*'([^']+)'") ,("next_stage",r"\$NextStage\s*=\s*'([^']+)'") ,("interpreter",r"\$Interpreter\s*=\s*'([^']+)'") ,("adapter",r"Adapter\s*=\s*'([^']+)'") ):
            m=re.search(pat,text,re.I)
            if m: fields[key]=m.group(1)
        if fields: return "|".join(f"{k}={v}" for k,v in fields.items()),fields
    codec, material = parse_codec_source(text)
    if codec and material is not None:
        raw = decode_material(codec, material)
        plain = raw.decode("utf-8", "strict")
        fields = dict(item.split("=", 1) for item in plain.split("|") if "=" in item)
        if fields or path.suffix.lower() not in (".js", ".mjs"):
            return plain, fields
    if path.suffix.lower() in (".js", ".mjs"):
        return js_descriptor(path)
    return None, {}


def js_descriptor(path: pathlib.Path) -> tuple[str | None, dict[str, str]]:
    text = path.read_text(errors="replace")
    # Older JScript fixtures carry a literal byte array (or two concatenated
    # arrays) and a tiny identity/reverse decoder. Recover those constants
    # directly instead of evaluating the script.
    arrs = []
    for variable in ("s", "item1", "item2", "firstPart", "secondPart", "characters", "SoUrCeByTeS", "v_a19c"):
        m = re.search(rf"(?im)\b{variable}\s*=\s*\[([^\]]+)\]", text)
        if m:
            arrs.append((variable, bytes(int(x, 0) & 255 for x in re.findall(r"0x[0-9a-f]+|\d+", m.group(1), re.I))))
    raw = None
    if arrs:
        lookup = dict(arrs)
        if "firstPart" in lookup and "secondPart" in lookup:
            raw = lookup["firstPart"] + lookup["secondPart"]
        elif "s" in lookup:
            raw = lookup["s"]
        elif "item1" in lookup:
            raw = lookup["item1"]
        elif "characters" in lookup:
            raw = lookup["characters"]
        elif "SoUrCeByTeS" in lookup:
            raw = lookup["SoUrCeByTeS"]
        elif "v_a19c" in lookup:
            raw = lookup["v_a19c"]
        if raw is not None:
            recover = re.search(r"(?is)(?:function\s+recover_[^(]+|recover_[A-Za-z0-9_]+\s*=\s*function[^\(]*)\([^)]*\)\s*\{(.*?)(?:\n\s*};?|\n\s*})", text)
            decoder = re.search(r"(?is)(?:function\s+decode_[^(]+|decode_[A-Za-z0-9_]+\s*=\s*function[^\(]*)\([^)]*\)\s*\{(.*?)(?:\n\s*};?|\n\s*})", text)
            code = decoder.group(1) if decoder else ""
            if recover and re.search(r"\.reverse\s*\(\s*\)", recover.group(1)):
                raw = raw[::-1]
            if re.search(r"\.reverse\s*\(\s*\)", code):
                raw = raw[::-1]
            key = re.search(r"keyBytes\s*=\s*\[([^\]]+)\]", code)
            if key:
                keys = [int(x, 0) for x in re.findall(r"0x[0-9a-f]+|\d+", key.group(1), re.I)]
                raw = bytes(b ^ keys[i % len(keys)] for i, b in enumerate(raw))
            else:
                previous = re.search(r"previous\s*=\s*(\d+)", code, re.I)
                rolling = re.search(r"previous\s*=\s*[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\]", code, re.I)
                if previous and rolling:
                    prior = int(previous.group(1)); out = []
                    for value in raw:
                        out.append(value ^ prior); prior = value
                    raw = bytes(out)
                else:
                    xor = re.search(r"\^\s*(0x[0-9a-f]+|\d+)", code, re.I)
                    if xor:
                        k = int(xor.group(1), 0)
                        raw = bytes(b ^ k for b in raw)
            try:
                obj = json.loads(raw.decode("utf-8"))
                if isinstance(obj, dict):
                    fields = {}
                    for k, v in obj.items():
                        if isinstance(v, dict):
                            fields.update(v)
                        else:
                            fields[k] = ">".join(v) if isinstance(v, list) else str(v)
                    if "stageCount" in fields:
                        fields["stage_count"] = fields["stageCount"]
                    return raw.decode("utf-8"), fields
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
    # A JScript fixture may store each byte as a percent-encoded triplet and
    # reconstruct bytes with parseInt(substr(index + 1, 2), 16).
    packed_match = re.search(r"(?is)packedText\s*=\s*([^;]+);", text)
    if packed_match:
        literal = re.findall(r"['\"]([^'\"]*)['\"]", packed_match.group(1))
        packed_text = "".join(literal)
        if packed_text:
            if re.search(r"substr\([^,]+\+\s*1\s*,\s*2\)", text, re.I):
                raw = bytes(int(packed_text[i + 1:i + 3], 16) for i in range(0, len(packed_text), 3))
            elif re.fullmatch(r"[0-9a-fA-F:]+", packed_text):
                raw = bytes.fromhex(packed_text.replace(":", ""))
            elif re.fullmatch(r"\d+(?:-\d+)+", packed_text):
                raw = bytes(int(x) & 255 for x in packed_text.split("-"))
            else:
                raw = None
        else:
            raw = None
        if raw is not None:
            decoder = re.search(r"(?is)(?:function\s+decode_[^(]+|decode_[A-Za-z0-9_]+\s*=\s*function[^\(]*)\([^)]*\)\s*\{(.*?)(?:\n\s*};?|\n\s*})", text)
            code = decoder.group(1) if decoder else ""
            if re.search(r"\.reverse\s*\(\s*\)", code):
                raw = raw[::-1]
            previous = re.search(r"previous\s*=\s*(\d+)", code, re.I)
            rolling = re.search(r"previous\s*=\s*[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\]", code, re.I)
            key = re.search(r"keyBytes\s*=\s*\[([^\]]+)\]", code, re.I)
            if key:
                keys = [int(x, 0) for x in re.findall(r"0x[0-9a-f]+|\d+", key.group(1), re.I)]
                raw = bytes(b ^ keys[i % len(keys)] for i, b in enumerate(raw))
            elif previous and rolling:
                prior = int(previous.group(1)); out = []
                for value in raw:
                    out.append(value ^ prior); prior = value
                raw = bytes(out)
            else:
                add = re.search(r"\+\s*(\d+)\s*\)\s*%\s*256", code)
                xor = re.search(r"\^\s*(0x[0-9a-f]+|\d+)", code, re.I)
                if add:
                    k = int(add.group(1)); raw = bytes((b + k) & 255 for b in raw)
                elif xor:
                    k = int(xor.group(1), 0)
                    raw = bytes(b ^ k for b in raw)
            try:
                obj = json.loads(raw.decode("utf-8"))
                if isinstance(obj, dict):
                    fields = {}
                    for k, v in obj.items():
                        fields.update(v) if isinstance(v, dict) else fields.__setitem__(k, ">".join(v) if isinstance(v, list) else str(v))
                    if "stageCount" in fields:
                        fields["stage_count"] = fields["stageCount"]
                    return raw.decode("utf-8"), fields
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
    # Pull only static literals from recover_*; emulate the simple byte transform
    # visible in decode_* without executing any challenge script.
    body_match = re.search(r"(?is)(?:function\s+recover_[^(]+\([^)]*\)|recover_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})", text)
    body = body_match.group(1) if body_match else text
    packed = re.findall(r"\b(?:packedText|encodedText)\s*=\s*([^;]+);", body, re.I)
    raw = None
    if packed:
        expr = packed[0]
        chunks = re.findall(r"['\"]([^'\"]*)['\"]", expr)
        value = "".join(chunks)
        if "%" in value:
            raw = urllib.parse.unquote_to_bytes(value)
        elif re.fullmatch(r"[0-9a-fA-F:]+", value) and ":" in value:
            raw = bytes(int(x, 16) for x in value.split(":"))
        elif re.fullmatch(r"(?:[0-9a-fA-F]{2}:?)+", value):
            raw = bytes.fromhex(value.replace(":", ""))
        elif re.fullmatch(r"\d+(?:-\d+)+", value):
            raw = bytes(int(x) & 255 for x in value.split("-"))
        else:
            try: raw = base64.b64decode(value)
            except Exception: pass
    if raw is None:
        if "firstPart" in text and "secondPart" in text:
            a = re.search(r"firstPart\s*=\s*\[([^\]]+)\]", text, re.I)
            b = re.search(r"secondPart\s*=\s*\[([^\]]+)\]", text, re.I)
            if a and b:
                vals=[]
                for part in (a.group(1), b.group(1)):
                    vals += [int(x, 0) if x.lower().startswith("0x") else int(x) for x in re.findall(r"0x[0-9a-f]+|\d+", part, re.I)]
                raw=bytes(x&255 for x in vals)
        arrays = re.findall(r"(?:var|let|const)\s+(?:item1|v_a19c|characters|storedMaterial|SoUrCeByTeS|firstPart)\s*=\s*\[([^\]]+)\]", body, re.I)
        if raw is None and arrays:
            nums = [int(x, 0) if x.lower().startswith("0x") else int(x) for x in re.findall(r"0x[0-9a-f]+|\d+", arrays[0], re.I)]
            raw = bytes(x & 255 for x in nums)
        if raw is not None and ".reverse()" in body:
            raw = raw[::-1]
    # Mirror the explicit decoder expression in source.
    dec = re.search(r"(?:function\s+decode_[^(]+\([^)]*\)|decode_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})", text, re.I|re.S)
    d = dec.group(1) if dec else ""
    if raw is not None and re.search(r"\.reverse\s*\(\s*\)", d):
        raw = raw[::-1]
    keym = re.search(r"(?:keyBytes|key)\s*=\s*\[([^\]]+)\]", d)
    if keym:
        key = [int(x, 0) for x in re.findall(r"0x[0-9a-f]+|\d+", keym.group(1), re.I)]
        raw = bytes(b ^ key[i % len(key)] for i,b in enumerate(raw))
    elif re.search(r"-\s*\d+\s*\+\s*256", d):
        n = int(re.search(r"-\s*(\d+)\s*\+\s*256", d).group(1)); raw = bytes((b-n)&255 for b in raw)
    elif re.search(r"\+\s*\d+\)\s*%\s*256", d):
        n = int(re.search(r"\+\s*(\d+)\)\s*%\s*256", d).group(1)); raw = bytes((b+n)&255 for b in raw)
    elif "previous =" in d and "previous = v_a19c[i]" in d:
        m=re.search(r"previous\s*=\s*(\d+)",d); prev=int(m.group(1)) if m else 0
        out=[]
        for b in raw: out.append(b^prev); prev=b
        raw=bytes(out)
    # Later JScript fixtures wrap a literal in a hand-written base64 decoder,
    # then invoke a second decode_* helper (reverse/XOR, arithmetic, or rolling
    # XOR). Recover those literal operations statically; never evaluate script.
    rec = re.search(r"(?is)(?:function\s+recover_[^(]+\([^)]*\)|recover_[A-Za-z0-9_]+\s*=\s*function[^\{]*\{)(.*?)(?:\n\s*};?|\n\s*})", text)
    rec_body = rec.group(1) if rec else text
    pm = re.search(r"(?is)packedText\s*=\s*([^;]+);", rec_body)
    if pm:
        chunks = re.findall(r"['\"]([^'\"]*)['\"]", pm.group(1))
        packed_text = "".join(chunks)
        try:
            if re.fullmatch(r"\d+(?:-\d+)+", packed_text):
                source_bytes = bytes(int(x) & 255 for x in packed_text.split("-"))
            else:
                source_bytes = base64.b64decode(packed_text, validate=False)
            call = re.search(r"\b(decode_[A-Za-z0-9_]+)\s*(?:\.(?:apply|call)\s*\(|\()", rec_body)
            decoder_name = call.group(1) if call else None
            if decoder_name is None:
                # Some inert fixtures pass the decoder as a callback argument
                # to invoke.call/apply rather than calling it directly.
                candidates = re.findall(r"\b(decode_[A-Za-z0-9_]+)\b", rec_body)
                decoder_name = candidates[-1] if candidates else None
            dm = re.search(rf"(?is)(?:function\s+{re.escape(decoder_name)}\s*\([^)]*\)|{re.escape(decoder_name)}\s*=\s*function[^\{{]*\{{)(.*?)(?:\n\s*}};?|\n\s*}})", text) if decoder_name else None
            dec_body = dm.group(1) if dm else ""
            if re.search(r"\.reverse\s*\(\s*\)", dec_body): source_bytes = source_bytes[::-1]
            rolling = re.search(r"previous\s*=\s*(\d+)\s*;.*?previous\s*=\s*[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\]", dec_body, re.S|re.I)
            if rolling:
                prev=int(rolling.group(1)); out=[]
                for b in source_bytes: out.append(b ^ prev); prev=b
                source_bytes=bytes(out)
            else:
                sub=re.search(r"-\s*(\d+)\s*\+\s*256",dec_body)
                add=re.search(r"\+\s*(\d+)\s*\)\s*%\s*256",dec_body)
                xor=re.search(r"\^\s*(0x[0-9a-f]+|\d+)",dec_body,re.I)
                if sub:
                    n=int(sub.group(1)); source_bytes=bytes((b-n)&255 for b in source_bytes)
                elif add:
                    n=int(add.group(1)); source_bytes=bytes((b+n)&255 for b in source_bytes)
                elif xor:
                    n=int(xor.group(1),0); source_bytes=bytes(b^n for b in source_bytes)
            obj=json.loads(source_bytes.decode("utf-8"))
            if isinstance(obj,dict):
                fields={}
                for k,v in obj.items():
                    if isinstance(v,dict): fields.update({a:(">".join(b) if isinstance(b,list) else str(b)) for a,b in v.items()})
                    else: fields[k]=">".join(v) if isinstance(v,list) else str(v)
                if "stageCount" in fields: fields["stage_count"]=fields["stageCount"]
                if isinstance(obj.get("steps"),list): fields["steps"]=">".join(obj["steps"])
                return source_bytes.decode("utf-8"),fields
        except Exception:
            pass
    # Some v2 JScript variants use a compact literal array plus an explicitly
    # named reverse, fixed-XOR, or rolling-XOR decoder.
    if True:
        recm = re.search(r"(?is)function\s+recover_[^(]+\([^)]*\)\s*\{(.*?)(?:\n\s*}\s*;?|\n\s*})", text)
        rb = recm.group(1) if recm else text
        packed = re.search(r"(?is)packedText\s*=\s*['\"]([^'\"]+)['\"]", rb)
        source_bytes = None
        if packed:
            v = packed.group(1)
            try:
                source_bytes = bytes(int(x) & 255 for x in v.split("-")) if re.fullmatch(r"\d+(?:-\d+)+",v) else base64.b64decode(v)
            except Exception: pass
        if source_bytes is None:
            am = re.search(r"(?:var|let|const)\s+(storedMaterial|item1|characters|SoUrCeByTeS|v_a19c)\s*=\s*\[([^\]]+)\]", rb, re.I)
            if am:
                try: source_bytes = bytes(int(x,0)&255 for x in re.findall(r"0x[0-9a-f]+|\d+",am.group(2),re.I))
                except Exception: pass
        if source_bytes is not None:
            dm = re.search(r"(?is)function\s+decode_[^(]+\([^)]*\)\s*\{(.*?)(?:\n\s*}\s*;?|\n\s*})",text)
            d = dm.group(1) if dm else ""
            if re.search(r"\.reverse\s*\(\s*\)",d): source_bytes=source_bytes[::-1]
            roll = re.search(r"previous\s*=\s*(\d+)\s*;.*?previous\s*=\s*([A-Za-z_$][\w$]*)\s*\[\s*[A-Za-z_$][\w$]*\s*\]",d,re.S|re.I)
            key = re.search(r"keyBytes\s*=\s*\[([^\]]+)\]",d,re.I)
            xor = re.search(r"\^\s*(0x[0-9a-f]+|\d+)",d,re.I)
            sub = re.search(r"-\s*(\d+)\s*\+\s*256",d)
            add = re.search(r"\+\s*(\d+)\s*\)\s*%\s*256",d)
            if key:
                keys=[int(x,0) for x in re.findall(r"0x[0-9a-f]+|\d+",key.group(1),re.I)]
                source_bytes=bytes(b^keys[i%len(keys)] for i,b in enumerate(source_bytes))
            elif roll:
                prior=int(roll.group(1)); out=[]
                for b in source_bytes: out.append(b^prior); prior=b
                source_bytes=bytes(out)
            elif sub:
                n=int(sub.group(1)); source_bytes=bytes((b-n)&255 for b in source_bytes)
            elif add:
                n=int(add.group(1)); source_bytes=bytes((b+n)&255 for b in source_bytes)
            elif xor:
                n=int(xor.group(1),0); source_bytes=bytes(b^n for b in source_bytes)
            # Preserve an earlier decode when this broad fallback only found
            # the encoded literal but could not identify its helper body.
            if raw is None:
                raw=source_bytes
    try:
        plain=raw.decode("utf-8")
        obj=json.loads(plain)
        if isinstance(obj,dict):
            fields={}
            for k,v in obj.items():
                if isinstance(v,dict): fields.update(v)
                else: fields[k] = (">".join(v) if isinstance(v,list) else str(v))
            if isinstance(obj.get("steps"),list): fields["steps"] = ">".join(obj["steps"])
            return plain, fields
        return plain, {}
    except Exception:
        return None, {}


if __name__ == "__main__":
    start = json.loads(START.read_text())
    with zipfile.ZipFile(ARCHIVE) as zf:
        pass
    ok, failures = [], []
    for p in sorted(ROOT.iterdir()):
        if not p.is_file():
            continue
        try:
            plain, fields = static_descriptor(p)
            if plain:
                ok.append((p.name, fields))
            else:
                failures.append((p.name, "no static descriptor carrier found"))
        except Exception as exc:
            failures.append((p.name, str(exc)))
    print("descriptors", len(ok), "failures", len(failures))
    for name, fields in failures:
        print("FAIL", name, fields)
    for name, fields in ok[:10]:
        print("OK", name, fields)
