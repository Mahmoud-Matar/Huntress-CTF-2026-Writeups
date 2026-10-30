#!/usr/bin/env python3
"""Statically recover inert Huntress Script Triage descriptors."""

from __future__ import annotations

import ast
import base64
import codecs
import json
import os
import re
import urllib.parse
from pathlib import Path


ROOT = Path(os.environ.get("INSTALLER_CHAIN_ROOT", "/tmp/installer-script-chain/files"))


def pipe_descriptor(text: str) -> dict[str, str]:
    """Parse key=value fields without interpreting or executing source code."""
    fields: dict[str, str] = {}
    for part in text.strip().split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def marker_descriptor(source: str) -> dict[str, str] | None:
    kind_and_data = ""
    marker = re.search(r"HUNTRESS_ANALYSIS_V1:(HEX|B64|HB64|FRAG)-", source)
    if marker:
        kind = marker.group(1)
        alphabet = {"HEX": r"[0-9a-fA-F]+", "HB64": r"[0-9a-fA-F]+", "B64": r"[A-Za-z0-9+/=]+", "FRAG": r"[0-9a-fA-F.]+"}[kind]
        payload = re.match(alphabet, source[marker.end():])
        if not payload:
            return None
        data = payload.group(0)
        kind_and_data = f"{kind}-{data}"
    else:
        marker = re.search(r"HUNTRESS_ANALYSIS_V1:([^\s\r\n]+)", source)
    if not marker:
        return None
    if not kind_and_data:
        kind_and_data = marker.group(1).strip().strip("*/;'\"),")
    if kind_and_data == "SPLIT":
        # Google Apps Script's SPLIT marker stores fragments in a constant
        # array. Extract those literals as data; never evaluate the script.
        array = re.search(r"HUNTRESS_ANALYSIS_V1_SPLIT_[A-Za-z0-9_]+\s*=\s*\[(.*?)\]\.join", source, re.S)
        if not array:
            raise ValueError("SPLIT marker has no fragment array")
        fragments = re.findall(r"['\"]([^'\"]+)['\"]", array.group(1))
        joined = "".join(fragments)
        kind, sep, data = joined.partition("-")
        if not sep:
            raise ValueError("SPLIT fragments lack encoding prefix")
    else:
        kind, _, data = kind_and_data.partition("-")
    if kind == "HEX":
        decoded = bytes.fromhex(data).decode("utf-8")
    elif kind == "B64":
        decoded = base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8")
    elif kind == "HB64":
        inner = bytes.fromhex(data)
        decoded = base64.b64decode(inner + b"=" * (-len(inner) % 4)).decode("utf-8")
    elif kind == "FRAG":
        decoded = bytes.fromhex(data.removeprefix("FRAG-").replace(".", "")).decode("utf-8")
    else:
        raise ValueError(f"Unsupported analysis marker {kind}")
    return pipe_descriptor(decoded)


def assigned_literal(source: str, name: str) -> object:
    """Parse a single literal assignment with ast.literal_eval only."""
    # Python assignments can span several physical lines; parse the syntax tree
    # and literal-evaluate only the named constant, without importing the file.
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets
            ):
                return ast.literal_eval(node.value)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
                return ast.literal_eval(node.value)
    except (SyntaxError, ValueError):
        pass
    pattern = rf"(?im)^\s*(?:(?:readonly|const|let|var)\s+)?{re.escape(name)}\s*=\s*(.+?)\s*;?\s*$"
    match = re.search(pattern, source)
    if not match:
        # VBScript's Const declarations use the same shape but may have CRLF.
        pattern = rf"(?im)^\s*Const\s+{re.escape(name)}\s*=\s*(.+?)\s*$"
        match = re.search(pattern, source)
    if not match:
        raise ValueError(f"No literal assignment for {name}")
    literal = match.group(1).strip()
    try:
        return ast.literal_eval(literal)
    except (ValueError, SyntaxError):
        # JavaScript string literals in this fixture use JSON-compatible syntax.
        try:
            return json.loads(literal)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Assignment for {name} is not a static literal") from exc


def codec_descriptor(source: str) -> dict[str, str] | None:
    codec_match = re.search(r"(?i)\bCODEC_([A-Za-z0-9_]+)\s*=\s*['\"]([^'\"]+)['\"]", source)
    if not codec_match:
        return None
    material_name = "MATERIAL_" + codec_match.group(1)
    encoding, operation, *params = codec_match.group(2).split("|")
    value = assigned_literal(source, material_name)

    if isinstance(value, (list, tuple)):
        raw = bytes(value)
        if encoding.startswith("reversed_"):
            raw = raw[::-1]
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        if encoding in {"integer_list", "integer_tuple", "decimal_array", "decimal_csv", "decimal_pipe", "decimal_comma", "decimal_colon", "decimal_dash", "decimal_space", "reversed_decimal", "reversed_integer_list"}:
            nums = [int(n) for n in re.findall(r"\d+", value)]
            if encoding.startswith("reversed_"):
                nums.reverse()
            raw = bytes(nums)
        elif encoding in {"hex_escape"}:
            raw = value.encode("latin1")
        elif encoding in {"hex_literal", "hex_compact", "hex_buffer"}:
            raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", value))
        elif encoding in {"hex_colon", "hex_dash", "hex_array", "xor_hex", "reversed_hex"}:
            raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", value))
            if encoding == "reversed_hex":
                raw = raw[::-1]
        elif encoding == "json_numbers":
            raw = bytes(json.loads(value))
        elif encoding == "unicode_escapes":
            raw = bytes(int(x, 16) for x in re.findall(r"\\u00([0-9a-fA-F]{2})", value))
        elif encoding in {"base64_literal", "base64_chunks"}:
            raw = base64.b64decode(re.sub(r"\s+", "", value) + "=" * (-len(re.sub(r"\s+", "", value)) % 4))
        elif encoding == "urlsafe_base64":
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        elif encoding == "reversed_base64":
            value = value[::-1]
            raw = base64.b64decode(value + "=" * (-len(value) % 4))
        elif encoding == "percent_hex":
            raw = urllib.parse.unquote_to_bytes(value)
        elif encoding == "escaped_octets":
            raw = codecs.decode(value, "unicode_escape").encode("latin1")
        else:
            raise ValueError(f"Unsupported source encoding {encoding}")
    else:
        raise ValueError(f"Unsupported material literal type {type(value).__name__}")

    param = params[0] if params else ""
    if operation in {"", "identity"}:
        decoded = raw
    elif encoding == "xor_hex" and re.fullmatch(r"[0-9a-fA-F]{2}", operation):
        key = int(operation, 16)
        decoded = bytes(b ^ key for b in raw)
    elif operation == "reverse_bytes":
        decoded = raw[::-1]
    elif operation == "reverse_then_xor":
        key = int(param, 16)
        decoded = bytes(b ^ key for b in raw[::-1])
    elif operation in {"single_byte_xor", "rolling_xor"}:
        key = int(param, 16)
        if operation == "single_byte_xor":
            decoded = bytes(b ^ key for b in raw)
        else:
            prev = key
            out = bytearray()
            for b in raw:
                out.append(b ^ prev)
                prev = b
            decoded = bytes(out)
    elif operation == "repeating_key_xor":
        key = bytes(int(k, 16) for k in param.split(","))
        decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    elif operation == "subtract_modulo_256":
        key = int(param, 16)
        decoded = bytes((b + key) & 0xFF for b in raw)
    elif operation == "add_modulo_256":
        key = int(param, 16)
        decoded = bytes((b - key) & 0xFF for b in raw)
    else:
        raise ValueError(f"Unsupported transform {operation}")
    return pipe_descriptor(decoded.decode("utf-8", "strict"))


def recover(path: Path) -> dict[str, str] | None:
    source = path.read_text(encoding="utf-8", errors="replace")
    recovered = marker_descriptor(source) or codec_descriptor(source)
    if recovered:
        return recovered
    return bespoke_descriptor(path, source)


def bespoke_descriptor(path: Path, source: str) -> dict[str, str] | None:
    """Statically decode the small JScript/Batch/PowerShell fixture families."""
    def from_json_bytes(raw: bytes) -> dict[str, str]:
        text = raw.decode("utf-8")
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return pipe_descriptor(text)
        if isinstance(obj, dict):
            flat = dict(obj)
            flat.update(obj.get("values", {}) if isinstance(obj.get("values"), dict) else {})
            for key in ("steps",):
                if isinstance(flat.get(key), list):
                    flat[key] = ",".join(map(str, flat[key]))
            return {str(k): str(v) for k, v in flat.items() if isinstance(v, (str, int, float, bool))}
        return {}

    name = path.name
    # PowerShell sample configs are Base64-encoded JSON literals. The sample
    # itself is parsed as text; no PowerShell code is run.
    if name in {"resource-sample.ps1", "collection-sample.ps1", "impact-sample.ps1"}:
        literals = re.findall(r"FromBase64String\(['\"]([^'\"]+)['\"]\)", source)
        for literal in literals:
            try:
                obj = json.loads(base64.b64decode(literal))
                if isinstance(obj, dict):
                    return {str(k): str(v) for k, v in obj.items()}
            except Exception:
                continue
    # JScript's reconstruction functions contain static byte/character arrays
    # or packed text. Reproduce only their visible decoder operations.
    if name.endswith((".js", ".mjs")):
        packed = re.search(r"packedText\s*=\s*(.*?);", source, re.S)
        raw = b""
        if packed:
            text = "".join(json.loads(literal) for literal in re.findall(r'"(?:[^"\\]|\\.)*"', packed.group(1)))
            if re.search(r"decodeBase64\s*\(\s*packedText\s*\)", source):
                raw = base64.b64decode(text + "=" * (-len(text) % 4))
            elif re.search(r"%[0-9a-fA-F]{2}", text):
                raw = bytes(int(x, 16) for x in re.findall(r"%([0-9a-fA-F]{2})", text))
            elif re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-])+[0-9a-fA-F]{2}", text):
                raw = bytes.fromhex(re.sub(r"[:-]", "", text))
            elif re.fullmatch(r"\d+(?:[-,:]\d+)+", text):
                raw = bytes(int(x) for x in re.split(r"[-,:]", text))
            else:
                # Treat an otherwise opaque packed string as Base64 only when
                # its alphabet and length make that representation valid.
                try:
                    raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
                except Exception:
                    raw = b""
        # Numeric array reconstructions.
        if not raw:
            arrays: dict[str, bytes] = {}
            for array_match in re.finditer(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([\s\d,0-9a-fA-Fx]+)\]", source, re.S):
                try:
                    arrays[array_match.group(1)] = bytes(int(x.strip(), 0) for x in array_match.group(2).split(",") if x.strip())
                except ValueError:
                    continue
            concat = re.search(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.concat\(([A-Za-z_$][\w$]*)\)", source)
            if concat and concat.group(2) in arrays and concat.group(3) in arrays:
                arrays[concat.group(1)] = arrays[concat.group(2)] + arrays[concat.group(3)]
            if concat and concat.group(1) in {"item1", "storedMaterial", "SoUrCeByTeS", "s", "v_a19c"}:
                raw = arrays[concat.group(1)]
            assigned = re.search(r"(?:var|let|const)\s+(?:item1|storedMaterial|SoUrCeByTeS|s|v_a19c)\s*=\s*([A-Za-z_$][\w$]*)", source)
            if not raw and assigned and assigned.group(1) in arrays:
                raw = arrays[assigned.group(1)]
            if not raw:
                array_match = re.search(r"(?:var|let|const)\s+(?:characters|v_a19c|item1|storedMaterial|SoUrCeByTeS|s)\s*=\s*\[([^]]+)\]", source, re.S)
                if array_match:
                    raw = bytes(int(x.strip(), 0) for x in array_match.group(1).split(",") if x.strip())
        # Some variants reverse the stored array before passing it to the decoder.
        if raw and re.search(r"(?:storedMaterial|SoUrCeByTeS|item1|s)\.reverse\(\)", source):
            raw = raw[::-1]
        if raw:
            # Apply the explicit arithmetic/XOR/reversal operations visible in
            # the decoder function. No source function is invoked.
            decoder_reverse = re.search(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.slice\(0\);[\s\S]{0,120}?\1\.reverse\(\)", source)
            output_reverse = re.search(r"(?:v_b27e|item2|recoveredMaterial|d)\.reverse\(\)", source)
            if decoder_reverse or output_reverse:
                raw = raw[::-1]
            key_match = re.search(r"keyBytes\s*=\s*\[([^]]+)\]", source)
            if re.search(r"\^\s*(?:previous|priorByte)", source):
                prior = re.search(r"(?:previous|priorByte)\s*=\s*(\d+)", source)
                last = int(prior.group(1)) if prior else 0
                out = bytearray()
                for x in raw:
                    out.append(x ^ last)
                    last = x
                raw = bytes(out)
            elif key_match and re.search(r"\^\s*keyBytes\s*\[", source):
                key = bytes(int(x.strip()) for x in key_match.group(1).split(","))
                raw = bytes(x ^ key[i % len(key)] for i, x in enumerate(raw))
            elif re.search(r"\^\s*\d+", source):
                key = int(re.search(r"\^\s*(\d+)", source).group(1))
                raw = bytes(x ^ key for x in raw)
            elif re.search(r"\+\s*\d+\)\s*&\s*255", source):
                key = int(re.search(r"\+\s*(\d+)\)\s*&\s*255", source).group(1))
                raw = bytes((x + key) & 255 for x in raw)
            elif re.search(r"-\s*\d+\s*\+\s*256\)\s*%\s*256", source):
                key = int(re.search(r"-\s*(\d+)\s*\+\s*256\)\s*%\s*256", source).group(1))
                raw = bytes((x - key) & 255 for x in raw)
            elif re.search(r"\+\s*\d+\)\s*%\s*256", source):
                key = int(re.search(r"\+\s*(\d+)\)\s*%\s*256", source).group(1))
                raw = bytes((x + key) & 255 for x in raw)
            return from_json_bytes(raw)
    # Batch files intentionally expose inert, reconstructed fragments. Join
    # those exact literals in numeric order; carets quote pipe delimiters.
    if path.suffix.lower() in {".cmd", ".bat"}:
        fragments: dict[int, str] = {}
        for m in re.finditer(r"(?im)^\s*set\s+[\"']?(?:fragment|frag|v_a|h|item)(\d+)\s*=([^\r\n\"']*)", source):
            index = int(m.group(1))
            if index < 4:
                fragments[index] = m.group(2).replace("^|", "|").replace("^^", "^")
        if fragments:
            joined = "".join(fragments[i] for i in sorted(fragments))
            joined = joined.strip().strip("\"'")
            if joined.startswith("v="):
                return pipe_descriptor(joined)
        # One-step inert byte decoders from the codec comments.
        codec = re.search(r"HUNTRESS-CODEC:([^|\r\n]+)\|([^\r\n]+)", source, re.I)
        material = re.search(r"HUNTRESS-MATERIAL:([^\r\n]+)", source, re.I)
        if codec and material:
            encoding, transform = codec.group(1).strip(), codec.group(2).strip()
            value = material.group(1).strip()
            if encoding == "base64_literal":
                if transform == "reverse": value = value[::-1]
                raw = base64.b64decode(value + "=" * (-len(value) % 4))
            elif encoding == "decimal_bytes":
                nums = [int(x) for x in re.findall(r"\d+", value)]
                raw = bytes(nums)
            elif encoding == "reversed_text":
                raw = value[::-1].encode()
            elif encoding in {"split_fragments", "plain_fragments"}:
                raw = base64.b64decode(value + "=" * (-len(value) % 4))
            else:
                raw = b""
            if transform == "add_7": raw = bytes((x - 7) & 255 for x in raw)
            elif transform == "rotate_left": raw = bytes(((x << 1) | (x >> 7)) & 255 for x in raw)
            elif transform == "reverse_xor": raw = bytes(x ^ 0x37 for x in raw[::-1])
            # Try the most common composite reversal after the byte transform.
            for candidate in (raw, raw[::-1]):
                try:
                    text = candidate.decode("utf-8")
                    fields = pipe_descriptor(text)
                    if fields:
                        return fields
                except UnicodeDecodeError:
                    pass
    return None


def main() -> None:
    recovered: dict[str, dict[str, str]] = {}
    failures: list[tuple[str, str]] = []
    for path in sorted(ROOT.iterdir()):
        if not path.is_file():
            continue
        try:
            fields = recover(path)
            if fields:
                recovered[path.name] = fields
        except Exception as exc:
            failures.append((path.name, str(exc)))
    print(json.dumps({"recovered": len(recovered), "failures": failures, "examples": dict(list(recovered.items())[:5])}, separators=(",", ":")))
    output_path = Path(os.environ.get("INSTALLER_CHAIN_DESCRIPTORS", "/tmp/installer-script-chain/descriptors.json"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(recovered, separators=(",", ":")))


if __name__ == "__main__":
    main()
