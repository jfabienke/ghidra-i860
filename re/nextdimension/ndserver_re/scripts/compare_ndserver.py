#!/usr/bin/env python3
"""Compare two 32-bit Mach-O m68k NDserver-style binaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MAGIC_BE = b"\xfe\xed\xfa\xce"
MAGIC_LE = b"\xce\xfa\xed\xfe"
LC_SEGMENT = 0x1


@dataclass
class SectionRecord:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int
    sha256: Optional[str]


@dataclass
class ParsedMachO:
    path: str
    size: int
    sha256: str
    endian: str
    cputype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    sections: List[SectionRecord]
    section_bytes: Dict[Tuple[str, str], bytes]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_macho(path: Path) -> ParsedMachO:
    blob = path.read_bytes()
    if len(blob) < 28:
        raise ValueError(f"file too small: {path}")

    magic = blob[:4]
    if magic == MAGIC_BE:
        endian = ">"
        endian_name = "be"
    elif magic == MAGIC_LE:
        endian = "<"
        endian_name = "le"
    else:
        raise ValueError(f"not Mach-O 32-bit: {path}")

    _, cputype, _, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "7I", blob, 0)

    cur = 28
    end = cur + sizeofcmds
    if end > len(blob):
        raise ValueError(f"invalid load command size in {path}")

    sections: List[SectionRecord] = []
    section_bytes: Dict[Tuple[str, str], bytes] = {}

    for _ in range(ncmds):
        if cur + 8 > end:
            raise ValueError(f"truncated load command in {path}")
        cmd, cmdsize = struct.unpack_from(endian + "II", blob, cur)
        if cmdsize < 8 or cur + cmdsize > end:
            raise ValueError(f"invalid load command size in {path}")

        if cmd == LC_SEGMENT and cmdsize >= 56:
            nsects = struct.unpack_from(endian + "I", blob, cur + 48)[0]
            scur = cur + 56
            for _ in range(nsects):
                if scur + 68 > cur + cmdsize:
                    raise ValueError(f"truncated section table in {path}")
                sectname = blob[scur : scur + 16].split(b"\0", 1)[0].decode("latin1")
                segname = blob[scur + 16 : scur + 32].split(b"\0", 1)[0].decode("latin1")
                addr, size, offset, _, _, _, _, _, _ = struct.unpack_from(endian + "9I", blob, scur + 32)

                sec_key = (segname, sectname)
                data = b""
                digest = None
                if offset + size <= len(blob):
                    data = blob[offset : offset + size]
                    digest = sha256_bytes(data)

                sections.append(
                    SectionRecord(
                        segname=segname,
                        sectname=sectname,
                        addr=addr,
                        size=size,
                        offset=offset,
                        sha256=digest,
                    )
                )
                section_bytes[sec_key] = data
                scur += 68

        cur += cmdsize

    return ParsedMachO(
        path=str(path),
        size=len(blob),
        sha256=sha256_bytes(blob),
        endian=endian_name,
        cputype=cputype,
        filetype=filetype,
        ncmds=ncmds,
        sizeofcmds=sizeofcmds,
        flags=flags,
        sections=sections,
        section_bytes=section_bytes,
    )


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    if not data:
        return []
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode("ascii") + rb",}")
    return [m.group().decode("latin1") for m in pattern.finditer(data)]


def compare(parsed_a: ParsedMachO, parsed_b: ParsedMachO) -> Dict:
    map_a = {(s.segname, s.sectname): s for s in parsed_a.sections}
    map_b = {(s.segname, s.sectname): s for s in parsed_b.sections}

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())
    shared = sorted(keys_a & keys_b)

    shared_sections = []
    for key in shared:
        a = map_a[key]
        b = map_b[key]
        shared_sections.append(
            {
                "segname": key[0],
                "sectname": key[1],
                "size_a": a.size,
                "size_b": b.size,
                "sha_a": a.sha256,
                "sha_b": b.sha256,
                "same_sha": a.sha256 is not None and a.sha256 == b.sha256,
            }
        )

    cstr_key = ("__TEXT", "__cstring")
    c_a = set(ascii_strings(parsed_a.section_bytes.get(cstr_key, b"")))
    c_b = set(ascii_strings(parsed_b.section_bytes.get(cstr_key, b"")))

    text_key = ("__TEXT", "__text")
    t_a = parsed_a.section_bytes.get(text_key, b"")
    t_b = parsed_b.section_bytes.get(text_key, b"")
    text_similarity = None
    if t_a and t_b:
        text_similarity = SequenceMatcher(None, t_a, t_b, autojunk=False).ratio()

    return {
        "file_a": {
            "path": parsed_a.path,
            "size": parsed_a.size,
            "sha256": parsed_a.sha256,
            "endian": parsed_a.endian,
            "cputype": parsed_a.cputype,
            "filetype": parsed_a.filetype,
            "ncmds": parsed_a.ncmds,
            "sizeofcmds": parsed_a.sizeofcmds,
            "flags": parsed_a.flags,
        },
        "file_b": {
            "path": parsed_b.path,
            "size": parsed_b.size,
            "sha256": parsed_b.sha256,
            "endian": parsed_b.endian,
            "cputype": parsed_b.cputype,
            "filetype": parsed_b.filetype,
            "ncmds": parsed_b.ncmds,
            "sizeofcmds": parsed_b.sizeofcmds,
            "flags": parsed_b.flags,
        },
        "delta": {
            "size_bytes": parsed_b.size - parsed_a.size,
            "ncmds": parsed_b.ncmds - parsed_a.ncmds,
            "sizeofcmds": parsed_b.sizeofcmds - parsed_a.sizeofcmds,
            "text_similarity_ratio": text_similarity,
        },
        "sections": {
            "shared": shared_sections,
            "only_a": [{"segname": k[0], "sectname": k[1]} for k in sorted(keys_a - keys_b)],
            "only_b": [{"segname": k[0], "sectname": k[1]} for k in sorted(keys_b - keys_a)],
        },
        "cstring": {
            "count_a": len(c_a),
            "count_b": len(c_b),
            "shared_count": len(c_a & c_b),
            "only_a": sorted(c_a - c_b),
            "only_b": sorted(c_b - c_a),
        },
    }


def write_markdown(result: Dict, out_path: Path) -> None:
    same_hash_sections = [s for s in result["sections"]["shared"] if s["same_sha"]]
    changed_sections = [s for s in result["sections"]["shared"] if not s["same_sha"]]

    lines = []
    lines.append("# NDserver Binary Comparison")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- file A: `{result['file_a']['path']}`")
    lines.append(f"- file B: `{result['file_b']['path']}`")
    lines.append(f"- size delta (B-A): `{result['delta']['size_bytes']}` bytes")
    lines.append(f"- ncmds delta (B-A): `{result['delta']['ncmds']}`")
    lines.append(f"- sizeofcmds delta (B-A): `{result['delta']['sizeofcmds']}`")
    sim = result["delta"]["text_similarity_ratio"]
    if sim is not None:
        lines.append(f"- __TEXT,__text similarity: `{sim:.6f}`")

    lines.append("")
    lines.append("## Sections")
    lines.append("")
    lines.append(f"- shared sections: `{len(result['sections']['shared'])}`")
    lines.append(f"- exact-hash shared sections: `{len(same_hash_sections)}`")
    lines.append(f"- changed shared sections: `{len(changed_sections)}`")
    lines.append(f"- sections only in A: `{len(result['sections']['only_a'])}`")
    lines.append(f"- sections only in B: `{len(result['sections']['only_b'])}`")

    lines.append("")
    lines.append("## CStrings")
    lines.append("")
    lines.append(f"- count A: `{result['cstring']['count_a']}`")
    lines.append(f"- count B: `{result['cstring']['count_b']}`")
    lines.append(f"- shared: `{result['cstring']['shared_count']}`")

    lines.append("")
    lines.append("### CStrings Only In A")
    lines.append("")
    if result["cstring"]["only_a"]:
        for item in result["cstring"]["only_a"][:50]:
            lines.append(f"- `{item}`")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("### CStrings Only In B")
    lines.append("")
    if result["cstring"]["only_b"]:
        for item in result["cstring"]["only_b"][:50]:
            lines.append(f"- `{item}`")
    else:
        lines.append("- none")

    out_path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a", required=True, type=Path, help="First Mach-O file")
    parser.add_argument("--b", required=True, type=Path, help="Second Mach-O file")
    parser.add_argument("--out-json", required=True, type=Path, help="Output JSON report")
    parser.add_argument("--out-md", required=False, type=Path, help="Output Markdown summary")
    args = parser.parse_args()

    if not args.a.exists():
        raise SystemExit(f"missing file: {args.a}")
    if not args.b.exists():
        raise SystemExit(f"missing file: {args.b}")

    parsed_a = parse_macho(args.a)
    parsed_b = parse_macho(args.b)
    result = compare(parsed_a, parsed_b)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2) + "\n")

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(result, args.out_md)


if __name__ == "__main__":
    main()
