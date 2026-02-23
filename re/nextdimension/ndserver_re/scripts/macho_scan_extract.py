#!/usr/bin/env python3
"""Scan a binary for embedded 32-bit Mach-O headers and extract objects.

This scanner is intentionally conservative and only accepts headers where
load-command structure parses cleanly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

MAGIC_BE = b"\xfe\xed\xfa\xce"
MAGIC_LE = b"\xce\xfa\xed\xfe"

CPU_NAMES: Dict[int, str] = {
    6: "m68k",
    7: "i386",
    14: "sparc",
    15: "i860",
}

FILETYPE_NAMES: Dict[int, str] = {
    1: "object",
    2: "execute",
    3: "fvmlib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB


@dataclass
class MachHeader:
    offset: int
    endian: str
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    estimated_end: int

    @property
    def cpu_name(self) -> str:
        return CPU_NAMES.get(self.cputype, f"cpu_{self.cputype}")

    @property
    def filetype_name(self) -> str:
        return FILETYPE_NAMES.get(self.filetype, f"filetype_{self.filetype}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_macho_header(blob: bytes, offset: int) -> Optional[MachHeader]:
    if offset + 28 > len(blob):
        return None

    magic = blob[offset : offset + 4]
    if magic == MAGIC_BE:
        endian = ">"
    elif magic == MAGIC_LE:
        endian = "<"
    else:
        return None

    try:
        _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "7I", blob, offset
        )
    except struct.error:
        return None

    # Conservative sanity checks to avoid false positives in data sections.
    if ncmds == 0 or ncmds > 256:
        return None
    if sizeofcmds == 0 or sizeofcmds > 0x200000:
        return None
    if filetype not in FILETYPE_NAMES:
        return None
    if cputype not in CPU_NAMES:
        return None

    lcoff = offset + 28
    lcend = lcoff + sizeofcmds
    if lcend > len(blob):
        return None

    estimated_end = lcend
    cur = lcoff
    try:
        for _ in range(ncmds):
            if cur + 8 > lcend:
                return None
            cmd, cmdsize = struct.unpack_from(endian + "II", blob, cur)
            if cmdsize < 8:
                return None
            if cur + cmdsize > lcend:
                return None

            if cmd == LC_SEGMENT and cmdsize >= 56:
                _, _, fileoff, filesize, _, _, _, _ = struct.unpack_from(endian + "8I", blob, cur + 24)
                estimated_end = max(estimated_end, offset + fileoff + filesize)
            elif cmd == LC_SYMTAB and cmdsize >= 24:
                symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "4I", blob, cur + 8)
                estimated_end = max(estimated_end, offset + symoff + nsyms * 12)
                estimated_end = max(estimated_end, offset + stroff + strsize)
            elif cmd == LC_DYSYMTAB and cmdsize >= 80:
                vals = struct.unpack_from(endian + "18I", blob, cur + 8)
                # (offset, count, entry_size)
                tables = [
                    (vals[6], vals[7], 8),   # toc
                    (vals[8], vals[9], 52),  # modtab
                    (vals[10], vals[11], 4), # extrefs
                    (vals[12], vals[13], 4), # indirectsyms
                    (vals[14], vals[15], 8), # ext reloc
                    (vals[16], vals[17], 8), # local reloc
                ]
                for table_off, count, entsz in tables:
                    estimated_end = max(estimated_end, offset + table_off + count * entsz)

            cur += cmdsize
    except struct.error:
        return None

    estimated_end = min(estimated_end, len(blob))
    if estimated_end <= offset:
        return None

    return MachHeader(
        offset=offset,
        endian="be" if endian == ">" else "le",
        cputype=cputype,
        cpusubtype=cpusubtype,
        filetype=filetype,
        ncmds=ncmds,
        sizeofcmds=sizeofcmds,
        flags=flags,
        estimated_end=estimated_end,
    )


def scan_headers(blob: bytes, step: int = 4) -> List[MachHeader]:
    results: List[MachHeader] = []
    seen = set()
    for off in range(0, len(blob) - 4, step):
        magic = blob[off : off + 4]
        if magic not in (MAGIC_BE, MAGIC_LE):
            continue
        hdr = parse_macho_header(blob, off)
        if not hdr:
            continue
        if hdr.offset in seen:
            continue
        seen.add(hdr.offset)
        results.append(hdr)
    results.sort(key=lambda h: h.offset)
    return results


def write_manifest(
    input_path: Path,
    out_dir: Path,
    headers: List[MachHeader],
    blob: bytes,
    primary_cpu: Optional[int],
    foreign_only: bool,
    extract: bool,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    objects = []
    for idx, h in enumerate(headers, start=1):
        is_primary = h.offset == 0
        if primary_cpu is None:
            is_foreign = not is_primary
        else:
            is_foreign = h.cputype != primary_cpu

        if foreign_only and not is_foreign:
            continue

        start = h.offset
        end = h.estimated_end
        data = blob[start:end]
        size = len(data)
        sha = sha256_bytes(data)

        record = {
            "index": idx,
            "offset": start,
            "offset_hex": f"0x{start:x}",
            "estimated_end": end,
            "estimated_end_hex": f"0x{end:x}",
            "size": size,
            "size_hex": f"0x{size:x}",
            "endian": h.endian,
            "cputype": h.cputype,
            "cpu_name": h.cpu_name,
            "cpusubtype": h.cpusubtype,
            "filetype": h.filetype,
            "filetype_name": h.filetype_name,
            "ncmds": h.ncmds,
            "sizeofcmds": h.sizeofcmds,
            "flags": h.flags,
            "is_primary": is_primary,
            "is_foreign": is_foreign,
            "sha256": sha,
        }

        if extract:
            out_name = (
                f"obj_{idx:02d}_off_{start:06x}_{h.cpu_name}_{h.filetype_name}_{size}.bin"
            )
            out_path = out_dir / out_name
            out_path.write_bytes(data)
            record["path"] = str(out_path)

        objects.append(record)

    manifest = {
        "input": str(input_path),
        "input_size": len(blob),
        "input_sha256": sha256_bytes(blob),
        "scan_step": 4,
        "primary_cpu": primary_cpu,
        "foreign_only": foreign_only,
        "objects": objects,
    }

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    summary_lines = [
        f"input: {input_path}",
        f"input_size: {len(blob)}",
        f"input_sha256: {manifest['input_sha256']}",
        f"objects: {len(objects)}",
        "",
    ]
    for obj in objects:
        summary_lines.append(
            "{idx:02d} off={off} size={size} cpu={cpu} type={ft} foreign={foreign}".format(
                idx=obj["index"],
                off=obj["offset_hex"],
                size=obj["size"],
                cpu=obj["cpu_name"],
                ft=obj["filetype_name"],
                foreign=obj["is_foreign"],
            )
        )

    (out_dir / "summary.txt").write_text("\n".join(summary_lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input binary to scan")
    parser.add_argument("output_dir", type=Path, help="Directory for manifest and extracted objects")
    parser.add_argument(
        "--primary-cpu",
        type=int,
        default=None,
        help="Primary CPU type for foreign-object classification (e.g., 15 for i860, 6 for m68k)",
    )
    parser.add_argument(
        "--foreign-only",
        action="store_true",
        help="Only emit objects classified as foreign",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Only write manifest/summary; do not write per-object blobs",
    )

    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"input not found: {args.input}")

    blob = args.input.read_bytes()
    headers = scan_headers(blob, step=4)

    write_manifest(
        input_path=args.input,
        out_dir=args.output_dir,
        headers=headers,
        blob=blob,
        primary_cpu=args.primary_cpu,
        foreign_only=args.foreign_only,
        extract=not args.no_extract,
    )


if __name__ == "__main__":
    main()
