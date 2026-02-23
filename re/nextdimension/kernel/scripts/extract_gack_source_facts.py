#!/usr/bin/env python3
"""Extract source-side function facts from NeXTDimension NDkernel sources.

Output schema (JSON):
{
  "schema_version": "gack-source-facts-v1",
  "source_root": "...",
  "generated_at_utc": "...",
  "files_scanned": {"c": N, "asm": N},
  "function_count": N,
  "functions": [ ... ]
}
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "gack-source-facts-v1"

C_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "switch",
    "case",
    "default",
    "return",
    "sizeof",
    "do",
    "goto",
}

HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
STR_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

C_FUNC_RE = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_][A-Za-z0-9_\s\*\(\)]*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:\n[ \t]*)?\{"
)
ASM_LABEL_RE = re.compile(r"(?m)^([A-Za-z_][A-Za-z0-9_]*):")
ASM_CALL_RE = re.compile(r"\b(?:call|calli|bsr)\b\s+([A-Za-z_][A-Za-z0-9_]*)")


def fmt_hex(v: int) -> str:
    return f"0x{(v & 0xFFFFFFFF):08x}"


def parse_hex_token(tok: str) -> int:
    return int(tok, 16) & 0xFFFFFFFF


def relpath(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def looks_mmio(value: int) -> bool:
    # ND board-centric ranges used as strong anchors.
    return (
        0x02000000 <= value <= 0x0200FFFF
        or 0xFF800000 <= value <= 0xFF80FFFF
        or 0x08000000 <= value <= 0x08FFFFFF
        or 0xF0000000 <= value <= 0xF000FFFF
    )


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items))


def extract_body_spans(text: str, starts: list[tuple[str, int, int]]) -> list[dict]:
    rows: list[dict] = []
    for idx, (name, line, start) in enumerate(starts):
        end = starts[idx + 1][2] if idx + 1 < len(starts) else len(text)
        rows.append({"name": name, "line": line, "start": start, "end": end})
    return rows


def collect_body_facts(body: str, fn_name: str, is_asm: bool) -> tuple[list[str], list[str], list[str], list[str]]:
    hex_vals = unique_sorted(fmt_hex(parse_hex_token(h)) for h in HEX_RE.findall(body))
    mmio_vals = unique_sorted(h for h in hex_vals if looks_mmio(int(h, 16)))

    strings = []
    for s in STR_RE.findall(body):
        cleaned = s.replace("\\n", "\\n").replace("\\t", "\\t")
        strings.append(cleaned)
    string_vals = unique_sorted(strings)

    calls: list[str] = []
    if is_asm:
        calls = unique_sorted(m.group(1) for m in ASM_CALL_RE.finditer(body))
    else:
        for m in CALL_RE.finditer(body):
            callee = m.group(1)
            if callee in C_KEYWORDS:
                continue
            if callee == fn_name:
                continue
            calls.append(callee)
        calls = unique_sorted(calls)

    return calls, mmio_vals, hex_vals, string_vals


def extract_c_file(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="latin-1", errors="replace")
    starts: list[tuple[str, int, int]] = []
    for m in C_FUNC_RE.finditer(text):
        name = m.group(1)
        if name in C_KEYWORDS:
            continue
        line = text.count("\n", 0, m.start()) + 1
        starts.append((name, line, m.start()))

    rows: list[dict] = []
    for span in extract_body_spans(text, starts):
        body = text[span["start"] : span["end"]]
        calls, mmio_vals, hex_vals, string_vals = collect_body_facts(body, span["name"], is_asm=False)
        rows.append(
            {
                "name": span["name"],
                "file": relpath(path, root),
                "line": span["line"],
                "lang": "c",
                "calls": calls,
                "mmio_consts": mmio_vals,
                "imm_consts": hex_vals,
                "string_literals": string_vals,
            }
        )
    return rows


def extract_asm_file(path: Path, root: Path) -> list[dict]:
    text = path.read_text(encoding="latin-1", errors="replace")
    starts: list[tuple[str, int, int]] = []
    for m in ASM_LABEL_RE.finditer(text):
        name = m.group(1)
        if name.startswith("L"):
            continue
        line = text.count("\n", 0, m.start()) + 1
        starts.append((name, line, m.start()))

    rows: list[dict] = []
    for span in extract_body_spans(text, starts):
        body = text[span["start"] : span["end"]]
        calls, mmio_vals, hex_vals, string_vals = collect_body_facts(body, span["name"], is_asm=True)
        rows.append(
            {
                "name": span["name"],
                "file": relpath(path, root),
                "line": span["line"],
                "lang": "asm",
                "calls": calls,
                "mmio_consts": mmio_vals,
                "imm_consts": hex_vals,
                "string_literals": string_vals,
            }
        )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract NDkernel source-side function facts")
    ap.add_argument("--source-root", required=True, help="Path to NextDimension-21/NDkernel")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument(
        "--source-version",
        default="NeXTSTEP-2.0",
        help="Source software version label for provenance (default: NeXTSTEP-2.0)",
    )
    args = ap.parse_args()

    root = Path(args.source_root).resolve()
    if not root.is_dir():
        raise SystemExit(f"source root not found: {root}")

    c_files = sorted(root.rglob("*.c"))
    asm_files = sorted(list(root.rglob("*.s")) + list(root.rglob("*.S")))

    functions: list[dict] = []
    for p in c_files:
        functions.extend(extract_c_file(p, root))
    for p in asm_files:
        functions.extend(extract_asm_file(p, root))

    functions.sort(key=lambda f: (f["file"], f["line"], f["name"]))

    out = {
        "schema_version": SCHEMA_VERSION,
        "source_root": str(root),
        "source_version": args.source_version,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files_scanned": {"c": len(c_files), "asm": len(asm_files)},
        "function_count": len(functions),
        "functions": functions,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print("=== extract_gack_source_facts ===")
    print(f"source_root:    {root}")
    print(f"source_version: {args.source_version}")
    print(f"files scanned:  c={len(c_files)} asm={len(asm_files)}")
    print(f"functions:      {len(functions)}")
    print(f"output:         {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
