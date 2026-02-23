#!/usr/bin/env python3
"""Extract binary-side function facts from Ghidra factpack JSONL exports."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "binary-facts-v1"
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
OFFSET_RE = re.compile(r"([+-]?(?:0x[0-9a-fA-F]+|\d+))\(r\d+\)")


def parse_hex(v: str) -> int:
    return int(v, 16)


def fmt_hex(v: int) -> str:
    return f"0x{(v & 0xFFFFFFFF):08x}"


def parse_signed_token(tok: str) -> int:
    t = tok.strip().lower()
    if t.startswith("-0x"):
        return -int(t[3:], 16)
    if t.startswith("+0x"):
        return int(t[3:], 16)
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def fmt_signed_hex(v: int) -> str:
    if v < 0:
        return f"-0x{abs(v):x}"
    return f"0x{v:x}"


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract binary-side function facts from factpack")
    ap.add_argument("--factpack", required=True, help="Factpack directory containing *.jsonl")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument(
        "--target-version",
        default="NeXTSTEP-3.3",
        help="Target binary/software version label for provenance (default: NeXTSTEP-3.3)",
    )
    args = ap.parse_args()

    factpack = Path(args.factpack).resolve()
    if not factpack.is_dir():
        raise SystemExit(f"factpack dir not found: {factpack}")

    functions = load_jsonl(factpack / "functions.jsonl")
    insns = load_jsonl(factpack / "insns.jsonl")
    refs = load_jsonl(factpack / "refs.jsonl")
    dispatch_unresolved = load_jsonl(factpack / "dispatch_unresolved.jsonl")
    meta = json.loads((factpack / "meta.json").read_text(encoding="utf-8")) if (factpack / "meta.json").exists() else {}

    fn_by_entry: dict[str, dict] = {}
    for f in functions:
        entry = str(f.get("entry", "")).lower()
        if not entry:
            continue
        size = int(f.get("size", 0) or 0)
        start = parse_hex(entry)
        end = start + max(size - 1, 0)
        fn_by_entry[entry] = {
            "entry": entry,
            "name": f.get("name", ""),
            "size": size,
            "start": start,
            "end": end,
            "mnemonic_hist": Counter(),
            "call_targets": set(),
            "flow_targets": set(),
            "mmio_offsets": set(),
            "imm_consts": set(),
            "string_refs": set(),
            "has_unresolved_bri": bool(f.get("has_unresolved_bri", False)),
        }

    # Promote unresolved dispatch flags from dedicated table.
    for d in dispatch_unresolved:
        fe = d.get("func_entry")
        if isinstance(fe, str):
            key = fe.lower()
            if key in fn_by_entry:
                fn_by_entry[key]["has_unresolved_bri"] = True

    addr_to_func: dict[str, str] = {}

    for ins in insns:
        fe = ins.get("func_entry")
        if not isinstance(fe, str):
            continue
        key = fe.lower()
        if key not in fn_by_entry:
            continue

        rec = fn_by_entry[key]
        addr = str(ins.get("addr", "")).lower()
        if addr:
            addr_to_func[addr] = key

        mnem = str(ins.get("mnemonic", "")).lower()
        if mnem:
            rec["mnemonic_hist"][mnem] += 1

        operands = str(ins.get("operands", ""))
        for tok in OFFSET_RE.findall(operands):
            try:
                sval = parse_signed_token(tok)
                rec["mmio_offsets"].add(fmt_signed_hex(sval))
            except ValueError:
                pass

        for tok in HEX_RE.findall(operands):
            rec["imm_consts"].add(fmt_hex(parse_hex(tok)))

        for u in ins.get("uses", []) or []:
            if isinstance(u, str) and u.lower().startswith("0x"):
                try:
                    rec["imm_consts"].add(fmt_hex(parse_hex(u)))
                except ValueError:
                    pass

        word = ins.get("word")
        if isinstance(word, str) and word.lower().startswith("0x"):
            try:
                rec["imm_consts"].add(fmt_hex(parse_hex(word)))
            except ValueError:
                pass

        sref = ins.get("string_ref")
        if isinstance(sref, str) and sref:
            rec["string_refs"].add(sref)

    for r in refs:
        src = r.get("from")
        dst = r.get("to")
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        src_key = src.lower()
        fn_key = addr_to_func.get(src_key)
        if not fn_key:
            continue

        rec = fn_by_entry[fn_key]
        is_flow = bool(r.get("is_flow", False))
        rtype = str(r.get("type", "")).upper()

        if is_flow:
            rec["flow_targets"].add(dst.lower())
            if "CALL" in rtype or "JUMP" in rtype or "BRANCH" in rtype:
                rec["call_targets"].add(dst.lower())

    out_functions = []
    for entry, rec in sorted(fn_by_entry.items(), key=lambda kv: kv[1]["start"]):
        out_functions.append(
            {
                "entry": rec["entry"],
                "name": rec["name"],
                "size": rec["size"],
                "mnemonic_hist": dict(sorted(rec["mnemonic_hist"].items())),
                "call_targets": sorted(rec["call_targets"]),
                "flow_targets": sorted(rec["flow_targets"]),
                "mmio_offsets": sorted(rec["mmio_offsets"]),
                "imm_consts": sorted(rec["imm_consts"]),
                "string_refs": sorted(rec["string_refs"]),
                "has_unresolved_bri": rec["has_unresolved_bri"],
            }
        )

    out = {
        "schema_version": SCHEMA_VERSION,
        "factpack_dir": str(factpack),
        "target_version": args.target_version,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "meta": {
            "program_name": meta.get("program_name"),
            "image_base": meta.get("image_base"),
            "language_id": meta.get("language_id"),
            "compiler_spec": meta.get("compiler_spec"),
        },
        "function_count": len(out_functions),
        "functions": out_functions,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print("=== extract_binary_facts ===")
    print(f"factpack:        {factpack}")
    print(f"target_version:  {args.target_version}")
    print(f"functions:       {len(out_functions)}")
    print(f"insn rows:       {len(insns)}")
    print(f"ref rows:        {len(refs)}")
    print(f"dispatch rows:   {len(dispatch_unresolved)}")
    print(f"output:          {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
