#!/usr/bin/env python3
"""Infer register/memory seed gaps from emulator trace JSONL.

This script is tolerant to partial trace schemas. It focuses on indirect branch/call
records and optional provenance fields.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, Optional

MMIO_START = 0x0200_0000
MMIO_END = 0x0200_1000


def parse_u32(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v & 0xFFFFFFFF
    if isinstance(v, float):
        return int(v) & 0xFFFFFFFF
    if isinstance(v, str):
        s = v.strip().replace("_", "")
        if not s:
            return None
        try:
            if s.lower().startswith("0x"):
                return int(s, 16) & 0xFFFFFFFF
            if re.fullmatch(r"-?\d+", s):
                return int(s, 10) & 0xFFFFFFFF
        except ValueError:
            return None
    return None


def event_name(e: Dict[str, Any]) -> str:
    vals = []
    for key in ("event", "type", "op", "kind"):
        v = e.get(key)
        if isinstance(v, str):
            vals.append(v.lower().strip())
    return " ".join(vals)


def is_indirect_event(e: Dict[str, Any]) -> bool:
    name = event_name(e)
    if any(tok in name for tok in ("indirect", "bri", "calli", "branch_indirect", "call_indirect")):
        return True
    flow = e.get("flow")
    return isinstance(flow, str) and flow.lower() in {"indirect", "bri", "calli"}


def iter_traces(paths: Iterable[str]):
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    yield path, line_no, None
                    continue
                if isinstance(obj, dict):
                    yield path, line_no, obj


def main() -> int:
    ap = argparse.ArgumentParser(description="Derive state-seeding hints from trace JSONL")
    ap.add_argument("--trace", action="append", required=True, help="Trace JSONL (repeatable)")
    ap.add_argument("--out-json", required=True, help="Output JSON report")
    ap.add_argument("--out-txt", default="", help="Optional text report")
    ap.add_argument("--top", type=int, default=20, help="Top-N rows in text report")
    args = ap.parse_args()

    traces = [os.path.abspath(p) for p in args.trace]
    missing = [p for p in traces if not os.path.isfile(p)]
    if missing:
        raise SystemExit(f"missing trace file(s): {', '.join(missing)}")

    lines_total = 0
    bad_json = 0
    events_total = 0
    indirect_events = 0

    src_reg_events = Counter()
    zero_src_reg_events = Counter()
    nonzero_src_reg_events = Counter()
    prov_type_counts = Counter()
    mmio_terminal_counts = Counter()

    # addr -> count where a load provenance produced zero value.
    mem_seed_gaps = Counter()

    # reg -> count where source register was zero at indirect event.
    reg_seed_gaps = Counter()

    for _path, _line, obj in iter_traces(traces):
        lines_total += 1
        if obj is None:
            bad_json += 1
            continue
        events_total += 1
        if not is_indirect_event(obj):
            continue

        indirect_events += 1

        src_reg = obj.get("src_reg")
        if isinstance(src_reg, str):
            src_reg_events[src_reg] += 1

        src_value = parse_u32(obj.get("src_value") or obj.get("reg_value"))
        if isinstance(src_reg, str):
            if src_value is None or src_value == 0:
                zero_src_reg_events[src_reg] += 1
                if src_reg != "r0":
                    reg_seed_gaps[src_reg] += 1
            else:
                nonzero_src_reg_events[src_reg] += 1

        prov = obj.get("provenance")
        if isinstance(prov, dict):
            ptype = prov.get("type")
            if isinstance(ptype, str):
                prov_type_counts[ptype] += 1

            mem_addr = parse_u32(prov.get("mem_addr") or prov.get("addr"))
            mem_value = parse_u32(prov.get("mem_value") or prov.get("value"))

            if mem_addr is not None:
                if MMIO_START <= mem_addr < MMIO_END:
                    mmio_terminal_counts[mem_addr] += 1
                if mem_value is None or mem_value == 0:
                    mem_seed_gaps[mem_addr] += 1

            # One-level backchain if available.
            base = prov.get("base")
            if isinstance(base, dict):
                breg = base.get("reg")
                bval = parse_u32(base.get("value"))
                if isinstance(breg, str) and breg != "r0" and (bval is None or bval == 0):
                    reg_seed_gaps[breg] += 1

    def fmt_addr(a: int) -> str:
        return f"0x{a:08X}"

    out = {
        "meta": {
            "generator": "generate_state_from_trace.py",
            "schema": "state-gap-report-v1",
            "trace_files": traces,
            "lines_total": lines_total,
            "bad_json": bad_json,
            "events_total": events_total,
            "indirect_events": indirect_events,
        },
        "register_activity": {
            "all": dict(src_reg_events),
            "zero": dict(zero_src_reg_events),
            "nonzero": dict(nonzero_src_reg_events),
        },
        "provenance_types": dict(prov_type_counts),
        "register_seed_candidates": [
            {
                "reg": reg,
                "zero_events": cnt,
                "total_events": src_reg_events.get(reg, cnt),
            }
            for reg, cnt in reg_seed_gaps.most_common()
        ],
        "memory_seed_candidates": [
            {"addr": fmt_addr(addr), "count": cnt, "is_mmio": MMIO_START <= addr < MMIO_END}
            for addr, cnt in mem_seed_gaps.most_common()
        ],
        "mmio_terminal_sources": [
            {"addr": fmt_addr(addr), "count": cnt}
            for addr, cnt in mmio_terminal_counts.most_common()
        ],
        "suggested_state_patch": {
            "registers": {
                item["reg"]: "0x00000001"
                for item in [
                    {"reg": reg, "count": cnt}
                    for reg, cnt in reg_seed_gaps.most_common(8)
                ]
            },
            "memory_u32": {
                fmt_addr(addr): "0x00000001"
                for addr, _cnt in mem_seed_gaps.most_common(16)
                if not (MMIO_START <= addr < MMIO_END)
            },
            "mmio_stubs": {
                fmt_addr(addr): "0x00000001"
                for addr, _cnt in mmio_terminal_counts.most_common(16)
            },
            "note": "Suggested values are placeholders; replace with hardware-consistent values.",
        },
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out_json)), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    if args.out_txt:
        os.makedirs(os.path.dirname(os.path.abspath(args.out_txt)), exist_ok=True)
        with open(args.out_txt, "w", encoding="utf-8") as f:
            f.write("=== State Gap Report ===\n")
            f.write(f"trace files:      {len(traces)}\n")
            f.write(f"lines total:      {lines_total}\n")
            f.write(f"bad json:         {bad_json}\n")
            f.write(f"events total:     {events_total}\n")
            f.write(f"indirect events:  {indirect_events}\n")
            f.write("\nTop register seed candidates:\n")
            for reg, cnt in reg_seed_gaps.most_common(args.top):
                f.write(
                    f"  {reg}: zero={cnt} total={src_reg_events.get(reg, cnt)} nonzero={nonzero_src_reg_events.get(reg, 0)}\n"
                )
            f.write("\nTop memory seed candidates:\n")
            for addr, cnt in mem_seed_gaps.most_common(args.top):
                kind = "MMIO" if MMIO_START <= addr < MMIO_END else "RAM"
                f.write(f"  {fmt_addr(addr)} {kind} count={cnt}\n")
            f.write("\nMMIO terminal provenance:\n")
            for addr, cnt in mmio_terminal_counts.most_common(args.top):
                f.write(f"  {fmt_addr(addr)} count={cnt}\n")

    print("=== generate_state_from_trace ===")
    print(f"indirect events: {indirect_events}")
    print(f"register gaps:   {len(reg_seed_gaps)}")
    print(f"memory gaps:     {len(mem_seed_gaps)}")
    print(f"json:            {os.path.abspath(args.out_json)}")
    if args.out_txt:
        print(f"report:          {os.path.abspath(args.out_txt)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
