#!/usr/bin/env python3
"""Convert emulator runtime trace JSONL into I860Analyze recovery-map seeds.

Expected input is JSONL with events that include runtime indirect control-flow facts.
The parser is intentionally tolerant to field naming drift.

Recognized event families:
  - indirect branch/call events:
      {"event":"indirect_branch","pc":"0xf8001234","target":"0xf8005678","kind":"bri"}
      {"type":"calli","site_pc":...,"target_pc":...}

  - optional memory/mmio events are counted for reporting only.

Output JSON matches the recovery-map schema consumed by I860Analyze.java:
  {
    "allow_ranges": [...],
    "deny_ranges": [...],
    "seeds": [
      {"addr":"0xF8005678","create_function":true,"source":"dynamic-trace",...}
    ],
    "meta": {...}
  }
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

U32_MASK = 0xFFFFFFFF


@dataclass
class TargetStats:
    target: int
    hits: int = 0
    calli_hits: int = 0
    bri_hits: int = 0
    self_loop_hits: int = 0
    non_self_hits: int = 0
    sites: set = field(default_factory=set)
    regs: Counter = field(default_factory=Counter)
    examples: List[dict] = field(default_factory=list)


@dataclass
class TraceSummary:
    files: List[str] = field(default_factory=list)
    lines_total: int = 0
    lines_bad_json: int = 0
    events_total: int = 0
    indirect_events: int = 0
    mem_events: int = 0
    mmio_events: int = 0


def parse_u32(v) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v & U32_MASK
    if isinstance(v, float):
        return int(v) & U32_MASK
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        s = s.replace("_", "")
        try:
            if s.lower().startswith("0x"):
                return int(s, 16) & U32_MASK
            if re.fullmatch(r"-?\d+", s):
                return int(s, 10) & U32_MASK
        except ValueError:
            return None
    return None


def norm_event_name(e: dict) -> str:
    parts = []
    for k in ("event", "type", "op", "kind"):
        v = e.get(k)
        if isinstance(v, str):
            parts.append(v.lower().strip())
    return " ".join(parts)


def extract_indirect_record(e: dict) -> Optional[Tuple[int, int, str, Optional[str], dict, Optional[int]]]:
    """Return (pc, target, kind, reg, evidence, src_word) for recognized indirect branch events."""
    name = norm_event_name(e)

    is_indirect = any(tok in name for tok in (
        "indirect", "bri", "calli", "branch_indirect", "call_indirect"
    ))

    if not is_indirect:
        # Some emitters use a generic event + explicit flow kind field.
        flow = e.get("flow")
        if isinstance(flow, str) and flow.lower() in {"bri", "calli", "indirect"}:
            is_indirect = True
    if not is_indirect:
        return None

    pc = None
    target = None
    for key in ("pc", "site_pc", "instruction_pc", "from", "src"):
        pc = parse_u32(e.get(key))
        if pc is not None:
            break
    for key in ("target", "target_pc", "to", "dst", "branch_target"):
        target = parse_u32(e.get(key))
        if target is not None:
            break
    if pc is None or target is None:
        return None

    kind = "indirect"
    if "calli" in name:
        kind = "calli"
    elif "bri" in name:
        kind = "bri"
    elif "call" in name and "indirect" in name:
        kind = "calli"

    reg = e.get("src_reg") or e.get("reg") or e.get("target_reg")
    if not isinstance(reg, str):
        reg = None

    ev = {
        "pc": f"0x{pc:08x}",
        "target": f"0x{target:08x}",
        "kind": kind,
    }
    if reg:
        ev["src_reg"] = reg

    src_val = parse_u32(e.get("src_value") or e.get("reg_value"))
    if src_val is not None:
        ev["src_value"] = f"0x{src_val:08x}"

    delay = parse_u32(e.get("delay_slot_pc"))
    if delay is not None:
        ev["delay_slot_pc"] = f"0x{delay:08x}"

    target_word = parse_u32(e.get("target_word") or e.get("target_u32") or e.get("target_peek"))
    if target_word is not None:
        ev["target_word"] = f"0x{target_word:08x}"

    target_next_word = parse_u32(e.get("target_next_word") or e.get("target_next_u32"))
    if target_next_word is not None:
        ev["target_next_word"] = f"0x{target_next_word:08x}"

    src_word = parse_u32(e.get("src_word") or e.get("src_u32") or e.get("src_ptr_word"))
    if src_word is not None:
        ev["src_word"] = f"0x{src_word:08x}"

    return pc, target, kind, reg, ev, src_word


def load_base_map(path: Optional[str]) -> dict:
    if not path:
        return {"allow_ranges": [], "deny_ranges": [], "seeds": []}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = {
        "allow_ranges": data.get("allow_ranges", []),
        "deny_ranges": data.get("deny_ranges", []),
        "seeds": data.get("seeds", []),
    }
    meta = data.get("meta")
    if isinstance(meta, dict):
        out["base_meta"] = meta
    return out


def score_target(stats: TargetStats) -> int:
    # Conservative scoring: reward repeatability + call-site confidence.
    score = 25
    score += min(stats.hits, 20)
    score += min(len(stats.sites) * 8, 24)
    if stats.calli_hits > 0:
        score += 18
    if stats.bri_hits > 0:
        score += 6
    if stats.hits >= 3:
        score += 8
    return min(score, 100)


def in_exec_range(addr: int, start: int, end: int) -> bool:
    return start <= addr <= end and (addr & 3) == 0


def emit_seed_entry(addr: int, create_function: bool, score: int, stats: TargetStats) -> dict:
    return {
        "addr": f"0x{addr:08X}",
        "create_function": bool(create_function),
        "source": "dynamic-trace",
        "confidence": score,
        "hit_count": stats.hits,
        "site_count": len(stats.sites),
        "kinds": sorted([k for k, v in (("calli", stats.calli_hits), ("bri", stats.bri_hits)) if v > 0]),
        "regs": dict(stats.regs),
        "examples": stats.examples[:8],
    }


def convert(
    traces: Iterable[str],
    base_map: dict,
    exec_start: int,
    exec_end: int,
    min_hits: int,
    min_sites: int,
    min_seed_score: int,
    min_create_score: int,
    reject_self_loop_only: bool,
) -> Tuple[dict, TraceSummary, dict]:
    summary = TraceSummary(files=list(traces))
    target_map: Dict[int, TargetStats] = {}
    derived_src_word_targets = 0

    for path in traces:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                summary.lines_total += 1
                s = line.strip()
                if not s:
                    continue
                try:
                    e = json.loads(s)
                except json.JSONDecodeError:
                    summary.lines_bad_json += 1
                    continue

                if not isinstance(e, dict):
                    continue
                summary.events_total += 1

                # Optional metrics only.
                name = norm_event_name(e)
                if any(t in name for t in ("mmio",)):
                    summary.mmio_events += 1
                if any(t in name for t in ("mem", "load", "store", "read", "write")):
                    summary.mem_events += 1
                space = e.get("space") or e.get("addr_space") or e.get("region")
                if isinstance(space, str) and space.lower() in {"mmio", "io"}:
                    summary.mem_events += 1
                    summary.mmio_events += 1

                rec = extract_indirect_record(e)
                if rec is None:
                    continue

                summary.indirect_events += 1
                pc, target, kind, reg, ev, src_word = rec

                st = target_map.get(target)
                if st is None:
                    st = TargetStats(target=target)
                    target_map[target] = st
                st.hits += 1
                st.sites.add(pc)
                st.examples.append(ev)
                if pc == target:
                    st.self_loop_hits += 1
                else:
                    st.non_self_hits += 1
                if kind == "calli":
                    st.calli_hits += 1
                elif kind == "bri":
                    st.bri_hits += 1
                if reg:
                    st.regs[reg] += 1

                # Fallback: if runtime target is out-of-range but src_word points to executable code,
                # treat src_word as a derived indirect target candidate.
                if (
                    src_word is not None
                    and src_word != target
                    and not in_exec_range(target, exec_start, exec_end)
                    and in_exec_range(src_word, exec_start, exec_end)
                ):
                    derived_src_word_targets += 1
                    st_alt = target_map.get(src_word)
                    if st_alt is None:
                        st_alt = TargetStats(target=src_word)
                        target_map[src_word] = st_alt
                    st_alt.hits += 1
                    st_alt.sites.add(pc)
                    if pc == src_word:
                        st_alt.self_loop_hits += 1
                    else:
                        st_alt.non_self_hits += 1
                    ev_alt = dict(ev)
                    ev_alt["derived_from"] = "src_word"
                    ev_alt["derived_target"] = f"0x{src_word:08x}"
                    st_alt.examples.append(ev_alt)
                    if kind == "calli":
                        st_alt.calli_hits += 1
                    elif kind == "bri":
                        st_alt.bri_hits += 1
                    if reg:
                        st_alt.regs[f"{reg}:src_word"] += 1

    seeds = list(base_map.get("seeds", []))
    base_seed_addrs = {
        parse_u32(s.get("addr") or s.get("address"))
        for s in seeds
        if isinstance(s, dict)
    }

    candidates = []
    rejected = []

    for target, st in target_map.items():
        if st.hits < min_hits:
            rejected.append((target, "hits"))
            continue
        if len(st.sites) < min_sites:
            rejected.append((target, "sites"))
            continue
        if not in_exec_range(target, exec_start, exec_end):
            rejected.append((target, "range_or_align"))
            continue
        if (
            reject_self_loop_only
            and st.non_self_hits == 0
            and st.self_loop_hits > 0
            and st.calli_hits == 0
        ):
            rejected.append((target, "self_loop_only"))
            continue

        score = score_target(st)
        if score < min_seed_score:
            rejected.append((target, "score"))
            continue

        create_function = score >= min_create_score or st.calli_hits > 0
        candidates.append((target, score, create_function, st))

    # Highest confidence first.
    candidates.sort(key=lambda t: (-t[1], -t[3].hits, t[0]))

    dynamic_added = 0
    for target, score, create_function, st in candidates:
        if target in base_seed_addrs:
            continue
        seeds.append(emit_seed_entry(target, create_function, score, st))
        dynamic_added += 1

    out = {
        "meta": {
            "generator": "dynamic_trace_to_recovery_map.py",
            "schema": "dynamic-recovery-map-v1",
            "dynamic_trace_files": summary.files,
            "lines_total": summary.lines_total,
            "lines_bad_json": summary.lines_bad_json,
            "events_total": summary.events_total,
            "indirect_events": summary.indirect_events,
            "mem_events": summary.mem_events,
            "mmio_events": summary.mmio_events,
            "targets_seen": len(target_map),
            "dynamic_candidates": len(candidates),
            "dynamic_added": dynamic_added,
            "derived_src_word_targets": derived_src_word_targets,
            "exec_range": {
                "start": f"0x{exec_start:08X}",
                "end": f"0x{exec_end:08X}",
            },
            "thresholds": {
                "min_hits": min_hits,
                "min_sites": min_sites,
                "min_seed_score": min_seed_score,
                "min_create_score": min_create_score,
                "reject_self_loop_only": reject_self_loop_only,
            },
        },
        "allow_ranges": base_map.get("allow_ranges", []),
        "deny_ranges": base_map.get("deny_ranges", []),
        "seeds": seeds,
    }

    details = {
        "candidates": candidates,
        "rejected": rejected,
        "target_map": target_map,
    }
    return out, summary, details


def write_report(path: str, out: dict, summary: TraceSummary, details: dict) -> None:
    candidates = details["candidates"]
    rejected = details["rejected"]

    with open(path, "w", encoding="utf-8") as f:
        f.write("=== Dynamic Trace -> Recovery Map Report ===\n")
        f.write(f"Trace files: {len(summary.files)}\n")
        for p in summary.files:
            f.write(f"  - {p}\n")
        f.write(f"Lines total:        {summary.lines_total}\n")
        f.write(f"Bad JSON lines:     {summary.lines_bad_json}\n")
        f.write(f"Events total:       {summary.events_total}\n")
        f.write(f"Indirect events:    {summary.indirect_events}\n")
        f.write(f"Memory events:      {summary.mem_events}\n")
        f.write(f"MMIO events:        {summary.mmio_events}\n")
        f.write(f"Targets seen:       {out['meta']['targets_seen']}\n")
        f.write(f"Derived src_word:   {out['meta'].get('derived_src_word_targets', 0)}\n")
        f.write(f"Candidates:         {out['meta']['dynamic_candidates']}\n")
        f.write(f"Dynamic seeds add:  {out['meta']['dynamic_added']}\n")
        f.write(f"Total seeds output: {len(out['seeds'])}\n")

        if candidates:
            f.write("\nTop candidates:\n")
            for target, score, create_function, st in candidates[:40]:
                kinds = []
                if st.calli_hits:
                    kinds.append(f"calli={st.calli_hits}")
                if st.bri_hits:
                    kinds.append(f"bri={st.bri_hits}")
                kind_txt = ", ".join(kinds) if kinds else "indirect"
                f.write(
                    f"  0x{target:08X} score={score:3d} hits={st.hits:3d} sites={len(st.sites):3d} "
                    f"self_loops={st.self_loop_hits:3d} create={str(create_function).lower()} [{kind_txt}] regs={dict(st.regs)}\n"
                )

        if rejected:
            cnt = Counter(reason for _, reason in rejected)
            f.write("\nRejected summary:\n")
            for reason, n in sorted(cnt.items(), key=lambda x: x[0]):
                f.write(f"  {reason}: {n}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert emulator trace JSONL into recovery_map seeds")
    ap.add_argument("--trace", action="append", required=True,
                    help="Path to trace JSONL (repeat for multiple files)")
    ap.add_argument("--base-map", default="",
                    help="Existing recovery_map.json to preserve allow/deny/seeds")
    ap.add_argument("--out", required=True, help="Output recovery-map JSON path")
    ap.add_argument("--report", default="", help="Optional text report path")
    ap.add_argument("--exec-start", default="0xF8000000", help="Executable range start")
    ap.add_argument("--exec-end", default="0xF80B2547", help="Executable range end")
    ap.add_argument("--min-hits", type=int, default=1)
    ap.add_argument("--min-sites", type=int, default=1)
    ap.add_argument("--min-seed-score", type=int, default=50)
    ap.add_argument("--min-create-score", type=int, default=70)
    ap.add_argument("--allow-self-loop-only", action="store_true",
                    help="Allow targets observed only as pc==target self-loops (default: reject)")

    args = ap.parse_args()

    traces = [os.path.abspath(t) for t in args.trace]
    missing = [t for t in traces if not os.path.isfile(t)]
    if missing:
        raise SystemExit(f"missing trace file(s): {', '.join(missing)}")

    base_map = load_base_map(args.base_map if args.base_map else None)

    exec_start = parse_u32(args.exec_start)
    exec_end = parse_u32(args.exec_end)
    if exec_start is None or exec_end is None:
        raise SystemExit("invalid exec range")
    if exec_start > exec_end:
        exec_start, exec_end = exec_end, exec_start

    out, summary, details = convert(
        traces=traces,
        base_map=base_map,
        exec_start=exec_start,
        exec_end=exec_end,
        min_hits=max(args.min_hits, 1),
        min_sites=max(args.min_sites, 1),
        min_seed_score=max(args.min_seed_score, 0),
        min_create_score=max(args.min_create_score, 0),
        reject_self_loop_only=not args.allow_self_loop_only,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        write_report(args.report, out, summary, details)

    print("=== dynamic_trace_to_recovery_map ===")
    print(f"traces:         {len(summary.files)}")
    print(f"events:         {summary.events_total} (indirect={summary.indirect_events})")
    print(f"targets seen:   {out['meta']['targets_seen']}")
    print(f"dynamic added:  {out['meta']['dynamic_added']}")
    print(f"output:         {os.path.abspath(args.out)}")
    if args.report:
        print(f"report:         {os.path.abspath(args.report)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
