#!/usr/bin/env python3
"""Build a ranked dispatch-breakthrough queue from call report candidates.

Inputs:
- i860_kernel_calls.txt candidate section ("CANDIDATE 0x... N refs")
- base recovery map (allow/deny ranges + existing seeds)
- optional dispatch_unresolved.jsonl for locality scoring

Outputs:
- queue_all.json
- queue_ranked.csv
- entries_topN.txt
- augmented_recovery_map.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


TEXT_START = 0xF8000000
TEXT_END = 0xF80B2547

CAND_RE = re.compile(r"^\s+CANDIDATE 0x([0-9a-fA-F]+)\s+(\d+) refs")


def fmt_hex_u32(v: int) -> str:
    return f"0x{(v & 0xFFFFFFFF):08X}"


@dataclass(frozen=True)
class Range:
    start: int
    end: int
    name: str

    def contains(self, addr: int) -> bool:
        return self.start <= addr <= self.end


def parse_ranges(rows: list[dict]) -> list[Range]:
    out: list[Range] = []
    for r in rows:
        try:
            start = int(str(r["start"]), 16)
            end = int(str(r["end"]), 16)
        except (KeyError, ValueError):
            continue
        lo, hi = (start, end) if start <= end else (end, start)
        out.append(Range(lo, hi, str(r.get("name", ""))))
    return out


def in_any(addr: int, ranges: list[Range]) -> bool:
    return any(r.contains(addr) for r in ranges)


def deny_name(addr: int, deny_ranges: list[Range]) -> str | None:
    for r in deny_ranges:
        if r.contains(addr):
            return r.name or "deny_range"
    return None


def parse_candidates(calls_report: Path) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for line in calls_report.read_text(encoding="utf-8", errors="replace").splitlines():
        m = CAND_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        refs = int(m.group(2))
        out.append((addr, refs))
    return out


def load_unresolved_sites(path: Path | None) -> list[int]:
    if path is None or not path.exists():
        return []
    out: list[int] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            addr = row.get("addr")
            if isinstance(addr, str) and addr.lower().startswith("0x"):
                try:
                    out.append(int(addr, 16))
                except ValueError:
                    pass
    return out


def score_candidate(addr: int, refs: int, unresolved_sites: list[int]) -> tuple[int, str]:
    score = refs * 100
    reasons = [f"refs={refs}"]

    if addr < 0xF8040000:
        score += 30
        reasons.append("region=clean_window")
    elif addr < 0xF8060000:
        score += 15
        reasons.append("region=mid_text")
    else:
        reasons.append("region=upper_text")

    if refs >= 3:
        score += 25
        reasons.append("multi_ref_bonus")

    if unresolved_sites:
        nearest = min(abs(addr - s) for s in unresolved_sites)
        if nearest <= 0x2000:
            prox = max(1, 40 - (nearest // 128))
            score += int(prox)
            reasons.append(f"near_unresolved=0x{nearest:X}")

    return score, ",".join(reasons)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build ranked queue to break dispatch ceiling")
    ap.add_argument(
        "--calls-report",
        default="re/nextdimension/kernel/reports/i860_kernel_calls.txt",
        help="Path to i860_kernel_calls.txt",
    )
    ap.add_argument(
        "--base-map",
        default="re/nextdimension/kernel/docs/recovery_map_hardmask_pcode.json",
        help="Base recovery map JSON",
    )
    ap.add_argument(
        "--dispatch-unresolved",
        default="re/nextdimension/kernel/reports/factpack/retagged/dispatch_unresolved.jsonl",
        help="dispatch_unresolved.jsonl for locality scoring",
    )
    ap.add_argument(
        "--out-dir",
        default="re/nextdimension/kernel/reports/dispatch_breakthrough",
        help="Output directory",
    )
    ap.add_argument(
        "--top-n",
        type=int,
        default=50,
        help="Top-N entries list for immediate sweep",
    )
    ap.add_argument(
        "--seed-count",
        type=int,
        default=56,
        help="How many ranked candidates to append into augmented map",
    )
    args = ap.parse_args()

    calls_path = Path(args.calls_report).resolve()
    base_map_path = Path(args.base_map).resolve()
    unresolved_path = Path(args.dispatch_unresolved).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not calls_path.is_file():
        raise SystemExit(f"calls report not found: {calls_path}")
    if not base_map_path.is_file():
        raise SystemExit(f"base map not found: {base_map_path}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = out_dir / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    base_map = json.loads(base_map_path.read_text(encoding="utf-8"))
    allow_ranges = parse_ranges(base_map.get("allow_ranges", []))
    deny_ranges = parse_ranges(base_map.get("deny_ranges", []))

    existing_seeds = set()
    for s in base_map.get("seeds", []):
        addr = s.get("addr")
        if isinstance(addr, str) and addr.lower().startswith("0x"):
            try:
                existing_seeds.add(int(addr, 16))
            except ValueError:
                pass

    unresolved_sites = load_unresolved_sites(unresolved_path if unresolved_path.exists() else None)

    raw = parse_candidates(calls_path)
    ranked: list[dict] = []
    dropped: list[dict] = []

    for addr, refs in raw:
        row = {
            "addr": fmt_hex_u32(addr),
            "refs": refs,
        }
        if not (TEXT_START <= addr <= TEXT_END):
            row["drop_reason"] = "out_of_text"
            dropped.append(row)
            continue
        if allow_ranges and not in_any(addr, allow_ranges):
            row["drop_reason"] = "outside_allow"
            dropped.append(row)
            continue
        dname = deny_name(addr, deny_ranges)
        if dname is not None:
            row["drop_reason"] = f"deny:{dname}"
            dropped.append(row)
            continue
        score, reason = score_candidate(addr, refs, unresolved_sites)
        row["score"] = score
        row["priority_reason"] = reason
        row["already_seeded"] = addr in existing_seeds
        ranked.append(row)

    ranked.sort(key=lambda r: (-int(r["score"]), -int(r["refs"]), r["addr"]))

    top_n = max(1, args.top_n)
    seed_count = max(0, args.seed_count)
    top_entries = ranked[:top_n]
    seed_rows = [r for r in ranked if not r["already_seeded"]][:seed_count]

    augmented = json.loads(base_map_path.read_text(encoding="utf-8"))
    seeds = list(augmented.get("seeds", []))
    for r in seed_rows:
        seeds.append(
            {
                "addr": r["addr"],
                "name": f"dispatch_candidate_{r['addr'][2:].lower()}",
                "create_function": True,
            }
        )
    augmented["seeds"] = seeds
    augmented.setdefault("meta", {})
    augmented["meta"]["dispatch_breakthrough"] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "calls_report": str(calls_path),
        "raw_candidates": len(raw),
        "allowed_candidates": len(ranked),
        "dropped_candidates": len(dropped),
        "added_seed_count": len(seed_rows),
        "top_n": top_n,
        "seed_count": seed_count,
    }

    queue_all_path = run_dir / "queue_all.json"
    queue_csv_path = run_dir / "queue_ranked.csv"
    entries_path = run_dir / "entries_topN.txt"
    augmented_map_path = run_dir / "augmented_recovery_map.json"
    dropped_path = run_dir / "dropped.json"
    summary_path = run_dir / "summary.json"

    queue_all_path.write_text(json.dumps(ranked, indent=2) + "\n", encoding="utf-8")
    dropped_path.write_text(json.dumps(dropped, indent=2) + "\n", encoding="utf-8")
    augmented_map_path.write_text(json.dumps(augmented, indent=2) + "\n", encoding="utf-8")

    with queue_csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "addr", "score", "refs", "already_seeded", "priority_reason"])
        for idx, r in enumerate(ranked, start=1):
            w.writerow([idx, r["addr"], r["score"], r["refs"], r["already_seeded"], r["priority_reason"]])

    with entries_path.open("w", encoding="utf-8") as f:
        for r in top_entries:
            f.write(r["addr"] + "\n")

    summary = {
        "schema_version": "dispatch-breakthrough-queue-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "raw_candidates": len(raw),
        "allowed_candidates": len(ranked),
        "dropped_candidates": len(dropped),
        "top_n_entries": len(top_entries),
        "added_seed_count": len(seed_rows),
        "paths": {
            "queue_all_json": str(queue_all_path),
            "queue_ranked_csv": str(queue_csv_path),
            "entries_topN_txt": str(entries_path),
            "augmented_recovery_map_json": str(augmented_map_path),
            "dropped_json": str(dropped_path),
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print("=== build_dispatch_breakthrough_queue ===")
    print(f"calls_report:        {calls_path}")
    print(f"base_map:            {base_map_path}")
    print(f"dispatch_unresolved: {unresolved_path if unresolved_path.exists() else '<none>'}")
    print(f"raw candidates:      {len(raw)}")
    print(f"allowed candidates:  {len(ranked)}")
    print(f"dropped candidates:  {len(dropped)}")
    print(f"top_n entries:       {len(top_entries)}")
    print(f"added seeds:         {len(seed_rows)}")
    print(f"out_dir:             {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
