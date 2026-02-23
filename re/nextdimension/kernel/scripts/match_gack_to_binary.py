#!/usr/bin/env python3
"""Match GaCK source functions to recovered binary functions using anchor scoring.

Compatibility mode is automatically enabled when source_version != target_version.
In compatibility mode (e.g., NeXTSTEP 2.0 source against 3.3 binary), matches are
conservative and default to candidate_compat unless hardware-invariant evidence is strong.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "gack-binary-match-v2"


def parse_u32(text: str) -> int | None:
    t = text.strip().lower()
    try:
        if t.startswith("-0x"):
            return (-int(t[3:], 16)) & 0xFFFFFFFF
        if t.startswith("+0x"):
            return int(t[3:], 16) & 0xFFFFFFFF
        if t.startswith("0x"):
            return int(t, 16) & 0xFFFFFFFF
        return int(t, 10) & 0xFFFFFFFF
    except ValueError:
        return None


def low16_set(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for tok in tokens:
        if not isinstance(tok, str):
            continue
        v = parse_u32(tok)
        if v is None:
            continue
        out.add(f"0x{(v & 0xFFFF):04x}")
    return out


def classify_evidence(mmio_overlap: int, exact_imm: int, low16_overlap: int, call_delta: int) -> str:
    if mmio_overlap >= 2:
        return "hardware_invariant"
    if exact_imm >= 2 and low16_overlap >= 2:
        return "constant_anchor"
    if exact_imm >= 1 and call_delta <= 1:
        return "shape_plus_constant"
    return "weak_similarity"


def score_pair(src: dict, binf: dict, compatibility_mode: bool) -> dict:
    src_imm = set(src.get("imm_consts", []))
    src_mmio = set(src.get("mmio_consts", []))
    src_low16 = low16_set(list(src_imm | src_mmio))
    src_mmio_low16 = low16_set(list(src_mmio))

    bin_imm = set(binf.get("imm_consts", []))
    bin_mmio_off = set(binf.get("mmio_offsets", []))
    bin_low16 = low16_set(list(bin_imm | bin_mmio_off))

    exact_imm = len(src_imm & bin_imm)
    low16_overlap = len(src_low16 & bin_low16)
    mmio_overlap = len(src_mmio_low16 & bin_low16)

    src_calls = len(src.get("calls", []))
    bin_calls = len(binf.get("call_targets", []))
    call_delta = abs(src_calls - bin_calls)

    # Invariants first, then weaker shape/similarity hints.
    s_mmio = min(45, mmio_overlap * 15)
    s_exact = min(24, exact_imm * 6)
    s_low16 = min(16, low16_overlap * 2)
    s_call = max(0, 6 - min(call_delta, 6))
    s_strings = 2 if src.get("string_literals") and binf.get("string_refs") else 0
    s_unresolved_penalty = -6 if binf.get("has_unresolved_bri") else 0

    evidence_type = classify_evidence(mmio_overlap, exact_imm, low16_overlap, call_delta)

    invariant_count = 0
    if mmio_overlap >= 1:
        invariant_count += 1
    if exact_imm >= 2:
        invariant_count += 1
    if low16_overlap >= 4:
        invariant_count += 1

    compat_adjust = 0
    if compatibility_mode:
        # Guard against over-matching across major version drift.
        if invariant_count == 0:
            compat_adjust -= 20
        elif invariant_count >= 2:
            compat_adjust += 12

    total = max(0, s_mmio + s_exact + s_low16 + s_call + s_strings + s_unresolved_penalty + compat_adjust)

    evidence = {
        "evidence_type": evidence_type,
        "invariant_count": invariant_count,
        "exact_imm_overlap": exact_imm,
        "low16_overlap": low16_overlap,
        "mmio_low16_overlap": mmio_overlap,
        "src_call_count": src_calls,
        "bin_call_count": bin_calls,
        "bin_has_unresolved_bri": bool(binf.get("has_unresolved_bri")),
        "score_breakdown": {
            "mmio_invariant": s_mmio,
            "exact_imm": s_exact,
            "low16": s_low16,
            "call_shape": s_call,
            "strings": s_strings,
            "unresolved_penalty": s_unresolved_penalty,
            "compat_adjust": compat_adjust,
        },
    }

    return {"score": total, "evidence": evidence}


def score_to_confidence(score: int, compatibility_mode: bool, invariant_count: int) -> int:
    base = max(0, min(99, score))
    if not compatibility_mode:
        return base

    # In compatibility mode cap confidence unless invariant evidence is strong.
    if invariant_count >= 2:
        return min(85, base)
    if invariant_count == 1:
        return min(59, base)
    return min(39, base)


def classify_match(score: int, compatibility_mode: bool, evidence_type: str, invariant_count: int) -> str:
    if not compatibility_mode:
        if score >= 70:
            return "strong_direct"
        if score >= 45:
            return "candidate_direct"
        return "weak_direct"

    if evidence_type == "hardware_invariant" and invariant_count >= 2 and score >= 55:
        return "strong_compat"
    if score >= 24:
        return "candidate_compat"
    return "weak_compat"


def main() -> int:
    ap = argparse.ArgumentParser(description="Match GaCK source functions to binary functions")
    ap.add_argument("--source", required=True, help="source_functions.json path")
    ap.add_argument("--binary", required=True, help="binary_functions.json path")
    ap.add_argument("--out-json", required=True, help="output match JSON")
    ap.add_argument("--out-csv", required=True, help="output ranked CSV")
    ap.add_argument("--min-score", type=int, default=24, help="minimum score for greedy assignment")
    ap.add_argument("--top-k", type=int, default=8, help="number of candidates to keep per binary function")
    ap.add_argument("--source-version", default="", help="Override source version label")
    ap.add_argument("--target-version", default="", help="Override target version label")
    args = ap.parse_args()

    src_doc = json.loads(Path(args.source).read_text(encoding="utf-8"))
    bin_doc = json.loads(Path(args.binary).read_text(encoding="utf-8"))

    src_rows = src_doc.get("functions", [])
    bin_rows = bin_doc.get("functions", [])

    source_version = args.source_version or src_doc.get("source_version") or "unknown"
    target_version = args.target_version or bin_doc.get("target_version") or "unknown"
    compatibility_mode = source_version != target_version

    all_pairs: list[dict] = []
    by_binary: dict[str, list[dict]] = {}

    for b in bin_rows:
        bkey = str(b.get("entry", ""))
        if not bkey:
            continue
        ranked: list[dict] = []
        for s in src_rows:
            scored = score_pair(s, b, compatibility_mode)
            evidence = scored["evidence"]
            confidence = score_to_confidence(scored["score"], compatibility_mode, int(evidence["invariant_count"]))
            match_class = classify_match(
                scored["score"],
                compatibility_mode,
                str(evidence["evidence_type"]),
                int(evidence["invariant_count"]),
            )
            pair = {
                "binary_entry": bkey,
                "binary_name": b.get("name", ""),
                "source_name": s.get("name", ""),
                "source_file": s.get("file", ""),
                "source_line": s.get("line", 0),
                "score": scored["score"],
                "confidence": confidence,
                "match_class": match_class,
                "evidence": evidence,
                "provenance": {
                    "source_version": source_version,
                    "target_version": target_version,
                    "compatibility_mode": compatibility_mode,
                },
            }
            ranked.append(pair)
            all_pairs.append(pair)
        ranked.sort(key=lambda r: (-r["score"], r["source_file"], r["source_line"], r["source_name"]))
        by_binary[bkey] = ranked[: max(1, args.top_k)]

    all_pairs.sort(
        key=lambda r: (
            -r["score"],
            r["binary_entry"],
            r["source_file"],
            int(r["source_line"]),
            r["source_name"],
        )
    )

    assigned_binary: set[str] = set()
    assigned_source: set[tuple[str, str, int]] = set()
    matches: list[dict] = []

    for pair in all_pairs:
        if pair["score"] < args.min_score:
            break
        src_key = (pair["source_file"], pair["source_name"], int(pair["source_line"]))
        bin_key = pair["binary_entry"]
        if bin_key in assigned_binary or src_key in assigned_source:
            continue
        assigned_binary.add(bin_key)
        assigned_source.add(src_key)
        matches.append(pair)

    class_counts: dict[str, int] = {}
    for m in matches:
        c = str(m.get("match_class", "unknown"))
        class_counts[c] = class_counts.get(c, 0) + 1

    out = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_path": str(Path(args.source).resolve()),
        "binary_path": str(Path(args.binary).resolve()),
        "summary": {
            "source_count": len(src_rows),
            "binary_count": len(bin_rows),
            "pairs_scored": len(all_pairs),
            "top_k": args.top_k,
            "min_score": args.min_score,
            "matched_count": len(matches),
            "source_version": source_version,
            "target_version": target_version,
            "compatibility_mode": compatibility_mode,
            "match_class_counts": class_counts,
        },
        "matches": matches,
        "candidates_by_binary": [
            {
                "binary_entry": b,
                "binary_name": rows[0]["binary_name"] if rows else "",
                "candidates": rows,
            }
            for b, rows in sorted(by_binary.items())
        ],
    }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "binary_entry",
                "binary_name",
                "source_name",
                "source_file",
                "source_line",
                "score",
                "confidence",
                "match_class",
                "evidence_type",
                "exact_imm_overlap",
                "low16_overlap",
                "mmio_low16_overlap",
                "src_call_count",
                "bin_call_count",
                "bin_has_unresolved_bri",
            ]
        )
        for row in matches:
            ev = row["evidence"]
            w.writerow(
                [
                    row["binary_entry"],
                    row["binary_name"],
                    row["source_name"],
                    row["source_file"],
                    row["source_line"],
                    row["score"],
                    row["confidence"],
                    row["match_class"],
                    ev["evidence_type"],
                    ev["exact_imm_overlap"],
                    ev["low16_overlap"],
                    ev["mmio_low16_overlap"],
                    ev["src_call_count"],
                    ev["bin_call_count"],
                    int(bool(ev["bin_has_unresolved_bri"])),
                ]
            )

    print("=== match_gack_to_binary ===")
    print(f"source functions:   {len(src_rows)}")
    print(f"binary functions:   {len(bin_rows)}")
    print(f"pairs scored:       {len(all_pairs)}")
    print(f"source_version:     {source_version}")
    print(f"target_version:     {target_version}")
    print(f"compatibility_mode: {compatibility_mode}")
    print(f"matches (greedy):   {len(matches)}")
    print(f"match classes:      {class_counts}")
    print(f"output json:        {out_json}")
    print(f"output csv:         {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
