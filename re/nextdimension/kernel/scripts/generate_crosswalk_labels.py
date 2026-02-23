#!/usr/bin/env python3
"""Generate Ghidra label/import artifacts from crosswalk matches.

Safety policy:
- If compatibility_mode=true (e.g., 2.0 source -> 3.3 binary), labels are blocked
  by default unless --allow-compat-labels is explicitly provided.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "crosswalk-labels-v2"
SAFE_RE = re.compile(r"[^A-Za-z0-9_]")


def sanitize_name(name: str) -> str:
    s = SAFE_RE.sub("_", name.strip())
    s = re.sub(r"_+", "_", s)
    s = s.strip("_")
    if not s:
        s = "unknown"
    if s[0].isdigit():
        s = f"fn_{s}"
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate crosswalk labels for Ghidra")
    ap.add_argument("--matches", required=True, help="matches.json from match_gack_to_binary.py")
    ap.add_argument("--out-csv", required=True, help="Output CSV for labels")
    ap.add_argument("--out-json", required=True, help="Output JSON for scripted import")
    ap.add_argument("--min-confidence", type=int, default=60, help="Minimum confidence to emit")
    ap.add_argument("--prefix", default="gack_", help="Label name prefix")
    ap.add_argument(
        "--allow-compat-labels",
        action="store_true",
        help="Allow emitting labels when compatibility_mode=true",
    )
    ap.add_argument(
        "--compat-class",
        default="strong_compat",
        help="Required match_class in compatibility mode (default: strong_compat)",
    )
    args = ap.parse_args()

    doc = json.loads(Path(args.matches).read_text(encoding="utf-8"))
    rows = doc.get("matches", [])
    summary = doc.get("summary", {})
    compatibility_mode = bool(summary.get("compatibility_mode", False))

    emitted = []
    used_names: dict[str, int] = {}
    blocked_compat = 0
    blocked_class = 0

    for row in rows:
        conf = int(row.get("confidence", 0) or 0)
        if conf < args.min_confidence:
            continue

        if compatibility_mode and not args.allow_compat_labels:
            blocked_compat += 1
            continue

        match_class = str(row.get("match_class", ""))
        if compatibility_mode and match_class != args.compat_class:
            blocked_class += 1
            continue

        addr = str(row.get("binary_entry", "")).lower()
        if not addr.startswith("0x"):
            continue

        src_name = sanitize_name(str(row.get("source_name", "unknown")))
        base_name = f"{args.prefix}{src_name}"
        count = used_names.get(base_name, 0)
        used_names[base_name] = count + 1
        label = base_name if count == 0 else f"{base_name}_{count + 1}"

        emitted.append(
            {
                "addr": addr,
                "label": label,
                "confidence": conf,
                "score": int(row.get("score", 0) or 0),
                "match_class": match_class,
                "evidence_type": row.get("evidence", {}).get("evidence_type"),
                "binary_name": row.get("binary_name", ""),
                "source_name": row.get("source_name", ""),
                "source_file": row.get("source_file", ""),
                "source_line": int(row.get("source_line", 0) or 0),
                "provenance": row.get("provenance", {}),
                "evidence": row.get("evidence", {}),
            }
        )

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "addr",
                "label",
                "confidence",
                "score",
                "match_class",
                "evidence_type",
                "source_file",
                "source_line",
                "source_name",
                "binary_name",
            ]
        )
        for row in emitted:
            w.writerow(
                [
                    row["addr"],
                    row["label"],
                    row["confidence"],
                    row["score"],
                    row["match_class"],
                    row["evidence_type"],
                    row["source_file"],
                    row["source_line"],
                    row["source_name"],
                    row["binary_name"],
                ]
            )

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_matches": str(Path(args.matches).resolve()),
        "min_confidence": args.min_confidence,
        "prefix": args.prefix,
        "compatibility_mode": compatibility_mode,
        "allow_compat_labels": bool(args.allow_compat_labels),
        "compat_class": args.compat_class,
        "blocked_compat": blocked_compat,
        "blocked_class": blocked_class,
        "label_count": len(emitted),
        "labels": emitted,
    }
    out_json.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")

    print("=== generate_crosswalk_labels ===")
    print(f"input matches:     {args.matches}")
    print(f"compatibility:    {compatibility_mode}")
    print(f"allow_compat:     {bool(args.allow_compat_labels)}")
    print(f"blocked_compat:   {blocked_compat}")
    print(f"blocked_class:    {blocked_class}")
    print(f"emitted labels:   {len(emitted)}")
    print(f"output csv:       {out_csv}")
    print(f"output json:      {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
