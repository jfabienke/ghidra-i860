#!/usr/bin/env python3
"""Find cross-version PSDriver routine candidates using strict i860 fingerprints.

This script matches hand-written i860 assembly routines from source against a
linear disassembly listing by:

1. Normalizing instruction signatures (mnemonic + operands).
2. Searching for exact n-gram matches (long sequences) in the target listing.
3. Scoring/cluster ranking with rarity weighting.
4. Running explicit anchor checks for key run32/mask32 idioms.

The matcher is intentionally conservative: if strong anchors are missing, it
reports low confidence even if scattered short n-gram hits exist.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


IMM_RE = re.compile(r"(?<![A-Za-z_])[-+]?(?:0x[0-9a-fA-F]+|\d+)(?![A-Za-z_])")
SPACE_RE = re.compile(r"\s+")
DISASM_RE = re.compile(r"^(0x[0-9a-fA-F]+):\s+([A-Za-z0-9_.]+)\s*(.*)$")


def normalize_instruction(text: str) -> str:
    t = text.strip().lower()
    if not t:
        return ""
    t = t.replace("%", "")
    # Keep register numbers (r16/f12) intact; replace immediates/offsets.
    t = IMM_RE.sub("#", t)
    t = SPACE_RE.sub(" ", t)
    return t.strip()


def parse_source_function(path: Path, label: str) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    target = f"{label}:".lower()
    in_fn = False
    out: list[str] = []

    for raw in lines:
        # Strip // comments from source asm.
        line = raw.split("//", 1)[0].rstrip()
        low = line.strip().lower()
        if not in_fn:
            if low == target:
                in_fn = True
            continue

        if not low:
            continue
        # stop if another global label starts
        if low.startswith(".globl "):
            break

        # Accept "label:" and "label: insn" forms.
        if ":" in low:
            before, after = low.split(":", 1)
            # Local labels are part of the function; keep only trailing insn.
            if not after.strip():
                continue
            low = after.strip()

        # Ignore directives.
        if low.startswith("."):
            continue

        sig = normalize_instruction(low)
        if sig:
            out.append(sig)

    return out


@dataclass
class BinInsn:
    addr: int
    sig: str
    mnemonic: str
    operands: str


def parse_disassembly(path: Path) -> list[BinInsn]:
    out: list[BinInsn] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = DISASM_RE.match(line.strip())
        if not m:
            continue
        addr_s, mnem, ops = m.groups()
        addr = int(addr_s, 16)
        sig = normalize_instruction(f"{mnem} {ops}".strip())
        out.append(BinInsn(addr=addr, sig=sig, mnemonic=mnem.lower(), operands=ops.strip()))
    return out


def build_ngram_index(seq: list[str], n: int) -> dict[tuple[str, ...], list[int]]:
    idx: dict[tuple[str, ...], list[int]] = defaultdict(list)
    if len(seq) < n:
        return idx
    for i in range(len(seq) - n + 1):
        idx[tuple(seq[i : i + n])].append(i)
    return idx


def cluster_positions(
    bin_insns: list[BinInsn],
    weighted_hits: list[dict[str, Any]],
    cluster_gap: int,
) -> list[dict[str, Any]]:
    if not weighted_hits:
        return []
    weighted_hits = sorted(weighted_hits, key=lambda h: h["pos"])
    clusters: list[list[dict[str, Any]]] = []
    cur = [weighted_hits[0]]
    for h in weighted_hits[1:]:
        if h["pos"] - cur[-1]["pos"] <= cluster_gap:
            cur.append(h)
        else:
            clusters.append(cur)
            cur = [h]
    clusters.append(cur)

    out: list[dict[str, Any]] = []
    for c in clusters:
        start_pos = c[0]["pos"]
        end_pos = max(h["pos"] + h["n"] for h in c) - 1
        start_addr = f"0x{bin_insns[start_pos].addr:08x}"
        end_addr = f"0x{bin_insns[min(end_pos, len(bin_insns)-1)].addr:08x}"
        score = sum(h["score"] for h in c)
        out.append(
            {
                "start_addr": start_addr,
                "end_addr": end_addr,
                "score": round(score, 2),
                "hit_count": len(c),
                "ns": sorted({h["n"] for h in c}, reverse=True),
                "sample_hits": [
                    {
                        "addr": f"0x{bin_insns[h['pos']].addr:08x}",
                        "n": h["n"],
                        "src_offset": h["src_i"],
                        "weight": round(h["score"], 2),
                    }
                    for h in c[:10]
                ],
            }
        )
    out.sort(key=lambda x: x["score"], reverse=True)
    return out


def run_match(
    name: str,
    src_seq: list[str],
    bin_insns: list[BinInsn],
    n_min: int,
    n_max: int,
    max_occ: int,
    cluster_gap: int,
    anchors: list[str],
) -> dict[str, Any]:
    bin_seq = [b.sig for b in bin_insns]
    weighted_hits: list[dict[str, Any]] = []
    ngram_stats: list[dict[str, Any]] = []

    for n in range(n_max, n_min - 1, -1):
        if len(src_seq) < n:
            continue
        idx = build_ngram_index(bin_seq, n)
        total = 0
        matched = 0
        for i in range(len(src_seq) - n + 1):
            ng = tuple(src_seq[i : i + n])
            total += 1
            poss = idx.get(ng, [])
            occ = len(poss)
            if occ == 0 or occ > max_occ:
                continue
            matched += 1
            # Rarity-weighted, favor longer n.
            weight = (n * n) / occ
            for p in poss:
                weighted_hits.append({"pos": p, "n": n, "src_i": i, "score": weight})
        ngram_stats.append(
            {"n": n, "source_ngrams": total, "matched_ngrams": matched}
        )

    ngram_clusters = cluster_positions(bin_insns, weighted_hits, cluster_gap)

    anchor_hits: list[dict[str, Any]] = []
    anchor_events: list[dict[str, Any]] = []
    for a in anchors:
        na = normalize_instruction(a)
        positions = [(idx, b) for idx, b in enumerate(bin_insns) if b.sig == na]
        for idx, b in positions:
            anchor_events.append({"anchor": a, "pos": idx, "addr": b.addr})
        anchor_hits.append(
            {
                "anchor": a,
                "normalized": na,
                "count": len(positions),
                "addresses": [f"0x{p.addr:08x}" for _, p in positions[:16]],
            }
        )

    # Cluster anchor events to rank concrete candidate regions even when n-grams drift.
    top_anchor_clusters: list[dict[str, Any]] = []
    if anchor_events:
        anchor_events.sort(key=lambda e: e["pos"])
        anchor_groups: list[list[dict[str, Any]]] = []
        cur = [anchor_events[0]]
        for e in anchor_events[1:]:
            if e["pos"] - cur[-1]["pos"] <= cluster_gap:
                cur.append(e)
            else:
                anchor_groups.append(cur)
                cur = [e]
        anchor_groups.append(cur)

        for c in anchor_groups:
            start_pos = c[0]["pos"]
            end_pos = c[-1]["pos"]
            span = end_pos - start_pos
            by_anchor: dict[str, int] = defaultdict(int)
            for e in c:
                by_anchor[e["anchor"]] += 1
            unique = len(by_anchor)
            # Heavily reward diversity of anchors in one neighborhood.
            score = unique * 100 + len(c) * 5 - (span / 8.0)
            top_anchor_clusters.append(
                {
                    "start_addr": f"0x{bin_insns[start_pos].addr:08x}",
                    "end_addr": f"0x{bin_insns[end_pos].addr:08x}",
                    "score": round(score, 2),
                    "event_count": len(c),
                    "unique_anchor_count": unique,
                    "anchor_counts": dict(sorted(by_anchor.items())),
                }
            )
        top_anchor_clusters.sort(key=lambda x: x["score"], reverse=True)

    return {
        "routine": name,
        "source_instruction_count": len(src_seq),
        "ngram_stats": ngram_stats,
        "top_clusters": ngram_clusters[:15],
        "anchor_hits": anchor_hits,
        "top_anchor_clusters": top_anchor_clusters[:15],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Find PSDriver routine fingerprints in disassembly")
    ap.add_argument("--run32-source", required=True)
    ap.add_argument("--mask32-source", required=True)
    ap.add_argument("--disasm", required=True, help="linear disassembly text file")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--n-min", type=int, default=4)
    ap.add_argument("--n-max", type=int, default=9)
    ap.add_argument("--max-occ", type=int, default=12, help="skip n-grams that occur too often")
    ap.add_argument("--cluster-gap", type=int, default=128)
    args = ap.parse_args()

    run32_seq = parse_source_function(Path(args.run32_source), "_ConstantRunMark32")
    mask32_seq = parse_source_function(Path(args.mask32_source), "_ConstantMasksMark32")
    bin_insns = parse_disassembly(Path(args.disasm))

    run32_anchors = [
        "fmov.ss f16,f17",
        "fmlow.dd f8,f12,f10",
        "ld.s 0(r22),r16",
        "ld.s 2(r22),r17",
        "subu r17,r16,r16",
        "and 7,r18,r0",
        "fst.d f16,8(r18)++",
        "bla r26,r31,#",
        "bla r26,r16,#",
        "fst.l f16,4(r18)++",
    ]
    mask32_anchors = [
        "bri r5",
        "ld.b 0(r22),r18",
        "ld.l 0(r22),r18",
        "shl 24,r18,r18",
        "shr 28,r18,r16",
        "shl 4,r16,r16",
        "adds r30,r16,r16",
        "bri r16",
    ]

    run32 = run_match(
        "ConstantRunMark32",
        run32_seq,
        bin_insns,
        args.n_min,
        args.n_max,
        args.max_occ,
        args.cluster_gap,
        run32_anchors,
    )
    mask32 = run_match(
        "ConstantMasksMark32",
        mask32_seq,
        bin_insns,
        args.n_min,
        args.n_max,
        args.max_occ,
        args.cluster_gap,
        mask32_anchors,
    )

    out = {
        "schema_version": "psdriver-fingerprint-v1",
        "disasm": str(Path(args.disasm).resolve()),
        "binary_instruction_count": len(bin_insns),
        "params": {
            "n_min": args.n_min,
            "n_max": args.n_max,
            "max_occ": args.max_occ,
            "cluster_gap": args.cluster_gap,
        },
        "results": [run32, mask32],
    }
    Path(args.out_json).write_text(json.dumps(out, indent=2), encoding="utf-8")

    # concise console summary
    print(f"Disasm insns: {len(bin_insns)}")
    for r in out["results"]:
        top = r["top_clusters"][0] if r["top_clusters"] else None
        if top:
            print(
                f"{r['routine']}: top cluster {top['start_addr']}..{top['end_addr']} "
                f"score={top['score']} hits={top['hit_count']}"
            )
        else:
            print(f"{r['routine']}: no n-gram clusters")
        ah = [(a["anchor"], a["count"]) for a in r["anchor_hits"]]
        print("  anchors:", ", ".join(f"{a}={c}" for a, c in ah))
    print(f"Wrote: {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
