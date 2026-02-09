#!/usr/bin/env python3
"""Generate a hard exclusion recovery map for ND i860 kernel analysis.

The map is designed for I860Analyze.java and contains:
- allow_ranges: full executable text range
- deny_ranges: hard-exclusion ranges from
  1) embedded non-i860 Mach-O objects
  2) x86-like blocks
  3) zero-heavy blocks
  4) ASCII-heavy blocks
- seeds: existing curated seeds + out-of-range branch targets recovered from
  ND_i860_VERIFIED_clean.bin
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple


LC_SEGMENT = 0x1
CPU_TYPE_I860 = 15


@dataclass
class Range:
    start: int
    end: int
    name: str


@dataclass
class BlockFeatures:
    start: int
    end: int
    zero_pct: float
    ascii_pct: float
    x86_score: int


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def read_u32(data: bytes, off: int, be: bool) -> int:
    b = data[off : off + 4]
    return int.from_bytes(b, "big" if be else "little", signed=False)


def merge_ranges(ranges: Iterable[Range]) -> List[Range]:
    items = sorted(ranges, key=lambda r: (r.start, r.end, r.name))
    if not items:
        return []
    out: List[Range] = []
    cur_start = items[0].start
    cur_end = items[0].end
    reasons = Counter([items[0].name])

    for r in items[1:]:
        if r.start <= cur_end + 1:
            cur_end = max(cur_end, r.end)
            reasons[r.name] += 1
            continue
        label = "+".join(sorted(reasons.keys()))
        out.append(Range(cur_start, cur_end, label))
        cur_start = r.start
        cur_end = r.end
        reasons = Counter([r.name])

    label = "+".join(sorted(reasons.keys()))
    out.append(Range(cur_start, cur_end, label))
    return out


def addrs_from_seeds(seeds: Iterable[dict]) -> List[int]:
    out: List[int] = []
    for s in seeds:
        if not isinstance(s, dict):
            continue
        raw = s.get("addr")
        if raw is None:
            continue
        try:
            out.append(int(str(raw), 0))
        except ValueError:
            continue
    return sorted(set(out))


def detect_embedded_non_i860_macho(text: bytes, base: int) -> List[Range]:
    ranges: List[Range] = []
    n = len(text)

    for off in range(0, n - 28, 4):
        word_be = int.from_bytes(text[off : off + 4], "big", signed=False)
        is_be = word_be == 0xFEEDFACE
        is_le = word_be == 0xCEFAEDFE
        if not is_be and not is_le:
            continue

        be = is_be
        cpu = read_u32(text, off + 4, be)

        # Skip primary header-like match at start and i860 objects.
        if off == 0 or cpu == CPU_TYPE_I860:
            continue

        ncmds = read_u32(text, off + 16, be)
        sizeofcmds = read_u32(text, off + 20, be)

        max_file_end = 28 + sizeofcmds
        cmd_off = off + 28
        for _ in range(ncmds):
            if cmd_off + 8 > n:
                break
            cmd = read_u32(text, cmd_off, be)
            cmd_size = read_u32(text, cmd_off + 4, be)
            if cmd_size < 8 or cmd_off + cmd_size > n:
                break

            if cmd == LC_SEGMENT and cmd_off + 40 <= n:
                file_off = read_u32(text, cmd_off + 32, be)
                file_size = read_u32(text, cmd_off + 36, be)
                seg_end = file_off + file_size
                if seg_end > max_file_end:
                    max_file_end = seg_end

            cmd_off += cmd_size

        abs_start = base + off
        abs_end = min(base + n - 1, abs_start + max_file_end - 1)
        ranges.append(Range(abs_start, abs_end, f"embedded_macho_cpu_{cpu}"))

    return merge_ranges(ranges)


def block_features(text: bytes, base: int, block_size: int) -> List[BlockFeatures]:
    out: List[BlockFeatures] = []
    n = len(text)

    for off in range(0, n, block_size):
        chunk = text[off : off + block_size]
        if not chunk:
            continue

        zeros = sum(1 for b in chunk if b == 0)
        printable = sum(
            1
            for b in chunk
            if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D)
        )

        x86 = 0
        for i in range(0, len(chunk) - 1):
            b0 = chunk[i]
            b1 = chunk[i + 1]
            if b0 == 0x55 and b1 in (0x89, 0x8B):
                x86 += 3
            elif b0 == 0x5D and b1 == 0xC3:
                x86 += 3
            elif b0 == 0xC3:
                x86 += 2
            elif b0 == 0xC2:
                x86 += 1
            elif b0 == 0xE8:
                x86 += 2
            elif b0 == 0xE9:
                x86 += 1
            elif b0 == 0x83 and b1 in (0xEC, 0xC4):
                x86 += 2
            elif b0 == 0xFF and (b1 & 0x38) == 0x10:
                x86 += 1

        start = base + off
        end = start + len(chunk) - 1
        out.append(
            BlockFeatures(
                start=start,
                end=end,
                zero_pct=(zeros * 100.0) / len(chunk),
                ascii_pct=(printable * 100.0) / len(chunk),
                x86_score=x86,
            )
        )

    return out


def classify_block_denies(
    feats: Iterable[BlockFeatures],
    zero_threshold: float,
    ascii_threshold: float,
    x86_threshold: int,
    protected_addrs: Iterable[int],
) -> List[Range]:
    protected = sorted(set(int(a) for a in protected_addrs))

    def is_protected(start: int, end: int) -> bool:
        for a in protected:
            if a < start:
                continue
            if a > end:
                return False
            return True
        return False

    out: List[Range] = []
    for f in feats:
        if is_protected(f.start, f.end):
            continue
        if f.zero_pct >= zero_threshold:
            out.append(Range(f.start, f.end, "zero_heavy"))
            continue
        if f.ascii_pct >= ascii_threshold:
            out.append(Range(f.start, f.end, "ascii_heavy"))
            continue
        if f.x86_score >= x86_threshold:
            out.append(Range(f.start, f.end, "x86_signature"))
            continue
    return merge_ranges(out)


def pcode_hotspot_denies(
    log_text: str,
    *,
    text_start: int,
    text_end: int,
    min_count: int,
    radius: int,
    protected_addrs: Iterable[int],
) -> List[Range]:
    protected = sorted(set(int(a) for a in protected_addrs))

    def overlaps_protected(start: int, end: int) -> bool:
        for a in protected:
            if a < start:
                continue
            if a > end:
                return False
            return True
        return False

    hits: Counter[int] = Counter()
    for line in log_text.splitlines():
        marker = "Pcode error at "
        if marker not in line:
            continue
        try:
            idx = line.index(marker) + len(marker)
            token = line[idx : idx + 8]
            addr = int(token, 16)
            hits[addr] += 1
        except Exception:
            continue

    ranges: List[Range] = []
    for addr, count in hits.items():
        if count < min_count:
            continue
        if addr < text_start or addr > text_end:
            continue
        start = max(text_start, addr - radius)
        end = min(text_end, addr + 4 + radius)
        # Keep 4-byte alignment for instruction boundaries.
        start &= ~0x3
        end &= ~0x3
        if end < start:
            continue
        if overlaps_protected(start, end):
            continue
        ranges.append(Range(start, end, f"pcode_hotspot_x{count}"))

    return merge_ranges(ranges)


def decode_out_of_range_branch_targets(
    clean: bytes,
    clean_base: int,
    full_text_end: int,
) -> List[int]:
    clean_end = clean_base + len(clean) - 1
    targets = set()

    for off in range(0, len(clean) - 3, 4):
        pc = clean_base + off
        w = int.from_bytes(clean[off : off + 4], "little", signed=False)
        op6 = (w >> 26) & 0x3F

        target = None
        if op6 in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
            disp = sign_extend(w & 0x03FF_FFFF, 26)
            target = (pc + ((disp << 2) + 4)) & 0xFFFFFFFF
        elif op6 in (0x14, 0x15, 0x16, 0x17, 0x2D):
            sb = ((w >> 5) & 0xF800) | (w & 0x07FF)
            disp = sign_extend(sb & 0xFFFF, 16)
            target = (pc + ((disp << 2) + 4)) & 0xFFFFFFFF

        if target is None:
            continue
        if (target & 3) != 0:
            continue

        # Targets beyond clean file but within full __TEXT section.
        if target > clean_end and target <= full_text_end and target >= clean_base:
            targets.add(target)

    return sorted(targets)


def load_existing_map(path: Path | None) -> Tuple[List[dict], List[dict], List[dict]]:
    if path is None or not path.exists():
        return ([], [], [])
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    allow = data.get("allow_ranges", [])
    deny = data.get("deny_ranges", [])
    seeds = data.get("seeds", [])
    return (allow, deny, seeds)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--text-bin", type=Path, required=True)
    p.add_argument("--clean-bin", type=Path, required=True)
    p.add_argument("--out-map", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--base-addr", type=lambda s: int(s, 0), default=0xF8000000)
    p.add_argument("--block-size", type=lambda s: int(s, 0), default=0x400)
    p.add_argument("--zero-threshold", type=float, default=85.0)
    p.add_argument("--ascii-threshold", type=float, default=80.0)
    p.add_argument("--x86-threshold", type=int, default=40)
    p.add_argument("--existing-map", type=Path, default=None)
    p.add_argument("--seed-limit", type=int, default=0, help="0 means no limit")
    p.add_argument("--pcode-log", type=Path, default=None)
    p.add_argument("--pcode-min-count", type=int, default=2)
    p.add_argument("--pcode-radius", type=lambda s: int(s, 0), default=0x20)
    args = p.parse_args()

    text = args.text_bin.read_bytes()
    clean = args.clean_bin.read_bytes()

    base = args.base_addr
    text_end = base + len(text) - 1

    existing_allow, existing_deny, existing_seeds = load_existing_map(args.existing_map)
    protected_addrs = addrs_from_seeds(existing_seeds)

    macho_denies = detect_embedded_non_i860_macho(text, base)
    feats = block_features(text, base, args.block_size)
    byte_denies = classify_block_denies(
        feats,
        zero_threshold=args.zero_threshold,
        ascii_threshold=args.ascii_threshold,
        x86_threshold=args.x86_threshold,
        protected_addrs=protected_addrs,
    )

    hotspot_denies: List[Range] = []
    if args.pcode_log is not None and args.pcode_log.exists():
        hotspot_denies = pcode_hotspot_denies(
            args.pcode_log.read_text(encoding="utf-8", errors="ignore"),
            text_start=base,
            text_end=text_end,
            min_count=max(1, args.pcode_min_count),
            radius=max(0, args.pcode_radius),
            protected_addrs=protected_addrs,
        )

    merged_denies = merge_ranges(
        list(macho_denies) + list(byte_denies) + list(hotspot_denies)
    )

    out_targets = decode_out_of_range_branch_targets(clean, base, text_end)
    if args.seed_limit > 0:
        out_targets = out_targets[: args.seed_limit]

    # Preserve existing curated seeds and append decode-only out-of-range seeds.
    seeds = list(existing_seeds)
    existing_seed_addrs = {
        int(str(s.get("addr", "0")), 0)
        for s in seeds
        if isinstance(s, dict) and s.get("addr") is not None
    }

    appended = 0
    for t in out_targets:
        if t in existing_seed_addrs:
            continue
        seeds.append(
            {
                "addr": f"0x{t:08X}",
                "name": f"oor_branch_seed_{t:08X}",
                "create_function": False,
            }
        )
        appended += 1

    # Keep broad allow range for the whole extracted __TEXT section; this makes
    # deny ranges act as a hard mask.
    allow_ranges = [{"start": f"0x{base:08X}", "end": f"0x{text_end:08X}", "name": "full_text_allow"}]

    out = {
        "meta": {
            "name": "nd-kernel-hard-mask-recovery-map",
            "version": "1",
            "notes": "Generated hard exclusion mask (embedded Mach-O/x86 + zero/ascii) plus out-of-range branch seeds.",
            "source_text": str(args.text_bin),
            "source_clean": str(args.clean_bin),
            "base_addr": f"0x{base:08X}",
            "text_end": f"0x{text_end:08X}",
            "block_size": args.block_size,
            "thresholds": {
                "zero_pct": args.zero_threshold,
                "ascii_pct": args.ascii_threshold,
                "x86_score": args.x86_threshold,
                "pcode_min_count": args.pcode_min_count,
                "pcode_radius": args.pcode_radius,
            },
            "stats": {
                "existing_allow_ranges": len(existing_allow),
                "existing_deny_ranges": len(existing_deny),
                "existing_seed_count": len(existing_seeds),
                "embedded_macho_deny_ranges": len(macho_denies),
                "byte_heuristic_deny_ranges": len(byte_denies),
                "pcode_hotspot_deny_ranges": len(hotspot_denies),
                "merged_deny_ranges": len(merged_denies),
                "out_of_range_branch_targets": len(out_targets),
                "out_of_range_seeds_appended": appended,
            },
        },
        "allow_ranges": allow_ranges,
        "deny_ranges": [
            {"start": f"0x{r.start:08X}", "end": f"0x{r.end:08X}", "name": r.name}
            for r in merged_denies
        ],
        "seeds": seeds,
    }

    args.out_map.parent.mkdir(parents=True, exist_ok=True)
    with args.out_map.open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    total_denied_bytes = sum((r.end - r.start + 1) for r in merged_denies)
    lines = [
        "Hard Mask Recovery Map Generation",
        f"text_bin: {args.text_bin}",
        f"clean_bin: {args.clean_bin}",
        f"base: 0x{base:08X}",
        f"text_end: 0x{text_end:08X}",
        f"text_size: {len(text):,} bytes",
        f"embedded_macho_ranges: {len(macho_denies)}",
        f"byte_heuristic_ranges: {len(byte_denies)}",
        f"pcode_hotspot_ranges: {len(hotspot_denies)}",
        f"merged_deny_ranges: {len(merged_denies)}",
        f"denied_bytes: {total_denied_bytes:,}",
        f"out_of_range_targets: {len(out_targets)}",
        f"seeds_appended: {appended}",
        f"final_seed_count: {len(seeds)}",
    ]

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"wrote_map: {args.out_map}")
    print(f"wrote_report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
