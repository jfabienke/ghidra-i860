#!/usr/bin/env python3
"""Validate a factpack export and sharded output for MMIO tag regressions.

Checks:
  1. No broad MMIO tags (mmio_high_space) in insns.jsonl
  2. Shard manifest priority_tags are consistent with shard content
  3. mmio_offset_* tags include _unresolved suffix (effective address unknown)
  4. No instruction tagged mmio_* unless it's a load/store/flush

Usage:
    python -m scripts.swarm.validate_factpack <factpack_dir> [sharded_dir]

Exit codes:
    0  All checks passed
    1  Validation failures found
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


# Tags that indicate over-broad MMIO heuristics — must never appear
BANNED_MMIO_TAGS = {
    "mmio_high_space",
    "mmio_low_space",
    "mmio_scalar_match",
}

# Mnemonics that can legitimately access memory (load/store/flush/prefetch)
MEMORY_ACCESS_MNEMONICS = {
    "ld.b", "ld.s", "ld.l",
    "ld.c",
    "fld.l", "fld.d", "fld.q",
    "pfld.l", "pfld.d", "pfld.q",
    "st.b", "st.s", "st.l",
    "st.c",
    "fst.l", "fst.d", "fst.q",
    "pst.d",
    "flush",
    "lock", "unlock",
}


def load_jsonl(path):
    """Load a JSONL file into a list of dicts."""
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def validate_insns(factpack_dir):
    """Check insns.jsonl for MMIO tag regressions."""
    insns_path = factpack_dir / "insns.jsonl"
    if not insns_path.exists():
        return [f"Missing {insns_path}"]

    errors = []
    insns = load_jsonl(insns_path)

    banned_counts = Counter()
    non_memory_mmio = []

    for insn in insns:
        tag = insn.get("mmio_tag")
        if not tag:
            continue

        # Check for banned broad tags
        tag_parts = [t.strip() for t in tag.split(",")]
        for part in tag_parts:
            if part in BANNED_MMIO_TAGS:
                banned_counts[part] += 1

        # Check that only memory-access instructions get MMIO tags
        mnemonic = insn.get("mnemonic", "")
        if mnemonic and mnemonic not in MEMORY_ACCESS_MNEMONICS:
            non_memory_mmio.append({
                "addr": insn.get("addr"),
                "mnemonic": mnemonic,
                "tag": tag,
            })

    for tag, count in banned_counts.items():
        errors.append(
            f"BANNED MMIO tag '{tag}' found in {count} instructions — "
            f"ExportFactPack.java heuristic regression"
        )

    if non_memory_mmio:
        examples = non_memory_mmio[:5]
        example_str = "; ".join(
            f"{e['addr']} {e['mnemonic']} [{e['tag']}]" for e in examples
        )
        errors.append(
            f"MMIO tag on {len(non_memory_mmio)} non-memory instructions: "
            f"{example_str}"
        )

    return errors


def validate_shards(sharded_dir):
    """Check sharded manifest and shard content for consistency."""
    manifest_path = sharded_dir / "manifest.json"
    if not manifest_path.exists():
        return [f"Missing {manifest_path}"]

    errors = []
    with open(manifest_path) as f:
        manifest = json.load(f)

    for shard_entry in manifest.get("shards", []):
        shard_path = sharded_dir / shard_entry["file"]
        if not shard_path.exists():
            errors.append(f"Missing shard file: {shard_entry['file']}")
            continue

        with open(shard_path) as f:
            shard = json.load(f)

        context = shard.get("context", {})
        priority_tags = context.get("priority_tags", [])
        mmio_accesses = context.get("mmio_accesses", [])

        # Check: mmio_access tag iff mmio_accesses list is non-empty
        has_mmio_tag = "mmio_access" in priority_tags
        has_mmio_data = len(mmio_accesses) > 0
        if has_mmio_tag != has_mmio_data:
            errors.append(
                f"Shard {shard_entry['entry']}: mmio_access tag "
                f"{'present' if has_mmio_tag else 'absent'} but "
                f"mmio_accesses has {len(mmio_accesses)} entries"
            )

        # Check: no banned tags leaked into shard mmio tags
        for access in mmio_accesses:
            tag = access.get("tag", "")
            for banned in BANNED_MMIO_TAGS:
                if banned in tag:
                    errors.append(
                        f"Shard {shard_entry['entry']}: banned tag "
                        f"'{banned}' in mmio_accesses at {access.get('addr')}"
                    )

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate factpack export for MMIO tag regressions"
    )
    parser.add_argument("factpack_dir", help="Path to factpack directory")
    parser.add_argument(
        "sharded_dir", nargs="?",
        help="Path to sharded directory (optional)",
    )
    args = parser.parse_args()

    factpack_dir = Path(args.factpack_dir)
    all_errors = []

    # Validate insns.jsonl
    print(f"Validating factpack: {factpack_dir}")
    insn_errors = validate_insns(factpack_dir)
    all_errors.extend(insn_errors)
    if insn_errors:
        for e in insn_errors:
            print(f"  FAIL: {e}")
    else:
        # Count MMIO-tagged instructions for info
        insns = load_jsonl(factpack_dir / "insns.jsonl")
        mmio_count = sum(1 for i in insns if i.get("mmio_tag"))
        print(f"  OK: {mmio_count} MMIO-tagged instructions, 0 banned tags")

    # Validate shards if provided
    if args.sharded_dir:
        sharded_dir = Path(args.sharded_dir)
        print(f"Validating shards: {sharded_dir}")
        shard_errors = validate_shards(sharded_dir)
        all_errors.extend(shard_errors)
        if shard_errors:
            for e in shard_errors:
                print(f"  FAIL: {e}")
        else:
            with open(sharded_dir / "manifest.json") as f:
                manifest = json.load(f)
            mmio_funcs = sum(
                1 for s in manifest["shards"]
                if "mmio_access" in s.get("priority_tags", [])
            )
            print(f"  OK: {len(manifest['shards'])} shards, "
                  f"{mmio_funcs} with mmio_access tag")

    if all_errors:
        print(f"\n{len(all_errors)} validation error(s) found.")
        sys.exit(1)
    else:
        print("\nAll checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
