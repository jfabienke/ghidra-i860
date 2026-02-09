#!/usr/bin/env python3
"""Shard a Ghidra fact-pack into per-function JSON dossiers for LLM agents.

Each shard contains one function plus its 1-hop neighborhood:
  - function record
  - blocks, edges, instructions within function
  - refs and strings touched by the function
  - dispatch_unresolved records for bri sites
  - callees / callers (summary only)
  - context tags: r15_cluster, mmio_accesses, deny_range_proximity

Usage:
    python -m scripts.swarm.shard <factpack_dir> [--out <output_dir>]
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path


# ---------- loading helpers ----------

def load_jsonl(path):
    """Load a JSONL file into a list of dicts."""
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_json(path):
    """Load a JSON file into a dict."""
    with open(path, "r") as f:
        return json.load(f)


# ---------- address helpers ----------

def addr_int(hex_str):
    """Parse hex address string to int."""
    if hex_str is None:
        return None
    return int(hex_str, 16)


def addr_hex(val):
    """Format int as hex address string."""
    if val is None:
        return None
    return f"0x{val:08x}"


def ranges_overlap(a_start, a_end, b_start, b_end):
    """Check if two ranges [a_start, a_end] and [b_start, b_end] overlap."""
    return a_start <= b_end and b_start <= a_end


# ---------- r15 cluster detection ----------

R15_ORH_PATTERN_IMM = 0x6514  # orh 0x6514, r15, *


def is_r15_cluster_insn(insn):
    """Check if instruction is orh 0x6514, r15, * pattern."""
    if insn.get("mnemonic") != "orh":
        return False
    operands = insn.get("operands", "")
    return "0x6514" in operands and "r15" in operands


# ---------- MMIO detection ----------

# Known ND MMIO ranges
MMIO_RANGES = [
    (0x00004000, 0x00007FFF, "ND_CSR"),  # ND board CSR
    (0xF80B4000, 0xF80C5FFF, "ND_DATA"),  # __DATA segment
]

MMIO_TAG_ADDRS = {
    0x0000401C: "MMIO_401C_token_read",
    0x00004018: "MMIO_4018",
    0x00004020: "MMIO_4020",
}


def detect_mmio(insn):
    """Return MMIO tag if instruction accesses a known MMIO address."""
    tag = insn.get("mmio_tag")
    if tag:
        return tag
    # Check operands for known MMIO addresses
    operands = insn.get("operands", "")
    for addr_val, tag_name in MMIO_TAG_ADDRS.items():
        if f"0x{addr_val:x}" in operands or f"0x{addr_val:04x}" in operands:
            return tag_name
    return None


# ---------- main sharding logic ----------

class FactPackSharder:
    """Shard a fact-pack into per-function dossiers."""

    def __init__(self, factpack_dir):
        self.factpack_dir = Path(factpack_dir)
        self.meta = None
        self.functions = []
        self.blocks = []
        self.edges = []
        self.insns = []
        self.refs = []
        self.strings = []
        self.dispatch_unresolved = []

        # Indices built during load
        self.func_by_entry = {}         # entry_addr_int -> func record
        self.blocks_by_func = defaultdict(list)
        self.insns_by_func = defaultdict(list)
        self.insns_by_addr = {}
        self.edges_by_src = defaultdict(list)
        self.edges_by_dst = defaultdict(list)
        self.refs_by_from = defaultdict(list)
        self.dispatch_by_func = defaultdict(list)

        # Derived
        self.func_addr_ranges = {}      # entry_int -> (start, end)
        self.callees_of = defaultdict(set)   # entry_int -> set of callee entry_ints
        self.callers_of = defaultdict(set)   # entry_int -> set of caller entry_ints

    def load(self):
        """Load all fact-pack files and build indices."""
        self.meta = load_json(self.factpack_dir / "meta.json")
        self.functions = load_jsonl(self.factpack_dir / "functions.jsonl")
        self.blocks = load_jsonl(self.factpack_dir / "blocks.jsonl")
        self.edges = load_jsonl(self.factpack_dir / "edges.jsonl")
        self.insns = load_jsonl(self.factpack_dir / "insns.jsonl")
        self.refs = load_jsonl(self.factpack_dir / "refs.jsonl")
        self.strings = load_jsonl(self.factpack_dir / "strings.jsonl")
        self.dispatch_unresolved = load_jsonl(
            self.factpack_dir / "dispatch_unresolved.jsonl"
        )
        self._build_indices()

    def _build_indices(self):
        """Build lookup indices for efficient sharding."""
        # Function index
        for func in self.functions:
            entry = addr_int(func["entry"])
            self.func_by_entry[entry] = func
            end = entry + func["size"] - 1 if func["size"] > 0 else entry
            self.func_addr_ranges[entry] = (entry, end)

        # Blocks by function
        for block in self.blocks:
            fe = block.get("func_entry")
            if fe:
                self.blocks_by_func[addr_int(fe)].append(block)

        # Instructions by function and address
        for insn in self.insns:
            fe = insn.get("func_entry")
            addr = addr_int(insn["addr"])
            self.insns_by_addr[addr] = insn
            if fe:
                self.insns_by_func[addr_int(fe)].append(insn)

        # Edges by src/dst
        for edge in self.edges:
            src = addr_int(edge["src"])
            self.edges_by_src[src].append(edge)
            if edge.get("dst"):
                dst = addr_int(edge["dst"])
                self.edges_by_dst[dst].append(edge)

        # Refs by from address
        for ref in self.refs:
            self.refs_by_from[addr_int(ref["from"])].append(ref)

        # Dispatch unresolved by function
        for disp in self.dispatch_unresolved:
            fe = disp.get("func_entry")
            if fe:
                self.dispatch_by_func[addr_int(fe)].append(disp)

        # Build call graph from edges
        for func_entry, func_insns in self.insns_by_func.items():
            for insn in func_insns:
                src = addr_int(insn["addr"])
                for edge in self.edges_by_src.get(src, []):
                    if edge["kind"] == "call" and edge.get("dst"):
                        callee = addr_int(edge["dst"])
                        if callee in self.func_by_entry:
                            self.callees_of[func_entry].add(callee)
                            self.callers_of[callee].add(func_entry)

    def shard_function(self, func_entry_int):
        """Produce a complete shard for one function."""
        func = self.func_by_entry[func_entry_int]
        f_start, f_end = self.func_addr_ranges[func_entry_int]

        # Blocks in this function
        func_blocks = self.blocks_by_func.get(func_entry_int, [])

        # Instructions in this function
        func_insns = self.insns_by_func.get(func_entry_int, [])

        # Edges: any edge where src or dst is in an instruction of this function
        func_addrs = {addr_int(i["addr"]) for i in func_insns}
        func_edges = []
        seen_edges = set()
        for a in func_addrs:
            for e in self.edges_by_src.get(a, []):
                key = (e["src"], e.get("dst"), e["kind"])
                if key not in seen_edges:
                    func_edges.append(e)
                    seen_edges.add(key)
            for e in self.edges_by_dst.get(a, []):
                key = (e["src"], e.get("dst"), e["kind"])
                if key not in seen_edges:
                    func_edges.append(e)
                    seen_edges.add(key)

        # Refs from this function's instructions
        func_refs = []
        for a in func_addrs:
            func_refs.extend(self.refs_by_from.get(a, []))

        # Strings within function address range
        func_strings = [
            s for s in self.strings
            if addr_int(s["addr"]) is not None
            and f_start <= addr_int(s["addr"]) <= f_end
        ]

        # Dispatch unresolved
        func_dispatch = self.dispatch_by_func.get(func_entry_int, [])

        # 1-hop callees (summary)
        callees = []
        for callee_entry in sorted(self.callees_of.get(func_entry_int, set())):
            cf = self.func_by_entry.get(callee_entry)
            if cf:
                callees.append({
                    "entry": cf["entry"],
                    "name": cf["name"],
                    "size": cf["size"],
                    "has_unresolved_bri": cf.get("has_unresolved_bri", False),
                })

        # 1-hop callers (summary)
        callers = []
        for caller_entry in sorted(self.callers_of.get(func_entry_int, set())):
            cf = self.func_by_entry.get(caller_entry)
            if cf:
                callers.append({
                    "entry": cf["entry"],
                    "name": cf["name"],
                    "size": cf["size"],
                    "has_unresolved_bri": cf.get("has_unresolved_bri", False),
                })

        # Context tags
        r15_cluster = any(is_r15_cluster_insn(i) for i in func_insns)
        mmio_accesses = []
        mmio_seen = set()
        for insn in func_insns:
            tag = detect_mmio(insn)
            if tag and tag not in mmio_seen:
                mmio_accesses.append({
                    "addr": insn["addr"],
                    "tag": tag,
                })
                mmio_seen.add(tag)

        # Nearby deny ranges
        deny_ranges = self.meta.get("deny_ranges", [])
        nearby_deny = []
        for dr in deny_ranges:
            dr_start = addr_int(dr["start"])
            dr_end = addr_int(dr["end"])
            if ranges_overlap(f_start, f_end, dr_start, dr_end):
                nearby_deny.append(dr)

        # Nearby embedded objects
        embedded = self.meta.get("embedded_non_i860_objects", [])
        nearby_embedded = []
        for eo in embedded:
            eo_start = addr_int(eo["start"])
            eo_end = addr_int(eo["end"])
            if ranges_overlap(f_start, f_end, eo_start, eo_end):
                nearby_embedded.append(eo)

        # Priority tags for routing
        priority_tags = []
        if r15_cluster:
            priority_tags.append("r15_gstate_cluster")
        if func.get("has_unresolved_bri"):
            priority_tags.append("unresolved_bri")
        if mmio_accesses:
            priority_tags.append("mmio_access")
        if any("MMIO_401C" in m.get("tag", "") for m in mmio_accesses):
            priority_tags.append("postscript_dispatch")
        # FP-heavy detection
        fp_mnemonics = {"fadd", "fsub", "fmul", "pfadd", "pfsub", "pfmul",
                        "fmlow", "frcp", "frsqr", "fix", "ftrunc",
                        "pfam", "pfsm", "pfmam", "pfmsm"}
        fp_count = sum(1 for i in func_insns
                       if i.get("mnemonic", "").split(".")[0] in fp_mnemonics)
        if len(func_insns) > 0 and fp_count / len(func_insns) >= 0.25:
            priority_tags.append("fp_heavy")

        return {
            "schema_version": "shard-v1",
            "factpack_source": str(self.factpack_dir),
            "function": func,
            "blocks": func_blocks,
            "edges": func_edges,
            "insns": func_insns,
            "refs": func_refs,
            "strings": func_strings,
            "dispatch_unresolved": func_dispatch,
            "callees": callees,
            "callers": callers,
            "context": {
                "r15_cluster": r15_cluster,
                "mmio_accesses": mmio_accesses,
                "nearby_deny_ranges": nearby_deny,
                "nearby_embedded_objects": nearby_embedded,
                "priority_tags": priority_tags,
            },
        }

    def shard_all(self, output_dir):
        """Shard all functions and write to output directory."""
        output_dir = Path(output_dir)
        shards_dir = output_dir / "shards"
        shards_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "schema_version": "manifest-v1",
            "factpack_source": str(self.factpack_dir),
            "binary_sha256": self.meta.get("executable_sha256"),
            "language_id": self.meta.get("language_id"),
            "compiler_spec": self.meta.get("compiler_spec"),
            "function_count": len(self.functions),
            "shards": [],
        }

        for func in self.functions:
            entry = addr_int(func["entry"])
            shard = self.shard_function(entry)

            filename = f"{func['entry']}_{func['name']}.json"
            shard_path = shards_dir / filename
            with open(shard_path, "w") as f:
                json.dump(shard, f, indent=2)

            manifest["shards"].append({
                "entry": func["entry"],
                "name": func["name"],
                "size": func["size"],
                "insn_count": len(shard["insns"]),
                "priority_tags": shard["context"]["priority_tags"],
                "file": f"shards/{filename}",
            })

        # Sort manifest shards by priority for routing
        def priority_sort_key(s):
            tags = s["priority_tags"]
            score = 0
            if "r15_gstate_cluster" in tags:
                score -= 100
            if "postscript_dispatch" in tags:
                score -= 90
            if "unresolved_bri" in tags:
                score -= 50
            if "mmio_access" in tags:
                score -= 30
            if "fp_heavy" in tags:
                score -= 10
            # Larger functions are more informative
            score -= s["size"] / 10000
            return score

        manifest["shards"].sort(key=priority_sort_key)

        manifest_path = output_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Shard a Ghidra fact-pack into per-function dossiers"
    )
    parser.add_argument("factpack_dir", help="Path to fact-pack directory")
    parser.add_argument(
        "--out", "-o",
        help="Output directory (default: <factpack_dir>/../sharded/)",
    )
    args = parser.parse_args()

    factpack_dir = Path(args.factpack_dir)
    if not (factpack_dir / "meta.json").exists():
        print(f"Error: {factpack_dir}/meta.json not found", file=sys.stderr)
        sys.exit(1)

    if args.out:
        output_dir = Path(args.out)
    else:
        output_dir = factpack_dir.parent / "sharded"

    print(f"Loading fact-pack from {factpack_dir}")
    sharder = FactPackSharder(factpack_dir)
    sharder.load()

    print(f"Loaded: {len(sharder.functions)} functions, "
          f"{len(sharder.insns)} insns, "
          f"{len(sharder.edges)} edges")

    print(f"Sharding to {output_dir}")
    manifest = sharder.shard_all(output_dir)

    print(f"\nManifest written: {output_dir}/manifest.json")
    print(f"Shards: {len(manifest['shards'])}")

    # Summary by priority
    tag_counts = defaultdict(int)
    for s in manifest["shards"]:
        for tag in s["priority_tags"]:
            tag_counts[tag] += 1
    if tag_counts:
        print("\nPriority tag distribution:")
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
            print(f"  {tag}: {count}")


if __name__ == "__main__":
    main()
