#!/usr/bin/env python3
"""Layer generic and compiler-specific intent rules over i860 factpacks.

This script keeps the base rule layer architecture-agnostic (`GENERIC_*`) and
adds a compiler/toolchain overlay (`COMPILER_*`) on top. The output is a
side-by-side comparison of generic-only ranking versus layered ranking.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuleDef:
    name: str
    layer: str
    description: str


GENERIC_RULES: tuple[RuleDef, ...] = (
    RuleDef("GENERIC_NO_MMIO_SIDE_EFFECTS", "generic", "Function has zero MMIO-tagged instructions."),
    RuleDef("GENERIC_NO_STRING_REFS", "generic", "Function has zero recovered string references."),
    RuleDef("GENERIC_NO_UNRESOLVED_BRI", "generic", "Function is not flagged with unresolved computed branch."),
    RuleDef("GENERIC_COMPACT_BODY_LE_64_INSNS", "generic", "Function body is compact (<= 64 decoded instructions)."),
)

COMPILER_RULES: tuple[RuleDef, ...] = (
    RuleDef(
        "COMPILER_DELAY_SLOT_NOP_PATTERN",
        "compiler",
        "At least one delayed control-transfer instruction has a canonical NOP delay slot.",
    ),
    RuleDef(
        "COMPILER_ORH_OR_CONST_BUILD",
        "compiler",
        "Contains GCC-style 32-bit constant materialization (`orh` then `or` on same destination).",
    ),
    RuleDef(
        "COMPILER_SHL_SHRA_SIGNEXT_PAIR",
        "compiler",
        "Contains `shl` -> `shra` immediate pair consistent with backend sign-extension idioms.",
    ),
    RuleDef(
        "COMPILER_FP_ESCAPE_PRESENT",
        "compiler",
        "Contains at least one FP escape opcode (op6=0x12).",
    ),
    RuleDef(
        "COMPILER_FP_SAVE_RESTORE_SHELL",
        "compiler",
        "Contains FP save/restore shell shape (`fst.q` + `fld.q` + `ret`).",
    ),
)

# Delayed-transfer opcodes in i860 encoding space.
DELAYED_OPS = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x2D, 0x10}


@dataclass
class Insn:
    addr: int
    word: int
    op6: int
    src2: int
    dest: int
    src1: int
    escop: int
    mnemonic: str
    mmio_tag: str | None
    string_ref: str | None


@dataclass
class FunctionRec:
    entry: str
    name: str
    size: int
    has_unresolved_bri: bool
    insns: list[Insn]


@dataclass
class RuntimeConstCheck:
    label: str
    full_block_present: bool
    full_block_offset: str | None
    subpattern_hits: dict[str, int]


def infer_compiler_generation_likelihood(run_33: dict[str, Any], run_42: dict[str, Any]) -> dict[str, Any]:
    """Infer compiler generation continuity between 3.3 and 4.2.

    Returns a score and one of:
      - same-lineage
      - possible-newer
      - unknown
    """

    strong_rules = [
        "COMPILER_DELAY_SLOT_NOP_PATTERN",
        "COMPILER_ORH_OR_CONST_BUILD",
        "COMPILER_SHL_SHRA_SIGNEXT_PAIR",
        "COMPILER_FP_SAVE_RESTORE_SHELL",
    ]
    weak_rules = [
        "COMPILER_FP_ESCAPE_PRESENT",
    ]

    c33 = run_33["rule_hit_counts"]
    c42 = run_42["rule_hit_counts"]

    strong_diff = sum(abs(int(c33.get(r, 0)) - int(c42.get(r, 0))) for r in strong_rules)
    weak_diff = sum(abs(int(c33.get(r, 0)) - int(c42.get(r, 0))) for r in weak_rules)

    f33 = max(int(run_33["function_evaluated_count"]), 1)
    f42 = max(int(run_42["function_evaluated_count"]), 1)
    rate_diff = sum(
        abs((int(c33.get(r, 0)) / f33) - (int(c42.get(r, 0)) / f42))
        for r in (strong_rules + weak_rules)
    )

    rt33 = bool(run_33["runtime860_const_probe"]["full_block_present"])
    rt42 = bool(run_42["runtime860_const_probe"]["full_block_present"])
    runtime_mismatch = rt33 != rt42

    # Higher means more likely a compiler-generation shift.
    delta_score = min(
        100,
        (strong_diff * 20)
        + (weak_diff * 5)
        + (25 if runtime_mismatch else 0)
        + int(min(20, rate_diff * 100)),
    )

    evidence_strength = (
        sum((int(c33.get(r, 0)) + int(c42.get(r, 0))) for r in strong_rules) * 1.0
        + sum((int(c33.get(r, 0)) + int(c42.get(r, 0))) for r in weak_rules) * 0.5
        + (3.0 if rt33 else 0.0)
        + (3.0 if rt42 else 0.0)
    )

    if delta_score >= 35:
        generation_bin = "possible-newer"
    elif evidence_strength < 1.0:
        generation_bin = "unknown"
    else:
        generation_bin = "same-lineage"

    if evidence_strength < 2.0:
        confidence = "low"
    elif evidence_strength < 8.0:
        confidence = "medium"
    else:
        confidence = "high"

    reasons: list[str] = []
    reasons.append(f"strong_rule_delta={strong_diff}")
    reasons.append(f"weak_rule_delta={weak_diff}")
    reasons.append(f"runtime_const_mismatch={runtime_mismatch}")
    reasons.append(f"normalized_rate_delta={rate_diff:.4f}")
    reasons.append(f"evidence_strength={evidence_strength:.2f}")

    return {
        "schema": "compiler-generation-likelihood-v1",
        "bin": generation_bin,
        "delta_score": delta_score,
        "confidence": confidence,
        "reasons": reasons,
        "components": {
            "strong_rule_delta": strong_diff,
            "weak_rule_delta": weak_diff,
            "runtime_const_mismatch": runtime_mismatch,
            "normalized_rate_delta": rate_diff,
            "evidence_strength": evidence_strength,
        },
        "bins": {
            "same-lineage": "low delta score with at least minimal evidence",
            "possible-newer": "material cross-version delta in compiler-specific signatures",
            "unknown": "insufficient signature evidence for a stable call",
        },
    }


def parse_hex(s: str) -> int:
    return int(s, 16)


def fmt_hex(v: int) -> str:
    return f"0x{v:08x}"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def build_functions(factpack: Path) -> dict[str, FunctionRec]:
    functions = load_jsonl(factpack / "functions.jsonl")
    insns = load_jsonl(factpack / "insns.jsonl")

    out: dict[str, FunctionRec] = {}
    for row in functions:
        entry = str(row.get("entry", "")).lower()
        if not entry:
            continue
        out[entry] = FunctionRec(
            entry=entry,
            name=str(row.get("name", "")),
            size=int(row.get("size", 0) or 0),
            has_unresolved_bri=bool(row.get("has_unresolved_bri", False)),
            insns=[],
        )

    for row in insns:
        fe = row.get("func_entry")
        if not isinstance(fe, str):
            continue
        key = fe.lower()
        rec = out.get(key)
        if rec is None:
            continue

        word_s = row.get("word")
        if not isinstance(word_s, str) or not word_s.startswith("0x"):
            continue

        word = int(word_s, 16)
        rec.insns.append(
            Insn(
                addr=parse_hex(str(row.get("addr", "0x0"))),
                word=word,
                op6=(word >> 26) & 0x3F,
                src2=(word >> 21) & 0x1F,
                dest=(word >> 16) & 0x1F,
                src1=(word >> 11) & 0x1F,
                escop=word & 0x7,
                mnemonic=str(row.get("mnemonic", "")),
                mmio_tag=row.get("mmio_tag") if isinstance(row.get("mmio_tag"), str) else None,
                string_ref=row.get("string_ref") if isinstance(row.get("string_ref"), str) else None,
            )
        )

    for rec in out.values():
        rec.insns.sort(key=lambda i: i.addr)

    return out


def has_calli_delayed(insn: Insn) -> bool:
    return insn.op6 == 0x13 and insn.escop == 0x2


def count_delay_slot_nops(insns: list[Insn]) -> int:
    c = 0
    for i in range(len(insns) - 1):
        cur = insns[i]
        nxt = insns[i + 1]
        delayed = (cur.op6 in DELAYED_OPS) or has_calli_delayed(cur)
        if delayed and nxt.word == 0:
            c += 1
    return c


def count_orh_or_pairs(insns: list[Insn]) -> int:
    c = 0
    for i in range(len(insns) - 1):
        a = insns[i]
        b = insns[i + 1]
        if a.op6 == 0x3B and b.op6 == 0x39 and b.src2 == a.dest and b.dest == a.dest:
            c += 1
    return c


def count_shl_shra_pairs(insns: list[Insn]) -> int:
    c = 0
    for i in range(len(insns) - 1):
        a = insns[i]
        b = insns[i + 1]
        # shl imm (0x29) then shra imm (0x2F), feeding same destination.
        if a.op6 == 0x29 and b.op6 == 0x2F and b.src2 == a.dest and b.dest == a.dest:
            c += 1
    return c


def count_fp_escape(insns: list[Insn]) -> int:
    return sum(1 for i in insns if i.op6 == 0x12)


def count_ret(insns: list[Insn]) -> int:
    return sum(1 for i in insns if i.op6 == 0x10 and i.src1 == 1)


def evaluate_function(rec: FunctionRec) -> dict[str, Any]:
    insns = rec.insns
    insn_count = len(insns)
    mmio_count = sum(1 for i in insns if i.mmio_tag)
    string_count = sum(1 for i in insns if i.string_ref)

    delay_nop_count = count_delay_slot_nops(insns)
    orh_or_count = count_orh_or_pairs(insns)
    shl_shra_count = count_shl_shra_pairs(insns)
    fp_escape_count = count_fp_escape(insns)
    fstq_count = sum(1 for i in insns if i.mnemonic == "fst.q")
    fldq_count = sum(1 for i in insns if i.mnemonic == "fld.q")
    ret_count = count_ret(insns)

    generic_hits = {
        "GENERIC_NO_MMIO_SIDE_EFFECTS": mmio_count == 0,
        "GENERIC_NO_STRING_REFS": string_count == 0,
        "GENERIC_NO_UNRESOLVED_BRI": not rec.has_unresolved_bri,
        "GENERIC_COMPACT_BODY_LE_64_INSNS": insn_count <= 64,
    }

    compiler_hits = {
        "COMPILER_DELAY_SLOT_NOP_PATTERN": delay_nop_count > 0,
        "COMPILER_ORH_OR_CONST_BUILD": orh_or_count > 0,
        "COMPILER_SHL_SHRA_SIGNEXT_PAIR": shl_shra_count > 0,
        "COMPILER_FP_ESCAPE_PRESENT": fp_escape_count > 0,
        "COMPILER_FP_SAVE_RESTORE_SHELL": fstq_count > 0 and fldq_count > 0 and ret_count > 0,
    }

    generic_score = sum(1 for v in generic_hits.values() if v)
    # Overlay weight biases toward compiler-shape evidence.
    compiler_score = (
        (2 if compiler_hits["COMPILER_DELAY_SLOT_NOP_PATTERN"] else 0)
        + (2 if compiler_hits["COMPILER_ORH_OR_CONST_BUILD"] else 0)
        + (1 if compiler_hits["COMPILER_SHL_SHRA_SIGNEXT_PAIR"] else 0)
        + (1 if compiler_hits["COMPILER_FP_ESCAPE_PRESENT"] else 0)
        + (2 if compiler_hits["COMPILER_FP_SAVE_RESTORE_SHELL"] else 0)
    )

    if mmio_count == 0 and generic_score >= 3 and compiler_score >= 4:
        cls = "likely_compiler_generated_helper"
    elif mmio_count == 0 and generic_score >= 3 and compiler_score >= 2:
        cls = "possible_compiler_wrapper"
    elif compiler_score > 0:
        cls = "mixed_compiler_signal_in_product_code"
    else:
        cls = "likely_product_or_dispatch"

    return {
        "entry": rec.entry,
        "name": rec.name,
        "size": rec.size,
        "insn_count": insn_count,
        "mmio_count": mmio_count,
        "string_ref_count": string_count,
        "has_unresolved_bri": rec.has_unresolved_bri,
        "shape_counters": {
            "delay_slot_nop_count": delay_nop_count,
            "orh_or_pair_count": orh_or_count,
            "shl_shra_pair_count": shl_shra_count,
            "fp_escape_count": fp_escape_count,
            "fstq_count": fstq_count,
            "fldq_count": fldq_count,
            "ret_count": ret_count,
        },
        "generic_hits": generic_hits,
        "compiler_hits": compiler_hits,
        "generic_score": generic_score,
        "compiler_score": compiler_score,
        "layered_score": generic_score + compiler_score,
        "classification": cls,
    }


def find_runtime860_constants(binary_path: Path, label: str) -> RuntimeConstCheck:
    blob = binary_path.read_bytes()

    # NDTools runtime860/_i860rt.s constants:
    # two52two31, two, onepluseps, two52
    constants = [
        0x43300000,
        0x80000000,
        0x40000000,
        0x00000000,
        0x3FF00000,
        0x00001000,
        0x43300000,
        0x00000000,
    ]
    full_le = b"".join(struct.pack("<I", x) for x in constants)
    full_be = b"".join(struct.pack(">I", x) for x in constants)

    full_off = blob.find(full_le)
    if full_off < 0:
        full_off = blob.find(full_be)

    subpatterns = {
        "two52two31": [0x43300000, 0x80000000],
        "onepluseps": [0x3FF00000, 0x00001000],
        "two52": [0x43300000, 0x00000000],
    }
    hits: dict[str, int] = {}
    for name, vals in subpatterns.items():
        p_le = b"".join(struct.pack("<I", x) for x in vals)
        p_be = b"".join(struct.pack(">I", x) for x in vals)
        cnt = 0
        i = 0
        while True:
            j = blob.find(p_le, i)
            if j < 0:
                break
            cnt += 1
            i = j + 1
        i = 0
        while True:
            j = blob.find(p_be, i)
            if j < 0:
                break
            cnt += 1
            i = j + 1
        hits[name] = cnt

    return RuntimeConstCheck(
        label=label,
        full_block_present=full_off >= 0,
        full_block_offset=(fmt_hex(full_off) if full_off >= 0 else None),
        subpattern_hits=hits,
    )


def summarize(label: str, factpack: Path, binary_path: Path) -> dict[str, Any]:
    funcs = build_functions(factpack)
    evals = [evaluate_function(rec) for rec in funcs.values() if rec.insns]

    rule_hits: dict[str, int] = {r.name: 0 for r in GENERIC_RULES + COMPILER_RULES}
    for e in evals:
        for name, hit in e["generic_hits"].items():
            if hit:
                rule_hits[name] += 1
        for name, hit in e["compiler_hits"].items():
            if hit:
                rule_hits[name] += 1

    generic_ranked = sorted(
        evals,
        key=lambda e: (
            e["generic_score"],
            -e["mmio_count"],
            -e["string_ref_count"],
            e["insn_count"],
            e["entry"],
        ),
        reverse=True,
    )

    layered_ranked = sorted(
        evals,
        key=lambda e: (
            e["layered_score"],
            e["compiler_score"],
            e["generic_score"],
            -e["mmio_count"],
            e["entry"],
        ),
        reverse=True,
    )

    by_class = defaultdict(int)
    for e in evals:
        by_class[e["classification"]] += 1

    runtime_const = find_runtime860_constants(binary_path, label)

    return {
        "label": label,
        "factpack": str(factpack),
        "binary": str(binary_path),
        "function_evaluated_count": len(evals),
        "rule_hit_counts": dict(sorted(rule_hits.items())),
        "classification_counts": dict(sorted(by_class.items())),
        "generic_top": generic_ranked[:15],
        "layered_top": layered_ranked[:20],
        "runtime860_const_probe": {
            "rule": "COMPILER_RUNTIME860_DIVMOD_CONST_BLOCK_PRESENT",
            "full_block_present": runtime_const.full_block_present,
            "full_block_offset": runtime_const.full_block_offset,
            "subpattern_hits": runtime_const.subpattern_hits,
        },
    }


def write_markdown(doc: dict[str, Any], out_md: Path) -> None:
    lines: list[str] = []
    lines.append("# Layered Intent Rules (Generic + Compiler)")
    lines.append("")
    lines.append("## Rule Naming")
    lines.append("")
    lines.append("Base layer (`GENERIC_*`) and compiler overlay (`COMPILER_*`):")
    lines.append("")
    for r in GENERIC_RULES + COMPILER_RULES:
        lines.append(f"- `{r.name}`: {r.description}")

    cg = doc.get("compiler_generation_likelihood", {})
    if cg:
        lines.append("")
        lines.append("## Compiler Generation Likelihood")
        lines.append("")
        lines.append(f"- Bin: `{cg.get('bin')}`")
        lines.append(f"- Delta score: `{cg.get('delta_score')}`")
        lines.append(f"- Confidence: `{cg.get('confidence')}`")
        lines.append("- Reasons:")
        for r in cg.get("reasons", []):
            lines.append(f"  - `{r}`")

    for run in doc["runs"]:
        lines.append("")
        lines.append(f"## {run['label']}")
        lines.append("")
        lines.append(f"- Factpack: `{run['factpack']}`")
        lines.append(f"- Binary: `{run['binary']}`")
        lines.append(f"- Functions evaluated: `{run['function_evaluated_count']}`")
        lines.append(f"- Class counts: `{json.dumps(run['classification_counts'], sort_keys=True)}`")
        lines.append("")
        lines.append("### Runtime860 Constant Probe")
        probe = run["runtime860_const_probe"]
        lines.append(f"- `{probe['rule']}`: `{probe['full_block_present']}`")
        lines.append(f"- Full-block offset: `{probe['full_block_offset']}`")
        lines.append(f"- Subpattern hits: `{json.dumps(probe['subpattern_hits'], sort_keys=True)}`")
        lines.append("")
        lines.append("### Rule Hit Counts")
        for name, n in run["rule_hit_counts"].items():
            lines.append(f"- `{name}`: `{n}`")

        lines.append("")
        lines.append("### Layered Top Candidates")
        lines.append("")
        lines.append("| Entry | Score | Class | Generic | Compiler | MMIO | Strings |")
        lines.append("|-------|------:|-------|--------:|---------:|-----:|--------:|")
        for row in run["layered_top"]:
            lines.append(
                "| "
                + f"`{row['entry']}` | {row['layered_score']} | {row['classification']} | "
                + f"{row['generic_score']} | {row['compiler_score']} | {row['mmio_count']} | {row['string_ref_count']} |"
            )

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Layer generic + compiler intent rules over factpacks")
    ap.add_argument("--factpack-33", required=True)
    ap.add_argument("--binary-33", required=True)
    ap.add_argument("--factpack-42", required=True)
    ap.add_argument("--binary-42", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    run_33 = summarize("NeXTSTEP 3.3", Path(args.factpack_33), Path(args.binary_33))
    run_42 = summarize("OPENSTEP 4.2", Path(args.factpack_42), Path(args.binary_42))
    compiler_generation_likelihood = infer_compiler_generation_likelihood(run_33, run_42)

    out = {
        "schema_version": "layered-intent-rules-v1",
        "description": "GENERIC rules with COMPILER overlay for helper-vs-product triage.",
        "compiler_generation_likelihood": compiler_generation_likelihood,
        "runs": [run_33, run_42],
    }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    write_markdown(out, out_md)

    print("=== layer_intent_rules ===")
    print(f"out_json: {out_json}")
    print(f"out_md:   {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
