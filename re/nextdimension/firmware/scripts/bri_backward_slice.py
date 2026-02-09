#!/usr/bin/env python3
"""Backward slicing from bri instructions to determine dispatch targets.

For each `bri rN` (indirect branch), walks backward through preceding
instructions to find what loaded the target register rN.  Classifies
each source as:
  - orh_or_const:   orh+or pair constructing a 32-bit constant (resolved!)
  - ld_table:       ld.l offset(rBase), rN -- table-based dispatch
  - ld_gstate:      ld.l offset(r15), rN -- GState field access
  - ld_reg:         ld.l R1(R2), rN -- register-indexed load
  - register_chain: written by another ALU op
  - unknown:        could not trace the write

Strategy to handle code/data mixing in TEXT section:
  1. Linear scan finds ALL words with op6=0x10 (bri encoding), but many are
     actually data (especially IEEE 754 floats near 2.0 like 0x40020000).
  2. Filter false positives using multiple heuristics:
     - bri r0 with dest field encoding small integers -> likely float data
     - Surrounding context: real bri should be preceded by valid instructions
     - Cross-reference with call/branch targets to identify code regions
  3. For validated bri, walk backward up to MAX_BACKTRACK instructions to
     find the writer of the target register.

Binary: ND_MachDriver __TEXT section from Mach-O, 200,704 bytes
        vmaddr = 0xF8000000, contains mixed code and data (PostScript strings,
        float constants, Emacs changelog data embedded in section).
"""

import json
import struct
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import i860_decode as dec

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
BINARY = Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
OUTPUT = Path(__file__).parent.parent / "analysis" / "phase1" / "bri_targets.json"
BASE_ADDR = 0xF8000000
MAX_BACKTRACK = 32

# Control flow opcodes
BRANCH_OPS = {
    dec.OP_BRI, dec.OP_BR, dec.OP_CALL,
    dec.OP_BC, dec.OP_BC_T, dec.OP_BNC, dec.OP_BNC_T,
    dec.OP_BLA, dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
    dec.OP_BTE_REG, dec.OP_BTE_IMM, dec.OP_TRAP,
}

DEST_WRITING_OPS = {
    dec.OP_LD_REG, dec.OP_LD_IMM,
    dec.OP_ADDU_REG, dec.OP_ADDU_IMM,
    dec.OP_SUBU_REG, dec.OP_SUBU_IMM,
    dec.OP_ADDS_REG, dec.OP_ADDS_IMM,
    dec.OP_SUBS_REG, dec.OP_SUBS_IMM,
    dec.OP_SHL_REG, dec.OP_SHL_IMM,
    dec.OP_SHR_REG, dec.OP_SHR_IMM,
    dec.OP_SHRA_REG, dec.OP_SHRA_IMM,
    dec.OP_AND_REG, dec.OP_AND_IMM,
    dec.OP_ANDH_IMM,
    dec.OP_ANDNOT_REG, dec.OP_ANDNOT_IMM,
    dec.OP_ANDNOTH_IMM,
    dec.OP_OR_REG, dec.OP_OR_IMM,
    dec.OP_ORH_IMM,
    dec.OP_XOR_REG, dec.OP_XOR_IMM,
    dec.OP_XORH_IMM,
}

# All opcodes that look like valid instructions (for context scoring)
CODE_LIKE_OPS = DEST_WRITING_OPS | BRANCH_OPS | {
    0x00, 0x01,  # ld.b reg/imm
    0x02,        # ixfr
    0x03,        # st.b
    0x06, 0x07,  # st reg/imm
    0x08, 0x09,  # fld reg/imm
    0x0A, 0x0B,  # fst reg/imm
    0x0C, 0x0D,  # flush reg/imm
    0x0E, 0x0F,  # pst.d reg/imm
    0x12, 0x13,  # fp_esc, core_esc
}


def opcode_name(d):
    """Human-readable opcode name."""
    names = {
        dec.OP_LD_REG: "ld_reg", dec.OP_LD_IMM: "ld_imm",
        dec.OP_ADDU_REG: "addu_reg", dec.OP_ADDU_IMM: "addu_imm",
        dec.OP_SUBU_REG: "subu_reg", dec.OP_SUBU_IMM: "subu_imm",
        dec.OP_ADDS_REG: "adds_reg", dec.OP_ADDS_IMM: "adds_imm",
        dec.OP_SUBS_REG: "subs_reg", dec.OP_SUBS_IMM: "subs_imm",
        dec.OP_SHL_REG: "shl_reg", dec.OP_SHL_IMM: "shl_imm",
        dec.OP_SHR_REG: "shr_reg", dec.OP_SHR_IMM: "shr_imm",
        dec.OP_SHRA_REG: "shra_reg", dec.OP_SHRA_IMM: "shra_imm",
        dec.OP_AND_REG: "and_reg", dec.OP_AND_IMM: "and_imm",
        dec.OP_ANDH_IMM: "andh_imm",
        dec.OP_ANDNOT_REG: "andnot_reg", dec.OP_ANDNOT_IMM: "andnot_imm",
        dec.OP_ANDNOTH_IMM: "andnoth_imm",
        dec.OP_OR_REG: "or_reg", dec.OP_OR_IMM: "or_imm",
        dec.OP_ORH_IMM: "orh_imm",
        dec.OP_XOR_REG: "xor_reg", dec.OP_XOR_IMM: "xor_imm",
        dec.OP_XORH_IMM: "xorh_imm",
        dec.OP_FP_ESC: "fp_escape", dec.OP_CORE_ESC: "core_escape",
        dec.OP_BR: "br", dec.OP_CALL: "call",
    }
    return names.get(d['op6'], f"op{d['op6']:02x}")


def dest_reg(d):
    """Return destination register, or None if instruction doesn't write one."""
    op = d['op6']
    if op in DEST_WRITING_OPS:
        return d['dest']
    if op == dec.OP_CALL:
        return 1
    if op == dec.OP_CORE_ESC and d['escop'] == dec.ESC_CALLI:
        return 1
    return None


# -----------------------------------------------------------------------
# Code region scoring
# -----------------------------------------------------------------------

def code_context_score(words_list, idx, window=4):
    """Score how code-like the context around index `idx` is.
    Returns 0.0 (pure data) to 1.0 (clearly code).
    Checks `window` instructions before and after.
    """
    valid = 0
    total = 0
    for delta in range(-window, window + 1):
        if delta == 0:
            continue  # skip the bri itself
        j = idx + delta
        if j < 0 or j >= len(words_list):
            continue
        total += 1
        _, w = words_list[j]
        d = dec.decode(w)
        if d['op6'] in CODE_LIKE_OPS or w == 0:
            valid += 1
    return valid / total if total > 0 else 0.0


def is_likely_data_float(raw):
    """Check if the raw word looks like an IEEE 754 float constant.
    Common in PostScript interpreter data: values near small integers.
    """
    # bri r0 with specific patterns = likely float ~2.0
    if (raw >> 26) != 0x10:
        return False
    src1 = (raw >> 11) & 0x1F
    if src1 != 0:
        return False  # only bri r0 are float suspects
    # Check if the value is a reasonable float
    try:
        f = struct.unpack('<f', struct.pack('<I', raw))[0]
        import math
        if math.isnan(f) or math.isinf(f):
            return False
        # Floats near 2.0 are very common in PS data
        if 1.0 <= abs(f) <= 4.0:
            return True
    except Exception:
        pass
    return False


def filter_bri_candidates(all_bris, words, addr_to_idx):
    """Filter bri candidates to remove likely data false positives.

    Returns (code_bris, data_bris) where code_bris are high-confidence
    actual bri instructions.
    """
    code_bris = []
    data_bris = []

    # First pass: collect call/branch targets within the binary for context
    binary_size = len(words) * 4
    call_targets = set()
    for off, word in words:
        d = dec.decode(word)
        if d['op6'] in (dec.OP_CALL, dec.OP_BR, dec.OP_BC, dec.OP_BC_T,
                        dec.OP_BNC, dec.OP_BNC_T):
            target = dec.call_target(off + BASE_ADDR, d) - BASE_ADDR
            if 0 <= target < binary_size:
                call_targets.add(target)

    # Build code region set by walking from call targets
    code_addrs = set()
    for entry in call_targets:
        if entry not in addr_to_idx:
            continue
        idx = addr_to_idx[entry]
        for i in range(idx, min(idx + 128, len(words))):
            off, word = words[i]
            d = dec.decode(word)
            code_addrs.add(off)
            if d['op6'] in (dec.OP_BRI, dec.OP_BR):
                if i + 1 < len(words):
                    code_addrs.add(words[i + 1][0])
                break

    for off, d in all_bris:
        raw = d['raw']
        src1 = d['src1']
        idx = addr_to_idx[off]

        # Rule 1: bri r0 is almost always a float constant in data
        if src1 == 0:
            data_bris.append((off, d, "bri_r0_likely_float"))
            continue

        # Rule 2: Context scoring - check if surrounded by valid code
        score = code_context_score(words, idx, window=4)

        # Rule 3: Is this address or nearby address a known code region?
        in_code_region = False
        for delta in range(-8, 9):
            if off + delta * 4 in code_addrs:
                in_code_region = True
                break

        # Decision
        if score >= 0.5 or in_code_region:
            code_bris.append((off, d))
        else:
            data_bris.append((off, d, f"low_score_{score:.2f}"))

    return code_bris, data_bris, call_targets


# -----------------------------------------------------------------------
# Backward slicing
# -----------------------------------------------------------------------

def classify_write(words_list, bri_idx, target_reg):
    """Walk backward from bri_idx to find what wrote target_reg."""
    for step in range(1, MAX_BACKTRACK + 1):
        idx = bri_idx - step
        if idx < 0:
            break

        addr, word = words_list[idx]
        d = dec.decode(word)

        # Stop at control flow boundaries (step >= 2 to allow delay slot)
        if step >= 2 and d['op6'] in BRANCH_OPS:
            # Conditional branches have fall-through; keep scanning
            if d['op6'] in (dec.OP_BC, dec.OP_BNC, dec.OP_BTE_REG,
                            dec.OP_BTE_IMM, dec.OP_BTNE_REG, dec.OP_BTNE_IMM):
                # But still check if this instruction writes our target
                dr = dest_reg(d)
                if dr == target_reg:
                    pass  # fall through to classification below
                else:
                    continue
            else:
                break

        dr = dest_reg(d)
        if dr != target_reg:
            continue

        # Found the writer -- classify it

        # ld.l imm(R2), Rd
        if dec.is_ld_l_imm(d):
            base = d['src2']
            offset = d['simm16']
            result = {
                "writer_addr": f"0x{addr + BASE_ADDR:08x}",
                "writer_file_offset": f"0x{addr:05x}",
                "base_reg": f"r{base}",
                "offset": offset,
            }
            if base == dec.REG_R15:
                result["source_type"] = "ld_gstate"
                result["detail"] = f"ld.l {offset}(r15), r{target_reg}"
            elif base == dec.REG_R0:
                eff = offset & 0xFFFFFFFF
                result["source_type"] = "ld_table"
                result["effective_addr"] = f"0x{eff:08x}"
                result["detail"] = f"ld.l 0x{offset & 0xFFFF:04x}(r0), r{target_reg}"
            else:
                result["source_type"] = "ld_table"
                result["detail"] = f"ld.l {offset}(r{base}), r{target_reg}"
            return result

        # ld.l R1(R2), Rd
        if dec.is_ld_l_reg(d):
            return {
                "source_type": "ld_reg",
                "writer_addr": f"0x{addr + BASE_ADDR:08x}",
                "writer_file_offset": f"0x{addr:05x}",
                "index_reg": f"r{d['src1']}",
                "base_reg": f"r{d['src2']}",
                "detail": f"ld.l r{d['src1']}(r{d['src2']}), r{target_reg}",
            }

        # or imm -- look for preceding orh to form 32-bit constant
        if dec.is_or_imm(d):
            lo16 = d['imm16']
            or_src2 = d['src2']
            for step2 in range(step + 1, MAX_BACKTRACK + 1):
                idx2 = bri_idx - step2
                if idx2 < 0:
                    break
                addr2, word2 = words_list[idx2]
                d2 = dec.decode(word2)
                # Stop at unconditional branches
                if d2['op6'] in BRANCH_OPS and d2['op6'] not in (
                    dec.OP_BC, dec.OP_BNC, dec.OP_BTE_REG,
                    dec.OP_BTE_IMM, dec.OP_BTNE_REG, dec.OP_BTNE_IMM):
                    break
                dr2 = dest_reg(d2)
                if dr2 == target_reg and not dec.is_orh(d2):
                    break  # clobbered
                if dec.is_orh(d2) and d2['dest'] == target_reg:
                    hi16 = d2['imm16']
                    value = (hi16 << 16) | lo16
                    return {
                        "source_type": "orh_or_const",
                        "writer_addr": f"0x{addr2 + BASE_ADDR:08x}",
                        "writer_file_offset": f"0x{addr2:05x}",
                        "orh_addr": f"0x{addr2 + BASE_ADDR:08x}",
                        "or_addr": f"0x{addr + BASE_ADDR:08x}",
                        "hi16": f"0x{hi16:04x}",
                        "lo16": f"0x{lo16:04x}",
                        "resolved_addr": f"0x{value:08x}",
                        "resolved_value": value,
                        "detail": (f"orh 0x{hi16:04x},r{d2['src2']},r{target_reg} + "
                                   f"or 0x{lo16:04x},r{or_src2},r{target_reg} = 0x{value:08x}"),
                    }
            return {
                "source_type": "register_chain",
                "writer_addr": f"0x{addr + BASE_ADDR:08x}",
                "writer_file_offset": f"0x{addr:05x}",
                "op": "or_imm",
                "detail": f"or 0x{lo16:04x}, r{or_src2}, r{target_reg}",
            }

        # orh without following or
        if dec.is_orh(d):
            hi16 = d['imm16']
            return {
                "source_type": "register_chain",
                "writer_addr": f"0x{addr + BASE_ADDR:08x}",
                "writer_file_offset": f"0x{addr:05x}",
                "op": "orh_imm",
                "detail": f"orh 0x{hi16:04x}, r{d['src2']}, r{target_reg}",
            }

        # ld.s or ld.b (non-.l load)
        if d['op6'] in (dec.OP_LD_REG, dec.OP_LD_IMM) and not d['lsbit0']:
            base = d['src2']
            if d['op6'] == dec.OP_LD_IMM:
                offset = d['simm16']
                detail = f"ld.s {offset}(r{base}), r{target_reg}"
            else:
                detail = f"ld.s r{d['src1']}(r{base}), r{target_reg}"
                offset = None
            return {
                "source_type": "ld_table",
                "writer_addr": f"0x{addr + BASE_ADDR:08x}",
                "writer_file_offset": f"0x{addr:05x}",
                "base_reg": f"r{base}",
                "offset": offset if offset is not None else "reg",
                "detail": detail,
            }

        # Any other ALU/shift
        return {
            "source_type": "register_chain",
            "writer_addr": f"0x{addr + BASE_ADDR:08x}",
            "writer_file_offset": f"0x{addr:05x}",
            "op": opcode_name(d),
            "detail": f"{opcode_name(d)} -> r{target_reg} at 0x{addr + BASE_ADDR:08x}",
        }

    return {
        "source_type": "unknown",
        "detail": f"no write to r{target_reg} found within {MAX_BACKTRACK} instructions",
    }


def main():
    print(f"Reading binary: {BINARY}")
    print(f"Base address: 0x{BASE_ADDR:08X}")
    data = dec.read_bytes(str(BINARY))
    words = dec.read_words(str(BINARY))
    total_words = len(words)
    print(f"  Total words: {total_words} ({len(data)} bytes)")

    addr_to_idx = {off: i for i, (off, _) in enumerate(words)}

    # Phase 1: Find all bri candidates
    all_bris = dec.find_bri(words)
    print(f"\nPhase 1: Linear scan found {len(all_bris)} bri candidates (excl ret)")

    # Phase 2: Filter
    print("\nPhase 2: Filtering false positives...")
    code_bris, data_bris, call_targets = filter_bri_candidates(
        all_bris, words, addr_to_idx)
    print(f"  Call/branch targets in binary: {len(call_targets)}")
    print(f"  High-confidence code bri: {len(code_bris)}")
    print(f"  Filtered out (likely data): {len(data_bris)}")

    # Breakdown of filtered-out reasons
    filter_reasons = Counter(reason for _, _, reason in data_bris)
    for reason, count in filter_reasons.most_common():
        print(f"    {reason}: {count}")

    # Phase 3: Backward slicing
    print(f"\nPhase 3: Backward slicing from {len(code_bris)} bri sites...")

    bri_sites = []
    resolved_targets = set()
    load_patterns = defaultdict(list)
    source_type_counts = defaultdict(int)

    for bri_off, bri_d in code_bris:
        target_reg = bri_d['src1']
        bri_idx = addr_to_idx[bri_off]

        classification = classify_write(words, bri_idx, target_reg)
        source_type = classification["source_type"]
        source_type_counts[source_type] += 1

        site = {
            "addr": f"0x{bri_off + BASE_ADDR:08x}",
            "file_offset": f"0x{bri_off:05x}",
            "addr_int": bri_off + BASE_ADDR,
            "file_offset_int": bri_off,
            "target_reg": f"r{target_reg}",
            "source_type": source_type,
            **classification,
        }

        if source_type == "orh_or_const":
            resolved_targets.add(classification["resolved_value"])

        if source_type in ("ld_table", "ld_gstate"):
            base = classification["base_reg"]
            offset = classification.get("offset")
            load_patterns[base].append({
                "offset": offset,
                "bri_addr": f"0x{bri_off + BASE_ADDR:08x}",
            })

        bri_sites.append(site)

    sorted_targets = sorted(resolved_targets)

    # Load pattern summary
    load_summary = {}
    for base_reg, entries in sorted(load_patterns.items()):
        numeric = [e for e in entries if isinstance(e["offset"], int)]
        offsets = sorted(set(e["offset"] for e in numeric))
        load_summary[base_reg] = {
            "count": len(entries),
            "unique_offsets": len(offsets),
            "offsets_hex": [f"0x{o & 0xFFFF:04x}" if o >= 0
                           else f"-0x{(-o) & 0xFFFF:04x}" for o in offsets],
            "offsets_decimal": offsets,
            "sites": entries,
        }

    resolved_count = source_type_counts.get("orh_or_const", 0)

    output = {
        "metadata": {
            "binary": str(BINARY.name),
            "base_address": f"0x{BASE_ADDR:08x}",
            "binary_size": len(data),
            "total_bri_raw": len(all_bris),
            "bri_in_code": len(code_bris),
            "bri_in_data_filtered": len(data_bris),
            "resolved_count": resolved_count,
            "unresolved_count": len(code_bris) - resolved_count,
            "source_type_breakdown": dict(source_type_counts),
        },
        "bri_sites": bri_sites,
        "resolved_targets": [f"0x{t:08x}" for t in sorted_targets],
        "resolved_targets_int": sorted_targets,
        "load_patterns": load_summary,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nJSON written to: {OUTPUT}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("BACKWARD SLICE SUMMARY: bri dispatch targets")
    print("=" * 72)

    print(f"\nRaw bri (linear scan):      {len(all_bris)}")
    print(f"  bri r0 (float data):      {sum(1 for _, d in all_bris if d['src1'] == 0)}")
    print(f"  bri rN, N>0:              {sum(1 for _, d in all_bris if d['src1'] != 0)}")
    print(f"In code regions:            {len(code_bris)}")
    print(f"Filtered (data regions):    {len(data_bris)}")
    print(f"Statically resolved:        {resolved_count}")
    print(f"Unresolved:                 {len(code_bris) - resolved_count}")

    print(f"\nSource type breakdown:")
    for stype, count in sorted(source_type_counts.items(), key=lambda x: -x[1]):
        pct = 100.0 * count / len(code_bris) if code_bris else 0
        print(f"  {stype:20s}: {count:4d}  ({pct:5.1f}%)")

    if sorted_targets:
        print(f"\nStatically resolved targets ({len(sorted_targets)} unique):")
        for t in sorted_targets:
            in_range = BASE_ADDR <= t < BASE_ADDR + len(data)
            label = "  (in TEXT)" if in_range else ""
            print(f"  0x{t:08x}{label}")

    if load_summary:
        print(f"\nLoad-based dispatch patterns:")
        for base_reg, info in sorted(load_summary.items()):
            print(f"  Base {base_reg}: {info['count']} sites, "
                  f"{info['unique_offsets']} unique offsets")
            for oh, od in zip(info['offsets_hex'], info['offsets_decimal']):
                n = sum(1 for e in info['sites'] if e['offset'] == od)
                print(f"    offset {oh} ({od:+d}): {n} bri(s)")

    # Target register distribution
    print(f"\n{'=' * 72}")
    print("TARGET REGISTER DISTRIBUTION")
    print(f"{'=' * 72}")
    reg_counts = Counter(d['src1'] for _, d in code_bris)
    for reg, count in reg_counts.most_common():
        print(f"  r{reg:2d}: {count:4d}")

    # Detailed listing
    print(f"\n{'=' * 72}")
    print("DETAILED BRI SITE LISTING")
    print(f"{'=' * 72}")
    for site in sorted(bri_sites, key=lambda s: s["file_offset_int"]):
        resolved = ""
        if site['source_type'] == 'orh_or_const':
            resolved = f" -> RESOLVED {site['resolved_addr']}"
        print(f"\n  bri {site['target_reg']} at {site['addr']} "
              f"(file: {site['file_offset']})")
        print(f"    source: {site['source_type']}")
        print(f"    detail: {site['detail']}{resolved}")


if __name__ == "__main__":
    main()
