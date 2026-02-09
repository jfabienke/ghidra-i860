#!/usr/bin/env python3
"""Scan ND firmware for all GState field accesses via register r15.

Strategy: three passes to find all GState (r15-based) memory accesses.

Pass 1 (direct): Find ld/st instructions that use r15 directly as base.
  ld.{s,l} simm16(r15), rD  or  st.{s,l} rS, simm16(r15)

Pass 2 (orh+use forward): Find `orh imm16, r15, rN` and trace forward up
  to LOOKAHEAD instructions for ld/st/or/addu that use rN before it gets
  clobbered or a branch is reached.  Handles pipelined code.

Pass 3 (ld/st backward): Find all ld/st instructions and trace backward
  to find if the base register was set by `orh imm16, r15, rN`.

Only instructions in verified I860_CODE regions are considered.
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))
import i860_decode as dec

# -- Config ----------------------------------------------------------------
BINARY = (SCRIPTS_DIR.parent / "extracted" /
          "ND_MachDriver___TEXT_clean_window.bin")
SURVEY = (SCRIPTS_DIR.parent / "contamination_survey_clean.txt")
OUTPUT = (SCRIPTS_DIR.parent / "analysis" / "phase1" / "gstate_offsets.json")
BASE_ADDR = 0xF8000000
LOOKAHEAD = 12       # forward scan window
LOOKBACK = 12        # backward scan window

REG_NAMES = {i: "r%d" % i for i in range(32)}


# ==========================================================================
# Code region parsing
# ==========================================================================
def parse_code_regions(survey_path):
    regions = []
    with open(survey_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    for p in parts[3:]:
                        if p == "I860_CODE":
                            regions.append((start, end))
                            break
                except (ValueError, IndexError):
                    pass
    regions.sort()
    return regions


def offset_in_code(off, regions):
    for s, e in regions:
        if s <= off <= e:
            return True
        if off < s:
            return False
    return False


# ==========================================================================
# Opcode constants and helpers
# ==========================================================================
_IMM_ALU = frozenset({
    dec.OP_OR_IMM, dec.OP_ORH_IMM, dec.OP_AND_IMM, dec.OP_ANDH_IMM,
    dec.OP_ANDNOT_IMM, dec.OP_ANDNOTH_IMM, dec.OP_XOR_IMM,
    dec.OP_XORH_IMM, dec.OP_ADDU_IMM, dec.OP_SUBU_IMM,
    dec.OP_ADDS_IMM, dec.OP_SUBS_IMM, dec.OP_SHL_IMM,
    dec.OP_SHR_IMM, dec.OP_SHRA_IMM,
})

_REG_ALU = frozenset({
    dec.OP_OR_REG, dec.OP_AND_REG, dec.OP_ANDNOT_REG, dec.OP_XOR_REG,
    dec.OP_ADDU_REG, dec.OP_SUBU_REG, dec.OP_ADDS_REG, dec.OP_SUBS_REG,
    dec.OP_SHL_REG, dec.OP_SHR_REG, dec.OP_SHRA_REG,
})

_DEST_WRITERS = _IMM_ALU | _REG_ALU | frozenset({dec.OP_LD_REG, dec.OP_LD_IMM})

_BRANCHES = frozenset({
    dec.OP_BRI, dec.OP_BR, dec.OP_CALL,
    dec.OP_BC, dec.OP_BC_T, dec.OP_BNC, dec.OP_BNC_T,
    dec.OP_BLA, dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
    dec.OP_BTE_REG, dec.OP_BTE_IMM, dec.OP_TRAP,
})


def opcode_mnemonic(d):
    op = d['op6']
    lb = d['lsbit0']
    _map = {
        dec.OP_LD_REG: "ld.%s_reg" % ("l" if lb else "s"),
        dec.OP_LD_IMM: "ld.%s" % ("l" if lb else "s"),
        dec.OP_ST_REG: "st.%s_reg" % ("l" if lb else "s"),
        dec.OP_ST_IMM: "st.%s" % ("l" if lb else "s"),
        dec.OP_OR_IMM: "or_imm", dec.OP_OR_REG: "or_reg",
        dec.OP_ORH_IMM: "orh",
        dec.OP_AND_IMM: "and_imm", dec.OP_ANDH_IMM: "andh",
        dec.OP_ANDNOT_IMM: "andnot_imm", dec.OP_ANDNOTH_IMM: "andnoth",
        dec.OP_XOR_IMM: "xor_imm", dec.OP_XORH_IMM: "xorh",
        dec.OP_ADDU_REG: "addu_reg", dec.OP_ADDU_IMM: "addu_imm",
        dec.OP_SUBU_REG: "subu_reg", dec.OP_SUBU_IMM: "subu_imm",
        dec.OP_ADDS_REG: "adds_reg", dec.OP_ADDS_IMM: "adds_imm",
        dec.OP_SUBS_REG: "subs_reg", dec.OP_SUBS_IMM: "subs_imm",
        dec.OP_SHL_REG: "shl_reg", dec.OP_SHL_IMM: "shl_imm",
        dec.OP_SHR_REG: "shr_reg", dec.OP_SHR_IMM: "shr_imm",
        dec.OP_SHRA_REG: "shra_reg", dec.OP_SHRA_IMM: "shra_imm",
        dec.OP_BR: "br", dec.OP_CALL: "call",
        dec.OP_BC: "bc", dec.OP_BC_T: "bc.t",
        dec.OP_BNC: "bnc", dec.OP_BNC_T: "bnc.t",
        dec.OP_BRI: "bri",
        dec.OP_BTE_REG: "bte_reg", dec.OP_BTE_IMM: "bte_imm",
        dec.OP_BTNE_REG: "btne_reg", dec.OP_BTNE_IMM: "btne_imm",
        dec.OP_BLA: "bla", dec.OP_TRAP: "trap",
        dec.OP_FP_ESC: "fp_esc", dec.OP_CORE_ESC: "core_esc",
    }
    return _map.get(op, "op0x%02x" % op)


def reads_reg(d, reg):
    op = d['op6']
    if op in _IMM_ALU:
        return d['src2'] == reg
    if op in _REG_ALU:
        return d['src1'] == reg or d['src2'] == reg
    # ld.{s,l} imm: src2 is base
    if op == dec.OP_LD_IMM:
        return d['src2'] == reg
    # ld.{s,l} reg: src1 is offset, src2 is base
    if op == dec.OP_LD_REG:
        return d['src1'] == reg or d['src2'] == reg
    # st.{s,l} imm: src2 is base, dest is value to store
    if op == dec.OP_ST_IMM:
        return d['src2'] == reg or d['dest'] == reg
    # st.{s,l} reg: src1 is offset, src2 is base
    if op == dec.OP_ST_REG:
        return d['src1'] == reg or d['src2'] == reg
    # ld.b reg (op6=0x00): src1 offset, src2 base
    if op == 0x00:
        return d['src1'] == reg or d['src2'] == reg
    # ld.b imm (op6=0x01): src2 base
    if op == 0x01:
        return d['src2'] == reg
    # ixfr (op6=0x02): reads src1 (integer register)
    if op == 0x02:
        return d['src1'] == reg
    # st.b (op6=0x03): src2 base, dest is value source
    if op == 0x03:
        return d['src2'] == reg or d['dest'] == reg
    # FP load/store: fld.l reg (0x08), fld.l imm (0x09),
    # fst.l reg (0x0A), fst.l imm (0x0B),
    # fld.d reg (0x0C), fld.d imm (0x0D),
    # fst.d reg (0x0E), fst.d imm (0x0F)
    # All use src2 as integer base register; reg forms also use src1
    if 0x08 <= op <= 0x0F:
        if op in (0x08, 0x0A, 0x0C, 0x0E):  # reg forms
            return d['src1'] == reg or d['src2'] == reg
        else:  # imm forms
            return d['src2'] == reg
    if op in (dec.OP_BTE_REG, dec.OP_BTNE_REG, dec.OP_BLA):
        return d['src1'] == reg or d['src2'] == reg
    if op in (dec.OP_BTE_IMM, dec.OP_BTNE_IMM):
        return d['src2'] == reg
    if op in (dec.OP_BRI, dec.OP_CORE_ESC):
        return d['src1'] == reg
    return False


def writes_dest(d, reg):
    """Does instruction d write to register reg via the dest field?"""
    if d['op6'] in _DEST_WRITERS:
        return d['dest'] == reg
    return False


# ==========================================================================
# Pass 1: Direct ld/st via r15
# ==========================================================================
def scan_direct_r15(words, code_regions):
    entries = []
    for i, (off, word) in enumerate(words):
        if not offset_in_code(off, code_regions):
            continue
        d = dec.decode(word)
        op = d['op6']

        if op == dec.OP_LD_IMM and d['src2'] == dec.REG_R15:
            sz = "l" if d['lsbit0'] else "s"
            eff = d['simm16'] & 0xFFFFFFFF
            entries.append({
                "pattern": "direct_ld",
                "addr": "0x%06x" % off,
                "vmaddr": "0x%08x" % (BASE_ADDR + off),
                "raw": "0x%08x" % word,
                "mnemonic": "ld.%s %d(r15), r%d" % (sz, d['simm16'], d['dest']),
                "effective_offset": "0x%08x" % eff,
                "access_type": "READ",
                "width": 4 if d['lsbit0'] else 2,
            })

        elif op == dec.OP_LD_REG and d['src2'] == dec.REG_R15:
            sz = "l" if d['lsbit0'] else "s"
            entries.append({
                "pattern": "direct_ld_reg",
                "addr": "0x%06x" % off,
                "vmaddr": "0x%08x" % (BASE_ADDR + off),
                "raw": "0x%08x" % word,
                "mnemonic": "ld.%s r%d(r15), r%d" % (sz, d['src1'], d['dest']),
                "effective_offset": None,
                "access_type": "READ_REG",
            })

        elif op == dec.OP_ST_IMM and d['src2'] == dec.REG_R15:
            sz = "l" if d['lsbit0'] else "s"
            eff = d['simm16'] & 0xFFFFFFFF
            entries.append({
                "pattern": "direct_st",
                "addr": "0x%06x" % off,
                "vmaddr": "0x%08x" % (BASE_ADDR + off),
                "raw": "0x%08x" % word,
                "mnemonic": "st.%s r%d, %d(r15)" % (sz, d['dest'], d['simm16']),
                "effective_offset": "0x%08x" % eff,
                "access_type": "WRITE",
                "width": 4 if d['lsbit0'] else 2,
            })

        elif op == dec.OP_ST_REG and d['src2'] == dec.REG_R15:
            sz = "l" if d['lsbit0'] else "s"
            entries.append({
                "pattern": "direct_st_reg",
                "addr": "0x%06x" % off,
                "vmaddr": "0x%08x" % (BASE_ADDR + off),
                "raw": "0x%08x" % word,
                "mnemonic": "st.%s r%d, r%d(r15)" % (sz, d['dest'], d['src1']),
                "effective_offset": None,
                "access_type": "WRITE_REG",
            })

    return entries


# ==========================================================================
# Pass 2: Forward scan from orh r15
# ==========================================================================
def scan_orh_forward(words, code_regions):
    entries = []

    for i, (off, word) in enumerate(words):
        if not offset_in_code(off, code_regions):
            continue
        d = dec.decode(word)
        if d['op6'] != dec.OP_ORH_IMM or d['src2'] != dec.REG_R15:
            continue

        orh_imm16 = d['imm16']
        high_offset = orh_imm16 << 16
        dest_reg = d['dest']

        following_ops = []
        primary_offset = None
        primary_type = "UNKNOWN"

        for k in range(1, LOOKAHEAD + 1):
            ni = i + k
            if ni >= len(words):
                break
            noff, nw = words[ni]
            nd = dec.decode(nw)

            if nd['raw'] == 0:
                continue

            # Stop at branches (but check delay slot: include +1 after branch)
            if nd['op6'] in _BRANCHES:
                if reads_reg(nd, dest_reg):
                    following_ops.append({
                        "step": k,
                        "addr": "0x%06x" % noff,
                        "mnemonic": opcode_mnemonic(nd),
                        "classification": "BRANCH_USE",
                    })
                break

            # Does this instruction use our dest reg?
            if reads_reg(nd, dest_reg):
                cls, imm_off = _classify_fwd(nd, dest_reg)
                entry_op = {
                    "step": k,
                    "addr": "0x%06x" % noff,
                    "mnemonic": opcode_mnemonic(nd),
                    "classification": cls,
                }
                if imm_off is not None:
                    eff = (high_offset + imm_off) & 0xFFFFFFFF
                    entry_op["imm_offset"] = imm_off
                    entry_op["effective_offset"] = "0x%08x" % eff
                    if primary_offset is None:
                        primary_offset = eff
                        if "READ" in cls:
                            primary_type = "READ"
                        elif "WRITE" in cls:
                            primary_type = "WRITE"
                        elif "ADDR_CALC" in cls:
                            primary_type = "ADDR_CALC"
                following_ops.append(entry_op)
                continue

            # Check if dest_reg gets overwritten
            if writes_dest(nd, dest_reg):
                break

        entries.append({
            "pattern": "orh_fwd",
            "addr": "0x%06x" % off,
            "vmaddr": "0x%08x" % (BASE_ADDR + off),
            "raw": "0x%08x" % word,
            "orh_imm16": "0x%04x" % orh_imm16,
            "high_offset": "0x%08x" % high_offset,
            "dest_reg": REG_NAMES[dest_reg],
            "following_ops": following_ops,
            "effective_offset": ("0x%08x" % primary_offset
                                 if primary_offset is not None else None),
            "access_type": primary_type,
        })

    return entries


def _classify_fwd(d, base_reg):
    op = d['op6']
    # ld.{s,l} imm
    if op == dec.OP_LD_IMM and d['src2'] == base_reg:
        sz = "l" if d['lsbit0'] else "s"
        return ("READ_ld.%s" % sz, d['simm16'])
    # ld.{s,l} reg
    if op == dec.OP_LD_REG and d['src2'] == base_reg:
        return ("READ_ld_reg", None)
    # st.{s,l} imm
    if op == dec.OP_ST_IMM and d['src2'] == base_reg:
        sz = "l" if d['lsbit0'] else "s"
        return ("WRITE_st.%s" % sz, d['simm16'])
    # st.{s,l} reg
    if op == dec.OP_ST_REG and d['src2'] == base_reg:
        return ("WRITE_st_reg", None)
    # ld.b imm (op6=0x01) -- byte load with immediate offset
    if op == 0x01 and d['src2'] == base_reg:
        return ("READ_ld.b", d['simm16'])
    # ld.b reg (op6=0x00) -- byte load with register offset
    if op == 0x00 and d['src2'] == base_reg:
        return ("READ_ld.b_reg", None)
    # st.b (op6=0x03) -- byte store
    if op == 0x03 and d['src2'] == base_reg:
        return ("WRITE_st.b", d['simm16'])
    # ixfr (op6=0x02) -- integer-to-FP transfer, reads src1
    if op == 0x02 and d['src1'] == base_reg:
        return ("IXFR", None)
    # FP loads/stores (0x08-0x0F) -- use src2 as base
    if op == 0x09 and d['src2'] == base_reg:  # fld.l imm
        return ("READ_fld.l", d['simm16'])
    if op == 0x08 and d['src2'] == base_reg:  # fld.l reg
        return ("READ_fld.l_reg", None)
    if op == 0x0B and d['src2'] == base_reg:  # fst.l imm
        return ("WRITE_fst.l", d['simm16'])
    if op == 0x0A and d['src2'] == base_reg:  # fst.l reg
        return ("WRITE_fst.l_reg", None)
    if op == 0x0D and d['src2'] == base_reg:  # fld.d imm
        return ("READ_fld.d", d['simm16'])
    if op == 0x0C and d['src2'] == base_reg:  # fld.d reg
        return ("READ_fld.d_reg", None)
    if op == 0x0F and d['src2'] == base_reg:  # fst.d imm
        return ("WRITE_fst.d", d['simm16'])
    if op == 0x0E and d['src2'] == base_reg:  # fst.d reg
        return ("WRITE_fst.d_reg", None)
    # or imm -- address calc
    if op == dec.OP_OR_IMM and d['src2'] == base_reg:
        return ("ADDR_CALC_or", d['imm16'])
    # addu imm
    if op == dec.OP_ADDU_IMM and d['src2'] == base_reg:
        return ("ADDR_CALC_addu", d['simm16'])
    # adds imm
    if op == dec.OP_ADDS_IMM and d['src2'] == base_reg:
        return ("ADDR_CALC_adds", d['simm16'])
    return ("USE", None)


# ==========================================================================
# Pass 3: Backward scan from ld/st to find orh r15 definitions
# ==========================================================================
def scan_backward(words, code_regions):
    """For each ld/st in code regions, trace backward to find if the base
    register was set by orh imm16, r15, rN."""
    entries = []
    seen = set()  # (ld_off, orh_off) pairs to avoid duplicates with pass 2

    for i, (off, word) in enumerate(words):
        if not offset_in_code(off, code_regions):
            continue
        d = dec.decode(word)
        op = d['op6']

        # Interested in any immediate-form load/store (known offset)
        # ld.{s,l} imm (op6=0x05)
        if op == dec.OP_LD_IMM:
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = True
            sz = "l" if d['lsbit0'] else "s"
        # st.{s,l} imm (op6=0x07)
        elif op == dec.OP_ST_IMM:
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = False
            sz = "l" if d['lsbit0'] else "s"
        # ld.b imm (op6=0x01)
        elif op == 0x01:
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = True
            sz = "b"
        # st.b imm (op6=0x03) -- uses stimm not simm16
        elif op == 0x03:
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = False
            sz = "b"
        # FP immediate-form loads/stores (0x09, 0x0B, 0x0D, 0x0F)
        elif op == 0x09:  # fld.l imm
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = True
            sz = "fl"
        elif op == 0x0B:  # fst.l imm
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = False
            sz = "fl"
        elif op == 0x0D:  # fld.d imm
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = True
            sz = "fd"
        elif op == 0x0F:  # fst.d imm
            base_reg = d['src2']
            imm_off = d['simm16']
            is_read = False
            sz = "fd"
        else:
            continue

        # Skip if base is r15 (already handled in pass 1)
        if base_reg == dec.REG_R15:
            continue
        # Skip r0 (always zero)
        if base_reg == 0:
            continue

        # Trace backward to find the definition of base_reg
        orh_found = None
        for k in range(1, LOOKBACK + 1):
            pi = i - k
            if pi < 0:
                break
            poff, pw = words[pi]
            pd = dec.decode(pw)

            # Found a branch? Stop (control flow boundary)
            if pd['op6'] in _BRANCHES:
                break

            # Found orh that writes to our base_reg?
            if (pd['op6'] == dec.OP_ORH_IMM and
                    pd['dest'] == base_reg and
                    pd['src2'] == dec.REG_R15):
                orh_found = (poff, pd)
                break

            # Found another instruction that writes to base_reg?
            # (clobber from non-orh source)
            if writes_dest(pd, base_reg):
                break

        if orh_found is None:
            continue

        orh_off, orh_d = orh_found
        key = (off, orh_off)
        if key in seen:
            continue
        seen.add(key)

        high_offset = orh_d['imm16'] << 16
        eff = (high_offset + imm_off) & 0xFFFFFFFF

        if is_read:
            mnemonic = "ld.%s %d(r%d), r%d" % (sz, imm_off, base_reg, d['dest'])
            access_type = "READ"
        else:
            mnemonic = "st.%s r%d, %d(r%d)" % (sz, d['dest'], imm_off, base_reg)
            access_type = "WRITE"

        entries.append({
            "pattern": "orh_bkwd",
            "addr": "0x%06x" % off,
            "vmaddr": "0x%08x" % (BASE_ADDR + off),
            "raw": "0x%08x" % word,
            "mnemonic": mnemonic,
            "orh_addr": "0x%06x" % orh_off,
            "orh_imm16": "0x%04x" % orh_d['imm16'],
            "high_offset": "0x%08x" % high_offset,
            "base_reg": REG_NAMES[base_reg],
            "imm_offset": imm_off,
            "effective_offset": "0x%08x" % eff,
            "access_type": access_type,
            "width": 4 if d['lsbit0'] else 2,
        })

    return entries


# ==========================================================================
# Summary builder
# ==========================================================================
def build_summary(all_entries):
    offset_counts = Counter()
    offset_access_types = defaultdict(set)
    offset_sites = defaultdict(list)
    offset_patterns = defaultdict(set)

    for e in all_entries:
        eff = e.get('effective_offset')
        if eff is None:
            continue
        offset_counts[eff] += 1
        offset_access_types[eff].add(e['access_type'])
        offset_sites[eff].append(e.get('vmaddr', e.get('addr', '?')))
        offset_patterns[eff].add(e['pattern'])

    unique_offsets_sorted = sorted(offset_counts.keys(),
                                    key=lambda x: int(x, 16))

    most_accessed = [
        {
            "offset": off,
            "count": cnt,
            "access_types": sorted(offset_access_types[off]),
            "patterns": sorted(offset_patterns[off]),
            "sites": offset_sites[off],
        }
        for off, cnt in offset_counts.most_common()
    ]

    return {
        "unique_offset_count": len(unique_offsets_sorted),
        "unique_offsets_sorted": unique_offsets_sorted,
        "most_accessed": most_accessed,
    }


# ==========================================================================
# Main
# ==========================================================================
def main():
    if SURVEY.exists():
        code_regions = parse_code_regions(str(SURVEY))
        print("Code regions from survey: %d regions" % len(code_regions))
        total_code = sum(e - s + 1 for s, e in code_regions)
        print("  Total code bytes: %d (%.1f%% of binary)" %
              (total_code, 100.0 * total_code / 200704))
    else:
        print("WARNING: survey not found, treating entire binary as code")
        code_regions = [(0, 200703)]

    print("Reading binary: %s" % BINARY)
    words = dec.read_words(str(BINARY))
    print("  %d words (%d bytes)" % (len(words), len(words) * 4))

    code_words = sum(1 for off, _ in words if offset_in_code(off, code_regions))
    print("  %d words in code regions" % code_words)

    # Pass 1
    print("\nPass 1: Direct ld/st via r15 ...")
    direct = scan_direct_r15(words, code_regions)
    print("  %d hits" % len(direct))

    # Pass 2
    print("\nPass 2: Forward from orh r15 ...")
    orh_fwd = scan_orh_forward(words, code_regions)
    fwd_resolved = sum(1 for e in orh_fwd if e['access_type'] != 'UNKNOWN')
    print("  %d orh sites, %d with resolved offset" %
          (len(orh_fwd), fwd_resolved))

    # Pass 3
    print("\nPass 3: Backward from ld/st to orh r15 ...")
    bkwd = scan_backward(words, code_regions)
    print("  %d hits" % len(bkwd))

    # Combine and deduplicate by (effective_offset, vmaddr) if needed
    all_entries = direct + [e for e in orh_fwd
                            if e['access_type'] != 'UNKNOWN'] + bkwd

    # Deduplicate: backward pass might find same (ldst_addr, orh_addr) as forward
    deduped = []
    seen_keys = set()
    for e in all_entries:
        key = (e.get('vmaddr', e.get('addr')), e.get('effective_offset'))
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(e)

    all_entries = deduped
    print("\nTotal unique r15 access entries: %d" % len(all_entries))

    summary = build_summary(all_entries)
    print("Unique GState offsets: %d" % summary['unique_offset_count'])

    # Collect unresolved orh sites for reference
    orh_unresolved = [e for e in orh_fwd if e['access_type'] == 'UNKNOWN']

    result = {
        "metadata": {
            "binary": str(BINARY),
            "vmaddr": "0x%08x" % BASE_ADDR,
            "total_words": len(words),
            "code_words": code_words,
            "code_regions": len(code_regions),
            "pass1_direct": len(direct),
            "pass2_orh_fwd_total": len(orh_fwd),
            "pass2_fwd_resolved": fwd_resolved,
            "pass2_fwd_unresolved": len(orh_unresolved),
            "pass3_backward": len(bkwd),
            "total_resolved_entries": len(all_entries),
            "lookahead": LOOKAHEAD,
            "lookback": LOOKBACK,
            "notes": [
                "Most orh r15 sites (43 total) are in pipelined FP rendering "
                "code where r31 is used as a scratch register. The orh result "
                "is immediately clobbered by the next integer instruction "
                "(xor/andnot/orh writing to r31).",
                "GState field accesses in this binary primarily use direct "
                "ld/st simm16(r15) with short-range signed 16-bit offsets.",
                "Register-indexed accesses (4 st_reg + 2 ld_reg) have unknown "
                "effective offsets because the index register value is dynamic.",
                "Offsets are relative to r15 (GState base pointer). Negative "
                "offsets indicate fields below the base address.",
            ],
        },
        "offsets": all_entries,
        "orh_r15_unresolved": [
            {
                "addr": e['addr'],
                "vmaddr": e['vmaddr'],
                "orh_imm16": e['orh_imm16'],
                "dest_reg": e['dest_reg'],
                "reason": "dest register clobbered before use (pipelined FP code)",
            }
            for e in orh_unresolved
        ],
        "summary": summary,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    print("\nJSON written to: %s" % OUTPUT)

    # Top-20 summary
    print("\n" + "=" * 80)
    print("Top 20 Most-Referenced GState Offsets (relative to r15)")
    print("=" * 80)
    print("%-16s %5s  %-14s  %-20s  Sites (first 5)" %
          ("Offset", "Count", "Patterns", "Access Types"))
    print("-" * 80)
    for item in summary['most_accessed'][:20]:
        types_str = ", ".join(item['access_types'])
        pats_str = ", ".join(item['patterns'])
        sites_str = ", ".join(item['sites'][:5])
        if len(item['sites']) > 5:
            sites_str += " (+%d more)" % (len(item['sites']) - 5)
        print("%-16s %5d  %-14s  %-20s  %s" %
              (item['offset'], item['count'], pats_str, types_str, sites_str))

    # Access type breakdown
    print("\n" + "=" * 80)
    print("Access Type Breakdown")
    print("=" * 80)
    type_counts = Counter()
    pattern_counts = Counter()
    for e in all_entries:
        type_counts[e['access_type']] += 1
        pattern_counts[e['pattern']] += 1
    for t, c in type_counts.most_common():
        print("  %-20s %5d" % (t, c))
    print("\nPattern Breakdown:")
    for p, c in pattern_counts.most_common():
        print("  %-20s %5d" % (p, c))

    # Offset range
    if summary['unique_offsets_sorted']:
        nums = []
        for s in summary['unique_offsets_sorted']:
            v = int(s, 16)
            if v >= 0x80000000:
                v -= 0x100000000
            nums.append(v)
        nums.sort()
        print("\nGState offset range (relative to r15):")
        print("  Min: %d (0x%x)" % (nums[0], nums[0] & 0xFFFFFFFF))
        print("  Max: %d (0x%x)" % (nums[-1], nums[-1] & 0xFFFFFFFF))
        print("  Span: %d bytes (0x%x)" % (nums[-1] - nums[0],
                                             nums[-1] - nums[0]))

    # Full offset list
    print("\n" + "=" * 80)
    print("All Unique GState Offsets (sorted)")
    print("=" * 80)
    for s in summary['unique_offsets_sorted']:
        v = int(s, 16)
        signed = v - 0x100000000 if v >= 0x80000000 else v
        cnt = 0
        types_set = set()
        for item in summary['most_accessed']:
            if item['offset'] == s:
                cnt = item['count']
                types_set = set(item['access_types'])
                break
        types_str = ", ".join(sorted(types_set))
        print("  %s  (%+8d)  refs=%-3d  %s" % (s, signed, cnt, types_str))


if __name__ == "__main__":
    main()
