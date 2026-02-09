#!/usr/bin/env python3
"""Phase 2 — Cross-block BRI resolution via reverse CFG tracing.

Builds a reverse control-flow graph from the binary, then traces registers
backward across basic block boundaries to resolve bri dispatch targets that
Phase 1 could not resolve (566 of 586 unknowns hit a branch boundary).

Phases:
  A. Build reverse CFG from branch instructions
  B. Recompute boundary metadata for all 616 bri sites
  C. Cross-block register tracing (br, call, conditional predecessors)
  D. Multi-hop on register_chain sites (27)
  E. Deep analysis on ld_table/ld_reg sites (3)
"""

import json
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import i860_decode as dec

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
BINARY = Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
PHASE1_JSON = Path(__file__).parent.parent / "analysis" / "phase1" / "bri_targets.json"
REG_CONTEXT = Path(__file__).parent.parent / "analysis" / "phase2" / "register_context.json"
OUTPUT = Path(__file__).parent.parent / "analysis" / "phase2" / "cross_block_results.json"
BASE_ADDR = 0xF8000000

MAX_INTRA_BLOCK_SCAN = 64      # Max instructions to scan backward within a block
MAX_BLOCK_DEPTH = 3             # Max cross-block hops
MAX_VISIT_BUDGET = 2048         # Global visit budget to prevent explosion
MAX_REGISTER_HOPS = 4           # Max register chain hops
MAX_CHAIN_PATHS = 32            # Max total paths for register chain exploration

# ABI selection
ABI = 'gcc'
CALLEE_SAVED = dec.GCC_CALLEE_SAVED if ABI == 'gcc' else dec.SPEA_CALLEE_SAVED

# Branch opcodes (from Phase 1)
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
# Phase B: Intra-block backward scan with boundary metadata
# -----------------------------------------------------------------------

def backward_scan(words, addr_to_idx, bri_offset, target_reg, max_scan=MAX_INTRA_BLOCK_SCAN):
    """Walk backward from bri_offset to find what wrote target_reg.

    Returns dict with:
      found: bool — whether a writer was found
      writer: classification dict if found
      stop_reason: 'found_writer' | 'branch_boundary' | 'window_limit' | 'start_of_binary'
      stop_op: opname of the branch that terminated scan (if branch_boundary)
      stop_addr: file offset of the terminator
      block_entry: computed block entry offset (for cross-block tracing)
    """
    bri_idx = addr_to_idx.get(bri_offset)
    if bri_idx is None:
        return {'found': False, 'stop_reason': 'invalid_offset'}

    for step in range(1, max_scan + 1):
        idx = bri_idx - step
        if idx < 0:
            return {'found': False, 'stop_reason': 'start_of_binary',
                    'scanned': step}

        off, word = words[idx]
        d = dec.decode(word)

        # Check for control flow boundary (step >= 2 to allow delay slot)
        if step >= 2 and d['op6'] in BRANCH_OPS:
            is_core_esc_branch = (d['op6'] == dec.OP_CORE_ESC and
                                   d['escop'] == dec.ESC_CALLI)
            is_branch = d['op6'] != dec.OP_CORE_ESC or is_core_esc_branch

            if is_branch:
                # Conditional branches have fall-through — only stop on unconditional
                is_cond = d['op6'] in (dec.OP_BC, dec.OP_BNC, dec.OP_BC_T, dec.OP_BNC_T,
                                        dec.OP_BTE_REG, dec.OP_BTE_IMM,
                                        dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
                                        dec.OP_BLA)

                # Still check if THIS instruction writes our target
                dr = dest_reg(d)
                if dr == target_reg:
                    writer = classify_writer(words, idx, target_reg)
                    return {'found': True, 'stop_reason': 'found_writer',
                            'writer': writer, 'scanned': step}

                if not is_cond:
                    opname = dec.branch_opname(d)
                    entry = dec.block_entry_after(off, d)
                    return {
                        'found': False,
                        'stop_reason': 'branch_boundary',
                        'stop_op': opname,
                        'stop_addr': off,
                        'stop_addr_va': f'0x{off + BASE_ADDR:08x}',
                        'block_entry': entry,
                        'is_delayed': dec.is_delayed(d),
                        'scanned': step,
                    }
                else:
                    # Conditional — continue scanning (fall-through path)
                    continue

        dr = dest_reg(d)
        if dr != target_reg:
            continue

        # Found the writer
        writer = classify_writer(words, idx, target_reg)
        return {'found': True, 'stop_reason': 'found_writer',
                'writer': writer, 'scanned': step}

    return {'found': False, 'stop_reason': 'window_limit',
            'scanned': max_scan}


def classify_writer(words, idx, target_reg):
    """Classify the instruction at idx that writes target_reg.

    Similar to Phase 1's classify_write but returns a richer dict.
    """
    off, word = words[idx]
    d = dec.decode(word)
    va = off + BASE_ADDR

    base = {
        'writer_addr': f'0x{va:08x}',
        'writer_offset': off,
    }

    # ld.l imm(R2), Rd
    if dec.is_ld_l_imm(d):
        br = d['src2']
        offset = d['simm16']
        base.update({
            'source_type': 'ld_gstate' if br == dec.REG_R15 else 'ld_table',
            'base_reg': br,
            'offset': offset,
            'detail': f'ld.l {offset}(r{br}), r{target_reg}',
        })
        return base

    # ld.l R1(R2), Rd
    if dec.is_ld_l_reg(d):
        base.update({
            'source_type': 'ld_reg',
            'index_reg': d['src1'],
            'base_reg': d['src2'],
            'detail': f'ld.l r{d["src1"]}(r{d["src2"]}), r{target_reg}',
        })
        return base

    # ld.s / ld.b immediate
    if d['op6'] == dec.OP_LD_IMM and d['dest'] == target_reg:
        br = d['src2']
        offset = d['simm16']
        size = '.l' if d['lsbit0'] else '.s'
        base.update({
            'source_type': 'ld_table',
            'base_reg': br,
            'offset': offset,
            'detail': f'ld{size} {offset}(r{br}), r{target_reg}',
        })
        return base

    # ld.s / ld.b register form
    if d['op6'] == dec.OP_LD_REG and d['dest'] == target_reg:
        size = '.l' if d['lsbit0'] else '.s'
        base.update({
            'source_type': 'ld_reg',
            'index_reg': d['src1'],
            'base_reg': d['src2'],
            'detail': f'ld{size} r{d["src1"]}(r{d["src2"]}), r{target_reg}',
        })
        return base

    # or imm — look for preceding orh to form constant
    if dec.is_or_imm(d):
        lo16 = d['imm16']
        or_src2 = d['src2']
        # Scan backward for orh
        for s2 in range(1, 16):
            idx2 = idx - s2
            if idx2 < 0:
                break
            _, w2 = words[idx2]
            d2 = dec.decode(w2)
            if d2['op6'] in BRANCH_OPS:
                # Don't cross branches when looking for orh
                if not (d2['op6'] in (dec.OP_BC, dec.OP_BNC, dec.OP_BTE_REG,
                                       dec.OP_BTE_IMM, dec.OP_BTNE_REG, dec.OP_BTNE_IMM)):
                    break
            dr2 = dest_reg(d2)
            if dr2 == target_reg and not dec.is_orh(d2):
                break  # clobbered
            if dec.is_orh(d2) and d2['dest'] == target_reg:
                hi16 = d2['imm16']
                value = (hi16 << 16) | lo16
                base.update({
                    'source_type': 'orh_or_const',
                    'value': value,
                    'value_hex': f'0x{value:08x}',
                    'orh_src2': d2['src2'],
                    'detail': f'orh 0x{hi16:04x},r{d2["src2"]},r{target_reg} + or 0x{lo16:04x},r{or_src2},r{target_reg} = 0x{value:08x}',
                })
                return base

        # or without orh
        if or_src2 == 0:
            base.update({
                'source_type': 'orh_or_const',
                'value': lo16,
                'value_hex': f'0x{lo16:08x}',
                'detail': f'or 0x{lo16:04x}, r0, r{target_reg} (small constant)',
            })
        else:
            base.update({
                'source_type': 'register_chain',
                'op': 'or_imm',
                'input_regs': [or_src2],
                'detail': f'or 0x{lo16:04x}, r{or_src2}, r{target_reg}',
            })
        return base

    # orh without or
    if dec.is_orh(d):
        hi16 = d['imm16']
        base.update({
            'source_type': 'register_chain',
            'op': 'orh_imm',
            'input_regs': [d['src2']] if d['src2'] != 0 else [],
            'detail': f'orh 0x{hi16:04x}, r{d["src2"]}, r{target_reg}',
        })
        return base

    # addu imm, r0, Rd — small constant
    if dec.is_addu_imm(d) and d['src2'] == 0:
        val = d['simm16'] & 0xFFFFFFFF
        base.update({
            'source_type': 'orh_or_const',
            'value': val,
            'value_hex': f'0x{val:08x}',
            'detail': f'addu {d["simm16"]}, r0, r{target_reg} (constant)',
        })
        return base

    # Generic ALU
    inputs = dec.writer_input_regs(d)
    op_names = {
        dec.OP_ADDU_REG: 'addu_reg', dec.OP_ADDU_IMM: 'addu_imm',
        dec.OP_SUBU_REG: 'subu_reg', dec.OP_SUBU_IMM: 'subu_imm',
        dec.OP_ADDS_REG: 'adds_reg', dec.OP_ADDS_IMM: 'adds_imm',
        dec.OP_SUBS_REG: 'subs_reg', dec.OP_SUBS_IMM: 'subs_imm',
        dec.OP_SHL_REG: 'shl_reg', dec.OP_SHL_IMM: 'shl_imm',
        dec.OP_SHR_REG: 'shr_reg', dec.OP_SHR_IMM: 'shr_imm',
        dec.OP_SHRA_REG: 'shra_reg', dec.OP_SHRA_IMM: 'shra_imm',
        dec.OP_AND_REG: 'and_reg', dec.OP_AND_IMM: 'and_imm',
        dec.OP_ANDH_IMM: 'andh_imm',
        dec.OP_ANDNOT_REG: 'andnot_reg', dec.OP_ANDNOT_IMM: 'andnot_imm',
        dec.OP_ANDNOTH_IMM: 'andnoth_imm',
        dec.OP_OR_REG: 'or_reg',
        dec.OP_XOR_REG: 'xor_reg', dec.OP_XOR_IMM: 'xor_imm',
        dec.OP_XORH_IMM: 'xorh_imm',
    }
    opname = op_names.get(d['op6'], f'op{d["op6"]:02x}')
    base.update({
        'source_type': 'register_chain',
        'op': opname,
        'input_regs': inputs,
        'detail': f'{opname} -> r{target_reg} (inputs: {", ".join(f"r{r}" for r in inputs) or "none"})',
    })
    return base


# -----------------------------------------------------------------------
# Phase C: Cross-block register tracing
# -----------------------------------------------------------------------

class CrossBlockTracer:
    """Traces a register backward across basic block boundaries using reverse CFG."""

    def __init__(self, words, addr_to_idx, reverse_cfg):
        self.words = words
        self.addr_to_idx = addr_to_idx
        self.reverse_cfg = reverse_cfg
        self.binary_size = len(words) * 4
        self.visit_count = 0
        self.memo = {}  # (block_entry, reg, depth) -> result

    def trace_register(self, block_entry, target_reg, depth=0):
        """Trace target_reg backward from block_entry through predecessors.

        Returns dict with classification result.
        """
        if self.visit_count >= MAX_VISIT_BUDGET:
            return {'classification': 'budget_exhausted', 'visits': self.visit_count}

        if depth > MAX_BLOCK_DEPTH:
            return {'classification': 'depth_exhausted', 'depth': depth}

        # Memoization
        key = (block_entry, target_reg, depth)
        if key in self.memo:
            return self.memo[key]

        self.visit_count += 1

        # Get predecessors of this block entry
        preds = self.reverse_cfg.get(block_entry, [])
        if not preds:
            # No branch predecessors — try sequential scan from before block_entry.
            # This handles blocks reached via fall-through from non-branching code.
            prev_offset = block_entry - 4
            if prev_offset >= 0 and prev_offset in self.addr_to_idx:
                _, prev_word = self.words[self.addr_to_idx[prev_offset]]
                prev_d = dec.decode(prev_word)
                # Only use sequential predecessor if it's NOT an unconditional branch
                if not (prev_d['op6'] in BRANCH_OPS and
                        dec.is_unconditional_branch(prev_d)):
                    scan = self._scan_from_offset(prev_offset, target_reg, depth)
                    if scan:
                        scan['edge_type'] = 'sequential'
                        self.memo[key] = scan
                        return scan
            result = {'classification': 'no_predecessors', 'block_entry': block_entry}
            self.memo[key] = result
            return result

        results = []
        for edge in preds:
            source_offset = edge['source_offset']
            opname = edge['opname']
            edge_type = edge['edge_type']

            # For call_return edges: check if register is callee-saved
            if edge_type == 'call_return':
                if target_reg not in CALLEE_SAVED:
                    results.append({
                        'classification': 'caller_saved_clobbered',
                        'predecessor': f'0x{source_offset + BASE_ADDR:08x}',
                        'edge_type': edge_type,
                        'register': f'r{target_reg}',
                    })
                    continue
                # Callee-saved: trace backward from before the call instruction
                scan = self._scan_from_offset(source_offset, target_reg, depth)
                if scan:
                    scan['callee_saved_trace'] = True
                    scan['call_addr'] = f'0x{source_offset + BASE_ADDR:08x}'
                results.append(scan)
                continue

            # For branch_target or fall_through: trace from source block
            scan = self._scan_from_offset(source_offset, target_reg, depth)
            if scan:
                scan['predecessor'] = f'0x{source_offset + BASE_ADDR:08x}'
                scan['edge_type'] = edge_type
            results.append(scan)

        # Consolidate results
        result = self._consolidate(results, block_entry, target_reg)
        self.memo[key] = result
        return result

    def _scan_from_offset(self, branch_offset, target_reg, depth):
        """Scan backward from branch_offset to find writer of target_reg.

        Searches within the predecessor block, and recurses if needed.
        """
        branch_idx = self.addr_to_idx.get(branch_offset)
        if branch_idx is None:
            return {'classification': 'invalid_predecessor'}

        # Scan backward from the branch instruction
        for step in range(0, MAX_INTRA_BLOCK_SCAN):
            idx = branch_idx - step
            if idx < 0:
                return {'classification': 'start_of_binary'}

            off, word = self.words[idx]
            d = dec.decode(word)

            # Stop at control flow boundaries (step >= 1 to skip the branch itself)
            if step >= 1 and d['op6'] in BRANCH_OPS:
                is_core_esc_branch = (d['op6'] == dec.OP_CORE_ESC and
                                       d['escop'] == dec.ESC_CALLI)
                is_branch_op = d['op6'] != dec.OP_CORE_ESC or is_core_esc_branch

                if is_branch_op:
                    dr = dest_reg(d)
                    if dr == target_reg:
                        writer = classify_writer(self.words, idx, target_reg)
                        return self._writer_to_result(writer)

                    is_cond = d['op6'] in (dec.OP_BC, dec.OP_BNC, dec.OP_BC_T, dec.OP_BNC_T,
                                            dec.OP_BTE_REG, dec.OP_BTE_IMM,
                                            dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
                                            dec.OP_BLA)
                    if not is_cond:
                        # Hit another boundary — recurse
                        entry = dec.block_entry_after(off, d)
                        if 0 <= entry < self.binary_size:
                            return self.trace_register(entry, target_reg, depth + 1)
                        return {'classification': 'out_of_bounds'}
                    continue

            dr = dest_reg(d)
            if dr == target_reg:
                writer = classify_writer(self.words, idx, target_reg)
                return self._writer_to_result(writer)

        return {'classification': 'window_limit_in_predecessor'}

    def _writer_to_result(self, writer):
        """Convert a classify_writer result to a cross-block result."""
        stype = writer.get('source_type', 'unknown')

        if stype == 'orh_or_const':
            return {
                'classification': 'resolved_const',
                'value': writer.get('value'),
                'value_hex': writer.get('value_hex'),
                'detail': writer.get('detail'),
                'writer_addr': writer.get('writer_addr'),
            }
        elif stype in ('ld_table', 'ld_gstate'):
            return {
                'classification': 'resolved_load',
                'base_reg': writer.get('base_reg'),
                'offset': writer.get('offset'),
                'detail': writer.get('detail'),
                'writer_addr': writer.get('writer_addr'),
            }
        elif stype == 'ld_reg':
            return {
                'classification': 'resolved_load',
                'index_reg': writer.get('index_reg'),
                'base_reg': writer.get('base_reg'),
                'detail': writer.get('detail'),
                'writer_addr': writer.get('writer_addr'),
            }
        elif stype == 'register_chain':
            return {
                'classification': 'register_chain',
                'op': writer.get('op'),
                'input_regs': writer.get('input_regs', []),
                'detail': writer.get('detail'),
                'writer_addr': writer.get('writer_addr'),
            }
        else:
            return {
                'classification': 'unknown',
                'detail': writer.get('detail'),
            }

    def _consolidate(self, results, block_entry, target_reg):
        """Consolidate results from multiple predecessors."""
        valid = [r for r in results if r is not None]
        if not valid:
            return {'classification': 'no_valid_predecessors',
                    'block_entry': block_entry}

        # If all resolved to the same constant, that's definitive
        resolved = [r for r in valid if r.get('classification') == 'resolved_const'
                    and r.get('value') is not None]
        if resolved:
            values = set(r['value'] for r in resolved)
            if len(values) == 1:
                v = resolved[0]['value']
                return {
                    'classification': 'resolved_const',
                    'value': v,
                    'value_hex': f'0x{v:08x}',
                    'detail': resolved[0].get('detail'),
                    'writer_addr': resolved[0].get('writer_addr'),
                    'predecessor_count': len(valid),
                }
            else:
                return {
                    'classification': 'ambiguous',
                    'values': [f'0x{v:08x}' for v in sorted(values)],
                    'predecessor_count': len(valid),
                    'predecessors': valid,
                }

        # If single predecessor, use its result
        if len(valid) == 1:
            return valid[0]

        # Multiple predecessors with mixed results
        classifications = Counter(r.get('classification') for r in valid)
        return {
            'classification': 'ambiguous',
            'predecessor_count': len(valid),
            'classification_breakdown': dict(classifications),
            'predecessors': valid,
        }


# -----------------------------------------------------------------------
# Phase D: Multi-hop register chain resolution
# -----------------------------------------------------------------------

def resolve_register_chain(words, addr_to_idx, reverse_cfg, site, max_hops=MAX_REGISTER_HOPS):
    """Follow register chains across multiple hops to find terminal values.

    For a register_chain site, traces each input register backward.
    Returns list of terminal findings.
    """
    tracer = CrossBlockTracer(words, addr_to_idx, reverse_cfg)
    terminals = []

    def follow(writer_offset, input_regs, hop, path):
        if hop >= max_hops or len(terminals) >= MAX_CHAIN_PATHS:
            terminals.append({
                'classification': 'chain_depth_exhausted',
                'hops': hop,
                'path': list(path),
            })
            return

        for reg in input_regs:
            if len(terminals) >= MAX_CHAIN_PATHS:
                break

            # Scan backward from writer to find who set this input register
            scan = backward_scan(words, addr_to_idx, writer_offset, reg)

            if scan['found']:
                writer = scan['writer']
                stype = writer.get('source_type')
                new_path = path + [f'r{reg}@0x{writer.get("writer_offset", 0) + BASE_ADDR:08x}']

                if stype == 'orh_or_const':
                    terminals.append({
                        'classification': 'resolved_const',
                        'value': writer.get('value'),
                        'value_hex': writer.get('value_hex'),
                        'detail': writer.get('detail'),
                        'hops': hop + 1,
                        'path': new_path,
                    })
                elif stype in ('ld_table', 'ld_gstate', 'ld_reg'):
                    terminals.append({
                        'classification': 'resolved_load',
                        'detail': writer.get('detail'),
                        'hops': hop + 1,
                        'path': new_path,
                    })
                elif stype == 'register_chain':
                    next_inputs = writer.get('input_regs', [])
                    next_offset = writer.get('writer_offset', 0)
                    if next_inputs and next_offset:
                        follow(next_offset, next_inputs, hop + 1, new_path)
                    else:
                        terminals.append({
                            'classification': 'chain_dead_end',
                            'detail': writer.get('detail'),
                            'hops': hop + 1,
                            'path': new_path,
                        })
                else:
                    terminals.append({
                        'classification': 'unknown',
                        'detail': writer.get('detail'),
                        'hops': hop + 1,
                        'path': new_path,
                    })
            elif scan['stop_reason'] == 'branch_boundary':
                # Try cross-block tracing
                block_entry = scan.get('block_entry')
                if block_entry and 0 <= block_entry < len(words) * 4:
                    cb_result = tracer.trace_register(block_entry, reg, 0)
                    cb_result['hops'] = hop + 1
                    cb_result['path'] = path + [f'r{reg}@cross_block']
                    terminals.append(cb_result)
                else:
                    terminals.append({
                        'classification': 'boundary_unresolved',
                        'stop_op': scan.get('stop_op'),
                        'hops': hop + 1,
                        'path': path + [f'r{reg}@boundary'],
                    })
            else:
                terminals.append({
                    'classification': 'scan_failed',
                    'stop_reason': scan.get('stop_reason'),
                    'hops': hop + 1,
                    'path': path + [f'r{reg}@{scan.get("stop_reason", "unknown")}'],
                })

    # Get writer info from Phase 1
    writer_offset_hex = site.get('writer_file_offset', '0x00000')
    writer_offset = int(writer_offset_hex, 16)
    detail = site.get('detail', '')

    # Extract input register numbers from Phase 1 data
    # Re-decode the writer instruction to get input regs
    if writer_offset in addr_to_idx:
        _, word = words[addr_to_idx[writer_offset]]
        d = dec.decode(word)
        input_regs = dec.writer_input_regs(d)
    else:
        input_regs = []

    if input_regs:
        follow(writer_offset, input_regs, 0, [f'writer@0x{writer_offset + BASE_ADDR:08x}'])

    return terminals


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    print("Phase 2 — Cross-Block BRI Resolution")
    print(f"Binary: {BINARY}")
    print(f"ABI: {ABI} (callee-saved: r{min(CALLEE_SAVED)}–r{max(CALLEE_SAVED)})")

    # Load binary
    words = dec.read_words(str(BINARY))
    addr_to_idx = {off: i for i, (off, _) in enumerate(words)}
    binary_size = len(words) * 4
    print(f"  Binary size: {binary_size} bytes ({len(words)} words)")

    # Load Phase 1 results
    with open(PHASE1_JSON) as f:
        phase1 = json.load(f)
    bri_sites = phase1['bri_sites']
    print(f"  Phase 1 bri sites: {len(bri_sites)}")

    # Load register context (may be empty if base_register_census found no persistent regs)
    reg_context = {}
    if REG_CONTEXT.exists():
        with open(REG_CONTEXT) as f:
            reg_context = json.load(f).get('registers', {})

    # -----------------------------------------------------------------------
    # Phase A: Build reverse CFG
    # -----------------------------------------------------------------------
    print("\n--- Phase A: Building reverse CFG ---")
    reverse_cfg = dec.build_reverse_cfg(words, BASE_ADDR)
    total_edges = sum(len(v) for v in reverse_cfg.values())
    print(f"  Blocks with predecessors: {len(reverse_cfg)}")
    print(f"  Total edges: {total_edges}")

    # Edge type breakdown
    edge_types = Counter()
    for edges in reverse_cfg.values():
        for e in edges:
            edge_types[e['opname']] += 1
    print("  Edge sources by opname:")
    for opname, count in edge_types.most_common(10):
        print(f"    {opname}: {count}")

    # -----------------------------------------------------------------------
    # Phase B: Recompute boundary metadata
    # -----------------------------------------------------------------------
    print("\n--- Phase B: Recomputing boundary metadata ---")
    boundary_data = []
    stop_reason_counts = Counter()
    stop_op_counts = Counter()

    for site in bri_sites:
        bri_offset = site['file_offset_int']
        target_reg_str = site['target_reg']  # "rN"
        target_reg = int(target_reg_str[1:])

        scan = backward_scan(words, addr_to_idx, bri_offset, target_reg)
        stop_reason = scan.get('stop_reason', 'unknown')
        stop_reason_counts[stop_reason] += 1

        entry = {
            'bri_addr': site['addr'],
            'bri_offset': bri_offset,
            'target_reg': target_reg_str,
            'target_reg_num': target_reg,
            'stop_reason': stop_reason,
            'phase1_source_type': site['source_type'],
        }

        if stop_reason == 'branch_boundary':
            entry['stop_op'] = scan.get('stop_op')
            entry['stop_addr'] = scan.get('stop_addr')
            entry['stop_addr_va'] = scan.get('stop_addr_va')
            entry['block_entry'] = scan.get('block_entry')
            entry['is_delayed'] = scan.get('is_delayed')
            stop_op_counts[scan.get('stop_op', 'unknown')] += 1
        elif stop_reason == 'found_writer':
            entry['writer'] = scan.get('writer')

        boundary_data.append(entry)

    print(f"  Stop reason breakdown:")
    for reason, count in stop_reason_counts.most_common():
        print(f"    {reason}: {count}")

    if stop_op_counts:
        print(f"  Boundary terminator breakdown:")
        for op, count in stop_op_counts.most_common():
            print(f"    {op}: {count}")

    # -----------------------------------------------------------------------
    # Phase C: Cross-block tracing
    # -----------------------------------------------------------------------
    print("\n--- Phase C: Cross-block register tracing ---")
    cross_block_results = []
    classification_counts = Counter()

    boundary_sites = [b for b in boundary_data if b['stop_reason'] == 'branch_boundary']
    print(f"  Boundary sites to trace: {len(boundary_sites)}")

    tracer = CrossBlockTracer(words, addr_to_idx, reverse_cfg)

    for bd in boundary_sites:
        stop_op = bd.get('stop_op', '')
        block_entry = bd.get('block_entry')
        target_reg = bd['target_reg_num']
        bri_offset = bd['bri_offset']

        # Skip untraceable terminators
        if stop_op in ('bri', 'trap'):
            cls = 'dynamic_entry' if stop_op == 'bri' else 'trap_entry'
            classification_counts[cls] += 1
            cross_block_results.append({
                'bri_addr': bd['bri_addr'],
                'bri_offset': bri_offset,
                'target_reg': bd['target_reg'],
                'classification': cls,
                'stop_op': stop_op,
            })
            continue

        if block_entry is None or block_entry < 0 or block_entry >= binary_size:
            classification_counts['invalid_block_entry'] += 1
            cross_block_results.append({
                'bri_addr': bd['bri_addr'],
                'bri_offset': bri_offset,
                'target_reg': bd['target_reg'],
                'classification': 'invalid_block_entry',
            })
            continue

        # Trace register through reverse CFG
        result = tracer.trace_register(block_entry, target_reg, 0)
        cls = result.get('classification', 'unknown')
        classification_counts[cls] += 1

        cross_block_results.append({
            'bri_addr': bd['bri_addr'],
            'bri_offset': bri_offset,
            'target_reg': bd['target_reg'],
            'stop_op': stop_op,
            'block_entry': block_entry,
            **result,
        })

    print(f"  Cross-block classification breakdown:")
    for cls, count in classification_counts.most_common():
        print(f"    {cls}: {count}")
    print(f"  Total visit budget used: {tracer.visit_count}/{MAX_VISIT_BUDGET}")

    # -----------------------------------------------------------------------
    # Phase D: Multi-hop register chains
    # -----------------------------------------------------------------------
    print("\n--- Phase D: Multi-hop register chain resolution ---")
    chain_sites = [s for s in bri_sites if s['source_type'] == 'register_chain']
    print(f"  Register chain sites: {len(chain_sites)}")

    chain_results = []
    chain_classification_counts = Counter()

    for site in chain_sites:
        terminals = resolve_register_chain(words, addr_to_idx, reverse_cfg, site)
        for t in terminals:
            chain_classification_counts[t.get('classification', 'unknown')] += 1

        chain_results.append({
            'bri_addr': site['addr'],
            'bri_offset': site['file_offset_int'],
            'target_reg': site['target_reg'],
            'phase1_detail': site.get('detail', ''),
            'terminals': terminals,
        })

    print(f"  Chain terminal classification:")
    for cls, count in chain_classification_counts.most_common():
        print(f"    {cls}: {count}")

    # -----------------------------------------------------------------------
    # Phase E: ld_table / ld_reg deep analysis
    # -----------------------------------------------------------------------
    print("\n--- Phase E: ld_table/ld_reg deep analysis ---")
    load_sites = [s for s in bri_sites if s['source_type'] in ('ld_table', 'ld_reg')]
    print(f"  Load-based sites: {len(load_sites)}")

    load_results = []
    for site in load_sites:
        # Trace the base register
        writer_offset_hex = site.get('writer_file_offset', '0x00000')
        writer_offset = int(writer_offset_hex, 16)
        base_reg_str = site.get('base_reg', 'r0')
        base_reg = int(base_reg_str[1:]) if base_reg_str.startswith('r') else 0

        # For ld_reg, also trace index_reg
        index_reg_str = site.get('index_reg')
        index_reg = int(index_reg_str[1:]) if index_reg_str and index_reg_str.startswith('r') else None

        load_tracer = CrossBlockTracer(words, addr_to_idx, reverse_cfg)

        # Trace base register backward from the load instruction
        base_scan = backward_scan(words, addr_to_idx, writer_offset, base_reg)
        base_result = {'classification': 'scan_failed', 'stop_reason': base_scan.get('stop_reason')}
        if base_scan['found']:
            base_result = load_tracer._writer_to_result(base_scan['writer'])
        elif base_scan.get('stop_reason') == 'branch_boundary':
            block_entry = base_scan.get('block_entry')
            if block_entry is not None and 0 <= block_entry < binary_size:
                base_result = load_tracer.trace_register(block_entry, base_reg, 0)
        elif base_scan.get('stop_reason') == 'window_limit':
            base_result = {'classification': 'window_limit', 'detail': f'r{base_reg} not found in {MAX_INTRA_BLOCK_SCAN} insns'}

        # Trace index register if applicable
        index_result = None
        if index_reg is not None:
            idx_scan = backward_scan(words, addr_to_idx, writer_offset, index_reg)
            index_result = {'classification': 'scan_failed', 'stop_reason': idx_scan.get('stop_reason')}
            if idx_scan['found']:
                index_result = load_tracer._writer_to_result(idx_scan['writer'])
            elif idx_scan.get('stop_reason') == 'branch_boundary':
                block_entry = idx_scan.get('block_entry')
                if block_entry is not None and 0 <= block_entry < binary_size:
                    index_result = load_tracer.trace_register(block_entry, index_reg, 0)

        # Compute effective address if possible
        effective_addr = None
        if base_result.get('classification') == 'resolved_const':
            base_val = base_result.get('value', 0)
            offset = site.get('offset')
            if isinstance(offset, int):
                effective_addr = (base_val + offset) & 0xFFFFFFFF

        entry = {
            'bri_addr': site['addr'],
            'bri_offset': site['file_offset_int'],
            'target_reg': site['target_reg'],
            'load_detail': site.get('detail', ''),
            'base_reg': base_reg_str,
            'base_trace': base_result,
        }
        if index_result:
            entry['index_reg'] = index_reg_str
            entry['index_trace'] = index_result
        if effective_addr is not None:
            entry['effective_addr'] = f'0x{effective_addr:08x}'
            entry['effective_addr_int'] = effective_addr
            # Try to read table entries from binary
            table_offset = effective_addr - BASE_ADDR
            if 0 <= table_offset < binary_size - 4:
                entries = []
                for j in range(8):
                    ptr_off = table_offset + j * 4
                    if ptr_off + 4 > binary_size:
                        break
                    if (ptr_off & ~3) in addr_to_idx:
                        _, word_val = words[addr_to_idx[ptr_off & ~3]]
                        entries.append(f'0x{word_val:08x}')
                entry['table_entries'] = entries

        load_results.append(entry)
        print(f"  {site['addr']}: {site.get('detail', '')}")
        print(f"    base r{base_reg} trace: {base_result.get('classification')} — {base_result.get('detail', 'n/a')}")
        if index_result:
            print(f"    index r{index_reg} trace: {index_result.get('classification')} — {index_result.get('detail', 'n/a')}")
        if effective_addr is not None:
            print(f"    effective addr: 0x{effective_addr:08x}")

    # -----------------------------------------------------------------------
    # Collect all resolved constants
    # -----------------------------------------------------------------------
    all_resolved = []

    # From cross-block tracing
    for r in cross_block_results:
        if r.get('classification') == 'resolved_const' and r.get('value') is not None:
            all_resolved.append({
                'source': 'cross_block',
                'bri_addr': r['bri_addr'],
                'value': r['value'],
                'value_hex': r.get('value_hex', f'0x{r["value"]:08x}'),
            })

    # From register chain multi-hop
    for cr in chain_results:
        for t in cr.get('terminals', []):
            if t.get('classification') == 'resolved_const' and t.get('value') is not None:
                all_resolved.append({
                    'source': 'register_chain',
                    'bri_addr': cr['bri_addr'],
                    'value': t['value'],
                    'value_hex': t.get('value_hex', f'0x{t["value"]:08x}'),
                })

    # From intra-block found_writer (Phase B found some directly)
    for bd in boundary_data:
        if bd['stop_reason'] == 'found_writer':
            writer = bd.get('writer', {})
            if writer.get('source_type') == 'orh_or_const' and writer.get('value') is not None:
                all_resolved.append({
                    'source': 'intra_block',
                    'bri_addr': bd['bri_addr'],
                    'value': writer['value'],
                    'value_hex': writer.get('value_hex', f'0x{writer["value"]:08x}'),
                })

    unique_resolved = {}
    for r in all_resolved:
        v = r['value']
        if v not in unique_resolved:
            unique_resolved[v] = r

    print(f"\n{'='*60}")
    print(f"PHASE 2 SUMMARY")
    print(f"{'='*60}")
    print(f"Total bri sites analyzed: {len(bri_sites)}")
    print(f"Boundary sites traced: {len(boundary_sites)}")
    print(f"Resolved constants: {len(all_resolved)} ({len(unique_resolved)} unique)")

    if unique_resolved:
        print(f"\nResolved target values:")
        for v in sorted(unique_resolved.keys()):
            r = unique_resolved[v]
            in_text = BASE_ADDR <= v < BASE_ADDR + binary_size
            label = " (in TEXT)" if in_text else ""
            print(f"  0x{v:08x} [{r['source']}] from {r['bri_addr']}{label}")

    # -----------------------------------------------------------------------
    # Write output
    # -----------------------------------------------------------------------
    output = {
        'metadata': {
            'binary': str(BINARY.name),
            'base_address': f'0x{BASE_ADDR:08x}',
            'binary_size': binary_size,
            'abi': ABI,
            'phase1_sites': len(bri_sites),
            'boundary_sites': len(boundary_sites),
            'cfg_blocks': len(reverse_cfg),
            'cfg_edges': total_edges,
            'visit_budget_used': tracer.visit_count,
        },
        'stop_reason_breakdown': dict(stop_reason_counts),
        'boundary_terminator_breakdown': dict(stop_op_counts),
        'cross_block_classification': dict(classification_counts),
        'chain_classification': dict(chain_classification_counts),
        'resolved_constants': [
            {'value': f'0x{v:08x}', 'value_int': v,
             'source': unique_resolved[v]['source'],
             'bri_addr': unique_resolved[v]['bri_addr'],
             'in_text': BASE_ADDR <= v < BASE_ADDR + binary_size}
            for v in sorted(unique_resolved.keys())
        ],
        'cross_block_results': cross_block_results,
        'chain_results': chain_results,
        'load_results': load_results,
        'boundary_data_sample': boundary_data[:20],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nOutput written to: {OUTPUT}")


if __name__ == '__main__':
    main()
