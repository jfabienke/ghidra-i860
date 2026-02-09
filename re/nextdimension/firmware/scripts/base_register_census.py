#!/usr/bin/env python3
"""Phase 2 — Base register census for r18 and r7 (and r13).

Determines if these registers are persistent base pointers by:
1. Scanning the entire binary for all instructions that write to each register
2. Classifying each write pattern (orh+or constant, load, copy, ALU)
3. Inferring persistence from write frequency and location
4. Resolving constant values where possible

If r18 resolves to a constant, computes all orh imm, r18, rDest effective addresses.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import i860_decode as dec

BINARY = Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
OUTPUT = Path(__file__).parent.parent / "analysis" / "phase2" / "register_context.json"
BASE_ADDR = 0xF8000000

# Registers of interest for base-pointer analysis
TARGET_REGS = [7, 13, 18]

# Dest-writing opcodes (from Phase 1)
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

# Opcodes recognized as valid instructions (for code context scoring)
CODE_LIKE_OPS = DEST_WRITING_OPS | {
    dec.OP_BRI, dec.OP_BR, dec.OP_CALL,
    dec.OP_BC, dec.OP_BC_T, dec.OP_BNC, dec.OP_BNC_T,
    dec.OP_BLA, dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
    dec.OP_BTE_REG, dec.OP_BTE_IMM, dec.OP_TRAP,
    0x00, 0x01, 0x02, 0x03, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x12, 0x13,
}


def code_context_score(words, idx, window=4):
    """Score 0.0-1.0 for how code-like the context is around idx."""
    valid = 0
    total = 0
    for delta in range(-window, window + 1):
        if delta == 0:
            continue
        j = idx + delta
        if j < 0 or j >= len(words):
            continue
        total += 1
        _, w = words[j]
        d = dec.decode(w)
        if d['op6'] in CODE_LIKE_OPS or w == 0:
            valid += 1
    return valid / total if total > 0 else 0.0


def classify_write(words, idx, reg):
    """Classify how instruction at idx writes to reg.

    Returns dict with write_type and details.
    """
    off, word = words[idx]
    d = dec.decode(word)
    va = off + BASE_ADDR

    result = {
        'addr': f'0x{va:08x}',
        'file_offset': f'0x{off:05x}',
        'file_offset_int': off,
        'opname': None,
        'write_type': 'unknown',
        'detail': '',
        'code_score': code_context_score(words, idx),
    }

    op = d['op6']

    # orh imm16, Rsrc2, Rdest — check for following or to form constant
    if dec.is_orh(d) and d['dest'] == reg:
        hi16 = d['imm16']
        src2 = d['src2']
        result['opname'] = 'orh'
        # Look ahead for or imm, Rdest, Rdest
        if idx + 1 < len(words):
            _, w2 = words[idx + 1]
            d2 = dec.decode(w2)
            if dec.is_or_imm(d2) and d2['src2'] == reg and d2['dest'] == reg:
                lo16 = d2['imm16']
                value = (hi16 << 16) | lo16
                result['write_type'] = 'orh_or_const'
                result['value'] = value
                result['value_hex'] = f'0x{value:08x}'
                result['src2'] = src2
                result['detail'] = f'orh 0x{hi16:04x},r{src2},r{reg} + or 0x{lo16:04x},r{reg},r{reg} = 0x{value:08x}'
                return result
        result['write_type'] = 'orh_only'
        result['detail'] = f'orh 0x{hi16:04x}, r{src2}, r{reg}'
        return result

    # or imm — possibly constant construction (without preceding orh)
    if dec.is_or_imm(d) and d['dest'] == reg:
        imm = d['imm16']
        src2 = d['src2']
        if src2 == 0:
            result['write_type'] = 'or_imm_const'
            result['value'] = imm
            result['value_hex'] = f'0x{imm:08x}'
            result['detail'] = f'or 0x{imm:04x}, r0, r{reg} (small constant)'
        else:
            result['write_type'] = 'or_imm_merge'
            result['detail'] = f'or 0x{imm:04x}, r{src2}, r{reg}'
        result['opname'] = 'or_imm'
        return result

    # ld.l / ld.s immediate form
    if op == dec.OP_LD_IMM and d['dest'] == reg:
        base = d['src2']
        offset = d['simm16']
        size = '.l' if d['lsbit0'] else '.s'
        result['write_type'] = 'load_imm'
        result['opname'] = f'ld{size}_imm'
        result['base_reg'] = base
        result['offset'] = offset
        result['detail'] = f'ld{size} {offset}(r{base}), r{reg}'
        return result

    # ld reg form
    if op == dec.OP_LD_REG and d['dest'] == reg:
        size = '.l' if d['lsbit0'] else '.s'
        result['write_type'] = 'load_reg'
        result['opname'] = f'ld{size}_reg'
        result['detail'] = f'ld{size} r{d["src1"]}(r{d["src2"]}), r{reg}'
        return result

    # addu / adds / or reg — register copy/compute
    if op in DEST_WRITING_OPS and d['dest'] == reg:
        # Identify the operation
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
        opname = op_names.get(op, f'op{op:02x}')
        result['opname'] = opname
        result['write_type'] = 'alu'
        inputs = dec.writer_input_regs(d)
        result['input_regs'] = [f'r{r}' for r in inputs]
        result['detail'] = f'{opname} -> r{reg} (inputs: {", ".join(f"r{r}" for r in inputs) or "none"})'
        return result

    result['detail'] = f'op{op:02x} -> r{reg}'
    return result


def scan_orh_uses(words, base_reg, base_value):
    """Find all orh imm, rBase, rDest instructions and compute effective addresses.

    For `orh imm, rBase, rDest`: effective upper bits = (base_value & 0xFFFF0000) | (imm << 16)
    Actually orh semantics: Rd = (imm16 << 16) | Rsrc2  -> so result = (imm << 16) | (base_value & 0xFFFF)
    Wait — re-check: orh sets bits[31:16] of dest from imm16, bits[15:0] from src2.
    Actually from SLEIGH: dest = (imm16 << 16) | (src2 & 0xFFFF).
    Wait no: `or` does OR. orh = imm16 << 16 OR'd with src2.
    Since it's an OR: dest = src2 | (imm16 << 16).
    With base_value known: dest_upper = base_value | (imm16 << 16).
    """
    results = []
    for i, (off, word) in enumerate(words):
        d = dec.decode(word)
        if not dec.is_orh(d) or d['src2'] != base_reg:
            continue

        va = off + BASE_ADDR
        hi16 = d['imm16']
        dest = d['dest']
        # orh semantics: dest = (hi16 << 16) | (src2 & 0xFFFF)
        # Since src2 = base_reg with known value:
        effective = (hi16 << 16) | (base_value & 0xFFFF)

        entry = {
            'addr': f'0x{va:08x}',
            'file_offset': f'0x{off:05x}',
            'dest_reg': f'r{dest}',
            'hi16': f'0x{hi16:04x}',
            'effective': f'0x{effective:08x}',
            'effective_int': effective,
        }

        # Check for following or to get full value
        if i + 1 < len(words):
            _, w2 = words[i + 1]
            d2 = dec.decode(w2)
            if dec.is_or_imm(d2) and d2['src2'] == dest and d2['dest'] == dest:
                lo16 = d2['imm16']
                full = effective | lo16  # Actually: (hi16<<16) | base_lo | lo16
                # More precisely: after orh, dest = (hi16<<16) | (base & 0xFFFF)
                # After or: dest = dest | lo16 = (hi16<<16) | (base & 0xFFFF) | lo16
                entry['or_lo16'] = f'0x{lo16:04x}'
                entry['full_value'] = f'0x{full:08x}'
                entry['full_value_int'] = full

        results.append(entry)
    return results


def main():
    print(f"Phase 2 — Base Register Census")
    print(f"Binary: {BINARY}")
    words = dec.read_words(str(BINARY))
    addr_to_idx = {off: i for i, (off, _) in enumerate(words)}
    print(f"  Total words: {len(words)}")

    output = {'registers': {}}

    for reg in TARGET_REGS:
        print(f"\n{'='*60}")
        print(f"Scanning writes to r{reg}")
        print(f"{'='*60}")

        writes = []
        for i, (off, word) in enumerate(words):
            d = dec.decode(word)
            op = d['op6']

            # Check if this instruction writes to our target register
            writes_dest = False
            if op in DEST_WRITING_OPS and d['dest'] == reg:
                writes_dest = True
            elif op == dec.OP_CALL and reg == 1:
                writes_dest = True  # call writes r1
            elif op == dec.OP_CORE_ESC and d['escop'] == dec.ESC_CALLI and reg == 1:
                writes_dest = True  # calli writes r1

            if not writes_dest:
                continue

            wc = classify_write(words, i, reg)
            writes.append(wc)

        # Filter to likely code regions
        code_writes = [w for w in writes if w['code_score'] >= 0.5]
        data_writes = [w for w in writes if w['code_score'] < 0.5]

        print(f"  Total writes found: {len(writes)}")
        print(f"  In code regions (score >= 0.5): {len(code_writes)}")
        print(f"  In data regions (score < 0.5): {len(data_writes)}")

        # Classify write types
        type_counts = defaultdict(int)
        for w in code_writes:
            type_counts[w['write_type']] += 1

        print(f"  Write type breakdown (code only):")
        for wtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {wtype}: {count}")

        # Check for constant resolution
        resolved_constants = []
        for w in code_writes:
            if w['write_type'] == 'orh_or_const' and 'value' in w:
                resolved_constants.append(w)
            elif w['write_type'] == 'or_imm_const' and 'value' in w:
                resolved_constants.append(w)

        if resolved_constants:
            print(f"  Resolved constants:")
            unique_values = set()
            for rc in resolved_constants:
                v = rc['value']
                unique_values.add(v)
                print(f"    {rc['addr']}: 0x{v:08x} ({rc['detail']})")
            print(f"  Unique constant values: {sorted(f'0x{v:08x}' for v in unique_values)}")

        # Persistence inference
        is_persistent = False
        dominant_value = None
        if len(code_writes) <= 5 and resolved_constants:
            # Few writes, at least one constant → likely persistent
            is_persistent = True
            # Find most common value
            from collections import Counter
            val_counts = Counter(rc['value'] for rc in resolved_constants)
            dominant_value = val_counts.most_common(1)[0][0]
            print(f"  PERSISTENT: r{reg} appears to be a base pointer (few writes, constant value)")
            print(f"  Dominant value: 0x{dominant_value:08x}")

        reg_info = {
            'total_writes': len(writes),
            'code_writes': len(code_writes),
            'data_writes': len(data_writes),
            'write_types': dict(type_counts),
            'is_persistent': is_persistent,
            'dominant_value': f'0x{dominant_value:08x}' if dominant_value else None,
            'dominant_value_int': dominant_value,
            'code_write_sites': code_writes,
            'resolved_constants': [{'addr': rc['addr'], 'value': rc['value'],
                                     'value_hex': f'0x{rc["value"]:08x}'}
                                    for rc in resolved_constants],
        }

        # If persistent with known value, compute orh-derived addresses
        if is_persistent and dominant_value is not None:
            print(f"\n  Scanning orh uses of r{reg} with base value 0x{dominant_value:08x}...")
            orh_uses = scan_orh_uses(words, reg, dominant_value)
            print(f"  Found {len(orh_uses)} orh uses")

            # Show unique effective addresses
            effective_addrs = set()
            for u in orh_uses:
                if 'full_value_int' in u:
                    effective_addrs.add(u['full_value_int'])
                else:
                    effective_addrs.add(u['effective_int'])
            print(f"  Unique effective addresses: {len(effective_addrs)}")
            for a in sorted(effective_addrs)[:20]:
                in_text = BASE_ADDR <= a < BASE_ADDR + len(words) * 4
                label = " (in TEXT)" if in_text else ""
                print(f"    0x{a:08x}{label}")
            if len(effective_addrs) > 20:
                print(f"    ... and {len(effective_addrs) - 20} more")

            reg_info['orh_uses'] = orh_uses
            reg_info['effective_addresses'] = sorted(f'0x{a:08x}' for a in effective_addrs)
            reg_info['effective_addresses_int'] = sorted(effective_addrs)

        output['registers'][f'r{reg}'] = reg_info

    # Write output
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nOutput written to: {OUTPUT}")


if __name__ == '__main__':
    main()
