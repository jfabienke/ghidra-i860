#!/usr/bin/env python3
"""Enumerate all 32-bit constant constructions in ND i860 firmware.

The i860 has no 32-bit immediate instruction. Constants are constructed via:
  1. orh+or pairs: orh hi, Rsrc, Rdest; or lo, Rsrc, Rdest  (same base reg)
     OR: orh hi, Rsrc, Rdest; or lo, Rdest, Rdest  (chained through dest)
  2. Standalone orh: orh hi, Rsrc, Rdest  (upper-half-only OR into a register)
  3. Small constants: or imm16, r0, Rd  /  addu simm16, r0, Rd

This firmware heavily uses standalone orh for register-relative offset
construction (especially via r15=GState base), rather than classic orh+or pairs.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Add scripts dir to path for shared decoder
sys.path.insert(0, str(Path(__file__).resolve().parent))
import i860_decode as dec

# --- Configuration ---
BINARY = Path(__file__).resolve().parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
OUTPUT = Path(__file__).resolve().parent.parent / "analysis" / "phase1" / "constants.json"

# Firmware address ranges
FW_CODE_START = 0x00001000
FW_CODE_END   = 0x00031000  # 200704 bytes = 0x31000
FW_SIZE       = 200704

# Branch opcodes (terminate forward scan)
BRANCH_OPS = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x10, 0x11, 0x2D}

# Opcodes that write to their dest field
DEST_WRITE_OPS = set(range(0x40)) - {
    0x06, 0x07,   # st.s, st.l (store: src1 written TO memory, dest is addr reg read)
    0x14, 0x15,   # btne (branch, no write)
    0x16, 0x17,   # bte (branch, no write)
    0x1A, 0x1B,   # br, call (no register dest write from imm)
    0x1C, 0x1D,   # bc, bc.t
    0x1E, 0x1F,   # bnc, bnc.t
    0x2D,          # bla
    0x11,          # trap
}


# --- Classification ---

def is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0

def is_bitmask(value):
    if value == 0:
        return False
    if is_power_of_two(value + 1):
        return True
    if is_power_of_two(value):
        return True
    inv = (~value) & 0xFFFFFFFF
    if is_power_of_two(inv + 1):
        return True
    v = value
    while v and not (v & 1):
        v >>= 1
    if v > 0 and is_power_of_two(v + 1):
        return True
    return False


def classify_value(value):
    """Classify a 32-bit constructed value."""
    if FW_CODE_START <= value <= FW_CODE_END and (value & 0x3) == 0:
        return "code_ptr"
    if 0x00000000 <= value <= 0x00000FFF:
        return "data_ptr"
    if 0xF8000000 <= value <= 0xF8FFFFFF:
        return "kernel_vaddr"
    if (value >> 28) == 0xF:
        return "mmio"
    if is_bitmask(value):
        return "mask"
    return "other"


def classify_hi16(imm16):
    """Classify a standalone orh by its upper-half value."""
    hi = imm16 << 16
    if hi == 0:
        return "zero_hi"
    if 0xF800 <= imm16 <= 0xF8FF:
        return "kernel_vaddr_hi"
    if (imm16 >> 12) == 0xF:
        return "mmio_hi"
    if is_bitmask(hi):
        return "mask_hi"
    if FW_CODE_START <= hi <= FW_CODE_END:
        return "code_range_hi"
    return "other_hi"


def reg_name(n):
    return f"r{n}"


def find_orh_or_pairs_extended(words):
    """Find orh+or pairs with both matching patterns:
    Pattern A (same-base):  orh hi, Rsrc, Rdest  +  or lo, Rsrc, Rdest
    Pattern B (chained):    orh hi, Rsrc, Rdest  +  or lo, Rdest, Rdest

    Scans up to 20 instructions forward, stopping at branches or dest overwrites.
    """
    pairs = []
    paired_orh_offsets = set()

    for i, (off1, w1) in enumerate(words):
        d1 = dec.decode(w1)
        if not dec.is_orh(d1):
            continue

        dest = d1['dest']
        src2 = d1['src2']

        for j in range(1, 21):
            if i + j >= len(words):
                break
            off2, w2 = words[i + j]
            d2 = dec.decode(w2)

            # Pattern A: or lo, same_src, same_dest
            if (dec.is_or_imm(d2) and d2['dest'] == dest
                    and d2['src2'] == src2):
                value = (d1['imm16'] << 16) | d2['imm16']
                pairs.append({
                    'orh_addr': off1,
                    'or_addr': off2,
                    'gap': j,
                    'pattern': 'same_base',
                    'src2': src2,
                    'dest': dest,
                    'hi16': d1['imm16'],
                    'lo16': d2['imm16'],
                    'value': value,
                })
                paired_orh_offsets.add(off1)
                break

            # Pattern B: or lo, Rdest, Rdest (chained)
            if (dec.is_or_imm(d2) and d2['dest'] == dest
                    and d2['src2'] == dest and src2 != dest):
                value = (d1['imm16'] << 16) | d2['imm16']
                pairs.append({
                    'orh_addr': off1,
                    'or_addr': off2,
                    'gap': j,
                    'pattern': 'chained',
                    'src2': src2,
                    'dest': dest,
                    'hi16': d1['imm16'],
                    'lo16': d2['imm16'],
                    'value': value,
                })
                paired_orh_offsets.add(off1)
                break

            # Stop at branches
            if d2['op6'] in BRANCH_OPS:
                break

            # Stop if dest register is overwritten by a different instruction
            if (d2['op6'] in DEST_WRITE_OPS and d2['dest'] == dest
                    and d2['op6'] != dec.OP_ORH_IMM):
                break

    return pairs, paired_orh_offsets


def find_small_constants(words):
    """Find or imm16, r0, Rd and addu simm16, r0, Rd (small constant loads)."""
    results = []
    for off, word in words:
        d = dec.decode(word)
        # or imm16, r0, Rd -- loads unsigned 16-bit constant
        if dec.is_or_imm(d) and d['src2'] == 0 and d['dest'] != 0:
            results.append({
                'addr': off,
                'insn': 'or',
                'value': d['imm16'],
                'dest': d['dest'],
            })
        # addu simm16, r0, Rd -- loads signed 16-bit constant
        elif dec.is_addu_imm(d) and d['src2'] == 0 and d['dest'] != 0:
            results.append({
                'addr': off,
                'insn': 'addu',
                'value': d['simm16'] & 0xFFFFFFFF,
                'dest': d['dest'],
            })
    return results


def main():
    print(f"Reading binary: {BINARY}")
    print(f"Binary size: {BINARY.stat().st_size} bytes ({BINARY.stat().st_size // 4} words)\n")

    words = dec.read_words(str(BINARY))
    total_words = len(words)

    # ===================================================================
    # 1. Find orh+or pairs (extended: same-base AND chained patterns)
    # ===================================================================
    pairs, paired_orh_offsets = find_orh_or_pairs_extended(words)

    pair_records = []
    for p in pairs:
        value = p['value']
        src2 = p['src2']
        is_absolute = (src2 == 0)
        cls = classify_value(value)
        pair_records.append({
            'orh_addr': f"0x{p['orh_addr']:05X}",
            'or_addr': f"0x{p['or_addr']:05X}",
            'orh_addr_int': p['orh_addr'],
            'or_addr_int': p['or_addr'],
            'gap': p['gap'],
            'pattern': p['pattern'],
            'src2': src2,
            'src2_name': reg_name(src2),
            'dest': p['dest'],
            'dest_name': reg_name(p['dest']),
            'hi16': f"0x{p['hi16']:04X}",
            'lo16': f"0x{p['lo16']:04X}",
            'value_hex': f"0x{value:08X}",
            'value_dec': value,
            'classification': cls,
            'is_absolute': is_absolute,
        })

    # ===================================================================
    # 2. Find standalone orh (not part of any pair)
    # ===================================================================
    standalone_orh = []
    for off, word in words:
        d = dec.decode(word)
        if not dec.is_orh(d):
            continue
        if off in paired_orh_offsets:
            continue
        hi_val = d['imm16'] << 16
        cls = classify_hi16(d['imm16'])
        standalone_orh.append({
            'addr': f"0x{off:05X}",
            'addr_int': off,
            'src2': d['src2'],
            'src2_name': reg_name(d['src2']),
            'dest': d['dest'],
            'dest_name': reg_name(d['dest']),
            'hi16': f"0x{d['imm16']:04X}",
            'hi_value_hex': f"0x{hi_val:08X}",
            'hi_value_dec': hi_val,
            'classification': cls,
            'is_absolute': (d['src2'] == 0),
        })

    # ===================================================================
    # 3. Find small constants (or/addu with r0)
    # ===================================================================
    small_consts = find_small_constants(words)

    # ===================================================================
    # 4. Classification & grouping
    # ===================================================================
    # -- Pairs --
    pair_by_class = defaultdict(list)
    for p in pair_records:
        pair_by_class[p['classification']].append({
            'orh_addr': p['orh_addr'],
            'or_addr': p['or_addr'],
            'value_hex': p['value_hex'],
            'is_absolute': p['is_absolute'],
            'src2_name': p['src2_name'],
            'dest_name': p['dest_name'],
            'pattern': p['pattern'],
            'gap': p['gap'],
        })

    # -- Standalone orh by classification --
    orh_by_class = defaultdict(list)
    for s in standalone_orh:
        orh_by_class[s['classification']].append({
            'addr': s['addr'],
            'hi16': s['hi16'],
            'src2_name': s['src2_name'],
            'dest_name': s['dest_name'],
        })

    # -- Standalone orh by base register --
    orh_by_base = defaultdict(list)
    for s in standalone_orh:
        orh_by_base[reg_name(s['src2'])].append({
            'addr': s['addr'],
            'hi16': s['hi16'],
            'dest_name': s['dest_name'],
        })

    # -- Unique values from pairs --
    pair_unique = defaultdict(list)
    for p in pair_records:
        pair_unique[p['value_dec']].append(p['orh_addr'])

    pair_value_freq = sorted(
        [(v, len(a), f"0x{v:08X}", a) for v, a in pair_unique.items()],
        key=lambda x: -x[1]
    )

    # -- Unique high-half values from standalone orh --
    orh_hi_unique = defaultdict(list)
    for s in standalone_orh:
        orh_hi_unique[s['hi_value_dec']].append(s['addr'])

    orh_hi_freq = sorted(
        [(v, len(a), f"0x{v:08X}", a) for v, a in orh_hi_unique.items()],
        key=lambda x: -x[1]
    )

    # Code pointer candidates from pairs
    code_ptr_from_pairs = sorted(set(
        p['value_dec'] for p in pair_records
        if p['classification'] == 'code_ptr' and p['is_absolute']
    ))

    # Code-range high-half values from standalone orh (absolute, in code range)
    code_hi_from_orh = sorted(set(
        s['hi_value_dec'] for s in standalone_orh
        if s['classification'] == 'code_range_hi' and s['is_absolute']
    ))

    # ===================================================================
    # PRINT SUMMARY
    # ===================================================================
    W = 70
    print("=" * W)
    print("  32-BIT CONSTANT CONSTRUCTION ANALYSIS — ND i860 FIRMWARE")
    print("=" * W)
    print()
    print(f"  Total instruction words:       {total_words:>8}")
    print(f"  Total orh instructions:        {len(standalone_orh) + len(pairs):>8}")
    print()

    # --- Section 1: orh+or pairs ---
    print("-" * W)
    print("  SECTION 1: ORH+OR PAIRS (full 32-bit constant construction)")
    print("-" * W)
    print(f"  Pairs found (extended scan):   {len(pairs):>8}")
    if pairs:
        abs_cnt = sum(1 for p in pair_records if p['is_absolute'])
        rel_cnt = len(pair_records) - abs_cnt
        print(f"    Absolute (src2=r0):          {abs_cnt:>8}")
        print(f"    Register-relative:           {rel_cnt:>8}")
        print()

        # Pattern breakdown
        pat_cnt = defaultdict(int)
        for p in pair_records:
            pat_cnt[p['pattern']] += 1
        for pat, cnt in sorted(pat_cnt.items()):
            print(f"    Pattern '{pat}': {cnt}")
        print()

        # Classification breakdown
        print(f"  {'Classification':<16} {'Count':>6}")
        print(f"  {'-'*16} {'-'*6}")
        for cls in sorted(pair_by_class.keys()):
            print(f"  {cls:<16} {len(pair_by_class[cls]):>6}")
        print()

        # List all pairs (there are very few)
        print("  All orh+or pairs:")
        print(f"  {'orh addr':<10} {'or addr':<10} {'gap':>3}  {'pattern':<10} "
              f"{'src2':<4} {'dest':<4} {'value':<12} {'class'}")
        print(f"  {'-'*10} {'-'*10} {'-'*3}  {'-'*10} {'-'*4} {'-'*4} {'-'*12} {'-'*16}")
        for p in pair_records:
            print(f"  {p['orh_addr']:<10} {p['or_addr']:<10} {p['gap']:>3}  "
                  f"{p['pattern']:<10} {p['src2_name']:<4} {p['dest_name']:<4} "
                  f"{p['value_hex']:<12} {p['classification']}")
    else:
        print("  (none found)")
    print()

    # --- Section 2: Standalone orh ---
    print("-" * W)
    print("  SECTION 2: STANDALONE ORH (upper-half-only, no paired or)")
    print("-" * W)
    print(f"  Total standalone orh:          {len(standalone_orh):>8}")
    abs_orh = sum(1 for s in standalone_orh if s['is_absolute'])
    rel_orh = len(standalone_orh) - abs_orh
    print(f"    Absolute (src2=r0):          {abs_orh:>8}")
    print(f"    Register-relative:           {rel_orh:>8}")
    print()

    # By base register
    print("  By base register:")
    for reg in sorted(orh_by_base.keys(), key=lambda r: -len(orh_by_base[r])):
        cnt = len(orh_by_base[reg])
        print(f"    {reg:<6}: {cnt:>4} occurrences")
    print()

    # By classification
    print("  By high-half classification:")
    for cls in sorted(orh_by_class.keys(), key=lambda c: -len(orh_by_class[c])):
        cnt = len(orh_by_class[cls])
        print(f"    {cls:<20}: {cnt:>4}")
    print()

    # Top 20 high-half values
    print("  Top 20 most-frequent high-half values:")
    print(f"  {'Hi value (<<16)':<16} {'Count':>5}  {'Example locations'}")
    print(f"  {'-'*16} {'-'*5}  {'-'*40}")
    for val, count, hex_str, addrs in orh_hi_freq[:20]:
        locs = ", ".join(addrs[:4])
        if len(addrs) > 4:
            locs += f" (+{len(addrs)-4} more)"
        print(f"  {hex_str:<16} {count:>5}  {locs}")
    print()

    # --- Section 3: Small constants ---
    print("-" * W)
    print("  SECTION 3: SMALL CONSTANTS (or/addu imm16, r0, Rd)")
    print("-" * W)
    print(f"  Total small constant loads:    {len(small_consts):>8}")
    if small_consts:
        sc_by_insn = defaultdict(int)
        for sc in small_consts:
            sc_by_insn[sc['insn']] += 1
        for insn, cnt in sorted(sc_by_insn.items()):
            print(f"    {insn}: {cnt}")
        print()

        sc_vals = defaultdict(list)
        for sc in small_consts:
            sc_vals[sc['value']].append(f"0x{sc['addr']:05X}")
        sc_freq = sorted(sc_vals.items(), key=lambda x: -len(x[1]))
        print("  Unique small constant values:")
        print(f"  {'Value':<14} {'Count':>5}  {'Classification':<16} {'Locations'}")
        print(f"  {'-'*14} {'-'*5}  {'-'*16} {'-'*30}")
        for val, addrs in sc_freq[:30]:
            cls = classify_value(val & 0xFFFFFFFF)
            locs = ", ".join(addrs[:3])
            if len(addrs) > 3:
                locs += f" (+{len(addrs)-3})"
            print(f"  0x{val & 0xFFFFFFFF:08X} {len(addrs):>5}  {cls:<16} {locs}")
    print()

    # --- Section 4: Code pointer candidates ---
    print("-" * W)
    print("  SECTION 4: CODE POINTER CANDIDATES")
    print("-" * W)
    print(f"  From orh+or pairs (absolute, 0x{FW_CODE_START:X}-0x{FW_CODE_END:X}, aligned):")
    print(f"    Count: {len(code_ptr_from_pairs)}")
    for addr in code_ptr_from_pairs:
        refs = pair_unique[addr]
        print(f"      0x{addr:08X}  ({len(refs)} ref{'s' if len(refs)>1 else ''})")
    print()

    print(f"  From standalone orh (absolute, hi<<16 in code range):")
    print(f"    Count: {len(code_hi_from_orh)}")
    for addr in code_hi_from_orh:
        refs = orh_hi_unique[addr]
        print(f"      0x{addr:08X}  ({len(refs)} ref{'s' if len(refs)>1 else ''})")
    print()

    # Small constants that are code pointers
    sc_code_ptrs = sorted(set(
        sc['value'] for sc in small_consts
        if classify_value(sc['value'] & 0xFFFFFFFF) == 'code_ptr'
    ))
    print(f"  From small constants (in code range, aligned):")
    print(f"    Count: {len(sc_code_ptrs)}")
    for addr in sc_code_ptrs:
        addrs = [f"0x{sc['addr']:05X}" for sc in small_consts if sc['value'] == addr]
        print(f"      0x{addr:08X}  ({len(addrs)} ref{'s' if len(addrs)>1 else ''})")
    print()

    # All code pointer seeds combined
    all_seeds = sorted(set(code_ptr_from_pairs) | set(code_hi_from_orh) | set(sc_code_ptrs))
    print(f"  COMBINED potential code address seeds: {len(all_seeds)}")
    for addr in all_seeds:
        print(f"    0x{addr:08X}")
    print()

    # --- Section 5: Notable values ---
    print("-" * W)
    print("  SECTION 5: NOTABLE VALUES")
    print("-" * W)

    # Collect ALL unique standalone orh values grouped by likely purpose
    # Kernel vaddr
    kernel_his = [(s['hi_value_dec'], s['addr'], s['src2_name'])
                  for s in standalone_orh if s['classification'] == 'kernel_vaddr_hi']
    if kernel_his:
        kv_unique = defaultdict(list)
        for val, addr, src in kernel_his:
            kv_unique[val].append((addr, src))
        print(f"\n  Kernel virtual address high-halves ({len(kv_unique)} unique):")
        for val in sorted(kv_unique.keys()):
            refs = kv_unique[val]
            print(f"    0x{val:08X}  ({len(refs)} ref{'s' if len(refs)>1 else ''})")

    # MMIO
    mmio_his = [(s['hi_value_dec'], s['addr'], s['src2_name'])
                for s in standalone_orh if s['classification'] == 'mmio_hi']
    if mmio_his:
        mv_unique = defaultdict(list)
        for val, addr, src in mmio_his:
            mv_unique[val].append((addr, src))
        print(f"\n  MMIO address high-halves ({len(mv_unique)} unique):")
        for val in sorted(mv_unique.keys()):
            refs = mv_unique[val]
            print(f"    0x{val:08X}  ({len(refs)} ref{'s' if len(refs)>1 else ''})")

    # Masks
    mask_his = [(s['hi_value_dec'], s['addr'])
                for s in standalone_orh if s['classification'] == 'mask_hi']
    if mask_his:
        mk_unique = defaultdict(list)
        for val, addr in mask_his:
            mk_unique[val].append(addr)
        print(f"\n  Bitmask high-halves ({len(mk_unique)} unique):")
        for val in sorted(mk_unique.keys()):
            refs = mk_unique[val]
            print(f"    0x{val:08X}  ({len(refs)} ref{'s' if len(refs)>1 else ''})")

    print()

    # ===================================================================
    # BUILD JSON
    # ===================================================================
    json_pairs = []
    for p in pair_records:
        json_pairs.append({k: v for k, v in p.items()
                          if not k.endswith('_int')})

    json_standalone = []
    for s in standalone_orh:
        json_standalone.append({k: v for k, v in s.items()
                               if not k.endswith('_int')})

    json_small = []
    for sc in small_consts:
        json_small.append({
            'addr': f"0x{sc['addr']:05X}",
            'insn': sc['insn'],
            'value_hex': f"0x{sc['value'] & 0xFFFFFFFF:08X}",
            'value_dec': sc['value'],
            'dest': sc['dest'],
            'dest_name': reg_name(sc['dest']),
            'classification': classify_value(sc['value'] & 0xFFFFFFFF),
        })

    output = {
        'metadata': {
            'binary': str(BINARY.name),
            'binary_size': BINARY.stat().st_size,
            'total_words': total_words,
            'total_orh_or_pairs': len(pairs),
            'total_standalone_orh': len(standalone_orh),
            'total_small_constants': len(small_consts),
            'pair_classification_counts': {
                cls: len(entries) for cls, entries in pair_by_class.items()
            },
            'orh_classification_counts': {
                cls: len(entries) for cls, entries in orh_by_class.items()
            },
            'orh_by_base_register': {
                reg: len(entries) for reg, entries in orh_by_base.items()
            },
        },
        'pairs': json_pairs,
        'standalone_orh': json_standalone,
        'small_constants': json_small,
        'by_classification': {
            'pairs': {cls: entries for cls, entries in sorted(pair_by_class.items())},
            'standalone_orh': {cls: entries for cls, entries in sorted(orh_by_class.items())},
        },
        'code_ptr_candidates': [f"0x{a:08X}" for a in all_seeds],
        'top_orh_hi_values': [
            {
                'hi_value_hex': hex_str,
                'hi_value_dec': val,
                'reference_count': count,
                'locations': addrs[:10],
            }
            for val, count, hex_str, addrs in orh_hi_freq[:50]
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"  JSON written to: {OUTPUT}")
    print(f"  File size: {OUTPUT.stat().st_size:,} bytes")
    print()
    print("Done.")


if __name__ == '__main__':
    main()
