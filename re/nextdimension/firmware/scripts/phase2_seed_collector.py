#!/usr/bin/env python3
"""Phase 2 — Seed collector: aggregate, validate, and deduplicate candidates.

Reads all Phase 2 analysis outputs and produces a final set of validated
seed candidates ready for merging into the recovery map.

Validation criteria:
  - 4-byte aligned
  - Within TEXT VA range (0xF8000000–0xF80B2547)
  - Not in a deny range (from recovery_map_hardmask_pcode.json)
  - Code context score >= 0.5
  - Deduplicated against existing seeds
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import i860_decode as dec

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
CROSS_BLOCK_JSON = Path(__file__).parent.parent / "analysis" / "phase2" / "cross_block_results.json"
REG_CONTEXT_JSON = Path(__file__).parent.parent / "analysis" / "phase2" / "register_context.json"
RECOVERY_MAP = Path(__file__).parent.parent.parent / "kernel" / "docs" / "recovery_map_hardmask_pcode.json"
BINARY = Path(__file__).parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
OUTPUT = Path(__file__).parent.parent / "analysis" / "phase2" / "phase2_seeds.json"

BASE_ADDR = 0xF8000000
TEXT_END = 0xF80B2547
BINARY_SIZE = 200704

# Code-like opcodes for context scoring
CODE_LIKE_OPS = {
    dec.OP_LD_REG, dec.OP_LD_IMM,
    dec.OP_ADDU_REG, dec.OP_ADDU_IMM, dec.OP_SUBU_REG, dec.OP_SUBU_IMM,
    dec.OP_ADDS_REG, dec.OP_ADDS_IMM, dec.OP_SUBS_REG, dec.OP_SUBS_IMM,
    dec.OP_SHL_REG, dec.OP_SHL_IMM, dec.OP_SHR_REG, dec.OP_SHR_IMM,
    dec.OP_SHRA_REG, dec.OP_SHRA_IMM,
    dec.OP_AND_REG, dec.OP_AND_IMM, dec.OP_ANDH_IMM,
    dec.OP_ANDNOT_REG, dec.OP_ANDNOT_IMM, dec.OP_ANDNOTH_IMM,
    dec.OP_OR_REG, dec.OP_OR_IMM, dec.OP_ORH_IMM,
    dec.OP_XOR_REG, dec.OP_XOR_IMM, dec.OP_XORH_IMM,
    dec.OP_BRI, dec.OP_BR, dec.OP_CALL,
    dec.OP_BC, dec.OP_BC_T, dec.OP_BNC, dec.OP_BNC_T,
    dec.OP_BLA, dec.OP_BTNE_REG, dec.OP_BTNE_IMM,
    dec.OP_BTE_REG, dec.OP_BTE_IMM, dec.OP_TRAP,
    dec.OP_ST_REG, dec.OP_ST_IMM,
    0x00, 0x01, 0x02, 0x03,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x12, 0x13,
}


def code_context_score(words, addr_to_idx, file_offset, window=4):
    """Score how code-like the context is at a given file offset."""
    idx = addr_to_idx.get(file_offset)
    if idx is None:
        return 0.0
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


def load_deny_ranges(recovery_map_path):
    """Load deny ranges from recovery map."""
    if not recovery_map_path.exists():
        return []
    with open(recovery_map_path) as f:
        data = json.load(f)
    ranges = []
    for dr in data.get('deny_ranges', []):
        start = int(dr['start'], 16) if isinstance(dr['start'], str) else dr['start']
        end = int(dr['end'], 16) if isinstance(dr['end'], str) else dr['end']
        ranges.append((start, end, dr.get('name', '')))
    return ranges


def load_existing_seeds(recovery_map_path):
    """Load existing seed addresses from recovery map."""
    if not recovery_map_path.exists():
        return set()
    with open(recovery_map_path) as f:
        data = json.load(f)
    seeds = set()
    for seed in data.get('seeds', []):
        addr = seed.get('addr')
        if addr:
            seeds.add(int(addr, 16) if isinstance(addr, str) else addr)
    return seeds


def in_deny_range(addr, deny_ranges):
    """Check if addr falls within any deny range."""
    for start, end, name in deny_ranges:
        if start <= addr <= end:
            return True, name
    return False, None


def main():
    print("Phase 2 — Seed Collector")

    # Load binary for context scoring
    words = dec.read_words(str(BINARY))
    addr_to_idx = {off: i for i, (off, _) in enumerate(words)}

    # Load deny ranges and existing seeds
    deny_ranges = load_deny_ranges(RECOVERY_MAP)
    existing_seeds = load_existing_seeds(RECOVERY_MAP)
    print(f"  Deny ranges: {len(deny_ranges)}")
    print(f"  Existing seeds: {len(existing_seeds)}")

    # -----------------------------------------------------------------------
    # Collect candidates from all Phase 2 sources
    # -----------------------------------------------------------------------
    candidates = []  # (addr_int, source, confidence, bri_addr, detail)

    # Source 1: Cross-block resolved constants
    if CROSS_BLOCK_JSON.exists():
        with open(CROSS_BLOCK_JSON) as f:
            cb_data = json.load(f)

        for rc in cb_data.get('resolved_constants', []):
            val = rc.get('value_int', 0)
            candidates.append({
                'addr': val,
                'source': 'cross_block',
                'confidence': 'resolved_const',
                'bri_addr': rc.get('bri_addr', ''),
                'detail': f"resolved via {rc.get('source', 'unknown')}",
            })

        # Also check chain results for resolved constants
        for cr in cb_data.get('chain_results', []):
            for t in cr.get('terminals', []):
                if t.get('classification') == 'resolved_const' and t.get('value') is not None:
                    candidates.append({
                        'addr': t['value'],
                        'source': 'register_chain',
                        'confidence': 'resolved_const',
                        'bri_addr': cr.get('bri_addr', ''),
                        'detail': f"chain hop {t.get('hops', 0)}: {t.get('detail', '')}",
                    })

        # Check load results for effective addresses
        for lr in cb_data.get('load_results', []):
            if lr.get('effective_addr_int') is not None:
                candidates.append({
                    'addr': lr['effective_addr_int'],
                    'source': 'ld_table',
                    'confidence': 'resolved_load',
                    'bri_addr': lr.get('bri_addr', ''),
                    'detail': lr.get('load_detail', ''),
                })

    # Source 2: Register context — effective addresses from known base registers
    if REG_CONTEXT_JSON.exists():
        with open(REG_CONTEXT_JSON) as f:
            reg_data = json.load(f)

        for reg_name, reg_info in reg_data.get('registers', {}).items():
            if not reg_info.get('is_persistent'):
                continue
            for ea in reg_info.get('effective_addresses_int', []):
                candidates.append({
                    'addr': ea,
                    'source': f'base_register_{reg_name}',
                    'confidence': 'base_register_derived',
                    'bri_addr': '',
                    'detail': f'{reg_name} base register derived',
                })

    print(f"\nRaw candidates collected: {len(candidates)}")

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------
    seeds = []
    rejected = []
    rejection_reasons = Counter()

    for cand in candidates:
        addr = cand['addr']
        reasons = []

        # Alignment check
        if addr % 4 != 0:
            reasons.append('not_aligned')

        # VA range check
        if not (BASE_ADDR <= addr <= TEXT_END):
            reasons.append('out_of_text_range')

        # Deny range check
        in_deny, deny_name = in_deny_range(addr, deny_ranges)
        if in_deny:
            reasons.append(f'in_deny_range:{deny_name}')

        # Duplicate check
        if addr in existing_seeds:
            reasons.append('duplicate_existing')

        # Code context check (only if within binary bounds)
        file_offset = addr - BASE_ADDR
        if 0 <= file_offset < BINARY_SIZE:
            score = code_context_score(words, addr_to_idx, file_offset)
            cand['code_score'] = score
            if score < 0.5:
                reasons.append(f'low_code_score:{score:.2f}')
        else:
            cand['code_score'] = None

        if reasons:
            for r in reasons:
                rejection_reasons[r.split(':')[0]] += 1
            rejected.append({
                **cand,
                'addr_hex': f'0x{addr:08x}',
                'rejection_reasons': reasons,
            })
        else:
            seeds.append({
                **cand,
                'addr_hex': f'0x{addr:08x}',
                'name': f'phase2_{addr - BASE_ADDR:05x}',
                'create_function': cand['confidence'] == 'resolved_const',
            })

    # Deduplicate seeds by address
    seen_addrs = set()
    unique_seeds = []
    for s in seeds:
        if s['addr'] not in seen_addrs:
            seen_addrs.add(s['addr'])
            unique_seeds.append(s)

    # Sort by address
    unique_seeds.sort(key=lambda s: s['addr'])

    # -----------------------------------------------------------------------
    # Statistics
    # -----------------------------------------------------------------------
    by_confidence = Counter(s['confidence'] for s in unique_seeds)
    by_source = Counter(s['source'] for s in unique_seeds)

    print(f"\n{'='*60}")
    print("PHASE 2 SEED COLLECTION SUMMARY")
    print(f"{'='*60}")
    print(f"Raw candidates: {len(candidates)}")
    print(f"Rejected: {len(rejected)}")
    print(f"  Rejection reasons:")
    for reason, count in rejection_reasons.most_common():
        print(f"    {reason}: {count}")
    print(f"Valid seeds (unique): {len(unique_seeds)}")
    print(f"  By confidence:")
    for conf, count in by_confidence.most_common():
        print(f"    {conf}: {count}")
    print(f"  By source:")
    for src, count in by_source.most_common():
        print(f"    {src}: {count}")

    if unique_seeds:
        print(f"\nSeeds:")
        for s in unique_seeds:
            func = " [CREATE_FUNCTION]" if s['create_function'] else ""
            print(f"  {s['addr_hex']} ({s['confidence']}) {s['detail']}{func}")

    # -----------------------------------------------------------------------
    # Write output
    # -----------------------------------------------------------------------
    output = {
        'metadata': {
            'raw_candidates': len(candidates),
            'rejected': len(rejected),
            'valid_seeds': len(unique_seeds),
            'existing_seeds_count': len(existing_seeds),
            'deny_ranges_count': len(deny_ranges),
        },
        'seeds': [{
            'addr': s['addr_hex'],
            'addr_int': s['addr'],
            'name': s['name'],
            'confidence': s['confidence'],
            'source': s['source'],
            'create_function': s['create_function'],
            'code_score': s.get('code_score'),
            'detail': s.get('detail', ''),
        } for s in unique_seeds],
        'rejected': [{
            'addr': r['addr_hex'],
            'addr_int': r['addr'],
            'confidence': r['confidence'],
            'source': r['source'],
            'rejection_reasons': r['rejection_reasons'],
            'detail': r.get('detail', ''),
        } for r in rejected],
        'stats': {
            'by_confidence': dict(by_confidence),
            'by_source': dict(by_source),
            'rejection_reasons': dict(rejection_reasons),
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nOutput written to: {OUTPUT}")


if __name__ == '__main__':
    main()
