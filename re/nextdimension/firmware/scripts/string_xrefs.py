#!/usr/bin/env python3
"""Find cross-references from code to ASCII string literals in the
ND_MachDriver clean_window binary.

The binary is a Mach-O i860 MH_PRELOAD (200,704 bytes, base VA 0xF8000000).
It contains:

  1. i860 code (0x00000 - ~0x17000): big-endian i860 instructions that reference
     addresses in the __DATA segment (0xF80B4000+).
  2. An **embedded M68k MH_OBJECT** Mach-O at file offset 0x17CB8 (CPU type 6):
       __text    : emb_va 0x00000000, file 0x17ED0, size 0x8562, 1096 relocs
       __const   : emb_va 0x00008562, file 0x20432, size 0x688
       __cstring : emb_va 0x00008BEA, file 0x20ABA, size 0x783 (48 strings)
       __data    : emb_va 0x0000936E, file 0x2123E, size 0x100

M68k code references __cstring addresses (0x8BEA+) via PEA abs.L, LEA abs.L, etc.
i860 code references __DATA segment addresses (binary data, not strings).

Output: string_xrefs.json
"""

import json
import struct
import sys
from collections import Counter
from pathlib import Path

# --- Configuration ---
BINARY = Path(__file__).resolve().parent.parent / "extracted" / "ND_MachDriver___TEXT_clean_window.bin"
DATA_BIN = Path(__file__).resolve().parent.parent / "extracted" / "ND_MachDriver___DATA_section.bin"
OUTPUT = Path(__file__).resolve().parent.parent / "analysis" / "phase1" / "string_xrefs.json"

BASE_VA = 0xF8000000
DATA_VA = 0xF80B4000
MIN_STRING_LEN = 4

# Embedded M68k Mach-O layout (parsed from header at 0x17CB8)
EMB_MACHO_OFF = 0x17CB8       # file offset of embedded Mach-O header
EMB_TEXT_OFF  = 0x17ED0        # file offset of embedded __text section
EMB_TEXT_VA   = 0x00000000     # embedded VA of __text
EMB_TEXT_SIZE = 0x8562
EMB_CONST_OFF = 0x20432
EMB_CONST_VA  = 0x00008562
EMB_CONST_SIZE = 0x688
EMB_CSTR_OFF  = 0x20ABA       # file offset of embedded __cstring section
EMB_CSTR_VA   = 0x00008BEA    # embedded VA of __cstring
EMB_CSTR_SIZE = 0x783
EMB_DATA_OFF  = 0x2123E
EMB_DATA_VA   = 0x0000936E
EMB_DATA_SIZE = 0x100

# i860 code region
I860_END = EMB_MACHO_OFF  # i860 code ends where the embedded Mach-O begins


# ========================================================================
# Big-endian i860 decoder
# ========================================================================

OP_LD_B_IMM  = 0x01
OP_LD_IMM    = 0x05
OP_CALL      = 0x1B
OP_ADDU_IMM  = 0x21
OP_OR_IMM    = 0x39
OP_ORH_IMM   = 0x3B


def decode_i860(word):
    imm16_raw = word & 0xFFFF
    return {
        'op6':    (word >> 26) & 0x3F,
        'src2':   (word >> 21) & 0x1F,
        'dest':   (word >> 16) & 0x1F,
        'src1':   (word >> 11) & 0x1F,
        'imm16':  imm16_raw,
        'simm16': imm16_raw - 0x10000 if imm16_raw & 0x8000 else imm16_raw,
        'imm26':  word & 0x3FFFFFF,
        'lsbit0': word & 1,
        'raw':    word,
    }


# ========================================================================
# String scanner
# ========================================================================

def find_strings(data, base_va, start=0, end=None, min_len=MIN_STRING_LEN):
    """Scan for NUL-terminated printable ASCII runs."""
    if end is None:
        end = len(data)
    strings = []
    i = start
    while i < end:
        if 0x20 <= data[i] <= 0x7E:
            sstart = i
            while i < end and 0x20 <= data[i] <= 0x7E:
                i += 1
            if i < end and data[i] == 0x00:
                length = i - sstart
                if length >= min_len:
                    content = data[sstart:i].decode('ascii', errors='replace')
                    if len(set(content)) <= 1 and length > 4:
                        i += 1
                        continue
                    if not content.strip():
                        i += 1
                        continue
                    strings.append({
                        'file_offset': sstart,
                        'va': base_va + (sstart - start),
                        'length': length,
                        'content': content,
                    })
            i += 1
        else:
            i += 1
    return strings


def build_string_lookup(strings, key='va'):
    """Build sorted interval list for lookups by VA."""
    intervals = []
    for s in strings:
        va_start = s[key]
        va_end = va_start + s['length']
        intervals.append((va_start, va_end, s))
    intervals.sort()
    return intervals


def lookup_in_intervals(val, intervals):
    """Binary search: check if val falls within [start, end) of any interval."""
    lo, hi = 0, len(intervals) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, info = intervals[mid]
        if val < start:
            hi = mid - 1
        elif val >= end:
            lo = mid + 1
        else:
            return info, val - start
    return None, 0


# ========================================================================
# i860 analysis
# ========================================================================

def find_i860_patterns(data, data_sec=None):
    """Analyze i860 code region for orh+or and orh+ld patterns."""
    words = []
    for off in range(0, min(I860_END, len(data)), 4):
        w = struct.unpack_from('>I', data, off)[0]
        words.append((off, w))

    # orh+or pairs (gap up to 5)
    orh_or_pairs = []
    for i in range(len(words)):
        off1, w1 = words[i]
        d1 = decode_i860(w1)
        if d1['op6'] != OP_ORH_IMM:
            continue
        dest = d1['dest']
        for j in range(1, min(6, len(words) - i)):
            off2, w2 = words[i + j]
            d2 = decode_i860(w2)
            if d2['op6'] == OP_OR_IMM and d2['src2'] == dest and d2['dest'] == dest:
                value = (d1['imm16'] << 16) | d2['imm16']
                orh_or_pairs.append({
                    'orh_addr': off1, 'or_addr': off2, 'gap': j,
                    'src2': d1['src2'], 'dest': dest,
                    'value': value,
                })
                break

    # orh+ld patterns (gap up to 3)
    orh_ld = []
    for i in range(len(words)):
        off1, w1 = words[i]
        d1 = decode_i860(w1)
        if d1['op6'] != OP_ORH_IMM:
            continue
        dest = d1['dest']
        for j in range(1, min(4, len(words) - i)):
            off2, w2 = words[i + j]
            d2 = decode_i860(w2)
            is_ld = d2['op6'] in (OP_LD_IMM, OP_LD_B_IMM)
            if is_ld and d2['src2'] == dest:
                eff = ((d1['imm16'] << 16) + d2['simm16']) & 0xFFFFFFFF
                ld_size = 'b' if d2['op6'] == OP_LD_B_IMM else ('l' if d2['lsbit0'] else 's')
                orh_ld.append({
                    'orh_addr': off1, 'ld_addr': off2, 'gap': j,
                    'orh_src2': d1['src2'], 'dest_reg': dest,
                    'eff_addr': eff, 'ld_size': ld_size,
                })
                break

    # Function entries
    prologues = set()
    for off, word in words:
        d = decode_i860(word)
        if d['op6'] == OP_ADDU_IMM and d['src2'] == 2 and d['dest'] == 2 and d['simm16'] < 0:
            prologues.add(off)
        if d['op6'] == OP_CALL:
            off26 = d['imm26']
            if off26 & 0x2000000:
                off26 -= 0x4000000
            target = off + (off26 << 2) + 4
            if 0 <= target < I860_END:
                prologues.add(target)

    return orh_or_pairs, orh_ld, sorted(prologues)


# ========================================================================
# M68k analysis (embedded Mach-O)
# ========================================================================

def find_m68k_abs_refs(data):
    """Find M68k absolute address references in the embedded __text section."""
    refs = []
    start = EMB_TEXT_OFF
    end = EMB_TEXT_OFF + EMB_TEXT_SIZE - 5

    i = start
    while i < end:
        w = struct.unpack_from('>H', data, i)[0]

        # LEA abs.L, An
        if w & 0xF1FF == 0x41F9:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            reg = (w >> 9) & 7
            refs.append({'code_off': i, 'insn': f'LEA 0x{addr:08X}, A{reg}',
                         'target_va': addr, 'type': 'lea'})
            i += 6; continue

        # PEA abs.L
        if w == 0x4879:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            refs.append({'code_off': i, 'insn': f'PEA 0x{addr:08X}',
                         'target_va': addr, 'type': 'pea'})
            i += 6; continue

        # JSR abs.L
        if w == 0x4EB9:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            refs.append({'code_off': i, 'insn': f'JSR 0x{addr:08X}',
                         'target_va': addr, 'type': 'jsr'})
            i += 6; continue

        # MOVE.L #imm32, Dn
        if w & 0xF1FF == 0x203C:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            reg = (w >> 9) & 7
            refs.append({'code_off': i, 'insn': f'MOVE.L #0x{addr:08X}, D{reg}',
                         'target_va': addr, 'type': 'move_imm'})
            i += 6; continue

        # MOVEA.L #imm32, An
        if w & 0xF1FF == 0x207C:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            reg = (w >> 9) & 7
            refs.append({'code_off': i, 'insn': f'MOVEA.L #0x{addr:08X}, A{reg}',
                         'target_va': addr, 'type': 'movea_imm'})
            i += 6; continue

        # MOVE.L abs.L, Dn
        if w & 0xF1FF == 0x2039:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            reg = (w >> 9) & 7
            refs.append({'code_off': i, 'insn': f'MOVE.L 0x{addr:08X}, D{reg}',
                         'target_va': addr, 'type': 'move_abs'})
            i += 6; continue

        # MOVEA.L abs.L, An
        if w & 0xF1FF == 0x2079:
            addr = struct.unpack_from('>I', data, i + 2)[0]
            reg = (w >> 9) & 7
            refs.append({'code_off': i, 'insn': f'MOVEA.L 0x{addr:08X}, A{reg}',
                         'target_va': addr, 'type': 'movea_abs'})
            i += 6; continue

        i += 2

    return refs


def find_m68k_functions(data):
    """Find M68k function entries via LINK A6 (0x4E56) in embedded __text."""
    functions = []
    for off in range(EMB_TEXT_OFF, EMB_TEXT_OFF + EMB_TEXT_SIZE - 3, 2):
        w = struct.unpack_from('>H', data, off)[0]
        if w == 0x4E56:
            functions.append(off)
    return sorted(functions)


# ========================================================================
# Helpers
# ========================================================================

def find_enclosing(addr, function_addrs):
    if not function_addrs:
        return 0
    lo, hi = 0, len(function_addrs) - 1
    result = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if function_addrs[mid] <= addr:
            result = function_addrs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return result


# ========================================================================
# Main
# ========================================================================

def main():
    print(f"Reading binary: {BINARY}")
    text_data = BINARY.read_bytes()
    print(f"  Size: {len(text_data)} bytes")
    print(f"  i860 code:   0x00000 - 0x{I860_END:05X}")
    print(f"  Embedded M68k Mach-O at 0x{EMB_MACHO_OFF:05X}")
    print(f"    __text:    0x{EMB_TEXT_OFF:05X} (emb_va 0x{EMB_TEXT_VA:08X}, {EMB_TEXT_SIZE} bytes)")
    print(f"    __cstring: 0x{EMB_CSTR_OFF:05X} (emb_va 0x{EMB_CSTR_VA:08X}, {EMB_CSTR_SIZE} bytes)")

    data_data = None
    if DATA_BIN.exists():
        data_data = DATA_BIN.read_bytes()
        print(f"  DATA section: {len(data_data)} bytes at VA 0x{DATA_VA:08X}")

    # ---- Pass 1: Find strings ----
    print("\nPass 1: Finding ASCII strings...")

    # Strings in the embedded __cstring section (primary source)
    emb_cstrings = find_strings(text_data, EMB_CSTR_VA,
                                start=EMB_CSTR_OFF,
                                end=EMB_CSTR_OFF + EMB_CSTR_SIZE)
    print(f"  Embedded __cstring: {len(emb_cstrings)} strings")

    # Strings in embedded __const section (may have string-like data)
    emb_const_strings = find_strings(text_data, EMB_CONST_VA,
                                     start=EMB_CONST_OFF,
                                     end=EMB_CONST_OFF + EMB_CONST_SIZE)
    print(f"  Embedded __const:   {len(emb_const_strings)} strings")

    # Strings in the outer TEXT (Mach-O section names, etc.) excluding embedded regions
    outer_strings = find_strings(text_data, BASE_VA, start=0, end=I860_END)
    print(f"  Outer i860 TEXT:    {len(outer_strings)} strings (likely false positives)")

    # Strings in embedded __data section
    emb_data_strings = find_strings(text_data, EMB_DATA_VA,
                                    start=EMB_DATA_OFF,
                                    end=min(EMB_DATA_OFF + EMB_DATA_SIZE, len(text_data)))
    print(f"  Embedded __data:    {len(emb_data_strings)} strings")

    # Strings past the embedded Mach-O regions (e.g., symbol table, other data)
    post_emb_off = EMB_DATA_OFF + EMB_DATA_SIZE
    post_strings = find_strings(text_data, BASE_VA + post_emb_off,
                                start=post_emb_off, end=len(text_data))
    print(f"  Post-embedded:      {len(post_strings)} strings")

    # DATA section strings
    data_strings = []
    if data_data:
        data_strings = find_strings(data_data, DATA_VA, start=0, end=len(data_data))
        print(f"  DATA section:       {len(data_strings)} strings")

    # Primary string set: embedded __cstring + __const (the main targets)
    # We build two interval sets:
    # 1. Embedded M68k VA space (for M68k xrefs)
    # 2. Outer i860 VA space (for i860 xrefs)
    all_emb_strings = emb_cstrings + emb_const_strings + emb_data_strings
    all_other_strings = outer_strings + post_strings + data_strings
    all_strings = all_emb_strings + all_other_strings

    emb_intervals = build_string_lookup(all_emb_strings, key='va')
    outer_intervals = build_string_lookup(all_other_strings, key='va')

    # Also build by file offset for i860 references
    i860_va_intervals = build_string_lookup(all_strings, key='va')

    total_strings = len(all_strings)
    print(f"  Total strings: {total_strings}")

    # ---- Pass 2: i860 code analysis ----
    print(f"\nPass 2: i860 code analysis (0x00000 - 0x{I860_END:05X})...")
    orh_or_pairs, orh_ld_patterns, i860_funcs = find_i860_patterns(text_data, data_data)

    abs_orh_or = [p for p in orh_or_pairs if p['src2'] == 0]
    abs_orh_ld = [p for p in orh_ld_patterns if p['orh_src2'] == 0]
    print(f"  orh+or pairs: {len(orh_or_pairs)} total, {len(abs_orh_or)} absolute")
    print(f"  orh+ld patterns: {len(orh_ld_patterns)} total, {len(abs_orh_ld)} absolute")
    print(f"  Function entries: {len(i860_funcs)}")

    # i860 string xrefs: check constructed addresses against ALL string VAs
    i860_xrefs = []
    for p in abs_orh_or:
        va = p['value']
        # Check in outer i860 VA space
        info, byte_off = lookup_in_intervals(va, i860_va_intervals)
        if info:
            func = find_enclosing(p['orh_addr'], i860_funcs)
            i860_xrefs.append({
                'code_addr': p['orh_addr'],
                'string_va': va,
                'string_content': info['content'] if byte_off == 0 else info['content'][byte_off:],
                'full_string': info['content'],
                'byte_offset_into_string': byte_off,
                'orh_addr': p['orh_addr'],
                'second_addr': p['or_addr'],
                'dest_reg': p['dest'],
                'enclosing_function_addr': func,
                'pattern': 'i860:orh+or',
                'arch': 'i860',
            })

    for p in abs_orh_ld:
        va = p['eff_addr']
        info, byte_off = lookup_in_intervals(va, i860_va_intervals)
        if info:
            func = find_enclosing(p['orh_addr'], i860_funcs)
            i860_xrefs.append({
                'code_addr': p['orh_addr'],
                'string_va': va,
                'string_content': info['content'] if byte_off == 0 else info['content'][byte_off:],
                'full_string': info['content'],
                'byte_offset_into_string': byte_off,
                'orh_addr': p['orh_addr'],
                'second_addr': p['ld_addr'],
                'dest_reg': p['dest_reg'],
                'enclosing_function_addr': func,
                'pattern': 'i860:orh+ld',
                'arch': 'i860',
            })

    print(f"  String xrefs: {len(i860_xrefs)}")

    # ---- Pass 3: M68k code analysis ----
    print(f"\nPass 3: M68k code analysis (embedded __text at 0x{EMB_TEXT_OFF:05X})...")

    m68k_refs = find_m68k_abs_refs(text_data)
    print(f"  Absolute address references: {len(m68k_refs)}")

    ref_types = Counter(r['type'] for r in m68k_refs)
    for t, c in ref_types.most_common():
        print(f"    {t}: {c}")

    m68k_funcs = find_m68k_functions(text_data)
    print(f"  M68k functions (LINK A6): {len(m68k_funcs)}")

    # M68k string xrefs: match embedded VAs against embedded string intervals
    m68k_xrefs = []
    for r in m68k_refs:
        va = r['target_va']
        info, byte_off = lookup_in_intervals(va, emb_intervals)
        if info:
            func = find_enclosing(r['code_off'], m68k_funcs)
            m68k_xrefs.append({
                'code_addr': r['code_off'],
                'string_va': va,
                'string_content': info['content'] if byte_off == 0 else info['content'][byte_off:],
                'full_string': info['content'],
                'byte_offset_into_string': byte_off,
                'insn': r['insn'],
                'ref_type': r['type'],
                'enclosing_function_addr': func,
                'pattern': f"m68k:{r['type']}",
                'arch': 'm68k',
            })

    print(f"  String xrefs: {len(m68k_xrefs)}")

    # ---- Merge all xrefs ----
    all_xrefs = i860_xrefs + m68k_xrefs
    all_xrefs.sort(key=lambda x: x['code_addr'])

    # ---- Group by function ----
    by_function = {}
    for x in all_xrefs:
        arch = x['arch']
        func_key = f"{arch}:0x{x['enclosing_function_addr']:05X}"
        if func_key not in by_function:
            by_function[func_key] = []
        by_function[func_key].append(x['string_content'])

    # ---- Unreferenced strings ----
    referenced_vas = set()
    for x in all_xrefs:
        # Find the string start VA
        for intervals_list in [emb_intervals, outer_intervals]:
            info, _ = lookup_in_intervals(x['string_va'], intervals_list)
            if info:
                referenced_vas.add(info['va'])
                break

    unreferenced = [s for s in all_strings if s['va'] not in referenced_vas]

    # ---- Statistics ----
    unique_strings = set(x['string_content'] for x in all_xrefs)
    string_counts = Counter(x['string_content'] for x in all_xrefs)
    top_strings = string_counts.most_common(20)

    # ---- JSON output ----
    def fmt_xref(x):
        out = {}
        for k, v in x.items():
            if k in ('code_addr', 'orh_addr', 'second_addr', 'enclosing_function_addr'):
                out[k] = f"0x{v:05X}" if isinstance(v, int) else v
            elif k == 'string_va':
                out[k] = f"0x{v:08X}" if isinstance(v, int) else v
            else:
                out[k] = v
        return out

    def fmt_string(s):
        return {
            'file_offset': f"0x{s['file_offset']:05X}",
            'va': f"0x{s['va']:08X}",
            'length': s['length'],
            'content': s['content'],
        }

    output = {
        'metadata': {
            'binary': str(BINARY),
            'binary_size': len(text_data),
            'base_va': f"0x{BASE_VA:08X}",
            'embedded_m68k_macho_offset': f"0x{EMB_MACHO_OFF:05X}",
            'embedded_cstring_va': f"0x{EMB_CSTR_VA:08X}",
            'embedded_cstring_file_offset': f"0x{EMB_CSTR_OFF:05X}",
            'total_strings_found': total_strings,
            'embedded_cstrings': len(emb_cstrings),
            'total_xrefs': len(all_xrefs),
            'i860_xrefs': len(i860_xrefs),
            'm68k_xrefs': len(m68k_xrefs),
            'total_unique_strings_referenced': len(unique_strings),
            'total_functions_with_strings': len(by_function),
            'total_unreferenced_strings': len(unreferenced),
            'i860_function_entries': len(i860_funcs),
            'm68k_function_entries': len(m68k_funcs),
        },
        'strings': [fmt_string(s) for s in all_strings],
        'xrefs': [fmt_xref(x) for x in all_xrefs],
        'by_function': {
            func: sorted(set(strs))
            for func, strs in sorted(by_function.items())
        },
        'unreferenced_strings': [fmt_string(s) for s in unreferenced],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nOutput written to: {OUTPUT}")

    # ---- Print summary ----
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  Binary:                           {BINARY.name}")
    print(f"  i860 base VA:                     0x{BASE_VA:08X}")
    print(f"  Embedded M68k Mach-O:             0x{EMB_MACHO_OFF:05X}")
    print(f"    __cstring VA:                   0x{EMB_CSTR_VA:08X}")
    print()
    print(f"  Total ASCII strings found:        {total_strings}")
    print(f"    Embedded __cstring:             {len(emb_cstrings)}")
    print(f"    Embedded __const:               {len(emb_const_strings)}")
    print(f"    Other regions:                  {len(all_other_strings)}")
    print()
    print(f"  Total code->string xrefs:         {len(all_xrefs)}")
    print(f"    i860 xrefs:                     {len(i860_xrefs)}")
    print(f"    M68k xrefs:                     {len(m68k_xrefs)}")
    if m68k_xrefs:
        m68k_types = Counter(x['ref_type'] for x in m68k_xrefs)
        for t, c in m68k_types.most_common():
            print(f"      {t:20s}          {c}")
    print()
    print(f"  Unique strings referenced:        {len(unique_strings)}")
    print(f"  Functions referencing strings:     {len(by_function)}")
    print(f"  Unreferenced strings:             {len(unreferenced)}")

    print(f"\n  Top 20 most-referenced strings:")
    print(f"  {'Count':>5}  String")
    print(f"  {'-' * 5}  {'-' * 60}")
    for content, count in top_strings:
        display = content if len(content) <= 58 else content[:55] + "..."
        print(f"  {count:5d}  {display}")
    if not top_strings:
        print("  (none)")

    # Sample xrefs
    print(f"\n  Sample xrefs (first 20):")
    print(f"  {'Code':>10}  {'Emb VA':>10}  {'Arch':>5}  {'Type':>10}  String")
    print(f"  {'-' * 10}  {'-' * 10}  {'-' * 5}  {'-' * 10}  {'-' * 38}")
    for x in all_xrefs[:20]:
        s = x['string_content']
        display = s if len(s) <= 36 else s[:33] + "..."
        ref_type = x.get('ref_type', x.get('pattern', ''))
        print(f"  0x{x['code_addr']:05X}"
              f"  0x{x['string_va']:08X}"
              f"  {x['arch']:>5}"
              f"  {ref_type:>10}"
              f"  {display}")
    if not all_xrefs:
        print("  (none)")

    # Functions with most strings
    if by_function:
        top_func = max(by_function.items(), key=lambda kv: len(kv[1]))
        unique_in_func = sorted(set(top_func[1]))
        print(f"\n  Function with most string refs: {top_func[0]}"
              f" ({len(top_func[1])} refs, {len(unique_in_func)} unique)")
        for s in unique_in_func[:15]:
            display = s if len(s) <= 60 else s[:57] + "..."
            print(f"    - {display}")
        if len(unique_in_func) > 15:
            print(f"    ... and {len(unique_in_func) - 15} more")

    # Show referenced string contents for M68k
    if m68k_xrefs:
        print(f"\n  All M68k-referenced strings:")
        for content, count in string_counts.most_common():
            display = content if len(content) <= 60 else content[:57] + "..."
            print(f"    x{count}: {display}")


if __name__ == '__main__':
    main()
