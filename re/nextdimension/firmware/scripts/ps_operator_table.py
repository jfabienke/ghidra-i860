#!/usr/bin/env python3
"""Decode PostScript operator registration table at offset 0x1FC00 in the
ND_MachDriver___TEXT_clean_window.bin firmware image.

The clean_window is a 200,704-byte (0x31000) slice from the __TEXT section of
the ND_MachDriver_reloc Mach-O (cpu_type=15, i860).  It contains:

  0x00000-0x0FC00  Big-endian i860 code (PostScript interpreter core)
  0x0FC00-0x117FF  Embedded PostScript prologue source (AI/EPS prolog)
  0x11800-0x17CB7  More i860 code / data
  0x17CB8-0x2133E  Embedded M68k Mach-O (host-side ND driver, cpu_type=6)
  0x2133E-0x31000  Remaining data / resources

Offset 0x1FC00 falls within the embedded M68k Mach-O's __text section.
The M68k driver registers PostScript operators (pswrap-style) that the
host WindowServer dispatches to the NeXTdimension board.

This script:
 1. Parses the embedded M68k Mach-O structure
 2. Hex-dumps the region at 0x1FC00 for visual inspection
 3. Decodes the M68k __const pointer table (function dispatch table)
 4. Resolves M68k __data entries (operator name->handler pairs)
 5. Extracts the kernel_loader error string table
 6. Extracts all referenced handler addresses as analysis seeds
 7. Outputs JSON to the phase1 analysis directory
"""

import json
import struct
import sys
from pathlib import Path

# ── paths ──────────────────────────────────────────────────────────────────────
FIRMWARE = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_clean_window.bin")
TEXT_SECTION = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_section.bin")
DATA_SECTION = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___DATA_section.bin")
OUTPUT = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/analysis/phase1/ps_operator_table.json")

# ── constants ──────────────────────────────────────────────────────────────────
MACHO_BASE = 0x17CB8          # Embedded M68k Mach-O header offset in clean_window
TEXT_VMBASE = 0xF8000000      # vmaddr base for the outer i860 Mach-O __TEXT
DATA_VMBASE = 0xF80B4000      # vmaddr base for the outer i860 __DATA segment
TARGET_OFFSET = 0x1FC00       # User-requested analysis offset
BINARY_SIZE = 0x31000         # Clean window size


def read_be32(buf, off):
    return struct.unpack_from('>I', buf, off)[0]


def read_be16(buf, off):
    return struct.unpack_from('>H', buf, off)[0]


def read_string(buf, off, maxlen=200):
    """Extract a null-terminated ASCII string."""
    end = buf.find(b'\x00', off, off + maxlen)
    if end == -1:
        end = off + maxlen
    try:
        return buf[off:end].decode('ascii')
    except UnicodeDecodeError:
        return None


def hex_dump(buf, start, length, base_label=None):
    """Return a hex dump string of `length` bytes starting at `start`."""
    lines = []
    for row in range(0, length, 16):
        off = start + row
        if off + 16 > len(buf):
            bs = buf[off:]
        else:
            bs = buf[off:off+16]
        hex_str = ' '.join(f'{b:02x}' for b in bs)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in bs)
        label = f'{off:06x}' if base_label is None else f'{base_label + row:06x}'
        lines.append(f'{label}: {hex_str:<48s}  {ascii_str}')
    return '\n'.join(lines)


# ── Parse embedded M68k Mach-O ─────────────────────────────────────────────────
def parse_m68k_macho(data, base):
    """Parse the embedded M68k Mach-O at `base` in `data`."""
    magic = read_be32(data, base)
    assert magic == 0xFEEDFACE, f"Bad magic: {magic:#x}"
    cpu_type = read_be32(data, base + 4)
    assert cpu_type == 6, f"Expected M68k (6), got {cpu_type}"
    ncmds = read_be32(data, base + 16)
    sizeofcmds = read_be32(data, base + 20)

    info = {
        'base_offset': base,
        'cpu_type': cpu_type,
        'ncmds': ncmds,
        'sections': {},
        'symtab': None,
    }

    off = base + 28  # past mach_header
    for _ in range(ncmds):
        cmd = read_be32(data, off)
        cmdsize = read_be32(data, off + 4)

        if cmd == 1:  # LC_SEGMENT
            segname = data[off+8:off+24].split(b'\x00')[0].decode('ascii')
            nsects = read_be32(data, off + 48)
            sect_off = off + 56
            for _ in range(nsects):
                sname = data[sect_off:sect_off+16].split(b'\x00')[0].decode('ascii')
                saddr = read_be32(data, sect_off + 32)
                ssize = read_be32(data, sect_off + 36)
                sfoff = read_be32(data, sect_off + 40)
                info['sections'][sname] = {
                    'vmaddr': saddr,
                    'size': ssize,
                    'file_offset_rel': sfoff,       # relative to Mach-O start
                    'file_offset_abs': base + sfoff, # absolute in clean_window
                }
                sect_off += 68

        elif cmd == 2:  # LC_SYMTAB
            info['symtab'] = {
                'symoff': read_be32(data, off + 8),
                'nsyms': read_be32(data, off + 12),
                'stroff': read_be32(data, off + 16),
                'strsize': read_be32(data, off + 20),
            }

        off += cmdsize

    return info


# ── Resolve strings in M68k sections ──────────────────────────────────────────
def resolve_m68k_string(data, macho_info, vmaddr):
    """Given a vmaddr in the M68k Mach-O, resolve to a string if possible."""
    for sname in ('__cstring', '__const', '__data'):
        sec = macho_info['sections'].get(sname)
        if sec is None:
            continue
        if sec['vmaddr'] <= vmaddr < sec['vmaddr'] + sec['size']:
            file_off = sec['file_offset_abs'] + (vmaddr - sec['vmaddr'])
            return read_string(data, file_off)
    return None


# ── Extract function pointer table from __const ──────────────────────────────
def extract_const_table(data, macho_info):
    """Extract the function pointer dispatch table from __const."""
    sec = macho_info['sections']['__const']
    abs_off = sec['file_offset_abs']
    size = sec['size']
    text_sec = macho_info['sections']['__text']
    text_end = text_sec['vmaddr'] + text_sec['size']

    tables = []
    current_table = []
    off = abs_off

    while off < abs_off + size:
        val = read_be32(data, off)
        vm = sec['vmaddr'] + (off - abs_off)

        if val == 0:
            # Null terminator — end of this sub-table
            if current_table:
                tables.append(current_table)
                current_table = []
        elif val < text_end:
            # Looks like a code pointer
            current_table.append({
                'const_vmaddr': vm,
                'const_file_offset': off,
                'target_vmaddr': val,
                'type': 'code_ptr',
            })
        else:
            # Could be a string pointer or other data
            s = resolve_m68k_string(data, macho_info, val)
            current_table.append({
                'const_vmaddr': vm,
                'const_file_offset': off,
                'value': val,
                'type': 'string_ptr' if s else 'data',
                'string': s,
            })

        off += 4

    if current_table:
        tables.append(current_table)

    return tables


# ── Extract name/handler pairs from __data ───────────────────────────────────
def extract_data_pairs(data, macho_info):
    """Extract named entries from __data (string_ptr, handler_ptr pairs)."""
    sec = macho_info['sections']['__data']
    abs_off = sec['file_offset_abs']
    size = sec['size']
    text_sec = macho_info['sections']['__text']
    text_end = text_sec['vmaddr'] + text_sec['size']

    entries = []
    for i in range(0, size, 4):
        off = abs_off + i
        val = read_be32(data, off)
        s = resolve_m68k_string(data, macho_info, val)
        vm = sec['vmaddr'] + i

        if s and len(s) >= 3:
            # Look at the next word — is it a code pointer?
            if i + 4 < size:
                next_val = read_be32(data, off + 4)
                if 0 < next_val < text_end:
                    entries.append({
                        'data_vmaddr': vm,
                        'name': s,
                        'name_addr': val,
                        'handler_addr': next_val,
                    })

    return entries


# ── Extract kernel_loader error string table from __data ─────────────────────
def extract_error_strings(data, macho_info):
    """Extract the kernel_loader error message table near end of __data."""
    sec = macho_info['sections']['__data']
    abs_off = sec['file_offset_abs']
    size = sec['size']

    strings = []
    for i in range(0, size, 4):
        off = abs_off + i
        val = read_be32(data, off)
        s = resolve_m68k_string(data, macho_info, val)
        if s and len(s) >= 6 and not any(c in s for c in '\n\r\t'):
            vm = sec['vmaddr'] + i
            strings.append({
                'data_vmaddr': vm,
                'string_addr': val,
                'string': s,
            })

    return strings


# ── Extract handler function pointer table from __data ───────────────────────
def extract_handler_table(data, macho_info):
    """Extract the dispatch handler table from __data (code pointers)."""
    sec = macho_info['sections']['__data']
    abs_off = sec['file_offset_abs']
    size = sec['size']
    text_sec = macho_info['sections']['__text']
    text_end = text_sec['vmaddr'] + text_sec['size']

    handlers = []
    for i in range(0, size, 4):
        off = abs_off + i
        val = read_be32(data, off)
        vm = sec['vmaddr'] + i

        if 0x100 < val < text_end:
            handlers.append({
                'data_vmaddr': vm,
                'handler_addr': val,
            })

    return handlers


# ── Scan i860 code region for orh+or constant-building patterns ──────────────
def find_i860_constants(data, start=0, end=None):
    """Find orh_imm + or_imm pairs that build 32-bit constants (BE i860)."""
    if end is None:
        end = len(data)

    constants = []
    for off in range(start, end - 4, 4):
        word = read_be32(data, off)
        op = (word >> 26) & 0x3F
        if op != 0x3B:  # orh_imm
            continue
        src2 = (word >> 21) & 0x1F
        dest = (word >> 16) & 0x1F
        hi16 = word & 0xFFFF

        word2 = read_be32(data, off + 4)
        op2 = (word2 >> 26) & 0x3F
        if op2 != 0x39:  # or_imm
            continue
        src2_2 = (word2 >> 21) & 0x1F
        dest2 = (word2 >> 16) & 0x1F
        lo16 = word2 & 0xFFFF

        if dest2 == dest and src2_2 == dest:
            value = (hi16 << 16) | lo16
            constants.append({
                'offset': off,
                'register': dest,
                'source_reg': src2,
                'value': value,
            })

    return constants


# ── Scan PS source code region for operator definitions ──────────────────────
def find_ps_operator_defs(data, start=0x0FC00, end=0x117FF):
    """Extract PostScript operator definitions from embedded PS source code."""
    try:
        text = data[start:end].decode('ascii', errors='replace')
    except:
        return []

    import re
    # Pattern: /opname ... def
    ops = []
    for m in re.finditer(r'/(\w+)\s*\{[^}]*\}\s*def', text):
        ops.append({
            'name': m.group(1),
            'offset': start + m.start(),
            'definition': m.group(0)[:80],
        })
    # Also: /Alias /op load def
    for m in re.finditer(r'/(\w+)\s+/(\w+)\s+load\s+def', text):
        ops.append({
            'name': m.group(1),
            'offset': start + m.start(),
            'definition': m.group(0),
            'alias_for': m.group(2),
        })

    return ops


# ── Locate the M68k _Start function and trace its registration logic ────────
def analyze_start_function(data, macho_info):
    """Try to understand the M68k _Start entry point and registration logic."""
    # From symbol table: _Start = 0x398
    start_vm = 0x398
    text_sec = macho_info['sections']['__text']
    start_foff = text_sec['file_offset_abs'] + start_vm

    # Scan M68k code for JSR/BSR patterns calling known framework functions
    # Look for patterns where addresses from __const/__data are loaded
    info = {
        'start_vmaddr': start_vm,
        'start_file_offset': start_foff,
    }

    # Look for M68k LEA instructions referencing __const entries
    # M68k LEA (pc,d16) = 0x41FA or similar
    # Also look for MOVE.L #imm patterns that reference known sections
    refs = []
    for off in range(start_foff, min(start_foff + 0x200, len(data) - 2), 2):
        word = read_be16(data, off)
        # MOVE.L #imm32, An or Dn
        if (word & 0xF1FF) == 0x203C or (word & 0xF1FF) == 0x207C:
            imm32 = read_be32(data, off + 2)
            s = resolve_m68k_string(data, macho_info, imm32)
            if s:
                refs.append({
                    'offset': off,
                    'vmaddr': off - text_sec['file_offset_abs'],
                    'value': imm32,
                    'string': s,
                })

    info['string_refs'] = refs
    return info


# ── Scan for all string references within the M68k __text ────────────────────
def find_m68k_string_refs(data, macho_info):
    """Find all M68k instructions that reference __cstring addresses."""
    text_sec = macho_info['sections']['__text']
    abs_off = text_sec['file_offset_abs']
    size = text_sec['size']

    refs = []
    for off in range(abs_off, abs_off + size - 6, 2):
        # Look for 32-bit immediates that resolve to strings
        val = read_be32(data, off)
        s = resolve_m68k_string(data, macho_info, val)
        if s and len(s) >= 4 and '\n' not in s[:20]:
            vm = off - abs_off
            refs.append({
                'text_offset': off,
                'text_vmaddr': vm,
                'string_addr': val,
                'string': s[:60],
            })

    return refs


# ══════════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 72)
    print("PostScript Operator Registration Table Analysis")
    print("=" * 72)

    data = FIRMWARE.read_bytes()
    assert len(data) == BINARY_SIZE, f"Unexpected size: {len(data)}"

    # ── 1. Hex dump at 0x1FC00 ──────────────────────────────────────────────
    print(f"\n{'─'*72}")
    print(f"Hex dump at offset 0x{TARGET_OFFSET:05X} (first 256 bytes)")
    print(f"{'─'*72}")
    print(hex_dump(data, TARGET_OFFSET, 256))

    # ── 2. Parse embedded M68k Mach-O ───────────────────────────────────────
    print(f"\n{'─'*72}")
    print("Embedded M68k Mach-O structure")
    print(f"{'─'*72}")
    macho = parse_m68k_macho(data, MACHO_BASE)
    for sname, sec in macho['sections'].items():
        print(f"  {sname:12s}  vmaddr=0x{sec['vmaddr']:08x}  size=0x{sec['size']:04x}  "
              f"file=0x{sec['file_offset_abs']:06x}")
        if sname == '__text':
            # Show where 0x1FC00 falls
            if sec['file_offset_abs'] <= TARGET_OFFSET < sec['file_offset_abs'] + sec['size']:
                vm_at_target = TARGET_OFFSET - sec['file_offset_abs']
                print(f"    ** 0x{TARGET_OFFSET:05X} = M68k __text vmaddr 0x{vm_at_target:04x}")

    # ── 3. Extract __const function pointer table ───────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __const: Function pointer dispatch table")
    print(f"{'─'*72}")
    const_tables = extract_const_table(data, macho)
    all_handler_addrs = set()

    for ti, table in enumerate(const_tables):
        code_ptrs = [e for e in table if e['type'] == 'code_ptr']
        if code_ptrs:
            print(f"\n  Sub-table {ti}: {len(code_ptrs)} code pointers")
            for e in code_ptrs:
                print(f"    const@0x{e['const_vmaddr']:04x} -> handler 0x{e['target_vmaddr']:04x}")
                all_handler_addrs.add(e['target_vmaddr'])

    # ── 4. Extract __data name/handler pairs ────────────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __data: Named operator/handler pairs")
    print(f"{'─'*72}")
    pairs = extract_data_pairs(data, macho)
    for p in pairs:
        print(f"  name=\"{p['name']}\"  handler=0x{p['handler_addr']:04x}")
        all_handler_addrs.add(p['handler_addr'])

    # ── 5. Handler function table from __data ───────────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __data: Handler dispatch table (code pointers)")
    print(f"{'─'*72}")
    handler_table = extract_handler_table(data, macho)
    for h in handler_table:
        print(f"  data@0x{h['data_vmaddr']:04x} -> handler 0x{h['handler_addr']:04x}")
        all_handler_addrs.add(h['handler_addr'])

    # ── 6. Error string table ───────────────────────────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __data: Error/status string table")
    print(f"{'─'*72}")
    err_strings = extract_error_strings(data, macho)
    for e in err_strings:
        print(f"  data@0x{e['data_vmaddr']:04x} -> \"{e['string']}\"")

    # ── 7. PS source code operator definitions ──────────────────────────────
    print(f"\n{'─'*72}")
    print("Embedded PostScript prologue: operator definitions")
    print(f"{'─'*72}")
    ps_ops = find_ps_operator_defs(data)
    for op in ps_ops[:40]:
        alias = f" (alias for {op['alias_for']})" if 'alias_for' in op else ""
        print(f"  /{op['name']:20s}  offset=0x{op['offset']:05x}{alias}")
    if len(ps_ops) > 40:
        print(f"  ... ({len(ps_ops) - 40} more)")

    # ── 8. i860 constant-building patterns ──────────────────────────────────
    print(f"\n{'─'*72}")
    print("i860 code: orh+or constant pairs (addresses into DATA/BSS)")
    print(f"{'─'*72}")
    i860_consts = find_i860_constants(data, 0, 0x10000)
    interesting = [c for c in i860_consts if 0xF8000000 <= c['value'] < 0xF80D0000]
    for c in interesting:
        region = ""
        v = c['value']
        if TEXT_VMBASE <= v < TEXT_VMBASE + BINARY_SIZE:
            region = f"__TEXT+0x{v - TEXT_VMBASE:05x}"
        elif DATA_VMBASE <= v < DATA_VMBASE + 0x12000:
            region = f"__DATA+0x{v - DATA_VMBASE:05x}"
        elif 0xF80C1D00 <= v < 0xF80C27C0:
            region = "__bss"
        elif 0xF80C27C0 <= v < 0xF80C4098:
            region = "__common"
        print(f"  i860@0x{c['offset']:05x}: r{c['register']} = 0x{c['value']:08x}  ({region})")

    # ── 9. M68k string references from __text code ──────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __text: String references (sampled)")
    print(f"{'─'*72}")
    str_refs = find_m68k_string_refs(data, macho)
    # Deduplicate by string
    seen = set()
    unique_refs = []
    for r in str_refs:
        if r['string'] not in seen:
            seen.add(r['string'])
            unique_refs.append(r)
    for r in unique_refs[:30]:
        print(f"  text@0x{r['text_vmaddr']:04x}: \"{r['string']}\"")
    if len(unique_refs) > 30:
        print(f"  ... ({len(unique_refs) - 30} more)")

    # ── 10. Extract ALL __cstring entries ────────────────────────────────────
    print(f"\n{'─'*72}")
    print("M68k __cstring: All strings")
    print(f"{'─'*72}")
    cs = macho['sections']['__cstring']
    cs_off = cs['file_offset_abs']
    cs_end = cs_off + cs['size']
    all_cstrings = []
    off = cs_off
    while off < cs_end:
        null = data.find(b'\x00', off, cs_end)
        if null == -1:
            break
        if null > off:
            s = data[off:null].decode('ascii', errors='replace')
            vm = cs['vmaddr'] + (off - cs_off)
            all_cstrings.append({'vmaddr': vm, 'string': s})
            print(f"  0x{vm:04x}: \"{s[:70]}\"")
        off = null + 1

    # ── Build output JSON ───────────────────────────────────────────────────
    handler_addrs_sorted = sorted(all_handler_addrs)

    result = {
        'metadata': {
            'firmware': str(FIRMWARE),
            'binary_size': BINARY_SIZE,
            'target_offset': TARGET_OFFSET,
            'target_offset_hex': f'0x{TARGET_OFFSET:05x}',
            'text_vmbase': f'0x{TEXT_VMBASE:08x}',
            'data_vmbase': f'0x{DATA_VMBASE:08x}',
            'embedded_m68k_macho_offset': f'0x{MACHO_BASE:05x}',
        },
        'embedded_m68k_macho': {
            'offset': MACHO_BASE,
            'sections': {
                name: {
                    'vmaddr': f'0x{s["vmaddr"]:08x}',
                    'size': s['size'],
                    'file_offset': f'0x{s["file_offset_abs"]:06x}',
                }
                for name, s in macho['sections'].items()
            },
            'symbols_readable': [
                '_Start', '_CIEABCImageInit', '_CIEASampleProc',
                '_CantHappen', '_ConvertColor', '_CrCMYKAdjustParams',
                '_FindDiffBounds', '_FindRCacheFor', '_LAddToDirty',
                '_LFlushBits', '_Mark', '_NXGetWi',
            ],
        },
        'const_dispatch_tables': [
            {
                'table_index': ti,
                'entry_count': len([e for e in t if e['type'] == 'code_ptr']),
                'entries': [
                    {
                        'const_vmaddr': f'0x{e["const_vmaddr"]:04x}',
                        'target_vmaddr': f'0x{e["target_vmaddr"]:04x}',
                    }
                    for e in t if e['type'] == 'code_ptr'
                ],
            }
            for ti, t in enumerate(const_tables)
            if any(e['type'] == 'code_ptr' for e in t)
        ],
        'named_handlers': [
            {
                'name': p['name'],
                'name_addr': f'0x{p["name_addr"]:04x}',
                'handler_addr': f'0x{p["handler_addr"]:04x}',
            }
            for p in pairs
        ],
        'handler_dispatch_table': [
            {
                'data_vmaddr': f'0x{h["data_vmaddr"]:04x}',
                'handler_addr': f'0x{h["handler_addr"]:04x}',
            }
            for h in handler_table
        ],
        'error_strings': [
            {'addr': f'0x{e["data_vmaddr"]:04x}', 'string': e['string']}
            for e in err_strings
        ],
        'ps_prologue_operators': [
            {
                'name': op['name'],
                'offset': f'0x{op["offset"]:05x}',
                'alias_for': op.get('alias_for'),
            }
            for op in ps_ops
        ],
        'cstrings': [
            {'vmaddr': f'0x{cs["vmaddr"]:04x}', 'string': cs['string']}
            for cs in all_cstrings
        ],
        'i860_address_constants': [
            {
                'offset': f'0x{c["offset"]:05x}',
                'register': c['register'],
                'value': f'0x{c["value"]:08x}',
            }
            for c in interesting
        ],
        'handler_addresses': [f'0x{a:04x}' for a in handler_addrs_sorted],
        'handler_count': len(handler_addrs_sorted),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + '\n')
    print(f"\n{'='*72}")
    print(f"Output written to: {OUTPUT}")
    print(f"  M68k dispatch table sub-tables: {len(result['const_dispatch_tables'])}")
    print(f"  Named handlers: {len(result['named_handlers'])}")
    print(f"  Handler addresses (seeds): {len(handler_addrs_sorted)}")
    print(f"  PS prologue operators: {len(ps_ops)}")
    print(f"  cstring entries: {len(all_cstrings)}")
    print(f"  i860 address constants: {len(interesting)}")
    print(f"{'='*72}")


if __name__ == '__main__':
    main()
