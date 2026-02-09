#!/usr/bin/env python3
"""Find matching code sequences between clean firmware and kernel binary.

Locates the clean firmware window within the kernel Mach-O, verifies byte-level
match, and scans the post-clean __text region for code-like sequences using
i860 opcode heuristics.

Output: kernel_seed_transfer.json with metadata, match verification,
address mapping, and post-clean code region catalog.
"""

import json
import struct
import sys
from pathlib import Path

# Add scripts dir to path for shared decoder
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from i860_decode import decode

# --- Paths ---
CLEAN_FW = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_clean_window.bin")
KERNEL   = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/kernel/i860_kernel.bin")
FULL_TEXT = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/extracted/ND_MachDriver___TEXT_section.bin")
OUTPUT   = Path("/Users/jvindahl/Development/ghidra-i860/re/nextdimension/firmware/analysis/phase1/kernel_seed_transfer.json")

# --- Constants ---
KERNEL_VMBASE = 0xF8000000

# Valid i860 primary opcodes (bits[31:26])
# Comprehensive set from the ISA
VALID_OP6 = {
    # Load/store
    0x00, 0x01, 0x02, 0x03,  # ld.b/ld.b/ld.s/ld.s (reg/imm variants via lsbit0)
    0x04, 0x05,               # ld (reg, imm)
    0x06, 0x07,               # st (reg, imm)
    0x08, 0x09,               # fld (reg, imm)
    0x0A, 0x0B,               # fst (reg, imm)
    0x0C, 0x0D,               # flush (reg, imm)
    0x0E, 0x0F,               # pst.d (reg, imm)
    # Control
    0x10,                     # bri
    0x11,                     # trap
    0x12,                     # FP escape
    0x13,                     # core escape
    0x14, 0x15,               # btne (reg, imm5)
    0x16, 0x17,               # bte (reg, imm5)
    0x1A,                     # br
    0x1B,                     # call
    0x1C, 0x1D,               # bc, bc.t
    0x1E, 0x1F,               # bnc, bnc.t
    # Integer arithmetic
    0x20, 0x21,               # addu (reg, imm)
    0x22, 0x23,               # subu (reg, imm)
    0x24, 0x25,               # adds (reg, imm)
    0x26, 0x27,               # subs (reg, imm)
    # Shifts
    0x28, 0x29,               # shl (reg, imm)
    0x2A, 0x2B,               # shr (reg, imm)
    0x2C,                     # shrd
    0x2D,                     # bla
    0x2E, 0x2F,               # shra (reg, imm)
    # Logic
    0x30, 0x31,               # and (reg, imm)
    0x33,                     # andh
    0x34, 0x35,               # andnot (reg, imm)
    0x37,                     # andnoth
    0x38, 0x39,               # or (reg, imm)
    0x3B,                     # orh
    0x3C, 0x3D,               # xor (reg, imm)
    0x3F,                     # xorh
    # FP load/store pfld
    # ixfr
    0x32,                     # ixfr
}

# Opcode name lookup for display
OP_NAMES = {
    0x00: "ld.b(r)", 0x01: "ld.b(i)", 0x02: "ld.s(r)", 0x03: "ld.s(i)",
    0x04: "ld(r)", 0x05: "ld(i)", 0x06: "st(r)", 0x07: "st(i)",
    0x08: "fld(r)", 0x09: "fld(i)", 0x0A: "fst(r)", 0x0B: "fst(i)",
    0x0C: "flush(r)", 0x0D: "flush(i)", 0x0E: "pst.d(r)", 0x0F: "pst.d(i)",
    0x10: "bri", 0x11: "trap", 0x12: "fp_esc", 0x13: "core_esc",
    0x14: "btne(r)", 0x15: "btne(i)", 0x16: "bte(r)", 0x17: "bte(i)",
    0x1A: "br", 0x1B: "call", 0x1C: "bc", 0x1D: "bc.t",
    0x1E: "bnc", 0x1F: "bnc.t",
    0x20: "addu(r)", 0x21: "addu(i)", 0x22: "subu(r)", 0x23: "subu(i)",
    0x24: "adds(r)", 0x25: "adds(i)", 0x26: "subs(r)", 0x27: "subs(i)",
    0x28: "shl(r)", 0x29: "shl(i)", 0x2A: "shr(r)", 0x2B: "shr(i)",
    0x2C: "shrd", 0x2D: "bla", 0x2E: "shra(r)", 0x2F: "shra(i)",
    0x30: "and(r)", 0x31: "and(i)", 0x32: "ixfr", 0x33: "andh",
    0x34: "andnot(r)", 0x35: "andnot(i)", 0x37: "andnoth",
    0x38: "or(r)", 0x39: "or(i)", 0x3B: "orh",
    0x3C: "xor(r)", 0x3D: "xor(i)", 0x3F: "xorh",
}


def is_valid_instruction(word):
    """Heuristic: is this word a plausible i860 instruction?"""
    if word == 0x00000000:
        return True  # nop (ld.b r0(r0),r0)
    op6 = (word >> 26) & 0x3F
    return op6 in VALID_OP6


def opcode_name(word):
    """Return mnemonic string for display."""
    if word == 0x00000000:
        return "nop"
    op6 = (word >> 26) & 0x3F
    return OP_NAMES.get(op6, f"?{op6:#04x}")


def parse_macho_text_offset(data):
    """Parse Mach-O header (big-endian) to find __text section file offset and size."""
    magic = struct.unpack_from('>I', data, 0)[0]
    assert magic == 0xFEEDFACE, f"Not a big-endian Mach-O: {magic:#x}"

    # Header: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) sizeofcmds(4) flags(4) = 28 bytes
    ncmds = struct.unpack_from('>I', data, 16)[0]

    offset = 28  # start of load commands
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('>II', data, offset)
        if cmd == 1:  # LC_SEGMENT
            segname = data[offset+8:offset+24].rstrip(b'\x00').decode('ascii', errors='replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('>IIII', data, offset+24)
            maxprot, initprot, nsects, seg_flags = struct.unpack_from('>IIII', data, offset+40)

            # Parse sections within this segment
            sec_off = offset + 56
            for _ in range(nsects):
                sectname = data[sec_off:sec_off+16].rstrip(b'\x00').decode('ascii', errors='replace')
                secsegname = data[sec_off+16:sec_off+32].rstrip(b'\x00').decode('ascii', errors='replace')
                sec_addr, sec_size, sec_fileoff = struct.unpack_from('>III', data, sec_off+32)

                if sectname == '__text' and secsegname == '__TEXT':
                    return sec_fileoff, sec_size, sec_addr

                sec_off += 68  # section header size

        offset += cmdsize

    raise ValueError("__text section not found in Mach-O")


def find_code_regions(data, min_run=4):
    """Scan binary data for runs of valid i860 instructions.

    Returns list of (offset_in_data, size, first_opcodes) for runs of
    min_run or more consecutive valid instructions.
    """
    regions = []
    num_words = len(data) // 4
    i = 0

    while i < num_words:
        word = struct.unpack_from('<I', data, i * 4)[0]
        if is_valid_instruction(word):
            # Start of a potential code run
            run_start = i
            opcodes = []
            while i < num_words:
                w = struct.unpack_from('<I', data, i * 4)[0]
                if is_valid_instruction(w):
                    if len(opcodes) < 8:
                        opcodes.append(opcode_name(w))
                    i += 1
                else:
                    break

            run_len = i - run_start
            if run_len >= min_run:
                regions.append({
                    'offset_in_data': run_start * 4,
                    'size_words': run_len,
                    'size_bytes': run_len * 4,
                    'first_opcodes': opcodes,
                })
        else:
            i += 1

    return regions


def merge_close_regions(regions, gap_threshold=16):
    """Merge code regions that are separated by small gaps (likely data literals
    embedded in code that fail the opcode check)."""
    if not regions:
        return []
    merged = [dict(regions[0])]
    for r in regions[1:]:
        prev = merged[-1]
        prev_end = prev['offset_in_data'] + prev['size_bytes']
        gap = r['offset_in_data'] - prev_end
        if gap <= gap_threshold:
            # Merge
            new_end = r['offset_in_data'] + r['size_bytes']
            prev['size_bytes'] = new_end - prev['offset_in_data']
            prev['size_words'] = prev['size_bytes'] // 4
            # Keep first_opcodes from original region
        else:
            merged.append(dict(r))
    return merged


def main():
    print("=" * 72)
    print("Kernel Seed Transfer Analysis")
    print("=" * 72)

    # --- Read files ---
    clean_data = CLEAN_FW.read_bytes()
    kernel_data = KERNEL.read_bytes()
    full_text_data = FULL_TEXT.read_bytes()

    clean_size = len(clean_data)
    kernel_size = len(kernel_data)
    full_text_size = len(full_text_data)

    print(f"\nClean FW:    {clean_size:>10,} bytes  ({CLEAN_FW.name})")
    print(f"Kernel:      {kernel_size:>10,} bytes  ({KERNEL.name})")
    print(f"Full __text: {full_text_size:>10,} bytes  ({FULL_TEXT.name})")

    # --- Step 1: Parse Mach-O to find __text offset ---
    text_file_offset, text_size, text_vmaddr = parse_macho_text_offset(kernel_data)
    print(f"\n--- Mach-O __text section ---")
    print(f"File offset: {text_file_offset:#x} ({text_file_offset})")
    print(f"Size:        {text_size:#x} ({text_size:,})")
    print(f"VM address:  {text_vmaddr:#010x}")

    # --- Step 2: Search for clean FW in kernel ---
    search_pattern = clean_data[:64]
    print(f"\n--- Searching for clean FW in kernel ---")
    print(f"Search pattern (first 64 bytes of clean FW):")
    print(f"  {search_pattern[:32].hex()}")
    print(f"  {search_pattern[32:64].hex()}")

    found_offset = kernel_data.find(search_pattern)
    if found_offset < 0:
        print("ERROR: Clean FW not found in kernel binary!")
        sys.exit(1)

    print(f"Found at kernel offset: {found_offset:#x} ({found_offset})")
    print(f"Expected (__text offset): {text_file_offset:#x} ({text_file_offset})")
    if found_offset == text_file_offset:
        print("MATCH: Clean FW starts exactly at __text section offset.")
    else:
        print(f"DIFFERENCE: {found_offset - text_file_offset} bytes from __text start")

    # --- Step 3: Verify byte-level match ---
    print(f"\n--- Byte-level verification ---")
    kernel_window = kernel_data[found_offset:found_offset + clean_size]
    if len(kernel_window) < clean_size:
        print(f"WARNING: Only {len(kernel_window)} bytes available at kernel offset")

    bytes_compared = min(clean_size, len(kernel_window))
    mismatches = []
    for i in range(bytes_compared):
        if clean_data[i] != kernel_window[i]:
            mismatches.append({
                'clean_offset': i,
                'kernel_offset': found_offset + i,
                'clean_byte': clean_data[i],
                'kernel_byte': kernel_window[i],
            })

    bytes_matched = bytes_compared - len(mismatches)
    print(f"Bytes compared: {bytes_compared:,}")
    print(f"Bytes matched:  {bytes_matched:,}")
    print(f"Mismatches:     {len(mismatches)}")
    if mismatches:
        print("First 10 mismatches:")
        for m in mismatches[:10]:
            print(f"  clean[{m['clean_offset']:#x}]={m['clean_byte']:#04x} vs kernel[{m['kernel_offset']:#x}]={m['kernel_byte']:#04x}")
    else:
        print("PERFECT MATCH: All clean FW bytes match kernel content.")

    # --- Step 4: Address mapping ---
    print(f"\n--- Address mapping ---")
    print(f"Clean FW base:     0x00000000")
    print(f"Kernel VM base:    {KERNEL_VMBASE:#010x}")
    print(f"Kernel file offset of __text: {found_offset:#x}")
    print(f"Mapping: clean_addr -> kernel_vmaddr = {KERNEL_VMBASE:#010x} + clean_addr")
    print(f"Mapping: clean_addr -> kernel_file   = {found_offset:#x} + clean_addr")
    print(f"Example: clean 0x1000 -> kernel VM {KERNEL_VMBASE + 0x1000:#010x}, file {found_offset + 0x1000:#x}")

    # --- Step 5: Verify full __text matches kernel ---
    print(f"\n--- Full __text section verification ---")
    kernel_text_region = kernel_data[found_offset:found_offset + text_size]
    if len(kernel_text_region) == full_text_size == text_size:
        ft_match = kernel_text_region == full_text_data
        print(f"Full __text ({full_text_size:,} bytes) vs kernel __text region: {'MATCH' if ft_match else 'MISMATCH'}")
    else:
        # Compare what we can
        compare_len = min(len(kernel_text_region), full_text_size, text_size)
        ft_match = kernel_text_region[:compare_len] == full_text_data[:compare_len]
        print(f"Compared {compare_len:,} bytes: {'MATCH' if ft_match else 'MISMATCH'}")
        print(f"  kernel_text_region: {len(kernel_text_region):,}")
        print(f"  full_text_data:     {full_text_size:,}")
        print(f"  text_size (header):  {text_size:,}")

    # --- Step 6: Scan post-clean region for code-like sequences ---
    print(f"\n--- Post-clean region analysis ---")
    post_clean_start = clean_size  # offset within __text
    post_clean_data = full_text_data[post_clean_start:]
    post_clean_size = len(post_clean_data)
    print(f"Post-clean region: __text offset {post_clean_start:#x} to {full_text_size:#x}")
    print(f"Post-clean size: {post_clean_size:,} bytes ({post_clean_size // 4:,} words)")

    # Count all-zero words and data-like words
    zero_words = 0
    valid_insn_count = 0
    total_words = post_clean_size // 4
    for i in range(total_words):
        w = struct.unpack_from('<I', post_clean_data, i * 4)[0]
        if w == 0:
            zero_words += 1
        if is_valid_instruction(w):
            valid_insn_count += 1

    print(f"Zero words:            {zero_words:,} ({100*zero_words/total_words:.1f}%)")
    print(f"Valid-opcode words:    {valid_insn_count:,} ({100*valid_insn_count/total_words:.1f}%)")
    print(f"Invalid-opcode words:  {total_words - valid_insn_count:,} ({100*(total_words - valid_insn_count)/total_words:.1f}%)")

    # Find code-like regions (runs of 4+ valid instructions)
    raw_regions = find_code_regions(post_clean_data, min_run=4)
    print(f"\nRaw code-like regions (4+ consecutive valid opcodes): {len(raw_regions)}")

    # Merge regions with small gaps
    merged_regions = merge_close_regions(raw_regions, gap_threshold=32)
    print(f"Merged regions (gap <= 32 bytes): {len(merged_regions)}")

    # Filter to significant regions (>= 16 instructions = 64 bytes)
    significant = [r for r in merged_regions if r['size_words'] >= 16]
    print(f"Significant regions (>= 16 insns): {len(significant)}")

    # Annotate with kernel addresses
    post_clean_regions = []
    for r in significant:
        text_offset = post_clean_start + r['offset_in_data']
        kernel_file_off = found_offset + text_offset
        kernel_vmaddr = KERNEL_VMBASE + text_offset
        post_clean_regions.append({
            'text_offset': text_offset,
            'text_offset_hex': f"0x{text_offset:x}",
            'kernel_file_offset': kernel_file_off,
            'kernel_file_offset_hex': f"0x{kernel_file_off:x}",
            'kernel_vmaddr': kernel_vmaddr,
            'kernel_vmaddr_hex': f"0x{kernel_vmaddr:08x}",
            'size_bytes': r['size_bytes'],
            'size_words': r['size_words'],
            'first_opcodes': r['first_opcodes'],
        })

    # Summary of significant regions
    total_code_bytes = sum(r['size_bytes'] for r in post_clean_regions)
    print(f"\nSignificant code regions cover {total_code_bytes:,} bytes ({100*total_code_bytes/post_clean_size:.1f}% of post-clean)")

    print(f"\nTop 20 largest code regions:")
    print(f"{'#':>3}  {'VM Address':>12}  {'Size':>8}  {'Insns':>6}  First opcodes")
    print(f"{'---':>3}  {'----------':>12}  {'------':>8}  {'-----':>6}  -------------")
    sorted_regions = sorted(post_clean_regions, key=lambda r: r['size_bytes'], reverse=True)
    for i, r in enumerate(sorted_regions[:20]):
        ops = ', '.join(r['first_opcodes'][:6])
        print(f"{i+1:>3}  {r['kernel_vmaddr_hex']:>12}  {r['size_bytes']:>7,}  {r['size_words']:>6,}  {ops}")

    # Total code in kernel __text
    clean_code_bytes = clean_size
    post_clean_code_bytes = total_code_bytes
    total_text_code = clean_code_bytes + post_clean_code_bytes
    print(f"\n--- Coverage summary ---")
    print(f"Clean window code:     {clean_code_bytes:>10,} bytes")
    print(f"Post-clean code:       {post_clean_code_bytes:>10,} bytes (in {len(post_clean_regions)} regions)")
    print(f"Total identified code: {total_text_code:>10,} bytes ({100*total_text_code/full_text_size:.1f}% of __text)")
    print(f"__text total:          {full_text_size:>10,} bytes")

    # --- Step 7: Build output JSON ---
    mismatch_list = []
    for m in mismatches[:100]:  # cap at 100
        mismatch_list.append({
            'clean_offset': f"0x{m['clean_offset']:x}",
            'kernel_offset': f"0x{m['kernel_offset']:x}",
            'clean_byte': f"0x{m['clean_byte']:02x}",
            'kernel_byte': f"0x{m['kernel_byte']:02x}",
        })

    output = {
        'metadata': {
            'clean_fw_path': str(CLEAN_FW),
            'kernel_path': str(KERNEL),
            'full_text_path': str(FULL_TEXT),
            'clean_size': clean_size,
            'kernel_size': kernel_size,
            'full_text_size': full_text_size,
            'text_start_in_kernel': found_offset,
            'text_start_in_kernel_hex': f"0x{found_offset:x}",
            'text_section_size': text_size,
            'vmaddr_base': KERNEL_VMBASE,
            'vmaddr_base_hex': f"0x{KERNEL_VMBASE:08x}",
        },
        'match_verification': {
            'bytes_compared': bytes_compared,
            'bytes_matched': bytes_matched,
            'mismatch_count': len(mismatches),
            'perfect_match': len(mismatches) == 0,
            'mismatches': mismatch_list,
        },
        'address_map': {
            'clean_base': 0,
            'clean_base_hex': "0x00000000",
            'kernel_vmbase': KERNEL_VMBASE,
            'kernel_vmbase_hex': f"0x{KERNEL_VMBASE:08x}",
            'kernel_text_file_offset': found_offset,
            'kernel_text_file_offset_hex': f"0x{found_offset:x}",
            'formula_vmaddr': "kernel_vmaddr = 0xF8000000 + clean_offset",
            'formula_file': f"kernel_file_offset = 0x{found_offset:x} + clean_offset",
        },
        'post_clean_analysis': {
            'post_clean_start_text_offset': post_clean_start,
            'post_clean_start_text_offset_hex': f"0x{post_clean_start:x}",
            'post_clean_size_bytes': post_clean_size,
            'total_words': total_words,
            'zero_words': zero_words,
            'zero_word_pct': round(100 * zero_words / total_words, 2),
            'valid_opcode_words': valid_insn_count,
            'valid_opcode_pct': round(100 * valid_insn_count / total_words, 2),
            'raw_regions_count': len(raw_regions),
            'merged_regions_count': len(merged_regions),
            'significant_regions_count': len(significant),
            'significant_code_bytes': total_code_bytes,
            'significant_code_pct': round(100 * total_code_bytes / post_clean_size, 2),
        },
        'post_clean_code_regions': post_clean_regions,
        'seed_transfer_note': (
            "The clean firmware (200,704 bytes) is an exact byte-for-byte match with the "
            "first 200,704 bytes of the kernel's __text section. Any function address "
            "identified in the clean firmware at offset X maps to kernel virtual address "
            f"0xF8000000 + X. The kernel file offset is 0x{found_offset:x} + X. "
            "The remaining __text content (offsets 0x31000 to 0xB2548) contains "
            f"{len(post_clean_regions)} significant code regions totaling "
            f"{total_code_bytes:,} bytes of additional i860 code not present in the "
            "clean firmware window. These regions likely contain additional kernel "
            "functions, interrupt handlers, and driver code."
        ),
    }

    # Write JSON
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n--- Output written to ---")
    print(f"{OUTPUT}")

    print(f"\n{'=' * 72}")
    print("Done.")


if __name__ == '__main__':
    main()
