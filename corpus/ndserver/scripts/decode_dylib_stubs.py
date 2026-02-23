#!/usr/bin/env python3
"""
Decode shared library call stubs in m68k Mach-O binaries.

The pattern we see in rasm2 output:
    invalid
    .short 0x04ff
    .short 0xXXXX

Is actually:
    4EF9 XXXX XXXX  ; jsr <absolute_address>

These are dylib jump stubs that get resolved at runtime.
"""

import struct
import sys

def decode_jsr_stub(bytes_at_pos):
    """
    Decode a 6-byte jsr stub: 4EF9 XXXX XXXX
    Returns (is_jsr, target_address)
    """
    if len(bytes_at_pos) < 6:
        return False, None

    opcode = struct.unpack('>H', bytes_at_pos[0:2])[0]

    # 4EF9 = jsr (absolute long addressing)
    if opcode == 0x4EF9:
        target = struct.unpack('>I', bytes_at_pos[2:6])[0]
        return True, target

    # 4EB9 = jsr (absolute long) - alternate encoding
    if opcode == 0x4EB9:
        target = struct.unpack('>I', bytes_at_pos[2:6])[0]
        return True, target

    return False, None

def is_dylib_stub_range(address):
    """
    Check if address is in the dylib stub range.
    NeXTSTEP shared library stubs are usually in __IMPORT section.
    Addresses starting with 0x0401 or 0x04ff are typical stub markers.
    """
    if (address & 0xFFFF0000) == 0x04010000:  # 0x0401XXXX range
        return True
    if (address & 0xFFFF0000) == 0x04FF0000:  # 0x04FFXXXX range
        return True
    return False

def analyze_function_calls(binary_path, function_start, function_size):
    """
    Analyze a function and identify all external library calls.
    """
    with open(binary_path, 'rb') as f:
        # Read the binary (assume raw extracted code)
        f.seek(function_start)
        code = f.read(function_size)

    calls = []
    i = 0
    while i < len(code) - 5:
        is_jsr, target = decode_jsr_stub(code[i:i+6])
        if is_jsr:
            call_type = "dylib_stub" if is_dylib_stub_range(target) else "internal"
            calls.append({
                'offset': function_start + i,
                'address': target,
                'type': call_type,
                'instruction': f'jsr 0x{target:08x}'
            })
            i += 6  # Skip the full jsr instruction
        else:
            i += 2  # Check every 2 bytes (m68k instructions are word-aligned)

    return calls

if __name__ == '__main__':
    # Test with ND_GetBoardList
    binary = 'extracted/m68k_text.bin'

    # ND_GetBoardList: 0x00002dc6 - 0x0000305b (662 bytes)
    # In extracted binary, entry point is at offset 0, so:
    # 0x00002dc6 - 0x00002d10 = 0xb6 = 182 bytes offset

    func_offset = 0xb6
    func_size = 662

    print("=== ND_GetBoardList External Calls ===\n")
    calls = analyze_function_calls(binary, func_offset, func_size)

    for call in calls:
        print(f"Offset 0x{call['offset']:04x}: {call['instruction']} ({call['type']})")

    print(f"\nTotal external calls found: {len(calls)}")
