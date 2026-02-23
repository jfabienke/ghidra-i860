#!/usr/bin/env python3
"""
Branch Target Validity Test
The most definitive test for genuine i860 code
"""

import struct
from pathlib import Path

def extract_branch_targets(data, base_address=0xF8010000):
    """Extract all branch instruction targets"""

    valid_ranges = [
        (0x00000000, 0x03FFFFFF, "DRAM"),
        (0x02000000, 0x02FFFFFF, "MMIO"),
        (0x10000000, 0x103FFFFF, "VRAM"),
        (0xF8000000, 0xF8FFFFFF, "FIRMWARE"),
        (0xFFF00000, 0xFFFFFFFF, "ROM"),
    ]

    branches = []

    for offset in range(0, len(data)-4, 4):
        instr = struct.unpack('>I', data[offset:offset+4])[0]
        addr = base_address + offset

        # Decode instruction
        opcode = (instr >> 26) & 0x3F

        # Branch instructions
        if opcode == 0x19:  # bri (indirect)
            src_reg = (instr >> 21) & 0x1F
            branches.append((addr, 'bri', f'%r{src_reg}', None))

        elif opcode == 0x1A:  # call (indirect)
            src_reg = (instr >> 21) & 0x1F
            branches.append((addr, 'call', f'%r{src_reg}', None))

        elif opcode in [0x14, 0x15, 0x16, 0x17]:  # bc, bnc, bt, bnc.t
            # Direct branch with 26-bit offset
            imm26 = instr & 0x3FFFFFF
            if imm26 & 0x2000000:  # Sign extend
                imm26 |= 0xFC000000
            target = (addr + (imm26 << 2)) & 0xFFFFFFFF
            branches.append((addr, f'branch_{opcode:02x}', None, target))

        elif opcode in [0x1B, 0x1C, 0x1D]:  # bla, br, bte
            # Direct branch/call
            imm26 = instr & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 |= 0xFC000000
            target = (addr + (imm26 << 2)) & 0xFFFFFFFF
            branches.append((addr, f'branch_{opcode:02x}', None, target))

    return branches

def validate_targets(branches, valid_ranges):
    """Check how many branch targets fall in valid memory ranges"""

    valid_count = 0
    invalid_count = 0
    indirect_count = 0

    for addr, instr_type, reg, target in branches:
        if target is None:
            indirect_count += 1
            continue

        is_valid = False
        for start, end, name in valid_ranges:
            if start <= target <= end:
                is_valid = True
                break

        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

    total_direct = valid_count + invalid_count
    if total_direct > 0:
        validity_pct = (valid_count / total_direct) * 100
    else:
        validity_pct = 0

    return {
        'total': len(branches),
        'direct': total_direct,
        'indirect': indirect_count,
        'valid': valid_count,
        'invalid': invalid_count,
        'validity_pct': validity_pct,
    }

def main():
    filename = '03_graphics_acceleration.bin'
    data = Path(filename).read_bytes()

    valid_ranges = [
        (0x00000000, 0x03FFFFFF, "DRAM"),
        (0x02000000, 0x02FFFFFF, "MMIO"),
        (0x10000000, 0x103FFFFF, "VRAM"),
        (0xF8000000, 0xF8FFFFFF, "FIRMWARE"),
        (0xFFF00000, 0xFFFFFFFF, "ROM"),
    ]

    print("# Branch Target Validity Analysis")
    print("=" * 80)

    # Analyze full file
    print("\nFull File Analysis:")
    branches = extract_branch_targets(data, 0xF8010000)
    stats = validate_targets(branches, valid_ranges)

    print(f"  Total branches: {stats['total']}")
    print(f"  Direct branches: {stats['direct']}")
    print(f"  Indirect branches: {stats['indirect']}")
    print(f"  Valid targets: {stats['valid']}")
    print(f"  Invalid targets: {stats['invalid']}")
    print(f"  Validity: {stats['validity_pct']:.1f}%")

    # Interpret results
    print("\n" + "=" * 80)
    print("Interpretation:")
    if stats['validity_pct'] > 85:
        print("✅ GENUINE i860 CODE (>85% valid branch targets)")
    elif stats['validity_pct'] > 50:
        print("⚠️  MIXED CONTENT (50-85% validity, some code + data/contamination)")
    else:
        print("❌ CONTAMINATION (<50% valid branch targets, not real code)")

    # Region-by-region analysis
    print("\n" + "=" * 80)
    print("\nRegion-by-Region Analysis:")
    print(f"{'Region':>6} {'Offset':>10} {'Branches':>10} {'Valid%':>8} {'Status':>15}")
    print("-" * 60)

    region_size = 8192
    for i in range(len(data) // region_size):
        offset = i * region_size
        region_data = data[offset:offset+region_size]

        branches = extract_branch_targets(region_data, 0xF8010000 + offset)
        stats = validate_targets(branches, valid_ranges)

        if stats['direct'] > 0:
            status = "CODE" if stats['validity_pct'] > 85 else "MIXED" if stats['validity_pct'] > 50 else "BAD"
            print(f"{i:6d} 0x{offset:08x} {stats['direct']:10d} {stats['validity_pct']:7.1f}% {status:>15}")

if __name__ == '__main__':
    main()