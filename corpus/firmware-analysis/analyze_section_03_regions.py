#!/usr/bin/env python3
"""
Section 03 Multi-Region Analysis
Samples 16 regions of 8KB each across the 128KB binary
"""

import struct
import sys
from pathlib import Path

def analyze_region(data, offset, size=8192):
    """Analyze a region for i860 code characteristics"""
    region = data[offset:offset+size]
    if len(region) < size:
        return None

    # Byte statistics
    zero_count = region.count(0)
    zero_pct = zero_count / len(region) * 100

    # Unique bytes
    unique_bytes = len(set(region))

    # i860 pattern detection
    nop_count = region.count(b'\xA0\x00\x00\x00')

    # Function boundaries (bri %r1)
    bri_count = 0
    for i in range(0, len(region)-4, 4):
        instr = struct.unpack('>I', region[i:i+4])[0]
        if instr == 0x40000020:
            bri_count += 1

    # Disassembly coherence estimation
    # Valid i860 instructions have specific patterns
    valid_instrs = 0
    total_instrs = 0
    for i in range(0, len(region)-4, 4):
        total_instrs += 1
        instr = struct.unpack('>I', region[i:i+4])[0]

        # Check if it looks like valid i860
        opcode = (instr >> 26) & 0x3F
        if opcode <= 0x2F:  # Valid i860 opcode range
            valid_instrs += 1

    coherence = (valid_instrs / total_instrs * 100) if total_instrs > 0 else 0

    # String detection (ASCII sequences)
    string_chars = sum(1 for b in region if 32 <= b <= 126)
    string_pct = string_chars / len(region) * 100

    return {
        'offset': offset,
        'size': len(region),
        'zero_pct': zero_pct,
        'unique_bytes': unique_bytes,
        'nop_count': nop_count,
        'bri_count': bri_count,
        'coherence': coherence,
        'string_pct': string_pct,
    }

def classify_region(stats):
    """Classify region as CODE, DATA, or CONTAMINATION"""
    if stats['zero_pct'] > 80:
        return 'EMPTY'
    elif stats['string_pct'] > 20:
        return 'TEXT'
    elif stats['coherence'] > 85:
        return 'CODE'
    elif stats['coherence'] > 50 and stats['zero_pct'] < 30:
        return 'MIXED'
    else:
        return 'CONTAMINATION'

def main():
    filename = '03_graphics_acceleration.bin'
    data = Path(filename).read_bytes()

    print(f"# Section 03 Multi-Region Analysis")
    print(f"Total size: {len(data)} bytes ({len(data)//1024} KB)\n")
    print(f"{ 'Region':>8} { 'Offset':>10} { 'Zeros':>8} { 'Unique':>8} { 'NOPs':>6} { 'BRIs':>6} { 'Coherence':>10} { 'Strings':>8} { 'Classification':>15}")
    print("-" * 100)

    # Analyze 16 regions of 8KB each
    region_size = 8192
    num_regions = len(data) // region_size

    results = []
    for i in range(num_regions):
        offset = i * region_size
        stats = analyze_region(data, offset, region_size)
        if stats:
            classification = classify_region(stats)
            results.append((stats, classification))

            print(f"{i:8d} 0x{offset:08x} {stats['zero_pct']:7.1f}% "
                  f"{stats['unique_bytes']:7d} {stats['nop_count']:6d} "
                  f"{stats['bri_count']:6d} {stats['coherence']:9.1f}% "
                  f"{stats['string_pct']:7.1f}% {classification:>15}")

    # Summary
    print("\n" + "=" * 100)
    print("\nSummary by Classification:")
    from collections import Counter
    classifications = Counter(c for _, c in results)
    for cls, count in sorted(classifications.items()):
        pct = count / len(results) * 100
        print(f"  {cls:15s}: {count:2d} regions ({pct:5.1f}%)")

    # Recommendations
    print("\n" + "=" * 100)
    print("\nRecommendations:")

    code_regions = [i for i, (s, c) in enumerate(results) if c == 'CODE']
    if code_regions:
        print(f"✅ KEEP regions: {code_regions}")
        print(f"   Total: {len(code_regions) * 8} KB of valid i860 code")
    else:
        print("❌ No CODE regions found - discard entire section")

    contamination_regions = [i for i, (s, c) in enumerate(results) if c in ['TEXT', 'CONTAMINATION']]
    if contamination_regions:
        print(f"❌ DISCARD regions: {contamination_regions}")
        print(f"   Total: {len(contamination_regions) * 8} KB of contamination")

if __name__ == '__main__':
    main()
