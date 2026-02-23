# Section 03 Comprehensive Re-Analysis Plan

**Date**: 2025-11-11
**Purpose**: Definitively determine if 03_graphics_acceleration.bin contains any valid i860 code
**Status**: Planning Phase

---

## Conflicting Reports

### Report 1: CLEAN_FIRMWARE_EXTRACTION_REPORT.md (2025-11-09)
- ✅ **Verified**: 128 KB of i860 code
- ✅ **Quality**: 92.6% average coherence
- ✅ **Functions**: 383 identified
- ✅ **Evidence**: 87.9%-95.8% coherence across 4 regions
- **Conclusion**: Production ready

### Report 2: 03_graphics_contamination_report.md (2025-11-10)
- ❌ **Contaminated**: 60.4% zeros
- ❌ **Foreign Data**: NIB files, Spanish UI strings
- ❌ **Empty Chunks**: 45 out of 128 (35.2%)
- ❌ **Low Function Density**: Only 131 bri returns
- **Conclusion**: Unusable

### Resolution Needed
These reports contradict each other. We need a **definitive multi-phase analysis** to:
1. Determine ground truth about i860 code presence
2. Map exact boundaries of any valid code regions
3. Identify and separate useful data structures
4. Make final keep/discard decision

---

## Analysis Strategy: 6-Phase Deep Scan

### Phase 1: Binary Structure Analysis (30 minutes)

**Goal**: Get ground truth statistics without assumptions

```bash
cd /Users/jvindahl/Development/nextdimension/firmware_clean

# 1. Basic statistics
hexdump -C 03_graphics_acceleration.bin | head -1000 > 03_hexdump_sample.txt
wc -c 03_graphics_acceleration.bin

# 2. Byte distribution
python3 << 'EOF'
from collections import Counter
import struct

with open('03_graphics_acceleration.bin', 'rb') as f:
    data = f.read()

print(f"Total size: {len(data)} bytes")
print(f"\nByte distribution:")
counter = Counter(data)
print(f"  Zero bytes: {counter[0]} ({counter[0]/len(data)*100:.1f}%)")
print(f"  0xFF bytes: {counter[0xFF]} ({counter[0xFF]/len(data)*100:.1f}%)")
print(f"  Unique byte values: {len(counter)}/256")

# Entropy per 1KB chunk
print(f"\nEntropy by 1KB chunk:")
import math
for i in range(0, len(data), 1024):
    chunk = data[i:i+1024]
    if len(chunk) < 1024:
        break

    # Calculate entropy
    counter = Counter(chunk)
    entropy = 0
    for count in counter.values():
        p = count / len(chunk)
        entropy -= p * math.log2(p)

    # Check if mostly zeros
    zero_pct = counter[0] / len(chunk) * 100

    status = "EMPTY" if zero_pct > 80 else "DATA" if entropy > 4 else "LOW"
    print(f"  Chunk {i//1024:3d} (0x{i:05x}): entropy={entropy:.2f}, zeros={zero_pct:5.1f}% [{status}]")
EOF

# 3. String analysis
strings -n 8 03_graphics_acceleration.bin > 03_strings.txt
echo "Found $(wc -l < 03_strings.txt) strings"
head -50 03_strings.txt

# 4. Pattern detection - look for i860 instruction opcodes
python3 << 'EOF'
with open('03_graphics_acceleration.bin', 'rb') as f:
    data = f.read()

# Common i860 instruction patterns (big-endian)
patterns = {
    'nop': b'\xA0\x00\x00\x00',       # or r0,r0,r0
    'bri_r1': b'\x40\x00\x00\x20',    # bri %r1
    'ld.l': b'\x18',                   # First byte of ld.l
    'st.l': b'\x1C',                   # First byte of st.l
    'addu': b'\x80',                   # First byte of addu
}

print("Instruction pattern frequency:")
for name, pattern in patterns.items():
    count = data.count(pattern)
    print(f"  {name:10s}: {count:5d} occurrences")

# Look for function boundaries (bri %r1 = 0x40000020)
import struct
bri_r1_count = 0
positions = []
for i in range(0, len(data)-4, 4):
    instr = struct.unpack('>I', data[i:i+4])[0]
    if instr == 0x40000020:  # bri %r1
        bri_r1_count += 1
        positions.append(i)

print(f"\nbri %r1 (function returns): {bri_r1_count}")
if positions:
    print(f"  First 10 positions: {[hex(p) for p in positions[:10]]}")
EOF
```

**Output**: Definitive statistics on content composition

---

### Phase 2: Multi-Region Sampling (1 hour)

**Goal**: Sample multiple regions to find code vs contamination boundaries

```python
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
    print(f"{'Region':>8} {'Offset':>10} {'Zeros':>8} {'Unique':>8} {'NOPs':>6} {'BRIs':>6} {'Coherence':>10} {'Strings':>8} {'Classification':>15}")
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
```

**Save as**: `analyze_section_03_regions.py`
**Run**: `python3 analyze_section_03_regions.py`

**Output**: Region-by-region classification with keep/discard recommendations

---

### Phase 3: Disassembly Sample Test (30 minutes)

**Goal**: Actually disassemble suspicious regions and inspect output

```bash
# Use the i860-disassembler tool to test a few regions
cd /Users/jvindahl/Development/nextdimension/i860-disassembler

# Test region 0 (first 8KB)
dd if=../firmware_clean/03_graphics_acceleration.bin of=/tmp/region_0.bin bs=1 count=8192 skip=0
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8010000 \
  /tmp/region_0.bin > /tmp/region_0.asm

echo "Region 0 sample (first 50 lines):"
head -50 /tmp/region_0.asm

# Test region 8 (middle 8KB at offset 64KB)
dd if=../firmware_clean/03_graphics_acceleration.bin of=/tmp/region_8.bin bs=1 count=8192 skip=65536
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF8020000 \
  /tmp/region_8.bin > /tmp/region_8.asm

echo "Region 8 sample (first 50 lines):"
head -50 /tmp/region_8.asm

# Test region 15 (last 8KB)
dd if=../firmware_clean/03_graphics_acceleration.bin of=/tmp/region_15.bin bs=1 count=8192 skip=122880
./target/release/i860-dissembler \
  --show-addresses \
  --base-address 0xF802E000 \
  /tmp/region_15.bin > /tmp/region_15.asm

echo "Region 15 sample (first 50 lines):"
head -50 /tmp/region_15.asm
```

**Inspect**: Do the disassemblies look coherent or nonsensical?

---

### Phase 4: Compare with VERIFIED File (15 minutes)

**Goal**: Check if 03_graphics_acceleration.bin matches what's in ND_i860_VERIFIED_clean.bin

```bash
cd /Users/jvindahl/Development/nextdimension/firmware_clean

# Extract the section from VERIFIED file
# According to reports, Section 03 should be at offset 64KB (after 32KB Section 01 + 32KB Section 02)
dd if=ND_i860_VERIFIED_clean.bin of=/tmp/verified_section_03.bin bs=1024 skip=64 count=128

# Compare with standalone file
cmp 03_graphics_acceleration.bin /tmp/verified_section_03.bin

# If different, show where they diverge
if ! cmp -s 03_graphics_acceleration.bin /tmp/verified_section_03.bin; then
    echo "FILES DIFFER!"
    cmp -l 03_graphics_acceleration.bin /tmp/verified_section_03.bin | head -20

    # Show file sizes
    ls -l 03_graphics_acceleration.bin /tmp/verified_section_03.bin

    # MD5 comparison
    echo "MD5 checksums:"
    md5 03_graphics_acceleration.bin
    md5 /tmp/verified_section_03.bin
    md5 ND_i860_VERIFIED_clean.bin
else
    echo "FILES ARE IDENTICAL - 03_graphics_acceleration.bin matches VERIFIED build"
fi
```

**Critical**: If files differ, we may have the wrong extraction of Section 03.

---

### Phase 5: Source Trace (30 minutes)

**Goal**: Find the original extraction script and verify offsets

```bash
# Find extraction scripts
find /Users/jvindahl/Development/nextdimension -name "*extract*" -type f 2>/dev/null | head -20

# Look for the script mentioned in CLEAN_FIRMWARE_EXTRACTION_REPORT
ls -la /tmp/extract_clean_firmware.sh 2>/dev/null || echo "Script not in /tmp"

# Check git history for extraction commands
cd /Users/jvindahl/Development/nextdimension/firmware_clean
git log --all --grep="extract" --oneline | head -20
git log --all --grep="Section 03" --oneline | head -20
git log --all --grep="graphics_acceleration" --oneline | head -20

# Look for the SOURCE file
ls -la /Users/jvindahl/Development/previous/src/nextdimension_files/ND_MachDriver_reloc

# Trace the exact offsets used
# From CLEAN_FIRMWARE_EXTRACTION_REPORT:
# "Region 1: offset 230,568"
# "Region 2: offset 263,336" (EXCLUDED)
# "Region 3: offset 295,936"
# "Region 4: offset 328,704"
# "Region 5: offset 361,472"

echo "Verifying extraction offsets..."
echo "Expected 03_graphics_acceleration.bin composition:"
echo "  Region 1: offset 230568, size 32768"
echo "  [Region 2 skipped]"
echo "  Region 3: offset 295936, size 32768"
echo "  Region 4: offset 328704, size 32768"
echo "  Region 5: offset 361472, size 32768"
echo "  Total: 128 KB (4 regions)"
```

**Outcome**: Understand exact provenance of the binary

---

### Phase 6: Branch Target Validation (1 hour)

**Goal**: The DEFINITIVE test - extract all branch instructions and verify targets

```python
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
```

**Save as**: `analyze_branch_validity.py`
**Run**: `python3 analyze_branch_validity.py`

**This is the DEFINITIVE test**: Real i860 code has >85% valid branch targets. Random data or wrong-architecture code has <50%.

---

## Decision Matrix

After all 6 phases, use this matrix:

| Phase | Test | Pass Criteria | Fail Criteria |
|-------|------|---------------|---------------|
| 1 | Binary Structure | <20% zeros, high entropy | >50% zeros, low entropy |
| 2 | Multi-Region | >50% CODE regions | <25% CODE regions |
| 3 | Disassembly | Coherent instructions | Nonsensical output |
| 4 | VERIFIED Match | Files identical | Files differ significantly |
| 5 | Source Trace | Clear provenance | Unknown origin |
| 6 | Branch Validity | >85% valid targets | <50% valid targets |

**Keep Section 03 if**: 4+ tests pass
**Discard Section 03 if**: 4+ tests fail
**Investigate further if**: 3 pass, 3 fail

---

## Expected Outcomes

### Scenario A: Section is Valid
- Branch validity: >85%
- Multi-region: 12+ CODE regions
- Matches VERIFIED file
- **Action**: Update contamination report, keep file

### Scenario B: Section is Contaminated
- Branch validity: <50%
- Multi-region: <4 CODE regions
- Does NOT match VERIFIED file
- **Action**: Discard file, extract from source

### Scenario C: Section is Mixed
- Branch validity: 50-85%
- Multi-region: 4-11 CODE regions
- Partially matches VERIFIED
- **Action**: Extract valid regions only

---

## Timeline

- Phase 1: 30 minutes
- Phase 2: 1 hour
- Phase 3: 30 minutes
- Phase 4: 15 minutes
- Phase 5: 30 minutes
- Phase 6: 1 hour

**Total**: ~4 hours for complete analysis

---

## Next Steps

1. Run Phase 1 (Binary Structure) immediately
2. If Phase 1 shows <30% zeros → proceed with all phases
3. If Phase 1 shows >60% zeros → skip to Phase 5 (find source)
4. Document all findings in `03_DEFINITIVE_ANALYSIS.md`
5. Update CLAUDE.md with final verdict

---

**Author**: Analysis planning
**Status**: Ready to execute
**Priority**: HIGH - needed to finalize firmware verification
