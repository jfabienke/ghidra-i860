
import sys
import struct

def is_valid_target(offset, data, size):
    """ Check if the offset points to a valid instruction boundary. """
    if offset < 0 or offset >= size:
        return False
    # In a real scenario, we might check for common function prologues
    # or ensure it's not in the middle of a multi-byte instruction.
    # For i860, all instructions are 4 bytes, so any 4-byte aligned
    # offset is a plausible target.
    return offset % 4 == 0

def analyze_branches(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return

    size = len(data)
    if size < 4:
        print("File is too small to contain i860 instructions.")
        return

    total_branches = 0
    direct_branches = 0
    indirect_branches = 0
    valid_targets = 0
    invalid_targets = 0

    # i860 branch opcodes
    # bri, br, call, calli, bc, bnc, bct, bnct, bla
    branch_opcodes = {0x18, 0x19, 0x1A, 0x1B} # Corresponds to bits 31-26
    
    for i in range(0, size - 3, 4):
        instruction = struct.unpack('>I', data[i:i+4])[0]
        opcode = (instruction >> 26) & 0x3F

        if opcode in branch_opcodes:
            total_branches += 1
            
            # bri (indirect)
            if opcode == 0x19:
                indirect_branches += 1
                # Cannot statically determine target, so we can't validate it here.
                continue
            
            # calli (indirect)
            if opcode == 0x1B:
                indirect_branches += 1
                # Cannot statically determine target
                continue

            # Direct branches: br, call, bc, bnc, bct, bnct, bla
            direct_branches += 1
            
            # Extract 26-bit signed displacement
            displacement = instruction & 0x03FFFFFF
            if displacement & 0x02000000: # Sign extend
                displacement -= 0x04000000
            
            target_offset = i + (displacement * 4)

            if is_valid_target(target_offset, data, size):
                valid_targets += 1
            else:
                invalid_targets += 1

    print("# Branch Target Validity Analysis")
    print("=" * 80)
    print("\nFull File Analysis:")
    if total_branches > 0:
        validity_percentage = (valid_targets / direct_branches) * 100 if direct_branches > 0 else 0
        print(f"  Total branches: {total_branches}")
        print(f"  Direct branches: {direct_branches}")
        print(f"  Indirect branches: {indirect_branches}")
        print(f"  Valid targets: {valid_targets}")
        print(f"  Invalid targets: {invalid_targets}")
        print(f"  Validity: {validity_percentage:.1f}%")
    else:
        print("  No branch instructions found.")
    
    print("\n" + "=" * 80)
    print("Interpretation:")
    if total_branches == 0:
        print("-> NO CODE (No branch instructions found)")
    elif validity_percentage >= 80:
        print("✅ LIKELY CODE (>=80% valid branch targets)")
    elif validity_percentage >= 50:
        print("⚠️ SUSPICIOUS (50-80% valid branch targets, might be mixed code/data)")
    else:
        print("❌ CONTAMINATION (<50% valid branch targets, not real code)")
    print("\n" + "=" * 80)

    # Region-by-region analysis
    print("\nRegion-by-Region Analysis:")
    print(f"{ 'Region':>6} {'Offset':>10} {'Branches':>10} {'Valid%':>9} {'Status':>15}")
    print("-" * 60)
    
    region_size = 8192 # 8KB regions
    num_regions = (size + region_size - 1) // region_size

    for r in range(num_regions):
        region_start = r * region_size
        region_end = min((r + 1) * region_size, size)
        region_data = data[region_start:region_end]
        
        r_total = 0
        r_direct = 0
        r_valid = 0

        for i in range(0, len(region_data) - 3, 4):
            instruction = struct.unpack('>I', region_data[i:i+4])[0]
            opcode = (instruction >> 26) & 0x3F

            if opcode in branch_opcodes:
                r_total += 1
                if opcode != 0x19 and opcode != 0x1B: # not bri or calli
                    r_direct += 1
                    displacement = instruction & 0x03FFFFFF
                    if displacement & 0x02000000:
                        displacement -= 0x04000000
                    
                    # IMPORTANT: Target must be relative to the full file, not the region
                    target_offset = (region_start + i) + (displacement * 4)

                    if is_valid_target(target_offset, data, size):
                        r_valid += 1
        
        r_validity = (r_valid / r_direct) * 100 if r_direct > 0 else 0
        status = "GOOD" if r_validity > 80 else "BAD"
        print(f"{r:6d} 0x{region_start:08x} {r_total:10d} {r_validity:8.1f}% {status:>15}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <file_path>")
    else:
        analyze_branches(sys.argv[1])
