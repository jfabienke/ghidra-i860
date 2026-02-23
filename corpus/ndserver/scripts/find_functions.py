#!/usr/bin/env python3
"""
Find all functions in NDserver m68k code by identifying:
- Function prologues (linkw %fp,#-XX)
- Function epilogues (unlk %fp ; rts)
- JSR call targets
- String references
"""

import sys

def read_code():
    """Read the m68k code section"""
    with open('extracted/m68k_text.bin', 'rb') as f:
        return f.read()

def find_linkw_unlk(code):
    """Find all linkw/unlk pairs (function boundaries)"""
    functions = []

    # Find all linkw instructions (4E 56)
    linkw_offsets = []
    for i in range(len(code) - 3):
        if code[i:i+2] == b'\x4e\x56':
            frame_size = int.from_bytes(code[i+2:i+4], 'big', signed=True)
            linkw_offsets.append((i, frame_size))

    # Find all unlk ; rts sequences (4E 5E 4E 75)
    unlk_rts_offsets = []
    for i in range(len(code) - 3):
        if code[i:i+4] == b'\x4e\x5e\x4e\x75':
            unlk_rts_offsets.append(i)

    # Match linkw with following unlk
    for i, (linkw_off, frame_size) in enumerate(linkw_offsets):
        # Find next unlk after this linkw
        next_unlk = None
        for unlk_off in unlk_rts_offsets:
            if unlk_off > linkw_off:
                next_unlk = unlk_off
                break

        if next_unlk:
            start_vm = 0x00002d10 + linkw_off
            end_vm = 0x00002d10 + next_unlk + 3  # +3 for unlk;rts bytes
            size = next_unlk - linkw_off + 4

            functions.append({
                'start_offset': linkw_off,
                'end_offset': next_unlk + 3,
                'start_vm': start_vm,
                'end_vm': end_vm,
                'size': size,
                'frame_size': abs(frame_size),
                'name': None  # To be filled in later
            })

    return functions

def find_string_references(code):
    """Find all PEA instructions referencing string section (0x7730-0x7a5b)"""
    refs = []

    # String section: 0x00007730-0x00007a5b
    for i in range(len(code) - 5):
        # PEA absolute.l = 48 79 XX XX XX XX
        if code[i:i+2] == b'\x48\x79':
            addr = int.from_bytes(code[i+2:i+6], 'big')
            # Check if in string section
            if 0x7730 <= addr <= 0x7a5b:
                vm_addr = 0x00002d10 + i
                refs.append({
                    'code_vm': vm_addr,
                    'string_vm': addr,
                    'offset': i
                })

    return refs

def find_jsr_targets(code):
    """Find all JSR (jump to subroutine) instructions"""
    jsrs = []

    for i in range(len(code) - 5):
        # JSR absolute.l = 4E B9 XX XX XX XX
        if code[i:i+2] == b'\x4e\xb9':
            target = int.from_bytes(code[i+2:i+6], 'big')
            vm_addr = 0x00002d10 + i
            jsrs.append({
                'from_vm': vm_addr,
                'target_vm': target,
                'offset': i
            })

    return jsrs

def load_strings():
    """Load interesting strings for function naming"""
    strings = {}
    try:
        with open('analysis/strings_full.txt', 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if 'ND_GetBoardList' in line or 'NextDimension' in line or \
                   'kern_loader' in line or 'ND_Boot' in line or \
                   'ND_' in line or 'nd_' in line:
                    # Extract string (rough parsing)
                    if ':' in line:
                        strings[line.split(':')[0]] = line.split(':', 1)[1].strip()
    except FileNotFoundError:
        pass

    return strings

def annotate_functions(functions, string_refs, strings_data):
    """Try to name functions based on string references"""

    # Mapping of string patterns to likely function names
    string_to_function = {
        'No NextDimension board found': 'ND_GetBoardList',
        'ND_GetBoardList': 'ND_GetBoardList',
        'ND_BootKernelFromSect': 'ND_BootKernelFromSect',
        'kern_loader': 'ND_Load_MachDriver',
        'Mach driver': 'ND_Load_MachDriver',
        'nd_setsync': 'nd_setsync',
        'nd_start_video': 'nd_start_video',
        'NDPingKernel': 'NDPingKernel',
        'ND_SetPagerTask': 'ND_SetPagerTask',
    }

    # For each string reference, find containing function
    for ref in string_refs:
        code_addr = ref['code_vm']
        string_addr = ref['string_vm']

        # Find function containing this code address
        for func in functions:
            if func['start_vm'] <= code_addr <= func['end_vm']:
                # Try to identify function name from string
                # (In real strings_full.txt, we'd look up the actual string)
                # For now, use address matching
                if string_addr == 0x776c:  # "No NextDimension board found"
                    func['name'] = 'ND_GetBoardList'
                    func['confidence'] = 'HIGH'
                elif func['name'] is None:
                    func['name'] = f'func_{func["start_vm"]:08x}'
                    func['confidence'] = 'LOW'
                break

    # Name remaining functions
    for func in functions:
        if func['name'] is None:
            func['name'] = f'func_{func["start_vm"]:08x}'
            func['confidence'] = 'UNKNOWN'

    return functions

def main():
    print("=== NDserver Function Finder ===\n")

    code = read_code()
    print(f"Code section: {len(code)} bytes (0x00002d10-0x000075f8)\n")

    # Find functions
    print("Finding function boundaries...")
    functions = find_linkw_unlk(code)
    print(f"Found {len(functions)} functions with linkw/unlk prologues/epilogues\n")

    # Find string references
    print("Finding string references...")
    string_refs = find_string_references(code)
    print(f"Found {len(string_refs)} string references\n")

    # Find JSR targets
    print("Finding JSR call targets...")
    jsrs = find_jsr_targets(code)
    print(f"Found {len(jsrs)} JSR instructions\n")

    # Load strings
    strings_data = load_strings()

    # Annotate functions with names
    functions = annotate_functions(functions, string_refs, strings_data)

    # Print function map
    print("=" * 80)
    print("FUNCTION MAP")
    print("=" * 80)
    print(f"{'Start':<12} {'End':<12} {'Size':<8} {'Frame':<7} {'Name':<30} {'Confidence'}")
    print("-" * 80)

    for func in sorted(functions, key=lambda x: x['start_vm']):
        print(f"0x{func['start_vm']:08x}  "
              f"0x{func['end_vm']:08x}  "
              f"{func['size']:6d}  "
              f"{func['frame_size']:5d}  "
              f"{func['name']:<30} "
              f"{func.get('confidence', 'UNKNOWN')}")

    print()
    print(f"Total functions: {len(functions)}")
    print(f"Named functions: {sum(1 for f in functions if f.get('confidence') == 'HIGH')}")

    # Print string reference details
    print("\n" + "=" * 80)
    print("STRING REFERENCES")
    print("=" * 80)
    print(f"{'Code Address':<14} {'String Address':<16} {'In Function'}")
    print("-" * 80)

    for ref in sorted(string_refs, key=lambda x: x['code_vm']):
        # Find containing function
        func_name = 'UNKNOWN'
        for func in functions:
            if func['start_vm'] <= ref['code_vm'] <= func['end_vm']:
                func_name = func['name']
                break

        print(f"0x{ref['code_vm']:08x}    "
              f"0x{ref['string_vm']:08x}      "
              f"{func_name}")

    # Save to file
    with open('analysis/function_map.txt', 'w') as f:
        f.write("NDserver Function Map\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Code section: 0x00002d10-0x000075f8 ({len(code)} bytes)\n")
        f.write(f"Total functions found: {len(functions)}\n\n")

        f.write("Function List:\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Start':<12} {'End':<12} {'Size':<8} {'Frame':<7} {'Name'}\n")
        f.write("-" * 80 + "\n")

        for func in sorted(functions, key=lambda x: x['start_vm']):
            f.write(f"0x{func['start_vm']:08x}  "
                   f"0x{func['end_vm']:08x}  "
                   f"{func['size']:6d}  "
                   f"{func['frame_size']:5d}  "
                   f"{func['name']}\n")

    print("\n✅ Function map saved to analysis/function_map.txt")

if __name__ == '__main__':
    main()
