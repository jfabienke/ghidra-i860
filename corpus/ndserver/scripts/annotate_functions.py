#!/usr/bin/env python3
"""
Systematically disassemble all 92 functions using radare2
and annotate them with intent/purpose based on:
- String references
- Function patterns
- Call sequences
- Register usage
"""

import subprocess
import json
import re
from pathlib import Path

# Load function map from our previous analysis
def load_function_map():
    """Parse the function_map.txt to get all function addresses"""
    functions = []

    with open('analysis/function_map.txt', 'r') as f:
        in_function_list = False
        for line in f:
            if 'Function List:' in line:
                in_function_list = True
                continue
            if in_function_list and line.startswith('0x'):
                parts = line.split()
                if len(parts) >= 5:
                    func = {
                        'start': int(parts[0], 16),
                        'end': int(parts[1], 16),
                        'size': int(parts[2]),
                        'frame': int(parts[3]),
                        'name': ' '.join(parts[4:])
                    }
                    functions.append(func)

    return functions

# Load string references to help with annotation
def load_string_refs():
    """Load string references to match with functions"""
    refs = {}

    try:
        with open('analysis/function_map.txt', 'r') as f:
            in_string_section = False
            for line in f:
                if 'STRING REFERENCES' in line:
                    in_string_section = True
                    continue
                if in_string_section and line.startswith('0x'):
                    parts = line.split()
                    if len(parts) >= 3:
                        code_addr = int(parts[0], 16)
                        string_addr = int(parts[1], 16)
                        func_name = ' '.join(parts[2:])

                        if func_name not in refs:
                            refs[func_name] = []
                        refs[func_name].append({
                            'code_addr': code_addr,
                            'string_addr': string_addr
                        })
    except FileNotFoundError:
        pass

    return refs

# Annotate function based on patterns
def infer_function_purpose(func, string_refs, disasm):
    """Infer function purpose from various indicators"""

    name = func['name']

    # Check if already named
    if name == 'ND_GetBoardList':
        return {
            'label': 'ND_GetBoardList',
            'purpose': 'Board Detection',
            'description': 'Scans NeXTBus slots for NeXTdimension boards, validates availability',
            'confidence': 'HIGH'
        }

    # Check string references
    if name in string_refs:
        string_count = len(string_refs[name])
        if string_count > 10:
            return {
                'label': f'func_{func["start"]:08x}',
                'purpose': 'Complex Logic',
                'description': f'Contains {string_count} string references - likely error handling or UI',
                'confidence': 'MEDIUM'
            }

    # Pattern matching on disassembly
    if disasm:
        # Check for printf/fprintf patterns
        if 'printf' in disasm or 'fprintf' in disasm:
            return {
                'label': f'error_handler_{func["start"]:08x}',
                'purpose': 'Error Reporting',
                'description': 'Contains printf calls - error/debug output',
                'confidence': 'MEDIUM'
            }

        # Check for memory operations
        if 'vm_allocate' in disasm or 'malloc' in disasm:
            return {
                'label': f'mem_mgmt_{func["start"]:08x}',
                'purpose': 'Memory Management',
                'description': 'Contains memory allocation calls',
                'confidence': 'MEDIUM'
            }

        # Check for port operations
        if 'port_allocate' in disasm or 'msg_send' in disasm:
            return {
                'label': f'ipc_handler_{func["start"]:08x}',
                'purpose': 'Mach IPC',
                'description': 'Contains Mach port/message operations',
                'confidence': 'MEDIUM'
            }

    # Size-based heuristics
    if func['size'] < 50:
        return {
            'label': f'helper_{func["start"]:08x}',
            'purpose': 'Utility/Helper',
            'description': f'Small function ({func["size"]} bytes) - likely helper/wrapper',
            'confidence': 'LOW'
        }
    elif func['size'] > 500:
        return {
            'label': f'main_logic_{func["start"]:08x}',
            'purpose': 'Main Logic',
            'description': f'Large function ({func["size"]} bytes) - complex logic',
            'confidence': 'LOW'
        }

    # Default
    return {
        'label': f'func_{func["start"]:08x}',
        'purpose': 'Unknown',
        'description': f'{func["size"]} bytes, frame size {func["frame"]}',
        'confidence': 'UNKNOWN'
    }

# Disassemble a single function using rasm2
def disassemble_function(func):
    """Disassemble a function using rasm2"""

    # Calculate offset in m68k_text.bin
    code_start = 0x00002d10
    func_offset = func['start'] - code_start

    # Extract function bytes
    with open('extracted/m68k_text.bin', 'rb') as f:
        f.seek(func_offset)
        code_bytes = f.read(func['size'])

    # Write to temp file
    temp_file = '/tmp/func_temp.bin'
    with open(temp_file, 'wb') as f:
        f.write(code_bytes)

    # Disassemble with rasm2
    try:
        result = subprocess.run(
            ['rasm2', '-a', 'm68k.gnu', '-d', '-B', '-f', temp_file],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except Exception as e:
        print(f"  Warning: Failed to disassemble {func['name']}: {e}")
        return None

def main():
    print("=" * 80)
    print("NDserver Function Annotation Tool")
    print("=" * 80)
    print()

    # Load data
    print("Loading function map...")
    functions = load_function_map()
    print(f"  Loaded {len(functions)} functions")

    print("Loading string references...")
    string_refs = load_string_refs()
    print(f"  Loaded string refs for {len(string_refs)} functions")
    print()

    # Create output directory
    func_dir = Path('disassembly/functions')
    func_dir.mkdir(parents=True, exist_ok=True)

    # Process each function
    annotated_functions = []

    print("Processing functions...")
    print("-" * 80)

    for i, func in enumerate(functions, 1):
        print(f"[{i:2d}/{len(functions)}] {func['name']:<30} ", end='', flush=True)

        # Disassemble
        disasm = disassemble_function(func)

        # Infer purpose
        annotation = infer_function_purpose(func, string_refs, disasm)

        # Combine
        annotated_func = {**func, **annotation, 'disassembly': disasm}
        annotated_functions.append(annotated_func)

        # Save individual function disassembly
        func_file = func_dir / f"{func['start']:08x}_{annotation['label']}.asm"
        with open(func_file, 'w') as f:
            f.write(f"; Function: {annotation['label']}\n")
            f.write(f"; Address: 0x{func['start']:08x} - 0x{func['end']:08x}\n")
            f.write(f"; Size: {func['size']} bytes\n")
            f.write(f"; Frame: {func['frame']} bytes\n")
            f.write(f"; Purpose: {annotation['purpose']}\n")
            f.write(f"; Description: {annotation['description']}\n")
            f.write(f"; Confidence: {annotation['confidence']}\n")
            f.write(";\n")

            if disasm:
                # Add address annotations to disassembly
                lines = disasm.strip().split('\n')
                addr = func['start']
                for line in lines:
                    f.write(f"0x{addr:08x}:  {line}\n")
                    # Rough estimate - most m68k instructions are 2-4 bytes
                    # This is approximate; real analysis would parse instruction sizes
                    addr += 2
            else:
                f.write("; (disassembly failed)\n")

        print(f"→ {annotation['purpose']:<20} [{annotation['confidence']}]")

    # Generate summary report
    print()
    print("=" * 80)
    print("Generating summary report...")

    with open('analysis/annotated_functions.txt', 'w') as f:
        f.write("NDserver Annotated Function Database\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total Functions: {len(annotated_functions)}\n\n")

        # Group by purpose
        by_purpose = {}
        for func in annotated_functions:
            purpose = func['purpose']
            if purpose not in by_purpose:
                by_purpose[purpose] = []
            by_purpose[purpose].append(func)

        f.write("Functions by Purpose:\n")
        f.write("-" * 80 + "\n")
        for purpose, funcs in sorted(by_purpose.items()):
            f.write(f"\n{purpose}: {len(funcs)} functions\n")
            for func in sorted(funcs, key=lambda x: x['start']):
                f.write(f"  0x{func['start']:08x}  {func['label']:<40} {func['confidence']}\n")

        f.write("\n\n" + "=" * 80 + "\n")
        f.write("Detailed Function List:\n")
        f.write("=" * 80 + "\n\n")

        for func in sorted(annotated_functions, key=lambda x: x['start']):
            f.write(f"Address:     0x{func['start']:08x} - 0x{func['end']:08x}\n")
            f.write(f"Label:       {func['label']}\n")
            f.write(f"Purpose:     {func['purpose']}\n")
            f.write(f"Description: {func['description']}\n")
            f.write(f"Size:        {func['size']} bytes\n")
            f.write(f"Frame:       {func['frame']} bytes\n")
            f.write(f"Confidence:  {func['confidence']}\n")

            if func['name'] in string_refs:
                f.write(f"Strings:     {len(string_refs[func['name']])} references\n")

            f.write(f"File:        disassembly/functions/{func['start']:08x}_{func['label']}.asm\n")
            f.write("-" * 80 + "\n")

    # Save as JSON for further processing
    with open('analysis/annotated_functions.json', 'w') as f:
        json.dump(annotated_functions, f, indent=2)

    print()
    print("✅ Annotation complete!")
    print()
    print(f"Individual functions: disassembly/functions/ ({len(functions)} files)")
    print(f"Summary report:       analysis/annotated_functions.txt")
    print(f"JSON database:        analysis/annotated_functions.json")
    print()

    # Print summary by purpose
    print("Summary by Purpose:")
    print("-" * 80)
    for purpose, funcs in sorted(by_purpose.items(), key=lambda x: -len(x[1])):
        print(f"  {purpose:<30} {len(funcs):3d} functions")

if __name__ == '__main__':
    main()
